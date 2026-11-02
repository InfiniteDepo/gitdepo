// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package secretdetection finds credentials (cloud keys, tokens, private keys)
// in text. It is pure: it reads bytes and reports where it found what, and it
// knows nothing about git, repositories or settings. Which rules are enabled
// is the caller's decision.
package secretdetection

import (
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"strings"
)

// Rule describes one kind of secret. Rules are plain data; build a Detector
// from them with NewDetector.
type Rule struct {
	ID   string // stable, kebab-case, e.g. "aws-access-key-id"
	Name string // human readable
	Type string // secret type group for filters, e.g. "aws", "github"

	// Keywords are lowercase literals. A rule runs its regex only when the
	// lowercased content contains one of them (the main CPU saver). No
	// keywords means the rule always runs.
	Keywords []string

	// Regex is RE2 (Go regexp). SecretGroup is the capture group holding the
	// secret (0 = the whole match).
	Regex       string
	SecretGroup int

	// MinEntropy is the minimum Shannon entropy (bits per byte) of the
	// secret; 0 = no check. Outside the generic rules, a non-zero value also
	// refuses a run of 10 ascending bytes (a placeholder such as 0123456789).
	MinEntropy float64

	// ReportAs, if set, is the rule ID its findings carry: a form of another
	// rule's secret (a JWT in base64) is then one alert with it.
	ReportAs string

	// Allowlist regexes are matched against the secret; a hit drops the
	// finding (placeholders like EXAMPLE, xxxx, ${VAR}, <token>).
	Allowlist []string

	// Normalize is optional: it turns the captured secret into its canonical
	// form (a key with its line breaks and indentation removed), and the
	// entropy, allowlist, Check and the fingerprint all work on that form, so
	// one secret has one fingerprint however it is wrapped. Returning nothing
	// refuses the match.
	Normalize func(secret []byte) []byte

	// Check is an optional extra test on the (normalized) secret that RE2 can't
	// express.
	Check func(secret []byte) bool

	// TokenChars, if set, are the bytes a token is made of. A match is dropped
	// when the byte before or after the secret is one of them: a token glued
	// to a token character is part of a longer word (a hash, an identifier),
	// not a key of its own. RE2 has no lookaround, and a boundary consumed by
	// the regex would hide a neighbouring token, so this is checked in Go.
	// Before the secret an escape is not glued: \n, \r, \t, \xXX, \uXXXX or
	// a URL escape (%XX). TrailingOK lists bytes that may follow anyway.
	TokenChars string

	// MaxSecretLen drops a longer capture; 0 means DefaultMaxSecretLen.
	// MinSecretLen drops a shorter one; 0 means no minimum.
	MaxSecretLen, MinSecretLen int

	// TrailingOK are bytes that may follow the secret although they are in
	// TokenChars (a full stop ending a sentence, a hyphen in "key-backup").
	TrailingOK string

	// RejectCap, if above 0, stops the rule for this Scan after that many
	// matches were thrown away (and Scan reports it). Custom rules have one,
	// built-in rules are known to be cheap and have none.
	RejectCap int

	// KeywordInMatch drops a match that holds none of the rule's keywords
	// (compared lowercase), so a custom pattern's keyword promise holds when
	// scanning, not only for its test string.
	KeywordInMatch bool

	// Window, if above 0, runs the regex only near keyword hits. A plain
	// window rule gets the Window bytes before and after each hit (windows
	// that touch are merged). An Anchored rule says every match starts
	// KeywordOffset bytes before a keyword hit (the regex starts with the
	// keyword, or the keyword sits at a fixed offset into it): the regex then
	// runs anchored on the bytes from there to Window bytes after the hit,
	// once per hit that HitCheck (a cheap exact test in Go: case, bytes
	// around; lower is the ASCII-lowercased content) lets through. \b and ^
	// at the start of a window see the start of the text. Needs keywords.
	Window        int
	Anchored      bool
	KeywordOffset int
	HitCheck      func(lower, content []byte, hit int) bool

	// custom marks a rule made by CustomRule: it costs more per byte, is capped
	// in number and runs after the built-in ones.
	custom bool

	// DefaultOff marks noisy rules (generic ones) that callers should not
	// enable unless asked to.
	DefaultOff bool
}

type compiledRule struct {
	Rule
	re        *regexp.Regexp
	anchored  *regexp.Regexp
	cost      int // work units per byte the regex is given, see Detector.MaxWork
	allowlist []*regexp.Regexp
	tokenSet  *[256]bool
	// keywordIDs are the rule's keywords in its Detector's keywordGate.
	keywordIDs []int
}

func compileRule(r Rule) (*compiledRule, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("secretdetection: rule without ID")
	}
	for _, k := range r.Keywords {
		if k == "" || k != strings.ToLower(k) {
			return nil, fmt.Errorf("secretdetection: rule %s: keyword %q must be non-empty and lowercase", r.ID, k)
		}
	}
	re, err := regexp.Compile(r.Regex)
	if err != nil {
		return nil, fmt.Errorf("secretdetection: rule %s: %w", r.ID, err)
	}
	if r.SecretGroup < 0 || r.SecretGroup > re.NumSubexp() {
		return nil, fmt.Errorf("secretdetection: rule %s: secret group %d does not exist", r.ID, r.SecretGroup)
	}
	if r.Window >= workChunk {
		return nil, fmt.Errorf("secretdetection: rule %s: window %d is not below %d", r.ID, r.Window, workChunk)
	}
	c := &compiledRule{Rule: r, re: re}
	c.cost = 1 // a pass over the content with a literal prefix is about 8 times cheaper than a window
	if prefix, _ := re.LiteralPrefix(); r.Anchored || r.Window > 0 || prefix == "" {
		c.cost = 8
		if prefix == "" && !r.Anchored && r.Window == 0 {
			c.cost = 12 // without a prefix the NFA reads every byte: about 30 ns each
		}
	}
	if r.custom {
		// The NFA costs about 3 units per instruction per byte (measured:
		// 150 instructions run at 1 MB/s).
		c.cost = max(8, 3*progSize(r.Regex))
	}
	if r.Anchored {
		if len(r.Keywords) == 0 || r.Window <= 0 {
			return nil, fmt.Errorf("secretdetection: rule %s: an anchored rule needs keywords and a window", r.ID)
		}
		if c.anchored, err = regexp.Compile(`^(?:` + r.Regex + `)`); err != nil {
			return nil, fmt.Errorf("secretdetection: rule %s: %w", r.ID, err)
		}
	}
	if r.TokenChars != "" {
		c.tokenSet = new([256]bool)
		for i := range len(r.TokenChars) {
			c.tokenSet[r.TokenChars[i]] = true
		}
	}
	for _, a := range r.Allowlist {
		are, err := regexp.Compile(a)
		if err != nil {
			return nil, fmt.Errorf("secretdetection: rule %s: allowlist: %w", r.ID, err)
		}
		c.allowlist = append(c.allowlist, are)
	}
	return c, nil
}

// entropy is the Shannon entropy of b in bits per byte.
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var e float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// boundaryOK is the TokenChars check for the secret at c[start:end].
func (r *compiledRule) boundaryOK(c []byte, start, end int) bool {
	if r.tokenSet == nil {
		return true
	}
	if end < len(c) && r.tokenSet[c[end]] && strings.IndexByte(r.TrailingOK, c[end]) < 0 {
		return false
	}
	if start == 0 || !r.tokenSet[c[start-1]] {
		return true
	}
	switch {
	case start >= 2 && c[start-2] == '\\' && strings.IndexByte("nrt", c[start-1]) >= 0:
		return true // JSON or C escape
	case start >= 3 && c[start-3] == '%' && isHex(c[start-2]) && isHex(c[start-1]):
		return true // URL encoding
	case start >= 4 && c[start-4] == '\\' && c[start-3] == 'x' && isHex(c[start-2]) && isHex(c[start-1]):
		return true // \xXX
	}
	return start >= 6 && c[start-6] == '\\' && c[start-5] == 'u' && isHex(c[start-4]) && isHex(c[start-3]) && isHex(c[start-2]) && isHex(c[start-1])
}

func isHex(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}

// progSize is the number of instructions of the simplified pattern.
func progSize(pattern string) int {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return MaxCustomProgSize
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return MaxCustomProgSize
	}
	return len(prog.Inst)
}
