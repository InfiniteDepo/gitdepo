// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
)

const (
	// MaxCustomPatternLen is the longest custom pattern, in bytes.
	MaxCustomPatternLen = 1024
	// MaxCustomNameLen is the longest custom rule name, in bytes.
	MaxCustomNameLen = 100
	// MaxCustomTestStringLen is the longest test string, in bytes.
	MaxCustomTestStringLen = 4 << 10
	// MaxCustomRepeatSum is the most the maxima of all counted repeats in a
	// pattern (x{0,100}) may add up to; an unbounded repeat counts its minimum.
	MaxCustomRepeatSum = 256
	// MaxCustomProgSize is the most instructions a compiled pattern may have.
	MaxCustomProgSize = 300
	// MinCustomKeywordLen and MaxCustomKeywordLen bound a keyword, in bytes;
	// MaxCustomKeywords is how many a rule may have.
	MinCustomKeywordLen = 3
	MaxCustomKeywordLen = 64
	MaxCustomKeywords   = 5
	// MinCustomSecretLen is the shortest secret a custom rule reports.
	MinCustomSecretLen = 8
	// MaxCustomRules is how many custom rules a Detector takes.
	MaxCustomRules = 50
	// MaxCorpusMatches is how often a custom pattern may match the ordinary
	// text corpus; more means it matches ordinary files (`.*`, `\w+`, a hash).
	MaxCorpusMatches = 10
)

// Reasons ValidateCustomRule refuses a rule; test with errors.Is.
var (
	ErrCustomNameInvalid     = errors.New("rule name is empty or too long")
	ErrPatternTooLong        = errors.New("pattern is too long")
	ErrPatternInvalid        = errors.New("pattern is not a valid RE2 expression")
	ErrPatternTooComplex     = errors.New("pattern is too complex")
	ErrPatternMatchesEmpty   = errors.New("pattern matches the empty string")
	ErrTestStringTooLong     = errors.New("test string is too long")
	ErrKeywordMissing        = errors.New("a rule needs 1 to 5 keywords of 3 to 64 bytes, and every one must appear in the match of the test string")
	ErrPatternNoMatchInTest  = errors.New("pattern finds nothing in the test string")
	ErrSecretTooShort        = errors.New("the secret found in the test string is too short")
	ErrPatternMatchesTooMuch = errors.New("pattern matches ordinary text too often")
	ErrKeywordTooCommon      = errors.New("a keyword is too common in ordinary text")
	ErrPatternHoldsSecret    = errors.New("the name, the pattern or a keyword has a known token format")
)

// ErrKeywordNotInMatch is the ErrKeywordMissing of a rule that passed every check up to the match of the test
// string (the pattern, its shape, the keywords' number and size, the test string's length): only a keyword is not in
// the match.
var ErrKeywordNotInMatch = fmt.Errorf("%w: a keyword is not in the match", ErrKeywordMissing)

// RefusalCode is a short code of why a rule was refused, for logs: never the
// error text, which may quote the pattern.
func RefusalCode(err error) string {
	for _, c := range []struct {
		err  error
		code string
	}{
		{ErrCustomNameInvalid, "name"},
		{ErrPatternTooLong, "too_long"},
		{ErrPatternInvalid, "invalid"},
		{ErrPatternTooComplex, "too_complex"},
		{ErrPatternMatchesEmpty, "matches_empty"},
		{ErrKeywordMissing, "keywords"},
		{ErrKeywordTooCommon, "keyword_common"},
		{ErrPatternMatchesTooMuch, "matches_too_much"},
		{ErrPatternHoldsSecret, "holds_secret"},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return "other"
}

// ValidateCustomRule checks a user-written rule and returns why it is refused.
// The cost of a pattern is bounded by its shape, not measured: RE2 is linear,
// but the cost per byte grows with the size of the program and with repeats
// that can nest or add up. So the pattern is at most 1024 bytes and compiles to
// at most 300 instructions, has no unbounded repeat (x*, x+, x{n,}), no repeat
// stands inside another, and the maxima of the counted repeats add up to at
// most 256. It can't match
// the empty string. keywords (1 to 5, 3 to 64 bytes) are literals that all
// appear in the text the pattern matches in testString (at most 4 KiB): the
// rule runs only in windows around them (see Rule.Window), which keeps a
// custom rule from costing CPU on whole files. The secret found in testString
// (capture group 1 if the pattern has one, else the whole match) must be at
// least 8 bytes. The pattern may match the fixed 64 KiB corpus of ordinary
// text at most MaxCorpusMatches times, and so may each keyword. None of the
// name, the pattern and the keywords may hold what a built-in rule that is on
// by default finds (a known token format). The checks that need no test
// string are ValidateStoredRule's. Build the rule with CustomRule.
func ValidateCustomRule(name, pattern, testString string, keywords []string) error {
	if len(testString) > MaxCustomTestStringLen {
		return ErrTestStringTooLong
	}
	if err := ValidateStoredRule(name, pattern, keywords); err != nil {
		return err
	}
	re := regexp.MustCompile(pattern) // ValidateStoredRule compiled it
	rule := CustomRule("custom", name, pattern, keywords)
	m := re.FindStringSubmatchIndex(testString)
	if m == nil {
		return ErrPatternNoMatchInTest
	}
	if !keywordsInMatch(rule.Keywords, strings.ToLower(testString[m[0]:m[1]])) {
		return ErrKeywordNotInMatch
	}
	if m[2*rule.SecretGroup+1]-m[2*rule.SecretGroup] < MinCustomSecretLen {
		return ErrSecretTooShort
	}
	d, err := NewDetector([]Rule{rule})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPatternInvalid, err)
	}
	if fs, _ := d.Scan([]byte(testString)); len(fs) == 0 {
		return ErrPatternNoMatchInTest
	}
	// the name, the pattern and the keywords are stored and shown (the first two also recorded in the audit log) as
	// they are: a literal secret written to catch one known leak would land there
	for _, f := range [][2]string{{"name", name}, {"pattern", pattern}, {"keywords", strings.Join(keywords, "\n")}} {
		if err := CheckHoldsSecret(f[0], f[1]); err != nil {
			return err
		}
	}
	return nil
}

// HoldsSecretError is the ErrPatternHoldsSecret of one field: Field is "name", "pattern" or "keywords", Format the
// name of the built-in rule that found it (never what it found).
type HoldsSecretError struct{ Field, Format string }

func (e *HoldsSecretError) Error() string {
	return ErrPatternHoldsSecret.Error() + " (" + e.Field + ")"
}

func (e *HoldsSecretError) Unwrap() error { return ErrPatternHoldsSecret }

// CheckHoldsSecret returns a *HoldsSecretError for field if a built-in rule that is on by default finds something in
// text (a known token format).
func CheckHoldsSecret(field, text string) error {
	fs, _ := builtinDetector().Scan([]byte(text))
	if len(fs) == 0 {
		return nil
	}
	format := fs[0].RuleID
	if r, ok := RuleByID(format); ok {
		format = r.Name
	}
	return &HoldsSecretError{Field: field, Format: format}
}

// builtinDetector runs the built-in rules that are on by default.
var builtinDetector = sync.OnceValue(func() *Detector {
	var rules []Rule
	for _, r := range BuiltinRules() {
		if !r.DefaultOff {
			rules = append(rules, r)
		}
	}
	d, err := NewDetector(rules)
	if err != nil {
		panic(err) // the built-in rules compile: tested
	}
	return d
})

// ValidateStoredRule is the half of ValidateCustomRule that needs no test string, run again on a rule that is already
// stored: the pattern, its shape and the corpus, and the keywords' number and size, each keyword at most
// MaxCorpusMatches times in the (lowercased) corpus. A rule that a later version of the engine refuses fails here,
// and the caller skips it.
func ValidateStoredRule(name, pattern string, keywords []string) error {
	if name == "" || len(name) > MaxCustomNameLen {
		return ErrCustomNameInvalid
	}
	if len(pattern) > MaxCustomPatternLen {
		return ErrPatternTooLong
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPatternInvalid, err) // the *syntax.Error says what is wrong
	}
	if err := checkComplexity(pattern); err != nil {
		return err
	}
	if re.MatchString("") {
		return ErrPatternMatchesEmpty
	}
	if len(keywords) == 0 || len(keywords) > MaxCustomKeywords {
		return ErrKeywordMissing
	}
	for _, k := range keywords {
		if len(k) < MinCustomKeywordLen || len(k) > MaxCustomKeywordLen {
			return ErrKeywordMissing
		}
		// The rule runs in windows around its keywords: a keyword found all over ordinary files (the, for, https,
		// return, config) would make it run on whole files.
		if strings.Count(lowerCorpus(), strings.ToLower(k)) > MaxCorpusMatches {
			return ErrKeywordTooCommon
		}
	}
	if len(re.FindAllIndex(corpus(), MaxCorpusMatches+1)) > MaxCorpusMatches {
		return ErrPatternMatchesTooMuch
	}
	return nil
}

// CustomRule is the Rule of a custom pattern: the secret is capture group 1 if
// the pattern has one, else the whole match, and at least 8 bytes. It runs in
// windows around the (lowercased) keywords: as many bytes on each side as the
// longest match of the pattern, so a match that holds a keyword lies inside.
func CustomRule(id, name, pattern string, keywords []string) Rule {
	r := Rule{
		ID: id, Name: name, Type: "custom", Regex: pattern, custom: true,
		MinSecretLen: MinCustomSecretLen, Window: DefaultMaxSecretLen + 256,
		KeywordInMatch: true, RejectCap: MaxRejectedPerRule,
		Allowlist: slices.Clone(placeholders),
	}
	if re, err := regexp.Compile(pattern); err == nil {
		r.SecretGroup = min(re.NumSubexp(), 1)
	}
	if parsed, err := syntax.Parse(pattern, syntax.Perl); err == nil {
		// Unbounded repeats are refused by validation, so this is finite; a
		// rule built without validation keeps the default.
		if n := maxMatchLen(parsed.Simplify()); n > 0 && n < workChunk {
			r.Window = n
		}
	}
	for _, k := range keywords {
		r.Keywords = append(r.Keywords, strings.ToLower(k))
	}
	return r
}

// keywordsInMatch: there are 1 to 5 keywords, each of a fitting length, and
// every one is in the match.
func keywordsInMatch(keywords []string, match string) bool {
	if len(keywords) == 0 || len(keywords) > MaxCustomKeywords {
		return false
	}
	for _, k := range keywords {
		if len(k) < MinCustomKeywordLen || len(k) > MaxCustomKeywordLen || !strings.Contains(match, k) {
			return false
		}
	}
	return true
}

// checkComplexity refuses the shapes that make RE2 slow: a big program, repeats
// inside repeats and counted repeats that add up.
func checkComplexity(pattern string) error {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPatternInvalid, err)
	}
	sum := 0
	var tooBig func(r *syntax.Regexp, inRepeat bool) bool
	tooBig = func(r *syntax.Regexp, inRepeat bool) bool {
		repeat := r.Op == syntax.OpStar || r.Op == syntax.OpPlus || r.Op == syntax.OpRepeat
		if repeat && inRepeat {
			return true
		}
		if r.Op == syntax.OpRepeat {
			sum += max(r.Max, r.Min)
		}
		for _, sub := range r.Sub {
			if tooBig(sub, inRepeat || repeat) {
				return true
			}
		}
		return false
	}
	if tooBig(parsed, false) || sum > MaxCustomRepeatSum {
		return ErrPatternTooComplex
	}
	simple := parsed.Simplify() // x{2,} becomes xx+, so this sees every unbounded repeat
	if unbounded(simple) {
		return ErrPatternTooComplex
	}
	prog, err := syntax.Compile(simple)
	if err != nil || len(prog.Inst) > MaxCustomProgSize {
		return ErrPatternTooComplex
	}
	return nil
}

// maxMatchLen is the most bytes a match of r can have (a pattern without
// unbounded repeats). A class or literal counts 4 bytes if it can hold a
// non-ASCII rune (the case folds of k and s are 3 bytes).
func maxMatchLen(r *syntax.Regexp) int {
	switch r.Op {
	case syntax.OpLiteral:
		n := 0
		for _, c := range r.Rune {
			switch {
			case c >= 0x80:
				n += 4
			case r.Flags&syntax.FoldCase != 0 && strings.ContainsRune("ksKS", c):
				n += 3
			default:
				n++
			}
		}
		return n
	case syntax.OpCharClass:
		for i := 1; i < len(r.Rune); i += 2 {
			if r.Rune[i] >= 0x80 {
				return 4
			}
		}
		return 1
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 4
	case syntax.OpStar, syntax.OpPlus:
		return -1 << 30 // unbounded: callers fall back
	case syntax.OpConcat, syntax.OpAlternate:
		total := 0
		for _, sub := range r.Sub {
			n := maxMatchLen(sub)
			if r.Op == syntax.OpConcat {
				total += n
			} else {
				total = max(total, n)
			}
		}
		return total
	case syntax.OpRepeat:
		return max(r.Max, 0) * maxMatchLen(r.Sub[0])
	case syntax.OpQuest, syntax.OpCapture:
		return maxMatchLen(r.Sub[0])
	}
	return 0
}

// unbounded: the simplified pattern has a * or + (an x{n,} became one).
func unbounded(r *syntax.Regexp) bool {
	if r.Op == syntax.OpStar || r.Op == syntax.OpPlus {
		return true
	}
	return slices.ContainsFunc(r.Sub, unbounded)
}

// corpus is a fixed 64 KiB of ordinary files: prose, code with tabs and
// braces, JSON, URLs, git hashes, UUIDs, lock file integrity lines, base64,
// and non-ASCII text. A simple generator makes it, so it is the same
// everywhere and holds no literal that looks like a secret.
var corpus = sync.OnceValue(func() []byte {
	words := strings.Fields(`the of and to in is that for it as was with be by on not this are or from at which but have an had they you were their one all we can her has there been if more when will would who so no
config server value name list item index result error file path user group time data build test version release branch commit merge request issue comment label state open closed
configuration repository environment implementation authentication organization notification description
2024 1.2.3 404 8080 v2 x86_64 id-42 foo_bar camelCase snake_case kebab-case`)
	var x uint32 = 1
	next := func(n int) int {
		x = x*1664525 + 1013904223
		return int(x>>8) % n
	}
	random := func(alphabet string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[next(len(alphabet))]
		}
		return string(b)
	}
	const hexDigits, b64 = "0123456789abcdef", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	for b.Len() < 64<<10 {
		switch next(14) {
		case 0:
			b.WriteString("commit " + random(hexDigits, 40) + "\n")
		case 1:
			b.WriteString("sha256:" + random(hexDigits, 64) + "\n")
		case 2:
			u := random(hexDigits, 32)
			b.WriteString(u[:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:] + "\n")
		case 3:
			b.WriteString(random(b64, 76) + "\n")
		case 4:
			b.WriteString("integrity sha512-" + random(b64, 86) + "==\n")
		case 5:
			b.WriteString("github.com/org/" + words[next(len(words))] + " v1.2.3 h1:" + random(b64, 43) + "=\n")
		case 6:
			b.WriteString("See https://git.corp.test/" + words[next(len(words))] + "/" + words[next(len(words))] + "/pulls/" + random("0123456789", 3) + "?tab=files&x=1 for details.\n")
		case 7:
			b.WriteString("func " + words[next(len(words))] + "() error {\n\tif err != nil {\n\t\treturn fmt.Errorf(\"" + words[next(len(words))] + ": %w\", err)\n\t}\n}\n")
		case 8:
			b.WriteString(`{"id": ` + random("0123456789", 3) + `, "name": "` + words[next(len(words))] + `", "items": [1, 2, 3], "ok": true}` + "\n")
		case 9:
			b.WriteString("Grüße aus Köln, naïve café — 日本語のテキスト, ¿qué tal?\n")
		default:
			for range 6 + next(10) {
				b.WriteString(words[next(len(words))])
				b.WriteByte(" .,;="[next(5)])
				b.WriteByte(' ')
			}
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
})

// lowerCorpus is the corpus in lower case, as keywords are matched.
var lowerCorpus = sync.OnceValue(func() string { return strings.ToLower(string(corpus())) })
