// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"bytes"
	"cmp"
	"fmt"
	"math"
	"slices"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	"forgejo.org/modules/keying"
)

const (
	// DefaultMaxContentSize is used when Detector.MaxContentSize is not set.
	DefaultMaxContentSize = 10 << 20
	// DefaultMaxMatchesPerRule is the number of findings one rule may report
	// per Scan, when Detector.MaxMatchesPerRule is not set. Only accepted
	// findings count: placeholders and other rejected matches never use it up.
	DefaultMaxMatchesPerRule = 100
	// DefaultMaxSecretLen is the longest secret reported (Rule.MaxSecretLen
	// overrides it): a longer capture is a bad pattern or not a secret.
	DefaultMaxSecretLen = 1 << 10
	// MinMaxWork and WorkPerByte give the default Detector.MaxWork: the
	// larger of MinMaxWork and WorkPerByte times the content length.
	MinMaxWork  = 16 << 20
	WorkPerByte = 3
	// MinCustomWork is the floor of the custom rules' own budget, which is
	// otherwise sized like the built-in rules' (see Detector.MaxWork): a small
	// file costs custom rules at most an eighth of what it may cost built-in
	// ones.
	MinCustomWork = 2 << 20
	// workChunk is the most bytes one regex call gets in a window rule, and
	// hitCheckCost the work units charged for one HitCheck.
	workChunk    = 64 << 10
	hitCheckCost = 64
	// hitCost is the work units charged for finding one keyword hit.
	hitCost = 16
	// callCost is the work units charged for every regex call, whatever its input
	// (the NFA setup and the match bookkeeping, about 2.5 microseconds).
	callCost = 700
	// MaxRejectedPerRule is how many matches of one rule a Scan may throw away
	// (placeholders, boundaries, low entropy) before the rule stops.
	MaxRejectedPerRule = 10000

	binarySniffLen = 8000 // as git
	lfsPointerHead = "version https://git-lfs.github.com/spec/v1"
	lfsBlobMax     = 1024 // as modules/lfs BlobSizeCutoff
)

// Finding is a secret found at a place. It never holds the secret: only its
// fingerprint, so printing or logging a Finding, however it is nested, can't
// leak it. Callers must never store or log the secret they scanned either.
type Finding struct {
	RuleID    string
	StartLine int // 1-based, line of the first byte of the secret; lines end at LF, as in git
	EndLine   int // 1-based, line of its last byte (PEM blocks span lines)
	StartCol  int // 1-based byte column in StartLine
	// Start and End are the byte offsets of the secret in the content as it was
	// scanned (for UTF-16 content, in its UTF-8 decoding).
	Start, End int
	// Fingerprint is Fingerprint(secret) (of the normalized secret, see
	// Rule.Normalize).
	Fingerprint string
}

// Detector scans content with a fixed set of rules. Set the limits right after
// NewDetector; after that a Detector may be used by many goroutines.
type Detector struct {
	// MaxContentSize cuts the content scanned (bytes); 0 or less means
	// DefaultMaxContentSize.
	MaxContentSize int
	// MaxMatchesPerRule is the findings per rule; 0 or less means
	// DefaultMaxMatchesPerRule.
	MaxMatchesPerRule int
	// MaxWork is the one CPU bound of a Scan. Every regex run is charged the
	// bytes it is given times the rule's cost (1 for a pass over the content
	// by a built-in rule, 8 for a window or a keyword hit, more for a custom
	// rule with a big program), in eighths of a byte: past MaxWork*8 the Scan
	// stops and returns complete=false. 0 or less means the larger of
	// MinMaxWork and WorkPerByte times the content length. The custom rules
	// have a budget of their own on top: MaxWork too when it is set, else the
	// larger of MinCustomWork and WorkPerByte times the content length.
	MaxWork int

	rules []*compiledRule
	gate  keywordGate
}

// NewDetector compiles rules. Which rules to pass is the caller's decision.
// Custom rules (made by CustomRule) run after the built-in ones, whatever
// the order given, so a built-in finding wins an overlap with a custom one
// (the first finding of a place is kept).
func NewDetector(rules []Rule) (*Detector, error) {
	d := &Detector{}
	// custom rules last (stable), so they can't starve the built-in ones
	rules = slices.SortedStableFunc(slices.Values(rules), func(a, b Rule) int { return boolInt(a.custom) - boolInt(b.custom) })
	custom := 0
	for _, r := range rules {
		if r.custom {
			custom++
		}
	}
	if custom > MaxCustomRules {
		return nil, fmt.Errorf("secretdetection: %d custom rules, at most %d", custom, MaxCustomRules)
	}
	for _, r := range rules {
		c, err := compileRule(r)
		if err != nil {
			return nil, err
		}
		c.keywordIDs = d.gate.add(r.Keywords)
		d.rules = append(d.rules, c)
	}
	return d, nil
}

// HasRule tells whether the detector runs the rule with that ID.
func (d *Detector) HasRule(id string) bool {
	return slices.ContainsFunc(d.rules, func(r *compiledRule) bool { return r.ID == id })
}

type rawFinding struct {
	rule        *compiledRule
	start, end  int
	fingerprint string
}

// Scan returns the secrets in content, ordered by position, and whether it
// looked at everything: complete is false when the content was cut at
// MaxContentSize, the MaxWork budget ran out, or a rule reached
// MaxMatchesPerRule or a custom rule MaxRejectedPerRule (so there may be more
// findings).
// Callers record that a scan was partial and must not treat it as clean.
// Binary content (a NUL byte in the first 8000 bytes, as git decides) and git
// LFS pointer files give nothing and count as complete. UTF-16 text (a byte
// order mark, or NULs on one side of every byte pair) is decoded first.
func (d *Detector) Scan(content []byte) (findings []Finding, complete bool) {
	maxSize := d.MaxContentSize
	if maxSize <= 0 {
		maxSize = DefaultMaxContentSize
	}
	maxFindings := d.MaxMatchesPerRule
	if maxFindings <= 0 {
		maxFindings = DefaultMaxMatchesPerRule
	}
	raw := content
	content, complete = text(raw, maxSize)
	if len(content) == 0 {
		return nil, complete
	}
	findings, ok := d.scanText(content, maxFindings)
	complete = complete && ok
	if bomWithoutNUL(raw) {
		// Decoded as UTF-16, but with no NUL in the first 8000 bytes it may
		// as well be a Latin-1 file that starts with FF FE: scan the bytes
		// too, and keep one finding per (rule, fingerprint).
		extra, ok := d.scanText(raw[:min(len(raw), maxSize)], maxFindings)
		complete = complete && ok
		seen := make(map[[2]string]bool, len(findings))
		for _, f := range findings {
			seen[[2]string{f.RuleID, f.Fingerprint}] = true
		}
		for _, f := range extra {
			if !seen[[2]string{f.RuleID, f.Fingerprint}] {
				findings = append(findings, f)
			}
		}
		sort.SliceStable(findings, func(i, j int) bool {
			return findings[i].StartLine < findings[j].StartLine ||
				findings[i].StartLine == findings[j].StartLine && findings[i].StartCol < findings[j].StartCol
		})
	}
	return findings, complete
}

// bomWithoutNUL: content starts with a UTF-16 byte order mark and has no NUL
// in its first 8000 bytes (CJK text, or not UTF-16 at all).
func bomWithoutNUL(content []byte) bool {
	return len(content) >= 2 && (content[0] == 0xFF && content[1] == 0xFE || content[0] == 0xFE && content[1] == 0xFF) &&
		bytes.IndexByte(content[:min(len(content), binarySniffLen)], 0) < 0
}

// scanText runs the rules on text that is UTF-8 (or taken as bytes).
func (d *Detector) scanText(content []byte, maxFindings int) (findings []Finding, complete bool) {
	complete = true
	lower := asciiLower(content)
	budget := d.MaxWork
	if budget <= 0 {
		budget = max(MinMaxWork, WorkPerByte*len(content))
	}
	budget *= 8
	customBudget := d.MaxWork
	if customBudget <= 0 {
		customBudget = max(MinCustomWork, WorkPerByte*len(content))
	}
	customBudget *= 8
	work := 0

	var macKey []byte
	var found []rawFinding
	var active []*compiledRule
	hits := d.gate.find(lower)
	firstHit := hits.first
	for _, r := range d.rules {
		if len(r.keywordIDs) == 0 || slices.ContainsFunc(r.keywordIDs, func(i int) bool { return firstHit[i] >= 0 }) {
			active = append(active, r)
		}
	}
	// ruleRun is one rule's progress, so that a rule that used up its share
	// can continue where it stopped.
	type ruleRun struct {
		r             *compiledRule
		accepted      int
		rejected      int
		done          bool
		ki, off, next int // anchored: keyword, search offset, end of the last match
		ranges        [][2]int
		haveRanges    bool
		ri, pos       int // windowed and whole-content: range and position in it
		inRange       bool
	}
	runs := make([]*ruleRun, len(active))
	for i, r := range active {
		runs[i] = &ruleRun{r: r}
	}
	// run works on one rule until it is finished or `work` passes limit, and
	// says whether the rule is finished.
	run := func(st *ruleRun, limit int) bool {
		r := st.r
		maxLen := r.MaxSecretLen
		if maxLen <= 0 {
			maxLen = DefaultMaxSecretLen
		}
		// handle takes one match (offsets relative to base) and says whether
		// the rule is done for this Scan.
		handle := func(base int, m []int) (stop bool) {
			start, end := m[2*r.SecretGroup], m[2*r.SecretGroup+1]
			if start < 0 || end <= start {
				return false
			}
			start, end = start+base, end+base
			secret := content[start:end]
			ok := (!r.KeywordInMatch || hasKeyword(lower[base+m[0]:base+m[1]], r.Keywords)) &&
				end-start <= maxLen && r.boundaryOK(content, start, end)
			if ok && r.Normalize != nil {
				secret = r.Normalize(secret)
				ok = len(secret) > 0
			}
			if ok {
				ok = len(secret) >= r.MinSecretLen && r.accepts(secret) && !overlaps(found, start, end)
			}
			if !ok {
				if st.rejected++; r.RejectCap > 0 && st.rejected >= r.RejectCap {
					complete = false
					return true
				}
				return false
			}
			if macKey == nil {
				macKey = keying.MACKey(keying.SecretScanning)
			}
			found = append(found, rawFinding{r, start, end, fingerprint(macKey, secret)})
			if st.accepted++; st.accepted >= maxFindings {
				complete = false
				return true
			}
			return false
		}
		if r.Anchored {
			// The match starts at a keyword hit: try the anchored regex on
			// the bytes after it, which costs a few bytes per hit and not a
			// pass over everything between hits.
			for ; st.ki < len(r.Keywords); st.ki, st.off, st.next = st.ki+1, 0, 0 {
				k := r.Keywords[st.ki]
				// The search starts at the keyword's first hit, and a keyword
				// the gate didn't see costs nothing.
				first := firstHit[r.keywordIDs[st.ki]]
				if first < 0 {
					continue
				}
				st.off = max(st.off, first)
				for {
					if work > limit {
						return false
					}
					p := hits.next(r.keywordIDs[st.ki], st.off)
					if p < 0 {
						break
					}
					st.off = p + 1
					start := p - r.KeywordOffset
					if p < st.next || start < 0 {
						continue
					}
					if r.HitCheck != nil {
						work += hitCheckCost
						if !r.HitCheck(lower, content, p) {
							continue
						}
					}
					win := content[start:min(len(content), p+len(k)+r.Window)]
					m := r.anchored.FindSubmatchIndex(win)
					// charge what the regex read: up to the match end, or the
					// whole window when it found nothing
					work += callCost
					if m == nil {
						work += len(win) * r.cost
						continue
					}
					work += m[1] * r.cost
					st.next = start + max(m[1], 1)
					if handle(start, m) {
						return true
					}
				}
			}
			return true
		}
		if !st.haveRanges {
			ranges, spent, ok := r.ranges(len(lower), firstHit, hits, limit-work)
			work += spent
			if !ok {
				return false
			}
			st.ranges, st.haveRanges = ranges, true
		}
		for ; st.ri < len(st.ranges); st.ri, st.inRange = st.ri+1, false {
			rg := st.ranges[st.ri]
			if !st.inRange {
				st.pos, st.inRange = rg[0], true
			}
			// One match at a time, so memory stays O(findings) however many
			// matches the rule rejects.
			for st.pos < rg[1] {
				if work > limit {
					return false
				}
				// A window rule gets the regex in pieces of workChunk bytes
				// that overlap by Window, so no single call can run far past
				// the budget; a match that starts in the overlap is found in
				// the next piece.
				// The piece is no bigger than what is left of the rule's share,
				// so a call can't run far past it.
				size := min(workChunk, max(2*r.Window+64, (limit-work)/r.cost))
				end, last := rg[1], true
				if r.Window > 0 && end-st.pos > size {
					end, last = st.pos+size, false
				}
				m := r.re.FindSubmatchIndex(content[st.pos:end])
				work += callCost
				if m == nil {
					work += (end - st.pos) * r.cost
				} else {
					work += m[1] * r.cost
				}
				if m == nil || !last && m[0] >= end-st.pos-r.Window {
					if last {
						break
					}
					st.pos = end - r.Window
					continue
				}
				base := st.pos
				st.pos += max(m[1], 1)
				if handle(base, m) {
					return true
				}
			}
		}
		return true
	}
	// First every rule runs on its fair share of what is left (a rule that
	// needs less passes the rest on), so decoys for early rules can't starve
	// later ones; then the work that is left goes to the rules that stopped,
	// each continuing where it stopped.
	share := func(runs []*ruleRun, budget int) {
		work = 0
		for i, st := range runs {
			if work >= budget {
				break
			}
			st.done = run(st, work+(budget-work)/(len(runs)-i))
		}
		for i, st := range runs {
			if st.done {
				continue
			}
			if work >= budget {
				break
			}
			stopped := 0
			for _, s := range runs[i:] {
				if !s.done {
					stopped++
				}
			}
			st.done = run(st, work+(budget-work)/stopped)
		}
	}
	// The built-in rules have the whole budget; the custom ones (last, see
	// NewDetector) their own, so they can never take work from a built-in rule.
	builtin := len(runs)
	for i, st := range runs {
		if st.r.custom {
			builtin = i
			break
		}
	}
	share(runs[:builtin], budget)
	share(runs[builtin:], customBudget)
	for _, st := range runs {
		if !st.done {
			complete = false
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].start < found[j].start })

	// One forward pass over the content turns offsets into lines, so memory
	// stays O(findings) however many lines there are.
	findings = make([]Finding, len(found))
	pos, line, lineStart := 0, 1, 0
	for i, f := range found {
		line += bytes.Count(content[pos:f.start], []byte("\n"))
		if nl := bytes.LastIndexByte(content[pos:f.start], '\n'); nl >= 0 {
			lineStart = pos + nl + 1
		}
		pos = f.start
		findings[i] = Finding{
			RuleID:      cmp.Or(f.rule.ReportAs, f.rule.ID),
			StartLine:   line,
			EndLine:     line + bytes.Count(content[f.start:f.end-1], []byte("\n")),
			StartCol:    f.start - lineStart + 1,
			Start:       f.start,
			End:         f.end,
			Fingerprint: f.fingerprint,
		}
	}
	return findings, complete
}

// text returns the content to scan as UTF-8, cut to maxSize bytes (complete is
// false then), or nothing if there is nothing to scan: binary, an LFS pointer
// or empty. A file with a byte order mark is UTF-16 (CJK text has no NUL);
// one without is tried as UTF-16 only if it has a NUL in its first 8000 bytes
// and the NULs sit on one side of the byte pairs, as in UTF-16 ASCII text.
func text(content []byte, maxSize int) (out []byte, complete bool) {
	hasBOM := len(content) >= 2 && (content[0] == 0xFF && content[1] == 0xFE || content[0] == 0xFE && content[1] == 0xFF)
	if hasBOM || bytes.IndexByte(content[:min(len(content), binarySniffLen)], 0) >= 0 {
		bigEndian, bom, ok := utf16Order(content)
		if !ok {
			return nil, true // binary
		}
		body := content[2*boolInt(bom):]
		cut := len(body) > maxSize
		decoded := decodeUTF16(body[:min(len(body), maxSize)], bigEndian, cut)
		if len(decoded) == 0 {
			return nil, false // there was a body and nothing could be read from it
		}
		if len(decoded) > maxSize {
			return decoded[:maxSize], false
		}
		return decoded, !cut
	}
	if isLFSPointer(content) {
		return nil, true
	}
	if len(content) > maxSize {
		return content[:maxSize], false
	}
	return content, true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// utf16Order says whether content (which has a NUL in its first 8000 bytes)
// is UTF-16, and its byte order: a byte order mark decides, else the NULs
// must be in the high (or low) byte of at least a quarter of the byte pairs
// and almost never in the other byte. UTF-32 and other binary data fail both.
func utf16Order(content []byte) (bigEndian, bom, ok bool) {
	if len(content) >= 2 {
		switch {
		case content[0] == 0xFF && content[1] == 0xFE:
			return false, true, true
		case content[0] == 0xFE && content[1] == 0xFF:
			return true, true, true
		}
	}
	sniff := content[:min(len(content), binarySniffLen)]
	pairs, evenNUL, oddNUL := len(sniff)/2, 0, 0
	for i := 0; i+1 < len(sniff); i += 2 {
		if sniff[i] == 0 {
			evenNUL++
		}
		if sniff[i+1] == 0 {
			oddNUL++
		}
	}
	switch {
	case oddNUL*4 >= pairs && evenNUL*10 <= oddNUL:
		return false, false, true
	case evenNUL*4 >= pairs && oddNUL*10 <= evenNUL:
		return true, false, true
	}
	return false, false, false
}

// decodeUTF16 decodes b to UTF-8 the way readers with replacement do: an odd
// last byte is dropped and an unpaired surrogate becomes U+FFFD, so a key in
// the valid part of a damaged file is still found. If cut, b ends where the
// size limit fell and a high surrogate in the last unit is dropped.
func decodeUTF16(b []byte, bigEndian, cut bool) []byte {
	n := len(b) / 2
	unit := func(i int) rune {
		if bigEndian {
			return rune(b[2*i])<<8 | rune(b[2*i+1])
		}
		return rune(b[2*i+1])<<8 | rune(b[2*i])
	}
	out := make([]byte, 0, n*3/2+4) // at most 3 bytes per unit
	for i := 0; i < n; i++ {
		switch u := unit(i); {
		case 0xD800 <= u && u < 0xDC00:
			switch {
			case i+1 < n && 0xDC00 <= unit(i+1) && unit(i+1) < 0xE000:
				out = utf8.AppendRune(out, utf16.DecodeRune(u, unit(i+1)))
				i++
			case i+1 == n && cut:
			default:
				out = utf8.AppendRune(out, utf8.RuneError)
			}
		case 0xDC00 <= u && u < 0xE000:
			out = utf8.AppendRune(out, utf8.RuneError)
		default:
			out = utf8.AppendRune(out, u)
		}
	}
	return out
}

// isLFSPointer is true for what git-lfs writes as a pointer (the checks of
// modules/lfs ReadPointerFromBuffer): at most 1024 bytes, the version line
// exactly, an "oid sha256:<64 hex>" line and a "size <n>" line. Anything else
// that starts with the version line is a file like any other.
func isLFSPointer(content []byte) bool {
	if len(content) > lfsBlobMax || !bytes.HasPrefix(content, []byte(lfsPointerHead)) {
		return false
	}
	lines := bytes.Split(content, []byte("\n"))
	if len(lines) < 3 || len(lines) > 4 || len(lines) == 4 && len(lines[3]) > 0 ||
		string(lines[0]) != lfsPointerHead ||
		!bytes.HasPrefix(lines[1], []byte("oid sha256:")) || len(lines[1]) != len("oid sha256:")+64 {
		return false
	}
	for _, c := range lines[1][len("oid sha256:"):] {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	size := bytes.TrimPrefix(lines[2], []byte("size "))
	if len(size) == 0 {
		return false
	}
	for _, c := range size {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ranges returns the byte ranges the rule's regex runs on: all of the content,
// or for a rule with a Window the windows around keyword hits, merged.
// firstHit is where each keyword of the gate first occurs (-1: nowhere).
// Finding the windows costs hitCost work units per keyword hit; ok is false
// when that is more than allow.
func (r *compiledRule) ranges(n int, firstHit []int, hits *keywordHits, allow int) (out [][2]int, spent int, ok bool) {
	if r.Window <= 0 {
		return [][2]int{{0, n}}, 0, true
	}
	for ki, k := range r.Keywords {
		if firstHit[r.keywordIDs[ki]] < 0 {
			continue
		}
		// Windows of one keyword, merged as they come.
		var cur [2]int
		have := false
		for off := firstHit[r.keywordIDs[ki]]; ; {
			p := hits.next(r.keywordIDs[ki], off)
			if p < 0 {
				break
			}
			off = p + 1
			if spent += hitCost; spent > allow {
				return nil, spent, false
			}
			lo, hi := max(0, p-r.Window), min(n, p+len(k)+r.Window)
			if have && lo <= cur[1] {
				cur[1] = hi
				continue
			}
			if have {
				out = append(out, cur)
			}
			cur, have = [2]int{lo, hi}, true
		}
		if have {
			out = append(out, cur)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	merged := out[:0]
	for _, w := range out {
		if n := len(merged); n > 0 && w[0] <= merged[n-1][1] {
			merged[n-1][1] = max(merged[n-1][1], w[1])
			continue
		}
		merged = append(merged, w)
	}
	return merged, spent, true
}

// accepts checks the secret itself, never the text around it: context such as
// XML tags or a template next to a real key must not drop it.
func (r *compiledRule) accepts(secret []byte) bool {
	if r.MinEntropy > 0 && (entropy(secret) < r.MinEntropy || r.Type != "generic" && ascending(secret, 10)) {
		return false
	}
	for _, a := range r.allowlist {
		if a.Match(secret) {
			return false
		}
	}
	return r.Check == nil || r.Check(secret)
}

// ascending: b has a run of n bytes that each follow the one before
// (0123456789, abcdefghij), a placeholder however high its entropy. People
// choose such runs in passwords, so the generic rules don't use it.
func ascending(b []byte, n int) bool {
	for i, k := 1, 1; i < len(b); i++ {
		if b[i] == b[i-1]+1 {
			k++
		} else {
			k = 1
		}
		if k >= n {
			return true
		}
	}
	return false
}

// overlaps: a secret overlapping one already found is the same secret, the
// first rule wins.
func overlaps(found []rawFinding, start, end int) bool {
	for _, f := range found {
		if start < f.end && f.start < end {
			return true
		}
	}
	return false
}

// asciiLower lowers A-Z only, so offsets stay the same as in content.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// keywordGate tells which keywords occur in a text in one pass over it, by
// their first two bytes, instead of one search per keyword (with a hundred
// rules that was most of the time of a scan). first holds the index+1 of the
// bucket of a byte pair (an array, not a map: a map lookup per byte pair was
// most of the time of the pass).
type keywordGate struct {
	words   []string
	ids     map[string]int
	first   [1 << 16]uint16
	buckets [][]int
	third   [][4]uint64 // by bucket, the third bytes of its keywords (all for a two-byte one)
	single  []int       // one-byte keywords
}

// add registers keywords and returns their IDs.
func (g *keywordGate) add(keywords []string) []int {
	if g.ids == nil {
		g.ids = map[string]int{}
	}
	out := make([]int, 0, len(keywords))
	for _, k := range keywords {
		id, ok := g.ids[k]
		if !ok {
			id = len(g.words)
			g.words = append(g.words, k)
			g.ids[k] = id
			if len(k) == 1 {
				g.single = append(g.single, id)
			} else {
				b := uint16(k[0])<<8 | uint16(k[1])
				if g.first[b] == 0 {
					if len(g.buckets) == math.MaxUint16 {
						panic("secretdetection: more keyword byte pairs than the gate holds")
					}
					g.buckets = append(g.buckets, nil)
					g.third = append(g.third, [4]uint64{})
					g.first[b] = uint16(len(g.buckets))
				}
				g.buckets[g.first[b]-1] = append(g.buckets[g.first[b]-1], id)
				if t := &g.third[g.first[b]-1]; len(k) == 2 {
					*t = [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
				} else {
					t[k[2]>>6] |= 1 << (k[2] & 63)
				}
			}
		}
		out = append(out, id)
	}
	return out
}

// find finds where each keyword occurs in lower, in one pass: by keyword ID
// the first occurrence (-1: nowhere) and, up to the hit limit, all of them.
func (g *keywordGate) find(lower []byte) *keywordHits {
	n := len(g.words)
	h := &keywordHits{lower: lower, words: g.words, first: make([]int, n), at: make([][]int32, n), from: make([]int, n), limit: len(lower)/16 + keptHitsBase}
	if len(lower) > math.MaxInt32 {
		h.limit = 0 // offsets are kept as int32
	}
	first := h.first
	for i := range first {
		first[i] = -1
	}
	left := n
	// open counts the keywords of each bucket not seen yet: once the hit
	// limit is reached, a bucket whose keywords were all seen costs no more
	// comparisons.
	open := make([]int, len(g.buckets))
	for i, b := range g.buckets {
		open[i] = len(b)
	}
	for _, id := range g.single {
		if first[id] = bytes.IndexByte(lower, g.words[id][0]); first[id] >= 0 {
			left--
		}
	}
	// done is where collecting all hits stopped: the lists are complete
	// before it, and next searches on from there.
	done := len(lower)
	collect := true
	for p := 0; p+1 < len(lower) && (left > 0 || collect); p++ {
		bucket := g.first[uint16(lower[p])<<8|uint16(lower[p+1])]
		if bucket == 0 || p+2 < len(lower) && g.third[bucket-1][lower[p+2]>>6]&(1<<(lower[p+2]&63)) == 0 || !collect && open[bucket-1] == 0 {
			continue
		}
		for _, id := range g.buckets[bucket-1] {
			// the third byte first: most keywords that share a pair differ there
			if w := g.words[id]; (collect || first[id] < 0) && (len(w) < 3 || p+2 < len(lower) && lower[p+2] == w[2]) && bytes.HasPrefix(lower[p:], []byte(w)) {
				if first[id] < 0 {
					first[id] = p
					open[bucket-1]--
					left--
				}
				if collect {
					h.at[id] = append(h.at[id], int32(p))
					h.total++
				}
			}
		}
		if collect && h.total >= h.limit {
			collect, done = false, p+1
		}
	}
	for id := range h.from {
		h.from[id] = done
	}
	for _, id := range g.single {
		h.from[id] = first[id]
		if first[id] < 0 {
			h.from[id] = len(lower)
		}
	}
	return h
}

// keptHitsBase plus a 16th of the content length is how many keyword hits a
// scan keeps (a variable for tests).
var keptHitsBase = 1024

// keywordHits are the keyword occurrences of one scan, shared by its rules,
// so a keyword that several rules use is searched once. at holds a keyword's
// occurrences in order, every one before from. At most about limit are kept
// in all, as int32: a quarter of the content's size live, and up to about
// four times that allocated while the lists grow.
type keywordHits struct {
	lower        []byte
	words        []string
	first        []int
	at           [][]int32
	from         []int
	total, limit int
}

// next returns the first occurrence of keyword id at or after off (-1: none).
func (h *keywordHits) next(id, off int) int {
	at := h.at[id]
	if len(at) > 0 && off <= int(at[len(at)-1]) {
		i, _ := slices.BinarySearch(at, int32(off))
		return int(at[i])
	}
	from := min(max(off, h.from[id]), len(h.lower))
	p := bytes.Index(h.lower[from:], []byte(h.words[id]))
	if p >= 0 {
		p += from
	}
	// Only a search that goes on from where the kept ones end is kept.
	if from == h.from[id] && h.total < h.limit {
		if p < 0 {
			h.from[id] = len(h.lower)
		} else {
			h.at[id], h.from[id] = append(at, int32(p)), p+1
			h.total++
		}
	}
	return p
}

func hasKeyword(lower []byte, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, k := range keywords {
		if bytes.Contains(lower, []byte(k)) {
			return true
		}
	}
	return false
}
