// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	maxRefFilterLen         = 2048
	maxRefFilterPatterns    = 100
	maxRefFilterPatternSize = 255
)

// NormalizeRefFilter validates a comma-separated list of ref patterns (names, or names with at most one `*`) and
// returns it trimmed and rejoined. An empty filter means "everything" and is returned as is. Empty patterns are
// refused, so a non-empty filter can never turn into "no refspec".
func NormalizeRefFilter(filter string) (string, error) {
	if filter == "" {
		return "", nil
	}
	if len(filter) > maxRefFilterLen {
		return "", fmt.Errorf("filter is longer than %d characters", maxRefFilterLen)
	}
	patterns := strings.Split(filter, ",")
	if len(patterns) > maxRefFilterPatterns {
		return "", fmt.Errorf("filter has more than %d patterns", maxRefFilterPatterns)
	}
	for i, p := range patterns {
		p = strings.TrimSpace(p)
		if err := validateRefPattern(p); err != nil {
			return "", fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		patterns[i] = p
	}
	return strings.Join(patterns, ","), nil
}

// validateRefPattern follows `git check-ref-format --refspec-pattern`, and refuses everything that isn't a plain
// name character so a pattern can never look like an option, a refspec modifier or shell syntax.
func validateRefPattern(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("empty pattern")
	case len(p) > maxRefFilterPatternSize:
		return fmt.Errorf("longer than %d characters", maxRefFilterPatternSize)
	case strings.Count(p, "*") > 1:
		return fmt.Errorf("more than one '*'")
	case strings.Contains(p, "..") || strings.Contains(p, "//") || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") ||
		strings.HasSuffix(p, ".") || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "+") || p == "@":
		return fmt.Errorf("not a valid ref name")
	}
	for c := range strings.SplitSeq(p, "/") {
		if strings.HasPrefix(c, ".") || strings.HasSuffix(c, ".lock") {
			return fmt.Errorf("not a valid ref name")
		}
	}
	for _, r := range p {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-/*+@#=%", r) {
			return fmt.Errorf("character %q is not allowed", r)
		}
	}
	return nil
}

// MatchRefFilter reports whether a short ref name (branch or tag name) matches the filter. As in git refspecs, `*`
// also matches `/`. An empty filter matches everything.
func MatchRefFilter(filter, name string) bool {
	if filter == "" {
		return true
	}
	for p := range strings.SplitSeq(filter, ",") {
		p = strings.TrimSpace(p)
		if pre, suf, ok := strings.Cut(p, "*"); ok {
			if len(name) >= len(pre)+len(suf) && strings.HasPrefix(name, pre) && strings.HasSuffix(name, suf) {
				return true
			}
		} else if p == name {
			return true
		}
	}
	return false
}

// RefSpecs returns the fetch refspecs for the mirror's filters (the validation runs again here and fails closed). A
// pattern without `*` is left out when exists is set and reports its full ref as missing upstream. The result is empty
// only when every pattern was left out.
func (m *Mirror) RefSpecs(exists func(fullRef string) bool) ([]string, error) {
	var specs []string
	for _, k := range []struct{ filter, prefix string }{{m.BranchFilter, "refs/heads/"}, {m.TagFilter, "refs/tags/"}} {
		if k.filter == "" {
			specs = append(specs, "+"+k.prefix+"*:"+k.prefix+"*")
			continue
		}
		filter, err := NormalizeRefFilter(k.filter)
		if err != nil {
			return nil, err
		}
		for p := range strings.SplitSeq(filter, ",") {
			ref := k.prefix + p
			if !strings.Contains(p, "*") && exists != nil && !exists(ref) {
				continue
			}
			specs = append(specs, "+"+ref+":"+ref)
		}
	}
	return specs, nil
}

// ExactRefs returns the full refs of the filters' patterns that have no `*`.
func (m *Mirror) ExactRefs() []string {
	var refs []string
	for _, k := range []struct{ filter, prefix string }{{m.BranchFilter, "refs/heads/"}, {m.TagFilter, "refs/tags/"}} {
		for p := range strings.SplitSeq(k.filter, ",") {
			if p = strings.TrimSpace(p); p != "" && !strings.Contains(p, "*") {
				refs = append(refs, k.prefix+p)
			}
		}
	}
	return refs
}

// HasFilter reports whether the mirror only fetches some refs.
func (m *Mirror) HasFilter() bool {
	return m.BranchFilter != "" || m.TagFilter != ""
}

// CheckDefaultBranchFilter refuses a branch filter that excludes the repository's default branch.
func CheckDefaultBranchFilter(branchFilter, defaultBranch string) error {
	if defaultBranch != "" && !MatchRefFilter(branchFilter, defaultBranch) {
		return fmt.Errorf("the default branch %q doesn't match the branch filter", defaultBranch)
	}
	return nil
}
