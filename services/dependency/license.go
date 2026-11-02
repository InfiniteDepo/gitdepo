// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"regexp"
	"strings"
	"sync"
)

var (
	spdxCanonical    = sync.OnceValue(func() map[string]string { return canonicalIDs(spdxLicenseIDs) })
	spdxExceptionMap = sync.OnceValue(func() map[string]string { return canonicalIDs(spdxExceptionIDs) })
	licenseToken     = regexp.MustCompile(`\(|\)|[^\s()]+`)
)

func canonicalIDs(ids []string) map[string]string {
	m := make(map[string]string, len(ids))
	for _, id := range ids {
		m[strings.ToLower(id)] = id
	}
	return m
}

// normalizeLicense returns the stored license text as a valid SPDX license expression: identifiers in their
// canonical case, AND/OR/WITH in capitals. ok is false for anything that isn't one (free text, LicenseRef, empty).
func normalizeLicense(s string) (expr string, ok bool) {
	toks := licenseToken.FindAllString(s, -1)
	if len(toks) == 0 || strings.Join(toks, "") != strings.Join(strings.Fields(s), "") {
		return "", false
	}
	p := &licenseParser{toks: toks}
	if !p.expr(0) || p.pos != len(toks) {
		return "", false
	}
	return strings.NewReplacer("( ", "(", " )", ")").Replace(strings.Join(p.out, " ")), true
}

type licenseParser struct {
	toks []string
	pos  int
	out  []string
}

func (p *licenseParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *licenseParser) expr(depth int) bool {
	if depth > 8 || !p.term(depth) {
		return false
	}
	for {
		op := strings.ToUpper(p.peek())
		if op != "AND" && op != "OR" {
			return true
		}
		p.pos++
		p.out = append(p.out, op)
		if !p.term(depth) {
			return false
		}
	}
}

func (p *licenseParser) term(depth int) bool {
	t := p.peek()
	if t == "" {
		return false
	}
	p.pos++
	if t == "(" {
		p.out = append(p.out, "(")
		if !p.expr(depth+1) || p.peek() != ")" {
			return false
		}
		p.pos++
		p.out = append(p.out, ")")
		return true
	}
	plus := strings.HasSuffix(t, "+")
	id, found := spdxCanonical()[strings.ToLower(strings.TrimSuffix(t, "+"))]
	if !found {
		return false
	}
	if plus {
		id += "+"
	}
	p.out = append(p.out, id)
	if strings.EqualFold(p.peek(), "WITH") {
		p.pos++
		ex, known := spdxExceptionMap()[strings.ToLower(p.peek())]
		if !known {
			return false // not an exception of the SPDX list (a license id after WITH is no exception either)
		}
		p.pos++
		p.out = append(p.out, "WITH", ex)
	}
	return true
}
