// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"net/url"
	"regexp"
	"strings"
)

func init() {
	register(&Format{Ecosystem: NPM, match: func(b string) bool { return b == "yarn.lock" }, parse: parseYarnLock})
}

// parseYarnLock reads yarn.lock version 1 (`version "1.2.3"`) and the berry format (`version: 1.2.3`), told apart
// as yarn berry does: a file whose first comment lines say `# yarn lockfile v1` is version 1. The lock file doesn't
// say which packages the project asks for, so the direct ones come from the package.json next to it: a package is
// direct if one of its descriptors is exactly what the package.json asks for (`name@range`, in berry
// `name@npm:range`), so another version of the same package is not. An alias descriptor (`alias@npm:real@range`)
// names the real package. Workspaces and packages from the disk (link:, portal:, file:, workspace:) are not listed.
//
// Both readers accept only the lines yarn writes (see yamlgrammar.go) and fail closed on anything else: a header at
// column 0, fields 2 spaces deeper, nested maps 2 more, scalars complete on their line and without escapes, and no
// key twice where a later one would win in yarn's reader.
func parseYarnLock(s *sink, data []byte, find Finder) error {
	var asked map[string]string
	var workspaces []string
	if p := s.npmPackage(find("package.json", false)); p != nil {
		asked, workspaces = p.asked, p.workspaces
	}
	legacy := yarnLegacyRe.Match(data) // on the bytes as yarn reads them: a BOM in front makes it no version 1 file
	data, err := prepass(data, true)
	sc := scannerOf(s, data, err)
	if err == nil && legacy {
		// version 1 lists no workspaces: the lock covers the root and the workspaces its package.json declares
		s.info.Dirs, s.info.Globs = []string{"."}, workspaces
		err = parseYarnV1(s, sc, asked)
	} else {
		err = parseYarnBerry(s, sc, asked)
	}
	if err != nil {
		return err
	}
	return scanErr(sc.Err(), "yarn.lock")
}

// yarnLegacyRe is how yarn berry tells a version 1 lockfile: LEGACY_REGEXP of @yarnpkg/parsers,
// `/^(#.*(\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n/i`, written out with JavaScript's classes: `.` is anything but
// \n, \r, U+2028 and U+2029, `\s` holds the Unicode spaces (U+00A0, U+FEFF, ...), and /i without the u flag folds
// only ASCII letters (the Kelvin sign is no k).
var yarnLegacyRe = regexp.MustCompile(`\A(?:#[^\n\r\x{2028}\x{2029}]*\r?\n)*?#` + jsSpace + `+[yY][aA][rR][nN]` + jsSpace +
	`+[lL][oO][cC][kK][fF][iI][lL][eE]` + jsSpace + `+[vV]1\r?\n`)

// jsSpace is JavaScript's \s.
const jsSpace = `[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

// yarnKeySep splits the descriptors of a berry header as yarn does.
var yarnKeySep = regexp.MustCompile(` *, *`)

// berryLocatorRe splits a resolution `name@reference` (`@scope/name@npm:1.2.3`) as yarn's parseLocator does.
var berryLocatorRe = regexp.MustCompile(`^(?:@([^/]+?)/)?([^@/]+?)@(.+)$`)

// yarnDescriptor reads one descriptor of a header: the package it names (an alias `alias@npm:real@range` names the
// real one), whether it is on the disk, and whether the package.json asks for exactly it.
func yarnDescriptor(desc string, asked map[string]string) (real string, local, direct, ok bool) {
	alias, rng, ok := splitYarnDescriptor(desc)
	if !ok {
		return "", false, false, false
	}
	real = alias
	if r, found := strings.CutPrefix(rng, "npm:"); found {
		if i := strings.LastIndex(r, "@"); i > 0 {
			real = r[:i]
		}
	}
	want, asks := asked[alias]
	return real, yarnLocalRange(rng), asks && (want == rng || "npm:"+want == rng), true
}

// yarnPlainWord reports whether a word of a version 1 file is read as text: yarn's tokenizer reads a bare word
// that starts with `true` or `false` as a boolean, so yarn quotes those.
func yarnPlainWord(w string) bool {
	return w[0] == '"' || !strings.HasPrefix(w, "true") && !strings.HasPrefix(w, "false")
}

// parseYarnV1 reads the version 1 format: `a@^1, "b@^2":` headers, `key value` fields, `key:` for a nested map.
func parseYarnV1(s *sink, sc *lineScanner, asked map[string]string) error {
	bad := func() error { return parseErr("yarn.lock: line %d", sc.n) }
	var blk yamlBlock
	seen := map[string]bool{} // descriptors: yarn keeps the last entry of one
	var descs []string        // of the current entry
	var version string
	var fields map[string]bool
	flush := func() error {
		name, local, direct, found := "", false, false, false
		for _, d := range descs {
			real, l, dir, ok := yarnDescriptor(d, asked)
			if !ok {
				continue // yarn's object has the key, but it names no package
			}
			if found && (real != name || l != local) {
				return bad() // one entry for several packages: yarn reads each descriptor on its own
			}
			name, local, direct, found = real, l, direct || dir, true
		}
		descs = nil
		if !found || local {
			return nil
		}
		return s.emit(Dependency{Name: name, Version: version, Direct: direct})
	}
	afterBreak := true // after a blank or comment line yarn's parser reads only a header
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			afterBreak = true
			continue
		}
		indent, t := lineIndent(line)
		if afterBreak && indent != 0 {
			return bad()
		}
		afterBreak = false
		if indent == 0 {
			if err := flush(); err != nil {
				return err
			}
			m := v1HeadRe.FindStringSubmatch(t)
			if m == nil || !blk.line(0, true) {
				return bad()
			}
			for _, w := range v1ScalarRe.FindAllString(m[1], -1) {
				d := unquoteYAML(w)
				if !yarnPlainWord(w) || seen[d] {
					return bad()
				}
				if err := s.entry(); err != nil {
					return err
				}
				seen[d] = true
				descs = append(descs, d)
			}
			version, fields = "", map[string]bool{}
			continue
		}
		m := v1FieldRe.FindStringSubmatch(t)
		if m == nil || !yarnPlainWord(m[1]) || m[2] != "" && m[2] != "true" && m[2] != "false" && !yarnPlainWord(m[2]) || !blk.line(indent, m[2] == "") {
			return bad()
		}
		if indent == 2 {
			key := unquoteYAML(m[1])
			if fields[key] {
				return bad() // the later one would win in yarn's parser
			}
			fields[key] = true
			if key == "version" {
				if m[2] == "" || m[2][0] != '"' {
					return bad() // yarn quotes a version; a bare `1.0` is a number for its parser
				}
				version = unquoteYAML(m[2])
			}
		}
	}
	if !blk.end() {
		return bad()
	}
	return flush()
}

// berryEntry is an entry of a berry lockfile being read.
type berryEntry struct {
	header, version, resolution string
	fields                      map[string]bool
}

// parseYarnBerry reads the berry format, which is YAML: the package of an entry is the one its `resolution:`
// names (what yarn installs), and a `version:` that disagrees with an npm resolution is refused.
func parseYarnBerry(s *sink, sc *lineScanner, asked map[string]string) error {
	bad := func() error { return parseErr("yarn.lock: line %d", sc.n) }
	var blk yamlBlock
	headers := map[string]bool{} // a later entry of the same key would win in yarn's YAML reader
	var e *berryEntry
	flush := func() error {
		cur := e
		e = nil
		if cur == nil || cur.header == "__metadata" {
			return nil
		}
		m := berryLocatorRe.FindStringSubmatch(cur.resolution)
		if m == nil {
			return bad() // yarn refuses an entry without a resolution it can read
		}
		name, ref := berryName(m), m[3]
		if dir, ok := strings.CutPrefix(ref, "workspace:"); ok {
			s.info.Dirs = append(s.info.Dirs, dir) // a project the lock was resolved for
			return nil
		}
		name, version, local, ok := berryVersion(name, ref, cur.version)
		if !ok {
			return bad()
		}
		if local {
			return nil
		}
		direct := false
		for _, d := range yarnKeySep.Split(cur.header, -1) {
			_, _, dir, _ := yarnDescriptor(d, asked)
			direct = direct || dir
		}
		return s.emit(Dependency{Name: name, Version: version, Direct: direct})
	}
	qkey := false // a `? header` line, whose `:` line is next
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		indent, t := lineIndent(line)
		if qkey {
			if line != ":" {
				return bad()
			}
			qkey, blk = false, yamlBlock{open: true}
			continue
		}
		var m []string
		switch indent {
		case 0:
			if err := flush(); err != nil {
				return err
			}
			if qkey = strings.HasPrefix(t, "? "); qkey {
				m = berryQKeyRe.FindStringSubmatch(t)
			} else {
				m = berryHeadRe.FindStringSubmatch(t)
			}
			if m == nil || !blk.line(0, !qkey) {
				return bad()
			}
			header := unquoteYAML(m[1])
			if headers[header] {
				return bad()
			}
			if err := s.entry(); err != nil {
				return err
			}
			headers[header] = true
			e = &berryEntry{header: header, fields: map[string]bool{}}
			continue
		case 2:
			m = berryFieldRe.FindStringSubmatch(t) // a field key is plain: a quoted or `?` key is refused
		default:
			m = berryNestedRe.FindStringSubmatch(t)
		}
		if m == nil || e == nil || !blk.line(indent, m[2] == "") {
			return bad()
		}
		if indent == 2 {
			if e.fields[m[1]] {
				return bad()
			}
			e.fields[m[1]] = true
			switch m[1] {
			case "version":
				e.version = unquoteYAML(m[2])
			case "resolution":
				e.resolution = unquoteYAML(m[2])
			}
		}
	}
	if qkey || !blk.end() {
		return bad()
	}
	return flush()
}

// berryName is the package a berryLocatorRe match names.
func berryName(m []string) string {
	if m[1] != "" {
		return "@" + m[1] + "/" + m[2]
	}
	return m[2]
}

// berryVersion is the package and version a berry resolution of package name installs: an npm reference names the
// version (and the entry's `version:` must agree), a patch the package and version of the locator it patches (an
// aliased package, `ts@patch:@scope/ts6@npm%3A6.0.2#…`, is the real one), and a git or URL reference no version (its
// `version:` is what the package says of itself). local is true for the project's own packages (workspace:, link:,
// portal:, file:, exec:). ok is false for a reference that doesn't read as one.
func berryVersion(name, ref, version string) (real, v string, local, ok bool) {
	if yarnLocalRange(ref) || strings.HasPrefix(ref, "exec:") {
		return name, "", true, true
	}
	if r, found := strings.CutPrefix(ref, "npm:"); found {
		r, _, _ = strings.Cut(r, "::")
		return name, r, false, r == version
	}
	if r, found := strings.CutPrefix(ref, "patch:"); found {
		// `patch:name@npm%3A1.2.3#./patch::version=1.2.3&hash=...`: the patched locator, URL-encoded
		r, _, _ = strings.Cut(r, "#")
		inner, err := url.PathUnescape(r)
		if err != nil {
			return "", "", false, false
		}
		m := berryLocatorRe.FindStringSubmatch(inner)
		if m == nil || strings.HasPrefix(m[3], "patch:") {
			return "", "", false, false
		}
		return berryVersion(berryName(m), m[3], version)
	}
	return name, "", false, true
}

// splitYarnDescriptor splits `name@range` (the name may start with @scope/).
func splitYarnDescriptor(desc string) (name, rng string, ok bool) {
	if len(desc) < 2 {
		return "", "", false
	}
	i := strings.IndexByte(desc[1:], '@')
	if i < 0 {
		return "", "", false
	}
	return desc[:i+1], desc[i+2:], true
}

// yarnLocalRange tells the ranges that point at the disk or at the project itself.
func yarnLocalRange(r string) bool {
	r = strings.TrimPrefix(r, "npm:")
	for _, p := range []string{"workspace:", "link:", "portal:", "file:"} {
		if strings.HasPrefix(r, p) {
			return true
		}
	}
	return false
}
