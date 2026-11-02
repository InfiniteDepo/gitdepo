// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"errors"
	"regexp"
	"strings"
)

func init() {
	register(&Format{Ecosystem: NPM, match: func(b string) bool { return b == "pnpm-lock.yaml" }, parse: parsePnpmLock})
}

// pnpmDoc is what is read of the lockfile's document.
type pnpmDoc struct {
	version  string
	direct   map[string]map[string]bool // name -> the versions an importer resolves it to ("" if unknown)
	packages []pnpmPackage
}

type pnpmPackage struct {
	key, name, version string
}

// parsePnpmLock reads lockfile versions 5, 6 and 9. pnpm writes plain block-style YAML, so the file is read line
// by line: a YAML library builds a node tree of the whole document first, which costs about a hundred times the
// size of a hostile file (flow sequences such as `[0,0,0,...]` under any key). The line reader keeps only the keys
// it needs and counts every one.
//
// The reader accepts only the subset pnpm writes (see yamlgrammar.go), and fails closed (a parse error, never
// partial rows) on anything else, in every section: each line must be one of the forms of the grammar, the
// indentation 2 spaces a level, and the values that are read must be scalars that pnpm's YAML reader takes as the
// same text. The documents are chosen as @pnpm/lockfile.fs does: a file that starts with `---` holds the
// environment document pnpm 11 writes (its tooling, not read) up to the next `---` line, then the lockfile; any
// other `---` line is refused (pnpm's reader takes one document).
//
// A package is direct if an importer (the root project or a workspace project) lists it, with the version where the
// lockfile names one. Packages that are files or links on the disk are not listed.
func parsePnpmLock(s *sink, data []byte, _ Finder) error {
	sc := newYAMLScanner(s, data)
	doc := &pnpmDoc{direct: map[string]map[string]bool{}}
	bad := func() error { return parseErr("pnpm-lock.yaml: line %d", sc.n) }

	var blk yamlBlock
	var path []string    // the keys of the lines the current line is under, by depth
	var pkg *pnpmPackage // the package whose fields follow
	env, first := false, true
	qkey := -1 // the indentation of a `? key` line, whose `:` line is next
	for sc.Scan() {
		line := sc.Text()
		if first && line == "---" {
			env, first = true, false
			continue
		}
		first = false
		if line == "---" && env && sc.n == 2 {
			continue // pnpm looks for the end of the environment document after its first line
		}
		if line == "---" {
			if !env || qkey >= 0 || !blk.end() {
				return bad() // a second document in the lockfile
			}
			env, blk, path, pkg = false, yamlBlock{}, nil, nil
			continue
		}
		if line == "" {
			continue
		}
		indent, t := lineIndent(line)
		if t == "" || indent == 0 && (strings.HasPrefix(t, "---") || strings.HasPrefix(t, "...")) {
			return bad()
		}
		var key, value string // raw, as written
		isKey := false
		var m []string
		switch {
		case qkey >= 0:
			// the value of `? key`: `:` (the map follows), `: key:` or `: key: value` (its first line)
			if m = pnpmQValRe.FindStringSubmatch(t); m == nil || indent != qkey {
				return bad()
			}
			qkey = -1
			if m[1] == "" {
				blk = yamlBlock{indent: indent, open: true}
				continue
			}
			indent += 2
			key, value, isKey = m[1], m[2], true
			blk = yamlBlock{indent: indent, open: value == ""}
		case strings.HasPrefix(t, "? "):
			if m = pnpmQKeyRe.FindStringSubmatch(t); m == nil || !blk.line(indent, false) {
				return bad()
			}
			qkey, key = indent, m[1]
		case strings.HasPrefix(t, "- "):
			if m = pnpmItemRe.FindStringSubmatch(t); m == nil || !blk.line(indent, false) {
				return bad()
			}
		default:
			if m = pnpmPairRe.FindStringSubmatch(t); m == nil {
				m = pnpmKeyRe.FindStringSubmatch(t)
			}
			if m == nil {
				return bad()
			}
			key, isKey = m[1], true
			if len(m) > 2 {
				value = m[2]
			}
			if !blk.line(indent, value == "") {
				return bad()
			}
		}
		depth := indent / 2
		if isKey || qkey >= 0 {
			path = append(path[:min(depth, len(path))], unquoteYAML(key))
		}
		if env {
			continue
		}
		if err := doc.line(s, path, depth, key, value, isKey, qkey >= 0, &pkg); err != nil {
			if errors.Is(err, ErrParse) {
				return bad()
			}
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return scanErr(err, "pnpm-lock.yaml")
	}
	if env || qkey >= 0 || !blk.end() {
		return bad()
	}
	if s.info.Dirs == nil {
		s.info.Dirs = []string{"."} // a lockfile of one project has no importers
	}
	return doc.emitDependencies(s)
}

// line interprets one line of the lockfile document at depth (indentation / 2), under path (path[depth] is the
// line's own key). A sequence item has isKey false; explicit is a `? key` line. In the sections that are read, the
// lines down to the depth that is read must be keys, and the values read must be scalars; anything else is refused.
func (d *pnpmDoc) line(s *sink, path []string, depth int, raw, value string, isKey, explicit bool, pkg **pnpmPackage) error {
	bad := parseErr("pnpm-lock.yaml")
	if len(path) == 0 {
		return bad // a sequence item before any key
	}
	section := path[0]
	importers, packages, rootDeps := section == "importers", section == "packages", pnpmDepSection(section)
	readDepth := 0
	switch {
	case importers:
		readDepth = 4
	case packages, rootDeps:
		readDepth = 2
	}
	if depth > readDepth || depth > 0 && !importers && !packages && !rootDeps {
		return nil // inside a value nothing is read of
	}
	if !isKey && !(explicit && packages && depth == 1) {
		return bad // a sequence or an explicit key where pnpm writes a map
	}
	if plainTyped(raw) && depth > 0 {
		return bad // a key such as `1.0` or `true` that YAML reads as another text
	}
	flow := value != "" && (value[0] == '{' || value[0] == '[')
	scalar := func() (string, error) { // a value that is read: one line, a string for js-yaml
		if value == "" || flow || plainTyped(value) {
			return "", bad
		}
		return unquoteYAML(value), nil
	}
	key := path[depth]
	switch {
	case depth == 0:
		if (importers || packages || rootDeps) && value != "" && value != "{}" {
			return bad // a flow mapping, an alias or a scalar in place of the section
		}
		if key == "lockfileVersion" {
			if value == "" || flow || plainTyped(value) && !pnpmPlainVersion.MatchString(value) {
				return bad // `5.4` is a number for js-yaml, which a short decimal keeps as text with the same start
			}
			d.version = unquoteYAML(value)
		}
	case importers && depth == 1, importers && depth == 2 && pnpmDepSection(key):
		if value != "" && value != "{}" {
			return bad
		}
		if depth == 1 { // a project the lock was resolved for: the root (".") or a workspace member
			if err := s.entry(); err != nil {
				return err
			}
			s.info.Dirs = append(s.info.Dirs, key)
		}
	case importers && depth == 3 && pnpmDepSection(path[2]), rootDeps && depth == 1:
		if value != "" { // v5: `name: 1.2.3`
			v, err := scalar()
			if err != nil {
				return err
			}
			return d.addDirect(s, key, v)
		}
	case importers && depth == 4 && pnpmDepSection(path[2]), rootDeps && depth == 2:
		if key == "version" { // v6+: `version:` under the name
			v, err := scalar()
			if err != nil {
				return err
			}
			return d.addDirect(s, path[depth-1], v)
		}
	case packages && depth == 1:
		if value != "" {
			return bad // pnpm writes the fields of a package below it; a flow mapping is read differently
		}
		if err := s.entry(); err != nil || len(d.packages) >= s.maxRows {
			return cmpOr(err, ErrTooManyEntries)
		}
		d.packages = append(d.packages, pnpmPackage{key: key})
		*pkg = &d.packages[len(d.packages)-1]
	case packages && depth == 2 && *pkg != nil && (key == "name" || key == "version"):
		v, err := scalar()
		if err != nil {
			return err
		}
		if key == "name" {
			(*pkg).name = v
		} else {
			(*pkg).version = v
		}
	}
	return nil
}

// pnpmPlainVersion is a lockfileVersion written as a short decimal number (`5.4`), which js-yaml reads as a number
// whose text starts with the same digit (all that is used of it).
var pnpmPlainVersion = regexp.MustCompile(`^[1-9][0-9]?(?:\.[0-9]{1,3})?$`)

func pnpmDepSection(k string) bool {
	return k == "dependencies" || k == "devDependencies" || k == "optionalDependencies"
}

// addDirect records that an importer resolves name to value (`1.2.3`, `1.2.3(react@18)`, `link:../x`, `other@1.0.0`).
func (d *pnpmDoc) addDirect(s *sink, name, value string) error {
	if pnpmLocal(value) {
		return nil
	}
	version := strings.TrimPrefix(value, "/")
	if i := strings.IndexAny(version, "(_"); i >= 0 {
		version = version[:i]
	}
	if i := strings.LastIndex(version, "@"); i > 0 { // an alias: the real package is `other@1.0.0`
		name, version = version[:i], version[i+1:]
	}
	if d.direct[name] == nil {
		if err := s.entry(); err != nil {
			return err
		}
		d.direct[name] = map[string]bool{}
	}
	if !d.direct[name][version] {
		if err := s.entry(); err != nil {
			return err
		}
		d.direct[name][version] = true
	}
	return nil
}

// pnpmLocal tells a file, link or workspace reference from a registry version.
func pnpmLocal(s string) bool {
	return strings.HasPrefix(s, "link:") || strings.HasPrefix(s, "file:") || strings.HasPrefix(s, "workspace:") || strings.Contains(s, "@file:") || strings.Contains(s, "@link:")
}

func (d *pnpmDoc) emitDependencies(s *sink) error {
	oldKeys := strings.HasPrefix(d.version, "5") // name/version instead of name@version
	for _, p := range d.packages {
		if pnpmLocal(p.key) || pnpmLocal(p.version) || strings.HasPrefix(strings.TrimPrefix(p.key, "/"), "file:") {
			continue
		}
		name, version := pnpmKey(p.key, oldKeys)
		if p.name != "" {
			name = p.name
		}
		if p.version != "" {
			version = p.version
		}
		v := d.direct[name]
		// a git or tarball importer dependency names its source in the importer; the package key has the version
		pkgVersionKey := ""
		if _, kv := pnpmKey(p.key, oldKeys); kv != "" {
			pkgVersionKey = kv
		}
		direct := v != nil && (v[version] || v[""] || (pkgVersionKey != "" && v[pkgVersionKey]))
		if err := s.emit(Dependency{Name: name, Version: version, Direct: direct}); err != nil {
			return err
		}
	}
	return nil
}

// pnpmKey splits a key of "packages": `/name@1.2.3(peer@1)`, `name@1.2.3` or, in v5, `/@scope/name/1.2.3_peer`.
func pnpmKey(k string, old bool) (name, version string) {
	k = strings.TrimPrefix(k, "/")
	if old {
		i := strings.LastIndex(k, "/")
		if i < 0 {
			return k, ""
		}
		version, _, _ = strings.Cut(k[i+1:], "_")
		return k[:i], version
	}
	k, _, _ = strings.Cut(k, "(")
	if i := strings.LastIndex(k, "@"); i > 0 {
		return k[:i], k[i+1:]
	}
	return k, ""
}
