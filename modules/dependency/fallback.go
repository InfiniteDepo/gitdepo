// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"bytes"
	"path"
	"regexp"
	"slices"
	"strings"
)

// The manifests read when no lock file covers them (Format.Unpinned): they list only the direct dependencies, each
// with the range it declares as its Requirement and no version. Nothing is resolved or evaluated: a Gemfile is
// read line by line for plain `gem "name", "range"` calls, the TOML files by the statement reader in toml.go.

func init() {
	register(&Format{
		Ecosystem: NPM, Small: true, Unpinned: true, Locks: []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}, cover: coverWorkspaces,
		match: func(b string) bool { return b == "package.json" }, parse: parsePackageJSON,
	})
	register(&Format{
		Ecosystem: Cargo, Small: true, Unpinned: true, Locks: []string{"Cargo.lock"}, cover: coverMembers,
		match: func(b string) bool { return b == "Cargo.toml" }, parse: parseCargoToml,
	})
	register(&Format{
		Ecosystem: RubyGems, Small: true, Unpinned: true, Locks: []string{"Gemfile.lock"},
		match: func(b string) bool { return b == "Gemfile" }, parse: parseGemfile,
	})
	register(&Format{
		Ecosystem: Packagist, Small: true, Unpinned: true, Locks: []string{"composer.lock"},
		match: func(b string) bool { return b == "composer.json" }, parse: parseComposerJSON,
	})
	register(&Format{
		Ecosystem: PyPI, Small: true, Unpinned: true, Locks: []string{"poetry.lock"}, // uv.lock has no reader, so it covers nothing
		match: func(b string) bool { return b == "pyproject.toml" }, parse: parsePyproject,
	})
}

// IsLockName reports whether a file of that base name is a lock file that covers an unpinned manifest.
func IsLockName(base string) bool {
	for _, f := range formats {
		if slices.Contains(f.Locks, base) {
			return true
		}
	}
	return false
}

// coverRule is how a lock file covers the manifests of a format.
type coverRule int

const (
	coverNextTo     coverRule = iota // the manifest next to it
	coverWorkspaces                  // npm: the projects it was resolved for (Info.Dirs, Info.Globs), in its directory or below
	coverMembers                     // Cargo: the manifest next to it, and below it the members it names (Info.Members)
)

// Covered reports whether a lock file the scan read covers the manifest at p. locks holds the lock files that
// parsed and gave rows, by path, with their Info; a lock that is missing, unread or empty covers nothing. own is
// the manifest's Info, nil before it is read: a Cargo.toml below a Cargo.lock is covered only when it names a
// member of that lock and is no workspace root itself, so the caller reads it and asks again.
func (f *Format) Covered(p string, locks map[string]*Info, own *Info) bool {
	mdir := pathDir(p)
	for dir := mdir; ; dir = pathDir(dir) {
		rel := "."
		if dir != mdir {
			rel = strings.TrimPrefix(mdir, pathJoin(dir, ""))
		}
		for _, l := range f.Locks {
			info := locks[pathJoin(dir, l)]
			switch {
			case info == nil:
			case f.cover == coverWorkspaces && (slices.Contains(info.Dirs, rel) || globsMatch(info.Globs, rel)):
				return true
			case f.cover != coverWorkspaces && rel == ".":
				return true
			case f.cover == coverMembers && own != nil && own.Name != "" && !own.OwnWorkspace && slices.Contains(info.Members, own.Name) &&
				globsMatch(info.Globs, rel) && !underAny(info.Excludes, rel):
				return true
			}
		}
		if f.cover == coverNextTo || dir == "" {
			return false
		}
	}
}

// LockAbove returns the nearest lock file in a directory that could cover the manifest at p and for which has is
// true (the locks the scan read), or "". A manifest that fell back below such a lock is not one of the projects
// that lock was resolved for. For formats whose lock covers only the manifest next to it, only that directory counts.
func (f *Format) LockAbove(p string, has func(path string) bool) string {
	for dir := pathDir(p); ; dir = pathDir(dir) {
		for _, l := range f.Locks {
			if lp := pathJoin(dir, l); has(lp) {
				return lp
			}
		}
		if f.cover == coverNextTo || dir == "" {
			return ""
		}
	}
}

// globsMatch reports whether dir matches one of the workspace patterns and none of their negations (`!x`). A
// pattern is matched segment by segment (`**` as one segment), so a member is never taken for more than yarn does;
// one that isn't matched is read on its own.
func globsMatch(globs []string, dir string) bool {
	found := false
	for _, g := range globs {
		neg := strings.HasPrefix(g, "!")
		g = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(g, "!"), "./"), "/")
		if ok, err := path.Match(g, dir); err == nil && ok {
			if neg {
				return false
			}
			found = true
		}
	}
	return found
}

// underAny reports whether dir is one of the directories or below one (Cargo's workspace.exclude).
func underAny(dirs []string, dir string) bool {
	for _, d := range dirs {
		d = strings.TrimSuffix(strings.TrimPrefix(d, "./"), "/")
		if dir == d || strings.HasPrefix(dir, d+"/") {
			return true
		}
	}
	return false
}

func pathDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

func pathJoin(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// npmFallbackKeys are the sections of a package.json read without a lock file (peer dependencies are the
// consumer's to install).
var npmFallbackKeys = map[string]bool{"dependencies": true, "devDependencies": true, "optionalDependencies": true}

// parsePackageJSON reads the dependency sections of a package.json. A local range (workspace:, file:, link:,
// a path) is the project's own and left out; an alias (`npm:real@^1`) is the real package; a git or URL range
// keeps the row without a requirement.
func parsePackageJSON(s *sink, data []byte, _ Finder) error {
	return jsonSections(s, data, "package.json", npmFallbackKeys, func(name, r string) error {
		if d, keep := npmRequirement(name, r); keep {
			return s.emit(d)
		}
		return nil
	})
}

// jsonSections reads the sections of a JSON manifest named in keys, each an object of name -> range (`[]` is an
// empty one), and calls row for each pair. A key given twice counts as the last one, as JSON.parse and
// json_decode read it: a later section replaces an earlier one, a later name in a section an earlier one.
func jsonSections(s *sink, data []byte, file string, keys map[string]bool, row func(name, r string) error) error {
	type pair struct{ name, r string }
	sections := map[string][]pair{}
	var order []string
	j := newJSONStream(s, bytes.TrimPrefix(data, utf8BOM))
	ok, err := j.object(func(key string) error {
		if !keys[key] {
			return j.skip()
		}
		var pairs []pair
		at := map[string]int{}
		ok, err := j.objectOr(true, func(name string) error {
			r, err := j.str()
			if err != nil {
				return err
			}
			if i, dup := at[name]; dup {
				pairs[i].r = r
				return nil
			}
			if err := s.entry(); err != nil {
				return err
			}
			at[name] = len(pairs)
			pairs = append(pairs, pair{name, r})
			return nil
		})
		if err == nil && !ok {
			return parseErr("%s: %s is no object", file, key)
		}
		if _, seen := sections[key]; !seen {
			order = append(order, key)
		}
		sections[key] = pairs
		return err
	})
	if err == nil && !ok {
		err = parseErr("%s", file)
	}
	if err != nil {
		return scanErr(err, file)
	}
	for _, key := range order {
		for _, p := range sections[key] {
			if err := row(p.name, p.r); err != nil {
				return err
			}
		}
	}
	return nil
}

func npmRequirement(name, r string) (Dependency, bool) {
	r = strings.TrimSpace(r)
	if yarnLocalRange(r) || strings.HasPrefix(r, ".") || strings.HasPrefix(r, "/") || strings.HasPrefix(r, "~/") {
		return Dependency{}, false
	}
	if rest, alias := strings.CutPrefix(r, "npm:"); alias {
		name, r = rest, ""
		if at := strings.LastIndexByte(rest, '@'); at > 0 {
			name, r = rest[:at], rest[at+1:]
		}
	}
	if strings.Contains(r, ":") || strings.Contains(r, "/") { // git+https://..., github:x/y, x/y, a tarball URL
		r = ""
	}
	return Dependency{Name: name, Requirement: r, Direct: true}, true
}

// parseComposerJSON reads require and require-dev; platform packages (php, ext-*, lib-*, composer-plugin-api)
// have no vendor and are left out.
func parseComposerJSON(s *sink, data []byte, _ Finder) error {
	return jsonSections(s, data, "composer.json", map[string]bool{"require": true, "require-dev": true}, func(name, r string) error {
		if !strings.Contains(name, "/") {
			return nil
		}
		return s.emit(Dependency{Name: strings.ToLower(name), Requirement: r, Direct: true})
	})
}

// tomlDep is a dependency of a TOML dependency table: its value (`name = "1.0"`) or its fields (an inline table,
// a [deps.name] table or dotted keys).
type tomlDep struct {
	name   string
	value  string
	fields map[string]string
}

// tomlSpec says which parts of a TOML manifest are read. table returns the length of the key path that names a
// dependency table (0 for none): the next key is a dependency, and one more a field of it. array returns the
// length of the key path of an array that is read (0 for none). parent tells a proper prefix of those paths
// (`project`, `target.'cfg(unix)'`): a value there, an inline table such as `project = {...}`, would hold what
// is read in a form this reader doesn't descend into, so it is a parse error. other, if set, sees every header
// and statement, with its full key path (and "" as the value of a header).
type tomlSpec struct {
	table, array func(path []string) int
	parent       func(path []string) bool
	other        func(path []string, value string)
}

// tomlDeps reads the dependency tables and arrays of a TOML manifest; the arrays come back in file order as (key
// path, raw value). Whatever it can't read inside the parts it reads is a parse error, never left out: a
// dependency or field given twice (as for cargo and poetry), an inline table at a parent level, a key below a
// dependency's fields or below an array, an array of tables there.
func tomlDeps(s *sink, data []byte, spec tomlSpec) ([]*tomlDep, [][2]string, error) {
	data, err := prepass(data, false)
	if err != nil {
		return nil, nil, err
	}
	var deps []*tomlDep
	byKey := map[string]*tomlDep{}
	var arrays [][2]string // key path, raw value
	dep := func(path []string, k int) (*tomlDep, error) {
		key := strings.Join(path[:k+1], "\x00")
		if d := byKey[key]; d != nil {
			return d, nil
		}
		if err := s.entry(); err != nil {
			return nil, err
		}
		d := &tomlDep{name: path[k]}
		byKey[key] = d
		deps = append(deps, d)
		return d, nil
	}
	r := &tomlReader{s: s, data: data}
	var header []string
	for {
		st, ok, err := r.next()
		if err != nil {
			return nil, nil, scanErr(err, "toml")
		}
		if !ok {
			return deps, arrays, nil
		}
		if st.Header {
			header = st.Key
			if spec.other != nil {
				spec.other(header, "")
			}
			k := spec.table(header)
			switch {
			case spec.array(header) > 0, st.Array && (k > 0 || spec.parent(header)):
				return nil, nil, parseErr("toml: a table where an array or a table is read") // [project.dependencies], [[dependencies]]
			case k > 0 && len(header) == k+1: // [dependencies.serde]
				d, err := dep(header, k)
				if err != nil {
					return nil, nil, err
				}
				if d.value != "" || d.fields != nil {
					return nil, nil, parseErr("toml: dependency defined twice")
				}
				d.fields = map[string]string{}
			}
			continue
		}
		full := append(append([]string(nil), header...), st.Key...)
		if spec.other != nil {
			spec.other(full, st.Value)
		}
		if spec.parent(full) {
			return nil, nil, parseErr("toml: %s as one value", strings.Join(full, ".")) // `project = {...}`
		}
		if a := spec.array(full); a > 0 {
			if len(full) > a {
				return nil, nil, parseErr("toml: a key below an array")
			}
			if err := s.entry(); err != nil {
				return nil, nil, err
			}
			arrays = append(arrays, [2]string{strings.Join(full, "."), st.Value})
			continue
		}
		k := spec.table(full)
		switch {
		case k == 0:
			continue
		case len(full) == k:
			return nil, nil, parseErr("toml: a dependency table as one value") // `dependencies = {...}`: not written by cargo or poetry
		}
		d, err := dep(full, k)
		if err != nil {
			return nil, nil, err
		}
		switch rest := full[k+1:]; {
		case len(rest) == 0:
			if d.value != "" || d.fields != nil {
				return nil, nil, parseErr("toml: dependency defined twice")
			}
			if strings.HasPrefix(st.Value, "{") {
				if d.fields, ok = tomlTable(s, st.Value); !ok {
					return nil, nil, parseErr("toml: inline table")
				}
			} else {
				d.value = st.Value
			}
		case len(rest) == 1:
			if d.value != "" {
				return nil, nil, parseErr("toml: dependency defined twice")
			}
			if d.fields == nil {
				d.fields = map[string]string{}
			}
			if _, dup := d.fields[rest[0]]; dup {
				return nil, nil, parseErr("toml: field defined twice")
			}
			if err := s.entry(); err != nil {
				return nil, nil, err
			}
			d.fields[rest[0]] = st.Value
		default:
			return nil, nil, parseErr("toml: a key below a dependency's field") // `serde.version.x = ...`
		}
	}
}

// tomlStr is the string a raw value holds; ok is false for any other value and for a string that doesn't decode.
func tomlStr(raw string) (string, bool) {
	if raw == "" || (raw[0] != '"' && raw[0] != '\'') {
		return "", false
	}
	return tomlUnquote(raw)
}

// tomlField is the string of a dependency's field, "" if it has none; a field that isn't a string is a parse error.
func tomlField(d *tomlDep, key string) (string, error) {
	raw, has := d.fields[key]
	if !has {
		return "", nil
	}
	v, ok := tomlStr(raw)
	if !ok {
		return "", parseErr("toml: field %s", key)
	}
	return v, nil
}

// pathHas reports whether p is want, an element of "" matching any key.
func pathHas(p []string, want ...string) bool {
	if len(p) != len(want) {
		return false
	}
	for i, w := range want {
		if w != "" && p[i] != w {
			return false
		}
	}
	return true
}

// tomlStrings reads an array of strings; ok is false for anything else.
func tomlStrings(s *sink, raw string) ([]string, bool) {
	items, err := tomlArray(s, raw)
	if err != nil {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		v, ok := tomlStr(item)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

var cargoDepTables = map[string]bool{"dependencies": true, "dev-dependencies": true, "build-dependencies": true, "dev_dependencies": true, "build_dependencies": true}

// parseCargoToml reads [dependencies], [dev-dependencies], [build-dependencies], their [target.X.*] forms and
// [workspace.dependencies]. A path dependency is the project's own; `package` renames; `workspace = true` takes
// the range from the workspace root, so the row has none. Info says which package it is and whether it is a
// workspace root, for the Cargo.lock above it (see Covered).
func parseCargoToml(s *sink, data []byte, _ Finder) error {
	badExclude := false
	deps, _, err := tomlDeps(s, data, tomlSpec{
		table: func(p []string) int {
			switch {
			case len(p) >= 1 && cargoDepTables[p[0]]:
				return 1
			case len(p) >= 2 && p[0] == "workspace" && p[1] == "dependencies":
				return 2
			case len(p) >= 3 && p[0] == "target" && cargoDepTables[p[2]]:
				return 3
			}
			return 0
		},
		array: func([]string) int { return 0 },
		parent: func(p []string) bool {
			return pathHas(p, "workspace") || pathHas(p, "target") || pathHas(p, "target", "")
		},
		other: func(p []string, value string) {
			if p[0] == "workspace" {
				s.info.OwnWorkspace = true
			}
			if pathHas(p, "workspace", "members") || pathHas(p, "workspace", "exclude") {
				list, ok := tomlStrings(s, value)
				switch {
				case p[1] == "members" && ok:
					s.info.Globs = list
				case p[1] == "exclude":
					s.info.Excludes = list
					badExclude = !ok
				}
			}
			if pathHas(p, "package", "name") {
				s.info.Name, _ = tomlStr(value) // not a string (`name.workspace = true`): no name, read on its own
			}
		},
	})
	if err != nil {
		return err
	}
	if badExclude {
		s.info.Globs = nil // an exclude list that can't be read: no member is known
	}
	for _, d := range deps {
		row := Dependency{Name: d.name, Direct: true}
		if d.fields == nil {
			var ok bool
			if row.Requirement, ok = tomlStr(d.value); !ok {
				return parseErr("Cargo.toml: dependency value")
			}
		} else {
			if _, local := d.fields["path"]; local {
				continue
			}
			if row.Requirement, err = tomlField(d, "version"); err != nil {
				return err
			}
			p, err := tomlField(d, "package")
			if err != nil {
				return err
			}
			if p != "" {
				row.Name = p
			}
		}
		if err := s.emit(row); err != nil {
			return err
		}
	}
	return nil
}

// pyDirectRef is a PEP 508 direct reference, `name @ url` (with extras): installed from that URL, not the index.
var pyDirectRef = regexp.MustCompile(`^(` + pyName + `)\s*(?:\[[^\]]*\])?\s*@`)

// parsePyproject reads the PEP 621 arrays (project.dependencies, project.optional-dependencies, PEP 735
// dependency-groups), uv's and PDM's dev arrays (tool.uv.dev-dependencies, tool.pdm.dev-dependencies.*) and
// poetry's dependency tables (tool.poetry.dependencies, dev-dependencies and groups), leaving out python itself and
// path dependencies. A direct reference (`name @ url`) is a row without a range. Hatch environments
// (tool.hatch.envs.*) are the tool's own environments, not the project's dependencies, and are not read.
func parsePyproject(s *sink, data []byte, _ Finder) error {
	deps, arrays, err := tomlDeps(s, data, tomlSpec{
		table: func(p []string) int {
			switch {
			case len(p) >= 3 && p[0] == "tool" && p[1] == "poetry" && (p[2] == "dependencies" || p[2] == "dev-dependencies"):
				return 3
			case len(p) >= 5 && p[0] == "tool" && p[1] == "poetry" && p[2] == "group" && p[4] == "dependencies":
				return 5
			}
			return 0
		},
		array: func(p []string) int {
			switch {
			case len(p) >= 2 && p[0] == "project" && p[1] == "dependencies", len(p) >= 2 && p[0] == "dependency-groups":
				return 2
			case len(p) >= 3 && p[0] == "project" && p[1] == "optional-dependencies":
				return 3
			case len(p) >= 3 && p[0] == "tool" && p[1] == "uv" && p[2] == "dev-dependencies":
				return 3
			case len(p) >= 4 && p[0] == "tool" && p[1] == "pdm" && p[2] == "dev-dependencies":
				return 4
			}
			return 0
		},
		parent: func(p []string) bool {
			return pathHas(p, "project") || pathHas(p, "project", "optional-dependencies") || pathHas(p, "dependency-groups") ||
				pathHas(p, "tool", "uv") || pathHas(p, "tool", "pdm") || pathHas(p, "tool", "pdm", "dev-dependencies") ||
				pathHas(p, "tool") || pathHas(p, "tool", "poetry") || pathHas(p, "tool", "poetry", "group") || pathHas(p, "tool", "poetry", "group", "")
		},
	})
	if err != nil {
		return err
	}
	for _, a := range arrays {
		items, err := tomlArray(s, a[1])
		if err != nil {
			return err
		}
		for _, item := range items {
			req, ok := tomlStr(item)
			if !ok {
				if strings.HasPrefix(a[0], "dependency-groups.") && strings.HasPrefix(item, "{") {
					continue // {include-group = "x"}: the requirements of another group, read there
				}
				return parseErr("pyproject.toml: %s holds no requirement", a[0])
			}
			req = strings.TrimSpace(req)
			d, ok := pyRequirement(req)
			if !ok {
				m := pyDirectRef.FindStringSubmatch(req)
				if m == nil {
					return parseErr("pyproject.toml: requirement")
				}
				d = Dependency{Name: m[1], Direct: true}
			}
			d.Version = ""
			if err := s.emit(d); err != nil {
				return err
			}
		}
	}
	for _, d := range deps {
		if strings.EqualFold(d.name, "python") {
			continue
		}
		row := Dependency{Name: d.name, Direct: true}
		switch {
		case d.fields != nil:
			if _, local := d.fields["path"]; local {
				continue
			}
			if row.Requirement, err = tomlField(d, "version"); err != nil {
				return err
			}
		case strings.HasPrefix(d.value, "["): // several constraints, by python version
		default:
			var ok bool
			if row.Requirement, ok = tomlStr(d.value); !ok {
				return parseErr("pyproject.toml: dependency value")
			}
		}
		if err := s.emit(row); err != nil {
			return err
		}
	}
	return nil
}

var (
	gemName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	gemCallHead = regexp.MustCompile(`^gem(?:[ \t(]|$)`)
	gemOption   = regexp.MustCompile(`^(?::([A-Za-z_][A-Za-z0-9_]*)\s*=>|([A-Za-z_][A-Za-z0-9_]*):(?:\s|$))`)
	gemModifier = regexp.MustCompile(`^(?:if|unless)\b`)
	rubyHeredoc = regexp.MustCompile(`<<([~-]?)(?:"(\w+)"|'(\w+)'|([A-Za-z_]\w*))`)
	// a gem call that doesn't start its line: after another statement, a block opener or a block's parameters
	gemCallInside = regexp.MustCompile(`(?:[;{(|]|\b(?:do|then|else|begin))\s*gem(?:[ \t(]|$)`)
)

// rubyCode is a line of Ruby without its comment and with every string literal emptied (`""`), except the quoted
// tag of a heredoc. ok is false when a string doesn't end on the line.
func rubyCode(t string) (code string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch c {
		case '#':
			return b.String(), true
		case '"', '\'':
			j := i + 1
			for ; j < len(t) && t[j] != c; j++ {
				if t[j] == '\\' {
					j++
				}
			}
			if j >= len(t) {
				return "", false
			}
			if cur := b.String(); strings.HasSuffix(cur, "<<") || strings.HasSuffix(cur, "<<~") || strings.HasSuffix(cur, "<<-") {
				b.WriteString(t[i : j+1])
			} else {
				b.WriteByte(c)
				b.WriteByte(c)
			}
			i = j
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// rubyString reads a string literal at the start of t: single-quoted or double-quoted without any escape or
// interpolation (anything else is no plain literal). It returns the content and the rest.
func rubyString(t string) (string, string, bool) {
	if t == "" || (t[0] != '"' && t[0] != '\'') {
		return "", "", false
	}
	end := strings.IndexByte(t[1:], t[0])
	if end < 0 {
		return "", "", false
	}
	v := t[1 : 1+end]
	if strings.ContainsRune(v, '\\') || strings.Contains(v, "#{") {
		return "", "", false
	}
	return v, t[2+end:], true
}

// rubyArgs splits the arguments of a call written without parentheses at the commas outside strings and brackets,
// up to a comment or a modifier (`if`, `unless`). ok is false when a string or a bracket doesn't end on the line or
// a `;` starts another statement; a last argument that is empty is a call continued on the next line.
func rubyArgs(t string) (args []string, ok bool) {
	depth, start := 0, 0
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c == '"' || c == '\'':
			j := i + 1
			for ; j < len(t) && t[j] != c; j++ {
				if t[j] == '\\' {
					j++
				}
			}
			if j >= len(t) {
				return nil, false
			}
			i = j
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth--; depth < 0 {
				return nil, false
			}
		case c == ';' || c == '#' && depth > 0:
			return nil, false
		case depth > 0:
		case c == ',':
			args, start = append(args, strings.TrimSpace(t[start:i])), i+1
		case c == '#' || (c == ' ' || c == '\t') && gemModifier.MatchString(t[i+1:]):
			return append(args, strings.TrimSpace(t[start:i])), true
		}
	}
	return append(args, strings.TrimSpace(t[start:])), depth == 0
}

// parseGemfile reads the calls `gem "name"[, "range"...][, option: value...]` on one line, wherever they are
// (groups and conditions, a modifier `if` included, are not evaluated, so a gem of any group or branch is listed);
// a version that isn't a plain string leaves the row without a range, and a gem with a path option is the
// project's own. Lines inside `=begin`/`=end` and after `__END__` are no code. A gem line in another form
// (`gem(...)`, a name that isn't a plain string, options continued on the next line, several statements, a call
// inside a block on one line, a gem line inside a heredoc) is counted in Info.Unread, so the page says the file
// was read only in part.
func parseGemfile(s *sink, data []byte, _ Finder) error {
	sc := newScanner(s, data)
	heredoc, indented, comment := "", false, false
	rubyMark := func(raw, mark string) bool {
		return strings.HasPrefix(raw, mark) && (len(raw) == len(mark) || raw[len(mark)] == ' ' || raw[len(mark)] == '\t')
	}
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		switch {
		case comment:
			comment = !rubyMark(raw, "=end")
			continue
		case heredoc != "":
			if line == heredoc && (indented || raw == heredoc) {
				heredoc = ""
			} else if gemCallHead.MatchString(line) {
				s.info.Unread++ // text to Ruby, unless the heredoc was misread: never hidden
			}
			continue
		case rubyMark(raw, "=begin"):
			comment = true
			continue
		case raw == "__END__":
			return scanErr(sc.Err(), "Gemfile")
		}
		code, codeOK := rubyCode(line)
		if m := rubyHeredoc.FindStringSubmatch(code); codeOK && m != nil {
			heredoc, indented = m[2]+m[3]+m[4], m[1] != ""
		}
		inside := codeOK && gemCallInside.MatchString(code)
		if !gemCallHead.MatchString(line) {
			if inside {
				s.info.Unread++
			}
			continue
		}
		d, local, ok := gemLine(strings.TrimLeft(line[3:], " \t"))
		if !ok || inside {
			s.info.Unread++
		}
		if ok && !local {
			if err := s.emit(d); err != nil {
				return err
			}
		}
	}
	if heredoc != "" || comment {
		return parseErr("Gemfile: unterminated heredoc or =begin")
	}
	return scanErr(sc.Err(), "Gemfile")
}

// gemLine reads the arguments of one `gem` call. local is true for a gem with a path option; ok is false for a
// call this reader can't read whole.
func gemLine(t string) (d Dependency, local, ok bool) {
	args, ok := rubyArgs(t)
	if !ok || strings.HasPrefix(t, "(") || args[len(args)-1] == "" {
		return d, false, false
	}
	name, rest, ok := rubyString(args[0])
	if !ok || strings.TrimSpace(rest) != "" || !gemName.MatchString(name) {
		return d, false, false
	}
	var ranges []string
	versions := true // the arguments before the options are versions
	for _, a := range args[1:] {
		m := gemOption.FindStringSubmatch(a)
		if m == nil {
			if !versions {
				return d, false, false // a version after an option
			}
			if r, rest, ok := rubyString(a); ok && strings.TrimSpace(rest) == "" {
				ranges = append(ranges, strings.TrimSpace(r))
			} else {
				ranges = nil // a version Ruby computes (`rack_version`): the row has no range
				versions = false
			}
			continue
		}
		versions = false
		if m[1] == "path" || m[2] == "path" {
			local = true
		}
	}
	return Dependency{Name: name, Requirement: strings.Join(ranges, ", "), Direct: true}, local, true
}
