// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"bytes"
	"errors"

	"golang.org/x/mod/modfile"
)

func init() {
	register(&Format{Ecosystem: Go, Small: true, match: func(b string) bool { return b == "go.mod" }, parse: parseGoMod})
}

// parseGoMod lists the requirements; `// indirect` marks the transitive ones. A replace directive is not followed.
func parseGoMod(s *sink, data []byte, _ Finder) error {
	// the strict parser follows the replace directives; the lax one skips them (they only apply to a main module,
	// which this is) and is the fallback. A line that is not valid (say a v9 version without /v9) costs that line,
	// not the file: it is blanked and the rest parsed again.
	f, ok := parseModLines(s, data, func(d []byte) (*modfile.File, error) { return modfile.Parse("go.mod", d, nil) })
	if !ok {
		if f, ok = parseModLines(s, data, func(d []byte) (*modfile.File, error) { return modfile.ParseLax("go.mod", d, nil) }); !ok {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			return parseErr("go.mod")
		}
	}
	// a module replaced by a directory on the disk is part of the project, not a dependency
	local := map[string]bool{}
	for _, r := range f.Replace {
		if modfile.IsDirectoryPath(r.New.Path) {
			local[r.Old.Path+"@"+r.Old.Version] = true
		}
	}
	if len(f.Require) == 0 && !bytes.Contains(data, []byte("require")) && len(bytes.TrimSpace(data)) > 0 && f.Module == nil {
		return parseErr("go.mod") // nothing of it was valid
	}
	for _, r := range f.Require {
		if local[r.Mod.Path+"@"] || local[r.Mod.Path+"@"+r.Mod.Version] {
			continue
		}
		if err := s.emit(Dependency{Name: r.Mod.Path, Version: r.Mod.Version, Direct: !r.Indirect}); err != nil {
			return err
		}
	}
	return nil
}

// parseModLines parses data, blanking the lines the parser rejects (at most 50 rounds).
func parseModLines(s *sink, data []byte, parse func([]byte) (*modfile.File, error)) (*modfile.File, bool) {
	for range 50 {
		if s.ctx.Err() != nil {
			return nil, false
		}
		f, err := parse(data)
		if err == nil {
			return f, true
		}
		var list modfile.ErrorList
		if !errors.As(err, &list) {
			return nil, false
		}
		lines := bytes.Split(data, []byte("\n"))
		changed := false
		for _, e := range list {
			if e.Pos.Line >= 1 && e.Pos.Line <= len(lines) && len(bytes.TrimSpace(lines[e.Pos.Line-1])) > 0 {
				lines[e.Pos.Line-1] = nil
				changed = true
			}
		}
		if !changed {
			return nil, false
		}
		data = bytes.Join(lines, []byte("\n"))
	}
	return nil, false
}
