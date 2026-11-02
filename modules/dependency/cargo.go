// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"strings"
)

func init() {
	register(&Format{Ecosystem: Cargo, match: func(b string) bool { return b == "Cargo.lock" }, parse: parseCargoLock})
}

type cargoPackage struct {
	name, version, source string
	deps                  []string
}

// parseCargoLock reads the [[package]] tables. A package without a `source` belongs to the project itself (the root
// or a workspace member, or a path dependency) and is not a dependency; what such packages depend on is direct.
// The workspace members the lock covers come from the Cargo.toml next to it: without one that can be read, the
// lock covers no Cargo.toml below it.
func parseCargoLock(s *sink, data []byte, find Finder) error {
	if root := find("Cargo.toml", false); root != nil {
		rs := newSink(s.ctx, maxHelperKeys)
		if parseCargoToml(rs, root, nil) == nil {
			s.info.Globs, s.info.Excludes = rs.info.Globs, rs.info.Excludes
		}
	}
	var pkgs []*cargoPackage
	var cur *cargoPackage
	inDeps := false
	sc := newScanner(s, data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			if err := s.entry(); err != nil {
				return err
			}
			cur, inDeps = &cargoPackage{}, false
			pkgs = append(pkgs, cur)
		case cur == nil || line == "" || line[0] == '#':
		case line[0] == '[':
			cur = nil // [metadata], [[patch.unused]]
		case inDeps:
			if strings.HasPrefix(line, "]") {
				inDeps = false
				continue
			}
			if d := strings.Trim(strings.TrimSuffix(line, ","), `"`); d != "" {
				if err := s.entry(); err != nil {
					return err
				}
				cur.deps = append(cur.deps, d)
			}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "name":
				cur.name = tomlString(v)
			case "version":
				cur.version = tomlString(v)
			case "source":
				cur.source = tomlString(v)
			case "dependencies":
				inDeps = strings.TrimSpace(v) == "[" // a one-line array is written on one line only when empty
			}
		}
	}
	if err := sc.Err(); err != nil {
		return scanErr(err, "Cargo.lock")
	}
	direct := map[string]bool{} // "name" or "name version"
	for _, p := range pkgs {
		if p.source != "" {
			continue
		}
		if p.name != "" { // the root package or a workspace member: a Cargo.toml this lock covers
			s.info.Members = append(s.info.Members, p.name)
		}
		for _, d := range p.deps {
			f := strings.Fields(d)
			if len(f) >= 2 {
				if err := s.entry(); err != nil {
					return err
				}
				direct[f[0]+" "+f[1]] = true
			} else if len(f) == 1 {
				if err := s.entry(); err != nil {
					return err
				}
				direct[f[0]] = true
			}
		}
	}
	for _, p := range pkgs {
		if p.source == "" || p.name == "" {
			continue
		}
		if err := s.emit(Dependency{Name: p.name, Version: p.version, Direct: direct[p.name] || direct[p.name+" "+p.version]}); err != nil {
			return err
		}
	}
	return nil
}
