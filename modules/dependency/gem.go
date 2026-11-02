// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"regexp"
	"strings"
)

func init() {
	register(&Format{Ecosystem: RubyGems, Small: true, match: func(b string) bool { return b == "Gemfile.lock" }, parse: parseGemfileLock})
}

// parseGemfileLock reads the specs of the GEM and GIT sections (PATH gems are the project's own); the names listed
// in DEPENDENCIES are direct.
func parseGemfileLock(s *sink, data []byte, _ Finder) error {
	var deps []Dependency
	section, inSpecs := "", false
	direct := map[string]bool{}
	sc := newScanner(s, data)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			section, inSpecs = strings.TrimSpace(line), false
			continue
		}
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case section == "DEPENDENCIES" && indent == 2:
			name, _, _ := strings.Cut(trimmed, " ")
			if err := s.entry(); err != nil {
				return err
			}
			direct[strings.TrimSuffix(name, "!")] = true
		case (section == "GEM" || section == "GIT") && indent == 2:
			inSpecs = trimmed == "specs:"
		case (section == "GEM" || section == "GIT") && inSpecs && indent == 4:
			name, rest, ok := strings.Cut(trimmed, " (")
			if ok {
				if err := s.entry(); err != nil {
					return err
				}
				deps = append(deps, Dependency{Name: name, Version: gemVersion(strings.TrimSuffix(rest, ")"))})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return scanErr(err, "Gemfile.lock")
	}
	for _, d := range deps {
		d.Direct = direct[d.Name]
		if err := s.emit(d); err != nil {
			return err
		}
	}
	return nil
}

// gemPlatform matches the platform suffix of a precompiled gem version (1.15.4-x86_64-linux); a prerelease such as
// 1.0.0-rc1 is not one.
var gemPlatform = regexp.MustCompile(`-(?:java|jruby|universal-[a-z0-9_.-]+|x86-[a-z0-9_.-]+|x86_64-[a-z0-9_.-]+|arm64-[a-z0-9_.-]+|aarch64-[a-z0-9_.-]+|arm-[a-z0-9_.-]+|mingw[a-z0-9_.-]*|mswin[a-z0-9_.-]*|x64-[a-z0-9_.-]+|ruby)$`)

func gemVersion(v string) string {
	return gemPlatform.ReplaceAllString(v, "")
}
