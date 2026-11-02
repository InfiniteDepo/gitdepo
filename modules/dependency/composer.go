// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"strings"

	"forgejo.org/modules/json"
)

func init() {
	register(&Format{Ecosystem: Packagist, match: func(b string) bool { return b == "composer.lock" }, parse: parseComposerLock})
}

// parseComposerLock reads packages and packages-dev, streamed: each package is emitted as it is read. A license
// array lists alternatives, so it becomes an SPDX "A OR B" expression. composer.lock doesn't say what the project
// requires: the direct packages are the ones the composer.json next to it requires (require and require-dev).
// Without a composer.json (or with one over the helper limits, see maxHelperKeys) none is marked direct.
func parseComposerLock(s *sink, data []byte, find Finder) error {
	var direct map[string]bool
	if cj := find("composer.json", false); cj != nil {
		direct, _ = helperParsed(s.ctx, "composer.json", cj, func() (map[string]bool, int64) {
			var c struct {
				Require    map[string]npmIgnored `json:"require"`
				RequireDev map[string]npmIgnored `json:"require-dev"`
			}
			if json.Unmarshal(cj, &c) != nil || len(c.Require)+len(c.RequireDev) > maxHelperKeys {
				return nil, 0
			}
			out, cost := map[string]bool{}, int64(0)
			for _, m := range []map[string]npmIgnored{c.Require, c.RequireDev} {
				for n := range m {
					out[strings.ToLower(n)] = true
					cost += int64(len(n)) + 64
				}
			}
			return out, cost
		})
	}
	j := newJSONStream(s, data)
	readPackage := func() error {
		var name, version, license string
		var path bool
		ok, err := j.object(func(f string) error {
			var err error
			switch f {
			case "name":
				name, err = j.str()
			case "version":
				version, err = j.str()
			case "license":
				license, err = j.license()
			case "dist":
				_, err = j.object(func(k string) error {
					if k != "type" {
						return j.skip()
					}
					t, err := j.str()
					path = t == "path"
					return err
				})
			default:
				err = j.skip()
			}
			return err
		})
		if err != nil || !ok || path { // a package from a path repository is part of the project, not a dependency
			return err
		}
		return s.emit(Dependency{Name: name, Version: version, License: license, Direct: direct[strings.ToLower(name)]})
	}
	ok, err := j.object(func(key string) error {
		if key != "packages" && key != "packages-dev" {
			return j.skip()
		}
		_, err := j.array(readPackage)
		return err
	})
	if err != nil {
		if isLimit(err) || s.ctx.Err() != nil {
			return err
		}
		return parseErr("composer.lock")
	}
	if !ok {
		return parseErr("composer.lock")
	}
	return nil
}
