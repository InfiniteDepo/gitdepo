// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"strings"
)

func init() {
	register(&Format{Ecosystem: NuGet, Small: true, match: func(b string) bool { return strings.HasSuffix(b, ".csproj") && len(b) > len(".csproj") }, parse: parseCsproj})
	register(&Format{Ecosystem: NuGet, match: func(b string) bool { return b == "packages.lock.json" }, parse: parseNuGetLock})
}

type msbuildPackage struct {
	Include         string `xml:"Include,attr"`
	Version         string `xml:"Version,attr"`
	VersionOverride string `xml:"VersionOverride,attr"`
	VersionChild    string `xml:"Version"`
}

type msbuildProject struct {
	PropertyGroups []struct {
		Items []xmlProp `xml:",any"`
	} `xml:"PropertyGroup"`
	ItemGroups []struct {
		PackageReferences []msbuildPackage `xml:"PackageReference"`
		PackageVersions   []msbuildPackage `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

func (p *msbuildProject) props() map[string]string {
	m := map[string]string{}
	for _, g := range p.PropertyGroups {
		for _, x := range g.Items {
			m[x.XMLName.Local] = strings.TrimSpace(x.Value)
		}
	}
	return m
}

func (m msbuildPackage) version() string {
	if m.Version != "" {
		return m.Version
	}
	return m.VersionChild
}

// parseCsproj lists the PackageReference items. A reference without a version takes it from the nearest
// Directory.Packages.props (central package management) above the project; VersionOverride wins. $(Property) is
// resolved from the same file's properties, else the version is empty.
func parseCsproj(s *sink, data []byte, find Finder) error {
	var proj msbuildProject
	if err := decodeXML(data, &proj, "csproj"); err != nil {
		return err
	}
	props := proj.props()
	var central map[string]string
	if cd := find("Directory.Packages.props", true); cd != nil {
		// a broken props file, or one over maxHelperKeys, only costs the versions
		central, _ = helperParsed(s.ctx, "Directory.Packages.props", cd, func() (map[string]string, int64) {
			var cp msbuildProject
			if decodeXML(cd, &cp, "Directory.Packages.props") != nil {
				return nil, 0
			}
			cprops := cp.props()
			out, cost := map[string]string{}, int64(0)
			for _, g := range cp.ItemGroups {
				for _, v := range g.PackageVersions {
					if len(out) >= maxHelperKeys {
						return nil, 0
					}
					version := expandProps(strings.TrimSpace(v.version()), cprops, "$(", ")")
					out[strings.ToLower(v.Include)] = version
					cost += int64(len(v.Include)+len(version)) + 64
				}
			}
			return out, cost
		})
	}
	for _, g := range proj.ItemGroups {
		for _, r := range g.PackageReferences {
			name := strings.TrimSpace(r.Include)
			if name == "" {
				continue
			}
			v := strings.TrimSpace(r.VersionOverride)
			if v == "" {
				v = strings.TrimSpace(r.version())
			}
			if v == "" {
				v = central[strings.ToLower(name)]
			} else {
				v = expandProps(v, props, "$(", ")")
			}
			if err := s.emit(Dependency{Name: name, Version: v, Direct: true}); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseNuGetLock reads packages.lock.json, streamed: type Direct is direct, Transitive is not; "Project" entries
// (other projects of the solution) are not packages. A package in several target frameworks is one row.
func parseNuGetLock(s *sink, data []byte, _ Finder) error {
	j := newJSONStream(s, data)
	readFramework := func(string) error {
		_, err := j.object(func(name string) error {
			var typ, resolved string
			ok, err := j.object(func(f string) error {
				var err error
				switch f {
				case "type":
					typ, err = j.str()
				case "resolved":
					resolved, err = j.str()
				default:
					err = j.skip()
				}
				return err
			})
			if err != nil || !ok || typ == "Project" {
				return err
			}
			return s.emit(Dependency{Name: name, Version: resolved, Direct: typ == "Direct"})
		})
		return err
	}
	ok, err := j.object(func(key string) error {
		if key != "dependencies" {
			return j.skip()
		}
		_, err := j.object(readFramework)
		return err
	})
	if err != nil {
		if isLimit(err) || s.ctx.Err() != nil {
			return err
		}
		return parseErr("packages.lock.json")
	}
	if !ok {
		return parseErr("packages.lock.json")
	}
	return nil
}
