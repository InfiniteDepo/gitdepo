// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"maps"
	"strings"
)

func init() {
	register(&Format{Ecosystem: Maven, Small: true, match: func(b string) bool { return b == "pom.xml" }, parse: parsePOM})
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomProject struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	Properties struct {
		Items []xmlProp `xml:",any"`
	} `xml:"properties"`
	Dependencies         []pomDependency `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []pomDependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
}

// pomScope is what a pom.xml offers to the dependencies below it: its properties and managed versions.
type pomScope struct {
	props   map[string]string
	managed map[string]string
}

// newPomScope reads the properties and the managed versions of a pom; the ones of the parent pom (if any) are the
// base the pom's own override.
func newPomScope(p *pomProject, parent *pomScope) *pomScope {
	sc := &pomScope{props: map[string]string{}, managed: map[string]string{}}
	if parent != nil {
		maps.Copy(sc.props, parent.props)
		maps.Copy(sc.managed, parent.managed)
	}
	for _, x := range p.Properties.Items {
		sc.props[x.XMLName.Local] = strings.TrimSpace(x.Value)
	}
	version := strings.TrimSpace(p.Version)
	if version == "" {
		version = strings.TrimSpace(p.Parent.Version)
	}
	group := strings.TrimSpace(p.GroupID)
	if group == "" {
		group = strings.TrimSpace(p.Parent.GroupID)
	}
	for _, k := range []string{"project.version", "pom.version", "version"} {
		sc.props[k] = version
	}
	for _, k := range []string{"project.groupId", "pom.groupId", "groupId"} {
		sc.props[k] = group
	}
	sc.props["project.parent.version"] = strings.TrimSpace(p.Parent.Version)
	for _, d := range p.DependencyManagement.Dependencies {
		sc.managed[sc.resolve(d.GroupID)+":"+sc.resolve(d.ArtifactID)] = sc.resolve(d.Version)
	}
	return sc
}

func (sc *pomScope) resolve(s string) string {
	return expandProps(strings.TrimSpace(s), sc.props, "${", "}")
}

// parsePOM reads the dependencies a pom.xml declares (the test scope too: the file doesn't say what ships). A
// version is a literal or a `${property}` of the file, of `project.version`, of the managed versions or, one level
// up, of the parent pom in the same repository (the pom the child's <relativePath> points at, ../pom.xml by
// default). Anything else gives an empty version; nothing is fetched.
func parsePOM(s *sink, data []byte, find Finder) error {
	var p pomProject
	if err := decodeXML(data, &p, "pom.xml"); err != nil {
		return err
	}
	var parent *pomScope
	// An empty <relativePath/> means "don't look on disk" (Maven's rule); a pom found where the path points is the
	// parent only if its coordinates are the ones the child names.
	if strings.TrimSpace(p.Parent.ArtifactID) != "" && (p.Parent.RelativePath == nil || strings.TrimSpace(*p.Parent.RelativePath) != "") {
		rel := "../pom.xml"
		if p.Parent.RelativePath != nil {
			rel = strings.TrimSpace(*p.Parent.RelativePath)
		}
		if !strings.HasSuffix(rel, ".xml") {
			rel = strings.TrimSuffix(rel, "/") + "/pom.xml"
		}
		if pd := find(rel, false); pd != nil {
			pp, _ := helperParsed(s.ctx, "pom.xml", pd, func() (*pomProject, int64) {
				var pp pomProject
				if decodeXML(pd, &pp, "pom.xml") != nil {
					return nil, 0
				}
				return &pp, int64(len(pd))
			})
			if pp != nil && pp.isParentOf(&p) {
				parent = newPomScope(pp, nil)
			}
		}
	}
	sc := newPomScope(&p, parent)
	for _, d := range p.Dependencies {
		g, a := sc.resolve(d.GroupID), sc.resolve(d.ArtifactID)
		if g == "" || a == "" {
			continue
		}
		v := sc.resolve(d.Version)
		if v == "" {
			v = sc.managed[g+":"+a]
		}
		if err := s.emit(Dependency{Name: g + ":" + a, Version: v, Direct: true}); err != nil {
			return err
		}
	}
	return nil
}

// isParentOf tells whether pom p is the parent the child names: the same groupId and artifactId (the group may be
// inherited from p's own parent) and, if the child names a version, the same version.
func (p *pomProject) isParentOf(child *pomProject) bool {
	group := strings.TrimSpace(p.GroupID)
	if group == "" {
		group = strings.TrimSpace(p.Parent.GroupID)
	}
	version := strings.TrimSpace(p.Version)
	if version == "" {
		version = strings.TrimSpace(p.Parent.Version)
	}
	c := child.Parent
	return group == strings.TrimSpace(c.GroupID) && strings.TrimSpace(p.ArtifactID) == strings.TrimSpace(c.ArtifactID) &&
		(strings.TrimSpace(c.Version) == "" || version == strings.TrimSpace(c.Version))
}
