// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"

	"github.com/google/uuid"
)

// SBOM formats.
const (
	FormatSPDX      = "spdx"
	FormatCycloneDX = "cyclonedx"
)

// SBOM is what an SBOM is made from: the repository, its last scan and the stored dependencies. Nothing is read
// from git.
type SBOM struct {
	Repo *repo_model.Repository
	Scan *repo_model.DependencyScan
	Deps []*repo_model.Dependency
}

// LoadSBOM loads the scan and the dependencies of the repository. It returns a nil SBOM if there is no successful
// scan yet.
func LoadSBOM(ctx context.Context, repo *repo_model.Repository) (*SBOM, error) {
	scan, err := repo_model.GetRepoDependencyScan(ctx, repo.ID)
	if err != nil || scan == nil || scan.CommitSHA == "" {
		return nil, err
	}
	var deps []*repo_model.Dependency
	if err := db.GetEngine(ctx).Where("repo_id = ?", repo.ID).OrderBy("ecosystem, name, version, manifest_path, id").Find(&deps); err != nil {
		return nil, err
	}
	return &SBOM{Repo: repo, Scan: scan, Deps: deps}, nil
}

// SBOMFileName is the download name: the full name of the repository with / replaced by -.
func SBOMFileName(repo *repo_model.Repository, format string) string {
	name := strings.NewReplacer("/", "-", `"`, "", `\`, "", "\r", "", "\n", "").Replace(repo.FullName())
	if format == FormatCycloneDX {
		return name + ".cdx.json"
	}
	return name + ".spdx.json"
}

// component is a package once: the same package in several manifests is one component with every manifest.
type component struct {
	purl, ecosystem, name, version, license string
	direct                                  bool
	manifests                               []string
	requirements                            []string // the declared ranges of a package without a version
}

func (s *SBOM) components() []*component {
	byPURL := map[string]*component{}
	var out []*component
	for _, d := range s.Deps {
		purl := dependency.PURL(d.Ecosystem, d.Name, d.Version)
		if purl == "" {
			continue
		}
		c := byPURL[purl]
		if c == nil {
			c = &component{purl: purl, ecosystem: d.Ecosystem, name: d.Name, version: d.Version, license: d.License}
			byPURL[purl] = c
			out = append(out, c)
		}
		c.direct = c.direct || d.Direct
		if c.license == "" {
			c.license = d.License
		}
		if d.ManifestPath != "" && !slices.Contains(c.manifests, d.ManifestPath) {
			c.manifests = append(c.manifests, d.ManifestPath)
		}
		if d.Requirement != "" && !slices.Contains(c.requirements, d.Requirement) {
			c.requirements = append(c.requirements, d.Requirement)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].purl < out[j].purl })
	return out
}

func (s *SBOM) skippedNote() string {
	skipped := s.Scan.SkippedManifests()
	if len(skipped) == 0 {
		return ""
	}
	parts := make([]string, len(skipped))
	for i, m := range skipped {
		parts[i] = m.Path + " (" + m.Code + ")"
		if m.Code == repo_model.DependencySkipPartial {
			parts[i] = fmt.Sprintf("%s (%s, %d lines)", m.Path, m.Code, m.Lines)
		}
	}
	return "Manifests that were not read or read only in part: " + strings.Join(parts, ", ")
}

// downloadLocation is the SPDX download location of the scanned commit. The SPDX validators (spdx-tools) refuse a
// host without a dot (localhost, a single-label intranet name), so then it is NOASSERTION.
func (s *SBOM) downloadLocation(sha string) string {
	clone := s.Repo.CloneLink().HTTPS
	if u, err := url.Parse(clone); err != nil || !strings.Contains(u.Hostname(), ".") {
		return "NOASSERTION"
	}
	return "git+" + clone + "@" + sha
}

func toolName() string { return "gitdepo-" + setting.AppVer }

func marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	return append(b, '\n'), err
}

type spdxPackage struct {
	Name             string       `json:"name"`
	SPDXID           string       `json:"SPDXID"`
	VersionInfo      string       `json:"versionInfo,omitempty"`
	DownloadLocation string       `json:"downloadLocation"`
	FilesAnalyzed    bool         `json:"filesAnalyzed"`
	LicenseConcluded string       `json:"licenseConcluded"`
	LicenseDeclared  string       `json:"licenseDeclared"`
	LicenseComments  string       `json:"licenseComments,omitempty"`
	CopyrightText    string       `json:"copyrightText"`
	SourceInfo       string       `json:"sourceInfo,omitempty"`
	Comment          string       `json:"comment,omitempty"`
	ExternalRefs     []spdxExtRef `json:"externalRefs,omitempty"`
	Primary          string       `json:"primaryPackagePurpose,omitempty"`
}

type spdxExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// GenerateSPDX returns the SPDX 2.3 JSON document. The package ids come from a counter, never from a name; the root
// package is the repository at the scanned commit. Direct dependencies are DEPENDS_ON the root, the others
// CONTAINED by it as syft writes them (the lock files don't give the edges between dependencies).
func (s *SBOM) GenerateSPDX(now time.Time, id uuid.UUID) ([]byte, error) {
	const root = "SPDXRef-Repository"
	sha := s.Scan.CommitSHA
	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              s.Repo.FullName(),
		"documentNamespace": setting.AppURL + s.Repo.EscapedPath() + "/sbom/spdx/" + sha + "/" + id.String(),
		"creationInfo": map[string]any{
			"created":  now.UTC().Format("2006-01-02T15:04:05Z"),
			"creators": []string{"Tool: " + toolName()},
		},
	}
	if note := s.skippedNote(); note != "" {
		doc["comment"] = note
	}
	pkgs := []spdxPackage{{
		Name: s.Repo.FullName(), SPDXID: root, VersionInfo: sha, DownloadLocation: s.downloadLocation(sha),
		LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Primary: "APPLICATION",
	}}
	rels := []spdxRelationship{{"SPDXRef-DOCUMENT", "DESCRIBES", root}}
	for i, c := range s.components() {
		spdxID := "SPDXRef-Package-" + strconv.Itoa(i+1)
		p := spdxPackage{
			Name: c.name, SPDXID: spdxID, VersionInfo: c.version, DownloadLocation: "NOASSERTION",
			LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
			ExternalRefs: []spdxExtRef{{"PACKAGE-MANAGER", "purl", c.purl}},
		}
		if len(c.manifests) > 0 {
			p.SourceInfo = "found in " + strings.Join(c.manifests, ", ")
		}
		if len(c.requirements) > 0 {
			p.Comment = "not pinned (no lock file); declared range: " + strings.Join(c.requirements, "; ")
		}
		if c.license != "" {
			if expr, ok := normalizeLicense(c.license); ok {
				p.LicenseDeclared = expr
			} else {
				p.LicenseComments = "license as stated by the package: " + c.license
			}
		}
		pkgs = append(pkgs, p)
		if c.direct {
			rels = append(rels, spdxRelationship{root, "DEPENDS_ON", spdxID})
		} else {
			rels = append(rels, spdxRelationship{root, "CONTAINS", spdxID})
		}
	}
	doc["packages"] = pkgs
	doc["relationships"] = rels
	return marshal(doc)
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxLicense struct {
	License    *cdxLicenseID `json:"license,omitempty"`
	Expression string        `json:"expression,omitempty"`
}

type cdxLicenseID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxComponent struct {
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref"`
	Group              string              `json:"group,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	Licenses           []cdxLicense        `json:"licenses,omitempty"`
	Properties         []cdxProperty       `json:"properties,omitempty"`
	ExternalReferences []map[string]string `json:"externalReferences,omitempty"`
}

// GenerateCycloneDX returns the CycloneDX 1.6 JSON document; bom-ref is the purl, and the dependency graph lists
// the direct dependencies of the repository.
func (s *SBOM) GenerateCycloneDX(now time.Time, id uuid.UUID) ([]byte, error) {
	const root = "repository"
	sha := s.Scan.CommitSHA
	meta := map[string]any{
		"timestamp": now.UTC().Format("2006-01-02T15:04:05Z"),
		"tools":     map[string]any{"components": []cdxComponent{{Type: "application", BOMRef: "tool", Name: "gitdepo", Version: setting.AppVer}}},
		"component": cdxComponent{
			Type: "application", BOMRef: root, Name: s.Repo.FullName(), Version: sha,
			ExternalReferences: []map[string]string{{"type": "vcs", "url": s.Repo.CloneLink().HTTPS}},
		},
	}
	if note := s.skippedNote(); note != "" {
		meta["properties"] = []cdxProperty{{Name: "gitdepo:skipped-manifests", Value: note}}
	}
	comps := []cdxComponent{}
	direct := []string{}
	for _, c := range s.components() {
		cc := cdxComponent{Type: "library", BOMRef: c.purl, Name: c.name, Version: c.version, PURL: c.purl}
		if c.ecosystem == dependency.Maven {
			if g, a, ok := strings.Cut(c.name, ":"); ok {
				cc.Group, cc.Name = g, a
			}
		}
		if c.license != "" {
			if expr, ok := normalizeLicense(c.license); ok {
				if strings.ContainsAny(expr, " ()+") {
					cc.Licenses = []cdxLicense{{Expression: expr}}
				} else {
					cc.Licenses = []cdxLicense{{License: &cdxLicenseID{ID: expr}}}
				}
			} else {
				cc.Licenses = []cdxLicense{{License: &cdxLicenseID{Name: c.license}}}
			}
		}
		for _, m := range c.manifests {
			cc.Properties = append(cc.Properties, cdxProperty{Name: "gitdepo:manifest", Value: m})
		}
		for _, r := range c.requirements {
			cc.Properties = append(cc.Properties, cdxProperty{Name: "gitdepo:requirement", Value: r})
		}
		comps = append(comps, cc)
		if c.direct {
			direct = append(direct, c.purl)
		}
	}
	return marshal(map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + id.String(),
		"version":      1,
		"metadata":     meta,
		"components":   comps,
		"dependencies": []map[string]any{{"ref": root, "dependsOn": direct}},
	})
}

// ParseFormat returns the SBOM format a request asks for; an empty value is SPDX. ok is false for anything else.
func ParseFormat(s string) (format string, ok bool) {
	switch s {
	case "", FormatSPDX:
		return FormatSPDX, true
	case FormatCycloneDX:
		return FormatCycloneDX, true
	}
	return "", false
}
