// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cdxBase  = "http://cyclonedx.org/schema/"
	spdxBase = "http://spdx.org/rdf/terms/2.3"
)

func loadSchema(t *testing.T, url, file string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for _, r := range [][2]string{
		{cdxBase + "bom-1.6.schema.json", "bom-1.6.schema.json"},
		{cdxBase + "spdx.schema.json", "spdx.schema.json"},
		{cdxBase + "jsf-0.82.schema.json", "jsf-0.82.schema.json"},
		{spdxBase, "spdx-schema.json"},
	} {
		f, err := os.Open(filepath.Join("testdata", r[1]))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(f)
		require.NoError(t, err)
		f.Close()
		require.NoError(t, c.AddResource(r[0], doc))
	}
	s, err := c.Compile(url)
	require.NoError(t, err)
	return s
}

func validateDoc(t *testing.T, s *jsonschema.Schema, doc []byte) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	require.NoError(t, err, "valid JSON")
	if err := s.Validate(v); err != nil {
		t.Fatalf("schema: %#v", err)
	}
}

func testSBOM() *SBOM {
	repo := &repo_model.Repository{ID: 7, OwnerName: "acme", GroupID: 3, GroupName: "payments", Name: "api"}
	scan := &repo_model.DependencyScan{RepoID: 7, CommitSHA: "0123456789abcdef0123456789abcdef01234567"}
	scan.SetSkippedManifests([]repo_model.SkippedManifest{{Path: "web/yarn.lock", Code: repo_model.DependencySkipParse}, {Path: "Gemfile", Code: repo_model.DependencySkipPartial, Lines: 2}})
	d := func(eco, name, version, manifest, license string, direct bool) *repo_model.Dependency {
		return &repo_model.Dependency{RepoID: 7, Ecosystem: eco, Name: name, Version: version, ManifestPath: manifest, License: license, Direct: direct}
	}
	return &SBOM{Repo: repo, Scan: scan, Deps: []*repo_model.Dependency{
		d("Go", "github.com/gin-gonic/gin", "v1.9.1", "go.mod", "MIT", true),
		d("Go", "golang.org/x/net", "v0.0.0-2021+incompatible", "go.mod", "", false),
		d("npm", "@scope/pkg", "1.2.0", "web/package-lock.json", "mit", true),
		d("npm", "@scope/pkg", "1.2.0", "docs/package-lock.json", "MIT", false),
		d("npm", "left-pad", "1.3.0", "web/package-lock.json", "WTFPL OR (MIT AND ISC)", false),
		d("PyPI", "Django_Rest", "3.0", "requirements.txt", "Some Custom <license> text", true),
		d("Maven", "org.apache:commons-lang3", "3.12.0", "pom.xml", "GPL-2.0-only WITH Classpath-exception-2.0", true),
		d("NuGet", "Newtonsoft.Json", "", "a.csproj", "LicenseRef-foo", true),
		d("crates.io", "serde", "1.0.0", "Cargo.lock", "MIT OR Apache-2.0", true),
		d("RubyGems", "rails", "7.0.0", "Gemfile.lock", "NOASSERTION", true),
		d("Packagist", "laravel/framework", "v10.0.0", "composer.lock", "", true),
		// hostile names must stay inside their JSON strings
		d("npm", "\" </script><img src=x onerror=alert(1)> \u202e", `1"},{"x":"`, "p/package-lock.json", `"} </script>`, true),
	}}
}

func TestSBOMSchemas(t *testing.T) {
	defer test.MockVariableValue(&setting.AppURL, "https://git.example.com/")()
	defer test.MockVariableValue(&setting.AppVer, "11.0.0+test")()
	s := testSBOM()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	t.Run("spdx", func(t *testing.T) {
		doc, err := s.GenerateSPDX(now, id)
		require.NoError(t, err)
		validateDoc(t, loadSchema(t, spdxBase, ""), doc)

		var out struct {
			DocumentNamespace string `json:"documentNamespace"`
			Name              string `json:"name"`
			Comment           string `json:"comment"`
			CreationInfo      struct {
				Creators []string `json:"creators"`
				Created  string   `json:"created"`
			} `json:"creationInfo"`
			Relationships []map[string]string `json:"relationships"`
			Packages      []struct {
				SPDXID           string `json:"SPDXID"`
				Name             string `json:"name"`
				VersionInfo      string `json:"versionInfo"`
				DownloadLocation string `json:"downloadLocation"`
				LicenseDeclared  string `json:"licenseDeclared"`
				LicenseComments  string `json:"licenseComments"`
				SourceInfo       string `json:"sourceInfo"`
				ExternalRefs     []struct {
					ReferenceLocator string `json:"referenceLocator"`
				} `json:"externalRefs"`
			} `json:"packages"`
		}
		require.NoError(t, json.Unmarshal(doc, &out))
		assert.Equal(t, "acme/payments/api", out.Name)
		assert.Equal(t, "https://git.example.com/acme/payments/api/sbom/spdx/0123456789abcdef0123456789abcdef01234567/11111111-2222-3333-4444-555555555555", out.DocumentNamespace)
		assert.Equal(t, []string{"Tool: gitdepo-11.0.0+test"}, out.CreationInfo.Creators)
		assert.Equal(t, "2026-10-25T12:00:00Z", out.CreationInfo.Created)
		assert.Contains(t, out.Comment, "web/yarn.lock (parse_error)")
		assert.Contains(t, out.Comment, "read only in part: web/yarn.lock (parse_error), Gemfile (partially_read, 2 lines)")
		root := out.Packages[0]
		assert.Equal(t, "acme/payments/api", root.Name)
		assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", root.VersionInfo)
		assert.Equal(t, "git+https://git.example.com/acme/payments/api.git@0123456789abcdef0123456789abcdef01234567", root.DownloadLocation)
		assert.Len(t, out.Packages, 1+11, "the scoped package of two manifests is one package")

		byPURL := map[string]int{}
		for i, p := range out.Packages {
			assert.Regexp(t, `^SPDXRef-[a-zA-Z0-9.-]+$`, p.SPDXID)
			if len(p.ExternalRefs) > 0 {
				byPURL[p.ExternalRefs[0].ReferenceLocator] = i
			}
		}
		pkg := func(purl string) int { return byPURL[purl] }
		scoped := out.Packages[pkg("pkg:npm/%40scope/pkg@1.2.0")]
		assert.Equal(t, "MIT", scoped.LicenseDeclared, "mit is written in the SPDX case")
		assert.Equal(t, "found in web/package-lock.json, docs/package-lock.json", scoped.SourceInfo)
		assert.Equal(t, "WTFPL OR (MIT AND ISC)", out.Packages[pkg("pkg:npm/left-pad@1.3.0")].LicenseDeclared)
		assert.Equal(t, "GPL-2.0-only WITH Classpath-exception-2.0", out.Packages[pkg("pkg:maven/org.apache/commons-lang3@3.12.0")].LicenseDeclared)
		custom := out.Packages[pkg("pkg:pypi/django-rest@3.0")]
		assert.Equal(t, "NOASSERTION", custom.LicenseDeclared)
		assert.Equal(t, "license as stated by the package: Some Custom <license> text", custom.LicenseComments)
		assert.Equal(t, "NOASSERTION", out.Packages[pkg("pkg:nuget/Newtonsoft.Json")].LicenseDeclared, "LicenseRef is not declared")

		rels := out.Relationships
		assert.Equal(t, map[string]string{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Repository"}, rels[0])
		var depends, contains int
		for _, r := range rels[1:] {
			assert.Equal(t, "SPDXRef-Repository", r["spdxElementId"])
			switch r["relationshipType"] {
			case "DEPENDS_ON":
				depends++
			case "CONTAINS":
				contains++
			}
		}
		assert.Equal(t, 9, depends)
		assert.Equal(t, 2, contains)
		assert.NotContains(t, string(doc), "</script>", "html is escaped in the JSON")
	})

	t.Run("cyclonedx", func(t *testing.T) {
		doc, err := s.GenerateCycloneDX(now, id)
		require.NoError(t, err)
		validateDoc(t, loadSchema(t, cdxBase+"bom-1.6.schema.json", ""), doc)

		var out struct {
			SerialNumber string `json:"serialNumber"`
			Metadata     struct {
				Component struct {
					Type, Name, Version string
				} `json:"component"`
				Tools struct {
					Components []struct{ Name, Version string } `json:"components"`
				} `json:"tools"`
				Properties []struct{ Name, Value string } `json:"properties"`
			} `json:"metadata"`
			Components []struct {
				BOMRef     string `json:"bom-ref"`
				Group      string
				Name       string
				Licenses   []map[string]any
				Properties []struct{ Name, Value string }
			} `json:"components"`
			Dependencies []struct {
				Ref       string
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		require.NoError(t, json.Unmarshal(doc, &out))
		assert.Equal(t, "urn:uuid:11111111-2222-3333-4444-555555555555", out.SerialNumber)
		assert.Equal(t, "application", out.Metadata.Component.Type)
		assert.Equal(t, "acme/payments/api", out.Metadata.Component.Name)
		assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", out.Metadata.Component.Version)
		assert.Equal(t, "gitdepo", out.Metadata.Tools.Components[0].Name)
		assert.Contains(t, out.Metadata.Properties[0].Value, "web/yarn.lock (parse_error)")
		assert.Len(t, out.Components, 11)
		refs := map[string]bool{}
		for _, c := range out.Components {
			assert.False(t, refs[c.BOMRef], "bom-ref is unique")
			refs[c.BOMRef] = true
			if c.BOMRef == "pkg:maven/org.apache/commons-lang3@3.12.0" {
				assert.Equal(t, "org.apache", c.Group)
				assert.Equal(t, "commons-lang3", c.Name)
				assert.Equal(t, "GPL-2.0-only WITH Classpath-exception-2.0", c.Licenses[0]["expression"])
			}
			if c.BOMRef == "pkg:npm/%40scope/pkg@1.2.0" {
				assert.Len(t, c.Properties, 2)
				assert.Equal(t, map[string]any{"id": "MIT"}, c.Licenses[0]["license"])
			}
			if c.BOMRef == "pkg:pypi/django-rest@3.0" {
				assert.Equal(t, map[string]any{"name": "Some Custom <license> text"}, c.Licenses[0]["license"])
			}
		}
		require.Len(t, out.Dependencies, 1)
		assert.Equal(t, "repository", out.Dependencies[0].Ref)
		assert.Len(t, out.Dependencies[0].DependsOn, 9)
		for _, ref := range out.Dependencies[0].DependsOn {
			assert.True(t, refs[ref])
		}
		assert.NotContains(t, string(doc), "</script>")
	})

	t.Run("empty", func(t *testing.T) {
		e := &SBOM{Repo: s.Repo, Scan: &repo_model.DependencyScan{RepoID: 7, CommitSHA: "abc"}}
		spdx, err := e.GenerateSPDX(now, id)
		require.NoError(t, err)
		validateDoc(t, loadSchema(t, spdxBase, ""), spdx)
		cdx, err := e.GenerateCycloneDX(now, id)
		require.NoError(t, err)
		validateDoc(t, loadSchema(t, cdxBase+"bom-1.6.schema.json", ""), cdx)
	})

	t.Run("deterministic", func(t *testing.T) {
		a, _ := s.GenerateSPDX(now, id)
		rev := &SBOM{Repo: s.Repo, Scan: s.Scan}
		for _, d := range slices.Backward(s.Deps) {
			rev.Deps = append(rev.Deps, d)
		}
		b, _ := rev.GenerateSPDX(now, id)
		// the order of the input must not change the order of the packages (SPDXIDs follow it)
		assert.Equal(t, strings.Count(string(a), "SPDXRef-Package-"), strings.Count(string(b), "SPDXRef-Package-"))
		c1, _ := s.GenerateCycloneDX(now, id)
		c2, _ := rev.GenerateCycloneDX(now, id)
		assert.Equal(t, string(c1)[:len(c1)/2], string(c2)[:len(c1)/2], "the components come in purl order")
	})
}

func TestSPDXDownloadLocation(t *testing.T) {
	defer test.MockVariableValue(&setting.AppVer, "11.0.0+test")()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	for appURL, want := range map[string]string{
		"https://git.example.com:3000/": "git+https://git.example.com:3000/acme/payments/api.git@0123456789abcdef0123456789abcdef01234567",
		"http://localhost:3300/":        "NOASSERTION",
		"https://intranet/":             "NOASSERTION",
	} {
		t.Run(appURL, func(t *testing.T) {
			defer test.MockVariableValue(&setting.AppURL, appURL)()
			doc, err := testSBOM().GenerateSPDX(now, id)
			require.NoError(t, err)
			validateDoc(t, loadSchema(t, spdxBase, ""), doc)
			var out struct {
				Packages []struct {
					DownloadLocation string `json:"downloadLocation"`
				} `json:"packages"`
			}
			require.NoError(t, json.Unmarshal(doc, &out))
			assert.Equal(t, want, out.Packages[0].DownloadLocation)
		})
	}
}

func TestSBOMFileName(t *testing.T) {
	r := &repo_model.Repository{OwnerName: "acme", GroupID: 3, GroupName: "payments", Name: "api"}
	assert.Equal(t, "acme-payments-api.spdx.json", SBOMFileName(r, FormatSPDX))
	assert.Equal(t, "acme-payments-api.cdx.json", SBOMFileName(r, FormatCycloneDX))
	assert.Equal(t, "u-r.spdx.json", SBOMFileName(&repo_model.Repository{OwnerName: "u", Name: "r"}, "x"))
}

func TestNormalizeLicense(t *testing.T) {
	for in, want := range map[string]string{
		"MIT":                           "MIT",
		"mit":                           "MIT",
		"apache-2.0":                    "Apache-2.0",
		"MIT OR Apache-2.0":             "MIT OR Apache-2.0",
		"mit or apache-2.0":             "MIT OR Apache-2.0",
		"(MIT AND ISC) OR BSD-3-Clause": "(MIT AND ISC) OR BSD-3-Clause",
		"( MIT )":                       "(MIT)",
		"GPL-2.0+":                      "GPL-2.0+",
		"GPL-2.0-only WITH Classpath-exception-2.0": "GPL-2.0-only WITH Classpath-exception-2.0",
		"gpl-2.0-only with classpath-exception-2.0": "GPL-2.0-only WITH Classpath-exception-2.0",
	} {
		got, ok := normalizeLicense(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "Proprietary", "MIT OR", "OR MIT", "(MIT", "MIT)", "LicenseRef-x", "NOASSERTION", "MIT; DROP", "MIT WITH", "MIT WITH <x>", "MIT WITH Nonsense-exception", "GPL-2.0-only WITH MIT", "MIT WITH LGPL-2.1-only", "Classpath-exception-2.0", "<script>", strings.Repeat("(", 20) + "MIT" + strings.Repeat(")", 20)} {
		_, ok := normalizeLicense(in)
		assert.False(t, ok, in)
	}
}

func TestSchemasRejectInvalid(t *testing.T) {
	for _, s := range []*jsonschema.Schema{loadSchema(t, spdxBase, ""), loadSchema(t, cdxBase+"bom-1.6.schema.json", "")} {
		v, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"spdxVersion":"SPDX-2.3","bomFormat":"nope","components":[{"type":"library"}]}`))
		require.NoError(t, err)
		require.Error(t, s.Validate(v), "the schema check is not a no-op")
	}
}

// A package of a manifest without a lock file has no version: a versionless purl, and the declared ranges as the
// CycloneDX property spoved:requirement and in the SPDX package comment.
func TestSBOMUnpinned(t *testing.T) {
	defer test.MockVariableValue(&setting.AppURL, "https://git.example.com/")()
	s := unpinnedSBOM()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	spdx, err := s.GenerateSPDX(now, id)
	require.NoError(t, err)
	validateDoc(t, loadSchema(t, spdxBase, ""), spdx)
	var sp struct {
		Packages []struct {
			Name, VersionInfo, Comment string
			ExternalRefs               []struct{ ReferenceLocator string } `json:"externalRefs"`
		} `json:"packages"`
	}
	require.NoError(t, json.Unmarshal(spdx, &sp))
	require.Len(t, sp.Packages, 4)
	byPURL := map[string]int{}
	for i, p := range sp.Packages[1:] {
		byPURL[p.ExternalRefs[0].ReferenceLocator] = i + 1
	}
	unpinned := sp.Packages[byPURL["pkg:npm/express"]]
	assert.Empty(t, unpinned.VersionInfo)
	assert.Equal(t, "not pinned (no lock file); declared range: ^4.18.0; ~4.18", unpinned.Comment)
	pinned := sp.Packages[byPURL["pkg:npm/express@4.18.2"]]
	assert.Equal(t, "4.18.2", pinned.VersionInfo)
	assert.Empty(t, pinned.Comment)
	assert.Empty(t, sp.Packages[byPURL["pkg:cargo/serde"]].Comment, "no range: nothing to say")

	cdx, err := s.GenerateCycloneDX(now, id)
	require.NoError(t, err)
	validateDoc(t, loadSchema(t, cdxBase+"bom-1.6.schema.json", ""), cdx)
	var cd struct {
		Components []struct {
			BOMRef     string `json:"bom-ref"`
			Version    string
			PURL       string
			Properties []struct{ Name, Value string }
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(cdx, &cd))
	require.Len(t, cd.Components, 3)
	for _, c := range cd.Components {
		var reqs []string
		for _, p := range c.Properties {
			if p.Name == "gitdepo:requirement" {
				reqs = append(reqs, p.Value)
			}
		}
		switch c.PURL {
		case "pkg:npm/express":
			assert.Empty(t, c.Version)
			assert.Equal(t, []string{"^4.18.0", "~4.18"}, reqs)
		default:
			assert.Empty(t, reqs, c.PURL)
		}
	}
}

func unpinnedSBOM() *SBOM {
	repo := &repo_model.Repository{ID: 7, OwnerName: "acme", Name: "api"}
	scan := &repo_model.DependencyScan{RepoID: 7, CommitSHA: "0123456789abcdef0123456789abcdef01234567"}
	return &SBOM{Repo: repo, Scan: scan, Deps: []*repo_model.Dependency{
		{Ecosystem: "npm", Name: "express", Requirement: "^4.18.0", ManifestPath: "web/package.json", Direct: true},
		{Ecosystem: "npm", Name: "express", Requirement: "~4.18", ManifestPath: "api/package.json", Direct: true},
		{Ecosystem: "npm", Name: "express", Requirement: "^4.18.0", ManifestPath: "docs/package.json", Direct: true},
		{Ecosystem: "npm", Name: "express", Version: "4.18.2", ManifestPath: "package-lock.json", Direct: true},
		{Ecosystem: "crates.io", Name: "serde", ManifestPath: "Cargo.toml", Direct: true},
	}}
}
