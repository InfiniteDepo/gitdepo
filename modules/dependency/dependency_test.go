// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseFixture parses testdata/<rel>, giving the parser the files next to it and above it like the scanner does.
func parseFixture(t *testing.T, rel string) []Dependency {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", rel))
	require.NoError(t, err)
	f := FormatFor(path.Base(rel))
	require.NotNil(t, f, rel)
	find := func(name string, up bool) []byte {
		for dir := path.Dir(rel); ; dir = path.Dir(dir) {
			if b, err := os.ReadFile(filepath.Join("testdata", dir, name)); err == nil {
				return b
			}
			if !up || dir == "." {
				return nil
			}
		}
	}
	deps, err := f.Parse(t.Context(), data, find)
	require.NoError(t, err, rel)
	return deps
}

func index(deps []Dependency) map[string]Dependency {
	m := map[string]Dependency{}
	for _, d := range deps {
		m[d.Name+"@"+d.Version] = d
	}
	return m
}

func TestRealFixtures(t *testing.T) {
	for rel, min := range map[string]int{
		"gin/go.mod":                  10,
		"nodegoat/package-lock.json":  50,
		"defectdojo/requirements.txt": 50,
		"defectdojo/yarn.lock":        20,
		"mastodon/yarn.lock":          40,
		"koel/yarn.lock":              40,
		"hyper-app/pnpm-lock.yaml":    50,
		"vite/pnpm-lock.yaml":         50,
		"mastodon/Gemfile.lock":       150,
		"koel/composer.lock":          30,
		"poetry/poetry.lock":          30,
		"ripgrep/Cargo.lock":          30,
		"webgoat/pom.xml":             10,
		"eshop/src/Web/Web.csproj":    10,
	} {
		deps := parseFixture(t, rel)
		assert.GreaterOrEqual(t, len(deps), min, rel)
		for _, d := range deps {
			assert.NotEmpty(t, d.Name, rel)
		}
	}
}

func TestGoMod(t *testing.T) {
	m := index(parseFixture(t, "gin/go.mod"))
	assert.True(t, m["github.com/bytedance/sonic@v1.9.1"].Direct)
	var direct, indirect int
	for _, d := range m {
		if d.Direct {
			direct++
		} else {
			indirect++
		}
	}
	assert.Positive(t, direct)
	assert.Positive(t, indirect)
}

func TestNPM(t *testing.T) {
	m := index(parseFixture(t, "npm-v3/package-lock.json"))
	assert.Equal(t, Dependency{Ecosystem: NPM, Name: "@scope/pkg", Version: "1.2.0", License: "MIT", Direct: true}, m["@scope/pkg@1.2.0"])
	assert.False(t, m["left-pad@1.0.0"].Direct, "nested copy")
	assert.True(t, m["left-pad@1.3.0"].Direct)
	assert.True(t, m["jest@29.7.0"].Direct)
	assert.Equal(t, "ISC", m["real-name@2.0.0"].License)
	assert.NotContains(t, m, "app@")
	assert.Len(t, m, 5, "workspace link and workspace member are no packages")

	m = index(parseFixture(t, "npm-v1/package-lock.json"))
	assert.True(t, m["express@4.18.2"].Direct)
	assert.True(t, m["mime-types@2.1.35"].Direct)
	assert.False(t, m["accepts@1.3.8"].Direct)
	assert.False(t, m["debug@2.6.9"].Direct)

	m = index(parseFixture(t, "nodegoat/package-lock.json"))
	assert.True(t, m["body-parser@1.18.3"].Direct)
}

func TestYarn(t *testing.T) {
	m := index(parseFixture(t, "yarn-berry/yarn.lock"))
	assert.Len(t, m, 3, "the workspace is not a package")
	assert.True(t, m["lodash@4.17.21"].Direct)
	assert.False(t, m["@babel/code-frame@7.22.13"].Direct)
	assert.Contains(t, m, "resolve@1.22.8")

	m = index(parseFixture(t, "koel/yarn.lock"))
	assert.Contains(t, m, "@ampproject/remapping@2.2.0")
}

func TestYarnAliasesAndLocal(t *testing.T) {
	pkgJSON := []byte(`{"dependencies":{"debug":"^4.3.4","str":"npm:string-width@^4.2.0","local":"link:../local"}}`)
	find := func(n string, _ bool) []byte {
		if n == "package.json" {
			return pkgJSON
		}
		return nil
	}
	parse := func(lock string) map[string]Dependency {
		deps, err := FormatFor("yarn.lock").Parse(t.Context(), []byte(lock), find)
		require.NoError(t, err)
		return index(deps)
	}
	t.Run("classic", func(t *testing.T) {
		m := parse(`# yarn lockfile v1


debug@^2.6.9:
  version "2.6.9"

debug@^4.3.4:
  version "4.3.4"

"string-width-cjs@npm:string-width@^4.2.0", "string-width@^4.1.0", "str@npm:string-width@^4.2.0":
  version "4.2.3"

"local@link:../local":
  version "1.0.0"
`)
		assert.Len(t, m, 3)
		assert.True(t, m["debug@4.3.4"].Direct)
		assert.False(t, m["debug@2.6.9"].Direct, "the other version is transitive")
		require.Contains(t, m, "string-width@4.2.3", "the alias entry is the real package")
		assert.True(t, m["string-width@4.2.3"].Direct)
		assert.NotContains(t, m, "string-width-cjs@4.2.3")
	})
	t.Run("berry", func(t *testing.T) {
		m := parse(`__metadata:
  version: 8

"debug@npm:^4.3.4":
  version: 4.3.4
  resolution: "debug@npm:4.3.4"
  languageName: node

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  languageName: node

"local@link:../local::locator=app%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "local@link:../local::locator=app%40workspace%3A."

"portal-pkg@portal:../p::locator=app%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "portal-pkg@portal:../p::locator=app%40workspace%3A."

"file-pkg@file:../f#../f::hash=abc&locator=app%40workspace%3A.":
  version: 1.0.0
  resolution: "file-pkg@file:../f#../f::hash=abc&locator=app%40workspace%3A."

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
`)
		assert.Len(t, m, 2)
		assert.True(t, m["debug@4.3.4"].Direct)
		assert.Contains(t, m, "string-width@4.2.3")
	})
}

func TestPnpm(t *testing.T) {
	m := index(parseFixture(t, "pnpm-v5/pnpm-lock.yaml"))
	assert.Len(t, m, 3)
	assert.True(t, m["lodash@4.17.21"].Direct)
	assert.True(t, m["@types/node@18.11.9"].Direct)
	assert.False(t, m["react-dom@18.2.0"].Direct)

	deps := parseFixture(t, "hyper-app/pnpm-lock.yaml")
	var direct bool
	for _, d := range deps {
		direct = direct || d.Direct
		assert.NotContains(t, d.Version, "(")
	}
	assert.True(t, direct)
}

func TestPnpmV6(t *testing.T) {
	m := index(parseFixture(t, "pnpm-v6/pnpm-lock.yaml"))
	require.Contains(t, m, "react@18.2.0")
	assert.True(t, m["react@18.2.0"].Direct)
	assert.False(t, m["react@17.0.2"].Direct, "another version of a direct package is transitive")
	assert.True(t, m["react-dom@18.2.0"].Direct, "the peer suffix is not part of the version")
	assert.True(t, m["@types/node@20.8.7"].Direct)
	assert.False(t, m["loose-envify@1.4.0"].Direct)
	assert.True(t, m["string-width@4.2.3"].Direct, "an alias is the real package")
	for k := range m {
		assert.NotContains(t, k, "localpkg", "a package on the disk is not listed")
		assert.NotContains(t, k, "(")
	}
	assert.Len(t, m, 8)
}

func TestPnpmMultiDocument(t *testing.T) {
	deps := parseFixture(t, "vite/pnpm-lock.yaml")
	m := index(deps)
	assert.GreaterOrEqual(t, len(deps), 60, "the project's document is read")
	for k := range m {
		assert.NotContains(t, k, "@pnpm/exe", "the tooling document is left out: %s", k)
	}
	var direct int
	for _, d := range deps {
		if d.Direct {
			direct++
		}
	}
	assert.Positive(t, direct)

	// pnpm reads one document: a second one that doesn't follow an environment document is refused
	two := "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {}\n---\nlockfileVersion: '9.0'\npackages:\n  b@2.0.0:\n    resolution: {}\n"
	_, err := FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte(two), nil)
	require.ErrorIs(t, err, ErrParse)
	got, err := FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte("---\n"+two), nil)
	require.NoError(t, err)
	require.Len(t, got, 1, "after an environment document, the next one is the lockfile")
	assert.Equal(t, "b", got[0].Name)
	_, err = FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte("---\n"+two+"---\nlockfileVersion: '9.0'\n"), nil)
	require.ErrorIs(t, err, ErrParse, "a third document")
	_, err = FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte("---\nlockfileVersion: '9.0'\n"), nil)
	require.ErrorIs(t, err, ErrParse, "an environment document without the lockfile after it")
	_, err = FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte("a: [\n---\nb: 1"), nil)
	require.ErrorIs(t, err, ErrParse, "a flow collection that doesn't end on its line is refused")
}

func TestFormatForPath(t *testing.T) {
	for p, want := range map[string]bool{
		"requirements.txt": true, "a/requirements-dev.txt": true, "dev-requirements.txt": true, "requirements_test.txt": true,
		"requirements/base.txt": true, "x/requirements/prod.txt": true,
		"requirements/base.md": false, "requirements/sub/base.txt": false, "notes.txt": false, "requirements.md": false,
	} {
		assert.Equal(t, want, FormatForPath(p) != nil, p)
	}
}

func TestPython(t *testing.T) {
	m := index(parseFixture(t, "defectdojo/requirements.txt"))
	for _, d := range m {
		assert.True(t, d.Direct)
	}
	f := FormatFor("requirements.txt")
	deps, err := f.Parse(t.Context(), []byte("# c\nDjango==4.2.1  # why\nrequests[security]==2.31.0 ; python_version>'3'\nflask>=2\n-r other.txt\n--index-url http://169.254.169.254\nfoo==1.*\ngit+https://x/y.git#egg=y\n"), nil)
	require.NoError(t, err)
	assert.Equal(t, []Dependency{
		{Ecosystem: PyPI, Name: "Django", Version: "4.2.1", Direct: true},
		{Ecosystem: PyPI, Name: "requests", Version: "2.31.0", Direct: true},
		{Ecosystem: PyPI, Name: "flask", Requirement: ">=2", Direct: true},
		{Ecosystem: PyPI, Name: "foo", Requirement: "==1.*", Direct: true},
	}, deps, "a range or a wildcard keeps the name with no version, and the range; URLs and options are dropped")

	deps, err = f.Parse(t.Context(), []byte("flask>=2.0\nrequests\nDjango==4.2.1 --hash=sha256:abc\nnumpy==1.26.0 \\\n    --hash=sha256:def\npkg @ https://example.test/p.whl\n-c constraints.txt\n"), nil)
	require.NoError(t, err)
	assert.Equal(t, []Dependency{
		{Ecosystem: PyPI, Name: "flask", Requirement: ">=2.0", Direct: true},
		{Ecosystem: PyPI, Name: "requests", Direct: true},
		{Ecosystem: PyPI, Name: "Django", Version: "4.2.1", Direct: true},
		{Ecosystem: PyPI, Name: "numpy", Version: "1.26.0", Direct: true},
	}, deps)

	p := index(parseFixture(t, "poetry/poetry.lock"))
	var direct int
	for _, d := range p {
		if d.Direct {
			direct++
		}
	}
	assert.Positive(t, direct)
}

func TestMaven(t *testing.T) {
	m := index(parseFixture(t, "pom-props/pom.xml"))
	assert.Contains(t, m, "junit:junit@4.13.2")
	assert.Contains(t, m, "com.fasterxml.jackson.core:jackson-core@2.15.0")
	assert.Contains(t, m, "org.example:sibling@3.1.0")
	assert.Contains(t, m, "org.slf4j:slf4j-api@2.0.9", "version from the same file's dependencyManagement")
	assert.Contains(t, m, "org.unknown:bom-managed@")
	assert.Contains(t, m, "org.unknown:unresolved@")
	assert.Len(t, m, 6)
	assert.True(t, m["junit:junit@4.13.2"].Direct, "test scope is included")
}

func TestNuGet(t *testing.T) {
	deps := parseFixture(t, "eshop/src/Web/Web.csproj")
	m := index(deps)
	assert.Contains(t, m, "Ardalis.ListStartupServices@1.1.4", "central package management")
	for _, d := range deps {
		assert.NotEmpty(t, d.Version, d.Name)
		assert.True(t, d.Direct)
	}

	m = index(parseFixture(t, "nuget/packages.lock.json"))
	assert.Len(t, m, 3)
	assert.True(t, m["Newtonsoft.Json@13.0.1"].Direct)
	assert.False(t, m["Microsoft.Extensions.Logging@6.0.0"].Direct)
	assert.Contains(t, m, "Microsoft.Extensions.Logging@8.0.0")

	f := FormatFor("a.csproj")
	deps, err := f.Parse(t.Context(), []byte(`<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><V>2.0.0</V></PropertyGroup><ItemGroup>
<PackageReference Include="A" Version="1.0.0" VersionOverride="3.0.0"/>
<PackageReference Include="B"><Version>$(V)</Version></PackageReference>
<PackageReference Include="C" Version="$(Nope)"/>
</ItemGroup></Project>`), nil)
	require.NoError(t, err)
	assert.Equal(t, []Dependency{
		{Ecosystem: NuGet, Name: "A", Version: "3.0.0", Direct: true},
		{Ecosystem: NuGet, Name: "B", Version: "2.0.0", Direct: true},
		{Ecosystem: NuGet, Name: "C", Direct: true},
	}, deps)
	assert.Nil(t, FormatFor(".csproj"))
}

func TestCargoGemComposer(t *testing.T) {
	m := index(parseFixture(t, "ripgrep/Cargo.lock"))
	var direct, other int
	for _, d := range m {
		assert.NotEqual(t, "ripgrep", d.Name, "the project itself is no dependency")
		if d.Direct {
			direct++
		} else {
			other++
		}
	}
	assert.Positive(t, direct)
	assert.Positive(t, other)

	var gd int
	for _, d := range parseFixture(t, "mastodon/Gemfile.lock") {
		if d.Direct {
			gd++
		}
		assert.NotEmpty(t, d.Version)
	}
	assert.Positive(t, gd)

	var licensed, cd int
	for _, d := range parseFixture(t, "koel/composer.lock") {
		if d.License != "" {
			licensed++
		}
		if d.Direct {
			cd++
		}
	}
	assert.Positive(t, licensed)
	assert.Positive(t, cd)
}

func TestPURL(t *testing.T) {
	for _, tc := range []struct{ eco, name, version, want string }{
		{Go, "github.com/Gin-Gonic/gin", "v1.9.1", "pkg:golang/github.com/gin-gonic/gin@v1.9.1"},
		{Go, "golang.org/x/net", "v0.0.0-2021+incompatible", "pkg:golang/golang.org/x/net@v0.0.0-2021%2Bincompatible"},
		{NPM, "@scope/name", "1.0.0", "pkg:npm/%40scope/name@1.0.0"},
		{NPM, "left-pad", "", "pkg:npm/left-pad"},
		{PyPI, "Django_Rest.Framework", "3.0", "pkg:pypi/django-rest.framework@3.0"},
		{Maven, "org.apache:commons-lang3", "3.12.0", "pkg:maven/org.apache/commons-lang3@3.12.0"},
		{NuGet, "Newtonsoft.Json", "13.0.1", "pkg:nuget/Newtonsoft.Json@13.0.1"},
		{Cargo, "serde", "1.0.0", "pkg:cargo/serde@1.0.0"},
		{RubyGems, "rails", "7.0.0", "pkg:gem/rails@7.0.0"},
		{Packagist, "Laravel/Framework", "v10.0.0", "pkg:composer/laravel/framework@v10.0.0"},
		{NPM, "a b/<x>", "1 2", "pkg:npm/a%20b/%3Cx%3E@1%202"},
		{"Nope", "x", "1", ""},
	} {
		assert.Equal(t, tc.want, PURL(tc.eco, tc.name, tc.version), tc.name)
	}
}

func TestValidate(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	in := []Dependency{
		{Name: "evil\x00name\r\n\u202Etxt", Version: "1\x1b[31m.0"},
		{Name: long, Version: "1"},
		{Name: "n", Version: long},
		{Name: "", Version: "1"},
		{Name: "../../x<img onerror=1>", Version: "<script>"},
		{Name: "bad\xffutf", Version: "1"},
		{Name: "dup", Version: "1"},
		{Name: "dup", Version: "1", Direct: true, License: "MIT"},
		{Name: "lic", Version: "1", License: long[:MaxLicenseLen+1]},
	}
	out := validate(Go, in)
	require.Len(t, out, 5)
	assert.Equal(t, "evilnametxt", out[0].Name)
	assert.Equal(t, "1[31m.0", out[0].Version)
	assert.Equal(t, "../../x<img onerror=1>", out[1].Name, "markup is kept; templates and JSON escape it")
	assert.Equal(t, "bad�utf", out[2].Name)
	assert.Equal(t, Dependency{Ecosystem: Go, Name: "dup", Version: "1", Direct: true, License: "MIT"}, out[3])
	assert.Empty(t, out[4].License)
	assert.NotContains(t, PURL(Go, out[1].Name, out[1].Version), "<")
}

func TestHostile(t *testing.T) {
	t.Run("requirements follow nothing", func(t *testing.T) {
		deps, err := FormatFor("requirements.txt").Parse(t.Context(), []byte("-r ../../../../etc/passwd\n--index-url http://169.254.169.254\n-e .\n"), nil)
		require.NoError(t, err)
		assert.Empty(t, deps)
	})
	t.Run("xml entities", func(t *testing.T) {
		xxe := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><project><artifactId>&x;</artifactId></project>`
		laughs := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><project><artifactId>&lol2;</artifactId></project>`
		for _, f := range []string{"pom.xml", "a.csproj"} {
			for _, x := range []string{xxe, laughs} {
				_, err := FormatFor(f).Parse(t.Context(), []byte(x), nil)
				require.ErrorIs(t, err, ErrParse, f)
			}
		}
	})
	t.Run("xml depth", func(t *testing.T) {
		start := time.Now()
		_, err := FormatFor("pom.xml").Parse(t.Context(), []byte(strings.Repeat("<a>", 100000)), nil)
		require.ErrorIs(t, err, ErrParse)
		assert.Less(t, time.Since(start), 5*time.Second)
	})
	t.Run("xml charset", func(t *testing.T) {
		_, err := FormatFor("pom.xml").Parse(t.Context(), []byte(`<?xml version="1.0" encoding="UTF-7"?><project/>`), nil)
		require.ErrorIs(t, err, ErrParse)
		m := parseText(t, "pom.xml", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><project><dependencies><dependency><groupId>org.x</groupId><artifactId>caf\xe9</artifactId><version>1</version></dependency></dependencies></project>", nil)
		assert.Contains(t, m, "org.x:café@1", "latin-1 is read")
	})
	t.Run("maven parent in the same repository", func(t *testing.T) {
		files := map[string]string{
			"../pom.xml":    `<project><groupId>org.x</groupId><artifactId>parent</artifactId><version>2.0</version><properties><lib.version>1.5</lib.version></properties><dependencyManagement><dependencies><dependency><groupId>org.x</groupId><artifactId>managed</artifactId><version>${lib.version}</version></dependency></dependencies></dependencyManagement></project>`,
			"../../pom.xml": `<project><groupId>org.x</groupId><artifactId>parent</artifactId><version>2.0</version><properties><lib.version>9</lib.version></properties></project>`,
		}
		find := func(n string, _ bool) []byte {
			if c, ok := files[n]; ok {
				return []byte(c)
			}
			return nil
		}
		child := `<project><parent><groupId>org.x</groupId><artifactId>parent</artifactId><version>2.0</version></parent><dependencies>
<dependency><groupId>org.x</groupId><artifactId>managed</artifactId></dependency>
<dependency><groupId>org.x</groupId><artifactId>prop</artifactId><version>${lib.version}</version></dependency>
</dependencies></project>`
		m := parseText(t, "pom.xml", child, find)
		assert.Contains(t, m, "org.x:managed@1.5")
		assert.Contains(t, m, "org.x:prop@1.5")
		// a relativePath names another parent; without a parent the versions stay empty
		m = parseText(t, "pom.xml", strings.Replace(child, "</parent>", "<relativePath>../../pom.xml</relativePath></parent>", 1), find)
		assert.Contains(t, m, "org.x:prop@9")
		// an empty <relativePath/> means no parent on the disk; a pom with other coordinates is not the parent
		m = parseText(t, "pom.xml", strings.Replace(child, "</parent>", "<relativePath/></parent>", 1), find)
		assert.Contains(t, m, "org.x:prop@")
		m = parseText(t, "pom.xml", strings.Replace(child, "<artifactId>parent</artifactId>", "<artifactId>spring-boot-starter-parent</artifactId>", 1), find)
		assert.Contains(t, m, "org.x:prop@")
		m = parseText(t, "pom.xml", strings.Replace(child, "<version>2.0</version></parent>", "<version>3.0</version></parent>", 1), find)
		assert.Contains(t, m, "org.x:prop@")
		m = parseText(t, "pom.xml", child, nil)
		assert.Contains(t, m, "org.x:managed@")
		assert.Contains(t, m, "org.x:prop@")
	})
	t.Run("yaml alias bomb", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\nl0: &a0 [a, a, a, a, a, a, a, a, a]\n")
		for i := 1; i < 12; i++ {
			prev := "*a" + strconv.Itoa(i-1)
			fmt.Fprintf(&b, "l%d: &a%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(prev+",", 9), ","))
		}
		start := time.Now()
		_, _ = FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte(b.String()), nil) // an error is expected; it must end quickly
		assert.Less(t, time.Since(start), time.Second)
	})
	t.Run("broken input is a parse error, never a panic", func(t *testing.T) {
		inputs := []string{"", "\x00\xff\xfe", "{", "[[[[", strings.Repeat(`{"a":`, 20000), strings.Repeat("x", 100000), "[[package]]\nname", "module", "\"@\":\n  version"}
		for _, name := range []string{"go.mod", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "pom.xml", "a.csproj", "packages.lock.json", "Cargo.lock", "Gemfile.lock", "composer.lock", "package.json", "composer.json", "Cargo.toml", "pyproject.toml", "Gemfile"} {
			for _, in := range inputs {
				_, _ = FormatFor(name).Parse(t.Context(), []byte(in), nil)
			}
		}
	})
	t.Run("a parser panic is a parse error", func(t *testing.T) {
		f := &Format{Ecosystem: Go, parse: func(*sink, []byte, Finder) error { panic("boom") }}
		_, err := f.Parse(t.Context(), nil, nil)
		require.ErrorIs(t, err, ErrParse)
	})
	t.Run("long line", func(t *testing.T) {
		_, err := FormatFor("Cargo.lock").Parse(t.Context(), []byte(strings.Repeat("x", maxLineLen+10)), nil)
		require.ErrorIs(t, err, ErrParse)
	})
	t.Run("json nesting", func(t *testing.T) {
		_, err := FormatFor("composer.lock").Parse(t.Context(), []byte(strings.Repeat("[", 100000)), nil)
		require.ErrorIs(t, err, ErrParse)
	})
}

func TestFormatFor(t *testing.T) {
	for _, n := range []string{"go.mod", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "pom.xml", "x.csproj", "packages.lock.json", "Cargo.lock", "Gemfile.lock", "composer.lock"} {
		assert.NotNil(t, FormatFor(n), n)
	}
	for _, n := range []string{"go.sum", "Go.mod", "requirements.md", "x.csproj.user", "gemfile", "uv.lock", ""} {
		assert.Nil(t, FormatFor(n), n)
	}
}

// FuzzParse runs every parser on the fixtures (the seed corpus) in a normal test run, and on mutations with -fuzz.
func FuzzParse(f *testing.F) {
	files, _ := filepath.Glob("testdata/*/*")
	files2, _ := filepath.Glob("testdata/*/*/*/*")
	for _, p := range append(files, files2...) {
		if b, err := os.ReadFile(p); err == nil && len(b) < 64<<10 {
			f.Add(path.Base(p), b)
		}
	}
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if format := FormatFor(name); format != nil {
			deps, err := format.Parse(t.Context(), data, nil)
			if err != nil {
				require.ErrorIs(t, err, ErrParse)
			}
			for _, d := range deps {
				require.NotEmpty(t, d.Name)
				require.LessOrEqual(t, len(d.Name), MaxNameLen)
				require.NotContains(t, d.Name+d.Version+d.License, "\x00")
			}
		}
	})
}

func parseText(t *testing.T, name, content string, find Finder) map[string]Dependency {
	t.Helper()
	deps, err := FormatFor(name).Parse(t.Context(), []byte(content), find)
	require.NoError(t, err)
	return index(deps)
}

func TestGoModBadLine(t *testing.T) {
	m := parseText(t, "go.mod", "module m\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/bad v9.9.9\n\texample.com/c v1.2.0 // indirect\n)\n\nrequire example.com/d v1.0.0\n", nil)
	assert.Len(t, m, 3)
	assert.Contains(t, m, "example.com/a@v1.0.0")
	assert.Contains(t, m, "example.com/c@v1.2.0")
	assert.Contains(t, m, "example.com/d@v1.0.0")
	_, err := FormatFor("go.mod").Parse(t.Context(), []byte("not a go mod ((("), nil)
	require.Error(t, err)
}

func TestLocalPackagesAndPlatforms(t *testing.T) {
	t.Run("go replace by a directory", func(t *testing.T) {
		m := parseText(t, "go.mod", "module m\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n\texample.com/c v1.0.0\n)\n\nreplace example.com/a => ../a\n\nreplace example.com/b v1.0.0 => ./b\n\nreplace example.com/c => example.com/fork v1.2.3\n", nil)
		assert.Len(t, m, 1)
		assert.Contains(t, m, "example.com/c@v1.0.0")
	})
	t.Run("poetry directory and file sources", func(t *testing.T) {
		m := parseText(t, "poetry.lock", `[[package]]
name = "registry"
version = "1.0.0"

[[package]]
name = "localdir"
version = "0.1.0"

[package.source]
type = "directory"
url = "../localdir"

[[package]]
name = "localfile"
version = "0.2.0"

[package.source]
type = "file"
url = "dist/x.whl"

[[package]]
name = "fromgit"
version = "0.3.0"

[package.source]
type = "git"
url = "https://example.test/x.git"
`, nil)
		assert.Len(t, m, 2)
		assert.Contains(t, m, "registry@1.0.0")
		assert.Contains(t, m, "fromgit@0.3.0")
	})
	t.Run("pyproject include-group is not a package", func(t *testing.T) {
		m := pyprojectDeps(newSink(t.Context(), 1000), []byte("[dependency-groups]\ndev = [\"pytest>=8\", {include-group = \"test\"}]\n"))
		assert.True(t, m["pytest"])
		assert.False(t, m["test"])
	})
	t.Run("composer path repository", func(t *testing.T) {
		m := parseText(t, "composer.lock", `{"packages":[{"name":"a/b","version":"1.0.0","dist":{"type":"zip"}},{"name":"a/local","version":"dev-main","dist":{"type":"path"}}]}`, nil)
		assert.Len(t, m, 1)
		assert.Contains(t, m, "a/b@1.0.0")
	})
	t.Run("gem platform suffix", func(t *testing.T) {
		m := parseText(t, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.4-x86_64-linux)\n    nokogiri (1.15.4-arm64-darwin)\n    nokogiri (1.15.4)\n    rack (3.0.0)\n\nDEPENDENCIES\n  nokogiri\n", nil)
		assert.Len(t, m, 2)
		assert.True(t, m["nokogiri@1.15.4"].Direct)
	})
	t.Run("npm v3 aliases and workspace members", func(t *testing.T) {
		m := parseText(t, "package-lock.json", `{"lockfileVersion":3,"packages":{
"":{"workspaces":["packages/*"],"dependencies":{"str":"npm:string-width@4"}},
"node_modules/str":{"name":"string-width","version":"4.2.3"},
"packages/a":{"dependencies":{"chalk":"^5"}},
"node_modules/chalk":{"version":"5.0.0"},
"node_modules/other":{"version":"1.0.0"}}}`, nil)
		assert.True(t, m["string-width@4.2.3"].Direct, "an alias is direct under its installed name")
		assert.True(t, m["chalk@5.0.0"].Direct, "a workspace member's dependency is direct")
		assert.False(t, m["other@1.0.0"].Direct)
	})
}

// pnpm reads its lockfile with a full YAML parser. Valid YAML this reader would read differently is refused (a
// parse error), never read into partial or invented rows.
// pnpmHidden is a lockfile whose package a@1.0.0 carries lines (the argument) that a YAML reader that lets a quote run
// over lines would use to swallow the section after it and then list evil@6.6.6.
func pnpmHidden(lines string) string {
	return "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0\n\npackages:\n\n" +
		"  a@1.0.0:\n    resolution: {integrity: sha512-a}\n" + lines + "  evil@6.6.6:\n    resolution: {integrity: sha512-e}\n"
}

func TestPnpmFailsClosed(t *testing.T) {
	const head = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0\n\npackages:\n\n"
	const a = "  a@1.0.0:\n    resolution: {integrity: sha512-a}\n\n"
	f := FormatFor("pnpm-lock.yaml")
	for name, in := range map[string]string{
		"anchor":                         head + "  &p a@1.0.0:\n    resolution: {}\n",
		"alias section":                  "lockfileVersion: '9.0'\npackages: *p\n",
		"flow packages":                  "lockfileVersion: '9.0'\npackages: {a@1.0.0: {resolution: {}}, evil@6.6.6: {resolution: {}}}\n",
		"json style file":                `{"lockfileVersion":"9.0","packages":{"evil@6.6.6":{}}}`,
		"block scalar packages":          "lockfileVersion: '9.0'\npackages: |\n  fake@1.0.0:\n    resolution: {}\n",
		"block scalar in a package":      head + a + "  b@1.0.0:\n    description: |\n  fake@9.9.9:\n      x\n",
		"folded value":                   head + "  b@1.0.0:\n    description: >\n      text\n",
		"four-space indentation":         "lockfileVersion: '9.0'\npackages:\n    a@1.0.0:\n        resolution: {}\n    evil@6.6.6:\n        resolution: {}\n",
		"odd indentation":                head + "   evil@6.6.6:\n    resolution: {}\n",
		"tab":                            head + "\ta@1.0.0:\n",
		"merge key":                      head + a + "  <<: *p\n",
		"alias value":                    head + "  b@1.0.0:\n    resolution: *r\n",
		"tag":                            head + "  b@1.0.0:\n    resolution: !!map {}\n",
		"escape in a key":                head + a + "  \"\\x65vil@6.6.6\":\n    resolution: {}\n",
		"unterminated quote":             head + "  b@1.0.0:\n    description: \"foo\n      bar: baz\"\n",
		"multi-line flow mapping":        head + "  b@1.0.0:\n    resolution: {integrity: x,\n      tarball: y}\n",
		"explicit key without its value": head + "  ? " + strings.Repeat("x", 1100) + "@1.0.0\n  b@1.0.0:\n    resolution: {}\n",
		"sequence item as a key":         head + "  - a@1.0.0\n",
		"unterminated flow deeper down":  head + "  b@1.0.0:\n    peerDependenciesMeta:\n      x: {optional: [\n  evil@6.6.6:\n    resolution: {}\n",
		"open quote in a deep item":      pnpmHidden("    cpu:\n      - \"x64\nsettings:\n  foo: \"\n"),
		"open single quote in an item":   pnpmHidden("    cpu:\n      - 'x64\nsettings:\n  foo: '\n"),
		"open quote in a mapping item":   pnpmHidden("    cpu:\n      - k: \"x64\nsettings:\n  foo: \"\n"),
		"quote inside a flow value":      pnpmHidden("    cpu: [x64, \"a]\nsettings:\n  foo: \"]\n"),
		"single quote inside a flow":     pnpmHidden("    cpu: [x64, 'a]\nsettings:\n  foo: ']\n"),
		"open quote in a flow mapping":   pnpmHidden("    resolution2: {integrity: \"x}\nsettings:\n  foo: \"}\n"),
		"unbalanced bracket":             pnpmHidden("    cpu: [x64\n"),
		"trailing space":                 head + "  b@1.0.0: \n    resolution: {}\n",
		"trailing comment on a header":   head + "  b@1.0.0: # c\n    resolution: {}\n",
		"flow mapping as a package":      head + "  b@1.0.0: {resolution: {integrity: x}, name: evil, version: 6.6.6}\n",
		"importers deep open quote":      "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0\n      x:\n        - \"q\nsettings:\n  z: \"\n      evil:\n        version: 6.6.6\n",
		"top-level flow":                 "lockfileVersion: '9.0'\nsettings: {\npackages:\n  a@1.0.0:\n    resolution: {}\n",
		"comments":                       head + "# c\n" + a + "  # d\n",

		// round 4 (rereview-security-3) and the differential fuzz against pnpm's loader (@zkochan/js-yaml): each
		// of these read other rows than pnpm before
		"N1 quote after ?":               pnpmHidden("    cpu:\n      ? \"x\nsettings:\n  foo: ? \"\n"),
		"N1 quote after a nested -":      pnpmHidden("    cpu:\n      - - \"x\nsettings:\n  foo: - \"\n"),
		"N1 quote after - ?":             pnpmHidden("    cpu:\n      - ? \"x\nsettings:\n  foo: - ? \"\n"),
		"N1 single quote after ?":        pnpmHidden("    cpu:\n      ? 'x\nsettings:\n  foo: ? '\n"),
		"N2 lone CR in an item":          head + "  a@1.0.0:\n    resolution: {integrity: sha512-a}\n    os:\n      - x\r  evil@6.6.6:\r    resolution:\r      integrity:\r        sha512-e\n  b@2.0.0:\n    resolution: {integrity: sha512-b}\n",
		"N2 lone CR hides a section":     "lockfileVersion: '9.0'\nsettings:\n  x: y\rpackages:\r  a@1.0.0:\r    resolution: {integrity: x}\n",
		"N2 lone CR at the start":        "\rpackages:\n  a@1.0.0:\n    resolution: {integrity: x}\n",
		"N3 space before the colon":      "lockfileVersion: '9.0'\npackages :\n  evil@6.6.6:\n    resolution: {integrity: e}\n",
		"N3 tab before the colon":        "lockfileVersion: '9.0'\npackages\t:\n  evil@6.6.6:\n    resolution: {integrity: e}\n",
		"N3 tab in lockfileVersion key":  "lockfileVersion\t: 5.4\npackages:\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {integrity: x}\n",
		"N5 value on the next line":      head + "  a@1.0.0:\n    resolution: {integrity: x}\n    name:\n      evil\n    version:\n      6.6.6\n",
		"N5 plain continuation":          head + "  a@1.0.0:\n    resolution: {integrity: x}\n    version: 1.0.0\n      6\n",
		"N5 importer version below":      "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version:\n          1.0.0\n",
		"a number for js-yaml":           head + "  a@1.0.0:\n    resolution: {integrity: x}\n    version: 1.0\n",
		"a number as a key":              head + "  1.0:\n    resolution: {integrity: x}\n",
		"a sequence as lockfileVersion":  "lockfileVersion: [5.4]\ndependencies:\n  lodash: 4.17.21\npackages:\n  /lodash/4.17.21:\n    resolution: {integrity: x}\n",
		"a sequence as a dependency map": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: [a]\n",
		"--- without the lockfile":       "---\npackages:\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {integrity: x}\n",
		"--- CRLF without the lockfile":  "---\r\npackages:\r\n  p-try@2.2.0:\r\n    resolution: {integrity: x}\r\n",
		"a second document":              head + a + "---\n" + head + "  evil@6.6.6:\n    resolution: {integrity: e}\n",
		"a document end marker":          head + a + "...\n",
		"double-quoted escape value":     head + "  a@1.0.0:\n    resolution: {integrity: x}\n    version: \"\\x36.6.6\"\n",
		"explicit key outside packages":  "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ? a\n      : version: 1.0.0\n",
	} {
		t.Run(name, func(t *testing.T) {
			deps, err := f.Parse(t.Context(), []byte(in), nil)
			require.ErrorIs(t, err, ErrParse)
			assert.Empty(t, deps)
		})
	}
	// forms pnpm writes still read
	for name, in := range map[string]string{
		"crlf":                           strings.ReplaceAll(head+a, "\n", "\r\n"),
		"empty section":                  "lockfileVersion: '9.0'\n\npackages: {}\n",
		"quoted key":                     head + "  'a@1.0.0':\n    resolution: {integrity: sha512-a}\n",
		"double quoted":                  head + "  \"a@1.0.0\":\n    resolution: {integrity: sha512-a}\n",
		"flow value":                     head + "  a@1.0.0:\n    resolution: {integrity: sha512-a, tarball: 'https://x/y.tgz'}\n    engines: {node: '>=12'}\n    cpu: [x64]\n",
		"peer sequences":                 head + "  a@1.0.0:\n    resolution: {integrity: sha512-a}\n    transitivePeerDependencies:\n      - '@algolia/client-search'\n      - b\n    peerDependenciesMeta:\n      b:\n        optional: true\n",
		"snapshot values":                head + a + "snapshots:\n\n  a@1.0.0: {}\n",
		"byte order mark":                "\ufeff" + head + a, // removed, as pnpm does
		"after the environment document": "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies: {}\n\n---\n" + head + a,
		"a --- line in the environment document's first line": "---\n---\nlockfileVersion: '9.0'\n---\n" + head + a,
	} {
		t.Run(name, func(t *testing.T) {
			deps, err := f.Parse(t.Context(), []byte(in), nil)
			require.NoError(t, err)
			if name != "empty section" {
				require.Len(t, deps, 1)
				assert.Equal(t, "a", deps[0].Name)
			}
		})
	}
}

// js-yaml writes a key over 1024 characters as `? key` and the mapping after `: `.
func TestPnpmExplicitKey(t *testing.T) {
	long := "foo@1.0.0(" + strings.Repeat("peer@1.0.0(", 120) + strings.Repeat(")", 121)
	in := "lockfileVersion: '6.0'\n\nimporters:\n\n  .:\n    dependencies:\n      foo:\n        specifier: 1.0.0\n        version: 1.0.0(" + strings.Repeat("peer@1.0.0(", 120) + strings.Repeat(")", 121) +
		"\n\npackages:\n\n  ? /" + long + "\n  : resolution: {integrity: sha512-a}\n    engines: {node: '>=12'}\n    dev: false\n\n  /bar@2.0.0:\n    resolution: {integrity: sha512-b}\n    dev: false\n"
	require.Greater(t, len(long), 1024)
	m := index(mustParse(t, "pnpm-lock.yaml", in))
	require.Contains(t, m, "foo@1.0.0")
	assert.True(t, m["foo@1.0.0"].Direct)
	assert.Contains(t, m, "bar@2.0.0")
	assert.Len(t, m, 2)
}

func mustParse(t *testing.T, name, in string) []Dependency {
	t.Helper()
	deps, err := FormatFor(name).Parse(t.Context(), []byte(in), nil)
	require.NoError(t, err)
	return deps
}

func TestPnpmGitDependencyStaysDirect(t *testing.T) {
	in := "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      mousetrap:\n        specifier: github:chabou/mousetrap#c95e\n        version: https://codeload.github.com/chabou/mousetrap/tar.gz/c95e\n\npackages:\n\n  mousetrap@https://codeload.github.com/chabou/mousetrap/tar.gz/c95e:\n    resolution: {tarball: 'https://codeload.github.com/chabou/mousetrap/tar.gz/c95e'}\n    version: 1.6.1\n"
	deps := mustParse(t, "pnpm-lock.yaml", in)
	require.Len(t, deps, 1)
	assert.True(t, deps[0].Direct)
	assert.Equal(t, "1.6.1", deps[0].Version)
}

func TestRequirementsFilesAreNotPackages(t *testing.T) {
	deps := mustParse(t, "requirements.txt", "foo-1.0-py3-none-any.whl\n./x.tar.gz\nbar.zip\nreal==1.0\n")
	require.Len(t, deps, 1)
	assert.Equal(t, "real", deps[0].Name)
}

func TestGemPlatformSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"1.15.4-x86_64-linux": "1.15.4", "1.15.4-arm64-darwin": "1.15.4", "1.0-java": "1.0", "1.2-x64-mingw32": "1.2",
		"1.0.0-rc1": "1.0.0-rc1", "2.0.0.pre1": "2.0.0.pre1", "1.0.0-beta": "1.0.0-beta",
	} {
		assert.Equal(t, want, gemVersion(in), in)
	}
}

// yarn.lock: only the shapes yarn writes are read; any other line is a parse error, never a hidden entry.
func TestYarnFailsClosed(t *testing.T) {
	const berry = "__metadata:\n  version: 8\n\n"
	for name, in := range map[string]string{
		"header with a trailing space":  berry + "\"evil@npm:^6.6.6\": \n  version: 6.6.6\n",
		"header with a comment":         berry + "\"c@npm:^1\": # x\n  version: 1.0.0\n",
		"flow entry":                    berry + "\"evil@npm:^6.6.6\": {version: 6.6.6, resolution: \"evil@npm:6.6.6\"}\n",
		"four-space fields":             berry + "\"evil@npm:^6.6.6\":\n    version: 6.6.6\n",
		"odd indentation":               berry + "\"evil@npm:^6.6.6\":\n   version: 6.6.6\n",
		"tab":                           berry + "\"evil@npm:^6.6.6\":\n\tversion: 6.6.6\n",
		"open quote in a field":         berry + "\"evil@npm:^6.6.6\":\n  version: 6.6.6\n  resolution: \"evil@npm:6.6.6\n",
		"open quote in a header":        berry + "\"evil@npm:^6.6.6:\n  version: 6.6.6\n",
		"two versions":                  berry + "\"evil@npm:^6.6.6\":\n  version: 1.0.0\n  version: 6.6.6\n",
		"v1 header with trailing space": "# yarn lockfile v1\n\nevil@^6.6.6: \n  version \"6.6.6\"\n",
		"v1 four-space fields":          "# yarn lockfile v1\n\nevil@^6.6.6:\n    version \"6.6.6\"\n",
		// classes the differential fuzz against @yarnpkg/parsers and @yarnpkg/lockfile found (fix round 4)
		"lone CR":                          berry + "\"a@npm:^1\":\r  version: 1.0.0\r  resolution: \"a@npm:1.0.0\"\n",
		"escape in a header":               berry + "\"\\u0065vil@npm:^6.6.6\":\n  version: 6.6.6\n  resolution: \"evil@npm:6.6.6\"\n",
		"comment after a value":            berry + "\"a@npm:^1\":\n  version: \"6.6.6\" # c\n  resolution: \"a@npm:6.6.6\"\n",
		"value on the next line":           berry + "\"a@npm:^1\":\n  version:\n    6.6.6\n  resolution: \"a@npm:6.6.6\"\n",
		"quoted field key":                 berry + "\"a@npm:^1\":\n  version: 1.0.0\n  \"version\": 6.6.6\n  resolution: \"a@npm:1.0.0\"\n",
		"explicit field key":               berry + "\"a@npm:^1\":\n  version: 1.0.0\n  ? version\n  : 6.6.6\n  resolution: \"a@npm:1.0.0\"\n",
		"version against resolution":       berry + "\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"a@npm:6.6.6\"\n",
		"no resolution":                    berry + "\"a@npm:^1\":\n  version: 1.0.0\n",
		"header twice":                     berry + "\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n\n\"a@npm:^1\":\n  version: 6.6.6\n  resolution: \"a@npm:6.6.6\"\n",
		"v1 escape in a header":            "# yarn lockfile v1\n\n\"\\u0065vil@^6.6.6\":\n  version \"6.6.6\"\n",
		"v1 indented line after a comment": "# yarn lockfile v1\n  version \"6.6.6\"\na@^1.0.0:\n  version \"1.0.0\"\n",
		"v1 indented line after a blank":   "# yarn lockfile v1\n\na@^1.0.0:\n\n  version \"6.6.6\"\n",
		"v1 white space line":              "# yarn lockfile v1\n\na@^1.0.0:\n    \n  version \"6.6.6\"\n",
		"v1 lone CR":                       "# yarn lockfile v1\n\na@^1.0.0:\n  version \"1.0.0\"\r\revil@^6.6.6:\r  version \"6.6.6\"\n",
		"v1 two packages in a header":      "# yarn lockfile v1\n\na@^1.0.0, evil@^6.6.6:\n  version \"1.0.0\"\n",
		"v1 descriptor twice":              "# yarn lockfile v1\n\na@^1.0.0:\n  version \"1.0.0\"\n\na@^1.0.0:\n  version \"6.6.6\"\n",
		"v1 unquoted version":              "# yarn lockfile v1\n\na@^1.0.0:\n  version 1.0\n",
		"v1 field twice":                   "# yarn lockfile v1\n\na@^1.0.0:\n  version \"1.0.0\"\n  \"version\" \"6.6.6\"\n",
		"v1 boolean word":                  "# yarn lockfile v1\n\na@^1.0.0:\n  version \"1.0.0\"\n  trueish \"x\"\n",
		// yarn takes a header with any of JavaScript's white space for version 1 (security re-review 4, M3): a
		// berry body behind it is no version 1 file
		"v1 header with NBSP, berry body":   "#\u00a0yarn lockfile v1\n\n\"evil@npm:^6.6.6\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
		"v1 header with U+3000":             "# yarn\u3000lockfile v1\n\n\"evil@npm:^6.6.6\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
		"v1 header with U+2028":             "#\u2028yarn lockfile v1\n\n\"evil@npm:^6.6.6\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
		"v1 header in capitals":             "# YARN LOCKFILE V1\n\n\"evil@npm:^6.6.6\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
		"v1 behind a BOM is no v1 for yarn": "\ufeff# yarn lockfile v1\n\na@^1:\n  version \"1.0.0\"\n",
		// berry resolutions other than npm: never the `version:` unchecked (S-L5)
		"patch of another version": berry + "\"lodash@patch:lodash@npm%3A^4#./p.patch\":\n  version: 4.17.21\n  resolution: \"lodash@patch:lodash@npm%3A4.17.4#./p.patch::version=4.17.4&hash=x\"\n",
		"patch of a patch":         berry + "\"a@patch:a@npm%3A^1#./p.patch\":\n  version: 1.0.0\n  resolution: \"a@patch:a@patch%3Aa@npm%253A1.0.0#./p.patch\"\n",
		"patch that won't decode":  berry + "\"a@patch:a@npm%3A^1#./p.patch\":\n  version: 1.0.0\n  resolution: \"a@patch:a@npm%ZZ1.0.0#./p.patch\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			deps, err := FormatFor("yarn.lock").Parse(t.Context(), []byte(in), nil)
			require.ErrorIs(t, err, ErrParse)
			assert.Empty(t, deps)
		})
	}
	// what yarn writes still reads
	in := berry + "\"a@npm:^1, a@npm:^1.2\":\n  version: 1.2.0\n  resolution: \"a@npm:1.2.0\"\n  dependencies:\n    b: \"npm:^2\"\n  checksum: 10/abc\n  languageName: node\n  linkType: hard\n"
	deps, err := FormatFor("yarn.lock").Parse(t.Context(), []byte(in), nil)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "1.2.0", deps[0].Version)
	// a patched alias (yarn writes `typescript@npm:@typescript/typescript6@6.0.2` patched so): the real package
	in = berry + "\"typescript@patch:typescript@npm%3A@typescript/typescript6@6.0.2#optional!builtin<compat/typescript>\":\n  version: 6.0.2\n  resolution: \"typescript@patch:@typescript/typescript6@npm%3A6.0.2#optional!builtin<compat/typescript>::version=6.0.2&hash=5786d5\"\n"
	deps, err = FormatFor("yarn.lock").Parse(t.Context(), []byte(in), nil)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "@typescript/typescript6", deps[0].Name)
	assert.Equal(t, "6.0.2", deps[0].Version)
	v1 := "# yarn lockfile v1\n\n\"@s/a@^1\", \"@s/a@^1.1\":\n  version \"1.2.0\"\n  resolved \"https://r/a.tgz#abc\"\n  dependencies:\n    b \"^2\"\n"
	deps, err = FormatFor("yarn.lock").Parse(t.Context(), []byte(v1), nil)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	// the package is the one the resolution names (what yarn installs), not the header's
	deps, err = FormatFor("yarn.lock").Parse(t.Context(), []byte(berry+"\"a@npm:^1.0.0\":\n  version: 6.6.6\n  resolution: \"evil@npm:6.6.6\"\n"), nil)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "evil", deps[0].Name)
	assert.Equal(t, "6.6.6", deps[0].Version)
	// a BOM is stripped in a berry file, as js-yaml does, and a header over 1024 characters is written as
	// `? header` / `:`
	long := "a@npm:" + strings.Repeat("1", 1100)
	for _, in := range []string{
		"\ufeff" + berry + "\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
		berry + "? \"" + long + "\"\n:\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
		// a Kelvin sign is no k for JavaScript's /i: this is no version 1 header, the file is read as berry
		"# yarn loc\u212afile v1\n" + berry + "\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n",
	} {
		deps, err = FormatFor("yarn.lock").Parse(t.Context(), []byte(in), nil)
		require.NoError(t, err)
		require.Len(t, deps, 1)
	}
}

// A package.json shared by many manifests is parsed once per scan, whatever the number of lock files; parses
// that the cache doesn't serve are bounded by the parse budget, and a package.json over the key limit is absent.
func TestHelperCacheParsesSharedPackageJSONOnce(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"dependencies":{`)
	for i := range 5000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"pkg-%d":"^1.%d.0"`, i, i)
	}
	sb.WriteString(`}}`)
	pkg := []byte(sb.String())
	lock := []byte("# yarn lockfile v1\n\npkg-1@^1.1.0:\n  version \"1.1.0\"\n")
	find := func(string, bool) []byte { return pkg }
	parse := func(ctx context.Context) []Dependency {
		deps, err := FormatFor("yarn.lock").ParseLimited(ctx, lock, find, 1000)
		require.NoError(t, err)
		require.Len(t, deps, 1)
		return deps
	}

	// the parses are what the cache charged to its parse budget
	parses := func(h *HelperCache, budget int64, pkg []byte) int64 { return (budget - h.parseLeft) / int64(len(pkg)) }
	h := NewHelperCache(8<<20, 8<<20)
	require.True(t, h.Keep(pkg))
	ctx := WithHelperCache(t.Context(), h)
	start := time.Now()
	for range 400 {
		assert.True(t, parse(ctx)[0].Direct)
	}
	assert.EqualValues(t, 1, parses(h, 8<<20, pkg))
	assert.Less(t, time.Since(start), 3*time.Second)

	// a file the scan doesn't keep is parsed each time, until the parse budget is spent: then it counts as absent
	h = NewHelperCache(8<<20, int64(2*len(pkg)))
	ctx = WithHelperCache(t.Context(), h)
	assert.True(t, parse(ctx)[0].Direct)
	assert.True(t, parse(ctx)[0].Direct)
	assert.False(t, parse(ctx)[0].Direct)
	assert.EqualValues(t, 2, parses(h, int64(2*len(pkg)), pkg))

	// over the key limit: absent, and the result (nothing) is cached like any other
	sb.Reset()
	sb.WriteString(`{"dependencies":{"pkg-1":"^1.1.0"`)
	for i := range 100000 {
		fmt.Fprintf(&sb, `,"%05x":""`, i)
	}
	sb.WriteString(`}}`)
	pkg = []byte(sb.String())
	h = NewHelperCache(8<<20, 8<<20)
	require.True(t, h.Keep(pkg))
	ctx = WithHelperCache(t.Context(), h)
	for range 400 {
		assert.False(t, parse(ctx)[0].Direct)
	}
	assert.EqualValues(t, 1, parses(h, 8<<20, pkg))
}

// A berry entry takes its version from its resolution: an npm one or the npm locator a patch applies to; a git
// or URL resolution names none, and the project's own packages are left out. The workspaces are what the lock
// covers.
func TestYarnBerryResolutions(t *testing.T) {
	const berry = "__metadata:\n  version: 8\n\n"
	entry := func(header, version, resolution string) string {
		return "\"" + header + "\":\n  version: " + version + "\n  resolution: \"" + resolution + "\"\n\n"
	}
	in := berry +
		entry("lodash@patch:lodash@npm%3A^4#./p.patch", "4.17.4", "lodash@patch:lodash@npm%3A4.17.4#./p.patch::version=4.17.4&hash=x") +
		entry("@s/a@patch:@s/a@npm%3A^1#./p.patch", "1.0.0", "@s/a@patch:@s/a@npm%3A1.0.0#./p.patch::version=1.0.0&hash=y") +
		entry("g@https://github.com/x/g.git", "9.9.9", "g@https://github.com/x/g.git#commit=abc") +
		entry("e@exec:./gen.js", "1.0.0", "e@exec:./gen.js#./gen.js::hash=z") +
		entry("app@workspace:.", "0.0.0-use.local", "app@workspace:.") +
		entry("lib@workspace:packages/lib", "0.0.0-use.local", "lib@workspace:packages/lib")
	r, err := FormatFor("yarn.lock").ParseFull(t.Context(), []byte(in), nil, 100)
	require.NoError(t, err)
	got := map[string]string{}
	for _, d := range r.Deps {
		got[d.Name] = d.Version
	}
	assert.Equal(t, map[string]string{"lodash": "4.17.4", "@s/a": "1.0.0", "g": ""}, got)
	assert.Equal(t, []string{".", "packages/lib"}, r.Info.Dirs)

	// version 1: the root and the workspaces of the package.json next to it
	v1 := "# yarn lockfile v1\n\na@^1:\n  version \"1.0.0\"\n"
	find := func(name string, _ bool) []byte {
		if name == "package.json" {
			return []byte(`{"workspaces": {"packages": ["packages/*"]}, "dependencies": {"a": "^1"}}`)
		}
		return nil
	}
	r, err = FormatFor("yarn.lock").ParseFull(t.Context(), []byte(v1), find, 100)
	require.NoError(t, err)
	assert.Equal(t, Info{Dirs: []string{"."}, Globs: []string{"packages/*"}}, r.Info)
}
