// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requirements returns name -> requirement of an unpinned parse, checking that no row has a version and that every
// row is direct.
func requirements(t *testing.T, name, content string) map[string]string {
	t.Helper()
	deps, err := FormatFor(name).Parse(t.Context(), []byte(content), nil)
	require.NoError(t, err, name)
	out := map[string]string{}
	for _, d := range deps {
		assert.Empty(t, d.Version, d.Name)
		assert.True(t, d.Direct, d.Name)
		out[d.Name] = d.Requirement
	}
	return out
}

func TestUnpinnedFormats(t *testing.T) {
	for name, locks := range map[string][]string{
		"package.json":   {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
		"Cargo.toml":     {"Cargo.lock"},
		"Gemfile":        {"Gemfile.lock"},
		"composer.json":  {"composer.lock"},
		"pyproject.toml": {"poetry.lock"}, // uv.lock has no reader: it covers nothing
	} {
		f := FormatFor(name)
		require.NotNil(t, f, name)
		assert.True(t, f.Unpinned && f.Small, name)
		assert.Equal(t, locks, f.Locks, name)
		for _, l := range locks {
			assert.True(t, IsLockName(l), l)
		}
	}
	assert.False(t, FormatFor("package-lock.json").Unpinned)
	assert.False(t, IsLockName("package.json"))
	assert.False(t, IsLockName("go.sum"))
	assert.False(t, IsLockName("uv.lock"))
}

func TestLockAbove(t *testing.T) {
	read := map[string]bool{"package-lock.json": true, "rust/Cargo.lock": true, "Gemfile.lock": true}
	has := func(p string) bool { return read[p] }
	assert.Equal(t, "package-lock.json", FormatFor("package.json").LockAbove("docs/site/package.json", has))
	assert.Equal(t, "rust/Cargo.lock", FormatFor("Cargo.toml").LockAbove("rust/tools/app/Cargo.toml", has))
	assert.Empty(t, FormatFor("Cargo.toml").LockAbove("crates/x/Cargo.toml", has))
	assert.Empty(t, FormatFor("Gemfile").LockAbove("ruby/Gemfile", has), "a Gemfile.lock covers only the Gemfile next to it")
}

func TestCovered(t *testing.T) {
	root := &Info{Dirs: []string{".", "apps/web"}}
	locks := map[string]*Info{"package-lock.json": root, "ruby/Gemfile.lock": {}, "py/poetry.lock": {}}
	npm, gem, cargo, py := FormatFor("package.json"), FormatFor("Gemfile"), FormatFor("Cargo.toml"), FormatFor("pyproject.toml")
	// a root lock covers the root and the workspaces it was resolved for, not another project below it
	assert.True(t, npm.Covered("package.json", locks, nil))
	assert.True(t, npm.Covered("apps/web/package.json", locks, nil))
	assert.False(t, npm.Covered("docs/package.json", locks, nil), "a nested project that is no workspace member")
	assert.False(t, npm.Covered("apps/web/sub/package.json", locks, nil))
	// yarn version 1: the root package.json's workspace patterns, with their negations
	locks["yarn/yarn.lock"] = &Info{Dirs: []string{"."}, Globs: []string{"packages/*", "./tools/", "!packages/private"}}
	assert.True(t, npm.Covered("yarn/packages/a/package.json", locks, nil))
	assert.True(t, npm.Covered("yarn/tools/package.json", locks, nil))
	assert.False(t, npm.Covered("yarn/packages/private/package.json", locks, nil))
	assert.False(t, npm.Covered("yarn/packages/a/b/package.json", locks, nil))
	// the lock files next to the manifest only
	assert.True(t, gem.Covered("ruby/Gemfile", locks, nil))
	assert.False(t, gem.Covered("ruby/sub/Gemfile", locks, nil), "no lock above for Gemfile")
	assert.False(t, FormatFor("composer.json").Covered("composer.json", locks, nil))
	assert.True(t, py.Covered("py/pyproject.toml", locks, nil))
	assert.False(t, py.Covered("py/sub/pyproject.toml", locks, nil))
	// a lock file that wasn't read (or uv.lock, which has no reader) is not in locks: it covers nothing
	assert.False(t, py.Covered("uv/pyproject.toml", map[string]*Info{"uv/uv.lock": {}}, nil))
	// Cargo: next to the lock always; below it only a member the lock names that has no workspace of its own
	locks["Cargo.lock"] = &Info{Members: []string{"app", "a"}, Globs: []string{"crates/*", "tools/*"}, Excludes: []string{"tools/a"}}
	assert.True(t, cargo.Covered("Cargo.toml", locks, nil), "the workspace root, also a virtual one")
	assert.False(t, cargo.Covered("crates/a/Cargo.toml", locks, nil), "below the lock: read first")
	assert.True(t, cargo.Covered("crates/a/Cargo.toml", locks, &Info{Name: "a"}))
	assert.False(t, cargo.Covered("crates/b/Cargo.toml", locks, &Info{Name: "b"}), "not a member")
	assert.False(t, cargo.Covered("fuzz/Cargo.toml", locks, &Info{Name: "a", OwnWorkspace: true}), "a workspace of its own")
	assert.False(t, cargo.Covered("x/Cargo.toml", locks, &Info{}), "no name")
	assert.False(t, cargo.Covered("tools/a/Cargo.toml", locks, &Info{Name: "a"}), "excluded, though a member has its name")
	assert.False(t, cargo.Covered("lib/a/Cargo.toml", locks, &Info{Name: "a"}), "no workspace member (a path dependency)")
	assert.False(t, cargo.Covered("crates/a/Cargo.toml", map[string]*Info{"Cargo.lock": {Members: []string{"a"}}}, &Info{Name: "a"}),
		"no Cargo.toml read next to the lock: nothing below it is covered")
}

func TestFallbackRealFixtures(t *testing.T) {
	for rel, want := range map[string]map[string]string{
		"nodegoat/package.json":   {"express": "^4.13.4", "bcrypt-nodejs": "0.0.3"},
		"koel/composer.json":      {"laravel/framework": "^9.0", "predis/predis": "~1.0"},
		"poetry/pyproject.toml":   {"poetry-core": "1.8.1", "cleo": "^2.1.0"},
		"serde-json/Cargo.toml":   {"itoa": "1.0", "memchr": "2", "serde": "1.0.220", "trybuild": "1.0.108"},
		"sinatra/Gemfile":         {"minitest": "~> 5.0", "rubocop": "~> 1.32.0", "rake": "", "falcon": "~> 0.40"},
		"httpx/pyproject.toml":    {"certifi": "", "httpcore": "==1.*", "rich": ">=10,<15", "h2": ">=3,<5"},
		"mastodon/package.json":   {},
		"defectdojo/package.json": {},
		"vite/package.json":       {},
	} {
		deps := parseFixture(t, rel)
		got := map[string]string{}
		for _, d := range deps {
			assert.Empty(t, d.Version, rel)
			got[d.Name] = d.Requirement
		}
		assert.NotEmpty(t, got, rel)
		for n, r := range want {
			assert.Contains(t, got, n, rel)
			assert.Equal(t, r, got[n], "%s: %s", rel, n)
		}
		switch rel {
		case "poetry/pyproject.toml":
			assert.NotContains(t, got, "python")
		case "sinatra/Gemfile":
			// path gems are the project's own; a gem with a modifier is listed (conditions are not evaluated)
			assert.NotContains(t, got, "rack-protection")
			assert.NotContains(t, got, "sinatra-contrib")
			assert.Equal(t, "~> 1.54", got["sass-embedded"])
			assert.Contains(t, got, "commonmarker")
		}
	}
}

func TestPackageJSON(t *testing.T) {
	got := requirements(t, "package.json", `{
		"name": "app", "version": "1.0.0",
		"dependencies": {"express": "^4.18.0", "local": "file:../local", "ws": "workspace:*", "rel": "./x.tgz",
			"alias": "npm:real-name@^2.1.0", "git": "git+https://example.com/x.git", "gh": "user/repo", "odd": 5},
		"devDependencies": {"lodash": "~4.17.20", "@types/node": "*"},
		"optionalDependencies": {"fsevents": "^2"},
		"peerDependencies": {"react": "^18"},
		"scripts": {"dependencies": "x"}
	}`)
	assert.Equal(t, map[string]string{
		"express": "^4.18.0", "real-name": "^2.1.0", "git": "", "gh": "", "odd": "",
		"lodash": "~4.17.20", "@types/node": "*", "fsevents": "^2",
	}, got)
	for _, bad := range []string{`[]`, `{"dependencies": ["a"]}`, `{"dependencies": {"a": "1"`, `"x"`, ``, "\xef\xbb\xbf"} {
		_, err := FormatFor("package.json").Parse(t.Context(), []byte(bad), nil)
		require.ErrorIs(t, err, ErrParse, bad)
	}
	// a byte order mark (npm strips it), an empty section written as a list, and a key given twice: the last one
	// wins, as in JSON.parse, and a section given twice replaces the first
	got = requirements(t, "package.json", "\xef\xbb\xbf"+`{"devDependencies": [], "dependencies": {"old": "1"},
		"dependencies": {"lodash": "^4.17.21", "lodash": "4.17.4"}}`)
	assert.Equal(t, map[string]string{"lodash": "4.17.4"}, got)
}

func TestComposerJSON(t *testing.T) {
	got := requirements(t, "composer.json", `{"require": {"php": ">=8.1", "ext-json": "*", "Monolog/Monolog": "^3.0", "composer-plugin-api": "^2"},
		"require-dev": {"phpunit/phpunit": "^10"}, "autoload": {"psr-4": {"A\\": "src/"}}}`)
	assert.Equal(t, map[string]string{"monolog/monolog": "^3.0", "phpunit/phpunit": "^10"}, got)
	_, err := FormatFor("composer.json").Parse(t.Context(), []byte(`{"require": "x"}`), nil)
	require.ErrorIs(t, err, ErrParse)
	// PHP's json_encode writes an empty map as []
	got = requirements(t, "composer.json", "\xef\xbb\xbf"+`{"require": {"a/b": "^1", "a/b": "^2"}, "require-dev": []}`)
	assert.Equal(t, map[string]string{"a/b": "^2"}, got)
}

func TestCargoToml(t *testing.T) {
	got := requirements(t, "Cargo.toml", `# a comment
[package]
name = "app"
description = """
[dependencies]
not-a-dependency = "1"
"""
keywords = ["a", "b",
  "c", # a comment in an array
]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
itoa = "1.0"
"quoted" = '2'
renamed = { package = "real-crate", version = "0.3" }
local = { path = "../local" }
inherited = { workspace = true }
dotted.version = "4"
dotted.optional = true
gitdep = { git = "https://example.com/x" }

[dependencies.tabled]
version = "~5"
default-features = false

[dev-dependencies]
tempfile = "3"

[build-dependencies]
cc = "1.0.83"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target."cfg(windows)".dev-dependencies.winapi]
version = "0.3"

[workspace.dependencies]
anyhow = "1"

[features]
default = ["serde"]

[[bin]]
name = "x"
path = "src/x.rs"
`)
	assert.Equal(t, map[string]string{
		"serde": "1.0", "itoa": "1.0", "quoted": "2", "real-crate": "0.3", "inherited": "", "dotted": "4", "gitdep": "",
		"tabled": "~5", "tempfile": "3", "cc": "1.0.83", "libc": "0.2", "winapi": "0.3", "anyhow": "1",
	}, got)

	for name, bad := range map[string]string{
		"dependency twice":            "[dependencies]\na = \"1\"\na = \"2\"\n",
		"table and value":             "[dependencies]\na = \"1\"\n[dependencies.a]\nversion = \"2\"\n",
		"field twice":                 "[dependencies]\na.version = \"1\"\na.version = \"2\"\n",
		"inline table twice":          "[dependencies]\na = {version = \"1\", version = \"2\"}\n",
		"number":                      "[dependencies]\na = 1\n",
		"unterminated string":         "[dependencies]\na = \"1\n",
		"unterminated array":          "[package]\nk = [\"a\",\n",
		"unterminated multi-line":     "[package]\nd = \"\"\"\n[dependencies]\na = \"1\"\n",
		"whole table as a value":      "dependencies = { a = \"1\" }\n",
		"garbage after a value":       "[dependencies]\na = \"1\" b\n",
		"bad header":                  "[dependencies\na = \"1\"\n",
		"lone carriage return":        "[dependencies]\ra = \"1\"\n",
		"deep nesting":                "[package]\nk = " + strings.Repeat("[", 40) + strings.Repeat("]", 40) + "\n",
		"bad escape":                  "[dependencies]\n\"a\\q\" = \"1\"\n",
		"key without a value":         "[dependencies]\na\n",
		"unicode escape out of range": "[dependencies]\n\"\\U00110000\" = \"1\"\n",
		// the dependency tables written in a form this reader doesn't descend into
		"target inline":         "target = { \"cfg(unix)\" = { dependencies = { evil = \"1\" } } }\n",
		"one target inline":     "[target]\n'cfg(unix)' = { dependencies = { evil = \"1\" } }\n",
		"workspace inline":      "workspace = { dependencies = { evil = \"1\" } }\n",
		"array of dependencies": "[[dependencies]]\nevil = \"1\"\n",
		"array of targets":      "[[target]]\nx = 1\n",
		"key below a field":     "[dependencies]\nserde.features.x = true\n",
		"dotted inline field":   "[dependencies]\nserde = { version.workspace = true }\n",
		"package won't decode":  "[dependencies]\nserde = { version = \"1\", package = \"evi\\ql\" }\n",
		"version not a string":  "[dependencies]\nserde = { version = 1 }\n",
		"package not a string":  "[dependencies]\nserde = { package = [\"evil\"] }\n",
	} {
		_, err := FormatFor("Cargo.toml").Parse(t.Context(), []byte(bad), nil)
		require.ErrorIs(t, err, ErrParse, name)
	}
	// CRLF line ends and a byte order mark are TOML
	got = requirements(t, "Cargo.toml", "\xef\xbb\xbf[dependencies]\r\na = \"1\"\r\n\"\\u00e9t\\u00e9\" = \"2\"\r\n")
	assert.Equal(t, map[string]string{"a": "1", "été": "2"}, got)
	// a line-ending backslash in a multi-line string trims the newline and the indentation; a date and a time
	// may be parted by a space
	got = requirements(t, "Cargo.toml", "[package]\nreleased = 1979-05-27 07:32:00Z\n[dependencies]\nserde = { version = \"1\", package = \"\"\"evi\\\n    l\"\"\" }\n")
	assert.Equal(t, map[string]string{"evil": "1"}, got)
}

// A Cargo.toml says which package it is, for the Cargo.lock above it.
func TestCargoTomlInfo(t *testing.T) {
	for content, want := range map[string]Info{
		"[package]\nname = \"app\"\n":                                          {Name: "app"},
		"[package]\nname = \"fuzz\"\n[workspace]\nmembers = [\".\"]\n":         {Name: "fuzz", OwnWorkspace: true, Globs: []string{"."}},
		"[workspace]\nmembers = [\"a\"]\n":                                     {OwnWorkspace: true, Globs: []string{"a"}},
		"[workspace]\nmembers = [\"a/*\"]\nexclude = [\"a/x\"]\n":              {OwnWorkspace: true, Globs: []string{"a/*"}, Excludes: []string{"a/x"}},
		"[workspace]\nmembers = [\"a/*\"]\nexclude = [1]\n":                    {OwnWorkspace: true},
		"[package]\nname.workspace = true\n":                                   {},
		"package.name = \"dotted\"\n[workspace.dependencies]\nserde = \"1\"\n": {Name: "dotted", OwnWorkspace: true},
	} {
		r, err := FormatFor("Cargo.toml").ParseFull(t.Context(), []byte(content), nil, 100)
		require.NoError(t, err, content)
		assert.Equal(t, want, r.Info, content)
	}
}

func TestPyprojectToml(t *testing.T) {
	got := requirements(t, "pyproject.toml", `[project]
name = "app"
dependencies = [
  "requests>=2.31,<3",
  "Flask[async] (>=3.0)",
  "tomli; python_version < '3.11'",
  "exact==1.2.3",
  "bare",
  "pkg [extra] @ https://example.com/pkg.whl",
  """multi\
     -line>=1""",
]
classifiers = ["Programming Language :: Python"]

[project.optional-dependencies]
dev = ["pytest>=7"]

[dependency-groups]
test = ["coverage", {include-group = "dev"}]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
mylib = { path = "../mylib", develop = true }
numpy = [
  { version = "^1.26", python = ">=3.9" },
  { version = "^1.24", python = "<3.9" },
]
pydantic = { version = "^2", extras = ["email"] }

[tool.poetry.group.lint.dependencies]
ruff = "^0.4"

[tool.poetry.dependencies.rich]
version = "^13"

[tool.uv]
dev-dependencies = ["uvdev>=1"]

[tool.pdm.dev-dependencies]
test = ["pdmdev~=2"]

[tool.hatch.envs.default]
dependencies = ["hatchenv"]
`)
	assert.Equal(t, map[string]string{
		"uvdev": ">=1", "pdmdev": "~=2", // hatch environments are the tool's own, not read
		"requests": ">=2.31,<3", "Flask": ">=3.0", "tomli": "", "exact": "==1.2.3", "bare": "", "pytest": ">=7",
		"coverage": "", "httpx": "^0.27", "numpy": "", "pydantic": "^2", "ruff": "^0.4", "rich": "^13",
		"pkg": "", "multi-line": ">=1", // a direct reference is a row without a range
	}, got)
	for name, bad := range map[string]string{
		"dependencies not an array": "[project]\ndependencies = \"requests\"\n",
		"poetry number":             "[tool.poetry.dependencies]\nhttpx = 1\n",
		"duplicate":                 "[tool.poetry.dependencies]\nhttpx = \"1\"\nhttpx = \"2\"\n",
		// the parts that are read, written in a form this reader doesn't descend into
		"project inline":           "project = { name = \"x\", dependencies = [\"evil>=1\"] }\n",
		"optional inline":          "[project]\noptional-dependencies = { dev = [\"evil>=1\"] }\n",
		"groups inline":            "dependency-groups = { dev = [\"evil>=1\"] }\n",
		"tool inline":              "tool = { poetry = { dependencies = { evil = \"^1\" } } }\n",
		"poetry inline":            "[tool]\npoetry = { dependencies = { evil = \"^1\" } }\n",
		"group inline":             "[tool.poetry]\ngroup = { dev = { dependencies = { evil = \"^1\" } } }\n",
		"one group inline":         "[tool.poetry.group]\ndev = { dependencies = { evil = \"^1\" } }\n",
		"uv inline":                "[tool]\nuv = { dev-dependencies = [\"evil\"] }\n",
		"pdm inline":               "[tool.pdm]\ndev-dependencies = { test = [\"evil\"] }\n",
		"uv dev as a table":        "[tool.uv.dev-dependencies]\nevil = \"1\"\n",
		"dependencies as a table":  "[project.dependencies]\nevil = \">=1\"\n",
		"optional as a table":      "[project.optional-dependencies.dev]\nevil = \">=1\"\n",
		"below an array":           "[project]\ndependencies.x = [\"evil\"]\n",
		"array of tables":          "[[tool.poetry.dependencies]]\nevil = \"1\"\n",
		"array of projects":        "[[project]]\ndependencies = [\"evil\"]\n",
		"key below a field":        "[tool.poetry.dependencies]\nevil.version.x = \"1\"\n",
		"dotted key in a field":    "[tool.poetry.dependencies]\nevil = { version.x = \"1\" }\n",
		"not a string":             "[project]\ndependencies = [1]\n",
		"inline table in project":  "[project]\ndependencies = [{include-group = \"x\"}]\n",
		"not a requirement":        "[project]\ndependencies = [\"./local.whl\"]\n",
		"string that won't decode": "[project]\ndependencies = [\"evil\\q\", \"a\"]\n",
		"field that won't decode":  "[tool.poetry.dependencies]\nevil = { version = \"\\q\" }\n",
		"version not a string":     "[tool.poetry.dependencies]\nevil = { version = 1 }\n",
	} {
		_, err := FormatFor("pyproject.toml").Parse(t.Context(), []byte(bad), nil)
		require.ErrorIs(t, err, ErrParse, name)
	}
	// a pyproject.toml of a tool's settings only names nothing
	assert.Empty(t, requirements(t, "pyproject.toml", "[tool.black]\nline-length = 100\n"))
}

func TestGemfile(t *testing.T) {
	src := `source "https://rubygems.org"
ruby "3.3.0"
gemspec

gem "rails", "~> 7.1", ">= 7.1.2"
gem 'pg', '~> 1.1' # the database
  gem "puma", require: false
gem "local", path: "../local"
gem "old", :path => "vendor/old"
gem "spaced", :path=>"vendor/spaced"
gem "gitgem", git: "https://example.com/x.git"
gem "dynamic", ENV.fetch("V", "1")
gem "interpolated", "#{ver}"
gem "commented", "~> 2", require: false # path: see docs
gem "modifier" if ENV["X"]
gem "platforms", "~> 3", platforms: [:ruby, :jruby] unless java
gems "notgem"
gemspec path: "x"
group :development, :test do
  gem "rspec-rails", "~> 6"
end
# gem "commented-out", "1"
=begin
gem "ghost"
=end
DOC = <<~EOS
  gem "heredoc"
  EOS
gem "after"
`
	got := requirements(t, "Gemfile", src)
	assert.Equal(t, map[string]string{
		"rails": "~> 7.1, >= 7.1.2", "pg": "~> 1.1", "puma": "", "gitgem": "", "dynamic": "", "interpolated": "",
		"commented": "~> 2", "modifier": "", "platforms": "~> 3", "rspec-rails": "~> 6", "after": "",
	}, got)
	r, err := FormatFor("Gemfile").ParseFull(t.Context(), []byte(src), nil, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Info.Unread, "the gem line in the heredoc")

	// gem lines in a form this reader doesn't read are counted, never dropped silently
	r, err = FormatFor("Gemfile").ParseFull(t.Context(), []byte(`gem "a"
gem("parens", "1")
gem "escaped\"name"
gem "bad name"
gem "b"; gem "evil"
gem "mylib",
  path: "./lib"
gem "c", "1", require: false, "2"
gem name_from_a_variable
gem "d" do
end
`), nil, 100)
	require.NoError(t, err)
	assert.Equal(t, 8, r.Info.Unread)
	require.Len(t, r.Deps, 1)
	assert.Equal(t, "a", r.Deps[0].Name)

	// a heredoc mark Ruby doesn't read as one (in a comment or a string) hides nothing; a gem call that doesn't
	// start its line is counted
	for name, c := range map[string]struct {
		src    string
		rows   []string
		unread int
	}{
		"mark in a comment":         {"gem \"a\"\nfoo; bar # <<X\ngem \"evil\"\nX\n", []string{"a", "evil"}, 0},
		"mark in a multi-line call": {"foo(1, # <<X\ngem \"evil\"\nX\n", []string{"evil"}, 0},
		"mark in a string":          {"gem \"a\", \"<<EOF\"\ngem \"evil\"\nEOF\n", []string{"a", "evil"}, 0},
		"real heredoc":              {"x = <<~'EOS'\n  gem \"evil\"\nEOS\ngem \"b\"\n", []string{"b"}, 1},
		"block on one line":         {"group :dev do gem \"evil\" end\n", nil, 1},
		"braces":                    {"platforms(:mri) { gem \"evil\" }\n", nil, 1},
		"after a statement":         {"x = 1; gem \"evil\"\n", nil, 1},
		"then":                      {"if true then gem \"evil\" end\n", nil, 1},
		"block parameter":           {"%w[evil1 evil2].each { |g| gem g }\n", nil, 1},
		"after a modifier":          {"gem \"a\" if x; gem \"evil\"\n", []string{"a"}, 1},
		"=endx is no end":           {"=begin\n=endx\ngem \"ghost\"\n=end\ngem \"b\"\n", []string{"b"}, 0},
		"__END__":                   {"gem \"b\"\n__END__\ngem \"ghost\"\n", []string{"b"}, 0},
	} {
		r, err := FormatFor("Gemfile").ParseFull(t.Context(), []byte(c.src), nil, 100)
		require.NoError(t, err, name)
		var rows []string
		for _, d := range r.Deps {
			rows = append(rows, d.Name)
		}
		assert.Equal(t, c.rows, rows, name)
		assert.Equal(t, c.unread, r.Info.Unread, name)
	}

	for name, bad := range map[string]string{
		"unterminated =begin":  "=begin\ngem \"a\"\n",
		"unterminated heredoc": "x = <<-EOS\ngem \"a\"\n",
	} {
		_, err := FormatFor("Gemfile").Parse(t.Context(), []byte(bad), nil)
		require.ErrorIs(t, err, ErrParse, name)
	}
}

// The fallback parsers stop at the caps, look at the context and refuse what can't be read, like the others.
func TestFallbackLimits(t *testing.T) {
	line := func(format string) func([]byte, int) []byte {
		return func(b []byte, i int) []byte {
			before, after, _ := strings.Cut(format, "%")
			return append(hexID(append(b, before...), i), after...)
		}
	}
	const small = 1 << 20
	for name, c := range map[string]struct {
		file string
		data []byte
	}{
		"package.json":      {"package.json", fill(`{"dependencies":{`, `"z":"1"}}`, small, line(`"%":"^1",`))},
		"composer.json":     {"composer.json", fill(`{"require":{`, `"a/z":"1"}}`, small, line(`"a/%":"^1",`))},
		"Cargo.toml":        {"Cargo.toml", fill("[dependencies]\n", "", small, line("% = \"1\"\n"))},
		"Cargo.toml table":  {"Cargo.toml", fill("", "", small, line("[dependencies.%]\nversion = \"1\"\n"))},
		"pyproject PEP 621": {"pyproject.toml", fill("[project]\ndependencies = [\n", "]\n", small, line("\"%>=1\",\n"))},
		"poetry":            {"pyproject.toml", fill("[tool.poetry.dependencies]\n", "", small, line("% = \"^1\"\n"))},
		"Gemfile":           {"Gemfile", fill("", "", small, line("gem \"%\", \"~> 1\"\n"))},
	} {
		t.Run(name, func(t *testing.T) {
			f := FormatFor(c.file)
			_, err := f.ParseLimited(t.Context(), c.data, nil, 100)
			require.True(t, isLimit(err), "%v", err) // rows, or the entries kept before the rows are made
			deps, err := f.ParseLimited(t.Context(), c.data, nil, 1<<20)
			require.NoError(t, err)
			assert.Greater(t, len(deps), 10000)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err = f.ParseLimited(ctx, c.data, nil, DefaultMaxDependencies)
			require.ErrorIs(t, err, context.Canceled)
		})
	}
	// many fields of one dependency are entries: the cap of the entries stops them
	_, err := FormatFor("Cargo.toml").ParseLimited(t.Context(), fill("[dependencies.a]\n", "", small, line("% = 1\n")), nil, 100)
	require.ErrorIs(t, err, ErrTooManyEntries)
	// a manifest of many keys that are no dependencies costs nothing kept
	deps, err := FormatFor("pyproject.toml").ParseLimited(t.Context(), fill("[tool.x]\n", "", small, line("% = [1, 2]\n")), nil, 100)
	require.NoError(t, err)
	assert.Empty(t, deps)
}

// poetry.lock marks as direct what the pyproject.toml next to it asks for, read by the same reader as without a
// lock file (quality re-review 2, L3).
func TestPoetryLockDirectFromPyproject(t *testing.T) {
	pyproject := []byte(`[tool.poetry]
description = '''
[tool.poetry.dependencies]
fake = "1"
'''
[tool.poetry.dependencies.click]
version = "^8"
`)
	lock := []byte("[[package]]\nname = \"click\"\nversion = \"8.1.0\"\n\n[[package]]\nname = \"fake\"\nversion = \"1.0.0\"\n")
	find := func(name string, _ bool) []byte {
		if name == "pyproject.toml" {
			return pyproject
		}
		return nil
	}
	deps, err := FormatFor("poetry.lock").Parse(t.Context(), lock, find)
	require.NoError(t, err)
	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	assert.Equal(t, map[string]bool{"click": true, "fake": false}, direct)
}
