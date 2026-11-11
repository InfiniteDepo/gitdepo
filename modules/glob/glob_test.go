// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package glob_test

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"forgejo.org/modules/glob"

	gobwas "github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A pattern means the same as it does to gobwas, except that `**` as a whole path segment also matches no directory
// and where a gobwas matcher deviates from its own syntax.
func TestCompileMatchesGobwas(t *testing.T) {
	// known differences, pattern -> name, both not matched here: in gobwas a prefix and suffix around `**` may
	// overlap, and a row of `?` with two separators ignores them
	gobwasDefects := map[[2]string]bool{
		{"ab**bc", "abc"}: true,
		{"??", "//"}:      true, {"??", "a/"}: true, {"??", "/a"}: true,
	}
	// a leading `**/` or a `/**/` (once in these patterns) may also match no directory: gobwas without that segment
	noDirs := func(p string, seps []rune) gobwas.Glob {
		if q := strings.Replace(strings.TrimPrefix(p, "**/"), "/**/", "/", 1); q != p {
			return gobwas.MustCompile(q, seps...)
		}
		return nil
	}
	for _, seps := range [][]rune{{'.', '/'}, {'/'}, nil} {
		for _, p := range corpusPatterns {
			want, wantErr := gobwas.Compile(p, seps...)
			got, err := glob.Compile(p, seps...)
			if wantErr != nil {
				require.Error(t, err, "pattern %q, separators %q is refused like gobwas does", p, string(seps))
				continue
			}
			require.NoError(t, err, "pattern %q, separators %q", p, string(seps))
			for _, n := range corpusNames {
				if gobwasDefects[[2]string{p, n}] {
					continue
				}
				match := want.Match(n)
				if g := noDirs(p, seps); g != nil {
					match = match || g.Match(n)
				}
				assert.Equal(t, match, got.MatchString(n), "pattern %q, separators %q, name %q", p, string(seps), n)
			}
		}
	}
	for d := range gobwasDefects {
		assert.False(t, mustCompile(t, d[0]).MatchString(d[1]), "%q doesn't match %q", d[0], d[1])
	}
}

var corpusPatterns = []string{
	"", "*", "**", "***", "?", "a", "a.b", "a+b(c)|$^",
	"*.go", "**.go", "**/*.go", "src/**", "src/**/*.go", "src/**/test/*.go", "**/test", "**/", "/**", "a/**/b",
	"src/*", "src/*/*.go", "*/*", "*/*/*", "**/*/*.go", "*a*", "a*b*c", "*.*", "?.go", "??", "a?b", "src/?/x",
	"{docs,api}/**/*.md", "{a,b}", "{a,}", "{,a}", "{}", "{a,b", "{a,{b,c}}", "x{a,b{c,d}}y", "{*.go,*.md}", "{**/a,b/*}",
	"a}", "a,b", "}{a,b}", "[abc]", "[!abc]", "[a-c]", "[!a-c]", "[.]", "[!.]", "[/]", "[!/]", "x[!a]y", "[a-c]*", "[]", "[!]",
	"[a", "[a-]", "[a-z]x", "[\\]]", "[\\-a]", "a\\*b", "a\\?b", "\\{a,b\\}", "a\\", "\\[x]", "a\\\\b", "[{,}]", "[*?]", "ab**bc",
	"release/*", "release/**", "feature/*-fix", "ü*", "*ü", "[ä-ü]", ".github/**", "*.min.js", "docs/**/*.{md,txt}",
}

var corpusNames = []string{
	// names are never empty: gobwas matches "" against a lone `?` or class
	"a", "b", "c", "x", "aa", "abc", "ab", "a/b/b", "ab", "a.b", "a/b", "ab.go", "a.go", "x.go", ".go", "go", "a+b(c)|$^", "a*b", "a?b", "a\\b",
	"src", "src/", "src/a.go", "src/a/b.go", "src/x/test/a.go", "src/test/a.go", "src/a/b/c.go", "src/a", "src/a.b/c.go",
	"/", "//", "a/", "/a", "a//b", "a/x/b", "a/x/y/b", "test", "x/test", "x/y/test", "docs/a.md", "api/x/y.md", "docs/a.txt",
	"{a,b}", "{a,b", "a}", "a,b", "}a", "a.min.js", "release/1", "release/1/2", "feature/x-fix", "feature/a/b-fix",
	"ü", "üx", "xü", "ö", ".", "-", "]", "{", ",", "}", "*", "?", "[", "[x]", "x\ny", "a\nb", "\n", ".github/workflows/a.yml",
	"xay", "xby", "x/y", "x.y", "xacdy", "xay", "xbcy", "xbdy", "xbcdy", "abc", "abbc", "a.b.c", "a/b/c", "\xff", "a\xffb",
}

// Patterns of branch protection rules in the tests of this repository, and the translations of the Bitbucket import.
var protectionPatterns = []string{
	"*", "a/*", "b/*", "lock-*", "release/*", "release/**", "release/**/hotfix", "**/hotfix", "{release,hotfix}/*",
	"{P,**/P}", "{,**/}x", "{,**/}a/b", "a{,/**}", "heads/{a,**/b}", "feature/**/{x,y}", "r\\*", "release-[0-9]*", "v[!0-9]*",
}

var separatorSets = [][]rune{{'.', '/'}, {'/'}, nil}

// compareExact compares CompileExact with gobwas for every separator set the callers use.
func compareExact(t *testing.T, p string, names []string) {
	t.Helper()
	for _, seps := range separatorSets {
		compareExactSeps(t, p, names, seps)
	}
}

func compareExactSeps(t *testing.T, p string, names []string, seps []rune) {
	t.Helper()
	want, wantErr := gobwas.Compile(p, seps...)
	got, err := glob.CompileExact(p, seps...)
	if wantErr == nil { // gobwas panics on some patterns (match.Row.matchAll): nothing to compare
		defer func() { _ = recover() }()
	}
	if wantErr != nil {
		require.Error(t, err, "pattern %q, separators %q is refused like gobwas does", p, string(seps))
		return
	}
	require.NoError(t, err, "pattern %q, separators %q", p, string(seps))
	for _, n := range names {
		// gobwas defects, not copied: a prefix and suffix around `**` overlapping; a row of `?`, or `?` next to `*`,
		// ignores the separators when there are two of them (`*?` matches `a.`), and with one only a row of `?`
		// does; an empty alternative `{}` before `**` is dropped, although `{}` alone matches nothing
		row := strings.Contains(p, "*?") || strings.Contains(p, "?*")
		if (p == "ab**bc" && n == "abc") ||
			((strings.Contains(p, "??") || (row && len(seps) > 1)) && strings.ContainsAny(n, string(append([]rune{'/'}, seps...)))) ||
			(strings.Contains(p, "{}") && strings.Contains(p, "**")) {
			continue
		}
		assert.Equal(t, want.Match(n), got.MatchString(n), "pattern %q, separators %q, name %q", p, string(seps), n)
	}
}

// CompileExact means what gobwas means, a leading `**/` included.
func TestCompileExactMatchesGobwas(t *testing.T) {
	names := append([]string{".", "..", "a/..", "../a", "release/hotfix", "release/a/hotfix", "release//hotfix", "hotfix", "/hotfix", "a/hotfix", "x", "a/x", "/x", "a/b", "feature/x", "feature/a/y", "feature//y", "heads/a", "heads/b", "heads/c/b", "r*", "release-1", "release-1/x", "va", "v1"}, corpusNames...)
	for _, p := range append(slices.Clone(corpusPatterns), protectionPatterns...) {
		compareExact(t, p, names)
	}
	assert.False(t, mustCompileExact(t, "**/x").MatchString("x"), "a leading **/ needs a directory, as in gobwas")
	assert.True(t, mustCompileExact(t, "release/**/hotfix").MatchString("release/hotfix"), "gobwas matches this too")
}

// A seeded random walk over pattern pieces and names built from the same pieces.
func TestCompileExactFuzz(t *testing.T) {
	rnd := rand.New(rand.NewPCG(645, 2))
	pieces := []string{"a", "b", "/", "*", "**", "?", "{", "}", ",", "[ab]", "[!a]", "[a-b]", "\\*", "\\{", "x", ".", "..", "**/", "/**"}
	letters := []string{"a", "b", "/", "x", ".", "*", "{", "c", "..", "./"}
	build := func(from []string, max int) string {
		var b strings.Builder
		for range 1 + rnd.IntN(max) {
			b.WriteString(from[rnd.IntN(len(from))])
		}
		return b.String()
	}
	names := make([]string, 0, 60)
	for range 60 {
		names = append(names, build(letters, 8))
	}
	for range 3000 {
		// gobwas itself is wrong for these (a run of `*` after `**`, `**` ending an alternative, an unclosed `{`):
		// they are not compared
		p := build(pieces, 7)
		if strings.Contains(p, "***") || strings.Contains(p, "**}") || strings.Count(p, "{") != strings.Count(p, "}") {
			continue
		}
		compareExact(t, p, names)
	}
}

func mustCompileExact(t *testing.T, pattern string) *regexp.Regexp {
	g, err := glob.CompileExact(pattern, '/')
	require.NoError(t, err)
	return g
}

// `**` as a whole path segment matches zero or more directories; a trailing `/**` matches everything below.
func TestCompileDoubleStarSegment(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		match         bool
	}{
		{"docs/**/README.md", "docs/README.md", true},
		{"docs/**/README.md", "docs/a/b/README.md", true},
		{"docs/**/README.md", "docsREADME.md", false},
		{"docs/**/README.md", "xdocs/README.md", false},
		{"**/x.go", "x.go", true},
		{"**/x.go", "a/b/x.go", true},
		{"**/x.go", "ax.go", false},
		{"src/**/*.go", "src/x.go", true},
		{"src/**/*.go", "src/a/x.go", true},
		{"a/**/b", "a/b", true},
		{"a/**/b/**/c", "a/b/c", true},
		{"{docs,api}/**/*.md", "api/x.md", true},
		{"docs/**", "docs/a/b", true},
		{"docs/**", "docs", false},
		{"a**/b", "a/b", true},
		{"a**/b", "b", false},
		{"x{**/a,b}", "xa", false},
	} {
		assert.Equal(t, c.match, mustCompile(t, c.pattern).MatchString(c.name), "%q against %q", c.pattern, c.name)
	}
}

// Approval-rule patterns use linear-time matching: wildcards between separators don't multiply the work.
func TestCompileLinearTime(t *testing.T) {
	for _, p := range []string{"*/*/*/*/*/*x", "**/*/*/*/*x", "*/*/*/*x"} {
		for _, seps := range [][]rune{{'.', '/'}, {'/'}} {
			g, err := glob.Compile(p, seps...)
			require.NoError(t, err)
			for _, name := range []string{strings.Repeat("a/", 600) + "x", strings.Repeat("a/", 600) + "y", strings.Repeat("a", 1200) + "x"} {
				start := time.Now()
				g.MatchString(name)
				assert.Less(t, time.Since(start), 5*slowdown*time.Millisecond, "%q against %d bytes", p, len(name))
			}
		}
	}
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	g, err := glob.Compile(pattern, '.', '/')
	require.NoError(t, err)
	return g
}
