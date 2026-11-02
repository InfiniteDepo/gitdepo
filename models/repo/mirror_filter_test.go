// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeRefFilter(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"main":                   "main",
		"v*":                     "v*",
		"main , release/*":       "main,release/*",
		"release/2.1,feature+x":  "release/2.1,feature+x",
		strings.Repeat("a", 255): strings.Repeat("a", 255),
	} {
		got, err := NormalizeRefFilter(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}

	tooMany := strings.TrimSuffix(strings.Repeat("a,", 101), ",")
	for _, in := range []string{
		"--upload-pack=x", "-x", "a:b", "+x", "!x", "^x", "a b", "$(x)", "a*b*c", "*/*", strings.Repeat("a", 256),
		tooMany, "a..b", ",", "a,,b", "a,", ",a", " ", "a, ,b", "/a", "a/", "a//b", "a.lock", ".a", "a/.b", "a.", "@",
		"a;b", "a|b", "a`b", "a\nb", "a\x00b", "a\\b", "a?b", "a[b", "a~b", "a>b", "a'b", "a\"b", "a&b",
		strings.Repeat("abcdefghi,", 210),
	} {
		_, err := NormalizeRefFilter(in)
		require.Error(t, err, "%q", in)
	}
	_, err := NormalizeRefFilter("good,bad pattern")
	assert.ErrorContains(t, err, `"bad pattern"`)
}

// The pure-Go rules must never accept something git itself refuses.
func TestNormalizeRefFilterAgreesWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	for _, p := range []string{"main", "release/*", "v*", "*-rc", "a.b", "a@b", "a#b", "a=b%", "feature+x", "ü*"} {
		_, err := NormalizeRefFilter(p)
		require.NoError(t, err)
		require.NoError(t, exec.Command("git", "check-ref-format", "--allow-onelevel", "--refspec-pattern", "refs/heads/"+p).Run(), p)
	}
}

func TestMatchRefFilter(t *testing.T) {
	assert.True(t, MatchRefFilter("", "anything"))
	assert.True(t, MatchRefFilter("main,release/*", "main"))
	assert.False(t, MatchRefFilter("main,release/*", "main2"))
	assert.True(t, MatchRefFilter("release/*", "release/2.1"))
	assert.True(t, MatchRefFilter("release/*", "release/a/b"), "* matches /")
	assert.False(t, MatchRefFilter("release/*", "release"))
	assert.True(t, MatchRefFilter("v*", "v1.0"))
	assert.True(t, MatchRefFilter("*-rc", "v1-rc"))
	assert.False(t, MatchRefFilter("*-rc", "v1-rc2"))
	assert.True(t, MatchRefFilter("a*b", "ab"))
	assert.False(t, MatchRefFilter("a*ab", "a"))
}

func TestMirrorRefSpecs(t *testing.T) {
	specs, err := (&Mirror{}).RefSpecs(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}, specs)

	m := &Mirror{BranchFilter: "main,release/*,gone", TagFilter: "v*"}
	specs, err = m.RefSpecs(func(ref string) bool { return ref != "refs/heads/gone" })
	require.NoError(t, err)
	assert.Equal(t, []string{
		"+refs/heads/main:refs/heads/main", "+refs/heads/release/*:refs/heads/release/*", "+refs/tags/v*:refs/tags/v*",
	}, specs)
	assert.Equal(t, []string{"refs/heads/main", "refs/heads/gone"}, m.ExactRefs())

	specs, err = (&Mirror{BranchFilter: "gone", TagFilter: "gone2"}).RefSpecs(func(string) bool { return false })
	require.NoError(t, err)
	assert.Empty(t, specs)

	// fails closed on a stored value that no longer validates
	for _, bad := range []string{"a,,b", "--x", " "} {
		_, err = (&Mirror{BranchFilter: bad}).RefSpecs(nil)
		require.Error(t, err, bad)
	}
}

func TestCheckDefaultBranchFilter(t *testing.T) {
	require.NoError(t, CheckDefaultBranchFilter("", "main"))
	require.NoError(t, CheckDefaultBranchFilter("rel*", ""))
	require.NoError(t, CheckDefaultBranchFilter("main", "main"))
	assert.ErrorContains(t, CheckDefaultBranchFilter("rel*", "main"), `"main"`)
}
