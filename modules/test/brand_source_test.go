// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var oldBrandRe = regexp.MustCompile(`Forgejo|Gitea|GitHat|CodeHat`)

// BrandMentions only sees rendered HTML. These strings reach users another way (plain-text 500 pages, the git
// login prompt, a Teams card, the JS error banner, API docs, package install snippets), so scan their source.
func TestNoOldBrandInUserFacingSource(t *testing.T) {
	literal := regexp.MustCompile("[\"`][^\"`\\n]*(Forgejo|Gitea|GitHat|CodeHat|(?i:\\bspoved\\b))[^\"`\\n]*[\"`]")
	for _, f := range []string{
		"routers/common/errpage.go",
		"services/context/context_response.go",
		"routers/web/githttp.go",
		"routers/web/repo/githttp.go",
		"routers/api/packages/api.go",
		"services/webhook/msteams.go",
		"web_src/js/bootstrap.js",
	} {
		for i, line := range readLines(t, filepath.Join("../..", f)) {
			if trimmed := strings.TrimSpace(line); !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") {
				assert.Empty(t, literal.FindString(line), "%s:%d", f, i+1)
			}
		}
	}

	// the registry names in the copy-paste snippets
	files, err := filepath.Glob("../../templates/package/content/*.tmpl")
	require.NoError(t, err)
	for _, f := range files {
		for i, line := range readLines(t, f) {
			assert.Empty(t, regexp.MustCompile(`(?i)\b(forgejo|gitea)\b`).FindString(line), "%s:%d", f, i+1)
		}
	}

	// API docs: only upstream references that are true as written stay (docs/branding.md keeps the API title)
	allowed := strings.NewReplacer(
		`"title": "Forgejo API"`, "",
		"This documentation describes the Forgejo API.", "",
		"deprecated in Forgejo 15", "", // an upstream version number
	)
	text := regexp.MustCompile(`"(description|summary|title)": "[^\n]*`)
	for i, line := range readLines(t, "../../templates/swagger/v1_json.tmpl") {
		if text.MatchString(line) {
			assert.Empty(t, oldBrandRe.FindString(allowed.Replace(line)), "swagger:%d", i+1)
		}
	}
}

// The product was called spoved before it became gitdepo. Only the brand guards may still name it, as the
// text they detect.
func TestNoOldProductNameInTree(t *testing.T) {
	out, err := exec.Command("git", "-C", "../..", "ls-files", "-z").Output()
	if err != nil {
		t.Skip("not a git checkout:", err)
	}
	guards := map[string]bool{
		"modules/test/brand.go":               true,
		"modules/test/brand_test.go":          true,
		"modules/test/brand_source_test.go":   true,
		"modules/translation/gitdepo_test.go": true,
	}
	old := regexp.MustCompile(`(?i)spoved`)
	for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		assert.False(t, old.MatchString(f), "file name %s", f)
		if guards[f] {
			continue
		}
		b, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil || bytes.IndexByte(b, 0) >= 0 { // deleted in the worktree, or binary
			continue
		}
		if loc := old.FindIndex(b); loc != nil {
			assert.Fail(t, "old product name", "%s:%d", f, bytes.Count(b[:loc[0]], []byte("\n"))+1)
		}
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.Split(string(b), "\n")
}
