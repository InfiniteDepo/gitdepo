// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIDEAssets deploys a stand-in for the built IDE, which the tests don't build.
func mockIDEAssets(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ide.js"), []byte("// ide"), 0o644))
	t.Cleanup(test.MockVariableValue(&setting.IDE.AssetsPath, dir))
	t.Cleanup(test.MockVariableValue(&setting.IDE.Enabled, true))
}

type ideTestConfig struct {
	CommitID        string `json:"commitID"`
	CanCommit       bool   `json:"canCommit"`
	CanCreateBranch bool   `json:"canCreateBranch"`
	TreePath        string `json:"treePath"`
}

func ideConfig(t *testing.T, session *TestSession, link string) ideTestConfig {
	t.Helper()
	resp := session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
	data, ok := NewHTMLParser(t, resp.Body).Find("#ide").Attr("data-config")
	require.True(t, ok)
	var config ideTestConfig
	require.NoError(t, json.Unmarshal([]byte(data), &config))
	return config
}

func ideCommit(t *testing.T, session *TestSession, branch string, body map[string]any, status int) map[string]string {
	t.Helper()
	resp := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/user2/repo1/ide/branch/"+branch, body), status)
	var out map[string]string
	DecodeJSON(t, resp, &out)
	return out
}

func ideFile(path, content string) *api.ChangeFileOperation {
	return &api.ChangeFileOperation{Operation: "create", Path: path, ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}
}

func TestWebIDEUnavailable(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")

	t.Run("disabled", func(t *testing.T) {
		mockIDEAssets(t)
		defer test.MockVariableValue(&setting.IDE.Enabled, false)()
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/-/ide/branch/master/README.md"), http.StatusNotFound)
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/user2/repo1/ide/branch/master", map[string]any{}), http.StatusNotFound)
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/master/README.md"), http.StatusOK)
		assert.Zero(t, NewHTMLParser(t, resp.Body).Find("a[data-ide-link]").Length())
	})

	t.Run("not deployed", func(t *testing.T) {
		defer test.MockVariableValue(&setting.IDE.AssetsPath, t.TempDir())()
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/-/ide/branch/master/README.md"), http.StatusNotFound)
	})

	t.Run("anonymous", func(t *testing.T) {
		mockIDEAssets(t)
		resp := MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/-/ide/branch/master"), http.StatusSeeOther)
		assert.Contains(t, resp.Header().Get("Location"), "/user/login")
	})
}

func TestWebIDE(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		mockIDEAssets(t)
		owner := loginUser(t, "user2")
		reader := loginUser(t, "user4")

		t.Run("entry points", func(t *testing.T) {
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/master/README.md"), http.StatusOK)
			assert.Equal(t, "/user2/repo1/-/ide/branch/master/README.md", NewHTMLParser(t, resp.Body).Find("a[data-ide-link]").AttrOr("href", ""))
			resp = owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls/3"), http.StatusOK)
			assert.Equal(t, "/user2/repo1/-/ide/branch/branch2", NewHTMLParser(t, resp.Body).Find("a[data-ide-link]").AttrOr("href", ""))
			// someone who can't push to the head branch gets no button on the pull request
			resp = reader.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls/3"), http.StatusOK)
			assert.Zero(t, NewHTMLParser(t, resp.Body).Find("a[data-ide-link]").Length())
		})

		t.Run("page", func(t *testing.T) {
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/-/ide/branch/master/README.md"), http.StatusOK)
			csp := resp.Header().Get("Content-Security-Policy")
			assert.Contains(t, csp, "default-src 'self'")
			assert.Contains(t, csp, "frame-ancestors 'none'")
			assert.NotContains(t, csp, "'unsafe-eval'")

			config := ideConfig(t, owner, "/user2/repo1/-/ide/branch/master/README.md")
			assert.True(t, config.CanCommit)
			assert.Equal(t, "README.md", config.TreePath)
			config = ideConfig(t, reader, "/user2/repo1/-/ide/branch/master")
			assert.False(t, config.CanCommit)
			assert.False(t, config.CanCreateBranch)
			// a tag is read-only
			config = ideConfig(t, owner, "/user2/repo1/-/ide/tag/v1.1")
			assert.False(t, config.CanCommit)
		})

		t.Run("tree", func(t *testing.T) {
			config := ideConfig(t, owner, "/user2/repo1/-/ide/branch/master")
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/ide/-/tree/"+config.CommitID), http.StatusOK)
			var tree api.GitTreeResponse
			DecodeJSON(t, resp, &tree)
			assert.Equal(t, "README.md", tree.Entries[0].Path)
			owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/ide/-/tree/master"), http.StatusNotFound)
		})

		t.Run("commit", func(t *testing.T) {
			config := ideConfig(t, owner, "/user2/repo1/-/ide/branch/master")
			readme := &api.ChangeFileOperation{Operation: "update", Path: "README.md", ContentBase64: base64.StdEncoding.EncodeToString([]byte("# edited\n"))}
			body := map[string]any{
				"last_commit": config.CommitID,
				"message":     "Edit in the Web IDE",
				"files":       []*api.ChangeFileOperation{readme, ideFile("docs/new.md", "new\n")},
			}

			// a reader can neither commit nor create a branch
			assert.Equal(t, "forbidden", ideCommit(t, reader, "master", body, http.StatusForbidden)["error"])
			body["new_branch"] = "reader-branch"
			assert.Equal(t, "forbidden", ideCommit(t, reader, "master", body, http.StatusForbidden)["error"])
			delete(body, "new_branch")

			out := ideCommit(t, owner, "master", body, http.StatusOK)
			assert.Equal(t, "master", out["branch"])
			assert.NotEqual(t, config.CommitID, out["commit"])
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/docs/new.md"), http.StatusOK)
			assert.Equal(t, "new\n", resp.Body.String())

			// the branch moved since the IDE opened
			body["files"] = []*api.ChangeFileOperation{ideFile("docs/other.md", "other\n")}
			assert.Equal(t, "branch_moved", ideCommit(t, owner, "master", body, http.StatusConflict)["error"])

			// a new branch is made from the commit the IDE opened
			body["new_branch"] = "ide-branch"
			out = ideCommit(t, owner, "master", body, http.StatusOK)
			assert.Equal(t, "ide-branch", out["branch"])
			assert.Equal(t, "branch_exists", ideCommit(t, owner, "master", body, http.StatusUnprocessableEntity)["error"])
			body["new_branch"] = "bad..name"
			assert.Equal(t, "invalid", ideCommit(t, owner, "master", body, http.StatusUnprocessableEntity)["error"])

			// renames aren't an operation of their own: they are an update with from_path
			body = map[string]any{"last_commit": out["commit"], "message": "x", "files": []map[string]string{{"operation": "rename", "path": "a"}}}
			owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/user2/repo1/ide/branch/ide-branch", body), http.StatusBadRequest)
		})

		t.Run("protected branch", func(t *testing.T) {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{
				"rule_name":   "master",
				"enable_push": "false",
			}), http.StatusSeeOther)
			config := ideConfig(t, owner, "/user2/repo1/-/ide/branch/master")
			assert.False(t, config.CanCommit)
			assert.True(t, config.CanCreateBranch)
			body := map[string]any{
				"last_commit": config.CommitID,
				"message":     "Edit in the Web IDE",
				"files":       []*api.ChangeFileOperation{ideFile("protected.md", "x\n")},
			}
			assert.Equal(t, "protected", ideCommit(t, owner, "master", body, http.StatusForbidden)["error"])
			body["new_branch"] = "from-protected"
			ideCommit(t, owner, "master", body, http.StatusOK)
		})
	})
}
