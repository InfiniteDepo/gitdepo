// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/url"
	"testing"

	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

// gitHTTPResponse is the status and body of a git HTTP info/refs request with a token.
func gitHTTPResponse(t *testing.T, repoPath, token string) string {
	t.Helper()
	req := NewRequest(t, "GET", "/"+repoPath+".git/info/refs?service=git-upload-pack")
	req.Request.SetBasicAuth("user2", token)
	resp := MakeRequest(t, req, NoExpectedStatus)
	return fmt.Sprintf("%d\n%s", resp.Code, resp.Body.String())
}

// A token limited to public or specific repositories answers a missing repository like one it can't see (403),
// never with a 500; an unrestricted token keeps its answers.
func TestGitHTTPTokenMissingRepo(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	const missing, hidden = "user2/no-such-repo", "user15/big_test_private_1"

	for _, c := range []struct {
		name  string
		token string
	}{
		{"public only", getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadRepository)},
		{"specific repos", createFineGrainedRepoAccessToken(t, "user2", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadRepository}, []int64{1})},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := gitHTTPResponse(t, missing, c.token)
			assert.Equal(t, "403\n", resp[:4])
			assert.Equal(t, gitHTTPResponse(t, hidden, c.token), resp)
		})
	}

	t.Run("all access", func(t *testing.T) {
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
		resp := gitHTTPResponse(t, missing, token)
		assert.Equal(t, "404\n", resp[:4])
		assert.Equal(t, gitHTTPResponse(t, hidden, token), resp)
	})
}

func TestGitHTTPTokenPushCreate(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateUser, true)()
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
		u.Path = "/user2/push-created-with-token.git"
		u.User = url.UserPassword("user2", token)
		tmpDir := t.TempDir()
		t.Run("Init", doGitInitTestRepository(tmpDir, git.Sha1ObjectFormat))
		t.Run("AddRemote", doGitAddRemote(tmpDir, "origin", u))
		t.Run("Push", doGitPushTestRepository(tmpDir, "origin", "master"))
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", LowerName: "push-created-with-token"})
	})
}
