// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionRunKeepWeb(t *testing.T) {
	defer unittest.OverrideFixtures("tests/integration/fixtures/TestActionRunDeletion")()
	defer tests.PrepareTestEnv(t)()

	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: user2.ID})
	repo62 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 62, OwnerID: user2.ID})
	sessUser2 := loginUser(t, user2.Name)
	sessUser5 := loginUser(t, user5.Name) // collaborator with write access
	kept := func() bool { return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: 34901}).Keep }
	runURL := fmt.Sprintf("/%s/actions/runs/3161", repo1.FullName())

	t.Run("Admin keeps and unkeeps", func(t *testing.T) {
		response := sessUser2.MakeRequest(t, NewRequest(t, "POST", runURL+"/keep"), http.StatusOK)
		assert.JSONEq(t, `{"ok":true}`, response.Body.String())
		assert.True(t, kept())

		// the run page tells the admin
		page := sessUser2.MakeRequest(t, NewRequest(t, "GET", runURL+"/jobs/0/attempt/1"), http.StatusOK).Body.String()
		assert.Contains(t, page, `&#34;keep&#34;:true`)
		assert.Contains(t, page, `&#34;canKeep&#34;:true`)
		// and the runs list marks it
		assert.Contains(t, sessUser2.MakeRequest(t, NewRequest(t, "GET", "/"+repo1.FullName()+"/actions"), http.StatusOK).Body.String(), "octicon-pin")

		sessUser2.MakeRequest(t, NewRequest(t, "POST", runURL+"/unkeep"), http.StatusOK)
		assert.False(t, kept())
	})

	t.Run("Write access is not enough", func(t *testing.T) {
		sessUser5.MakeRequest(t, NewRequest(t, "POST", runURL+"/keep"), http.StatusNotFound)
		assert.False(t, kept())

		page := sessUser5.MakeRequest(t, NewRequest(t, "GET", runURL+"/jobs/0/attempt/1"), http.StatusOK).Body.String()
		assert.NotContains(t, page, "canKeep")
	})

	t.Run("Anonymous", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "POST", runURL+"/keep"), http.StatusNotFound)
		assert.False(t, kept())
	})

	t.Run("Run of another repository", func(t *testing.T) {
		sessUser2.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/%s/actions/runs/3161/keep", repo62.FullName())), http.StatusNotFound)
		assert.False(t, kept())
	})
}

func TestActionRunKeepAPI(t *testing.T) {
	defer unittest.OverrideFixtures("tests/integration/fixtures/TestActionRunDeletion")()
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: user2.ID})
		repo62 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 62, OwnerID: user2.ID})
		writeToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository)
		readToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeReadRepository)
		collaboratorToken := getUserToken(t, user5.Name, auth_model.AccessTokenScopeWriteRepository)
		kept := func() bool { return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: 34901}).Keep }
		keepURL := fmt.Sprintf("/api/v1/repos/%s/actions/runs/34901/keep", repo1.FullName())
		runJSON := func() api.ActionRun {
			var run api.ActionRun
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", strings.TrimSuffix(keepURL, "/keep")).AddTokenAuth(readToken), http.StatusOK), &run)
			return run
		}

		// a job token of a task of this repository, with the default (write) permissions
		task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
		original := *task
		t.Cleanup(func() {
			require.NoError(t, actions_model.UpdateTask(context.Background(), &original, "repo_id", "owner_id", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
		})
		task.RepoID, task.OwnerID, task.TokenPermissions = repo1.ID, repo1.OwnerID, ""
		task.GenerateToken()
		require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))

		assert.False(t, runJSON().Keep)

		MakeRequest(t, NewRequest(t, "POST", keepURL).AddTokenAuth(writeToken), http.StatusNoContent)
		assert.True(t, kept())
		assert.True(t, runJSON().Keep)

		MakeRequest(t, NewRequest(t, "DELETE", keepURL).AddTokenAuth(writeToken), http.StatusNoContent)
		assert.False(t, kept())
		assert.False(t, runJSON().Keep)

		// refused: read-only scope, write access without admin, job token, anonymous
		for name, token := range map[string]string{"read scope": readToken, "collaborator": collaboratorToken, "job token": task.Token} {
			t.Run(name, func(t *testing.T) {
				MakeRequest(t, NewRequest(t, "POST", keepURL).AddTokenAuth(token), http.StatusForbidden)
				assert.False(t, kept())
			})
		}
		MakeRequest(t, NewRequest(t, "POST", keepURL), http.StatusUnauthorized)
		assert.False(t, kept())

		// a run of another repository
		MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/api/v1/repos/%s/actions/runs/34901/keep", repo62.FullName())).AddTokenAuth(writeToken), http.StatusNotFound)
		assert.False(t, kept())
		MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/api/v1/repos/%s/actions/runs/260871/keep", repo1.FullName())).AddTokenAuth(writeToken), http.StatusNotFound)
	})
}
