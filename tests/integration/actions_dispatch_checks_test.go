// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	release_service "forgejo.org/services/release"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsWorkflowDispatchChecks(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		reader := forgery.CreateUser(t, nil)
		files := forgery.MapFS{}
		for name, on := range map[string]string{
			"push.yml":     "[push]",
			"schedule.yml": "\n  schedule:\n    - cron: '0 0 * * *'",
			"release.yml":  "\n  release:\n    types: [published]",
			"call.yml":     "[workflow_call]",
			"dispatch.yml": "[workflow_dispatch]",
			"scalar.yml":   "workflow_dispatch",
			"null.yml":     "\n  workflow_dispatch:",
		} {
			files[".forgejo/workflows/"+name] = forgery.MapFile(fmt.Sprintf("name: %s\non: %s\njobs:\n  t:\n    runs-on: docker\n    steps:\n      - run: echo t\n", name, on))
		}
		var sha string
		repo := forgery.CreateRepository(t, owner, &forgery.CreateRepositoryOptions{
			Files:         files,
			LatestSha:     &sha,
			Collaborators: map[*user_model.User]perm.AccessMode{reader: perm.AccessModeRead},
		})
		forgery.EnableRepoUnit(t, repo, unit_model.TypeActions, nil)
		require.NoError(t, release_service.CreateNewTag(db.DefaultContext, owner, repo, sha, "v1", "tag"))

		token := getUserToken(t, owner.LowerName, auth_model.AccessTokenScopeWriteRepository)
		session := loginUser(t, owner.Name)
		countRuns := func() int64 {
			return int64(unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID}))
		}
		apiDispatch := func(workflow, ref, tok string, status int) *api.APIError {
			resp := MakeRequest(t, NewRequestWithJSON(t, http.MethodPost,
				fmt.Sprintf("/api/v1/repos/%s/%s/actions/workflows/%s/dispatches", repo.OwnerName, repo.Name, workflow),
				&api.DispatchWorkflowOption{Ref: ref},
			).AddTokenAuth(tok), status)
			if status < 400 {
				return nil
			}
			apiError := new(api.APIError)
			DecodeJSON(t, resp, apiError)
			return apiError
		}
		webDispatch := func(workflow, ref string) string {
			session.SetCookie(&http.Cookie{Name: "gitea_flash", Value: "", MaxAge: -1})
			session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/%s/actions/manual", repo.OwnerName, repo.Name), map[string]string{
				"ref": ref, "workflow": workflow,
			}), http.StatusSeeOther)
			return bwFlash(session)
		}
		setDisabled := func(workflow string, disabled bool) {
			fresh, err := repo_model.GetRepositoryByID(t.Context(), repo.ID)
			require.NoError(t, err)
			ru, err := fresh.GetUnit(t.Context(), unit_model.TypeActions)
			require.NoError(t, err)
			cfg := ru.ActionsConfig()
			if disabled {
				cfg.DisableWorkflow(workflow)
			} else {
				cfg.EnableWorkflow(workflow)
			}
			require.NoError(t, repo_model.UpdateRepoUnit(t.Context(), ru))
		}

		t.Run("no workflow_dispatch trigger", func(t *testing.T) {
			for _, workflow := range []string{"push.yml", "schedule.yml", "release.yml", "call.yml"} {
				for _, ref := range []string{repo.DefaultBranch, "v1", sha} {
					before := countRuns()
					apiError := apiDispatch(workflow, ref, token, http.StatusBadRequest)
					assert.Contains(t, apiError.Message, "workflow_dispatch", "%s@%s", workflow, ref)
					assert.Contains(t, webDispatch(workflow, ref), "no workflow_dispatch trigger", "%s@%s", workflow, ref)
					assert.Equal(t, before, countRuns(), "%s@%s", workflow, ref)
				}
			}
		})

		t.Run("accepted forms", func(t *testing.T) {
			for _, workflow := range []string{"scalar.yml", "null.yml"} {
				before := countRuns()
				apiDispatch(workflow, repo.DefaultBranch, token, http.StatusNoContent)
				assert.Equal(t, before+1, countRuns(), workflow)
			}
		})

		t.Run("disabled", func(t *testing.T) {
			setDisabled("dispatch.yml", true)
			before := countRuns()
			apiError := apiDispatch("dispatch.yml", repo.DefaultBranch, token, http.StatusBadRequest)
			assert.Contains(t, apiError.Message, "disabled")
			assert.Contains(t, webDispatch("dispatch.yml", repo.DefaultBranch), "disabled")
			assert.Equal(t, before, countRuns())

			setDisabled("dispatch.yml", false)
			apiDispatch("dispatch.yml", repo.DefaultBranch, token, http.StatusNoContent)
			assert.Equal(t, before+1, countRuns())
			assert.NotContains(t, webDispatch("dispatch.yml", repo.DefaultBranch), "disabled")
			assert.Equal(t, before+2, countRuns())
		})

		t.Run("read-only user", func(t *testing.T) {
			before := countRuns()
			readerToken := getUserToken(t, reader.LowerName, auth_model.AccessTokenScopeWriteRepository)
			apiDispatch("dispatch.yml", repo.DefaultBranch, readerToken, http.StatusForbidden)
			loginUser(t, reader.Name).MakeRequest(t, NewRequestWithValues(t, "POST",
				fmt.Sprintf("/%s/%s/actions/manual", repo.OwnerName, repo.Name),
				map[string]string{"ref": repo.DefaultBranch, "workflow": "dispatch.yml"}), http.StatusNotFound)
			assert.Equal(t, before, countRuns())
		})
	})
}
