// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Org owners manage the webhooks of a project on its settings page. They fire for the events of the repositories in
// the project only, follow a repository that moves, and are reachable from no organization, user or API route.
func TestRepoGroupWebhooks(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		f := prepareRepoGroupWeb(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		owner := loginUser(t, "user2")
		proj, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "proj")
		require.NoError(t, err)
		secret, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "secret")
		require.NoError(t, err)
		org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})
		foreign, err := repo_model.CreateRepoGroup(ctx, org17, "foreign", "")
		require.NoError(t, err)
		// team 12 (admin, user28) and team1 (write, user4) reach the repositories of the project through the link
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		for _, teamID := range []int64{12, 2} {
			require.NoError(t, repo_service.LinkTeamToRepoGroup(ctx, admin, organization.OrgFromUser(f.org), teamID, proj.ID))
		}
		link := "/org3/proj/-/settings/hooks"
		const (
			hookURL  = "http://127.0.0.1:1/token-in-url-9f3a"
			hookKey  = "topsecret-hook-key-81"
			hookAuth = "Bearer auth-header-value-77"
		)

		mk := func(ownerID, groupID int64) *webhook_model.Webhook {
			w := &webhook_model.Webhook{OwnerID: ownerID, GroupID: groupID, URL: hookURL, HTTPMethod: "POST", ContentType: webhook_model.ContentTypeJSON, Type: "forgejo", Secret: hookKey, Events: `{"send_everything":true}`, IsActive: true}
			require.NoError(t, webhook_model.CreateWebhook(ctx, w, hookAuth))
			return w
		}
		orgHook := mk(f.org.ID, 0)
		secretHook := mk(f.org.ID, secret.ID)
		foreignHook := mk(org17.ID, foreign.ID)

		t.Run("owner creates, edits and deletes", func(t *testing.T) {
			owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
			owner.MakeRequest(t, NewRequest(t, "GET", link+"/forgejo/new"), http.StatusOK)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/forgejo/new", map[string]string{
				"payload_url": "http://127.0.0.1:1/project", "content_type": "1", "http_method": "POST", "secret": hookKey, "events": "send_everything", "active": "on",
			}), http.StatusSeeOther)
			ws, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{OwnerID: f.org.ID, GroupID: proj.ID})
			require.NoError(t, err)
			require.Len(t, ws, 1)
			w := ws[0]
			assert.EqualValues(t, 0, w.RepoID)
			assert.Equal(t, "http://127.0.0.1:1/project", w.URL)
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String(), "http://127.0.0.1:1/project")
			assert.NotContains(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/hooks"), http.StatusOK).Body.String(), "127.0.0.1:1/project", "not in the organization's list")
			held := mk(f.org.ID, proj.ID)
			list := owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.Contains(t, list, hookURL)
			assert.NotContains(t, list, hookKey, "the list shows neither the secret nor the Authorization header")
			assert.NotContains(t, list, hookAuth)
			unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: held.ID})

			owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", link, w.ID)), http.StatusOK)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d", link, w.ID), map[string]string{
				"payload_url": "http://127.0.0.1:1/changed", "content_type": "1", "http_method": "POST", "events": "send_everything", "active": "on",
			}), http.StatusSeeOther)
			w = unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: w.ID})
			assert.Equal(t, "http://127.0.0.1:1/changed", w.URL)
			assert.Equal(t, proj.ID, w.GroupID, "the project can't be changed")
			assert.Equal(t, f.org.ID, w.OwnerID)

			// the replay of a delivery of another hook is not found, of its own it is accepted
			own, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{HookID: w.ID, PayloadContent: "{}", EventType: "push", PayloadVersion: 2})
			require.NoError(t, err)
			other, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{HookID: orgHook.ID, PayloadContent: "{}", EventType: "push", PayloadVersion: 2})
			require.NoError(t, err)
			owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/replay/%s", link, w.ID, other.UUID)), http.StatusNotFound)
			owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/replay/%s", link, w.ID, own.UUID)), http.StatusSeeOther)
			// a hook of another project, of another organization or of the organization: not found, even with its own delivery
			for _, h := range []*webhook_model.Webhook{secretHook, foreignHook, orgHook} {
				task, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{HookID: h.ID, PayloadContent: "{}", EventType: "push", PayloadVersion: 2})
				require.NoError(t, err)
				owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/replay/%s", link, h.ID, task.UUID)), http.StatusNotFound)
			}

			owner.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/delete", map[string]string{"id": fmt.Sprint(w.ID)}), http.StatusOK)
			unittest.AssertNotExistsBean(t, &webhook_model.Webhook{ID: w.ID})
			unittest.AssertNotExistsBean(t, &webhook_model.HookTask{HookID: w.ID})
		})

		t.Run("nobody below an owner reaches it, nothing leaks", func(t *testing.T) {
			project := mk(f.org.ID, proj.ID)
			task, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{HookID: project.ID, PayloadContent: "{}", EventType: "push", PayloadVersion: 2})
			require.NoError(t, err)
			one := fmt.Sprintf("%s/%d", link, project.ID)
			for _, session := range []*TestSession{loginUser(t, "user4"), loginUser(t, "user28"), loginUser(t, "user5"), emptyTestSession(t)} {
				for _, req := range []*RequestWrapper{
					NewRequest(t, "GET", link),
					NewRequest(t, "GET", one),
					NewRequest(t, "GET", link+"/forgejo/new"),
					NewRequestWithValues(t, "POST", link+"/forgejo/new", map[string]string{"payload_url": hookURL, "content_type": "1", "http_method": "POST", "events": "send_everything", "active": "on"}),
					NewRequestWithValues(t, "POST", one, map[string]string{"payload_url": "http://127.0.0.1:1/x", "content_type": "1", "http_method": "POST", "events": "send_everything", "active": "on"}),
					NewRequestWithValues(t, "POST", link+"/delete", map[string]string{"id": fmt.Sprint(project.ID)}),
					NewRequest(t, "POST", fmt.Sprintf("%s/replay/%s", one, task.UUID)),
				} {
					resp := session.MakeRequest(t, req, NoExpectedStatus)
					assert.NotEqual(t, http.StatusOK, resp.Code, "%s %s", req.Method, req.URL)
					body := resp.Body.String()
					for _, leak := range []string{hookURL, hookKey, hookAuth, "token-in-url-9f3a"} {
						assert.NotContains(t, body, leak, "%s %s", req.Method, req.URL)
					}
				}
			}
			unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: project.ID, URL: hookURL})
			unittest.AssertExistsAndLoadBean(t, &webhook_model.HookTask{ID: task.ID})
		})

		t.Run("no mix-up of projects, organizations and owners", func(t *testing.T) {
			project := mk(f.org.ID, proj.ID)
			// hooks of the organization, of another project and of another organization's project, by this project's routes
			for _, id := range []int64{orgHook.ID, secretHook.ID, foreignHook.ID} {
				one := fmt.Sprintf("%s/%d", link, id)
				owner.MakeRequest(t, NewRequest(t, "GET", one), http.StatusNotFound)
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", one, map[string]string{"payload_url": "http://127.0.0.1:1/x", "content_type": "1", "http_method": "POST", "events": "send_everything", "active": "on"}), http.StatusNotFound)
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/delete", map[string]string{"id": fmt.Sprint(id)}), http.StatusOK) // a flash error, nothing deleted
				unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: id})
			}
			// another organization's project through this organization's route
			owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org/org3/groups/%d/settings/hooks", foreign.ID)), http.StatusNotFound)
			owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org/org3/groups/%d/settings/hooks/%d", foreign.ID, foreignHook.ID)), http.StatusNotFound)

			// the project hook by the organization's and the user's routes and the API
			one := fmt.Sprintf("/org/org3/settings/hooks/%d", project.ID)
			owner.MakeRequest(t, NewRequest(t, "GET", one), http.StatusNotFound)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", one, map[string]string{"payload_url": "http://127.0.0.1:1/x", "content_type": "1", "http_method": "POST", "events": "send_everything", "active": "on"}), http.StatusNotFound)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/hooks/delete", map[string]string{"id": fmt.Sprint(project.ID)}), http.StatusOK)
			owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user/settings/hooks/%d", project.ID)), http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: project.ID, GroupID: proj.ID})

			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteOrganization)
			var list []*api.Hook
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/hooks").AddTokenAuth(token), http.StatusOK), &list)
			for _, h := range list {
				assert.NotContains(t, []int64{project.ID, secretHook.ID}, h.ID)
			}
			apiHook := fmt.Sprintf("/api/v1/orgs/org3/hooks/%d", project.ID)
			MakeRequest(t, NewRequest(t, "GET", apiHook).AddTokenAuth(token), http.StatusNotFound)
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiHook, &api.EditHookOption{Active: new(bool)}).AddTokenAuth(token), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "DELETE", apiHook).AddTokenAuth(token), http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: project.ID, IsActive: true})
		})

		t.Run("a git push over HTTP fires the project hook only", func(t *testing.T) {
			pushHook := mk(f.org.ID, proj.ID)
			count := func(w *webhook_model.Webhook) int64 {
				n, err := db.GetEngine(ctx).Where("hook_id = ? AND event_type = ?", w.ID, "push").Count(new(webhook_model.HookTask))
				require.NoError(t, err)
				return n
			}
			secretBefore := count(secretHook)
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
			c := *u
			c.Path = "/org3/proj/priv.git"
			c.User = url.UserPassword("user2", token)
			dir := t.TempDir()
			doGitClone(dir, &c)(t)
			doGitAddSomeCommits(dir, "main")(t)
			doGitPushTestRepository(dir, "origin", "main")(t)
			assert.Eventually(t, func() bool { return count(pushHook) == 1 }, 10*time.Second, 100*time.Millisecond)
			assert.Equal(t, secretBefore, count(secretHook), "another project's hook doesn't fire")
		})

		t.Run("deleting the project deletes its hooks", func(t *testing.T) {
			gone, err := repo_model.CreateRepoGroup(ctx, f.org, "gone", "")
			require.NoError(t, err)
			w := mk(f.org.ID, gone.ID)
			_, err = webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{HookID: w.ID, PayloadContent: "{}", EventType: "push", PayloadVersion: 2})
			require.NoError(t, err)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/gone/-/settings/delete", map[string]string{"confirm_name": "org3/gone"}), http.StatusSeeOther)
			unittest.AssertNotExistsBean(t, &repo_model.RepoGroup{ID: gone.ID})
			unittest.AssertNotExistsBean(t, &webhook_model.Webhook{ID: w.ID})
			unittest.AssertNotExistsBean(t, &webhook_model.HookTask{HookID: w.ID})
			owner.MakeRequest(t, NewRequest(t, "GET", "/org3/gone/-/settings/hooks"), http.StatusNotFound)
			owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org/org3/groups/%d/settings/hooks", gone.ID)), http.StatusNotFound)
		})

		t.Run("archived organization", func(t *testing.T) {
			_, err := db.GetEngine(ctx).ID(f.org.ID).Cols("is_archived").Update(&user_model.User{IsArchived: true})
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(ctx).ID(f.org.ID).Cols("is_archived").Update(&user_model.User{IsArchived: false})
				require.NoError(t, err)
			}()
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/forgejo/new", map[string]string{"payload_url": hookURL, "content_type": "1", "http_method": "POST", "events": "send_everything", "active": "on"}), http.StatusForbidden)
		})

		t.Run("fires for the repositories of the project and follows a move", func(t *testing.T) {
			proj1 := mk(f.org.ID, proj.ID)
			count := func(w *webhook_model.Webhook) int64 {
				n, err := db.GetEngine(ctx).Where("hook_id = ?", w.ID).Count(new(webhook_model.HookTask))
				require.NoError(t, err)
				return n
			}
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeWriteRepository)
			createIssue := func(repoID int64) {
				MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repositories/%d/issues", repoID), &api.CreateIssueOption{Title: "hook"}).AddTokenAuth(token), http.StatusCreated)
			}
			orgBefore, secretBefore, foreignBefore := count(orgHook), count(secretHook), count(foreignHook)

			createIssue(f.priv.ID)
			assert.EqualValues(t, 1, count(proj1), "an event of a repository in the project")
			assert.Equal(t, orgBefore+1, count(orgHook), "organization hooks still fire")
			assert.Equal(t, secretBefore, count(secretHook), "another project's doesn't")
			assert.Equal(t, foreignBefore, count(foreignHook))

			createIssue(f.hid.ID) // a repository of the other project
			assert.EqualValues(t, 1, count(proj1))
			assert.Equal(t, secretBefore+1, count(secretHook))

			require.NoError(t, repo_service.MoveRepository(ctx, user2, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.priv.ID}), secret.ID))
			createIssue(f.priv.ID)
			assert.EqualValues(t, 1, count(proj1), "the old project stops")
			assert.Equal(t, secretBefore+2, count(secretHook), "the new project starts")
			require.NoError(t, repo_service.MoveRepository(ctx, user2, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.priv.ID}), 0))
			createIssue(f.priv.ID)
			assert.EqualValues(t, 1, count(proj1))
			assert.Equal(t, secretBefore+2, count(secretHook), "a repository at the root fires no project hook")
		})
	})
}
