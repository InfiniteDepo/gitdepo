// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The web settings pages of Actions environments: every handler through real requests, with the rows and audit
// entries they leave.
func TestActionsEnvironmentsWeb(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		ownerToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		owner := loginUser(t, user2.Name)
		ctx := audit_model.WithSystem(t.Context(), "test")

		apiRepo := createActionsTestRepo(t, ownerToken, "web-envs", true)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		for user, perm := range map[string]string{"user4": "write", "user8": "admin", "user5": "read"} {
			MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", user2.Name, repo.Name, user),
				&api.AddCollaboratorOption{Permission: new(perm)}).AddTokenAuth(ownerToken), http.StatusNoContent)
		}
		other := createActionsTestRepo(t, ownerToken, "web-envs-other", true)
		base := fmt.Sprintf("/%s/%s/settings/actions/environments", user2.Name, repo.Name)
		otherBase := fmt.Sprintf("/%s/%s/settings/actions/environments", user2.Name, other.Name)

		auditNow := func() int64 {
			var id int64
			_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
			require.NoError(t, err)
			return id
		}
		auditActions := func(since int64, prefix string) []string {
			var entries []*audit_model.Entry
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", since).OrderBy("id").Find(&entries))
			var actions []string
			for _, e := range entries {
				if strings.HasPrefix(e.Action, prefix) {
					actions = append(actions, e.Action)
				}
			}
			return actions
		}
		form := func(values map[string][]string) url.Values {
			v := url.Values{"ref_policy": {"0"}, "wait_timer": {"0"}}
			maps.Copy(v, values)
			return v
		}
		post := func(s *TestSession, link string, values url.Values, status int) *httptest.ResponseRecorder {
			t.Helper()
			return s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link, values), status)
		}
		envByName := func(repoID int64, name string) *actions_model.ActionEnvironment {
			env, err := actions_model.GetRepoEnvironmentByName(t.Context(), repoID, name)
			require.NoError(t, err)
			return env
		}
		envLink := func(env *actions_model.ActionEnvironment) string {
			return base + "/" + strconv.FormatInt(env.ID, 10)
		}

		t.Run("empty list", func(t *testing.T) {
			body := owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, body, "No environments yet")
			assert.Contains(t, body, base+"/new")
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", base+"/new"), http.StatusOK).Body.String(), `id="environment-form"`)
		})

		var production *actions_model.ActionEnvironment
		t.Run("create with reviewers and patterns", func(t *testing.T) {
			since := auditNow()
			resp := post(owner, base+"/new", form(map[string][]string{
				"name": {"Production"}, "reviewers": {"user:4,user:5"}, "prevent_self_review": {"on"}, "wait_timer": {"10"},
				"ref_policy": {"2"}, "pattern_type": {"branch", "tag"}, "pattern": {"main", "v*"},
				"runner_labels": {"prod\n eu-west \n"}, "allowed_workflows": {"deploy-*.yml"},
			}), http.StatusSeeOther)
			production = envByName(repo.ID, "production")
			assert.Equal(t, envLink(production), resp.Header().Get("Location"))
			assert.Equal(t, "Production", production.Name)
			assert.True(t, production.ReviewsRequired)
			assert.True(t, production.PreventSelfReview)
			assert.Equal(t, 10, production.WaitTimerMinutes)
			assert.Equal(t, actions_model.EnvironmentRefPatterns, production.RefPolicy)
			assert.Equal(t, []actions_model.EnvironmentRefPattern{{Type: "branch", Pattern: "main"}, {Type: "tag", Pattern: "v*"}}, production.RefPatterns)
			assert.Equal(t, []string{"prod", "eu-west"}, production.RunnerLabels)
			assert.Equal(t, []string{"deploy-*.yml"}, production.AllowedWorkflows)
			assert.False(t, production.CreatedByWorkflow)
			unittest.AssertCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: production.ID}, 2)
			assert.Equal(t, []string{"repo.actions_env.created"}, auditActions(since, "repo.actions_env"))

			body := owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, body, "2 reviewers · Prevent self-review · main, v* · 10 min wait · runners: prod, eu-west · workflows: deploy-*.yml")
			assert.Contains(t, body, "0 secrets · 0 variables")
			assert.Contains(t, body, "1 of 100 environments.")
			assert.NotContains(t, body, "No protection")

			body = owner.MakeRequest(t, NewRequest(t, "GET", envLink(production)), http.StatusOK).Body.String()
			assert.Contains(t, body, `value="user:4,user:5"`)
			assert.Contains(t, body, `name="pattern" value="v*"`)
			assert.Contains(t, body, "Counts from when the job is ready, at the same time as the review. The job starts when both are done.")
		})

		t.Run("refusals are named and change nothing", func(t *testing.T) {
			since := auditNow()
			for name, c := range map[string]struct {
				link   string
				values url.Values
				text   string
			}{
				"name taken ignoring case": {base + "/new", form(map[string][]string{"name": {"PRODUCTION"}}), "An environment with this name already exists."},
				"invalid name":             {base + "/new", form(map[string][]string{"name": {"has space"}}), "The name must be 1 to 255"},
				"invalid pattern, escaped": {envLink(production), form(map[string][]string{"ref_policy": {"2"}, "pattern_type": {"branch"}, "pattern": {"<b>x[</b>"}}), "&lt;b&gt;x[&lt;/b&gt;"},
				"no pattern":               {envLink(production), form(map[string][]string{"ref_policy": {"2"}}), "Selected branches and tags needs 1 to 50 patterns."},
				"wait timer":               {envLink(production), form(map[string][]string{"wait_timer": {"50000"}}), "The wait timer must be 0 to 43200 minutes."},
				"wait timer not a number":  {envLink(production), form(map[string][]string{"wait_timer": {"soon"}}), "The wait timer must be 0 to 43200 minutes."},
				"runner label twice":       {envLink(production), form(map[string][]string{"runner_labels": {"a\na"}}), "is not valid or listed twice."},
				"seven reviewers":          {envLink(production), form(map[string][]string{"reviewers": {"user:1,user:4,user:5,user:8,user:10,user:11,user:12"}}), "At most 6 reviewers."},
				"reviewer twice":           {envLink(production), form(map[string][]string{"reviewers": {"user:4,user:4"}}), "A reviewer is listed twice."},
				"name of dots":             {base + "/new", form(map[string][]string{"name": {".."}}), "and not only dots"},
				"name with a slash":        {base + "/new", form(map[string][]string{"name": {"a/b"}}), "without spaces or any of : / ? # % \\"},
				"reviewer of no type":      {envLink(production), form(map[string][]string{"reviewers": {"admin:1"}}), "Choose up to 6 reviewers from the list."},
				// user31 is private and shares no organization with user2: unknown like a missing one
				"hidden reviewer": {envLink(production), form(map[string][]string{"reviewers": {"user:31"}}), "Choose up to 6 reviewers from the list."},
				"foreign team":    {envLink(production), form(map[string][]string{"reviewers": {"team:1"}}), "Choose up to 6 reviewers from the list."},
			} {
				t.Run(name, func(t *testing.T) {
					body := post(owner, c.link, c.values, http.StatusOK).Body.String()
					assert.Regexp(t, `The rules weren(&#39;|')t saved\.`, body)
					assert.Contains(t, body, c.text)
					assert.NotContains(t, body, "<b>x[")
				})
			}
			assert.Empty(t, auditActions(since, "repo.actions_env"))
			assert.Equal(t, *production, *envByName(repo.ID, "production"))
			unittest.AssertCount(t, &actions_model.ActionEnvironment{RepoID: repo.ID}, 1)
		})

		t.Run("edit records one entry and keeps the name", func(t *testing.T) {
			since := auditNow()
			post(owner, envLink(production), form(map[string][]string{"name": {"renamed"}, "reviewers": {"user:4"}, "ref_policy": {"1"}, "pattern_type": {"branch"}, "pattern": {"left"}}), http.StatusSeeOther)
			stored := envByName(repo.ID, "production")
			assert.Equal(t, "Production", stored.Name)
			assert.Equal(t, actions_model.EnvironmentRefProtectedBranches, stored.RefPolicy)
			assert.Empty(t, stored.RefPatterns, "the rows of another choice are not saved")
			assert.False(t, stored.PreventSelfReview)
			assert.Zero(t, stored.WaitTimerMinutes)
			unittest.AssertCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: production.ID}, 1)
			assert.Equal(t, []string{"repo.actions_env.updated"}, auditActions(since, "repo.actions_env"))
			// an unchanged save records nothing
			since = auditNow()
			post(owner, envLink(production), form(map[string][]string{"reviewers": {"user:4"}, "ref_policy": {"1"}}), http.StatusSeeOther)
			assert.Empty(t, auditActions(since, "repo.actions_env"))
		})

		t.Run("no eligible reviewer warning", func(t *testing.T) {
			// user10 was a collaborator when listed and no longer is: nobody listed can approve
			require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: repo.ID, UserID: 10, Mode: perm.AccessModeRead}))
			post(owner, base+"/new", form(map[string][]string{"name": {"locked"}, "reviewers": {"user:10"}}), http.StatusSeeOther)
			_, err := db.GetEngine(ctx).Where("repo_id = ? AND user_id = 10", repo.ID).Delete(&repo_model.Collaboration{})
			require.NoError(t, err)
			locked := envByName(repo.ID, "locked")
			warning := "Nobody listed can approve a deployment right now"
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String(), warning)
			body := owner.MakeRequest(t, NewRequest(t, "GET", envLink(locked)), http.StatusOK).Body.String()
			assert.Contains(t, body, warning)
			assert.Contains(t, body, "not a member of this repository", "the listed user is shown with the one answer of a non-member")
			// the reader can approve: no warning
			post(owner, envLink(locked), form(map[string][]string{"reviewers": {"user:10,user:5"}}), http.StatusSeeOther)
			assert.NotContains(t, owner.MakeRequest(t, NewRequest(t, "GET", envLink(locked)), http.StatusOK).Body.String(), warning)
			// a reviewer that can't sign in no longer counts
			_, err = db.Exec(ctx, "UPDATE `user` SET prohibit_login = ? WHERE id = 5", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(ctx, "UPDATE `user` SET prohibit_login = ? WHERE id = 5", false)
				require.NoError(t, err)
			}()
			body = owner.MakeRequest(t, NewRequest(t, "GET", envLink(locked)), http.StatusOK).Body.String()
			assert.Contains(t, body, warning)
			assert.Regexp(t, `can(&#39;|')t sign in`, body)
		})

		t.Run("a deleted or hidden listed reviewer can be removed", func(t *testing.T) {
			post(owner, base+"/new", form(map[string][]string{"name": {"stale"}, "reviewers": {"user:4"}}), http.StatusSeeOther)
			stale := envByName(repo.ID, "stale")
			// listed earlier: a user who no longer exists, and user31 (private, shares no organization with user2)
			require.NoError(t, db.Insert(ctx, &actions_model.ActionEnvironmentReviewer{EnvironmentID: stale.ID, UserID: 99999}))
			require.NoError(t, db.Insert(ctx, &actions_model.ActionEnvironmentReviewer{EnvironmentID: stale.ID, UserID: 31}))
			body := owner.MakeRequest(t, NewRequest(t, "GET", envLink(stale)), http.StatusOK).Body.String()
			assert.Contains(t, body, `data-value="user:99999"`)
			assert.Contains(t, body, `data-value="user:31"`)
			assert.Equal(t, 2, strings.Count(body, "Unknown reviewer"), "one entry each, removable")
			assert.NotContains(t, body, "user31", "the hidden user's name is not shown")

			// keeping the hidden one while removing the missing one and adding a reader saves: only the added one is
			// checked for visibility (a missing user is never saved)
			post(owner, envLink(stale), form(map[string][]string{"reviewers": {"user:4,user:31,user:5"}}), http.StatusSeeOther)
			unittest.AssertCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: stale.ID}, 3)
			// clearing them saves, with one entry
			since := auditNow()
			post(owner, envLink(stale), form(nil), http.StatusSeeOther)
			unittest.AssertCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: stale.ID}, 0)
			assert.Equal(t, []string{"repo.actions_env.updated"}, auditActions(since, "repo.actions_env"))
			// once removed, the hidden user is refused like any new one
			body = post(owner, envLink(stale), form(map[string][]string{"reviewers": {"user:31"}}), http.StatusOK).Body.String()
			assert.Contains(t, body, "Choose up to 6 reviewers from the list.")
		})

		t.Run("a name with markup is escaped everywhere", func(t *testing.T) {
			resp := post(owner, base+"/new", form(map[string][]string{"name": {"<b>x"}}), http.StatusSeeOther)
			marked := envByName(repo.ID, "<b>x")
			assert.Equal(t, envLink(marked), resp.Header().Get("Location"))
			for _, body := range []string{
				owner.MakeRequest(t, NewRequest(t, "GET", envLink(marked)), http.StatusOK).Body.String(), // flash, title, delete modal
				owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String(),
			} {
				assert.NotContains(t, body, "<b>x")
				assert.Contains(t, body, "&lt;b&gt;x")
			}
			post(owner, envLink(marked)+"/delete", url.Values{"confirm_name": {"<b>x"}}, http.StatusSeeOther)
			body := owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String() // the deleted flash
			assert.NotContains(t, body, "<b>x")
			assert.Contains(t, body, "&lt;b&gt;x")
		})

		t.Run("secrets and variables of an environment", func(t *testing.T) {
			_, err := secret_model.InsertEncryptedSecret(ctx, 0, 0, repo.ID, "DEPLOY_TOKEN", "repo-level")
			require.NoError(t, err)
			since := auditNow()
			link := envLink(production)
			secretValue := "s3cr3t-value-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			post(owner, link+"/secrets", url.Values{"name": {"deploy_token"}, "data": {secretValue}}, http.StatusOK)
			secrets, err := db.Find[secret_model.Secret](t.Context(), secret_model.FindSecretsOptions{RepoID: repo.ID, EnvironmentID: production.ID})
			require.NoError(t, err)
			require.Len(t, secrets, 1)
			value, err := secrets[0].GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, secretValue, value)

			post(owner, link+"/variables/new", url.Values{"name": {"region"}, "data": {"eu-west-1"}}, http.StatusOK)
			variables, err := actions_model.FindVariables(t.Context(), actions_model.FindVariablesOpts{RepoID: repo.ID, EnvironmentID: production.ID})
			require.NoError(t, err)
			require.Len(t, variables, 1)

			body := owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.NotContains(t, body, secretValue, "a secret value is never in the page")
			assert.Contains(t, body, "DEPLOY_TOKEN")
			assert.Contains(t, body, "overrides repository")
			assert.Contains(t, body, "eu-west-1")
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String(), "1 secret · 1 variable")
			// a re-rendered form after an error has no secret value either
			assert.NotContains(t, post(owner, link, form(map[string][]string{"wait_timer": {"-1"}}), http.StatusOK).Body.String(), secretValue)

			sid := strconv.FormatInt(secrets[0].ID, 10)
			vid := strconv.FormatInt(variables[0].ID, 10)
			post(owner, link+"/secrets/"+sid+"/edit", url.Values{"name": {"DEPLOY_TOKEN"}, "data": {"new-value-123"}}, http.StatusOK)
			post(owner, link+"/variables/"+vid+"/edit", url.Values{"name": {"REGION"}, "data": {"eu-central-1"}}, http.StatusOK)
			s, err := secret_model.GetEnvironmentSecretByID(t.Context(), repo.ID, production.ID, secrets[0].ID)
			require.NoError(t, err)
			value, err = s.GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, "new-value-123", value)

			// the routes of another environment don't reach them
			post(owner, base+"/new", form(map[string][]string{"name": {"sibling"}}), http.StatusSeeOther)
			sibling := envLink(envByName(repo.ID, "sibling"))
			post(owner, sibling+"/secrets/"+sid+"/edit", url.Values{"name": {"STOLEN"}, "data": {"x"}}, http.StatusNotFound)
			post(owner, sibling+"/secrets/"+sid+"/delete", nil, http.StatusNotFound)
			post(owner, sibling+"/variables/"+vid+"/edit", url.Values{"name": {"STOLEN"}, "data": {"x"}}, http.StatusNotFound)
			post(owner, sibling+"/variables/"+vid+"/delete", nil, http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: secrets[0].ID, Name: "DEPLOY_TOKEN"})
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{ID: variables[0].ID})

			post(owner, link+"/secrets/"+sid+"/delete", nil, http.StatusOK)
			post(owner, link+"/variables/"+vid+"/delete", nil, http.StatusOK)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{ID: secrets[0].ID})
			unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{ID: variables[0].ID})
			assert.Equal(t, []string{
				"repo.actions_env_secret.created", "repo.actions_env_variable.created",
				"repo.actions_env_secret.updated", "repo.actions_env_variable.updated",
				"repo.actions_env_secret.deleted", "repo.actions_env_variable.deleted",
			}, auditActions(since, "repo.actions_env_"))
			assert.Empty(t, auditActions(since, "repo.actions_secret"), "the repository's secret is untouched")
		})

		t.Run("a value is measured after its line breaks are normalized", func(t *testing.T) {
			// "a\r\n" is stored as "a\n": 32768 of them are exactly 64 KiB stored, 96 KiB as posted
			fits := strings.Repeat("a\r\n", secret_model.MaxValueSize/2)
			tooLarge := fits + "b"
			for _, level := range []string{envLink(production), fmt.Sprintf("/%s/%s/settings/actions", user2.Name, repo.Name)} {
				post(owner, level+"/secrets", url.Values{"name": {"BIG"}, "data": {fits}}, http.StatusOK)
				var stored []*secret_model.Secret
				require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ? AND name = ?", repo.ID, "BIG").Find(&stored))
				var s *secret_model.Secret
				for _, x := range stored {
					if (x.EnvironmentID != 0) == strings.Contains(level, "/environments/") {
						s = x
					}
				}
				require.NotNil(t, s, level)
				sid := strconv.FormatInt(s.ID, 10)
				post(owner, level+"/secrets/"+sid+"/edit", url.Values{"name": {"BIG"}, "data": {fits}}, http.StatusOK)
				for _, req := range []struct{ link, name string }{{level + "/secrets", "BIG2"}, {level + "/secrets/" + sid + "/edit", "BIG"}} {
					body := post(owner, req.link, url.Values{"name": {req.name}, "data": {tooLarge}}, http.StatusBadRequest).Body.String()
					assert.Contains(t, body, "The value is too large: a secret holds at most 64 KiB.", req.link)
				}
				post(owner, level+"/variables/new", url.Values{"name": {"BIG"}, "data": {fits}}, http.StatusOK)
				body := post(owner, level+"/variables/new", url.Values{"name": {"BIG2"}, "data": {tooLarge}}, http.StatusBadRequest).Body.String()
				assert.Contains(t, body, "The value is too large: a variable holds at most 64 KiB.")
				post(owner, level+"/secrets/"+sid+"/delete", nil, http.StatusOK)
			}
			_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND name = ?", repo.ID, "BIG").Delete(new(actions_model.ActionVariable))
			require.NoError(t, err)
		})

		t.Run("who may manage environments", func(t *testing.T) {
			link := envLink(production)
			for _, name := range []string{"user4", "user8", "user5", "user10"} {
				t.Run(name, func(t *testing.T) {
					s := loginUser(t, name)
					for _, path := range []string{base, base + "/new", link} {
						s.MakeRequest(t, NewRequest(t, "GET", path), http.StatusNotFound)
					}
					post(s, base+"/new", form(map[string][]string{"name": {"intruder"}}), http.StatusNotFound)
					post(s, link, form(nil), http.StatusNotFound)
					post(s, link+"/delete", url.Values{"confirm_name": {"Production"}}, http.StatusNotFound)
					post(s, link+"/secrets", url.Values{"name": {"X"}, "data": {"y"}}, http.StatusNotFound)
					post(s, link+"/variables/new", url.Values{"name": {"X"}, "data": {"y"}}, http.StatusNotFound)
				})
			}
			// an admin collaborator sees the other Actions settings, but not the menu item
			body := loginUser(t, "user8").MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/%s/settings/actions/secrets", user2.Name, repo.Name)), http.StatusOK).Body.String()
			assert.NotContains(t, body, "/settings/actions/environments")
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/%s/settings/actions/secrets", user2.Name, repo.Name)), http.StatusOK).Body.String(), "/settings/actions/environments")
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "intruder"})
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: production.ID})

			admin := loginUser(t, "user1")
			admin.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
			post(admin, link, form(map[string][]string{"reviewers": {"user:4"}, "ref_policy": {"1"}}), http.StatusSeeOther)
		})

		t.Run("an environment of another repository is not found", func(t *testing.T) {
			wrong := otherBase + "/" + strconv.FormatInt(production.ID, 10)
			owner.MakeRequest(t, NewRequest(t, "GET", wrong), http.StatusNotFound)
			post(owner, wrong, form(nil), http.StatusNotFound)
			post(owner, wrong+"/delete", url.Values{"confirm_name": {"Production"}}, http.StatusNotFound)
			post(owner, wrong+"/secrets", url.Values{"name": {"X"}, "data": {"y"}}, http.StatusNotFound)
			post(owner, wrong+"/variables/new", url.Values{"name": {"X"}, "data": {"y"}}, http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: production.ID})
			unittest.AssertCount(t, &secret_model.Secret{EnvironmentID: production.ID}, 0)
		})

		t.Run("archived repository refuses writes", func(t *testing.T) {
			_, err := db.Exec(ctx, "UPDATE repository SET is_archived = ? WHERE id = ?", true, repo.ID)
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(ctx, "UPDATE repository SET is_archived = ? WHERE id = ?", false, repo.ID)
				require.NoError(t, err)
			}()
			link := envLink(production)
			body := owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.Contains(t, body, `id="environment-archived"`)
			assert.Contains(t, body, "<fieldset class=\"tw-contents\" disabled>")
			assert.NotContains(t, body, `id="environment-save"`)
			assert.NotContains(t, body, `data-modal="#add-secret-modal"`)
			assert.NotContains(t, body, `id="delete-environment-modal"`)
			assert.NotContains(t, owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String(), base+"/new")
			post(owner, base+"/new", form(map[string][]string{"name": {"frozen"}}), http.StatusNotFound)
			post(owner, link, form(nil), http.StatusNotFound)
			post(owner, link+"/delete", url.Values{"confirm_name": {"Production"}}, http.StatusNotFound)
			post(owner, link+"/secrets", url.Values{"name": {"X"}, "data": {"y"}}, http.StatusNotFound)
			post(owner, link+"/variables/new", url.Values{"name": {"X"}, "data": {"y"}}, http.StatusNotFound)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "frozen"})
		})

		t.Run("read-only maintenance refuses writes", func(t *testing.T) {
			defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
			owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
			req := NewRequestWithURLValues(t, "POST", base+"/new", form(map[string][]string{"name": {"frozen"}}))
			req.Header.Set("Referer", setting.AppURL+user2.Name)
			owner.MakeRequest(t, req, http.StatusSeeOther)
			assertMaintenanceFlash(t, owner)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "frozen"})
		})

		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "env-web-runner", []string{"env-web"})
		pushJob := func(path, env string) *actions_model.ActionRunJob {
			content := fmt.Sprintf("on:\n  push:\n    paths:\n      - '%s'\njobs:\n  deploy:\n    runs-on: env-web\n    environment: %s\n    steps:\n      - run: echo\n", path, env)
			fileResp := createWorkflowFile(t, ownerToken, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add "+path, content))
			var job *actions_model.ActionRunJob
			require.Eventually(t, func() bool {
				r := new(actions_model.ActionRun)
				if has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repo.ID, fileResp.Commit.SHA).Get(r); err != nil || !has {
					return false
				}
				jobs, err := actions_model.GetRunJobsByRunID(db.DefaultContext, r.ID)
				if err == nil && len(jobs) == 1 {
					job = jobs[0]
				}
				return job != nil
			}, 10*time.Second, 100*time.Millisecond)
			return job
		}
		jobStatus := func(job *actions_model.ActionRunJob) actions_model.Status {
			j := new(actions_model.ActionRunJob)
			if has, err := db.GetEngine(db.DefaultContext).ID(job.ID).Get(j); err != nil || !has {
				return actions_model.StatusUnknown
			}
			return j.Status
		}

		t.Run("a save that clears the reviewers releases a waiting job", func(t *testing.T) {
			post(owner, base+"/new", form(map[string][]string{"name": {"gated"}, "reviewers": {"user:4"}}), http.StatusSeeOther)
			gated := envByName(repo.ID, "gated")
			job := pushJob(".gitea/workflows/web-gated.yml", "gated")
			d, err := actions_model.GetDeployment(t.Context(), job.ID, 1)
			require.NoError(t, err)
			require.NotNil(t, d)
			require.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
			assert.Nil(t, runner.maybeFetchTask(t))

			since := auditNow()
			post(owner, envLink(gated), form(nil), http.StatusSeeOther)
			require.Eventually(t, func() bool { return jobStatus(job) == actions_model.StatusWaiting }, 10*time.Second, 100*time.Millisecond)
			d, err = actions_model.GetDeployment(t.Context(), job.ID, 1)
			require.NoError(t, err)
			assert.Equal(t, actions_model.DeploymentReleased, d.Status)
			assert.Equal(t, []string{"repo.actions_env.updated"}, auditActions(since, "repo.actions_env"))
			// released, no runner took it yet
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String(), "Released, not started yet")
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_FAILURE})

			// the list shows the last deployment with its outcome, ref and run
			body := owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.NotContains(t, body, "Released, not started yet")
			assert.Regexp(t, `(?s)environment-deployment.*Failure`, body)
			assert.Regexp(t, `href="/user2/web-envs/actions/runs/\d+">main</a>`, body)
		})

		t.Run("delete needs the typed name and shows the last deployment", func(t *testing.T) {
			gated := envByName(repo.ID, "gated")
			link := envLink(gated)
			body := owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.Contains(t, body, "The next deployment to gated will run without approval")
			assert.Contains(t, body, `id="delete-environment-modal"`)
			assert.Regexp(t, `(?s)Last deployment:.*Failure`, body)

			since := auditNow()
			resp := post(owner, link+"/delete", url.Values{"confirm_name": {"GATED"}}, http.StatusSeeOther)
			assert.Equal(t, link, resp.Header().Get("Location"))
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: gated.ID})
			assert.Empty(t, auditActions(since, "repo.actions_env"))

			resp = post(owner, link+"/delete", url.Values{"confirm_name": {"gated"}}, http.StatusSeeOther)
			assert.Equal(t, base, resp.Header().Get("Location"))
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{ID: gated.ID})
			assert.Equal(t, []string{"repo.actions_env.deleted"}, auditActions(since, "repo.actions_env"))
			post(owner, link+"/delete", url.Values{"confirm_name": {"gated"}}, http.StatusNotFound)
		})

		t.Run("a workflow-created environment says so", func(t *testing.T) {
			pushJob(".gitea/workflows/web-preview.yml", "preview")
			require.Eventually(t, func() bool {
				_, err := actions_model.GetRepoEnvironmentByName(db.DefaultContext, repo.ID, "preview")
				return err == nil
			}, 10*time.Second, 100*time.Millisecond)
			body := owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, body, "No protection")
			assert.Contains(t, body, "Created by a workflow, no protection rules.")
		})
	})
}

// The reviewer picker of an organization's repository offers its teams only, and no user the doer can't see.
func TestActionsEnvironmentsWebPicker(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "web-env-picker", AutoInit: true}).AddTokenAuth(token), http.StatusCreated)
	body := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3/web-env-picker/settings/actions/environments/new"), http.StatusOK).Body.String()

	var teams []*struct{ ID int64 }
	require.NoError(t, db.GetEngine(t.Context()).Table("team").Where("org_id = 3").Cols("id").Find(&teams))
	require.NotEmpty(t, teams)
	want := map[string]bool{}
	for _, team := range teams {
		want["team:"+strconv.FormatInt(team.ID, 10)] = true
	}
	got := map[string]bool{}
	for _, m := range regexp.MustCompile(`data-value="(team:\d+)"`).FindAllStringSubmatch(body, -1) {
		got[m[1]] = true
	}
	assert.Equal(t, want, got, "exactly the teams of the owning organization")
	assert.NotContains(t, body, `data-value="user:31"`)
	assert.Contains(t, body, `data-value="user:2"`)
}

// The picker of a public repository offers its read-only collaborators and the read-only members of its teams (the
// access table holds no read rows on a public repository), and only an owner of the organization manages the
// environments of its repositories.
func TestActionsEnvironmentsWebOrgRepo(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "web-env-public", AutoInit: true}).AddTokenAuth(token), http.StatusCreated)
	repo, err := repo_model.GetRepositoryByOwnerAndName(ctx, "org3", "web-env-public")
	require.NoError(t, err)
	require.False(t, repo.IsPrivate)
	link := "/org3/web-env-public/settings/actions/environments"
	owner := loginUser(t, "user2")

	readers := &organization.Team{OrgID: 3, Name: "env-readers", AccessMode: perm.AccessModeRead, Units: []*organization.TeamUnit{
		{OrgID: 3, Type: unit.TypeCode, AccessMode: perm.AccessModeRead}, {OrgID: 3, Type: unit.TypeActions, AccessMode: perm.AccessModeRead},
	}}
	require.NoError(t, models.NewTeam(ctx, readers))
	require.NoError(t, models.AddTeamMemberByCooptation(ctx, readers, 5, 2))
	require.NoError(t, org_service.TeamAddRepository(ctx, readers, repo))
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/web-env-public/collaborators/user10",
		&api.AddCollaboratorOption{Permission: new("read")}).AddTokenAuth(token), http.StatusNoContent)

	t.Run("picker offers read-only users", func(t *testing.T) {
		body := owner.MakeRequest(t, NewRequest(t, "GET", link+"/new"), http.StatusOK).Body.String()
		assert.Contains(t, body, `data-value="user:5"`, "a read-only team member")
		assert.Contains(t, body, `data-value="user:10"`, "a read-only collaborator")
		assert.Contains(t, body, "@user5", "users show their login")
		assert.Contains(t, body, "org3/env-readers", "teams show their organization")
		assert.Contains(t, body, "users or teams of the organization")
	})

	t.Run("only an acting owner of the organization", func(t *testing.T) {
		// team12 has administrator access (Admin, not Owner)
		admins := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 12})
		require.NoError(t, org_service.TeamAddRepository(ctx, admins, repo))
		for _, c := range []struct {
			user   string
			status int
		}{{"user2", http.StatusOK}, {"user1", http.StatusOK}, {"user28", http.StatusNotFound}, {"user5", http.StatusNotFound}, {"user10", http.StatusNotFound}} {
			s := loginUser(t, c.user)
			s.MakeRequest(t, NewRequest(t, "GET", link), c.status)
			s.MakeRequest(t, NewRequest(t, "GET", link+"/new"), c.status)
		}
		post := NewRequestWithValues(t, "POST", link+"/new", map[string]string{"name": "intruder", "ref_policy": "0"})
		loginUser(t, "user28").MakeRequest(t, post, http.StatusNotFound)
		unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "intruder"})

		// an owner without 2FA in an organization that requires it is no owner there
		_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		resp := owner.MakeRequest(t, NewRequest(t, "GET", link), NoExpectedStatus)
		assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, resp.Code)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/new", map[string]string{"name": "blocked", "ref_policy": "0"}), NoExpectedStatus)
		unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "blocked"})
	})
}

// The list and the form decide every reviewer with a fixed number of queries, whatever the number of environments,
// readers and team members.
func TestActionsEnvironmentsWebQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	session := loginUser(t, "user2")
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)

	count := func(n int) []int64 {
		org := &organization.Organization{Name: fmt.Sprintf("env-q-%d", n)}
		require.NoError(t, organization.CreateOrganization(ctx, org, owner))
		repo, err := repo_service.CreateRepositoryDirectly(ctx, owner, org.AsUser(), repo_service.CreateRepoOptions{Name: "deploy"})
		require.NoError(t, err)
		team := &organization.Team{OrgID: org.ID, Name: "deployers", AccessMode: perm.AccessModeRead, Units: []*organization.TeamUnit{
			{OrgID: org.ID, Type: unit.TypeActions, AccessMode: perm.AccessModeRead},
		}}
		require.NoError(t, models.NewTeam(ctx, team))
		require.NoError(t, org_service.TeamAddRepository(ctx, team, repo))
		for i := range n {
			u := &user_model.User{Name: fmt.Sprintf("env-q-%d-%d", n, i), Email: fmt.Sprintf("env-q-%d-%d@example.com", n, i), IsActive: true}
			require.NoError(t, user_model.CreateUser(ctx, u))
			require.NoError(t, models.AddTeamMemberByCooptation(ctx, team, u.ID, owner.ID))
			MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/deploy/collaborators/%s", org.Name, u.Name),
				&api.AddCollaboratorOption{Permission: new("read")}).AddTokenAuth(token), http.StatusNoContent)
		}
		base := fmt.Sprintf("/%s/deploy/settings/actions/environments", org.Name)
		for i := range n {
			session.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/new", map[string]string{
				"name": fmt.Sprintf("env-%d", i), "reviewers": fmt.Sprintf("team:%d", team.ID), "ref_policy": "0",
			}), http.StatusSeeOther)
		}
		env, err := actions_model.GetRepoEnvironmentByName(ctx, repo.ID, "env-0")
		require.NoError(t, err)
		var counts []int64
		for _, l := range []string{base, base + "/new", fmt.Sprintf("%s/%d", base, env.ID)} {
			session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) // generated avatars are saved once
			counts = append(counts, stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) }))
		}
		return counts
	}
	assert.Equal(t, count(1), count(20))
}

// The pages tell nothing about an account that has no membership path to the repository: site administrators and
// auditors are never offered, a stranger can't be added and shows the one answer of a non-member whatever their
// account (deactivated, login prohibited, with or without 2FA), and a list of any length is bounded before a lookup.
func TestActionsEnvironmentsWebOutsiders(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	ownerTok := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeWriteOrganization)
	owner := loginUser(t, "user2") // before the 2FA row below, which would ask for a second factor
	priv := createActionsTestRepo(t, ownerTok, "env-outsiders", true)
	createActionsTestRepo(t, ownerTok, "env-outsiders-pub", false)
	base := "/user2/env-outsiders/settings/actions/environments"
	form := func(kv ...string) map[string]string {
		v := map[string]string{"ref_policy": "0", "wait_timer": "0"}
		for i := 0; i+1 < len(kv); i += 2 {
			v[kv[i]] = kv[i+1]
		}
		return v
	}
	reasonOf := func(body string, uid int) string {
		m := regexp.MustCompile(`(?s)data-value="user:` + strconv.Itoa(uid) + `">.*?<span class="help">\s*(.*?)\s*</span>`).FindStringSubmatch(body)
		if m == nil {
			return ""
		}
		return m[1]
	}

	t.Run("site administrators and auditors are not offered", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE `user` SET is_auditor = ? WHERE id = 11", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE `user` SET is_auditor = ? WHERE id = 11", false)
			require.NoError(t, err)
		}()
		for _, p := range []string{"/user2/env-outsiders-pub/settings/actions/environments/new", base + "/new"} {
			body := owner.MakeRequest(t, NewRequest(t, "GET", p), http.StatusOK).Body.String()
			assert.NotContains(t, body, `data-value="user:1"`, "the site admin on %s", p)
			assert.NotContains(t, body, `data-value="user:11"`, "an auditor on %s", p)
			assert.NotContains(t, body, `data-value="user:31"`, "a private user who shares nothing on %s", p)
			assert.Contains(t, body, `data-value="user:2"`, p)
		}
	})

	t.Run("a stranger's account state is not told", func(t *testing.T) {
		// user9 is deactivated, user37 can't sign in, user11 is a plain active user: none relates to the repository
		resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/new", form("name", "probe", "reviewers", "user:9,user:37,user:11")), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "A reviewer must be the owner, a collaborator or a member of a team with access to this repository.")
		unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: priv.ID, LowerName: "probe"})
		for _, uid := range []int{9, 37, 11} {
			assert.Equal(t, "not a member of this repository", reasonOf(body, uid), "user %d", uid)
		}

		// listed before (as a site administrator may): the edit page tells the same
		require.Equal(t, http.StatusSeeOther, owner.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/new", form("name", "probe")), NoExpectedStatus).Code)
		probe, err := actions_model.GetRepoEnvironmentByName(ctx, priv.ID, "probe")
		require.NoError(t, err)
		for _, uid := range []int64{9, 37, 11} {
			require.NoError(t, db.Insert(ctx, &actions_model.ActionEnvironmentReviewer{EnvironmentID: probe.ID, UserID: uid}))
		}
		body = owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", base, probe.ID)), http.StatusOK).Body.String()
		for _, uid := range []int{9, 37, 11} {
			assert.Equal(t, "not a member of this repository", reasonOf(body, uid), "listed user %d", uid)
		}
	})

	t.Run("2FA enrolment of a non-member is not told", func(t *testing.T) {
		// user24 has 2FA, user11 hasn't; neither is a member of an organization that requires it
		_, err := db.Exec(ctx, "INSERT INTO two_factor (uid, secret, scratch_salt, scratch_hash, created_unix, updated_unix) SELECT 2, secret, scratch_salt, scratch_hash, created_unix, updated_unix FROM two_factor WHERE uid = 24")
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "DELETE FROM two_factor WHERE uid = 2")
			require.NoError(t, err)
		}()
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "env-2fa"}).AddTokenAuth(ownerTok), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/env-2fa/repos", &api.CreateRepoOption{Name: "pub", AutoInit: true}).AddTokenAuth(ownerTok), http.StatusCreated)
		_, err = db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE lower_name = ?", true, "env-2fa")
		require.NoError(t, err)
		body := owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/env-2fa/pub/settings/actions/environments/new", form("name", "probe", "reviewers", "user:24,user:11")), http.StatusOK).Body.String()
		assert.Equal(t, "not a member of this repository", reasonOf(body, 24))
		assert.Equal(t, reasonOf(body, 24), reasonOf(body, 11))
	})

	t.Run("a list of any length is refused by its size", func(t *testing.T) {
		keys := make([]string, 40000)
		for i := range keys {
			keys[i] = "user:" + strconv.Itoa(100000+i)
		}
		require.Equal(t, http.StatusSeeOther, owner.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/new", form("name", "alpha")), NoExpectedStatus).Code)
		alpha, err := actions_model.GetRepoEnvironmentByName(ctx, priv.ID, "alpha")
		require.NoError(t, err)
		for _, link := range []string{base + "/new", fmt.Sprintf("%s/%d", base, alpha.ID)} {
			body := owner.MakeRequest(t, NewRequestWithValues(t, "POST", link, form("name", "huge", "reviewers", strings.Join(keys, ","))), http.StatusOK).Body.String()
			assert.Contains(t, body, "At most 6 reviewers.", link)
		}
		unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: priv.ID, LowerName: "huge"})
	})

	t.Run("the delete confirmation is the exact name", func(t *testing.T) {
		alpha, err := actions_model.GetRepoEnvironmentByName(ctx, priv.ID, "alpha")
		require.NoError(t, err)
		link := fmt.Sprintf("%s/%d/delete", base, alpha.ID)
		for _, typed := range []string{"alpha\r", " alpha", "alpha\n", "ALPHA"} {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"confirm_name": typed}), http.StatusSeeOther)
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: alpha.ID})
		}
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"confirm_name": "alpha"}), http.StatusSeeOther)
		unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{ID: alpha.ID})
	})
}
