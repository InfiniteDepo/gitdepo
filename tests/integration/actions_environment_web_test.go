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

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
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
				"seven reviewers":          {envLink(production), form(map[string][]string{"reviewers": {"user:1,user:4,user:5,user:8,user:10,user:11,user:12"}}), "Choose up to 6 reviewers from the list."},
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
			// user10 can't read the private repository, so nobody listed can approve
			post(owner, base+"/new", form(map[string][]string{"name": {"locked"}, "reviewers": {"user:10"}}), http.StatusSeeOther)
			locked := envByName(repo.ID, "locked")
			warning := "Nobody listed can approve a deployment right now"
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String(), warning)
			body := owner.MakeRequest(t, NewRequest(t, "GET", envLink(locked)), http.StatusOK).Body.String()
			assert.Contains(t, body, warning)
			assert.Contains(t, body, "no access to Actions", "the listed user is shown with the reason")
			// the reader can approve: no warning
			post(owner, envLink(locked), form(map[string][]string{"reviewers": {"user:10,user:5"}}), http.StatusSeeOther)
			assert.NotContains(t, owner.MakeRequest(t, NewRequest(t, "GET", envLink(locked)), http.StatusOK).Body.String(), warning)
			// a reviewer that can't sign in no longer counts
			_, err := db.Exec(ctx, "UPDATE `user` SET prohibit_login = ? WHERE id = 5", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(ctx, "UPDATE `user` SET prohibit_login = ? WHERE id = 5", false)
				require.NoError(t, err)
			}()
			body = owner.MakeRequest(t, NewRequest(t, "GET", envLink(locked)), http.StatusOK).Body.String()
			assert.Contains(t, body, warning)
			assert.Regexp(t, `can(&#39;|')t sign in`, body)
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
			post(owner, sibling+"/secrets/"+sid+"/delete", nil, http.StatusBadRequest)
			post(owner, sibling+"/variables/"+vid+"/delete", nil, http.StatusBadRequest)
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
			owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
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
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			// the list shows the last deployment with its ref and run
			body := owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, body, "Released")
			assert.Regexp(t, `href="/user2/web-envs/actions/runs/\d+">main</a>`, body)
		})

		t.Run("delete needs the typed name and shows the last deployment", func(t *testing.T) {
			gated := envByName(repo.ID, "gated")
			link := envLink(gated)
			body := owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.Contains(t, body, "The next deployment to gated will run without approval")
			assert.Contains(t, body, `id="delete-environment-modal"`)
			assert.Regexp(t, `(?s)Last deployment:.*Released`, body)

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
