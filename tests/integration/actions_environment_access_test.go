// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	actions_service "forgejo.org/services/actions"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Attempts against the environments API and their deployment protection that must fail: tokens that don't reach the
// repository, blocked owners, trashed repositories, leaks of secret values, malformed bodies and rule edits that
// would release a waiting job early.
func TestActionsEnvironmentAccess(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		owner := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		reviewer := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository)

		apiRepo := createActionsTestRepo(t, owner, "env-access", true)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		otherAPIRepo := createActionsTestRepo(t, owner, "env-access-other", true)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/user4", user2.Name, repo.Name),
			&api.AddCollaboratorOption{Permission: new("read")}).AddTokenAuth(owner), http.StatusNoContent)
		base := fmt.Sprintf("/api/v1/repos/%s/%s/actions/environments", user2.Name, repo.Name)
		put := func(token, name string, opts any, status int) {
			t.Helper()
			if o, ok := opts.(api.CreateOrUpdateEnvironmentOption); ok {
				opts = envRules(o)
			}
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/"+url.PathEscape(name), opts).AddTokenAuth(token), status)
		}
		// rules is a complete body as a map, with the fields of change replaced
		rules := func(change map[string]any) map[string]any {
			body := map[string]any{
				"ref_policy": "any", "ref_patterns": []any{}, "wait_timer": 0, "prevent_self_review": false,
				"reviewers": []any{}, "runner_labels": []any{}, "allowed_workflows": []any{},
			}
			maps.Copy(body, change)
			return body
		}
		auditNow := func() int64 {
			var id int64
			_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
			require.NoError(t, err)
			return id
		}

		t.Run("tokens that don't reach the repository", func(t *testing.T) {
			put(owner, "prod", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			other := createFineGrainedRepoAccessToken(t, user2.Name, []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository}, []int64{otherAPIRepo.ID})
			for _, req := range []*RequestWrapper{
				NewRequest(t, "GET", base),
				NewRequestWithJSON(t, "PUT", base+"/prod", envRules(api.CreateOrUpdateEnvironmentOption{})),
				NewRequestWithJSON(t, "PUT", base+"/prod/secrets/X", api.CreateOrUpdateSecretOption{Data: "x"}),
			} {
				code := MakeRequest(t, req.AddTokenAuth(other), NoExpectedStatus).Code
				assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, code, req.URL.Path)
			}
			publicOnly := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopePublicOnly)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/actions/deployments", user2.Name, repo.Name)).AddTokenAuth(publicOnly), http.StatusNotFound)
			readOnly := getUserToken(t, user2.Name, auth_model.AccessTokenScopeReadRepository)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/prod/variables/V", api.UpdateVariableOption{Value: "x"}).AddTokenAuth(readOnly), http.StatusForbidden)
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/prod/variables/V", api.CreateVariableOption{Value: "x"}).AddTokenAuth(readOnly), http.StatusForbidden)
			// the ID mount: a reader of the repository is no admin, a stranger doesn't see it
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d/actions/environments", repo.ID)).AddTokenAuth(reviewer), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d/actions/environments", otherAPIRepo.ID)).AddTokenAuth(reviewer), http.StatusNotFound)
		})

		t.Run("an owner blocked by the organization's 2FA requirement", func(t *testing.T) {
			unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{}})
			orgBase := "/api/v1/repos/org3/repo3/actions/environments"
			MakeRequest(t, NewRequestWithJSON(t, "PUT", orgBase+"/prod", envRules(api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "team", ID: 1}}})).AddTokenAuth(owner), http.StatusCreated)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
				require.NoError(t, err)
			}()
			for _, req := range []*RequestWrapper{
				NewRequestWithJSON(t, "PUT", orgBase+"/prod", envRules(api.CreateOrUpdateEnvironmentOption{})),
				NewRequest(t, "DELETE", orgBase+"/prod"),
				NewRequestWithJSON(t, "PUT", orgBase+"/prod/secrets/S", api.CreateOrUpdateSecretOption{Data: "x"}),
				NewRequest(t, "GET", orgBase+"/prod"),
				NewRequest(t, "GET", "/api/v1/repos/org3/repo3/actions/deployments"),
			} {
				code := MakeRequest(t, req.AddTokenAuth(owner), NoExpectedStatus).Code
				assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, code, req.URL.Path)
			}
			e := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: 3, LowerName: "prod"})
			assert.True(t, e.ReviewsRequired, "the rules are unchanged")
		})

		t.Run("a repository in the trash", func(t *testing.T) {
			trashed := createActionsTestRepo(t, owner, "env-access-trash", true)
			trashBase := fmt.Sprintf("/api/v1/repos/%s/%s/actions/environments", user2.Name, trashed.Name)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", trashBase+"/prod", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(owner), http.StatusCreated)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = ? WHERE id = ?", timeutil.TimeStampNow(), trashed.ID)
			require.NoError(t, err)
			MakeRequest(t, NewRequest(t, "GET", trashBase).AddTokenAuth(owner), http.StatusNotFound)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", trashBase+"/prod", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(owner), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d/actions/environments", trashed.ID)).AddTokenAuth(owner), http.StatusNotFound)
		})

		t.Run("a secret value is never in a response or the audit log", func(t *testing.T) {
			put(owner, "leak", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			since := auditNow()
			value := "ENV-ACCESS-SECRET-VALUE-zz9"
			for _, req := range []*RequestWrapper{
				NewRequestWithJSON(t, "PUT", base+"/leak/secrets/K", api.CreateOrUpdateSecretOption{Data: value}),
				NewRequestWithJSON(t, "PUT", base+"/leak/secrets/K", api.CreateOrUpdateSecretOption{Data: value + "2"}),
				NewRequestWithJSON(t, "PUT", base+"/leak/secrets/GITEA_X", api.CreateOrUpdateSecretOption{Data: value}),
				NewRequestWithJSON(t, "PUT", base+"/leak/secrets/"+url.PathEscape("bad name"), api.CreateOrUpdateSecretOption{Data: value}),
				NewRequest(t, "GET", base+"/leak/secrets"),
				NewRequest(t, "GET", base+"/leak"),
				NewRequest(t, "GET", base),
				NewRequest(t, "DELETE", base+"/leak/secrets/K"),
				NewRequestWithJSON(t, "PUT", base+"/leak/secrets/K", api.CreateOrUpdateSecretOption{Data: value}),
				NewRequest(t, "DELETE", base+"/leak"),
			} {
				assert.NotContains(t, MakeRequest(t, req.AddTokenAuth(owner), NoExpectedStatus).Body.String(), value, req.URL.Path)
			}
			var data []string
			require.NoError(t, db.GetEngine(t.Context()).Table("audit_event").Where("id > ?", since).Cols("data").Find(&data))
			assert.NotEmpty(t, data)
			for _, d := range data {
				assert.NotContains(t, d, value)
			}
		})

		t.Run("a variable renamed onto a taken name, and value sizes", func(t *testing.T) {
			put(owner, "vars", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			repoBase := fmt.Sprintf("/api/v1/repos/%s/%s/actions", user2.Name, repo.Name)
			for _, level := range []string{base + "/vars", repoBase} {
				MakeRequest(t, NewRequestWithJSON(t, "POST", level+"/variables/A", api.CreateVariableOption{Value: "a"}).AddTokenAuth(owner), http.StatusNoContent)
				MakeRequest(t, NewRequestWithJSON(t, "POST", level+"/variables/B", api.CreateVariableOption{Value: "b"}).AddTokenAuth(owner), http.StatusNoContent)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", level+"/variables/A", api.UpdateVariableOption{Name: "B", Value: "x"}).AddTokenAuth(owner), http.StatusConflict)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", level+"/variables/A", api.UpdateVariableOption{Name: "ci", Value: "x"}).AddTokenAuth(owner), http.StatusBadRequest)

				big, fits := strings.Repeat("v", secret_model.MaxValueSize+1), strings.Repeat("v", secret_model.MaxValueSize)
				MakeRequest(t, NewRequestWithJSON(t, "POST", level+"/variables/BIG", api.CreateVariableOption{Value: big}).AddTokenAuth(owner), http.StatusBadRequest)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", level+"/variables/A", api.UpdateVariableOption{Value: big}).AddTokenAuth(owner), http.StatusBadRequest)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", level+"/secrets/BIG", api.CreateOrUpdateSecretOption{Data: big}).AddTokenAuth(owner), http.StatusBadRequest)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", level+"/secrets/BIG", api.CreateOrUpdateSecretOption{Data: fits}).AddTokenAuth(owner), http.StatusCreated)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", level+"/secrets/BIG", api.CreateOrUpdateSecretOption{Data: big}).AddTokenAuth(owner), http.StatusBadRequest)
				MakeRequest(t, NewRequestWithJSON(t, "POST", level+"/variables/FITS", api.CreateVariableOption{Value: fits}).AddTokenAuth(owner), http.StatusNoContent)
			}

			// an environment holds at most 100 secrets and 100 variables
			env := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "vars"})
			ctx := audit_model.WithSystem(t.Context(), "test")
			for i := unittest.GetCount(t, &actions_model.ActionVariable{EnvironmentID: env.ID}); i < secret_model.MaxPerEnvironment; i++ {
				_, err := actions_model.InsertEnvironmentVariable(ctx, repo.ID, env.ID, fmt.Sprintf("V%d", i), "x")
				require.NoError(t, err)
			}
			for i := unittest.GetCount(t, &secret_model.Secret{EnvironmentID: env.ID}); i < secret_model.MaxPerEnvironment; i++ {
				_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, env.ID, fmt.Sprintf("S%d", i), "x")
				require.NoError(t, err)
			}
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/vars/variables/ONE_MORE", api.CreateVariableOption{Value: "x"}).AddTokenAuth(owner), http.StatusBadRequest)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/vars/secrets/ONE_MORE", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(owner), http.StatusBadRequest)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/vars/secrets/S1", api.CreateOrUpdateSecretOption{Data: "y"}).AddTokenAuth(owner), http.StatusNoContent)
		})

		t.Run("malformed bodies and names", func(t *testing.T) {
			put(owner, "typo", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}, WaitTimer: new(5)}, http.StatusCreated)
			// a typo in a key leaves a rule out, which is refused instead of resetting it
			put(owner, "typo", map[string]any{"reviewer": []map[string]any{{"type": "user", "id": 4}}, "wait_timer": 5}, http.StatusUnprocessableEntity)
			put(owner, "typo", map[string]any{"reviewers": nil}, http.StatusUnprocessableEntity)
			e := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "typo"})
			assert.True(t, e.ReviewsRequired)
			assert.Equal(t, 5, e.WaitTimerMinutes)

			// a long reviewer list is refused before any reviewer is looked up
			many := make([]map[string]any, 0, 20000)
			for i := range 20000 {
				many = append(many, map[string]any{"type": "user", "id": 4 + i%2})
			}
			put(owner, "typo", rules(map[string]any{"reviewers": many}), http.StatusUnprocessableEntity)
			for _, reviewer := range []map[string]any{{"type": "User", "id": 4}, {"type": "user", "id": 0}, {"type": "user", "login": "user4"}} {
				put(owner, "typo", rules(map[string]any{"reviewers": []map[string]any{reviewer}}), http.StatusUnprocessableEntity)
			}
			put(owner, "typo", rules(map[string]any{"ref_patterns": []map[string]any{{"type": "branch", "pattern": "x"}}}), http.StatusUnprocessableEntity)
			for _, timer := range []int64{1 << 40, 43201, -1} {
				code := MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/typo", rules(map[string]any{"wait_timer": timer})).AddTokenAuth(owner), NoExpectedStatus).Code
				assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnprocessableEntity}, code, timer)
			}
			e = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "typo"})
			assert.Equal(t, 5, e.WaitTimerMinutes, "nothing refused changed the rules")

			// names that are paths, or a known name with spaces around it
			for _, name := range []string{"..", ".", "...", "a/b", "TyPo ", " typo"} {
				code := MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/"+url.PathEscape(name), rules(nil)).AddTokenAuth(owner), NoExpectedStatus).Code
				assert.NotEqual(t, http.StatusCreated, code, name)
			}
			var names []string
			require.NoError(t, db.GetEngine(t.Context()).Table("action_environment").Where("repo_id = ?", repo.ID).Cols("lower_name").Find(&names))
			for _, name := range names {
				assert.NotEmpty(t, strings.Trim(name, "."), "a name of dots")
				assert.NotContains(t, name, "/")
			}
		})

		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "env-access-runner", []string{"env-access"})
		files := 0
		pushJob := func(jobLines string) *actions_model.ActionRunJob {
			files++
			path := fmt.Sprintf(".gitea/workflows/access%d.yml", files)
			content := fmt.Sprintf("on:\n  push:\n    paths:\n      - '%s'\njobs:\n  deploy:\n    runs-on: env-access\n%s    steps:\n      - run: echo\n", path, jobLines)
			fileResp := createWorkflowFile(t, owner, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add "+path, content))
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
		deployment := func(job *actions_model.ActionRunJob) *actions_model.ActionDeployment {
			d, err := actions_model.GetDeployment(db.DefaultContext, job.ID, 1)
			require.NoError(t, err)
			require.NotNil(t, d)
			return d
		}
		jobStatus := func(job *actions_model.ActionRunJob) actions_model.Status {
			j := new(actions_model.ActionRunJob)
			if has, err := db.GetEngine(db.DefaultContext).ID(job.ID).Get(j); err != nil || !has {
				return actions_model.StatusUnknown
			}
			return j.Status
		}

		t.Run("a wait timer edit never releases a waiting job early", func(t *testing.T) {
			put(owner, "timer", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(60)}, http.StatusCreated)
			job := pushJob("    environment: timer\n")
			require.Equal(t, actions_model.DeploymentWaitingTimer, deployment(job).Status)
			put(owner, "timer", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(0)}, http.StatusOK)
			require.NoError(t, actions_service.EmitJobsIfReady(job.RunID))
			assert.Equal(t, actions_model.StatusBlocked, jobStatus(job), "a lowered timer doesn't shorten the wait")

			put(owner, "timer2", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(1)}, http.StatusCreated)
			raised := pushJob("    environment: timer2\n")
			put(owner, "timer2", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(600)}, http.StatusOK)
			// the first minute is over: the raised timer holds the job
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = ? WHERE job_id = ?", timeutil.TimeStampNow()-1, raised.ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.EmitJobsIfReady(raised.RunID))
			d := deployment(raised)
			assert.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
			assert.Greater(t, d.ReleaseAfterUnix, timeutil.TimeStampNow()+500*60)
			assert.Equal(t, actions_model.StatusBlocked, jobStatus(raised))
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("an approval by a reviewer removed before the release is revoked", func(t *testing.T) {
			put(owner, "swap", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(60), Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusCreated)
			job := pushJob("    environment: swap\n")
			require.Equal(t, actions_model.DeploymentWaitingReview, deployment(job).Status)
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs/%d/deployments/review", user2.Name, repo.Name, job.RunID),
				api.ReviewDeploymentsOption{JobIDs: []int64{job.ID}, State: "approved"}).AddTokenAuth(reviewer), http.StatusOK)
			d := deployment(job)
			require.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
			require.EqualValues(t, 4, d.ReviewedBy)
			// user4 is replaced by user10 (no access to the repository) and the timer is due
			put(owner, "swap", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(0), Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 10}}}, http.StatusOK)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = ? WHERE job_id = ?", timeutil.TimeStampNow()-1, job.ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.EmitJobsIfReady(job.RunID))
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job).Status)
			assert.Equal(t, actions_model.StatusBlocked, jobStatus(job))
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("deleting and recreating an environment doesn't release its waiting job", func(t *testing.T) {
			put(owner, "phoenix", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusCreated)
			job := pushJob("    environment: phoenix\n")
			require.Equal(t, actions_model.DeploymentWaitingReview, deployment(job).Status)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/PHOENIX").AddTokenAuth(owner), http.StatusNoContent)
			put(owner, "phoenix", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			require.NoError(t, actions_service.EmitJobsIfReady(job.RunID))
			assert.Equal(t, actions_model.StatusFailure, jobStatus(job))
			assert.Nil(t, runner.maybeFetchTask(t))
			// the old deployment keeps the old environment: the new one has none
			var out []*api.ActionDeployment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/actions/deployments?environment=phoenix", user2.Name, repo.Name)).AddTokenAuth(owner), http.StatusOK), &out)
			assert.Empty(t, out)
		})
	})
}
