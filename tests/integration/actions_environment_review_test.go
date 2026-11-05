// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
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
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	actions_service "forgejo.org/services/actions"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setEnvironmentReviewers makes the users and teams the reviewers of the environment as it is stored, keeping its rules.
func setEnvironmentReviewers(ctx context.Context, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) error {
	stored, err := actions_model.GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
	if err != nil {
		return err
	}
	_, err = actions_service.SaveEnvironment(ctx, stored, userIDs, teamIDs)
	return err
}

// Required reviewers, approvals, expiry, allowed workflows, referenced secrets, the OIDC environment claim and the
// refusal of a monolithic call that names an environment, each through the real Actions, API and cron code.
func TestActionsEnvironmentReviews(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		ownerToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		reviewerToken := getUserToken(t, user4.Name, auth_model.AccessTokenScopeWriteRepository)
		strangerToken := getUserToken(t, user5.Name, auth_model.AccessTokenScopeWriteRepository)
		adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteAdmin)

		apiRepo := createActionsTestRepo(t, ownerToken, "actions-env-reviews", true)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		ctx := audit_model.WithSystem(t.Context(), "test")
		// user4 reads the repository, user5 has no access to it
		MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", user2.Name, repo.Name, user4.Name),
			&api.AddCollaboratorOption{Permission: new("read")}).AddTokenAuth(ownerToken), http.StatusNoContent)

		labels := []string{"rv-a", "rv-b", "rv-c", "rv-d", "rv-e", "rv-f", "rv-g", "rv-h", "rv-i", "rv-j", "rv-k"}
		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "review-runner", labels)

		files := 0
		pushWorkflow := func(path, content string) *actions_model.ActionRun {
			fileResp := createWorkflowFile(t, ownerToken, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add "+path, content))
			var run *actions_model.ActionRun
			require.Eventually(t, func() bool {
				r := new(actions_model.ActionRun)
				has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repo.ID, fileResp.Commit.SHA).Get(r)
				if err == nil && has {
					run = r
				}
				return run != nil
			}, 10*time.Second, 100*time.Millisecond)
			return run
		}
		// pushJob pushes a workflow of one job on a label, with the given job lines and step, in a file of that name
		// (or env<N>.yml), and returns the run and its job
		pushJob := func(file, label, jobLines, step string) (*actions_model.ActionRun, *actions_model.ActionRunJob) {
			files++
			if file == "" {
				file = fmt.Sprintf("env%d.yml", files)
			}
			path := ".gitea/workflows/" + file
			run := pushWorkflow(path, fmt.Sprintf("name: rv%d\non:\n  push:\n    paths:\n      - '%s'\njobs:\n  deploy:\n    runs-on: %s\n%s    steps:\n      - run: %s\n", files, path, label, jobLines, step))
			jobs, err := actions_model.GetRunJobsByRunID(t.Context(), run.ID)
			require.NoError(t, err)
			require.Len(t, jobs, 1)
			return run, jobs[0]
		}
		deployment := func(job *actions_model.ActionRunJob, attempt int64) *actions_model.ActionDeployment {
			d, err := actions_model.GetDeployment(t.Context(), job.ID, attempt)
			require.NoError(t, err)
			require.NotNil(t, d)
			return d
		}
		reload := func(job *actions_model.ActionRunJob) *actions_model.ActionRunJob {
			return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: job.ID})
		}
		hasStatus := func(job *actions_model.ActionRunJob, status actions_model.Status) bool {
			j := new(actions_model.ActionRunJob)
			has, err := db.GetEngine(db.DefaultContext).ID(job.ID).Get(j)
			return err == nil && has && j.Status == status
		}
		newEnv := func(name string, reviewers []int64, mutate func(e *actions_model.ActionEnvironment)) *actions_model.ActionEnvironment {
			e := &actions_model.ActionEnvironment{RepoID: repo.ID, Name: name}
			if mutate != nil {
				mutate(e)
			}
			require.NoError(t, actions_model.CreateEnvironment(ctx, e, nil))
			require.NoError(t, setEnvironmentReviewers(ctx, e, reviewers, nil))
			return e
		}
		basePath := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs", user2.Name, repo.Name)
		review := func(token string, run *actions_model.ActionRun, opts api.ReviewDeploymentsOption, status int) []*api.ActionDeployment {
			t.Helper()
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/deployments/review", basePath, run.ID), opts).AddTokenAuth(token), status)
			if status != http.StatusOK {
				return nil
			}
			var out []*api.ActionDeployment
			DecodeJSON(t, resp, &out)
			return out
		}
		list := func(token string, run *actions_model.ActionRun, status int) []*api.ActionDeployment {
			t.Helper()
			resp := MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d/deployments", basePath, run.ID)).AddTokenAuth(token), status)
			if status != http.StatusOK {
				return nil
			}
			var out []*api.ActionDeployment
			DecodeJSON(t, resp, &out)
			return out
		}
		auditCount := func(since int64, action string) int {
			var entries []*audit_model.Entry
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, action).Find(&entries))
			return len(entries)
		}
		auditNow := func() int64 {
			var id int64
			_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
			require.NoError(t, err)
			return id
		}
		secretStep := "echo ${{ secrets.ENV_KEY }}"

		t.Run("an approval through the API releases the job, which then gets its environment's secret", func(t *testing.T) {
			e := newEnv("prod", []int64{user4.ID}, nil)
			_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "ENV_KEY", "prod-key")
			require.NoError(t, err)
			_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "UNUSED", "never-asked-for")
			require.NoError(t, err)
			run, job := pushJob("", "rv-a", "    environment: prod\n", secretStep)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)
			assert.Equal(t, actions_model.StatusBlocked, reload(job).Status)
			assert.Nil(t, runner.maybeFetchTask(t), "never given to a runner while it waits")

			// who sees what: a reader sees the deployment, and whether they may review it
			ds := list(reviewerToken, run, http.StatusOK)
			require.Len(t, ds, 1)
			assert.Equal(t, "waiting_review", ds[0].Status)
			assert.Equal(t, "prod", ds[0].Environment)
			assert.Equal(t, "deploy", ds[0].JobName)
			assert.Equal(t, job.ID, ds[0].JobID)
			assert.True(t, ds[0].Reviewers.CanReview)
			assert.Equal(t, 1, ds[0].Reviewers.Users)
			assert.Zero(t, ds[0].Reviewers.Teams)
			assert.False(t, list(ownerToken, run, http.StatusOK)[0].Reviewers.CanReview, "the owner is not a listed reviewer")
			list(strangerToken, run, http.StatusNotFound)

			// nobody else may: not the owner, not a site administrator, not a reader who isn't listed, not a stranger
			since := auditNow()
			for _, token := range []string{ownerToken, adminToken} {
				review(token, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)
			}
			review(strangerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusNotFound)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)
			assert.Zero(t, auditCount(since, "repo.actions_deployment.approved"))

			out := review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved", Comment: "ship it"}, http.StatusOK)
			require.Len(t, out, 1)
			assert.Equal(t, "released", out[0].Status)
			assert.Equal(t, "ship it", out[0].ReviewComment)
			require.NotNil(t, out[0].ReviewedBy)
			assert.Equal(t, user4.Name, out[0].ReviewedBy.UserName)
			assert.NotNil(t, out[0].ReviewedAt)
			assert.Equal(t, 1, auditCount(since, "repo.actions_deployment.approved"))

			task := runner.fetchTask(t)
			assert.Equal(t, "prod-key", task.Secrets["ENV_KEY"])
			assert.NotContains(t, task.Secrets, "UNUSED", "an environment secret the job doesn't name is not given")
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			// the decision stands: a second review finds it no longer waiting
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusUnprocessableEntity)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "rejected", Comment: "too late"}, http.StatusUnprocessableEntity)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved", JobIDs: []int64{job.ID}}, http.StatusUnprocessableEntity)
			assert.Equal(t, "released", list(ownerToken, run, http.StatusOK)[0].Status)
		})

		t.Run("a rejection needs a comment, fails the job and runs nothing", func(t *testing.T) {
			e := newEnv("rejecting", []int64{user4.ID}, nil)
			_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "ENV_KEY", "never")
			require.NoError(t, err)
			run, job := pushJob("", "rv-b", "    environment: rejecting\n", secretStep)
			since := auditNow()
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "rejected"}, http.StatusUnprocessableEntity)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "rejected", Comment: "  "}, http.StatusUnprocessableEntity)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)
			out := review(reviewerToken, run, api.ReviewDeploymentsOption{State: "rejected", Comment: "<b>not</b> now"}, http.StatusOK)
			require.Len(t, out, 1)
			assert.Equal(t, "rejected", out[0].Status)
			assert.Equal(t, "<b>not</b> now", out[0].ReviewComment, "plain text, as written")
			require.Eventually(t, func() bool { return hasStatus(job, actions_model.StatusFailure) }, 10*time.Second, 100*time.Millisecond)
			assert.NotZero(t, reload(job).Stopped)
			assert.Nil(t, runner.maybeFetchTask(t))
			assert.Equal(t, 1, auditCount(since, "repo.actions_deployment.rejected"))
			var entry audit_model.Entry
			has, err := db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "repo.actions_deployment.rejected").Get(&entry)
			require.NoError(t, err)
			require.True(t, has)
			assert.NotContains(t, entry.Data, "not</b>", "the comment is not in the audit entry")
		})

		t.Run("bad requests", func(t *testing.T) {
			newEnv("bad-requests", []int64{user4.ID}, nil)
			run, job := pushJob("", "rv-c", "    environment: bad-requests\n", "echo")
			for name, opts := range map[string]api.ReviewDeploymentsOption{
				"no state":          {},
				"another state":     {State: "maybe"},
				"unknown job":       {State: "approved", JobIDs: []int64{job.ID + 100000}},
				"too many jobs":     {State: "approved", JobIDs: make([]int64, 101)},
				"comment too long":  {State: "approved", Comment: strings.Repeat("a", 2001)},
				"control character": {State: "approved", Comment: "a\x1b[31mb"},
				"nul":               {State: "approved", Comment: "a\x00b"},
			} {
				review(reviewerToken, run, opts, http.StatusUnprocessableEntity)
				assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status, name)
			}
			// a run of another repository is not found through this one
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET repo_id = 99999 WHERE id = ?", run.ID)
			require.NoError(t, err)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusNotFound)
			list(reviewerToken, run, http.StatusNotFound)
			_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run SET repo_id = ? WHERE id = ?", repo.ID, run.ID)
			require.NoError(t, err)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			require.Eventually(t, func() bool { return hasStatus(job, actions_model.StatusWaiting) }, 10*time.Second, 100*time.Millisecond)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("self review is blocked when the environment says so, and allowed otherwise", func(t *testing.T) {
			// user2 pushes, so user2 triggers the runs
			newEnv("no-self", []int64{user2.ID, user4.ID}, func(e *actions_model.ActionEnvironment) { e.PreventSelfReview = true })
			newEnv("self-ok", []int64{user2.ID, user4.ID}, nil)
			run, job := pushJob("", "rv-d", "    environment: no-self\n", "echo")
			review(ownerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			run, job = pushJob("", "rv-d", "    environment: self-ok\n", "echo")
			review(ownerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			assert.Equal(t, int64(2), deployment(job, 1).ReviewedBy)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("the Actions job token and the identity of an owned token never review", func(t *testing.T) {
			newEnv("tokens", []int64{user4.ID, user2.ID}, nil)
			run, job := pushJob("", "rv-e", "    environment: tokens\n", "echo")
			_, _ = pushJob("", "rv-e", "", "echo") // a job without an environment: the runner gets this one
			plain := runner.fetchTask(t)
			jobToken := plain.Context.Fields["token"].GetStringValue()
			require.NotEmpty(t, jobToken)
			review(jobToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)

			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/tokens", user2.Name, repo.Name),
				api.CreateOwnedAccessTokenOption{Name: "env-review-token", Scopes: []string{"write:repository"}, Permission: "write"}).AddTokenAuth(ownerToken), http.StatusCreated)
			var owned api.AccessToken
			DecodeJSON(t, resp, &owned)
			review(owned.Token, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)

			runner.execTask(t, plain, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("a review under sudo is refused", func(t *testing.T) {
			newEnv("sudo-rv", []int64{user4.ID}, nil)
			run, job := pushJob("", "rv-f", "    environment: sudo-rv\n", "echo")
			since := auditNow()
			review(adminToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/deployments/review?sudo=%s", basePath, run.ID, user4.Name),
				api.ReviewDeploymentsOption{State: "approved"}).AddTokenAuth(adminToken), http.StatusForbidden)
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/deployments/review", basePath, run.ID),
				api.ReviewDeploymentsOption{State: "approved"}).AddTokenAuth(adminToken).SetHeader("Sudo", user4.Name), http.StatusForbidden)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)
			assert.Zero(t, auditCount(since, "repo.actions_deployment.approved"))
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("who reran an attempt can't approve it under the self-review rule", func(t *testing.T) {
			newEnv("rerun-self", []int64{user2.ID, user4.ID}, func(e *actions_model.ActionEnvironment) { e.PreventSelfReview = true })
			run, job := pushJob("", "rv-f", "    environment: rerun-self\n", "echo")
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			run = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: run.ID})
			_, err := actions_service.RerunAllJobs(ctx, user4, run)
			require.NoError(t, err)
			job = reload(job)
			assert.Equal(t, user4.ID, job.AttemptTriggerUserID)
			assert.Equal(t, user4.ID, deployment(job, 2).TriggerUserID)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)
			review(ownerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden) // the run's own trigger user
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 2).Status)
			assert.False(t, list(reviewerToken, run, http.StatusOK)[1].Reviewers.CanReview)
		})

		t.Run("removing the reviewers releases a waiting job at once", func(t *testing.T) {
			e := newEnv("breakglass-rv", []int64{user4.ID}, nil)
			_, job := pushJob("", "rv-g", "    environment: breakglass-rv\n", "echo")
			require.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)
			assert.Nil(t, runner.maybeFetchTask(t))
			require.NoError(t, setEnvironmentReviewers(ctx, e, nil, nil))
			require.Eventually(t, func() bool { return hasStatus(job, actions_model.StatusWaiting) }, 10*time.Second, 100*time.Millisecond)
			assert.Equal(t, actions_model.DeploymentReleased, deployment(job, 1).Status)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("a rerun needs a new approval", func(t *testing.T) {
			newEnv("rerun-rv", []int64{user4.ID}, nil)
			run, job := pushJob("", "rv-f", "    environment: rerun-rv\n", "echo")
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			run = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: run.ID})
			_, err := actions_service.RerunAllJobs(ctx, nil, run)
			require.NoError(t, err)
			job = reload(job)
			require.Equal(t, int64(2), job.Attempt)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 2).Status)
			assert.Zero(t, deployment(job, 2).ReviewedBy)
			assert.Equal(t, actions_model.DeploymentReleased, deployment(job, 1).Status)
			assert.Equal(t, actions_model.StatusBlocked, job.Status)
			assert.Nil(t, runner.maybeFetchTask(t), "the approval of attempt 1 doesn't carry")
			ds := list(reviewerToken, run, http.StatusOK)
			require.Len(t, ds, 2)
			assert.Equal(t, []string{"released", "waiting_review"}, []string{ds[0].Status, ds[1].Status})
			assert.Equal(t, []int64{1, 2}, []int64{ds[0].Attempt, ds[1].Attempt})

			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("the approval and the wait timer are both needed", func(t *testing.T) {
			newEnv("timer-rv", []int64{user4.ID}, func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			// the timer is due, nobody approved: held
			unapprovedRun, unapproved := pushJob("", "rv-g", "    environment: timer-rv\n", "echo")
			d := deployment(unapproved, 1)
			assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
			assert.NotZero(t, d.ReleaseAfterUnix)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = 1 WHERE id = ?", d.ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(unapproved, 1).Status)
			assert.Equal(t, actions_model.StatusBlocked, reload(unapproved).Status)
			assert.Nil(t, runner.maybeFetchTask(t))

			// approved, the timer is not due: held
			approvedRun, approved := pushJob("", "rv-g", "    environment: timer-rv\n", "echo")
			out := review(reviewerToken, approvedRun, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			assert.Equal(t, "waiting_timer", out[0].Status, "approved, waiting for the timer")
			assert.Equal(t, actions_model.StatusBlocked, reload(approved).Status)
			assert.Nil(t, runner.maybeFetchTask(t))
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			assert.Equal(t, actions_model.StatusBlocked, reload(approved).Status, "not due")

			// the timer ends: the approved job is released, the other one still waits
			_, err = db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = 1 WHERE id = ?", deployment(approved, 1).ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			assert.Equal(t, actions_model.DeploymentReleased, deployment(approved, 1).Status)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(unapproved, 1).Status)

			// approval after the timer is due releases at once
			review(reviewerToken, unapprovedRun, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			assert.Equal(t, actions_model.DeploymentReleased, deployment(unapproved, 1).Status)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("expiry fails a deployment nobody reviewed, even in the middle of its timer", func(t *testing.T) {
			newEnv("expiring", []int64{user4.ID}, func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = actions_model.MaxWaitTimerMinutes })
			run, job := pushJob("", "rv-h", "    environment: expiring\n", "echo")
			fresh, freshJob := pushJob("", "rv-h", "    environment: expiring\n", "echo")

			// the cron task exists and leaves a young deployment alone
			MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/cron/expire_deployment_reviews").AddTokenAuth(adminToken), http.StatusNoContent)
			require.NoError(t, actions_service.ExpireDeploymentReviews(ctx))
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(job, 1).Status)

			since := auditNow()
			// the older deployment is past the timeout, the other one is not
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET created = ? WHERE id = ?", time.Now().Add(-setting.Actions.DeploymentApprovalTimeout-time.Hour).Unix(), deployment(job, 1).ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.ExpireDeploymentReviews(ctx))
			assert.Equal(t, actions_model.DeploymentExpired, deployment(job, 1).Status)
			require.Eventually(t, func() bool { return hasStatus(job, actions_model.StatusFailure) }, 10*time.Second, 100*time.Millisecond)
			assert.NotZero(t, reload(job).Stopped)
			assert.Equal(t, 1, auditCount(since, "repo.actions_deployment.expired"))
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(freshJob, 1).Status)
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusUnprocessableEntity)
			assert.Equal(t, "expired", list(reviewerToken, run, http.StatusOK)[0].Status)

			// with the clock moved past the timeout, the other one expires too
			defer test.MockVariableValue(&setting.Actions.DeploymentApprovalTimeout, time.Hour)()
			timeutil.MockSet(time.Now().Add(2 * time.Hour))
			defer timeutil.MockUnset()
			require.NoError(t, actions_service.ExpireDeploymentReviews(ctx))
			assert.Equal(t, actions_model.DeploymentExpired, deployment(freshJob, 1).Status)
			require.Eventually(t, func() bool { return hasStatus(freshJob, actions_model.StatusFailure) }, 10*time.Second, 100*time.Millisecond)
			review(reviewerToken, fresh, api.ReviewDeploymentsOption{State: "rejected", Comment: "late"}, http.StatusUnprocessableEntity)
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("allowed workflows", func(t *testing.T) {
			e := newEnv("wf-locked", nil, func(e *actions_model.ActionEnvironment) { e.AllowedWorkflows = []string{"deploy-*.yml"} })
			_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "ENV_KEY", "locked-key")
			require.NoError(t, err)
			since := auditNow()
			_, refused := pushJob("", "rv-i", "    environment: wf-locked\n", secretStep)
			require.Eventually(t, func() bool { return hasStatus(refused, actions_model.StatusFailure) }, 10*time.Second, 100*time.Millisecond)
			d := deployment(refused, 1)
			assert.Equal(t, actions_model.DeploymentRefused, d.Status)
			assert.Equal(t, actions_model.DeploymentReasonWorkflowNotAllowed, d.Reason)
			assert.Nil(t, runner.maybeFetchTask(t), "no task, so no secret")
			assert.Equal(t, 1, auditCount(since, "repo.actions_deployment.refused"))

			_, allowed := pushJob("deploy-prod.yml", "rv-i", "    environment: wf-locked\n", secretStep)
			task := runner.fetchTask(t)
			assert.Equal(t, "locked-key", task.Secrets["ENV_KEY"])
			assert.Equal(t, actions_model.DeploymentReleased, deployment(allowed, 1).Status)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("only the secrets a job names are given", func(t *testing.T) {
			e := newEnv("named-secrets", nil, nil)
			for k, v := range map[string]string{"ENV_KEY": "env-key", "OTHER_KEY": "other-key"} {
				_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, k, v)
				require.NoError(t, err)
			}
			for name, tc := range map[string]struct {
				step string
				want []string
			}{
				"toJSON(secrets)":    {"echo '${{ toJSON(secrets) }}' ${{ secrets.ENV_KEY }}", nil},
				"a computed name":    {"echo ${{ secrets[format('{0}_KEY', 'ENV')] }}", nil},
				"a literal":          {"echo ${{ secrets.ENV_KEY }}", []string{"ENV_KEY"}},
				"an indexed literal": {"echo ${{ secrets['OTHER_KEY'] }}", []string{"OTHER_KEY"}},
				"both":               {"echo ${{ secrets.ENV_KEY }} ${{ secrets.OTHER_KEY }}", []string{"ENV_KEY", "OTHER_KEY"}},
			} {
				_, job := pushJob("", "rv-j", "    environment: named-secrets\n", tc.step)
				task := runner.fetchTask(t)
				for _, k := range []string{"ENV_KEY", "OTHER_KEY"} {
					if slices.Contains(tc.want, k) {
						assert.Contains(t, task.Secrets, k, name)
					} else {
						assert.NotContains(t, task.Secrets, k, name)
					}
				}
				assert.Equal(t, actions_model.DeploymentReleased, deployment(job, 1).Status, name)
				runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			}
		})

		t.Run("the ID token of a released job names its environment", func(t *testing.T) {
			newEnv("oidc-env", []int64{user4.ID}, nil)
			claimsOf := func(task *runnerv1.Task) *actions_service.AuthorizationTokenClaims {
				claims := &actions_service.AuthorizationTokenClaims{}
				_, _, err := jwt.NewParser().ParseUnverified(task.Context.Fields["forgejo_runtime_token"].GetStringValue(), claims)
				require.NoError(t, err)
				return claims
			}
			prefix := fmt.Sprintf("repo:%s-%d/%s-%d:", user2.Name, user2.ID, repo.Name, repo.ID)

			run, job := pushJob("", "rv-k", "    enable-openid-connect: true\n    environment: oidc-env\n", "echo")
			assert.Nil(t, runner.maybeFetchTask(t), "no token before the release")
			review(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			task := runner.fetchTask(t)
			claims := claimsOf(task)
			assert.Equal(t, prefix+"environment:oidc-env", claims.OIDCSub)
			assert.Contains(t, claims.OIDCExtra, `"environment":"oidc-env"`)
			assert.Equal(t, actions_model.DeploymentReleased, deployment(job, 1).Status)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			// a job without an environment keeps the subject of its ref
			pushJob("", "rv-k", "    enable-openid-connect: true\n", "echo")
			task = runner.fetchTask(t)
			claims = claimsOf(task)
			assert.Equal(t, prefix+"ref:refs/heads/"+repo.DefaultBranch, claims.OIDCSub)
			assert.NotContains(t, claims.OIDCExtra, "environment")
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("a call that is not expanded may not name an environment", func(t *testing.T) {
			createWorkflowFile(t, ownerToken, user2.Name, repo.Name, ".gitea/workflows/env-mono-called.yml", getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add called",
				"name: env-mono-called\non:\n  workflow_call:\njobs:\n  deploy:\n    runs-on: rv-a\n    environment: production\n    steps:\n      - run: echo\n"))
			run := pushWorkflow(".gitea/workflows/env-mono-caller.yml", `name: env-mono-caller
on:
  push:
    paths:
      - '.gitea/workflows/env-mono-caller.yml'
jobs:
  call:
    runs-on: rv-a
    uses: ./.gitea/workflows/env-mono-called.yml
`)
			require.Eventually(t, func() bool {
				r := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: run.ID})
				return r.Status == actions_model.StatusFailure
			}, 10*time.Second, 100*time.Millisecond)
			run = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: run.ID})
			assert.Equal(t, actions_model.ErrorCodeJobParsingError, run.PreExecutionErrorCode)
			assert.Contains(t, fmt.Sprint(run.PreExecutionErrorDetails), "names an environment")
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("reviewers go with their user and their environment", func(t *testing.T) {
			var cleanupEnvID int64
			count := func() int64 {
				n, err := db.GetEngine(t.Context()).Where("environment_id = ?", cleanupEnvID).Count(new(actions_model.ActionEnvironmentReviewer))
				require.NoError(t, err)
				return n
			}
			e := newEnv("cleanup-rv", []int64{user5.ID}, nil)
			cleanupEnvID = e.ID
			assert.EqualValues(t, 1, count())
			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/"+user5.Name+"?purge=true").AddTokenAuth(adminToken), http.StatusNoContent)
			assert.EqualValues(t, 0, count())
			require.NoError(t, setEnvironmentReviewers(ctx, e, []int64{user4.ID}, nil))
			require.NoError(t, actions_service.DeleteEnvironment(ctx, e))
			assert.EqualValues(t, 0, count())
		})

		t.Run("a user who reviews in a repository in the trash can still be deleted, and the removal is recorded", func(t *testing.T) {
			e := newEnv("trash-rv", []int64{user4.ID}, nil)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = ? WHERE id = ?", timeutil.TimeStampNow(), repo.ID)
			require.NoError(t, err)
			since := auditNow()
			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/"+user4.Name+"?purge=true").AddTokenAuth(adminToken), http.StatusNoContent)
			n, err := db.GetEngine(t.Context()).Where("environment_id = ?", e.ID).Count(new(actions_model.ActionEnvironmentReviewer))
			require.NoError(t, err)
			assert.EqualValues(t, 0, n)
			assert.Positive(t, auditCount(since, "repo.actions_env.updated"))
		})
	})
}
