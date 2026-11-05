// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	actions_service "forgejo.org/services/actions"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Attacks on required reviewers: each subtest tries to get a gated job released, or its environment secrets, without a
// valid approval by an eligible, distinct human reviewer.
func TestActionsEnvironmentReviewAttacks(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}) // site admin
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}) // repo owner
		user3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}) // organization
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}) // listed reviewer (read collaborator)
		user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}) // stranger, no access

		ownerToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		reviewerToken := getUserToken(t, user4.Name, auth_model.AccessTokenScopeWriteRepository)
		strangerToken := getUserToken(t, user5.Name, auth_model.AccessTokenScopeWriteRepository)
		adminToken := getUserToken(t, user1.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteAdmin)

		apiRepo := createActionsTestRepo(t, ownerToken, "env-attacks", true)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		sctx := audit_model.WithSystem(t.Context(), "test")

		readPerm := "read"
		collab := func(method string, status int) {
			req := NewRequestWithJSON(t, method, fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", user2.Name, repo.Name, user4.Name),
				&api.AddCollaboratorOption{Permission: &readPerm}).AddTokenAuth(ownerToken)
			MakeRequest(t, req, status)
		}
		collab("PUT", http.StatusNoContent)

		labels := []string{"rv-a", "rv-b", "rv-c", "rv-d", "rv-e", "rv-f", "rv-g", "rv-h"}
		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "env-attacks-runner", labels)

		files := 0
		pushWorkflow := func(path, content string) *actions_model.ActionRun {
			t.Helper()
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
		// pushOneJob pushes a one-job workflow on label, naming environment env, with step.
		pushOneJob := func(label, env, step string) (*actions_model.ActionRun, *actions_model.ActionRunJob) {
			t.Helper()
			files++
			path := fmt.Sprintf(".gitea/workflows/rt%d.yml", files)
			content := fmt.Sprintf("name: rt%d\non:\n  push:\n    paths:\n      - '%s'\njobs:\n  deploy:\n    runs-on: %s\n    environment: %s\n    steps:\n      - run: %s\n", files, path, label, env, step)
			run := pushWorkflow(path, content)
			var jobs []*actions_model.ActionRunJob
			require.Eventually(t, func() bool {
				var err error
				jobs, err = actions_model.GetRunJobsByRunID(t.Context(), run.ID)
				return err == nil && len(jobs) == 1
			}, 10*time.Second, 100*time.Millisecond)
			return run, jobs[0]
		}
		getDeployment := func(job *actions_model.ActionRunJob, attempt int64) *actions_model.ActionDeployment {
			t.Helper()
			var d *actions_model.ActionDeployment
			require.Eventually(t, func() bool {
				var err error
				d, err = actions_model.GetDeployment(t.Context(), job.ID, attempt)
				return err == nil && d != nil
			}, 10*time.Second, 100*time.Millisecond)
			return d
		}
		depStatus := func(job *actions_model.ActionRunJob, attempt int64) actions_model.DeploymentStatus {
			d, err := actions_model.GetDeployment(t.Context(), job.ID, attempt)
			require.NoError(t, err)
			require.NotNil(t, d)
			return d.Status
		}
		jobStatus := func(job *actions_model.ActionRunJob) actions_model.Status {
			return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: job.ID}).Status
		}
		freshRun := func(run *actions_model.ActionRun) *actions_model.ActionRun {
			r, err := actions_model.GetRunByID(t.Context(), run.ID)
			require.NoError(t, err)
			return r
		}
		newEnv := func(name string, reviewers []int64, mutate func(e *actions_model.ActionEnvironment)) *actions_model.ActionEnvironment {
			e := &actions_model.ActionEnvironment{RepoID: repo.ID, Name: name}
			if mutate != nil {
				mutate(e)
			}
			require.NoError(t, actions_model.CreateEnvironment(sctx, e, nil))
			require.NoError(t, setEnvironmentReviewers(sctx, e, reviewers, nil))
			return e
		}
		base := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs", user2.Name, repo.Name)
		reviewHTTP := func(token string, run *actions_model.ActionRun, opts api.ReviewDeploymentsOption, status int) {
			t.Helper()
			if opts.JobIDs == nil { // the API needs the jobs named: by default every job of the run
				jobs, err := actions_model.GetRunJobsByRunID(t.Context(), run.ID)
				require.NoError(t, err)
				opts.JobIDs = []int64{}
				for _, j := range jobs {
					opts.JobIDs = append(opts.JobIDs, j.ID)
				}
			}
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/deployments/review", base, run.ID), opts).AddTokenAuth(token), status)
		}

		// ---- A. Identity guards, exercised at the service layer against one live waiting deployment. ----
		t.Run("A identity guards cannot approve", func(t *testing.T) {
			e := newEnv("idguard", []int64{user4.ID}, nil)
			run, job := pushOneJob("rv-a", "idguard", "echo hi")
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job, 1).Status)

			// craft doers
			deactivated := *user4
			deactivated.IsActive = false
			prohibited := *user4
			prohibited.ProhibitLogin = true
			ownedTok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, repo.ID, 0, perm_model.AccessModeAdmin, auth_model.AccessTokenScopeWriteRepository)
			bot := user_model.NewAccessTokenBot(ownedTok)

			cases := []struct {
				name string
				doer *user_model.User
			}{
				{"the Actions user (GITEA_TOKEN)", user_model.NewActionsUser()},
				{"an owned access token identity", bot},
				{"a deactivated listed reviewer", &deactivated},
				{"a prohibited-login listed reviewer", &prohibited},
				{"an organization as doer", user3},
				{"the repo owner (not listed)", user2},
				{"a site administrator (not listed)", user1},
				{"a stranger", user5},
			}
			for _, c := range cases {
				_, err := actions_service.ReviewDeployments(sctx, c.doer, freshRun(run), nil, true, "approve")
				require.ErrorIs(t, err, actions_service.ErrReviewForbidden, c.name)
				assert.Equal(t, actions_model.DeploymentWaitingReview, depStatus(job, 1), c.name)
			}

			// under sudo nobody reviews: even the listed reviewer's own call is refused when an admin impersonates
			actor := &audit_model.Actor{Type: audit_model.ActorUser, ID: user1.ID, Name: user1.Name}
			actor.SetSudo(user4.ID, user4.Name)
			sudoCtx := audit_model.WithActor(audit_model.WithSystem(t.Context(), "test"), actor)
			_, err := actions_service.ReviewDeployments(sudoCtx, user4, freshRun(run), nil, true, "sudo approve")
			require.ErrorIs(t, err, actions_service.ErrReviewForbidden, "sudo review refused")
			assert.Equal(t, actions_model.DeploymentWaitingReview, depStatus(job, 1))

			// a reviewer who lost Actions read (removed from the repo) can no longer approve
			collab("DELETE", http.StatusNoContent)
			freshUser4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user4.ID})
			_, err = actions_service.ReviewDeployments(sctx, freshUser4, freshRun(run), nil, true, "no access")
			require.ErrorIs(t, err, actions_service.ErrReviewForbidden, "lost Actions read")
			assert.Equal(t, actions_model.DeploymentWaitingReview, depStatus(job, 1))
			collab("PUT", http.StatusNoContent)

			// positive control: the real listed reviewer releases it
			out, err := actions_service.ReviewDeployments(sctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user4.ID}), freshRun(run), nil, true, "ship")
			require.NoError(t, err)
			require.Len(t, out, 1)
			assert.Equal(t, actions_model.DeploymentReleased, getDeployment(job, 1).Status)
			_ = e
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		// ---- B. The decision stands: twice / after reject / after expiry. ----
		t.Run("B second review, review after reject, review after expiry", func(t *testing.T) {
			newEnv("standsg", []int64{user4.ID}, nil)
			run, job := pushOneJob("rv-b", "standsg", "echo")
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job, 1).Status)
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "rejected", Comment: "no"}, http.StatusOK)
			// after a reject, a later approve or reject finds it not waiting
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusUnprocessableEntity)
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "rejected", Comment: "again"}, http.StatusUnprocessableEntity)
			require.Eventually(t, func() bool { return jobStatus(job) == actions_model.StatusFailure }, 10*time.Second, 100*time.Millisecond)
			assert.Nil(t, runner.maybeFetchTask(t))

			// approve after the timeout, before the expiry task ran, is refused; then the expiry fails the job
			newEnv("expireg", []int64{user4.ID}, nil)
			run2, job2 := pushOneJob("rv-c", "expireg", "echo")
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job2, 1).Status)
			future := time.Now().Add(setting.Actions.DeploymentApprovalTimeout + time.Hour)
			timeutil.MockSet(future)
			defer timeutil.MockUnset()
			_, err := actions_service.ReviewDeployments(sctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user4.ID}), freshRun(run2), nil, true, "too late")
			require.ErrorIs(t, err, actions_service.ErrReviewNotWaiting, "approve after timeout refused")
			require.NoError(t, actions_service.ExpireDeploymentReviews(sctx))
			assert.Equal(t, actions_model.DeploymentExpired, getDeployment(job2, 1).Status)
			require.Eventually(t, func() bool { return jobStatus(job2) == actions_model.StatusFailure }, 10*time.Second, 100*time.Millisecond)
			assert.Nil(t, runner.maybeFetchTask(t))
			timeutil.MockUnset()
		})

		// ---- C. Approving one job does not release a sibling job, and jobIDs scopes the action. ----
		t.Run("C sibling job isolation", func(t *testing.T) {
			newEnv("siba", []int64{user4.ID}, nil)
			newEnv("sibb", []int64{user4.ID}, nil)
			files++
			path := fmt.Sprintf(".gitea/workflows/rt%d.yml", files)
			content := fmt.Sprintf("name: sib%d\non:\n  push:\n    paths:\n      - '%s'\njobs:\n  ja:\n    runs-on: rv-d\n    environment: siba\n    steps:\n      - run: echo\n  jb:\n    runs-on: rv-e\n    environment: sibb\n    steps:\n      - run: echo\n", files, path)
			run := pushWorkflow(path, content)
			var jobs []*actions_model.ActionRunJob
			require.Eventually(t, func() bool {
				var err error
				jobs, err = actions_model.GetRunJobsByRunID(t.Context(), run.ID)
				return err == nil && len(jobs) == 2
			}, 10*time.Second, 100*time.Millisecond)
			var ja, jb *actions_model.ActionRunJob
			for _, j := range jobs {
				if j.Name == "ja" {
					ja = j
				} else {
					jb = j
				}
			}
			require.NotNil(t, ja)
			require.NotNil(t, jb)
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(ja, 1).Status)
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(jb, 1).Status)

			// approve only ja: jb must stay waiting and never be given to a runner
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved", JobIDs: []int64{ja.ID}}, http.StatusOK)
			assert.Equal(t, actions_model.DeploymentReleased, getDeployment(ja, 1).Status)
			assert.Equal(t, actions_model.DeploymentWaitingReview, depStatus(jb, 1), "sibling job not released")
			// drain ja, confirm jb is still not fetchable
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			assert.Nil(t, runner.maybeFetchTask(t), "the unapproved sibling is never picked")
			assert.Equal(t, actions_model.DeploymentWaitingReview, depStatus(jb, 1))
		})

		// ---- D. Environment secrets stay out of a job that reads secrets dynamically, even after approval. ----
		t.Run("D dynamic secret access gets no environment secrets", func(t *testing.T) {
			e := newEnv("dyn", []int64{user4.ID}, nil)
			_, err := secret_model.InsertEncryptedEnvironmentSecret(sctx, repo.ID, e.ID, "ENV_KEY", "top-secret")
			require.NoError(t, err)
			run, job := pushOneJob("rv-f", "dyn", "echo ${{ toJSON(secrets) }}")
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job, 1).Status)
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			assert.Equal(t, actions_model.DeploymentReleased, getDeployment(job, 1).Status)
			task := runner.fetchTask(t)
			assert.NotContains(t, task.Secrets, "ENV_KEY", "toJSON(secrets) must not receive environment secrets")
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		// ---- E. A rerun needs a new approval; the rerunner can't self-review it. ----
		t.Run("E rerun needs a new approval and the rerunner cannot self-review", func(t *testing.T) {
			newEnv("rerung", []int64{user4.ID}, func(e *actions_model.ActionEnvironment) { e.PreventSelfReview = true })
			run, job := pushOneJob("rv-g", "rerung", "echo")
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job, 1).Status)
			// attempt 1: user4 approves (user2 triggered the run)
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			require.Eventually(t, func() bool { return freshRun(run).Status.IsDone() }, 10*time.Second, 100*time.Millisecond)

			// user4 reruns: a new attempt, a new deployment that waits again (no carry-over of the approval)
			_, err := actions_service.RerunAllJobs(sctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user4.ID}), freshRun(run))
			require.NoError(t, err)
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job, 2).Status, "the rerun is gated afresh")
			assert.Nil(t, runner.maybeFetchTask(t), "the rerun is not released by the earlier approval")

			// the rerunner (attempt trigger) and the run trigger cannot approve their own deployment
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden) // user4 reran it
			reviewHTTP(ownerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusForbidden)    // user2 triggered the run
			assert.Equal(t, actions_model.DeploymentWaitingReview, depStatus(job, 2))
		})

		// ---- F. IDOR: a deployment of another repository's run is never reachable through this repo. ----
		t.Run("F IDOR another repo's run and job ids", func(t *testing.T) {
			newEnv("idor", []int64{user4.ID}, nil)
			run, job := pushOneJob("rv-h", "idor", "echo")
			require.Equal(t, actions_model.DeploymentWaitingReview, getDeployment(job, 1).Status)
			// move the run under a non-existent repo id: the review and list endpoints answer not found
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET repo_id = 88888 WHERE id = ?", run.ID)
			require.NoError(t, err)
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d/deployments", base, run.ID)).AddTokenAuth(reviewerToken), http.StatusNotFound)
			_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run SET repo_id = ? WHERE id = ?", repo.ID, run.ID)
			require.NoError(t, err)
			// a stranger and a public-only-equivalent (no access) get not found at the private repo too
			reviewHTTP(strangerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d/deployments", base, run.ID)).AddTokenAuth(strangerToken), http.StatusNotFound)
			// clean up: approve so the run can finish
			reviewHTTP(reviewerToken, run, api.ReviewDeploymentsOption{State: "approved"}, http.StatusOK)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		_ = adminToken
	})
}
