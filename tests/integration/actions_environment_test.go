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
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	actions_service "forgejo.org/services/actions"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsEnvironments(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		session := loginUser(t, user2.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		apiRepo := createActionsTestRepo(t, token, "actions-environments", false)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		ctx := audit_model.WithSystem(t.Context(), "test")

		labels := []string{"env-a", "env-b", "env-c", "env-d", "env-e", "env-f", "env-g", "env-h", "env-i", "env-j"}
		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "env-runner", labels)

		files := 0
		// push creates a workflow file with one job on label and returns the jobs of the run it starts
		push := func(label, environment string) []*actions_model.ActionRunJob {
			files++
			path := fmt.Sprintf(".gitea/workflows/env%d.yml", files)
			content := fmt.Sprintf(`name: env%d
on:
  push:
    paths:
      - '%s'
jobs:
  deploy:
    runs-on: %s
    %s
    steps:
      - run: echo deploy
`, files, path, label, environment)
			fileResp := createWorkflowFile(t, token, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add "+path, content))
			var run *actions_model.ActionRun
			require.Eventually(t, func() bool {
				r := new(actions_model.ActionRun)
				has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repo.ID, fileResp.Commit.SHA).Get(r)
				if err == nil && has {
					run = r
				}
				return run != nil
			}, 10*time.Second, 100*time.Millisecond)
			jobs, err := actions_model.GetRunJobsByRunID(t.Context(), run.ID)
			require.NoError(t, err)
			return jobs
		}
		reload := func(job *actions_model.ActionRunJob) *actions_model.ActionRunJob {
			return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: job.ID})
		}
		deployment := func(job *actions_model.ActionRunJob, attempt int64) *actions_model.ActionDeployment {
			d, err := actions_model.GetDeployment(t.Context(), job.ID, attempt)
			require.NoError(t, err)
			return d
		}
		newEnv := func(name string, mutate func(e *actions_model.ActionEnvironment)) *actions_model.ActionEnvironment {
			e := &actions_model.ActionEnvironment{RepoID: repo.ID, Name: name}
			if mutate != nil {
				mutate(e)
			}
			require.NoError(t, actions_model.CreateEnvironment(ctx, e))
			return e
		}

		t.Run("released job gets the secrets and variables of its environment", func(t *testing.T) {
			_, err := secret_model.InsertEncryptedSecret(ctx, 0, 0, repo.ID, "SHARED", "from-repo")
			require.NoError(t, err)
			_, err = actions_model.InsertVariable(ctx, 0, 0, repo.ID, "SHARED_VAR", "from-repo")
			require.NoError(t, err)
			e := newEnv("Staging", nil)
			_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "SHARED", "from-env")
			require.NoError(t, err)
			_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "ONLY_ENV", "only-env")
			require.NoError(t, err)
			_, err = actions_model.InsertEnvironmentVariable(ctx, repo.ID, e.ID, "SHARED_VAR", "from-env")
			require.NoError(t, err)

			// the name matches ignoring case, and the map form gives a url
			jobs := push("env-a", "environment:\n      name: staging\n      url: https://staging.example.com/app")
			task := runner.fetchTask(t)
			assert.Equal(t, "from-env", task.Secrets["SHARED"])
			assert.Equal(t, "only-env", task.Secrets["ONLY_ENV"])
			assert.Equal(t, "from-env", task.Vars["SHARED_VAR"])
			d := deployment(jobs[0], 1)
			require.NotNil(t, d)
			assert.Equal(t, actions_model.DeploymentReleased, d.Status)
			assert.Equal(t, e.ID, d.EnvironmentID)
			assert.Equal(t, "https://staging.example.com/app", d.URL)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			// a job without an environment gets the repository's values only
			push("env-a", "")
			task = runner.fetchTask(t)
			assert.Equal(t, "from-repo", task.Secrets["SHARED"])
			assert.NotContains(t, task.Secrets, "ONLY_ENV")
			assert.Equal(t, "from-repo", task.Vars["SHARED_VAR"])
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("unknown environment is created, a bad url is dropped", func(t *testing.T) {
			jobs := push("env-b", "environment:\n      name: Fresh\n      url: javascript:alert(1)")
			task := runner.fetchTask(t)
			e, err := actions_model.GetRepoEnvironmentByName(t.Context(), repo.ID, "fresh")
			require.NoError(t, err)
			assert.Equal(t, "Fresh", e.Name)
			d := deployment(jobs[0], 1)
			assert.Equal(t, e.ID, d.EnvironmentID)
			assert.Empty(t, d.URL)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("ref policy refuses the job", func(t *testing.T) {
			newEnv("only-releases", func(e *actions_model.ActionEnvironment) {
				e.RefPolicy = actions_model.EnvironmentRefPatterns
				e.RefPatterns = []actions_model.EnvironmentRefPattern{{Type: actions_model.EnvironmentPatternBranch, Pattern: "release/*"}}
			})
			newEnv("only-protected", func(e *actions_model.ActionEnvironment) { e.RefPolicy = actions_model.EnvironmentRefProtectedBranches })

			var since int64
			_, err := db.GetEngine(t.Context()).Table(new(audit_model.Entry)).Select("COALESCE(MAX(id), 0)").Get(&since)
			require.NoError(t, err)

			for _, name := range []string{"only-releases", "only-protected"} {
				jobs := push("env-c", "environment: "+name)
				require.Eventually(t, func() bool { return reload(jobs[0]).Status == actions_model.StatusFailure }, 10*time.Second, 100*time.Millisecond, name)
				d := deployment(jobs[0], 1)
				require.NotNil(t, d, name)
				assert.Equal(t, actions_model.DeploymentRefused, d.Status)
				assert.Equal(t, actions_model.DeploymentReasonRefNotAllowed, d.Reason)
				assert.Nil(t, runner.maybeFetchTask(t), name)
			}
			entry := new(audit_model.Entry)
			has, err := db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "repo.actions_deployment.refused").Get(entry)
			require.NoError(t, err)
			assert.True(t, has)

			// a branch protection rule on the branch lets the protected policy through
			require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: repo.DefaultBranch, CanPush: true}, git_model.WhitelistOptions{}))
			jobs := push("env-c", "environment: only-protected")
			task := runner.fetchTask(t)
			assert.Equal(t, actions_model.DeploymentReleased, deployment(jobs[0], 1).Status)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("wait timer holds the job until it is due", func(t *testing.T) {
			e := newEnv("slow", func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			jobs := push("env-d", "environment: slow")
			d := deployment(jobs[0], 1)
			require.NotNil(t, d)
			assert.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
			assert.Equal(t, e.ID, d.EnvironmentID)
			assert.Equal(t, actions_model.StatusBlocked, reload(jobs[0]).Status)
			assert.Nil(t, runner.maybeFetchTask(t))

			// not due yet: the timer task changes nothing
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			assert.Equal(t, actions_model.DeploymentWaitingTimer, deployment(jobs[0], 1).Status)
			assert.Equal(t, actions_model.StatusBlocked, reload(jobs[0]).Status)
			assert.Nil(t, runner.maybeFetchTask(t))

			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = 1 WHERE id = ?", d.ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			assert.Equal(t, actions_model.DeploymentReleased, deployment(jobs[0], 1).Status)
			task := runner.fetchTask(t)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("cancelling a waiting run cancels its deployment", func(t *testing.T) {
			newEnv("slow-cancel", func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			jobs := push("env-e", "environment: slow-cancel")
			assert.Equal(t, actions_model.DeploymentWaitingTimer, deployment(jobs[0], 1).Status)
			run, err := actions_model.GetRunByID(t.Context(), jobs[0].RunID)
			require.NoError(t, err)
			require.NoError(t, actions_service.CancelRun(t.Context(), run))
			assert.Equal(t, actions_model.DeploymentCancelled, deployment(jobs[0], 1).Status)
			assert.Equal(t, actions_model.StatusCancelled, reload(jobs[0]).Status)
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("runner labels of the environment narrow the runners", func(t *testing.T) {
			newEnv("labelled", func(e *actions_model.ActionEnvironment) { e.RunnerLabels = []string{"env-g"} })
			plain := newMockRunner()
			plain.registerAsRepoRunner(t, user2.Name, repo.Name, "plain-runner", []string{"env-f"})
			jobs := push("env-f", "environment: labelled")
			require.Eventually(t, func() bool { return reload(jobs[0]).Status == actions_model.StatusWaiting }, 10*time.Second, 100*time.Millisecond)
			assert.Nil(t, plain.maybeFetchTask(t)) // no env-g label

			task := runner.fetchTask(t) // has env-f and env-g
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("rerun gates a new attempt", func(t *testing.T) {
			newEnv("rerun-env", func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			jobs := push("env-h", "environment: rerun-env")
			d1 := deployment(jobs[0], 1)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = 1 WHERE id = ?", d1.ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			task := runner.fetchTask(t)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			run, err := actions_model.GetRunByID(t.Context(), jobs[0].RunID)
			require.NoError(t, err)
			_, err = actions_service.RerunAllJobs(t.Context(), run)
			require.NoError(t, err)
			job := reload(jobs[0])
			require.Equal(t, int64(2), job.Attempt)
			d2 := deployment(job, 2)
			require.NotNil(t, d2)
			assert.Equal(t, actions_model.DeploymentWaitingTimer, d2.Status)
			assert.Equal(t, actions_model.DeploymentReleased, deployment(job, 1).Status)
			assert.Equal(t, actions_model.StatusBlocked, job.Status)
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("workflow_dispatch input names the environment", func(t *testing.T) {
			newEnv("from-input", nil)
			path := ".gitea/workflows/env-dispatch.yml"
			content := `name: env-dispatch
on:
  workflow_dispatch:
    inputs:
      target:
        required: true
jobs:
  deploy:
    runs-on: env-i
    environment: ${{ inputs.target }}
    steps:
      - run: echo deploy
`
			createWorkflowFile(t, token, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add dispatch", content))
			MakeRequest(t, NewRequestWithJSON(t, http.MethodPost,
				fmt.Sprintf("/api/v1/repos/%s/%s/actions/workflows/env-dispatch.yml/dispatches", user2.Name, repo.Name),
				&api.DispatchWorkflowOption{Ref: repo.DefaultBranch, Inputs: map[string]string{"target": "From-Input"}},
			).AddTokenAuth(token), http.StatusNoContent)
			task := runner.fetchTask(t)
			e, err := actions_model.GetRepoEnvironmentByName(t.Context(), repo.ID, "from-input")
			require.NoError(t, err)
			count, err := db.GetEngine(t.Context()).Where("environment_id = ? AND status = ?", e.ID, actions_model.DeploymentReleased).Count(new(actions_model.ActionDeployment))
			require.NoError(t, err)
			assert.EqualValues(t, 1, count)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})
	})
}
