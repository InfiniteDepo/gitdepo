// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	"forgejo.org/modules/git"
	"forgejo.org/modules/optional"
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

		labels := []string{"env-a", "env-b", "env-c", "env-d", "env-e", "env-f", "env-g", "env-h", "env-i", "env-j", "env-k", "env-l", "env-m", "env-n"}
		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "env-runner", labels)

		files := 0
		// pushWorkflow creates the workflow file at path, which content must start on its own path, and returns the run
		// it starts
		pushWorkflow := func(path, content string) *actions_model.ActionRun {
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
			return run
		}
		runJobs := func(run *actions_model.ActionRun) []*actions_model.ActionRunJob {
			jobs, err := actions_model.GetRunJobsByRunID(t.Context(), run.ID)
			require.NoError(t, err)
			return jobs
		}
		// push creates a workflow file with one job on label and returns the jobs of the run it starts
		push := func(label, environment string) []*actions_model.ActionRunJob {
			files++
			path := fmt.Sprintf(".gitea/workflows/env%d.yml", files)
			return runJobs(pushWorkflow(path, fmt.Sprintf(`name: env%d
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
`, files, path, label, environment)))
		}
		// hasStatus reads the job without require or t.Context(), so that it can run in an Eventually condition
		hasStatus := func(job *actions_model.ActionRunJob, status actions_model.Status) bool {
			j := new(actions_model.ActionRunJob)
			has, err := db.GetEngine(db.DefaultContext).ID(job.ID).Get(j)
			return err == nil && has && j.Status == status
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
				require.Eventually(t, func() bool { return hasStatus(jobs[0], actions_model.StatusFailure) }, 10*time.Second, 100*time.Millisecond, name)
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
			require.Eventually(t, func() bool { return hasStatus(jobs[0], actions_model.StatusWaiting) }, 10*time.Second, 100*time.Millisecond)
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
		t.Run("the job of a reusable workflow is gated, with the inputs of the call", func(t *testing.T) {
			e := newEnv("called-env", func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "CALLED_SECRET", "called-value")
			require.NoError(t, err)
			createWorkflowFile(t, token, user2.Name, repo.Name, ".gitea/workflows/env-called.yml", getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add called", `name: env-called
on:
  workflow_call:
    inputs:
      target:
        type: string
jobs:
  deploy:
    runs-on: env-j
    environment: ${{ inputs.target }}
    steps:
      - run: echo deploy
`))
			jobs := runJobs(pushWorkflow(".gitea/workflows/env-caller.yml", `name: env-caller
on:
  push:
    paths:
      - '.gitea/workflows/env-caller.yml'
jobs:
  call:
    uses: ./.gitea/workflows/env-called.yml
    with:
      target: called-env
`))
			var inner *actions_model.ActionRunJob
			for _, job := range jobs {
				if job.EnvironmentName != "" {
					inner = job
				}
			}
			require.NotNil(t, inner, "the job of the called workflow keeps its environment")
			assert.Equal(t, "${{ inputs.target }}", inner.EnvironmentName)
			d := deployment(inner, 1)
			require.NotNil(t, d)
			assert.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
			assert.Equal(t, e.ID, d.EnvironmentID)
			assert.Nil(t, runner.maybeFetchTask(t))

			_, err = db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = 1 WHERE id = ?", d.ID)
			require.NoError(t, err)
			require.NoError(t, actions_service.StartDueDeployments(t.Context()))
			task := runner.fetchTask(t)
			assert.Equal(t, "called-value", task.Secrets["CALLED_SECRET"], "after the release, and only then")
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("the name from the matrix of the job", func(t *testing.T) {
			for _, name := range []string{"mx-a", "mx-b"} {
				e := newEnv(name, nil)
				_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, repo.ID, e.ID, "WHO", name)
				require.NoError(t, err)
			}
			jobs := push("env-k", "environment: ${{ matrix.target }}\n    strategy:\n      matrix:\n        target: [mx-a, mx-b]")
			require.Len(t, jobs, 2)
			names := map[string]bool{}
			for _, job := range jobs {
				d := deployment(job, 1)
				require.NotNil(t, d)
				e, err := actions_model.GetRepoEnvironmentByID(t.Context(), repo.ID, d.EnvironmentID)
				require.NoError(t, err)
				names[e.Name] = true
			}
			assert.Equal(t, map[string]bool{"mx-a": true, "mx-b": true}, names)
			secrets := map[string]bool{}
			for range jobs {
				task := runner.fetchTask(t)
				secrets[task.Secrets["WHO"]] = true
				runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			}
			assert.Equal(t, map[string]bool{"mx-a": true, "mx-b": true}, secrets, "each job has the secrets of its own environment")
		})

		t.Run("the name from the output of a needed job", func(t *testing.T) {
			e := newEnv("needs-env", nil)
			files++
			path := fmt.Sprintf(".gitea/workflows/env%d.yml", files)
			jobs := runJobs(pushWorkflow(path, fmt.Sprintf(`name: env-needs
on:
  push:
    paths:
      - '%s'
jobs:
  prepare:
    runs-on: env-l
    outputs:
      target: ${{ steps.t.outputs.target }}
    steps:
      - id: t
        run: echo target
  deploy:
    runs-on: env-l
    needs: [prepare]
    environment: ${{ needs.prepare.outputs.target }}
    steps:
      - run: echo deploy
`, path)))
			require.Len(t, jobs, 2)
			task := runner.fetchTask(t) // prepare; deploy waits for it
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS, outputs: map[string]string{"target": "needs-env"}})
			task = runner.fetchTask(t)
			count, err := db.GetEngine(t.Context()).Where("environment_id = ? AND status = ?", e.ID, actions_model.DeploymentReleased).Count(new(actions_model.ActionDeployment))
			require.NoError(t, err)
			assert.EqualValues(t, 1, count)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("a job that calls a reusable workflow can't have an environment", func(t *testing.T) {
			run := pushWorkflow(".gitea/workflows/env-bad-call.yml", `name: env-bad-call
on:
  push:
    paths:
      - '.gitea/workflows/env-bad-call.yml'
jobs:
  call:
    uses: ./.gitea/workflows/env-called.yml
    environment: prod
`)
			assert.Equal(t, actions_model.StatusFailure, run.Status)
			assert.Equal(t, actions_model.ErrorCodeJobParsingError, run.PreExecutionErrorCode)
			for _, job := range runJobs(run) {
				assert.Equal(t, actions_model.StatusFailure, job.Status)
				assert.Empty(t, job.EnvironmentName)
			}
			assert.Nil(t, runner.maybeFetchTask(t))
		})
		t.Run("dispatch only to refs that exist as they are named", func(t *testing.T) {
			dispatch := func(ref string, status int) {
				MakeRequest(t, NewRequestWithJSON(t, http.MethodPost,
					fmt.Sprintf("/api/v1/repos/%s/%s/actions/workflows/env-dispatch.yml/dispatches", user2.Name, repo.Name),
					&api.DispatchWorkflowOption{Ref: ref, Inputs: map[string]string{"target": "from-input"}},
				).AddTokenAuth(token), status)
			}
			createBranchReq := NewRequestWithJSON(t, http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/%s/branches", user2.Name, repo.Name),
				&api.CreateBranchRepoOption{BranchName: "release/1"}).AddTokenAuth(token)
			MakeRequest(t, createBranchReq, http.StatusCreated)
			before := unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID})
			for _, ref := range []string{"refs/heads/main~1", "refs/heads/release/1@{1}", "main^", "refs/heads/release/1~1", "refs/heads/nope", "main:README.md", "refs/heads/main^{tree}"} {
				dispatch(ref, http.StatusBadRequest)
			}
			assert.Equal(t, before, unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID}), "none of them started a run")

			// the names that exist, in their full and short form, still work; so does a commit ID
			branch := new(api.Branch)
			DecodeJSON(t, MakeRequest(t, NewRequest(t, http.MethodGet, fmt.Sprintf("/api/v1/repos/%s/%s/branches/main", user2.Name, repo.Name)).AddTokenAuth(token), http.StatusOK), branch)
			for _, ref := range []string{"refs/heads/release/1", "release/1", "main", branch.Commit.ID} {
				dispatch(ref, http.StatusNoContent)
				runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			}
		})

		t.Run("a name is never resolved to a branch that is named like another ref", func(t *testing.T) {
			newEnv("tag-v", func(e *actions_model.ActionEnvironment) {
				e.RefPolicy = actions_model.EnvironmentRefPatterns
				e.RefPatterns = []actions_model.EnvironmentRefPattern{{Type: actions_model.EnvironmentPatternTag, Pattern: "v*"}}
			})
			sha, _, rsErr := git.NewCommand(t.Context(), "rev-parse").AddDynamicArguments(repo.DefaultBranch).RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
			require.NoError(t, rsErr)
			sha = strings.TrimSpace(sha)
			// branches whose names read as a tag and as another branch
			for _, name := range []string{"refs/tags/v99", "refs/heads/release/2"} {
				_, _, rsErr := git.NewCommand(t.Context(), "update-ref").AddDynamicArguments("refs/heads/"+name, sha).RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
				require.NoError(t, rsErr)
			}
			before := unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID})
			for _, ref := range []string{"refs/tags/v99", "v99", "tags/v99", "refs/heads/release/2", "heads/release/2"} {
				MakeRequest(t, NewRequestWithJSON(t, http.MethodPost,
					fmt.Sprintf("/api/v1/repos/%s/%s/actions/workflows/env-dispatch.yml/dispatches", user2.Name, repo.Name),
					&api.DispatchWorkflowOption{Ref: ref, Inputs: map[string]string{"target": "tag-v"}},
				).AddTokenAuth(token), http.StatusBadRequest)
			}
			assert.Equal(t, before, unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID}), "none of them started a run")
			e, err := actions_model.GetRepoEnvironmentByName(t.Context(), repo.ID, "tag-v")
			require.NoError(t, err)
			count, err := db.GetEngine(t.Context()).Where("environment_id = ?", e.ID).Count(new(actions_model.ActionDeployment))
			require.NoError(t, err)
			assert.Zero(t, count, "the environment released nothing")
			assert.Nil(t, runner.maybeFetchTask(t))

			// the real name of such a branch is the one that works
			MakeRequest(t, NewRequestWithJSON(t, http.MethodPost,
				fmt.Sprintf("/api/v1/repos/%s/%s/actions/workflows/env-dispatch.yml/dispatches", user2.Name, repo.Name),
				&api.DispatchWorkflowOption{Ref: "refs/heads/refs/tags/v99", Inputs: map[string]string{"target": "from-input"}},
			).AddTokenAuth(token), http.StatusNoContent)
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("deleting an environment fails the jobs that no runner took", func(t *testing.T) {
			waiting := newEnv("del-timer", func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			released := newEnv("del-released", nil)
			timerJobs := push("env-m", "environment: del-timer")
			releasedJobs := push("env-m", "environment: del-released") // released, and no runner has its labels
			require.Equal(t, actions_model.StatusBlocked, reload(timerJobs[0]).Status)
			require.Equal(t, actions_model.StatusWaiting, reload(releasedJobs[0]).Status)
			newEnv("del-kept", func(e *actions_model.ActionEnvironment) { e.WaitTimerMinutes = 10 })
			keptJobs := push("env-m", "environment: del-kept")

			require.NoError(t, actions_service.DeleteEnvironment(ctx, waiting))
			require.NoError(t, actions_service.DeleteEnvironment(ctx, released))
			for _, job := range [][]*actions_model.ActionRunJob{timerJobs, releasedJobs} {
				j := reload(job[0])
				assert.Equal(t, actions_model.StatusFailure, j.Status)
				assert.NotZero(t, j.Stopped)
				d := deployment(j, 1)
				assert.Equal(t, actions_model.DeploymentRefused, d.Status)
				assert.Equal(t, actions_model.DeploymentReasonEnvironmentDeleted, d.Reason)
			}
			assert.Equal(t, actions_model.StatusBlocked, reload(keptJobs[0]).Status, "the job of another environment is left alone")
			assert.Equal(t, actions_model.DeploymentWaitingTimer, deployment(keptJobs[0], 1).Status)
			assert.Nil(t, runner.maybeFetchTask(t))
		})

		t.Run("a released job whose environment is gone never stops a shared runner", func(t *testing.T) {
			gone := newEnv("gone-env", nil)
			goneJobs := push("env-m", "environment: gone-env")
			require.Equal(t, actions_model.StatusWaiting, reload(goneJobs[0]).Status)
			// the environment goes without the service that fails its jobs, as if another server had missed them
			require.NoError(t, actions_service.DeleteEnvironment(ctx, gone))

			other := createActionsTestRepo(t, token, "actions-environments-other", false)
			token2, err := actions_model.NewRunnerToken(ctx, optional.Some(user2.ID), optional.None[int64]())
			require.NoError(t, err)
			shared := newMockRunner()
			shared.doRegister(t, "shared-runner", token2.Token, []string{"env-m"})
			createWorkflowFile(t, token, user2.Name, other.Name, ".gitea/workflows/plain.yml", getWorkflowCreateFileOptions(user2, other.DefaultBranch, "add plain", `name: plain
on:
  push:
    paths:
      - '.gitea/workflows/plain.yml'
jobs:
  plain:
    runs-on: env-m
    steps:
      - run: echo plain
`))
			task := shared.fetchTask(t)
			assert.NotEqual(t, goneJobs[0].ID, task.GetId())
			j := reload(goneJobs[0])
			assert.Equal(t, actions_model.StatusFailure, j.Status)
			assert.Equal(t, actions_model.DeploymentReasonEnvironmentDeleted, deployment(j, 1).Reason)
			var running actions_model.ActionTask
			has, err := db.GetEngine(t.Context()).ID(task.GetId()).Get(&running)
			require.NoError(t, err)
			require.True(t, has)
			assert.Equal(t, other.ID, running.RepoID, "the job of the other repository was picked")
			shared.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})

		t.Run("a rerun takes the runner labels the environment has now", func(t *testing.T) {
			e := newEnv("relabel", func(e *actions_model.ActionEnvironment) { e.RunnerLabels = []string{"env-a"} })
			jobs := push("env-b", "environment: relabel")
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
			assert.Equal(t, []string{"env-b", "env-a"}, reload(jobs[0]).RunsOn)

			e.RunnerLabels = []string{"env-c"}
			require.NoError(t, actions_model.UpdateEnvironment(ctx, e))
			run, err := actions_model.GetRunByID(t.Context(), jobs[0].RunID)
			require.NoError(t, err)
			_, err = actions_service.RerunAllJobs(t.Context(), run)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				j := new(actions_model.ActionRunJob)
				has, err := db.GetEngine(db.DefaultContext).ID(jobs[0].ID).Get(j)
				return err == nil && has && j.Status == actions_model.StatusWaiting
			}, 10*time.Second, 100*time.Millisecond)
			assert.Equal(t, []string{"env-b", "env-c"}, reload(jobs[0]).RunsOn, "the label of the first attempt is gone")
			runner.execTask(t, runner.fetchTask(t), &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})
		})
	})
}
