// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	actions_module "forgejo.org/modules/actions"
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gateJobID = 600 // a job of repository 63 in the fixtures of TestGetSecretsOfJob

func envWorkflow(environment string) string {
	return "on: push\njobs:\n  produce-artifacts:\n    runs-on: docker\n" + environment + "    steps:\n      - run: echo\n"
}

// gateJob makes the fixture job a blocked job of that workflow, in a run of that ref, at its first attempt.
func gateJob(t *testing.T, workflow, ref string) *actions_model.ActionRunJob {
	t.Helper()
	sws, err := actions_module.JobParser([]byte(workflow))
	require.NoError(t, err)
	return gateSingle(t, sws[0], ref)
}

// gateSingle is gateJob for one of the single workflows a parse returned.
func gateSingle(t *testing.T, sw *jobparser.SingleWorkflow, ref string) *actions_model.ActionRunJob {
	t.Helper()
	sws := []*jobparser.SingleWorkflow{sw}
	payload, err := sws[0].Marshal()
	require.NoError(t, err)
	name := ""
	if env, err := actions_module.GetJobEnvironment(sws[0]); err != nil {
		require.NoError(t, err)
	} else if env != nil {
		name = env.Name
	}
	e := db.GetEngine(t.Context())
	_, err = e.Exec("UPDATE action_run_job SET workflow_payload = ?, environment_name = ?, status = ?, attempt = 1, runs_on = ?, repo_id = 63 WHERE id = ?",
		string(payload), name, actions_model.StatusBlocked, `["docker"]`, gateJobID)
	require.NoError(t, err)
	_, err = e.Exec("UPDATE action_run SET ref = ?, trigger_user_id = 2, commit_sha = ? WHERE id = 900", ref, "c2d72f548424103f01ee1dc02889c1e2bff816b0")
	require.NoError(t, err)
	return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID})
}

func deploymentOf(t *testing.T, job *actions_model.ActionRunJob) *actions_model.ActionDeployment {
	t.Helper()
	d, err := actions_model.GetDeployment(t.Context(), job.ID, job.Attempt)
	require.NoError(t, err)
	return d
}

func newEnvironment(t *testing.T, e *actions_model.ActionEnvironment) *actions_model.ActionEnvironment {
	t.Helper()
	e.RepoID = 63
	require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(t.Context(), "test"), e))
	return e
}

func patternEnv(name string, patterns ...actions_model.EnvironmentRefPattern) *actions_model.ActionEnvironment {
	return &actions_model.ActionEnvironment{Name: name, RefPolicy: actions_model.EnvironmentRefPatterns, RefPatterns: patterns}
}

func TestGateEnvironment(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	branch := func(p string) actions_model.EnvironmentRefPattern {
		return actions_model.EnvironmentRefPattern{Type: actions_model.EnvironmentPatternBranch, Pattern: p}
	}
	tag := func(p string) actions_model.EnvironmentRefPattern {
		return actions_model.EnvironmentRefPattern{Type: actions_model.EnvironmentPatternTag, Pattern: p}
	}

	t.Run("a job without an environment runs", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		job := gateJob(t, envWorkflow(""), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Nil(t, deploymentOf(t, job))
		assert.Equal(t, 0, unittest.GetCount(t, &actions_model.ActionEnvironment{}))
	})

	t.Run("an unknown name is created without rules and releases the job", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		job := gateJob(t, envWorkflow("    environment: Production\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		env := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: 63, LowerName: "production"})
		assert.Equal(t, "Production", env.Name)
		assert.Equal(t, actions_model.EnvironmentRefAny, env.RefPolicy)
		assert.Empty(t, env.RefPatterns)
		d := deploymentOf(t, job)
		require.NotNil(t, d)
		assert.Equal(t, actions_model.DeploymentReleased, d.Status)
		assert.Equal(t, env.ID, d.EnvironmentID)
		assert.EqualValues(t, 63, d.RepoID)
		assert.EqualValues(t, 900, d.RunID)
		assert.Equal(t, "refs/heads/main", d.Ref)
		assert.Equal(t, "c2d72f548424103f01ee1dc02889c1e2bff816b0", d.CommitSHA)
		assert.EqualValues(t, 2, d.TriggerUserID)
		assert.Equal(t, []string{"docker"}, job.RunsOn)

		// the same gate again (the emitter ran twice) changes nothing
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, 1, unittest.GetCount(t, &actions_model.ActionDeployment{}))
	})

	t.Run("the url", func(t *testing.T) {
		for url, want := range map[string]string{
			"https://example.com/app": "https://example.com/app",
			"javascript:alert(1)":     "",
			"${{ vars.SITE }}":        "https://example.com/from-var",
			"${{ vars.NOPE }}":        "",
		} {
			require.NoError(t, unittest.PrepareTestDatabase())
			_, err := actions_model.InsertVariable(t.Context(), 0, 0, 63, "SITE", "https://example.com/from-var")
			require.NoError(t, err)
			job := gateJob(t, envWorkflow(fmt.Sprintf("    environment:\n      name: prod\n      url: '%s'\n", url)), "refs/heads/main")
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			assert.Equal(t, behaviourExecuteJob, b, url)
			assert.Equal(t, want, deploymentOf(t, job).URL, url)
		}
	})

	t.Run("a name from an expression", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		_, err := actions_model.InsertVariable(t.Context(), 0, 0, 63, "TARGET", "from-var")
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run SET event_payload = ? WHERE id = 900", `{"inputs":{"target":"from-input"}}`)
		require.NoError(t, err)
		for name, want := range map[string]string{
			"${{ inputs.target }}":        "from-input",
			"${{ vars.TARGET }}":          "from-var",
			"deploy-${{ inputs.target }}": "deploy-from-input",
		} {
			job := gateJob(t, envWorkflow(fmt.Sprintf("    environment: %s\n", "'"+name+"'")), "refs/heads/main")
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			assert.Equal(t, behaviourExecuteJob, b, name)
			env, err := actions_model.GetRepoEnvironmentByID(t.Context(), 63, deploymentOf(t, job).EnvironmentID)
			require.NoError(t, err)
			assert.Equal(t, want, env.Name)
			_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
		}
	})

	t.Run("a name from the matrix of the job", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		sws, err := actions_module.JobParser([]byte("on: push\njobs:\n  deploy:\n    runs-on: docker\n    strategy:\n      matrix:\n        target: [alpha, beta]\n    environment: 'env-${{ matrix.target }}'\n    steps: [{run: echo}]\n"))
		require.NoError(t, err)
		require.Len(t, sws, 2)
		var names []string
		for _, sw := range sws {
			job := gateSingle(t, sw, "refs/heads/main")
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			assert.Equal(t, behaviourExecuteJob, b)
			env, err := actions_model.GetRepoEnvironmentByID(t.Context(), 63, deploymentOf(t, job).EnvironmentID)
			require.NoError(t, err)
			names = append(names, env.Name)
			_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
		}
		assert.ElementsMatch(t, []string{"env-alpha", "env-beta"}, names)
	})

	t.Run("a job of a reusable workflow: the inputs of the call, and an environment that can't be read", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		caller := "on: push\njobs:\n  call:\n    uses: ./called.yml\n    with:\n      target: from-call\n"
		called := "on:\n  workflow_call:\n    inputs:\n      target:\n        type: string\njobs:\n  deploy:\n    runs-on: docker\n    environment: '${{ inputs.target }}'\n    steps: [{run: echo}]\n"
		fetch := func(job *jobparser.Job, path string) ([]byte, error) { return []byte(called), nil }
		for _, known := range []bool{true, false} {
			r := actions_module.ReusableWorkflows{}
			expand := jobparser.ExpandLocalReusableWorkflows(fetch)
			if known {
				expand = r.ExpandLocal(fetch)
			}
			sws, err := r.JobParser([]byte(caller), expand, jobparser.EnableNamespaces())
			require.NoError(t, err)
			var job *actions_model.ActionRunJob
			for _, sw := range sws {
				if id, _ := sw.Job(); id == "deploy" {
					job = gateSingle(t, sw, "refs/heads/main")
				}
			}
			require.NotNil(t, job)
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			d := deploymentOf(t, job)
			if known {
				assert.Equal(t, behaviourExecuteJob, b)
				env, err := actions_model.GetRepoEnvironmentByID(t.Context(), 63, d.EnvironmentID)
				require.NoError(t, err)
				assert.Equal(t, "from-call", env.Name)
			} else {
				assert.Equal(t, behaviourFailJob, b)
				assert.Equal(t, actions_model.DeploymentRefused, d.Status)
				assert.Equal(t, actions_model.DeploymentReasonUnsupported, d.Reason)
				assert.Zero(t, d.EnvironmentID)
			}
			_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
		}
	})

	t.Run("an invalid name fails the job", func(t *testing.T) {
		for name, env := range map[string]string{
			"empty":              "    environment: ''\n",
			"empty expression":   "    environment: ${{ inputs.missing }}\n",
			"broken expression":  "    environment: ${{ inputs.( }}\n",
			"control characters": "    environment: \"a\\nb\"\n",
			"too long":           fmt.Sprintf("    environment: %s\n", string(make([]byte, 0))+fmt.Sprintf("%0256d", 1)),
			"unknown context":    "    environment: ${{ matrix.x }}\n",
			"no name in the map": "    environment:\n      url: https://example.com\n",
		} {
			require.NoError(t, unittest.PrepareTestDatabase())
			job := gateJob(t, envWorkflow(env), "refs/heads/main")
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err, name)
			assert.Equal(t, behaviourFailJob, b, name)
			d := deploymentOf(t, job)
			require.NotNil(t, d, name)
			assert.Equal(t, actions_model.DeploymentRefused, d.Status, name)
			assert.Equal(t, actions_model.DeploymentReasonInvalidName, d.Reason, name)
			assert.EqualValues(t, 0, d.EnvironmentID, name)
			assert.Equal(t, 0, unittest.GetCount(t, &actions_model.ActionEnvironment{}), name)
		}
	})

	t.Run("the environment limit", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		for i := range actions_model.MaxEnvironmentsPerRepo {
			_, err := actions_model.GetOrCreateRepoEnvironment(audit_model.WithSystem(t.Context(), "test"), 63, fmt.Sprint("e", i))
			require.NoError(t, err)
		}
		job := gateJob(t, envWorkflow("    environment: one-too-many\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentReasonEnvironmentLimit, deploymentOf(t, job).Reason)
		assert.Equal(t, actions_model.MaxEnvironmentsPerRepo, unittest.GetCount(t, &actions_model.ActionEnvironment{}))
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		job = gateJob(t, envWorkflow("    environment: E3\n"), "refs/heads/main")
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b, "an existing environment still releases at the cap")
	})

	t.Run("the ref policy", func(t *testing.T) {
		for _, tc := range []struct {
			name, ref string
			env       *actions_model.ActionEnvironment
			want      behaviour
		}{
			{"branch pattern matches", "refs/heads/release/1", patternEnv("p", branch("release/*")), behaviourExecuteJob},
			{"branch pattern doesn't match", "refs/heads/main", patternEnv("p", branch("release/*")), behaviourFailJob},
			{"star doesn't cross a slash", "refs/heads/release/a/b", patternEnv("p", branch("release/*")), behaviourFailJob},
			{"double star does", "refs/heads/release/a/b", patternEnv("p", branch("release/**")), behaviourExecuteJob},
			{"tag pattern doesn't allow the branch of that name", "refs/heads/v1", patternEnv("p", tag("v1")), behaviourFailJob},
			{"branch pattern doesn't allow the tag of that name", "refs/tags/v1", patternEnv("p", branch("v1")), behaviourFailJob},
			{"tag pattern allows the tag", "refs/tags/v1", patternEnv("p", tag("v*")), behaviourExecuteJob},
			{"pull request ref under patterns", "refs/pull/3/head", patternEnv("p", branch("**"), tag("**")), behaviourFailJob},
			{"pull request ref under the any policy", "refs/pull/3/head", &actions_model.ActionEnvironment{Name: "p"}, behaviourExecuteJob},
			{"pull request ref under protected branches", "refs/pull/3/head", &actions_model.ActionEnvironment{Name: "p", RefPolicy: actions_model.EnvironmentRefProtectedBranches}, behaviourFailJob},
			{"a tag under protected branches", "refs/tags/v1", &actions_model.ActionEnvironment{Name: "p", RefPolicy: actions_model.EnvironmentRefProtectedBranches}, behaviourFailJob},
			{"a branch without a rule", "refs/heads/main", &actions_model.ActionEnvironment{Name: "p", RefPolicy: actions_model.EnvironmentRefProtectedBranches}, behaviourFailJob},
			{"no ref", "", patternEnv("p", branch("**")), behaviourFailJob},
		} {
			t.Run(tc.name, func(t *testing.T) {
				require.NoError(t, unittest.PrepareTestDatabase())
				newEnvironment(t, tc.env)
				job := gateJob(t, envWorkflow("    environment: P\n"), tc.ref) // another case of the name
				since := auditSince(t)
				b, err := gateEnvironment(t.Context(), job)
				require.NoError(t, err)
				assert.Equal(t, tc.want, b)
				d := deploymentOf(t, job)
				if tc.want == behaviourFailJob {
					assert.Equal(t, actions_model.DeploymentRefused, d.Status)
					assert.Equal(t, actions_model.DeploymentReasonRefNotAllowed, d.Reason)
					refused := auditRefused(t, since)
					require.Len(t, refused, 1)
					assert.Equal(t, audit_model.ResultRefused, refused[0].Result)
					assert.Equal(t, d.ID, refused[0].TargetID)
					assert.EqualValues(t, 63, refused[0].RepoID)
				} else {
					assert.Equal(t, actions_model.DeploymentReleased, d.Status)
					assert.Empty(t, auditRefused(t, since))
				}
				assert.Equal(t, 1, unittest.GetCount(t, &actions_model.ActionEnvironment{}), "the name found the environment, no twin was created")
			})
		}
	})

	t.Run("protected branches: a rule of the repository, the project or the organization counts", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		ctx := t.Context()
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		project, err := repo_model.CreateRepoGroup(audit_model.WithSystem(ctx, "test"), org3, "pa", "")
		require.NoError(t, err)
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod", RefPolicy: actions_model.EnvironmentRefProtectedBranches})
		run := func(ref string) behaviour {
			_, err := db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
			b, err := gateEnvironment(ctx, gateJob(t, envWorkflow("    environment: prod\n"), ref))
			require.NoError(t, err)
			return b
		}
		assert.Equal(t, behaviourFailJob, run("refs/heads/main"))

		// repository 63 belongs to a user: rules of the organization and of the project don't reach it
		require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{OrgID: 3, GroupID: project.ID, RuleName: "main"}))
		require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{OrgID: 3, RuleName: "stable"}))
		assert.Equal(t, behaviourFailJob, run("refs/heads/main"))

		_, err = db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = 3, group_id = ? WHERE id = 63", project.ID)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, run("refs/heads/main"), "a rule of the project")
		assert.Equal(t, behaviourExecuteJob, run("refs/heads/stable"), "a rule of the organization")
		assert.Equal(t, behaviourFailJob, run("refs/heads/other"))
		_, err = db.GetEngine(ctx).Exec("UPDATE repository SET group_id = 0 WHERE id = 63")
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, run("refs/heads/main"), "out of the project, its rule no longer counts")

		require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: 63, RuleName: "release/*"}))
		assert.Equal(t, behaviourExecuteJob, run("refs/heads/release/1"), "a rule of the repository")
	})

	t.Run("the wait timer", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		start := time.Now().Truncate(time.Second)
		timeutil.MockSet(start)
		defer timeutil.MockUnset()
		env := newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")

		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
		d := deploymentOf(t, job)
		assert.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
		assert.EqualValues(t, start.Unix()+300, d.ReleaseAfterUnix)

		timeutil.MockSet(start.Add(299 * time.Second))
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b, "not yet")
		due, err := actions_model.FindDueDeploymentRunIDs(t.Context(), timeutil.TimeStampNow(), 10)
		require.NoError(t, err)
		assert.Empty(t, due)

		// the environment's timer is shortened meanwhile: the deployment keeps the deadline it was given
		env.WaitTimerMinutes = 1
		require.NoError(t, actions_model.UpdateEnvironment(audit_model.WithSystem(t.Context(), "test"), env))
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)

		timeutil.MockSet(start.Add(300 * time.Second))
		due, err = actions_model.FindDueDeploymentRunIDs(t.Context(), timeutil.TimeStampNow(), 10)
		require.NoError(t, err)
		assert.Equal(t, []int64{900}, due)
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, deploymentOf(t, job).Status)
	})

	t.Run("the rules apply to a waiting job as they are when it is looked at again", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		start := time.Now().Truncate(time.Second)
		timeutil.MockSet(start)
		defer timeutil.MockUnset()
		env := newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		require.Equal(t, behaviourHoldJob, b)

		env.RefPolicy, env.RefPatterns = actions_model.EnvironmentRefPatterns, []actions_model.EnvironmentRefPattern{branch("release/*")}
		require.NoError(t, actions_model.UpdateEnvironment(audit_model.WithSystem(t.Context(), "test"), env))
		timeutil.MockSet(start.Add(time.Hour))
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentReasonRefNotAllowed, deploymentOf(t, job).Reason)

		// the refusal stays: another pass fails the job again without a second entry
		since := auditSince(t)
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Empty(t, auditRefused(t, since))
	})

	t.Run("a deleted environment refuses the waiting job", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		env := newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		require.Equal(t, behaviourHoldJob, b)
		require.NoError(t, actions_model.DeleteEnvironment(audit_model.WithSystem(t.Context(), "test"), env))
		timeutil.MockSet(time.Now().Add(time.Hour))
		defer timeutil.MockUnset()
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentReasonEnvironmentDeleted, deploymentOf(t, job).Reason)
	})

	t.Run("a cancelled deployment keeps the job blocked", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
		_, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		require.NoError(t, actions_model.CancelOpenDeployments(t.Context(), job.ID))
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
	})

	t.Run("runner labels narrow the runners", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod", RunnerLabels: []string{"deploy", "docker", "eu"}})
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, []string{"docker", "deploy", "eu"}, job.RunsOn, "added without a duplicate")
		assert.False(t, job.ItRunsOn([]string{"docker"}))
		assert.False(t, job.ItRunsOn([]string{"docker", "deploy"}))
		assert.True(t, job.ItRunsOn([]string{"docker", "deploy", "eu"}))
		assert.True(t, job.ItRunsOn([]string{"deploy", "eu", "docker", "extra"}))
		assert.Equal(t, []string{"docker"}, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID}).RunsOn, "the payload and the column are persisted by the emitter, not here")

		// a job that runs on nothing stays that way
		job = gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		job.RunsOn = nil
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		_, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Empty(t, job.RunsOn)
	})

	t.Run("a rerun is a new attempt with a new deployment", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
		_, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		first := deploymentOf(t, job)
		job.Attempt = 2
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b, "the release of attempt 1 doesn't carry over")
		second := deploymentOf(t, job)
		assert.NotEqual(t, first.ID, second.ID)
		assert.EqualValues(t, 2, second.Attempt)
	})
	t.Run("approving a run never skips the gate", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
		run, err := actions_model.GetRunByID(t.Context(), job.RunID)
		require.NoError(t, err)
		require.NoError(t, ApproveRun(audit_model.WithSystem(t.Context(), "test"), run, 2))
		job = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID})
		assert.Equal(t, actions_model.StatusBlocked, job.Status)
		d := deploymentOf(t, job)
		require.NotNil(t, d)
		assert.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
	})
}

func auditSince(t *testing.T) int64 {
	t.Helper()
	var id int64
	_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(t, err)
	return id
}

func auditRefused(t *testing.T, since int64) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "repo.actions_deployment.refused").Find(&entries))
	return entries
}

// A job that names an environment only gets its secrets and variables through a released deployment of this attempt.
func TestEnvironmentSecretsAndVariables(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	project, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = 3, group_id = ? WHERE id = 63", project.ID)
	require.NoError(t, err)

	prod := newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod"})
	staging := newEnvironment(t, &actions_model.ActionEnvironment{Name: "staging"})
	for _, s := range []struct {
		owner, group, repo, env int64
		name, value             string
	}{
		{3, 0, 0, 0, "LEVEL", "org"},
		{3, 0, 0, 0, "ORG_ONLY", "org"},
		{3, project.ID, 0, 0, "LEVEL", "project"},
		{0, 0, 63, 0, "LEVEL", "repo"},
		{0, 0, 63, 0, "REPO_ONLY", "repo"},
		{0, 0, 63, prod.ID, "LEVEL", "prod"},
		{0, 0, 63, prod.ID, "PROD_ONLY", "prod"},
		{0, 0, 63, staging.ID, "STAGING_ONLY", "staging"},
	} {
		if s.env != 0 {
			_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, s.repo, s.env, s.name, s.value)
		} else {
			_, err = secret_model.InsertEncryptedSecret(ctx, s.owner, s.group, s.repo, s.name, s.value)
		}
		require.NoError(t, err)
	}
	_, err = actions_model.InsertVariable(ctx, 0, 0, 63, "LEVEL", "repo")
	require.NoError(t, err)
	_, err = actions_model.InsertVariable(ctx, 0, 0, 63, "REPO_ONLY", "repo")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 63, prod.ID, "LEVEL", "prod")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 63, prod.ID, "PROD_ONLY", "prod")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 63, staging.ID, "STAGING_ONLY", "staging")
	require.NoError(t, err)

	secretsOf := func(job *actions_model.ActionRunJob) (map[string]string, error) { return getSecretsOfJob(ctx, job) }
	varsOf := func(job *actions_model.ActionRunJob) (map[string]string, error) { return getVariablesOfJob(ctx, job) }

	t.Run("a job without an environment gets none of theirs", func(t *testing.T) {
		job := gateJob(t, envWorkflow(""), "refs/heads/main")
		got, err := secretsOf(job)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"LEVEL": "repo", "ORG_ONLY": "org", "REPO_ONLY": "repo"}, got)
		vars, err := varsOf(job)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"LEVEL": "repo", "REPO_ONLY": "repo", "GLOBAL_VAR": "this is a global variable", "REPO_VAR": "this is a repo variable"}, vars)
	})

	t.Run("fail closed without a released deployment", func(t *testing.T) {
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		for name, d := range map[string]*actions_model.ActionDeployment{
			"no deployment":      nil,
			"waiting":            {Status: actions_model.DeploymentWaitingTimer},
			"refused":            {Status: actions_model.DeploymentRefused},
			"cancelled":          {Status: actions_model.DeploymentCancelled},
			"another attempt":    {Status: actions_model.DeploymentReleased, Attempt: 2},
			"another job":        {Status: actions_model.DeploymentReleased, JobID: job.ID + 1},
			"another repo":       {Status: actions_model.DeploymentReleased, RepoID: 1},
			"deleted env":        {Status: actions_model.DeploymentReleased, EnvironmentID: 9999},
			"no environment":     {Status: actions_model.DeploymentReleased, EnvironmentID: 0},
			"another repo's env": {Status: actions_model.DeploymentReleased, EnvironmentID: otherRepoEnvironment(t).ID},
		} {
			_, err := db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
			if d != nil {
				d.RepoID = cmpOr(d.RepoID, 63)
				d.JobID = cmpOr(d.JobID, job.ID)
				d.Attempt = cmpOr(d.Attempt, job.Attempt)
				if name != "deleted env" && name != "no environment" && name != "another repo's env" {
					d.EnvironmentID = prod.ID
				}
				require.NoError(t, db.Insert(ctx, d))
			}
			got, err := secretsOf(job)
			require.ErrorIs(t, err, errEnvironmentNotReleased, name)
			assert.Nil(t, got, name)
			vars, err := varsOf(job)
			require.ErrorIs(t, err, errEnvironmentNotReleased, name)
			assert.Nil(t, vars, name)
		}
	})

	release := func(t *testing.T, job *actions_model.ActionRunJob, env *actions_model.ActionEnvironment) {
		t.Helper()
		_, err := db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{RepoID: 63, EnvironmentID: env.ID, RunID: job.RunID, JobID: job.ID, Attempt: job.Attempt, Status: actions_model.DeploymentReleased}))
	}

	t.Run("a released job gets those of its environment on top, never another's", func(t *testing.T) {
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		release(t, job, prod)
		got, err := secretsOf(job)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"LEVEL": "prod", "ORG_ONLY": "org", "REPO_ONLY": "repo", "PROD_ONLY": "prod"}, got, "environment > repository > project > organization")
		vars, err := varsOf(job)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"LEVEL": "prod", "REPO_ONLY": "repo", "PROD_ONLY": "prod", "GLOBAL_VAR": "this is a global variable", "REPO_VAR": "this is a repo variable"}, vars)

		release(t, job, staging)
		got, err = secretsOf(job)
		require.NoError(t, err)
		assert.Equal(t, "staging", got["STAGING_ONLY"])
		assert.NotContains(t, got, "PROD_ONLY")
		vars, err = varsOf(job)
		require.NoError(t, err)
		assert.NotContains(t, vars, "PROD_ONLY")
	})

	t.Run("a job without an environment doesn't get them even if a deployment of its attempt exists", func(t *testing.T) {
		job := gateJob(t, envWorkflow(""), "refs/heads/main")
		release(t, job, prod)
		got, err := secretsOf(job)
		require.NoError(t, err)
		assert.NotContains(t, got, "PROD_ONLY")
		vars, err := varsOf(job)
		require.NoError(t, err)
		assert.NotContains(t, vars, "PROD_ONLY")
	})

	t.Run("fork pull requests get no secrets, and variables only from pull_request_target", func(t *testing.T) {
		for _, jobID := range []int64{604, 602} { // pull_request of a fork, pull_request_target of a fork
			sws, err := actions_module.JobParser([]byte(envWorkflow("    environment: prod\n")))
			require.NoError(t, err)
			payload, err := sws[0].Marshal()
			require.NoError(t, err)
			_, err = db.GetEngine(ctx).Exec("UPDATE action_run_job SET workflow_payload = ?, environment_name = 'prod', attempt = 1, repo_id = 63 WHERE id = ?", string(payload), jobID)
			require.NoError(t, err)
			job := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: jobID})
			_, err = db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
			require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{RepoID: 63, EnvironmentID: prod.ID, RunID: job.RunID, JobID: job.ID, Attempt: 1, Status: actions_model.DeploymentReleased}))
			got, err := secretsOf(job)
			require.NoError(t, err)
			vars, err := varsOf(job)
			require.NoError(t, err)
			if jobID == 604 {
				assert.Empty(t, got)
				assert.NotContains(t, vars, "PROD_ONLY")
			} else {
				assert.Equal(t, "prod", got["PROD_ONLY"])
				assert.Equal(t, "prod", vars["PROD_ONLY"])
			}
		}
	})
}

func otherRepoEnvironment(t *testing.T) *actions_model.ActionEnvironment {
	t.Helper()
	e := &actions_model.ActionEnvironment{RepoID: 1, Name: "elsewhere"}
	require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(t.Context(), "test"), e))
	return e
}

func cmpOr(v, fallback int64) int64 {
	if v != 0 {
		return v
	}
	return fallback
}

// A job without needs but with an environment starts blocked, and the emitter alone moves it: held while the timer
// runs (without the recursion of the emitter counting it as updated), then released with the labels of the
// environment, or failed by the ref policy.
func TestEmitterEnvironmentJob(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	start := time.Now().Truncate(time.Second)
	timeutil.MockSet(start)
	defer timeutil.MockUnset()
	jobs, err := actions_model.GetRunJobsByRunID(ctx, 900)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	status := func() actions_model.Status {
		return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID}).Status
	}

	newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5, RunnerLabels: []string{"deploy"}})
	gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
	require.NoError(t, checkJobsOfRun(ctx, 900, 0))
	assert.Equal(t, actions_model.StatusBlocked, status(), "held")
	require.NoError(t, checkJobsOfRun(ctx, 900, 0), "and again")
	assert.Equal(t, actions_model.StatusBlocked, status())

	timeutil.MockSet(start.Add(10 * time.Minute))
	require.NoError(t, checkJobsOfRun(ctx, 900, 0))
	released := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID})
	assert.Equal(t, actions_model.StatusWaiting, released.Status)
	assert.Equal(t, []string{"docker", "deploy"}, released.RunsOn, "the labels of the environment are persisted")
	assert.False(t, released.ItRunsOn([]string{"docker"}))
	assert.True(t, released.ItRunsOn([]string{"docker", "deploy"}))

	// the ref policy fails the job
	require.NoError(t, unittest.PrepareTestDatabase())
	newEnvironment(t, patternEnv("locked", actions_model.EnvironmentRefPattern{Type: actions_model.EnvironmentPatternBranch, Pattern: "release/*"}))
	gateJob(t, envWorkflow("    environment: locked\n"), "refs/heads/main")
	require.NoError(t, checkJobsOfRun(ctx, 900, 0))
	assert.Equal(t, actions_model.StatusFailure, status())
	assert.Equal(t, actions_model.DeploymentRefused, deploymentOf(t, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID})).Status)

	// a job without an environment is untouched by all this
	require.NoError(t, unittest.PrepareTestDatabase())
	gateJob(t, envWorkflow(""), "refs/heads/main")
	require.NoError(t, checkJobsOfRun(ctx, 900, 0))
	assert.Equal(t, actions_model.StatusWaiting, status())
	assert.Equal(t, 0, unittest.GetCount(t, &actions_model.ActionDeployment{}))
}

// A job with an environment starts blocked, whatever else it has, and keeps its environment in the stored payload.
func TestConvertEnvironmentJobs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	sws, err := actions_module.JobParser([]byte(`
on: push
jobs:
  plain:
    runs-on: docker
    steps: [{run: echo}]
  deploy:
    runs-on: docker
    environment: {name: Production, url: 'https://example.com'}
    steps: [{run: echo}]
  skipped:
    runs-on: docker
    if: false
    environment: Production
    steps: [{run: echo}]
`))
	require.NoError(t, err)
	jobs, err := convertSingleWorkflowToJobs(&actions_model.ActionRun{ID: 1, RepoID: 63}, sws)
	require.NoError(t, err)
	byID := map[string]*actions_model.ActionRunJob{}
	for _, j := range jobs {
		byID[string(j.JobID)] = j
	}
	assert.Equal(t, actions_model.StatusWaiting, byID["plain"].Status)
	assert.Empty(t, byID["plain"].EnvironmentName)
	assert.Equal(t, actions_model.StatusBlocked, byID["deploy"].Status)
	assert.Equal(t, "Production", byID["deploy"].EnvironmentName)
	assert.Equal(t, actions_model.StatusBlocked, byID["skipped"].Status, "the gate comes after the if of the emitter")
	has, err := jobHasEnvironment(byID["plain"])
	require.NoError(t, err)
	assert.False(t, has)
	env, err := blockedJobEnvironment(byID["deploy"])
	require.NoError(t, err)
	assert.Equal(t, &actions_module.JobEnvironment{Name: "Production", URL: "https://example.com"}, env)
}
