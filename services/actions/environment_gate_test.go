// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"
	"strings"
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
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gateJobID = 600 // a job of repository 63 in the fixtures of TestGetSecretsOfJob

func envWorkflow(environment string) string {
	return "on: push\njobs:\n  produce-artifacts:\n    runs-on: docker\n" + environment + "    steps:\n      - run: echo ${{ secrets.LEVEL }} ${{ secrets.PROD_ONLY }} ${{ secrets.STAGING_ONLY }} ${{ secrets.ORG_ONLY }} ${{ secrets.REPO_ONLY }}\n"
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
	require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(t.Context(), "test"), e, nil))
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
			env, err := actions_model.GetEnvironmentByID(t.Context(), 0, 63, deploymentOf(t, job).EnvironmentID)
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
			env, err := actions_model.GetEnvironmentByID(t.Context(), 0, 63, deploymentOf(t, job).EnvironmentID)
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
				env, err := actions_model.GetEnvironmentByID(t.Context(), 0, 63, d.EnvironmentID)
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
			"empty expression":   "    environment: ${{ inputs.missing }}\n",
			"broken expression":  "    environment: ${{ inputs.( }}\n",
			"control characters": "    environment: \"a\\nb\"\n",
			"too long":           fmt.Sprintf("    environment: %s\n", string(make([]byte, 0))+fmt.Sprintf("%0256d", 1)),
			"unknown context":    "    environment: ${{ matrix.x }}\n",
			"only dots":          "    environment: \"...\"\n",
			"a slash":            "    environment: a/b\n",
			"a percent sign":     "    environment: a%2e\n",
			"a backslash":        "    environment: \"a\\\\b\"\n",
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
		for i := range actions_model.MaxEnvironments {
			_, err := actions_model.GetOrCreateRepoEnvironment(audit_model.WithSystem(t.Context(), "test"), 63, fmt.Sprint("e", i))
			require.NoError(t, err)
		}
		job := gateJob(t, envWorkflow("    environment: one-too-many\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentReasonEnvironmentLimit, deploymentOf(t, job).Reason)
		assert.Equal(t, actions_model.MaxEnvironments, unittest.GetCount(t, &actions_model.ActionEnvironment{}))
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

	t.Run("protected branches of an organization environment: a rule of the repository doesn't count", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		ctx := t.Context()
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = 3 WHERE id = 63")
		require.NoError(t, err)
		require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(ctx, "test"), &actions_model.ActionEnvironment{
			OwnerID: 3, Name: "prod", RefPolicy: actions_model.EnvironmentRefProtectedBranches, RepoIDs: []int64{63},
		}, nil))
		run := func(ref string) behaviour {
			_, err := db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
			b, err := gateEnvironment(ctx, gateJob(t, envWorkflow("    environment: prod\n"), ref))
			require.NoError(t, err)
			return b
		}
		// a repository administrator writes the repository's rules, never the organization owner's policy
		require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: 63, RuleName: "*"}))
		assert.Equal(t, behaviourFailJob, run("refs/heads/attacker"))
		require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{OrgID: 3, RuleName: "main"}))
		assert.Equal(t, behaviourExecuteJob, run("refs/heads/main"), "a rule of the organization")
		assert.Equal(t, behaviourFailJob, run("refs/heads/attacker"))
	})

	t.Run("an organization environment not selected for the repository", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		ctx := t.Context()
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = 3 WHERE id = 63")
		require.NoError(t, err)
		require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(ctx, "test"), &actions_model.ActionEnvironment{OwnerID: 3, Name: "prod", RepoIDs: []int64{3}}, nil))
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		b, err := gateEnvironment(ctx, job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentReasonNotAvailable, deploymentOf(t, job).Reason)
		unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: 63, LowerName: "prod"})
	})

	t.Run("the wait timer", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		start := time.Now().Truncate(time.Second)
		timeutil.MockSet(start)
		defer timeutil.MockUnset()
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
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

		timeutil.MockSet(start.Add(300 * time.Second))
		due, err = actions_model.FindDueDeploymentRunIDs(t.Context(), timeutil.TimeStampNow(), 10)
		require.NoError(t, err)
		assert.Equal(t, []int64{900}, due)
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, deploymentOf(t, job).Status)
	})

	t.Run("a waiting job's release is its ready time plus the current timer: raise holds, lower and remove release", func(t *testing.T) {
		start := time.Now().Truncate(time.Second)
		defer timeutil.MockUnset()
		ctx := audit_model.WithSystem(t.Context(), "test")
		var job *actions_model.ActionRunJob
		// pass sets the timer to minutes, moves the clock to start+at and runs the gate
		pass := func(t *testing.T, minutes int, at time.Duration) (behaviour, *actions_model.ActionDeployment) {
			t.Helper()
			env, err := actions_model.GetEnvironmentByName(t.Context(), 0, 63, "slow")
			require.NoError(t, err)
			if env.WaitTimerMinutes != minutes {
				env.WaitTimerMinutes = minutes
				require.NoError(t, actions_model.UpdateEnvironment(ctx, env, nil))
			}
			timeutil.MockSet(start.Add(at))
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			return b, deploymentOf(t, job)
		}
		setup := func(t *testing.T, minutes int) timeutil.TimeStamp {
			t.Helper()
			require.NoError(t, unittest.PrepareTestDatabase())
			timeutil.MockSet(start)
			newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: minutes})
			job = gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
			b, d := pass(t, minutes, 0)
			require.Equal(t, behaviourHoldJob, b)
			require.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
			require.Equal(t, d.Created+timeutil.TimeStamp(minutes)*60, d.ReleaseAfterUnix)
			return d.Created // the timer counts from when the job became ready
		}

		ready := setup(t, 1)
		b, d := pass(t, 10, 2*time.Minute) // the first timer ended, the raised one holds
		assert.Equal(t, behaviourHoldJob, b)
		assert.Equal(t, actions_model.DeploymentWaitingTimer, d.Status)
		assert.Equal(t, ready+600, d.ReleaseAfterUnix, "stored")
		b, d = pass(t, 5, 3*time.Minute) // lowered: it now runs to ready+5 minutes
		assert.Equal(t, behaviourHoldJob, b)
		assert.Equal(t, ready+300, d.ReleaseAfterUnix)
		b, d = pass(t, 2, 3*time.Minute) // lowered below the time waited: released at once
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, d.Status)

		setup(t, 60)
		b, d = pass(t, 0, time.Minute) // removed: released at once
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, d.Status)
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
		require.NoError(t, actions_model.UpdateEnvironment(audit_model.WithSystem(t.Context(), "test"), env, nil))
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
		require.NoError(t, DeleteEnvironment(audit_model.WithSystem(t.Context(), "test"), env))
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
		cfg, err := setting.NewConfigProviderFromData("[queue.actions_ready_job]\nTYPE = channel\n")
		require.NoError(t, err)
		defer test.MockVariableValue(&setting.CfgProvider, cfg)()
		q := queue.CreateUniqueQueue(t.Context(), "actions_ready_job", func(items ...*jobUpdate) []*jobUpdate { return nil })
		require.NotNil(t, q)
		defer test.MockVariableValue(&jobEmitterQueue, q)()

		newEnvironment(t, &actions_model.ActionEnvironment{Name: "slow", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: slow\n"), "refs/heads/main")
		run, err := actions_model.GetRunByID(t.Context(), job.RunID)
		require.NoError(t, err)
		require.NoError(t, ApproveRun(audit_model.WithSystem(t.Context(), "test"), run, 2))
		job = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID})
		assert.Equal(t, actions_model.StatusBlocked, job.Status)
		assert.Nil(t, deploymentOf(t, job), "the approval doesn't gate, the emitter does, after the commit")
		has, err := q.Has(&jobUpdate{RunID: job.RunID})
		require.NoError(t, err)
		assert.True(t, has, "the run is queued for the emitter")

		require.NoError(t, checkJobsOfRun(t.Context(), job.RunID, 0))
		assert.Equal(t, actions_model.StatusBlocked, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: gateJobID}).Status)
		assert.Equal(t, actions_model.DeploymentWaitingTimer, deploymentOf(t, job).Status)
	})

	t.Run("a fork pull request never creates an environment", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		newEnvironment(t, &actions_model.ActionEnvironment{Name: "known"})
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET is_fork_pull_request = ?, trigger_event = ? WHERE id = 900", true, "pull_request")
		require.NoError(t, err)
		job := gateJob(t, envWorkflow("    environment: unknown\n"), "refs/pull/1/head")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		d := deploymentOf(t, job)
		assert.Equal(t, actions_model.DeploymentRefused, d.Status)
		assert.Equal(t, actions_model.DeploymentReasonNotFound, d.Reason)
		assert.Equal(t, 1, unittest.GetCount(t, &actions_model.ActionEnvironment{}), "nothing was created")

		// an environment that exists is found; pull_request_target creates like any other run
		job = gateJob(t, envWorkflow("    environment: KNOWN\n"), "refs/pull/1/head")
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run SET trigger_event = ? WHERE id = 900", "pull_request_target")
		require.NoError(t, err)
		job = gateJob(t, envWorkflow("    environment: made-here\n"), "refs/pull/1/head")
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run SET trigger_event = ? WHERE id = 900", "pull_request_target")
		require.NoError(t, err)
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, 2, unittest.GetCount(t, &actions_model.ActionEnvironment{}))
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
			_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, s.repo, s.env, s.name, s.value)
		} else {
			_, err = secret_model.InsertEncryptedSecret(ctx, s.owner, s.group, s.repo, s.name, s.value)
		}
		require.NoError(t, err)
	}
	_, err = actions_model.InsertVariable(ctx, 0, 0, 63, "LEVEL", "repo")
	require.NoError(t, err)
	_, err = actions_model.InsertVariable(ctx, 0, 0, 63, "REPO_ONLY", "repo")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 0, 63, prod.ID, "LEVEL", "prod")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 0, 63, prod.ID, "PROD_ONLY", "prod")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 0, 63, staging.ID, "STAGING_ONLY", "staging")
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

	t.Run("a task reads the deployment of its own attempt", func(t *testing.T) {
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		release(t, job, prod)
		task := &actions_model.ActionTask{Job: job, Attempt: job.Attempt}
		_, err := getSecretsOfJob(ctx, jobOfTask(task))
		require.NoError(t, err)
		task.Attempt = job.Attempt + 1 // the row says one thing, the task another
		_, err = getSecretsOfJob(ctx, jobOfTask(task))
		require.ErrorIs(t, err, errEnvironmentNotReleased)
		_, err = getVariablesOfJob(ctx, jobOfTask(task))
		require.ErrorIs(t, err, errEnvironmentNotReleased)
	})

	t.Run("another failure is not a refusal of the gate: the job stays queued", func(t *testing.T) {
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		release(t, job, prod)
		rows, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: 63, EnvironmentID: prod.ID})
		require.NoError(t, err)
		require.NotEmpty(t, rows)
		defer func() {
			for _, row := range rows {
				_, err := db.GetEngine(ctx).Exec("UPDATE secret SET data = ? WHERE id = ?", row.Data, row.ID)
				require.NoError(t, err)
			}
		}()
		_, err = db.GetEngine(ctx).Exec("UPDATE secret SET data = 'x' WHERE environment_id = ?", prod.ID)
		require.NoError(t, err)
		got, err := secretsOf(job)
		require.Error(t, err)
		require.NotErrorIs(t, err, errEnvironmentNotReleased)
		assert.Nil(t, got)
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
	require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(t.Context(), "test"), e, nil))
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

func TestGateAllowedWorkflows(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	setWorkflow := func(t *testing.T, id string) {
		t.Helper()
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET workflow_id = ? WHERE id = 900", id)
		require.NoError(t, err)
	}
	for _, tc := range []struct {
		name     string
		allowed  []string
		workflow string
		ok       bool
	}{
		{"no list allows every workflow", nil, "anything.yml", true},
		{"the file name", []string{"deploy.yml"}, "deploy.yml", true},
		{"another file", []string{"deploy.yml"}, "ci.yml", false},
		{"a pattern", []string{"deploy-*.yml"}, "deploy-prod.yml", true},
		{"a pattern, another file", []string{"deploy-*.yml"}, "build-prod.yml", false},
		{"the star stops at a slash", []string{"deploy-*.yml"}, "deploy-x/y.yml", false},
		{"one of several", []string{"a.yml", "b.yml"}, "b.yml", true},
		{"a longer name is no match", []string{"deploy.yml"}, "deploy.yml.bak", false},
		{"case matters", []string{"deploy.yml"}, "Deploy.yml", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			env := newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod", AllowedWorkflows: tc.allowed})
			_, err := secret_model.InsertEncryptedEnvironmentSecret(audit_model.WithSystem(t.Context(), "test"), 0, 63, env.ID, "ENV_SECRET", "x")
			require.NoError(t, err)
			job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
			setWorkflow(t, tc.workflow)
			since := auditSince(t)
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			d := deploymentOf(t, job)
			if tc.ok {
				assert.Equal(t, behaviourExecuteJob, b)
				assert.Equal(t, actions_model.DeploymentReleased, d.Status)
				return
			}
			assert.Equal(t, behaviourFailJob, b)
			assert.Equal(t, actions_model.DeploymentRefused, d.Status)
			assert.Equal(t, actions_model.DeploymentReasonWorkflowNotAllowed, d.Reason)
			assert.Len(t, auditRefused(t, since), 1)
			secrets, err := getEnvironmentSecrets(t.Context(), job)
			require.ErrorIs(t, err, errEnvironmentNotReleased, "a refused job gets no secret of the environment")
			assert.Nil(t, secrets)
		})
	}

	t.Run("the rule applies to a job that waits, as it is when looked at again", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		env := newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod", WaitTimerMinutes: 5})
		job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
		b, err := gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		require.Equal(t, behaviourHoldJob, b)
		env.AllowedWorkflows = []string{"deploy.yml"}
		require.NoError(t, actions_model.UpdateEnvironment(audit_model.WithSystem(t.Context(), "test"), env, nil))
		b, err = gateEnvironment(t.Context(), job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentReasonWorkflowNotAllowed, deploymentOf(t, job).Reason)
	})

	t.Run("a job of a reusable workflow is decided by the file of the run, not by the called file", func(t *testing.T) {
		caller := "on: push\njobs:\n  call:\n    uses: ./deploy.yml\n"
		called := "on:\n  workflow_call:\njobs:\n  deploy:\n    runs-on: docker\n    environment: prod\n    steps: [{run: echo}]\n"
		fetch := func(job *jobparser.Job, path string) ([]byte, error) { return []byte(called), nil }
		for _, tc := range []struct {
			run string
			ok  bool
		}{{"ci.yml", false}, {"release.yml", true}} {
			require.NoError(t, unittest.PrepareTestDatabase())
			// the called file is named deploy.yml, the pattern allows only release.yml: the run's file decides
			newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod", AllowedWorkflows: []string{"release.yml"}})
			r := actions_module.ReusableWorkflows{}
			sws, err := r.JobParser([]byte(caller), r.ExpandLocal(fetch), jobparser.EnableNamespaces())
			require.NoError(t, err)
			var job *actions_model.ActionRunJob
			for _, sw := range sws {
				if id, _ := sw.Job(); id == "deploy" {
					job = gateSingle(t, sw, "refs/heads/main")
				}
			}
			require.NotNil(t, job)
			setWorkflow(t, tc.run)
			b, err := gateEnvironment(t.Context(), job)
			require.NoError(t, err)
			if tc.ok {
				assert.Equal(t, behaviourExecuteJob, b, tc.run)
			} else {
				assert.Equal(t, behaviourFailJob, b, tc.run)
				assert.Equal(t, actions_model.DeploymentReasonWorkflowNotAllowed, deploymentOf(t, job).Reason)
			}
		}
	})
}

func TestEnvironmentSecretsReferencedByName(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	prod := newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod"})
	for name, value := range map[string]string{"DEPLOY_KEY": "env-key", "OTHER": "env-other", "SHARED": "env-shared"} {
		_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 63, prod.ID, name, value)
		require.NoError(t, err)
	}
	_, err := secret_model.InsertEncryptedSecret(ctx, 0, 0, 63, "SHARED", "repo-shared")
	require.NoError(t, err)
	_, err = secret_model.InsertEncryptedSecret(ctx, 0, 0, 63, "REPO_ONLY", "repo-only")
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		step string
		want map[string]string
	}{
		{"a literal reference", "echo ${{ secrets.DEPLOY_KEY }}", map[string]string{"DEPLOY_KEY": "env-key", "SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
		{"an index with a string", "echo ${{ secrets['DEPLOY_KEY'] }}", map[string]string{"DEPLOY_KEY": "env-key", "SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
		{"the environment secret wins over the repository's of the same name", "echo ${{ secrets.SHARED }}", map[string]string{"SHARED": "env-shared", "REPO_ONLY": "repo-only"}},
		{"no reference", "echo hi", map[string]string{"SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
		{"toJSON(secrets)", "echo '${{ toJSON(secrets) }}' ${{ secrets.DEPLOY_KEY }}", map[string]string{"SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
		{"a computed index", "echo ${{ secrets[format('{0}_KEY', 'DEPLOY')] }}", map[string]string{"SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
		{"a name from the matrix", "echo ${{ secrets[matrix.key] }}", map[string]string{"SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
		{"the whole context", "echo ${{ secrets.* }}", map[string]string{"SHARED": "repo-shared", "REPO_ONLY": "repo-only"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wf := "on: push\njobs:\n  produce-artifacts:\n    runs-on: docker\n    environment: prod\n    steps:\n      - run: \"" + strings.ReplaceAll(tc.step, `"`, `\"`) + "\"\n"
			job := gateJob(t, wf, "refs/heads/main")
			_, err := db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
			require.NoError(t, err)
			require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{RepoID: 63, EnvironmentID: prod.ID, RunID: job.RunID, JobID: job.ID, Attempt: job.Attempt, Status: actions_model.DeploymentReleased}))
			got, err := getSecretsOfJob(ctx, job)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("secrets: inherit gets none", func(t *testing.T) {
		wf := "on: push\njobs:\n  produce-artifacts:\n    runs-on: docker\n    environment: prod\n    secrets: inherit\n    steps:\n      - run: echo ${{ secrets.DEPLOY_KEY }}\n"
		job := gateJob(t, wf, "refs/heads/main")
		_, err := db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{RepoID: 63, EnvironmentID: prod.ID, RunID: job.RunID, JobID: job.ID, Attempt: job.Attempt, Status: actions_model.DeploymentReleased}))
		got, err := getSecretsOfJob(ctx, job)
		require.NoError(t, err)
		assert.NotContains(t, got, "DEPLOY_KEY")
		assert.NotContains(t, got, "OTHER")
	})
}

func TestOIDCSubjectOfAnEnvironment(t *testing.T) {
	gitCtx := map[string]any{
		"repository": "org/project/repo", "repository_owner": "org", "repository_owner_id": "3", "repository_id": "63",
		"event_name": "push", "ref": "refs/heads/main",
	}
	assert.Equal(t, "repo:org-3/repo-63:ref:refs/heads/main", generateOIDCSub(gitCtx))
	assert.Equal(t, "repo:org/project/repo:ref:refs/heads/main", legacyGenerateOIDCSub(gitCtx))

	gitCtx["environment"] = "production"
	assert.Equal(t, "repo:org-3/repo-63:environment:production", generateOIDCSub(gitCtx), "the environment replaces the ref")
	assert.Equal(t, "repo:org/project/repo:environment:production", legacyGenerateOIDCSub(gitCtx))
	gitCtx["event_name"] = "pull_request"
	assert.Equal(t, "repo:org-3/repo-63:environment:production", generateOIDCSub(gitCtx), "and the pull request")

	extra, err := generateOIDCExtra(gitCtx)
	require.NoError(t, err)
	assert.Contains(t, extra, `"environment":"production"`)
	delete(gitCtx, "environment")
	extra, err = generateOIDCExtra(gitCtx)
	require.NoError(t, err)
	assert.NotContains(t, extra, "environment")
}

// A job marked unsupported (an inner job of a reusable workflow whose file wasn't read) is stored with an empty name:
// the emitter, which parses the stored job again, must fail that job alone, not the run.
func TestEmitterUnsupportedEnvironmentJobFailsAlone(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")

	caller := "on: push\njobs:\n  call:\n    uses: ./called.yml\n"
	called := "on: workflow_call\njobs:\n  deploy:\n    runs-on: docker\n    environment: prod\n    steps: [{run: echo}]\n"
	sws, err := actions_module.ReusableWorkflows{}.JobParser([]byte(caller),
		// a fetcher that doesn't remember what it read, so the environment of the file is unknown
		jobparser.ExpandLocalReusableWorkflows(func(*jobparser.Job, string) ([]byte, error) { return []byte(called), nil }),
		jobparser.EnableNamespaces())
	require.NoError(t, err)
	var inner *jobparser.SingleWorkflow
	for _, sw := range sws {
		if id, _ := sw.Job(); id == "deploy" {
			inner = sw
		}
	}
	require.NotNil(t, inner)
	env, err := actions_module.GetJobEnvironment(inner)
	require.NoError(t, err)
	require.Equal(t, &actions_module.JobEnvironment{Unsupported: true}, env, "marked unsupported, with an empty name")
	job := gateSingle(t, inner, "refs/heads/main")

	sibling := *job
	sibling.ID, sibling.JobID, sibling.Name, sibling.Handle = 0, "sibling", "sibling", "sibling-handle"
	siblingWorkflow, err := actions_module.JobParser([]byte(envWorkflow("")))
	require.NoError(t, err)
	payload, err := siblingWorkflow[0].Marshal()
	require.NoError(t, err)
	sibling.WorkflowPayload, sibling.EnvironmentName = payload, ""
	require.NoError(t, db.Insert(t.Context(), &sibling))

	require.NoError(t, checkJobsOfRun(ctx, 900, 0))

	failed := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: job.ID})
	assert.Equal(t, actions_model.StatusFailure, failed.Status)
	d := deploymentOf(t, failed)
	require.NotNil(t, d)
	assert.Equal(t, actions_model.DeploymentRefused, d.Status)
	assert.Equal(t, actions_model.DeploymentReasonUnsupported, d.Reason)
	ok := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: sibling.ID})
	assert.Equal(t, actions_model.StatusWaiting, ok.Status, "the sibling without an environment is released")
	run := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: 900})
	assert.Zero(t, run.PreExecutionErrorCode, "the run has no workflow error")
}

// Only a text that can't be evaluated is an invalid name; an error of the stored payload (or the database) is not, so
// the pass of the emitter is repeated instead of refusing the job for good.
func TestEvaluateEnvironmentTextErrors(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
	require.NoError(t, job.LoadRun(t.Context()))
	require.NoError(t, job.Run.LoadRepo(t.Context()))

	name, err := evaluateEnvironmentText(t.Context(), job, nil, "plain")
	require.NoError(t, err)
	assert.Equal(t, "plain", name)

	broken := *job
	broken.WorkflowPayload = []byte("{{{ not yaml")
	_, err = evaluateEnvironmentText(t.Context(), &broken, nil, "${{ vars.X }}")
	require.Error(t, err)
	assert.NotErrorIs(t, err, errInvalidEnvironmentText)
}

// Runs whose pass of the gate fails every tick, more of them than one tick takes, don't hold back a due deployment of
// another repository: each tick moves the runs it looked at to the back of the line, whatever their pass did.
func TestStuckRunsDontStarveTheDueTask(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&maxDueDeploymentRuns, 2)()
	ctx := audit_model.WithSystem(t.Context(), "test")

	// the other repository: a job of run 900 whose wait timer ended
	newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod", WaitTimerMinutes: 1})
	job := gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
	b, err := gateEnvironment(ctx, job)
	require.NoError(t, err)
	require.Equal(t, behaviourHoldJob, b)
	_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET release_after_unix = 1, created = created - 86400, updated = ? WHERE job_id = ?", timeutil.TimeStampNow()-60, job.ID)
	require.NoError(t, err)
	// three stuck runs of repository 4 that wait longer: their pass never moves them (a job whose `if:` errors)
	for i := range int64(3) {
		stuck := &actions_model.ActionRunJob{RunID: 7001 + i, RepoID: 4, OwnerID: 1, Attempt: 1, JobID: "deploy", Status: actions_model.StatusBlocked, Handle: fmt.Sprintf("stuck-%d", i)}
		require.NoError(t, db.Insert(ctx, stuck))
		d := &actions_model.ActionDeployment{RepoID: 4, RunID: stuck.RunID, JobID: stuck.ID, Attempt: 1, Status: actions_model.DeploymentWaitingTimer, ReleaseAfterUnix: 1}
		require.NoError(t, db.Insert(ctx, d))
		_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET updated = ? WHERE id = ?", timeutil.TimeStampNow()-3600+timeutil.TimeStamp(i), d.ID)
		require.NoError(t, err)
	}

	// the queue's pass: it fails for the stuck runs and gates the other one
	cfg, err := setting.NewConfigProviderFromData("[queue.actions_ready_job]\nTYPE = immediate\n")
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.CfgProvider, cfg)()
	var passes []int64
	q := queue.CreateUniqueQueue(t.Context(), "actions_ready_job", func(items ...*jobUpdate) []*jobUpdate {
		for _, item := range items {
			passes = append(passes, item.RunID)
			if item.RunID == job.RunID {
				_, err := gateEnvironment(ctx, job)
				assert.NoError(t, err)
			}
		}
		return nil
	})
	require.NotNil(t, q)
	defer test.MockVariableValue(&jobEmitterQueue, q)()

	for tick := 0; tick < 2 && deploymentOf(t, job).Status != actions_model.DeploymentReleased; tick++ {
		timeutil.MockSet(time.Now().Add(time.Duration(tick) * time.Minute))
		require.NoError(t, StartDueDeployments(ctx))
	}
	timeutil.MockUnset()
	assert.Equal(t, []int64{7001, 7002, 7003, job.RunID}, passes, "each in turn")
	assert.Equal(t, actions_model.DeploymentReleased, deploymentOf(t, job).Status)
}
