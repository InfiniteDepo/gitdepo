// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestWorkflowTokenPermissions(t *testing.T) {
	read, write := perm.AccessModeRead, perm.AccessModeWrite
	contents := func(mode perm.AccessMode) actions_model.TokenPermissions {
		return actions_model.TokenPermissions{unit.TypeCode: mode, unit.TypeReleases: mode, unit.TypeWiki: mode}
	}

	for _, tc := range []struct {
		name     string
		workflow string
		want     actions_model.TokenPermissions
		ignored  []string
	}{
		{name: "absent", workflow: "jobs: {j: {runs-on: x}}", want: nil},
		{name: "null", workflow: "permissions:\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}, ignored: []string{"permissions"}},
		{name: "empty", workflow: "permissions: {}\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}},
		{name: "contents read", workflow: "permissions: {contents: read}\njobs: {j: {runs-on: x}}", want: contents(read)},
		{name: "contents write", workflow: "permissions: {contents: write}\njobs: {j: {runs-on: x}}", want: contents(write)},
		{name: "contents none", workflow: "permissions: {contents: none}\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}},
		{
			name:     "each key",
			workflow: "permissions: {issues: write, pull-requests: read, actions: write, repository-projects: read}\njobs: {j: {runs-on: x}}",
			want:     actions_model.TokenPermissions{unit.TypeIssues: write, unit.TypePullRequests: read, unit.TypeActions: write, unit.TypeProjects: read},
		},
		{name: "read-all", workflow: "permissions: read-all\njobs: {j: {runs-on: x}}", want: allTokenPermissions(read)},
		{name: "write-all", workflow: "permissions: write-all\njobs: {j: {runs-on: x}}", want: allTokenPermissions(write)},
		{name: "other scalar", workflow: "permissions: write\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}, ignored: []string{"permissions"}},
		{name: "sequence", workflow: "permissions: [contents]\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}, ignored: []string{"permissions"}},
		{name: "case", workflow: "permissions: {Contents: Write}\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}, ignored: []string{"Contents"}},
		{
			name:     "invalid value",
			workflow: "permissions: {contents: banana, issues: write}\njobs: {j: {runs-on: x}}",
			want:     actions_model.TokenPermissions{unit.TypeIssues: write},
			ignored:  []string{"contents"},
		},
		{
			name:     "invalid value after valid",
			workflow: "permissions: {issues: write}\njobs: {j: {runs-on: x, permissions: {issues: [write]}}}",
			want:     actions_model.TokenPermissions{},
			ignored:  []string{"issues"},
		},
		{
			name:     "ignored keys",
			workflow: "permissions: {packages: write, statuses: write, id-token: write, unknown: read, contents: read}\njobs: {j: {runs-on: x}}",
			want:     contents(read),
			ignored:  []string{"packages", "statuses", "id-token", "unknown"},
		},
		{name: "only ignored keys", workflow: "permissions: {packages: write}\njobs: {j: {runs-on: x}}", want: actions_model.TokenPermissions{}, ignored: []string{"packages"}},
		{
			name:     "job replaces workflow",
			workflow: "permissions: write-all\njobs: {j: {runs-on: x, permissions: {issues: read}}}",
			want:     actions_model.TokenPermissions{unit.TypeIssues: read},
		},
		{name: "job empty replaces workflow", workflow: "permissions: write-all\njobs: {j: {runs-on: x, permissions: {}}}", want: actions_model.TokenPermissions{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swfs, err := jobparser.Parse([]byte(tc.workflow), false)
			require.NoError(t, err)
			require.Len(t, swfs, 1)
			// round trip through the stored payload, as CreateTaskForRunner reads it
			payload, err := swfs[0].Marshal()
			require.NoError(t, err)
			job := &actions_model.ActionRunJob{WorkflowPayload: payload}
			swf, err := job.DecodeWorkflowPayload()
			require.NoError(t, err)

			got, ignored := workflowTokenPermissions(swf, "write")
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.ignored, ignored)
			if tc.want != nil {
				assert.NotEmpty(t, got.Encode())
			}
		})
	}

	t.Run("alias", func(t *testing.T) {
		got, ignored := parseTokenPermissions(&yaml.Node{Kind: yaml.AliasNode, Alias: &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "write-all"}})
		assert.Equal(t, actions_model.TokenPermissions{}, got)
		assert.Equal(t, []string{"permissions"}, ignored)
	})

	t.Run("default read", func(t *testing.T) {
		swfs, err := jobparser.Parse([]byte("jobs: {j: {runs-on: x}}"), false)
		require.NoError(t, err)
		got, ignored := workflowTokenPermissions(swfs[0], "read")
		assert.Equal(t, allTokenPermissions(read), got)
		assert.Empty(t, ignored)

		// a default, not a cap
		swfs, err = jobparser.Parse([]byte("permissions: write-all\njobs: {j: {runs-on: x}}"), false)
		require.NoError(t, err)
		got, _ = workflowTokenPermissions(swfs[0], "read")
		assert.Equal(t, allTokenPermissions(write), got)
	})
}

func TestJobTokenPermissions(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	read, write := perm.AccessModeRead, perm.AccessModeWrite

	// insertRun stores the jobs of a workflow that calls the reusable workflows in callees (by path), and returns
	// the job named name.
	insertRun := func(t *testing.T, isFork bool, workflow string, callees map[string]string) map[string]*actions_model.ActionRunJob {
		t.Helper()
		run := &actions_model.ActionRun{RepoID: 10, OwnerID: 3, IsForkPullRequest: isFork}
		swfs, err := jobparser.Parse([]byte(workflow), false,
			jobparser.WithJobOutputs(map[string]map[string]string{}),
			jobparser.ExpandLocalReusableWorkflows(func(job *jobparser.Job, path string) ([]byte, error) {
				return []byte(callees[path]), nil
			}))
		require.NoError(t, err)
		jobs, err := convertSingleWorkflowToJobs(run, swfs)
		require.NoError(t, err)
		require.NoError(t, actions_model.InsertRunWithoutNotification(t.Context(), run, jobs))
		byName := map[string]*actions_model.ActionRunJob{}
		for _, j := range jobs {
			j.Run = run
			j.IsForkPullRequest = isFork
			byName[j.Name] = j
		}
		return byName
	}
	get := func(t *testing.T, job *actions_model.ActionRunJob) actions_model.TokenPermissions {
		t.Helper()
		p, err := jobTokenPermissions(t.Context(), job)
		require.NoError(t, err)
		return p
	}

	t.Run("legacy", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {j: {runs-on: x, steps: []}}", nil)
		assert.Nil(t, get(t, jobs["j"]))
	})
	t.Run("legacy fork", func(t *testing.T) {
		jobs := insertRun(t, true, "jobs: {j: {runs-on: x, steps: []}}", nil)
		assert.Nil(t, get(t, jobs["j"]))
	})
	t.Run("fork write-all", func(t *testing.T) {
		jobs := insertRun(t, true, "permissions: write-all\njobs: {j: {runs-on: x, steps: []}}", nil)
		assert.Equal(t, allTokenPermissions(read), get(t, jobs["j"]))
	})
	t.Run("fork default read", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Actions.DefaultTokenPermissions, "read")()
		jobs := insertRun(t, true, "jobs: {j: {runs-on: x, steps: []}}", nil)
		assert.Equal(t, allTokenPermissions(read), get(t, jobs["j"]))
	})

	const callee = "on: {workflow_call: {}}\njobs: {inner: {runs-on: x, steps: []}}"
	const calleeWriteAll = "on: {workflow_call: {}}\njobs: {inner: {runs-on: x, steps: [], permissions: write-all}}"

	t.Run("caller permissions survive in the outer payload", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./callee.yml, permissions: {contents: read}}}",
			map[string]string{"./callee.yml": callee})
		swf, err := jobs["outer"].DecodeWorkflowPayload()
		require.NoError(t, err)
		_, job := swf.Job()
		assert.NotZero(t, job.Permissions.Kind)
	})
	t.Run("inner callee without permissions", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./callee.yml, permissions: {contents: read}}}",
			map[string]string{"./callee.yml": callee})
		assert.Equal(t, actions_model.TokenPermissions{unit.TypeCode: read, unit.TypeReleases: read, unit.TypeWiki: read}, get(t, jobs["inner"]))
	})
	t.Run("inner callee write-all", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./callee.yml, permissions: {issues: write}}}",
			map[string]string{"./callee.yml": calleeWriteAll})
		p := get(t, jobs["inner"])
		assert.Equal(t, write, p[unit.TypeIssues])
		assert.Equal(t, perm.AccessModeNone, p[unit.TypeCode])
	})
	t.Run("inner legacy", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./callee.yml}}", map[string]string{"./callee.yml": callee})
		assert.Nil(t, get(t, jobs["inner"]))
	})
	t.Run("inner legacy caller", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./callee.yml}}", map[string]string{"./callee.yml": calleeWriteAll})
		assert.Equal(t, allTokenPermissions(write), get(t, jobs["inner"]))
	})
	t.Run("nested", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./middle.yml, permissions: {contents: read, issues: write}}}",
			map[string]string{
				"./middle.yml": "on: {workflow_call: {}}\njobs: {middle: {uses: ./callee.yml, permissions: write-all}}",
				"./callee.yml": calleeWriteAll,
			})
		p := get(t, jobs["inner"])
		assert.Equal(t, read, p[unit.TypeCode])
		assert.Equal(t, write, p[unit.TypeIssues])
		assert.Equal(t, perm.AccessModeNone, p[unit.TypeActions])
	})
	t.Run("fork inner", func(t *testing.T) {
		jobs := insertRun(t, true, "jobs: {outer: {uses: ./callee.yml, permissions: write-all}}", map[string]string{"./callee.yml": callee})
		assert.Equal(t, allTokenPermissions(read), get(t, jobs["inner"]))
	})
	t.Run("workflow call loop", func(t *testing.T) {
		run := &actions_model.ActionRun{RepoID: 10, OwnerID: 3}
		jobs := []*actions_model.ActionRunJob{
			{Name: "a", JobID: "a", RepoID: 10, OwnerID: 3, Handle: "loop-a", WorkflowPayload: []byte("__metadata: {workflow_call_id: a, workflow_call_parent: b}\njobs: {a: {runs-on: x}}\n")},
			{Name: "b", JobID: "b", RepoID: 10, OwnerID: 3, Handle: "loop-b", WorkflowPayload: []byte("__metadata: {workflow_call_id: b, workflow_call_parent: a}\njobs: {b: {runs-on: x}}\n")},
		}
		require.NoError(t, actions_model.InsertRunWithoutNotification(t.Context(), run, jobs))
		jobs[0].Run = run
		_, err := jobTokenPermissions(t.Context(), jobs[0])
		require.ErrorContains(t, err, "workflow call loop")
	})
	t.Run("outer lookup fails", func(t *testing.T) {
		jobs := insertRun(t, false, "jobs: {outer: {uses: ./callee.yml, permissions: {contents: read}}}",
			map[string]string{"./callee.yml": callee})
		require.NoError(t, actions_model.DeleteJob(t.Context(), jobs["outer"].ID))
		_, err := jobTokenPermissions(t.Context(), jobs["inner"])
		require.Error(t, err)
	})
}

func TestCalculateWarningsTokenPermissions(t *testing.T) {
	swfs, err := jobparser.Parse([]byte(`
permissions: {contents: read}
jobs:
  supported: {runs-on: x}
  ignored: {runs-on: x, permissions: {packages: write, issues: banana}}
  absent-overrides: {runs-on: x, permissions: write-all}
`), false)
	require.NoError(t, err)
	run := &actions_model.ActionRun{}
	calculateWarnings(run, swfs)
	assert.Equal(t, []actions_model.PreExecutionWarning{actions_model.WarningCodePermissionsIgnored}, run.PreExecutionWarningCodes)
	assert.Equal(t, [][]any{{"ignored", "packages, issues"}}, run.PreExecutionWarningDetails)
}

func TestCreateTaskForRunnerTokenPermissions(t *testing.T) {
	for _, tc := range []struct {
		name, permissions, defaultPermissions, repoDefault, want string
		isFork                                                   bool
	}{
		{name: "legacy", defaultPermissions: "write", want: ""},
		{name: "default read", defaultPermissions: "read", want: allTokenPermissions(perm.AccessModeRead).Encode()},
		{name: "empty", permissions: "permissions: {}\n", defaultPermissions: "write", want: "{}"},
		{name: "issues", permissions: "permissions: {issues: write}\n", defaultPermissions: "read", want: `{"2":2}`},
		{name: "repo read", defaultPermissions: "write", repoDefault: "read", want: allTokenPermissions(perm.AccessModeRead).Encode()},
		{name: "repo write", defaultPermissions: "read", repoDefault: "write", want: ""},
		{name: "repo read is no cap", permissions: "permissions: {issues: write}\n", defaultPermissions: "write", repoDefault: "read", want: `{"2":2}`},
		{name: "repo read fork", defaultPermissions: "write", repoDefault: "read", isFork: true, want: allTokenPermissions(perm.AccessModeRead).Encode()},
		{name: "repo write fork", defaultPermissions: "read", repoDefault: "write", isFork: true, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer unittest.OverrideFixtures("services/actions/TestCreateTaskForRunner")()
			require.NoError(t, unittest.PrepareTestDatabase())
			defer test.MockVariableValue(&setting.Actions.DefaultTokenPermissions, tc.defaultPermissions)()

			runner := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{ID: 41601})
			job := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 47301})
			job.WorkflowPayload = []byte(tc.permissions + "jobs:\n  build:\n    runs-on: debian\n    steps:\n      - run: echo\n")
			job.IsForkPullRequest = tc.isFork
			_, err := db.GetEngine(t.Context()).ID(job.ID).Cols("workflow_payload", "is_fork_pull_request").Update(job)
			require.NoError(t, err)
			actionsUnit := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: job.RepoID, Type: unit.TypeActions})
			actionsUnit.ActionsConfig().DefaultTokenPermissions = tc.repoDefault
			require.NoError(t, repo_model.UpdateRepoUnit(t.Context(), actionsUnit))

			task, err := CreateTaskForRunner(t.Context(), runner, nil, nil)
			require.NoError(t, err)
			stored := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: task.ID})
			assert.Equal(t, tc.want, stored.TokenPermissions)
			assert.Equal(t, tc.isFork, stored.IsForkPullRequest)
		})
	}
}
