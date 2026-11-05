// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	"forgejo.org/modules/util"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func environmentOf(t *testing.T, sw *jobparser.SingleWorkflow) *JobEnvironment {
	t.Helper()
	env, err := GetJobEnvironment(sw)
	require.NoError(t, err)
	return env
}

func TestJobParserKeepsEnvironment(t *testing.T) {
	workflow := `
on: push
jobs:
  plain:
    runs-on: docker
    steps: [{run: echo}]
  short:
    runs-on: docker
    environment: Production
    steps: [{run: echo}]
  long:
    runs-on: docker
    environment:
      name: staging-${{ inputs.x }}
      url: https://example.com/${{ vars.PATH }}
    steps: [{run: echo}]
  matrix:
    runs-on: docker
    environment: ${{ matrix.target }}
    strategy:
      matrix:
        target: [a, b]
    steps: [{run: echo}]
`
	sws, err := JobParser([]byte(workflow))
	require.NoError(t, err)
	got := map[string][]*JobEnvironment{}
	for _, sw := range sws {
		id, _ := sw.Job()
		got[id] = append(got[id], environmentOf(t, sw))
	}
	require.Len(t, got["plain"], 1)
	assert.Nil(t, got["plain"][0])
	assert.Equal(t, []*JobEnvironment{{Name: "Production"}}, got["short"])
	assert.Equal(t, []*JobEnvironment{{Name: "staging-${{ inputs.x }}", URL: "https://example.com/${{ vars.PATH }}"}}, got["long"])
	assert.Equal(t, []*JobEnvironment{{Name: "${{ matrix.target }}"}, {Name: "${{ matrix.target }}"}}, got["matrix"], "every job of a matrix has it")

	// it is in the payload that is stored, and read back from it
	for _, sw := range sws {
		if id, _ := sw.Job(); id != "long" {
			continue
		}
		payload, err := sw.Marshal()
		require.NoError(t, err)
		assert.Contains(t, string(payload), "environment:")
		var decoded jobparser.SingleWorkflow
		require.NoError(t, yaml.Unmarshal(payload, &decoded))
		assert.Equal(t, &JobEnvironment{Name: "staging-${{ inputs.x }}", URL: "https://example.com/${{ vars.PATH }}"}, environmentOf(t, &decoded))
	}
}

// jobparser's SetJob rewrites the job and drops the environment: SetJobEnvironment puts it back.
func TestSetJobEnvironmentAfterSetJob(t *testing.T) {
	sws, err := JobParser([]byte("on: push\njobs:\n  a:\n    runs-on: docker\n    environment: prod\n    steps: [{run: echo}]\n"))
	require.NoError(t, err)
	require.Len(t, sws, 1)
	sw := sws[0]
	env := environmentOf(t, sw)
	require.NotNil(t, env)
	id, job := sw.Job()
	require.NoError(t, sw.SetJob(id, job.EraseNeeds()))
	assert.Nil(t, environmentOf(t, sw), "dropped")
	require.NoError(t, SetJobEnvironment(sw, env))
	assert.Equal(t, &JobEnvironment{Name: "prod"}, environmentOf(t, sw))
	require.NoError(t, SetJobEnvironment(sw, &JobEnvironment{Name: "other"}))
	assert.Equal(t, &JobEnvironment{Name: "other"}, environmentOf(t, sw), "set again replaces")
}

func TestJobParserRefusesBadEnvironment(t *testing.T) {
	for name, env := range map[string]string{
		"list":     "[a, b]",
		"map list": "{name: [a]}",
	} {
		_, err := JobParser([]byte("on: push\njobs:\n  a:\n    runs-on: docker\n    environment: " + env + "\n    steps: [{run: echo}]\n"))
		require.Error(t, err, name)
	}
	// a map without a name is an invalid argument, so that a dispatch answers 400
	for name, env := range map[string]string{"no name": "{url: 'https://x.y'}", "empty name": "{name: ''}", "empty": "''"} {
		_, err := JobParser([]byte("on: push\njobs:\n  a:\n    runs-on: docker\n    environment: " + env + "\n    steps: [{run: echo}]\n"))
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
	}
}

// A job that calls a reusable workflow can't have an environment, as on GitHub.
func TestJobParserRefusesEnvironmentOfWorkflowCalls(t *testing.T) {
	_, err := JobParser([]byte("on: push\njobs:\n  call:\n    uses: ./.forgejo/workflows/x.yml\n    environment: prod\n"))
	require.ErrorContains(t, err, "can't have an environment")
	// the jobs of a reusable workflow are not matched by the id of a job of the caller's file
	inner, err := JobParser([]byte("on: push\njobs:\n  call:\n    runs-on: docker\n    environment: prod\n    steps: [{run: echo}]\n"))
	require.NoError(t, err)
	inner[0].Metadata.WorkflowCallParent = "parent"
	assert.NoError(t, attachJobEnvironments([]byte("jobs:\n  call:\n    environment: other\n"), inner))
	assert.Equal(t, &JobEnvironment{Name: "prod"}, environmentOf(t, inner[0]), "a job of a reusable workflow keeps what it has and gets nothing from the caller's file")
}

const (
	callerWorkflow = `on: push
jobs:
  call:
    uses: ./.forgejo/workflows/called.yml
    with:
      environment: production
`
	calledWorkflow = `on:
  workflow_call:
    inputs:
      environment:
        type: string
        required: true
jobs:
  build:
    runs-on: docker
    steps: [{run: echo}]
  deploy:
    runs-on: docker
    needs: [build]
    environment:
      name: ${{ inputs.environment }}
      url: https://${{ inputs.environment }}.example.com
    steps: [{run: echo}]
`
)

func parseWithCalled(t *testing.T, caller string, files map[string]string) (ReusableWorkflows, []*jobparser.SingleWorkflow) {
	t.Helper()
	r := ReusableWorkflows{}
	sws, err := r.JobParser([]byte(caller),
		r.ExpandLocal(func(job *jobparser.Job, path string) ([]byte, error) { return []byte(files[path]), nil }),
		jobparser.EnableNamespaces(),
	)
	require.NoError(t, err)
	return r, sws
}

func TestReusableWorkflowEnvironments(t *testing.T) {
	_, sws := parseWithCalled(t, callerWorkflow, map[string]string{"./.forgejo/workflows/called.yml": calledWorkflow})
	got := map[string]*JobEnvironment{}
	for _, sw := range sws {
		id, _ := sw.Job()
		got[id] = environmentOf(t, sw)
	}
	require.Len(t, got, 3)
	assert.Nil(t, got["call"], "the call itself has none")
	assert.Nil(t, got["build"])
	assert.Equal(t, &JobEnvironment{Name: "${{ inputs.environment }}", URL: "https://${{ inputs.environment }}.example.com"}, got["deploy"])
}

func TestReusableWorkflowEnvironmentsNested(t *testing.T) {
	files := map[string]string{
		"./.forgejo/workflows/called.yml": `on:
  workflow_call:
jobs:
  inner:
    uses: ./.forgejo/workflows/leaf.yml
`,
		"./.forgejo/workflows/leaf.yml": `on:
  workflow_call:
jobs:
  deploy:
    runs-on: docker
    environment: leaf-env
    steps: [{run: echo}]
`,
	}
	_, sws := parseWithCalled(t, "on: push\njobs:\n  call:\n    uses: ./.forgejo/workflows/called.yml\n", files)
	found := false
	for _, sw := range sws {
		if id, _ := sw.Job(); id == "deploy" {
			found = true
			assert.Equal(t, &JobEnvironment{Name: "leaf-env"}, environmentOf(t, sw))
		}
	}
	assert.True(t, found)
}

// A job of a reusable workflow that the server can't read the environment of is marked, so that the gate refuses it.
func TestReusableWorkflowEnvironmentsUnsupported(t *testing.T) {
	files := map[string]string{"./.forgejo/workflows/called.yml": calledWorkflow}
	sws, err := JobParser([]byte(callerWorkflow), // the fetcher doesn't remember what it read
		jobparser.ExpandLocalReusableWorkflows(func(job *jobparser.Job, path string) ([]byte, error) { return []byte(files[path]), nil }),
		jobparser.EnableNamespaces(),
	)
	require.NoError(t, err)
	require.NoError(t, ReusableWorkflows{}.AttachEnvironments([]byte(callerWorkflow), sws))
	for _, sw := range sws {
		id, _ := sw.Job()
		if id == "call" {
			assert.Nil(t, environmentOf(t, sw))
		} else {
			assert.Equal(t, &JobEnvironment{Unsupported: true}, environmentOf(t, sw), id)
		}
	}
	// an invalid called file is an error, as it would be as the workflow itself
	r := ReusableWorkflows{}
	_, err = r.JobParser([]byte(callerWorkflow),
		r.ExpandLocal(func(job *jobparser.Job, path string) ([]byte, error) {
			return []byte("on:\n  workflow_call:\njobs:\n  x:\n    uses: ./y.yml\n    environment: prod\n"), nil
		}),
		jobparser.EnableNamespaces(),
	)
	require.Error(t, err)
}

func TestNamesEnvironment(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		want    bool
	}{
		"string":      {"jobs:\n  a:\n    environment: prod\n", true},
		"map":         {"jobs:\n  a:\n    environment:\n      name: prod\n", true},
		"in one job":  {"jobs:\n  a:\n    runs-on: x\n  b:\n    environment: prod\n", true},
		"expression":  {"jobs:\n  a:\n    environment: ${{ inputs.target }}\n", true},
		"nested call": {"jobs:\n  a:\n    uses: ./b.yml\n", true},
		"none":        {"jobs:\n  a:\n    runs-on: x\n", false},
		"in a step":   {"jobs:\n  a:\n    steps:\n      - env:\n          environment: prod\n", false},
		"top level":   {"environment: prod\njobs:\n  a:\n    runs-on: x\n", false},
		"not a file":  {"jobs: [", false},
		"no jobs":     {"", false},
		"empty value": {"jobs:\n  a:\n    environment:\n", false},
	} {
		assert.Equal(t, tc.want, NamesEnvironment([]byte(tc.content)), name)
	}
}
