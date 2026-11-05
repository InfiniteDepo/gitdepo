// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

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
	// a map without a name is read as an empty name, which the gate refuses
	sws, err := JobParser([]byte("on: push\njobs:\n  a:\n    runs-on: docker\n    environment: {url: 'https://x.y'}\n    steps: [{run: echo}]\n"))
	require.NoError(t, err)
	assert.Equal(t, &JobEnvironment{URL: "https://x.y"}, environmentOf(t, sws[0]))
}

// A job that calls a reusable workflow has no environment, and the jobs of the reusable workflow are not matched by
// the id of a job of the caller.
func TestJobParserIgnoresEnvironmentOfWorkflowCalls(t *testing.T) {
	sws, err := JobParser([]byte("on: push\njobs:\n  call:\n    uses: ./.forgejo/workflows/x.yml\n    environment: prod\n"))
	if err == nil {
		for _, sw := range sws {
			assert.Nil(t, environmentOf(t, sw))
		}
	}
	inner, err := JobParser([]byte("on: push\njobs:\n  call:\n    runs-on: docker\n    environment: prod\n    steps: [{run: echo}]\n"))
	require.NoError(t, err)
	inner[0].Metadata.WorkflowCallParent = "parent"
	assert.NoError(t, attachJobEnvironments([]byte("jobs:\n  call:\n    environment: other\n"), inner))
	assert.Equal(t, &JobEnvironment{Name: "prod"}, environmentOf(t, inner[0]), "a job of a reusable workflow keeps what it has and gets nothing from the caller's file")
}
