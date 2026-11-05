// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"errors"
	"fmt"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"go.yaml.in/yaml/v3"
)

const environmentKey = "environment"

// JobEnvironment is the `environment:` of a job: `environment: name` or `environment: {name, url}`. Both may hold
// expressions. jobparser drops the key, so JobParser puts it back into the job of every single workflow it returns and
// the server carries it with SetJobEnvironment wherever it rewrites a job.
type JobEnvironment struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url,omitempty"`
}

// UnmarshalYAML reads the string and the map form.
func (e *JobEnvironment) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Decode(&e.Name)
	case yaml.MappingNode:
		type plain JobEnvironment
		return n.Decode((*plain)(e))
	}
	return errors.New("environment must be a name or a map with a name")
}

// attachJobEnvironments reads the `environment:` of every job of the workflow in content and sets it on the single
// workflows that were made of that job. Jobs of a reusable workflow are left out (their ids belong to another file), and
// so are jobs that call one (a workflow call has no environment).
func attachJobEnvironments(content []byte, workflows []*jobparser.SingleWorkflow) error {
	var raw struct {
		Jobs map[string]struct {
			Environment *JobEnvironment `yaml:"environment"`
			Uses        string          `yaml:"uses"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return fmt.Errorf("invalid environment: %w", err)
	}
	for _, sw := range workflows {
		id, _ := sw.Job()
		if job := raw.Jobs[id]; job.Environment != nil && job.Uses == "" && sw.Metadata.WorkflowCallParent == "" {
			if err := SetJobEnvironment(sw, job.Environment); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetJobEnvironment returns the environment of the job of sw, nil if it names none.
func GetJobEnvironment(sw *jobparser.SingleWorkflow) (*JobEnvironment, error) {
	job := jobNode(sw)
	if job == nil {
		return nil, nil //nolint:nilnil // nil means the job names no environment
	}
	for i := 0; i+1 < len(job.Content); i += 2 {
		if job.Content[i].Value == environmentKey {
			env := new(JobEnvironment)
			if err := job.Content[i+1].Decode(env); err != nil {
				return nil, err
			}
			return env, nil
		}
	}
	return nil, nil //nolint:nilnil // nil means the job names no environment
}

// SetJobEnvironment sets the environment of the job of sw (it survives sw.Marshal, not sw.SetJob).
func SetJobEnvironment(sw *jobparser.SingleWorkflow, env *JobEnvironment) error {
	job := jobNode(sw)
	if job == nil {
		return errors.New("workflow has no job")
	}
	var value yaml.Node
	if err := value.Encode(env); err != nil {
		return err
	}
	for i := 0; i+1 < len(job.Content); i += 2 {
		if job.Content[i].Value == environmentKey {
			job.Content[i+1] = &value
			return nil
		}
	}
	job.Content = append(job.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: environmentKey}, &value)
	return nil
}

// jobNode returns the mapping of the single job of sw.
func jobNode(sw *jobparser.SingleWorkflow) *yaml.Node {
	if sw.RawJobs.Kind != yaml.MappingNode || len(sw.RawJobs.Content) != 2 || sw.RawJobs.Content[1].Kind != yaml.MappingNode {
		return nil
	}
	return sw.RawJobs.Content[1]
}
