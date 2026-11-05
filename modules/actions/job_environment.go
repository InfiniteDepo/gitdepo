// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"errors"

	"forgejo.org/modules/util"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"code.forgejo.org/forgejo/runner/v13/act/model"
	"go.yaml.in/yaml/v3"
)

const environmentKey = "environment"

// JobEnvironment is the `environment:` of a job: `environment: name` or `environment: {name, url}`. Both may hold
// expressions. jobparser drops the key, so JobParser puts it back into the job of every single workflow it returns and
// the server carries it with SetJobEnvironment wherever it rewrites a job.
type JobEnvironment struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url,omitempty"`
	// Unsupported is set by the server on a job of a reusable workflow whose file it can't read the environment from.
	Unsupported bool `yaml:"unsupported,omitempty"`
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

// rawJob is what the server reads of a job of a workflow file besides what jobparser keeps.
type rawJob struct {
	Environment *JobEnvironment `yaml:"environment"`
	Uses        string          `yaml:"uses"`
}

// readRawJobs reads the jobs of a workflow file. A job that calls a reusable workflow can't have an environment, as
// on GitHub: it is a workflow error.
func readRawJobs(content []byte) (map[string]rawJob, error) {
	var raw struct {
		Jobs map[string]rawJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return nil, util.NewInvalidArgumentErrorf("invalid environment: %v", err)
	}
	for id, job := range raw.Jobs {
		if job.Environment != nil && job.Environment.Name == "" && !job.Environment.Unsupported {
			return nil, util.NewInvalidArgumentErrorf("job %q: the environment needs a name", id)
		}
		if job.Uses != "" && job.Environment != nil {
			return nil, util.NewInvalidArgumentErrorf("job %q calls a reusable workflow, so it can't have an environment", id)
		}
	}
	return raw.Jobs, nil
}

// attachJobEnvironments reads the `environment:` of every job of the workflow in content and sets it on the single
// workflows that were made of that job. The jobs of a reusable workflow are left out (their ids belong to another file):
// ReusableWorkflows.AttachEnvironments does them.
func attachJobEnvironments(content []byte, workflows []*jobparser.SingleWorkflow) error {
	jobs, err := readRawJobs(content)
	if err != nil {
		return err
	}
	for _, sw := range workflows {
		id, _ := sw.Job()
		if job := jobs[id]; job.Environment != nil && sw.Metadata.WorkflowCallParent == "" {
			if err := SetJobEnvironment(sw, job.Environment); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReusableWorkflows holds the content of the reusable workflows a parse read, by their `uses:`. jobparser expands the
// jobs of a reusable workflow itself and drops their environment, so the server reads it from the file the fetchers
// returned.
type ReusableWorkflows map[string][]byte

// ExpandLocal is jobparser.ExpandLocalReusableWorkflows that also remembers what the fetcher read.
func (r ReusableWorkflows) ExpandLocal(fetch jobparser.LocalWorkflowFetcher) jobparser.ParseOption {
	return jobparser.ExpandLocalReusableWorkflows(func(job *jobparser.Job, path string) ([]byte, error) {
		uses := job.Uses
		content, err := fetch(job, path)
		if err == nil {
			r[uses] = content
		}
		return content, err
	})
}

// ExpandInstance is jobparser.ExpandInstanceReusableWorkflows that also remembers what the fetcher read.
func (r ReusableWorkflows) ExpandInstance(fetch jobparser.InstanceWorkflowFetcher) jobparser.ParseOption {
	return jobparser.ExpandInstanceReusableWorkflows(func(job *jobparser.Job, ref *model.NonLocalReusableWorkflowReference) ([]byte, error) {
		uses := job.Uses
		content, err := fetch(job, ref)
		if err == nil {
			r[uses] = content
		}
		return content, err
	})
}

// JobParser is JobParser followed by AttachEnvironments.
func (r ReusableWorkflows) JobParser(workflow []byte, options ...jobparser.ParseOption) ([]*jobparser.SingleWorkflow, error) {
	workflows, err := JobParser(workflow, options...)
	if err != nil {
		return nil, err
	}
	return workflows, r.AttachEnvironments(workflow, workflows)
}

// AttachEnvironments sets the environment of the jobs that came from a reusable workflow called by a job of content
// (or by a job of such a workflow). A job whose called file isn't known, or doesn't have it, gets an environment
// that the gate refuses: a job that may name an environment never runs without its gate.
func (r ReusableWorkflows) AttachEnvironments(content []byte, workflows []*jobparser.SingleWorkflow) error {
	top, err := readRawJobs(content)
	if err != nil {
		return err
	}
	callers := map[string]*jobparser.SingleWorkflow{} // by WorkflowCallID
	for _, sw := range workflows {
		if sw.Metadata.WorkflowCallID != "" {
			callers[sw.Metadata.WorkflowCallID] = sw
		}
	}
	called := map[string]map[string]rawJob{} // the jobs of the file a call executes, by WorkflowCallID
	var jobsOfCall func(callID string, depth int) (map[string]rawJob, bool, error)
	jobsOfCall = func(callID string, depth int) (map[string]rawJob, bool, error) {
		if jobs, ok := called[callID]; ok {
			return jobs, true, nil
		}
		caller := callers[callID]
		if caller == nil || depth > 10 {
			return nil, false, nil //nolint:nilnil // not known: the caller marks its jobs unsupported
		}
		enclosing := top
		if parent := caller.Metadata.WorkflowCallParent; parent != "" && callers[parent] != nil {
			var ok bool
			if enclosing, ok, err = jobsOfCall(parent, depth+1); !ok || err != nil {
				return nil, false, err
			}
		}
		id, _ := caller.Job()
		file, ok := r[enclosing[id].Uses]
		if !ok || enclosing[id].Uses == "" {
			return nil, false, nil //nolint:nilnil // not known: the caller marks its jobs unsupported
		}
		jobs, err := readRawJobs(file)
		called[callID] = jobs
		return jobs, err == nil, err
	}
	for _, sw := range workflows {
		parent := sw.Metadata.WorkflowCallParent
		if callers[parent] == nil {
			continue // not a job of a call that was expanded here; it brings its own environment
		}
		id, _ := sw.Job()
		jobs, ok, err := jobsOfCall(parent, 0)
		if err != nil {
			return err
		}
		job, found := jobs[id]
		switch {
		case ok && found && job.Environment == nil:
		case ok && found:
			err = SetJobEnvironment(sw, job.Environment)
		default:
			err = SetJobEnvironment(sw, &JobEnvironment{Unsupported: true})
		}
		if err != nil {
			return err
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
