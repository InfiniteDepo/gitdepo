// Copyright 2025 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"errors"
	"fmt"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"go.yaml.in/yaml/v3"
)

// RejectWorkflowMetadata refuses a workflow file with a top-level `__metadata` key: jobparser reads it from the file,
// but only the server may write it (it links the jobs of a reusable workflow to their caller job).
func RejectWorkflowMetadata(content []byte) error {
	// decoded as jobparser decodes it, so that merge keys can't hide it
	var workflow struct {
		Metadata yaml.Node `yaml:"__metadata"`
	}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return fmt.Errorf("yaml.Unmarshal: %w", err)
	}
	if workflow.Metadata.Kind != 0 {
		return errors.New("a workflow must not have a __metadata key")
	}
	return nil
}

func JobParser(workflow []byte, options ...jobparser.ParseOption) ([]*jobparser.SingleWorkflow, error) {
	if err := RejectWorkflowMetadata(workflow); err != nil {
		return nil, err
	}
	singleWorkflows, err := jobparser.Parse(workflow, false, options...)
	if err != nil {
		return nil, err
	}
	nameToSingleWorkflows := make(map[string][]*jobparser.SingleWorkflow, len(singleWorkflows))
	duplicates := make(map[string]int, len(singleWorkflows))
	for _, singleWorkflow := range singleWorkflows {
		id, job := singleWorkflow.Job()
		nameToSingleWorkflows[job.Name] = append(nameToSingleWorkflows[job.Name], singleWorkflow)
		if len(nameToSingleWorkflows[job.Name]) > 1 {
			duplicates[job.Name]++
			job.Name = fmt.Sprintf("%s-%d", job.Name, duplicates[job.Name])
			if err := singleWorkflow.SetJob(id, job); err != nil {
				return nil, err
			}
		}
	}
	if err := attachJobEnvironments(workflow, singleWorkflows); err != nil {
		return nil, err
	}
	return singleWorkflows, nil
}
