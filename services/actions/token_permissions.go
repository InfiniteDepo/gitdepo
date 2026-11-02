// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/setting"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"go.yaml.in/yaml/v3"
)

// tokenPermissionUnits maps the `permissions:` keys that gitdepo supports to repository units. Other keys
// (packages, statuses, deployments, id-token, ...) grant nothing and are reported as ignored.
var tokenPermissionUnits = map[string][]unit.Type{
	"contents":            {unit.TypeCode, unit.TypeReleases, unit.TypeWiki},
	"issues":              {unit.TypeIssues},
	"pull-requests":       {unit.TypePullRequests},
	"actions":             {unit.TypeActions},
	"repository-projects": {unit.TypeProjects},
}

var tokenPermissionModes = map[string]perm.AccessMode{
	"none":  perm.AccessModeNone,
	"read":  perm.AccessModeRead,
	"write": perm.AccessModeWrite,
}

// allTokenPermissions gives mode on every unit, like the legacy token for write.
func allTokenPermissions(mode perm.AccessMode) actions_model.TokenPermissions {
	p := actions_model.TokenPermissions{}
	for _, t := range unit.AllRepoUnitTypes {
		p[t] = mode
	}
	return p
}

// parseTokenPermissions reads a present `permissions:` block: the token gets what it grants and nothing else.
// ignored lists the keys that grant nothing because gitdepo doesn't support them or their value is invalid
// ("permissions" when the whole block is invalid).
func parseTokenPermissions(node *yaml.Node) (p actions_model.TokenPermissions, ignored []string) {
	switch {
	case node.Kind == yaml.ScalarNode && node.Tag == "!!str" && node.Value == "read-all":
		return allTokenPermissions(perm.AccessModeRead), nil
	case node.Kind == yaml.ScalarNode && node.Tag == "!!str" && node.Value == "write-all":
		return allTokenPermissions(perm.AccessModeWrite), nil
	case node.Kind != yaml.MappingNode:
		return actions_model.TokenPermissions{}, []string{"permissions"}
	}
	p = actions_model.TokenPermissions{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		units, ok := tokenPermissionUnits[key.Value]
		mode, validMode := tokenPermissionModes[value.Value]
		if key.Kind != yaml.ScalarNode || !ok || value.Kind != yaml.ScalarNode || value.Tag != "!!str" || !validMode {
			ignored = append(ignored, key.Value)
			mode = perm.AccessModeNone
		}
		for _, t := range units {
			if mode == perm.AccessModeNone {
				delete(p, t)
			} else {
				p[t] = mode
			}
		}
	}
	return p, ignored
}

// workflowTokenPermissions returns the token permissions that a job asks for: its own `permissions:` block,
// else its workflow's, else defaultPermissions ("read" or "write"). nil means the legacy permissions (default write).
func workflowTokenPermissions(swf *jobparser.SingleWorkflow, defaultPermissions string) (p actions_model.TokenPermissions, ignored []string) {
	node := &swf.Permissions
	if _, job := swf.Job(); job != nil && job.Permissions.Kind != 0 {
		node = &job.Permissions
	}
	if node.Kind != 0 {
		return parseTokenPermissions(node)
	}
	if defaultPermissions == "read" {
		return allTokenPermissions(perm.AccessModeRead), nil
	}
	return nil, nil
}

// jobTokenPermissions returns the permissions of the token of a task for the job: what it asks for, capped by the
// job that called its reusable workflow, if any, and at read for a fork pull request. job.Run must be loaded.
func jobTokenPermissions(ctx context.Context, job *actions_model.ActionRunJob) (actions_model.TokenPermissions, error) {
	if err := job.Run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	defaultPermissions := setting.Actions.DefaultTokenPermissions
	actionsUnit, err := job.Run.Repo.GetUnit(ctx, unit.TypeActions)
	if err == nil {
		defaultPermissions = actionsUnit.ActionsConfig().EffectiveDefaultTokenPermissions()
	} else if !repo_model.IsErrUnitTypeNotExist(err) {
		return nil, err
	}
	return capTokenPermissions(ctx, job, defaultPermissions, map[int64]bool{})
}

// capTokenPermissions is jobTokenPermissions; seen holds the jobs of the call chain, which must not loop.
func capTokenPermissions(ctx context.Context, job *actions_model.ActionRunJob, defaultPermissions string, seen map[int64]bool) (actions_model.TokenPermissions, error) {
	if seen[job.ID] {
		return nil, fmt.Errorf("token permissions of job %d: workflow call loop", job.ID)
	}
	seen[job.ID] = true
	swf, err := job.DecodeWorkflowPayload()
	if err != nil {
		return nil, err
	}
	p, _ := workflowTokenPermissions(swf, defaultPermissions)
	if swf.Metadata.WorkflowCallParent != "" {
		outer, err := job.Run.FindOuterWorkflowCall(ctx, job)
		if err != nil {
			return nil, fmt.Errorf("token permissions of job %d: %w", job.ID, err)
		}
		outer.Run = job.Run
		outerPerms, err := capTokenPermissions(ctx, outer, defaultPermissions, seen)
		if err != nil {
			return nil, err
		}
		if p != nil || outerPerms != nil {
			if p == nil {
				p = allTokenPermissions(perm.AccessModeWrite)
			}
			if outerPerms == nil {
				outerPerms = allTokenPermissions(perm.AccessModeWrite)
			}
			for t, mode := range p {
				if mode = min(mode, outerPerms[t]); mode == perm.AccessModeNone {
					delete(p, t)
				} else {
					p[t] = mode
				}
			}
		}
	}
	if job.IsForkPullRequest && p != nil {
		for t, mode := range p {
			p[t] = min(mode, perm.AccessModeRead)
		}
	}
	return p, nil
}
