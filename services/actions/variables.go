// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"context"
	"regexp"
	"strings"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/secret"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"
)

// CreateVariable creates a variable of the instance, an owner, a project, a repository, or (environmentID not 0) an
// environment of the repository; a variable of an environment, like every write of one, only by the doer's own act
// (checked by secret_model.LockLevel): an environment's variables are part of its deployment protection, like its rules.
func CreateVariable(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name, data string) (*actions_model.ActionVariable, error) {
	if err := secret.ValidateName(name); err != nil {
		return nil, err
	}

	if err := envNameCIRegexMatch(name); err != nil {
		return nil, err
	}

	if environmentID != 0 {
		return actions_model.InsertEnvironmentVariable(ctx, repoID, environmentID, name, util.ReserveLineBreakForTextarea(data))
	}
	return actions_model.InsertVariable(ctx, ownerID, groupID, repoID, name, util.ReserveLineBreakForTextarea(data))
}

func UpdateVariable(ctx context.Context, variableID, ownerID, groupID, repoID, environmentID int64, name, data string) (bool, error) {
	if err := secret.ValidateName(name); err != nil {
		return false, err
	}

	if err := envNameCIRegexMatch(name); err != nil {
		return false, err
	}

	return actions_model.UpdateVariable(ctx, &actions_model.ActionVariable{
		ID:            variableID,
		Name:          strings.ToUpper(name),
		Data:          util.ReserveLineBreakForTextarea(data),
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
	})
}

func DeleteVariableByName(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name string) error {
	v, err := GetVariable(ctx, actions_model.FindVariablesOpts{
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
		Name:          name,
	})
	if err != nil {
		return err
	}

	if environmentID != 0 {
		_, err = actions_model.DeleteEnvironmentVariable(ctx, v.ID, repoID, environmentID)
	} else {
		_, err = actions_model.DeleteVariable(ctx, v.ID, ownerID, groupID, repoID)
	}
	return err
}

func GetVariable(ctx context.Context, opts actions_model.FindVariablesOpts) (*actions_model.ActionVariable, error) {
	vars, err := actions_model.FindVariables(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(vars) != 1 {
		return nil, util.NewNotExistErrorf("variable not found")
	}
	return vars[0], nil
}

// some regular expression of `variables` and `secrets`
// reference to:
// https://docs.github.com/en/actions/learn-github-actions/variables#naming-conventions-for-configuration-variables
// https://docs.github.com/en/actions/security-guides/encrypted-secrets#naming-your-secrets
// https://forgejo.org/docs/latest/user/actions/basic-concepts/#name-constraints
var (
	forbiddenEnvNameCIRx = regexp.MustCompile("(?i)^CI$")
)

func envNameCIRegexMatch(name string) error {
	if forbiddenEnvNameCIRx.MatchString(name) {
		log.Error("Env Name cannot be ci")
		return util.NewInvalidArgumentErrorf("env name cannot be ci")
	}
	return nil
}
