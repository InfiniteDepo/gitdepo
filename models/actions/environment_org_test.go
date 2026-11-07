// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"testing"

	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Organization 3 owns repositories 3, 5 and 32; user 2 owns repository 1.

func TestOrgEnvironmentResolution(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	since := auditMax(t)

	prod := &ActionEnvironment{OwnerID: 3, Name: "Production", WaitTimerMinutes: 5}
	require.NoError(t, CreateEnvironment(ctx, prod, nil))
	assert.Zero(t, prod.RepoID)
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, RepoID: 3, Name: "x"}, nil), util.ErrInvalidArgument, "one level only")
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: "PRODUCTION"}, nil), ErrEnvironmentExists)

	// a repository of the organization resolves it, ignoring case; a repository of another owner never does
	for _, repoID := range []int64{3, 5, 32} {
		env, err := ResolveEnvironment(ctx, repoID, "production")
		require.NoError(t, err)
		assert.Equal(t, prod.ID, env.ID)
		env, err = GetEnvironmentOfRepo(ctx, repoID, prod.ID)
		require.NoError(t, err)
		assert.Equal(t, prod.ID, env.ID)
	}
	_, err := ResolveEnvironment(ctx, 1, "production")
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	_, err = GetEnvironmentOfRepo(ctx, 1, prod.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	// the by-name and by-ID lookups bind both the owner and the repository
	_, err = GetEnvironmentByName(ctx, 0, 3, "production")
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	_, err = GetEnvironmentByID(ctx, 0, 0, prod.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	_, err = GetEnvironmentByID(ctx, 2, 0, prod.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	found, err := GetEnvironmentByName(ctx, 3, 0, "PRODUCTION")
	require.NoError(t, err)
	assert.Equal(t, prod.ID, found.ID)

	// a matching organization environment is inherited, never auto-created
	env, err := GetOrCreateRepoEnvironment(ctx, 3, "PRODUCTION")
	require.NoError(t, err)
	assert.Equal(t, prod.ID, env.ID)
	unittest.AssertCount(t, &ActionEnvironment{LowerName: "production"}, 1)

	// names never twin
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 3, Name: "production"}, nil), ErrEnvironmentTakenByOrg)
	require.NoError(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 1, Name: "production"}, nil), "another owner's repository")
	_, err = GetOrCreateRepoEnvironment(ctx, 3, "Staging")
	require.NoError(t, err)
	_, err = GetOrCreateRepoEnvironment(ctx, 5, "staging")
	require.NoError(t, err)
	_, err = GetOrCreateRepoEnvironment(ctx, 1, "staging")
	require.NoError(t, err)
	err = CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: "STAGING"}, nil)
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	assert.Equal(t, ErrEnvironmentUsedByRepos{N: 2}, err, "counted over the organization's repositories only")

	// lists: the organization's own, and a repository's with the inherited ones
	envs, count, err := FindEnvironments(ctx, 3, 0, db.ListOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
	assert.Equal(t, prod.ID, envs[0].ID)
	envs, count, err = FindEnvironmentsOfRepo(ctx, 3, db.ListOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 2, count)
	assert.Equal(t, []string{"Production", "Staging"}, []string{envs[0].Name, envs[1].Name})
	envs, _, err = FindEnvironmentsOfRepo(ctx, 1, db.ListOptions{})
	require.NoError(t, err)
	for _, e := range envs {
		assert.EqualValues(t, 1, e.RepoID, "no environment of another owner")
	}

	// a repository with a name of the new owner's environments can't move there
	require.ErrorIs(t, RefuseTwinsOnTransfer(ctx, 1, 3), ErrEnvironmentTwin)
	require.NoError(t, RefuseTwinsOnTransfer(ctx, 3, 2))

	var actions []string
	for _, e := range auditEntries(t, since) {
		if e.Action == "org.actions_env.created" {
			assert.EqualValues(t, 3, e.OwnerID)
			assert.Zero(t, e.RepoID)
		}
		actions = append(actions, e.Action)
	}
	assert.Equal(t, "org.actions_env.created", actions[0])
	assert.NotContains(t, actions[1:], "org.actions_env.created")
}

func TestOrgEnvironmentSecretsAndLifecycle(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	prod := &ActionEnvironment{OwnerID: 3, Name: "prod"}
	require.NoError(t, CreateEnvironment(ctx, prod, nil))
	since := auditMax(t)

	_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 3, prod.ID, "token", "x")
	require.ErrorIs(t, err, ErrEnvironmentNotFound, "the organization's environment is no repository's")
	secret, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 3, 0, prod.ID, "token", "org-secret-value")
	require.NoError(t, err)
	secret.SetData("org-secret-value-2")
	require.NoError(t, secret_model.UpdateSecret(ctx, secret, true))
	require.NoError(t, secret_model.DeleteSecret(ctx, secret))
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 3, 0, prod.ID, "kept", "org-secret-value")
	require.NoError(t, err)
	_, err = InsertEnvironmentVariable(ctx, 0, 3, prod.ID, "color", "blue")
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	variable, err := InsertEnvironmentVariable(ctx, 3, 0, prod.ID, "color", "blue")
	require.NoError(t, err)
	variable.Data = "green"
	_, err = UpdateVariable(ctx, variable)
	require.NoError(t, err)
	_, err = DeleteEnvironmentVariable(ctx, variable.ID, 0, 3, prod.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound, "bound to the organization")
	deleted, err := DeleteEnvironmentVariable(ctx, variable.ID, 3, 0, prod.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
	_, err = InsertEnvironmentVariable(ctx, 3, 0, prod.ID, "kept", "x")
	require.NoError(t, err)

	secrets, variables, err := CountEnvironmentSecretsAndVariables(ctx, 3, 0, []int64{prod.ID})
	require.NoError(t, err)
	assert.EqualValues(t, 1, secrets[prod.ID])
	assert.EqualValues(t, 1, variables[prod.ID])
	fetched, err := secret_model.FetchEnvironmentSecrets(ctx, 3, 0, prod.ID)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"KEPT": "org-secret-value"}, fetched)

	prod.WaitTimerMinutes = 3
	require.NoError(t, UpdateEnvironment(ctx, prod, nil))
	require.NoError(t, DeleteEnvironment(ctx, prod, func(context.Context) error { return nil }))
	unittest.AssertNotExistsBean(t, &secret_model.Secret{EnvironmentID: prod.ID})
	unittest.AssertNotExistsBean(t, &ActionVariable{EnvironmentID: prod.ID})

	var actions []string
	for _, e := range auditEntries(t, since) {
		actions = append(actions, e.Action)
		assert.EqualValues(t, 3, e.OwnerID)
		assert.NotContains(t, e.Data, "org-secret-value")
	}
	assert.Equal(t, []string{
		"org.actions_env_secret.created", "org.actions_env_secret.updated", "org.actions_env_secret.deleted",
		"org.actions_env_secret.created",
		"org.actions_env_variable.created", "org.actions_env_variable.updated", "org.actions_env_variable.deleted",
		"org.actions_env_variable.created",
		"org.actions_env.updated", "org.actions_env.deleted",
	}, actions)
}

func TestOrgEnvironmentLimit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	for i := range MaxEnvironmentsPerRepo {
		require.NoError(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: fmt.Sprint("env-", i)}, nil))
	}
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: "one-too-many"}, nil), ErrEnvironmentLimit)
	_, err := GetOrCreateRepoEnvironment(ctx, 3, "repo-level")
	require.NoError(t, err, "the repositories have their own cap")
}
