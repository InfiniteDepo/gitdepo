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
	"forgejo.org/modules/json"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Organization 3 owns repositories 3, 5 and 32; user 2 owns repository 1.

func TestOrgEnvironmentResolution(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	since := auditMax(t)

	prod := &ActionEnvironment{OwnerID: 3, Name: "Production", WaitTimerMinutes: 5, AllRepos: true}
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
	var usedBy ErrEnvironmentUsedByRepos
	require.ErrorAs(t, err, &usedBy)
	assert.EqualValues(t, 2, usedBy.N, "counted over the organization's repositories only")
	require.Len(t, usedBy.Repos, 2)
	assert.Equal(t, "repo3", usedBy.Repos[0].Name)
	assert.Equal(t, "the name is used by environments of 2 repositories of the organization (repo3, repo5): delete theirs first", err.Error())

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
	for i := range MaxEnvironments {
		require.NoError(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: fmt.Sprint("env-", i)}, nil))
	}
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: "one-too-many"}, nil), ErrEnvironmentLimit)
	_, err := GetOrCreateRepoEnvironment(ctx, 3, "repo-level")
	require.NoError(t, err, "the repositories have their own cap")
}

// An organization environment applies to the repositories it selects, or to all with AllRepos: none by default. A
// repository it doesn't apply to can't name it, and never gets a twin of it.
func TestOrgEnvironmentSelection(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	since := auditMax(t)
	none := &ActionEnvironment{OwnerID: 3, Name: "none"}
	require.NoError(t, CreateEnvironment(ctx, none, nil))
	some := &ActionEnvironment{OwnerID: 3, Name: "some", RepoIDs: []int64{5, 3, 5}}
	require.NoError(t, CreateEnvironment(ctx, some, nil))
	all := &ActionEnvironment{OwnerID: 3, Name: "all", AllRepos: true, RepoIDs: []int64{3}}
	require.NoError(t, CreateEnvironment(ctx, all, nil))
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{OwnerID: 3, Name: "x", RepoIDs: []int64{1}}, nil), util.ErrInvalidArgument, "a repository of another owner")
	unittest.AssertNotExistsBean(t, &ActionEnvironment{LowerName: "x"})

	selected, err := EnvironmentRepoIDs(ctx, []int64{none.ID, some.ID, all.ID})
	require.NoError(t, err)
	assert.Equal(t, map[int64][]int64{some.ID: {3, 5}}, selected, "deduplicated; none with AllRepos")

	for _, c := range []struct {
		repoID int64
		names  []string
	}{{3, []string{"all", "some"}}, {5, []string{"all", "some"}}, {32, []string{"all"}}, {1, nil}} {
		envs, _, err := FindEnvironmentsOfRepo(ctx, c.repoID, db.ListOptions{})
		require.NoError(t, err)
		var names []string
		for _, e := range envs {
			names = append(names, e.Name)
		}
		assert.Equal(t, c.names, names, "repository %d", c.repoID)
	}
	_, err = GetOrCreateRepoEnvironment(ctx, 32, "Some")
	require.ErrorIs(t, err, ErrEnvironmentNotAvailable)
	_, err = GetEnvironmentOfRepo(ctx, 32, some.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 32, Name: "none"}, nil), ErrEnvironmentTakenByOrg, "twins are refused over all repositories")
	unittest.AssertCount(t, &ActionEnvironment{LowerName: "some"}, 1)

	// the selection changes with the rules; transfer out and deletion drop a repository's rows
	some.RepoIDs = []int64{32}
	require.NoError(t, UpdateEnvironment(ctx, some, nil))
	env, err := GetOrCreateRepoEnvironment(ctx, 32, "some")
	require.NoError(t, err)
	assert.Equal(t, some.ID, env.ID)
	require.NoError(t, DropEnvironmentRepoSelections(ctx, 32))
	unittest.AssertNotExistsBean(t, &ActionEnvironmentRepo{RepoID: 32})

	var data []map[string]any
	for _, e := range auditEntries(t, since) {
		if e.TargetID == some.ID {
			var d map[string]any
			require.NoError(t, json.Unmarshal([]byte(e.Data), &d))
			data = append(data, d)
		}
	}
	require.Len(t, data, 2)
	assert.Equal(t, []any{float64(3), float64(5)}, data[0]["repo_ids"])
	assert.Equal(t, map[string]any{"repo_ids": []any{float64(3), float64(5)}}, data[1]["before"])
}

// EnvironmentCoversCond is one rule in two forms: bound to a repository, and joined with the repository rows.
func TestEnvironmentCoversCondForms(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	var ids []int64
	for i, e := range []*ActionEnvironment{
		{OwnerID: 3, Name: "none"},
		{OwnerID: 3, Name: "some", RepoIDs: []int64{5}},
		{OwnerID: 3, Name: "all", AllRepos: true},
		{OwnerID: 17, Name: "other", AllRepos: true},
		{RepoID: 3, Name: "own"},
	} {
		require.NoError(t, CreateEnvironment(ctx, e, nil), i)
		ids = append(ids, e.ID)
	}
	// a stray selection of a repository of another owner selects nothing
	require.NoError(t, db.Insert(ctx, &ActionEnvironmentRepo{EnvironmentID: ids[0], RepoID: 1}))
	joined, err := FindEnvironmentRepos(ctx, ids)
	require.NoError(t, err)
	inJoined := map[EnvironmentRepo]bool{}
	for _, r := range joined {
		inJoined[r] = true
	}
	var repoIDs []int64
	require.NoError(t, db.GetEngine(ctx).Table("repository").Where("trashed_unix = 0").Cols("id").Find(&repoIDs))
	covered := 0
	for _, repoID := range repoIDs {
		for _, id := range ids {
			bound, err := db.GetEngine(ctx).Table("action_environment").Where(EnvironmentCoversCond(repoID)).And("action_environment.id = ?", id).Exist()
			require.NoError(t, err)
			assert.Equal(t, bound, inJoined[EnvironmentRepo{id, repoID}], "environment %d, repository %d", id, repoID)
			if bound {
				covered++
			}
		}
	}
	assert.Equal(t, len(joined), covered)
	assert.True(t, inJoined[EnvironmentRepo{ids[1], 5}])
	assert.False(t, inJoined[EnvironmentRepo{ids[1], 3}])
	assert.False(t, inJoined[EnvironmentRepo{ids[0], 1}])
}

// An environment of all repositories never holds secrets without required reviewers, whichever write comes last.
func TestOrgEnvironmentOpenSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	reviewers := []ActionEnvironmentReviewer{{UserID: 4}}
	open := &ActionEnvironment{OwnerID: 3, Name: "open", AllRepos: true}
	require.NoError(t, CreateEnvironment(ctx, open, nil))
	_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 3, 0, open.ID, "key", "v")
	require.ErrorIs(t, err, ErrEnvironmentOpenSecrets, "a secret added to it")
	_, err = InsertEnvironmentVariable(ctx, 3, 0, open.ID, "color", "blue")
	require.NoError(t, err, "variables are no secrets")

	held := &ActionEnvironment{OwnerID: 3, Name: "held", RepoIDs: []int64{3}}
	require.NoError(t, CreateEnvironment(ctx, held, nil))
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 3, 0, held.ID, "key", "v")
	require.NoError(t, err, "selected repositories need no reviewers")
	held.AllRepos = true
	require.ErrorIs(t, UpdateEnvironment(ctx, held, nil), ErrEnvironmentOpenSecrets, "switched to all repositories")
	require.NoError(t, UpdateEnvironment(ctx, held, reviewers), "all repositories with reviewers")
	require.ErrorIs(t, UpdateEnvironment(ctx, held, nil), ErrEnvironmentOpenSecrets, "its last reviewer removed")
	stored := unittest.AssertExistsAndLoadBean(t, &ActionEnvironment{ID: held.ID})
	assert.True(t, stored.AllRepos)
	assert.True(t, stored.ReviewsRequired)
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 3, 0, held.ID, "other", "v")
	require.NoError(t, err)
}
