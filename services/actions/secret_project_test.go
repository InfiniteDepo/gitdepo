// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The secrets of a job include those of the project its repository is in now, with the fork pull request rules of
// the organization secrets.
func TestGetSecretsOfJobProject(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	a, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	b, err := repo_model.CreateRepoGroup(ctx, org3, "pb", "")
	require.NoError(t, err)
	for _, s := range []struct {
		owner, group, repo int64
		name, value        string
	}{
		{3, 0, 0, "SECRET_1", "org"},
		{3, a.ID, 0, "SECRET_1", "project a"},
		{3, a.ID, 0, "ONLY_A", "project a"},
		{3, b.ID, 0, "ONLY_B", "project b"},
		{0, 0, 63, "ONLY_REPO", "repo"},
	} {
		_, err := secret_model.InsertEncryptedSecret(ctx, s.owner, s.group, s.repo, s.name, s.value)
		require.NoError(t, err)
	}
	secrets := func(jobID int64) map[string]string {
		got, err := getSecretsOfJob(ctx, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: jobID}))
		require.NoError(t, err)
		return got
	}
	moveRepo63 := func(owner, group int64) {
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = ?, group_id = ? WHERE id = 63", owner, group)
		require.NoError(t, err)
	}

	// repository 63 belongs to user 2: no organization or project secret, whatever the IDs
	assert.Equal(t, map[string]string{"ONLY_REPO": "repo"}, secrets(600), "user-owned repository")

	moveRepo63(3, 0)
	assert.Equal(t, map[string]string{"SECRET_1": "org", "ONLY_REPO": "repo"}, secrets(600), "root repository of the organization")

	moveRepo63(3, a.ID)
	assert.Equal(t, map[string]string{"SECRET_1": "project a", "ONLY_A": "project a", "ONLY_REPO": "repo"}, secrets(600), "push")
	assert.Equal(t, map[string]string{"SECRET_1": "project a", "ONLY_A": "project a", "ONLY_REPO": "repo"}, secrets(602), "pull_request_target of a fork")
	assert.Empty(t, secrets(604), "pull_request of a fork gets no secret")
	// variables are not withheld from fork pull requests (they are not secret)
	_, err = actions_model.InsertVariable(ctx, 3, a.ID, 0, "VAR_A", "va")
	require.NoError(t, err)
	forkJob := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 604})
	require.NoError(t, forkJob.LoadRun(ctx))
	require.True(t, forkJob.Run.IsForkPullRequest)
	vars, err := actions_model.GetVariablesOfRun(ctx, forkJob.Run)
	require.NoError(t, err)
	assert.Equal(t, "va", vars["VAR_A"])

	moveRepo63(3, b.ID)
	assert.Equal(t, map[string]string{"SECRET_1": "org", "ONLY_B": "project b", "ONLY_REPO": "repo"}, secrets(600), "moved to the other project")
}
