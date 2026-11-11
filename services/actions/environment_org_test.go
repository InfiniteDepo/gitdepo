// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	actions_module "forgejo.org/modules/actions"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A job of a repository of the organization resolves the organization's environment, which then gives it its secrets
// and variables on top of every other level; the jobs of other owners' repositories and of forks never do.
func TestOrgEnvironmentSecretsAndVariables(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	project, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = 3, group_id = ? WHERE id = 63", project.ID)
	require.NoError(t, err)

	live := &actions_model.ActionEnvironment{OwnerID: 3, Name: "live", RepoIDs: []int64{63}}
	require.NoError(t, actions_model.CreateEnvironment(ctx, live, nil))
	for _, s := range []struct {
		owner, group, repo, env int64
		name, value             string
	}{
		{3, 0, 0, 0, "LEVEL", "org"},
		{3, 0, 0, 0, "ORG_ONLY", "org"},
		{3, project.ID, 0, 0, "LEVEL", "project"},
		{0, 0, 63, 0, "LEVEL", "repo"},
		{0, 0, 63, 0, "REPO_ONLY", "repo"},
		{3, 0, 0, live.ID, "LEVEL", "org environment"},
		{3, 0, 0, live.ID, "PROD_ONLY", "org environment"},
		{3, 0, 0, live.ID, "UNREFERENCED", "org environment"},
	} {
		if s.env != 0 {
			_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, s.owner, s.repo, s.env, s.name, s.value)
		} else {
			_, err = secret_model.InsertEncryptedSecret(ctx, s.owner, s.group, s.repo, s.name, s.value)
		}
		require.NoError(t, err)
	}
	_, err = actions_model.InsertVariable(ctx, 0, 0, 63, "LEVEL", "repo")
	require.NoError(t, err)
	_, err = actions_model.InsertEnvironmentVariable(ctx, 3, 0, live.ID, "LEVEL", "org environment")
	require.NoError(t, err)

	job := gateJob(t, envWorkflow("    environment: LIVE\n"), "refs/heads/main")
	b, err := gateEnvironment(ctx, job)
	require.NoError(t, err)
	assert.Equal(t, behaviourExecuteJob, b)
	d := deploymentOf(t, job)
	require.NotNil(t, d)
	assert.Equal(t, live.ID, d.EnvironmentID, "inherited, never auto-created")
	unittest.AssertCount(t, &actions_model.ActionEnvironment{}, 1)
	assert.Equal(t, actions_model.DeploymentReleased, d.Status)

	got, err := getSecretsOfJob(ctx, job)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"LEVEL": "org environment", "ORG_ONLY": "org", "REPO_ONLY": "repo", "PROD_ONLY": "org environment"}, got,
		"organization environment > repository > project > organization, only the names the job reads")
	vars, err := getVariablesOfJob(ctx, job)
	require.NoError(t, err)
	assert.Equal(t, "org environment", vars["LEVEL"])
	name, err := releasedEnvironmentName(ctx, job)
	require.NoError(t, err)
	assert.Equal(t, "live", name)

	t.Run("fork pull requests get none of it", func(t *testing.T) {
		sws, err := actions_module.JobParser([]byte(envWorkflow("    environment: live\n")))
		require.NoError(t, err)
		payload, err := sws[0].Marshal()
		require.NoError(t, err)
		_, err = db.GetEngine(ctx).Exec("UPDATE action_run_job SET workflow_payload = ?, environment_name = 'live', attempt = 1, repo_id = 63 WHERE id = 604", string(payload))
		require.NoError(t, err)
		fork := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 604})
		require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{RepoID: 63, EnvironmentID: live.ID, RunID: fork.RunID, JobID: fork.ID, Attempt: 1, Status: actions_model.DeploymentReleased}))
		got, err := getSecretsOfJob(ctx, fork)
		require.NoError(t, err)
		assert.Empty(t, got)
		vars, err := getVariablesOfJob(ctx, fork)
		require.NoError(t, err)
		assert.NotEqual(t, "org environment", vars["LEVEL"])
	})

	t.Run("transferred out, the environment no longer applies", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET owner_id = 2, group_id = 0 WHERE id = 63")
		require.NoError(t, err)
		_, err = getSecretsOfJob(ctx, job)
		require.ErrorIs(t, err, errEnvironmentNotReleased)
		_, err = getVariablesOfJob(ctx, job)
		require.ErrorIs(t, err, errEnvironmentNotReleased)

		// another owner's job names the same environment: it gets one of its own repository, without rules
		_, err = db.GetEngine(ctx).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		job := gateJob(t, envWorkflow("    environment: live\n"), "refs/heads/main")
		_, err = gateEnvironment(ctx, job)
		require.NoError(t, err)
		d := deploymentOf(t, job)
		require.NotNil(t, d)
		assert.NotEqual(t, live.ID, d.EnvironmentID)
		own := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: d.EnvironmentID})
		assert.EqualValues(t, 63, own.RepoID)
		got, err := getSecretsOfJob(ctx, job)
		require.NoError(t, err)
		assert.NotContains(t, got, "PROD_ONLY")
	})
}
