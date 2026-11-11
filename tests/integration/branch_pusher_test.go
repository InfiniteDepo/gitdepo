// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	perm_model "forgejo.org/models/perm"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pre-receive hook records who pushed to a branch, credited to the user behind the credential, before the push
// is accepted; a deploy key with no recorded owner is recorded as user 0.
func TestPreReceiveRecordsBranchPusher(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	for _, name := range []string{"user4", "user5"} {
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/"+name, &api.AddCollaboratorOption{Permission: new("write")}).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)), http.StatusNoContent)
	}
	commit := "2a47ca4b614a9f5a43abbd5ad851a54a616ffee6"
	zero := git.Sha1ObjectFormat.EmptyObjectID().String()
	hook := func(repoID int64, branch, oldID, newID string, opts private.HookOptions) private.ResponseExtra {
		opts.OldCommitIDs, opts.NewCommitIDs = []string{oldID}, []string{newID}
		opts.RefFullNames = []git.RefName{git.RefNameFromBranch(branch)}
		return private.HookPreReceive(ctx, repoID, opts)
	}
	pushers := func(repoID int64, branch string) []int64 {
		ids, err := git_model.FindBranchPusherIDs(ctx, repoID, branch)
		require.NoError(t, err)
		slices.Sort(ids)
		return ids
	}

	t.Run("a user", func(t *testing.T) {
		require.NoError(t, hook(1, "bp-user", zero, commit, private.HookOptions{UserID: 4}).Error)
		require.NoError(t, hook(1, "bp-user", zero, commit, private.HookOptions{UserID: 4}).Error)
		assert.Equal(t, []int64{4}, pushers(1, "bp-user"), "once per user")
		require.NoError(t, hook(1, "bp-user", zero, commit, private.HookOptions{UserID: 5}).Error)
		assert.Equal(t, []int64{4, 5}, pushers(1, "bp-user"))
		assert.Empty(t, pushers(1, "other-branch"))
		assert.Empty(t, pushers(2, "bp-user"), "per repository")
	})

	t.Run("a delete is no push", func(t *testing.T) {
		hook(1, "bp-delete", commit, zero, private.HookOptions{UserID: 4})
		assert.Empty(t, pushers(1, "bp-delete"))
	})

	t.Run("a push without permission records nothing", func(t *testing.T) {
		// user 10 can't write to repo1
		require.Error(t, hook(1, "bp-refused", zero, commit, private.HookOptions{UserID: 10}).Error)
		assert.Empty(t, pushers(1, "bp-refused"), "refused before it is accepted: no permission, nothing recorded")
	})

	t.Run("an access token identity is its creator", func(t *testing.T) {
		token := &auth_model.AccessToken{
			Name: "bp-token", OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1, Mode: perm_model.AccessModeWrite,
			Scope: "write:repository", ResourceAllRepos: true, CreatorID: 5,
		}
		require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), token, nil))
		bot := user_model.AccessTokenBotID(token.ID)
		require.NoError(t, hook(1, "bp-token", zero, commit, private.HookOptions{UserID: bot}).Error)
		assert.Equal(t, []int64{5}, pushers(1, "bp-token"))
	})

	t.Run("an Actions job is the user who triggered the run", func(t *testing.T) {
		task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
		require.NoError(t, task.LoadJob(ctx))
		_, err := db.GetEngine(ctx).Exec("UPDATE action_run SET trigger_user_id = 4 WHERE id = ?", task.Job.RunID)
		require.NoError(t, err)
		hook(task.RepoID, "bp-actions", zero, commit, private.HookOptions{UserID: user_model.ActionsUserID, ActionTaskID: task.ID})
		assert.Equal(t, []int64{4}, pushers(task.RepoID, "bp-actions"))
		// the Actions user without a task is nobody
		hook(task.RepoID, "bp-actions-none", zero, commit, private.HookOptions{UserID: user_model.ActionsUserID})
		assert.Empty(t, pushers(task.RepoID, "bp-actions-none"))
	})

	t.Run("a push nobody can be named for is user 0", func(t *testing.T) {
		task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
		require.NoError(t, task.LoadJob(ctx))
		runAs := func(branch string, triggerUserID int64) []int64 {
			_, err := db.GetEngine(ctx).Exec("UPDATE action_run SET trigger_user_id = ? WHERE id = ?", triggerUserID, task.Job.RunID)
			require.NoError(t, err)
			hook(task.RepoID, branch, zero, commit, private.HookOptions{UserID: user_model.ActionsUserID, ActionTaskID: task.ID})
			return pushers(task.RepoID, branch)
		}
		newToken := func(name string, creator int64) int64 {
			token := &auth_model.AccessToken{
				Name: name, OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: task.RepoID, Mode: perm_model.AccessModeWrite,
				Scope: "write:repository", ResourceAllRepos: true, CreatorID: creator,
			}
			require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), token, nil))
			return token.ID
		}
		assert.Equal(t, []int64{0}, runAs("bp-scheduled", user_model.ActionsUserID), "a scheduled run")
		assert.Equal(t, []int64{5}, runAs("bp-token-run", user_model.AccessTokenBotID(newToken("bp-run-token", 5))), "a run started by a token is its creator")
		assert.Equal(t, []int64{0}, runAs("bp-token-run-0", user_model.AccessTokenBotID(newToken("bp-run-token-0", 0))), "a token with no creator")
		assert.Equal(t, []int64{0}, runAs("bp-token-gone", user_model.AccessTokenBotID(99999)), "a token that is gone")
		assert.Equal(t, []int64{0}, runAs("bp-user-gone", 99999), "a user that is gone")

		// a token that pushes directly, with no creator
		bot := user_model.AccessTokenBotID(newToken("bp-direct-0", 0))
		require.NoError(t, hook(task.RepoID, "bp-direct-0", zero, commit, private.HookOptions{UserID: bot}).Error)
		assert.Equal(t, []int64{0}, pushers(task.RepoID, "bp-direct-0"))
	})

	t.Run("a deploy key is its creator, or marks a key with no recorded owner", func(t *testing.T) {
		owned, err := asymkey_model.AddDeployKey(asymkey_model.WithKeyCreator(ctx, 4), 1, "owned", newOrgDeployKeyContent(t), false, 0)
		require.NoError(t, err)
		assert.EqualValues(t, 4, unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{ID: owned.ID}).CreatorID)
		orphan, err := asymkey_model.AddDeployKey(ctx, 1, "orphan", newOrgDeployKeyContent(t), false, 0)
		require.NoError(t, err)
		assert.Zero(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{ID: orphan.ID}).CreatorID, "no user in the context")

		// as serv sets it: the repository owner as the pusher
		require.NoError(t, hook(1, "bp-key", zero, commit, private.HookOptions{UserID: 2, DeployKeyKeyID: owned.KeyID}).Error)
		assert.Equal(t, []int64{4}, pushers(1, "bp-key"))
		require.NoError(t, hook(1, "bp-key", zero, commit, private.HookOptions{UserID: 2, DeployKeyKeyID: orphan.KeyID}).Error)
		assert.Equal(t, []int64{0, 4}, pushers(1, "bp-key"), "user 0 makes the rule unsatisfiable")
	})
}

// Every way to add a deploy key records the user who adds it.
func TestDeployKeyCreatorRecorded(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)

	var repoKey api.DeployKey
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/keys", api.CreateKeyOption{Title: "api", Key: newOrgDeployKeyContent(t)}).AddTokenAuth(token), http.StatusCreated), &repoKey)
	assert.EqualValues(t, 2, unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{ID: repoKey.ID}).CreatorID)

	var orgKey api.OrgDeployKey
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/keys", api.CreateOrgDeployKeyOption{Title: "org", Key: newOrgDeployKeyContent(t), AllRepositories: true}).AddTokenAuth(token), http.StatusCreated), &orgKey)
	assert.EqualValues(t, 2, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: orgKey.ID}).CreatorID)

	project := createProjectForKeys(t, 3, "creator")
	var projectKey api.OrgDeployKey
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/keys", project.ID), api.CreateOrgDeployKeyOption{Title: "project", Key: newOrgDeployKeyContent(t)}).AddTokenAuth(token), http.StatusCreated), &projectKey)
	assert.EqualValues(t, 2, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: projectKey.ID}).CreatorID)

	// the web forms
	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/keys", map[string]string{"title": "web", "content": newOrgDeployKeyContent(t)}), http.StatusSeeOther)
	key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{RepoID: 1, Name: "web"})
	assert.EqualValues(t, 2, key.CreatorID)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/keys", map[string]string{"title": "web", "content": newOrgDeployKeyContent(t), "scope": "all"}), http.StatusSeeOther)
	assert.EqualValues(t, 2, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "web"}).CreatorID)
}
