// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package accessreport

import (
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The report's access token rows cover the repositories CoversRepo says they cover, and give what the permission code
// gives the token's identity.
func TestTokenRowsMatchPermission(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(func() { require.NoError(t, unittest.PrepareTestDatabase()) })
	ctx := audit_model.WithSystem(db.DefaultContext, "test")

	// org3 owns repos 3, 5 and 32, user2 owns 1
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pa, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	_, err = db.Exec(ctx, "UPDATE repository SET group_id = ? WHERE id = 5", pa.ID)
	require.NoError(t, err)

	tokens := []*auth_model.AccessToken{
		{Name: "org all", OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3, Mode: perm_model.AccessModeWrite, ResourceAllRepos: true},
		{Name: "org selected", OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3, Mode: perm_model.AccessModeRead},
		{Name: "project", OwnerType: auth_model.AccessTokenOwnerProject, OwnerID: 3, GroupID: pa.ID, Mode: perm_model.AccessModeAdmin, ResourceAllRepos: true},
		{Name: "repo1", OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1, Mode: perm_model.AccessModeRead, ResourceAllRepos: true},
		{Name: "expired", OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 3, Mode: perm_model.AccessModeWrite, ResourceAllRepos: true, ExpiresUnix: timeutil.TimeStampNow() - 10},
		{Name: "revoked", OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 3, Mode: perm_model.AccessModeWrite, ResourceAllRepos: true},
	}
	for i, tok := range tokens {
		tok.Scope = "read:repository"
		var resources []*auth_model.AccessTokenResourceRepo
		if i == 1 {
			resources = []*auth_model.AccessTokenResourceRepo{{RepoID: 32}}
		}
		require.NoError(t, auth_model.NewAccessToken(ctx, tok, resources))
	}
	require.NoError(t, auth_model.DeleteOwnedAccessToken(ctx, auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 3}, tokens[5].ID, 2))

	repoIDs := []int64{1, 3, 5, 32}
	rows, err := Compute(ctx, Options{RepoIDs: repoIDs})
	require.NoError(t, err)
	got := map[int64][]string{}
	for _, r := range rows {
		if r.AccessToken == nil {
			continue
		}
		assert.Equal(t, "token", r.Type())
		got[r.Repo.ID] = append(got[r.Repo.ID], r.AccessToken.Name)

		bot, err := user_model.GetAccessTokenBot(ctx, user_model.AccessTokenBotID(r.AccessToken.ID))
		require.NoError(t, err)
		perm, err := access_model.GetUserRepoPermission(ctx, r.Repo, bot)
		require.NoError(t, err)
		for _, u := range r.Repo.Units {
			assert.Equal(t, perm.UnitAccessMode(u.Type), r.Perm.UnitAccessMode(u.Type), "%s on repo %d, %s", r.AccessToken.Name, r.Repo.ID, u.Type)
		}
		assert.Equal(t, r.AccessToken.IsUsable(), r.Paths[0].Applied)
	}
	assert.Equal(t, map[int64][]string{
		1:  {"repo1"},
		3:  {"expired", "org all"},
		5:  {"org all", "project"},
		32: {"org all", "org selected"},
	}, got)

	// the bulk lookup agrees with the lookup for one repository (organization and project tokens)
	for _, id := range repoIDs {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
		one, err := auth_model.FindOwnedAccessTokensCoveringRepo(ctx, repo.ID, repo.OwnerID, repo.GroupID)
		require.NoError(t, err)
		for _, tok := range one {
			assert.Contains(t, got[id], tok.Name, "repo %d", id)
		}
	}
}
