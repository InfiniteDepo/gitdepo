// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package asymkey

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestProject(t *testing.T, ownerID int64, name string) *repo_model.RepoGroup {
	t.Helper()
	group, err := repo_model.CreateRepoGroup(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: ownerID}), name, "")
	require.NoError(t, err)
	return group
}

func setRepoGroup(t *testing.T, repoID, groupID int64) *repo_model.Repository {
	t.Helper()
	_, err := db.Exec(db.DefaultContext, "UPDATE repository SET group_id = ? WHERE id = ?", groupID, repoID)
	require.NoError(t, err)
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
}

// A project key covers the repositories that are in its project now, nothing else.
func TestProjectDeployKeyCoverage(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext
	// org3 owns repos 3, 5 and 32; org17 owns repo 23; user2 owns repo 1
	pa, pb := createTestProject(t, 3, "pa"), createTestProject(t, 3, "pb")
	key, err := AddOrgDeployKey(ctx, 3, pa.ID, "pa write", newTestDeployKeyContent(t), false, false, nil, 0)
	require.NoError(t, err)
	assert.Equal(t, pa.ID, key.GroupID)

	inPA := setRepoGroup(t, 5, pa.ID)
	inPB := setRepoGroup(t, 32, pb.ID)
	otherOrg := setRepoGroup(t, 23, pa.ID) // org17's repository with the same group_id value
	root := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	user := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})

	effective, err := GetEffectiveDeployKey(ctx, key.KeyID, inPA)
	require.NoError(t, err)
	assert.Equal(t, key.ID, effective.OrgKey.ID)
	assert.Equal(t, perm.AccessModeWrite, effective.Mode)
	for _, r := range []*repo_model.Repository{inPB, otherOrg, root, user} {
		_, err := GetEffectiveDeployKey(ctx, key.KeyID, r)
		assert.True(t, IsErrDeployKeyNotExist(err), "repo %d: %v", r.ID, err)
	}

	t.Run("forged rows don't widen it", func(t *testing.T) {
		require.NoError(t, db.Insert(ctx, &OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: 3}))
		_, err := db.Exec(ctx, "UPDATE org_deploy_key SET includes_all_repos = ? WHERE id = ?", true, key.ID)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE org_deploy_key SET includes_all_repos = ? WHERE id = ?", false, key.ID)
			require.NoError(t, err)
			_, err = db.GetEngine(ctx).Delete(&OrgDeployKeyRepo{OrgDeployKeyID: key.ID})
			require.NoError(t, err)
		}()
		_, err = GetEffectiveDeployKey(ctx, key.KeyID, root)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		_, err = GetEffectiveDeployKey(ctx, key.KeyID, inPB)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
	})

	t.Run("a move changes coverage", func(t *testing.T) {
		out := setRepoGroup(t, 5, 0)
		_, err := GetEffectiveDeployKey(ctx, key.KeyID, out)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		in := setRepoGroup(t, 32, pa.ID)
		_, err = GetEffectiveDeployKey(ctx, key.KeyID, in)
		require.NoError(t, err)
	})
}

// Ties go to the more specific key: repository, then project, then organization.
func TestProjectDeployKeyPrecedence(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext
	pa := createTestProject(t, 3, "pa")
	repo := setRepoGroup(t, 5, pa.ID)
	past := timeutil.TimeStampNow() - 10

	for _, c := range []struct {
		name                     string
		repo, project, org       perm.AccessMode // AccessModeNone: no such key
		projectExpired, orgExpir bool
		want                     string
	}{
		{name: "project and org tie", project: perm.AccessModeWrite, org: perm.AccessModeWrite, want: "project"},
		{name: "org writes", project: perm.AccessModeRead, org: perm.AccessModeWrite, want: "org"},
		{name: "project writes", project: perm.AccessModeWrite, org: perm.AccessModeRead, want: "project"},
		{name: "repo and project tie", repo: perm.AccessModeRead, project: perm.AccessModeRead, want: "repo"},
		{name: "project over repo read", repo: perm.AccessModeRead, project: perm.AccessModeWrite, want: "project"},
		{name: "expired project", project: perm.AccessModeWrite, org: perm.AccessModeRead, projectExpired: true, want: "org"},
		{name: "expired org", project: perm.AccessModeRead, org: perm.AccessModeWrite, orgExpir: true, want: "project"},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := newTestDeployKeyContent(t)
			var keyID int64
			if c.repo != perm.AccessModeNone {
				k, err := AddDeployKey(ctx, repo.ID, c.name, content, c.repo == perm.AccessModeRead, 0)
				require.NoError(t, err)
				keyID = k.KeyID
			}
			add := func(groupID int64, mode perm.AccessMode, expired bool) {
				if mode == perm.AccessModeNone {
					return
				}
				var expires timeutil.TimeStamp
				if expired {
					expires = past
				}
				k, err := AddOrgDeployKey(ctx, 3, groupID, c.name, content, mode == perm.AccessModeRead, groupID == 0, nil, expires)
				require.NoError(t, err)
				keyID = k.KeyID
			}
			add(pa.ID, c.project, c.projectExpired)
			add(0, c.org, c.orgExpir)

			effective, err := GetEffectiveDeployKey(ctx, keyID, repo)
			require.NoError(t, err)
			got := "repo"
			if effective.OrgKey != nil {
				got = "org"
				if effective.OrgKey.GroupID == pa.ID {
					got = "project"
				}
			}
			assert.Equal(t, c.want, got)
			assert.False(t, effective.IsExpired())
		})
	}
}

// Project keys are reached only with their project: the organization's functions never see them.
func TestProjectDeployKeyScope(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext
	pa, pb := createTestProject(t, 3, "pa"), createTestProject(t, 3, "pb")
	other := createTestProject(t, 17, "other")
	content := newTestDeployKeyContent(t)
	key, err := AddOrgDeployKey(ctx, 3, pa.ID, "ci", content, true, false, nil, 0)
	require.NoError(t, err)

	t.Run("refused rows", func(t *testing.T) {
		_, err := AddOrgDeployKey(ctx, 3, pa.ID, "all", newTestDeployKeyContent(t), true, true, nil, 0)
		require.ErrorIs(t, err, util.ErrInvalidArgument, "a project key covers its project only")
		_, err = AddOrgDeployKey(ctx, 3, pa.ID, "sel", newTestDeployKeyContent(t), true, false, []int64{3}, 0)
		require.ErrorIs(t, err, util.ErrInvalidArgument, "a project key has no selection")
		for _, groupID := range []int64{other.ID, 99999} { // another organization's project, none
			_, err = AddOrgDeployKey(ctx, 3, groupID, "x", newTestDeployKeyContent(t), true, false, nil, 0)
			require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist)
		}
		_, err = AddOrgDeployKey(ctx, 3, pa.ID, "ci", newTestDeployKeyContent(t), true, false, nil, 0)
		assert.True(t, IsErrDeployKeyNameAlreadyUsed(err), "%v", err)
		_, err = AddOrgDeployKey(ctx, 3, pa.ID, "again", content, true, false, nil, 0)
		assert.True(t, IsErrDeployKeyAlreadyExist(err), "%v", err)
	})

	t.Run("same name and key on the org and another project", func(t *testing.T) {
		orgKey, err := AddOrgDeployKey(ctx, 3, 0, "ci", content, true, true, nil, 0)
		require.NoError(t, err)
		pbKey, err := AddOrgDeployKey(ctx, 3, pb.ID, "ci", content, true, false, nil, 0)
		require.NoError(t, err)
		assert.Equal(t, key.KeyID, orgKey.KeyID)
		assert.Equal(t, key.KeyID, pbKey.KeyID)
	})

	t.Run("bound lookups", func(t *testing.T) {
		got, err := GetOrgDeployKey(ctx, 3, pa.ID, key.ID)
		require.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
		for _, scope := range [][2]int64{{3, 0}, {3, pb.ID}, {17, pa.ID}} {
			_, err := GetOrgDeployKey(ctx, scope[0], scope[1], key.ID)
			assert.True(t, IsErrDeployKeyNotExist(err), "%v: %v", scope, err)
		}

		orgKeys, err := FindOrgDeployKeys(ctx, 3, 0)
		require.NoError(t, err)
		for _, k := range orgKeys {
			assert.Zero(t, k.GroupID)
		}
		paKeys, err := FindOrgDeployKeys(ctx, 3, pa.ID)
		require.NoError(t, err)
		require.Len(t, paKeys, 1)
		assert.Equal(t, key.ID, paKeys[0].ID)
	})

	t.Run("org selection changes don't touch it", func(t *testing.T) {
		_, err := SetOrgDeployKeyRepos(ctx, 3, key.ID, true, nil)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		_, err = SetOrgDeployKeyAllRepos(ctx, 3, key.ID, true)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		_, err = AddOrgDeployKeyRepo(ctx, 3, key.ID, 3)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		_, err = RemoveOrgDeployKeyRepo(ctx, 3, key.ID, 3)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		stored := unittest.AssertExistsAndLoadBean(t, &OrgDeployKey{ID: key.ID})
		assert.False(t, stored.IncludesAllRepos)
		unittest.AssertNotExistsBean(t, &OrgDeployKeyRepo{OrgDeployKeyID: key.ID})
	})

	t.Run("org deletion takes the project keys", func(t *testing.T) {
		deleted, err := DeleteOrgDeployKeys(ctx, 3)
		require.NoError(t, err)
		assert.True(t, deleted)
		unittest.AssertNotExistsBean(t, &OrgDeployKey{OrgID: 3})
		unittest.AssertNotExistsBean(t, &PublicKey{ID: key.KeyID})
	})
}

// The coverage matrix, in the value form (FindOrgDeployKeysCoveringRepo, GetEffectiveDeployKey) and the joined form
// (FindOrgDeployKeysCoveringRepos): an organization key and a project key against a root repository, a repository in
// the project, one in another project and one of another organization with the project's ID as group_id.
func TestProjectDeployKeyCoverageMatrix(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext
	pa, pb := createTestProject(t, 3, "pa"), createTestProject(t, 3, "pb")
	orgKey, err := AddOrgDeployKey(ctx, 3, 0, "org", newTestDeployKeyContent(t), true, true, nil, 0)
	require.NoError(t, err)
	projectKey, err := AddOrgDeployKey(ctx, 3, pa.ID, "project", newTestDeployKeyContent(t), true, false, nil, 0)
	require.NoError(t, err)

	repos := map[string]*repo_model.Repository{
		"root":            unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}),
		"in project":      setRepoGroup(t, 5, pa.ID),
		"other project":   setRepoGroup(t, 32, pb.ID),
		"other org":       setRepoGroup(t, 23, pa.ID),
		"user repository": setRepoGroup(t, 1, pa.ID),
	}
	want := map[string][]int64{
		"root":          {orgKey.ID},
		"in project":    {orgKey.ID, projectKey.ID},
		"other project": {orgKey.ID},
	}
	repoIDs := make([]int64, 0, len(repos))
	for _, r := range repos {
		repoIDs = append(repoIDs, r.ID)
	}
	joined, err := FindOrgDeployKeysCoveringRepos(ctx, repoIDs)
	require.NoError(t, err)

	for name, r := range repos {
		value, err := FindOrgDeployKeysCoveringRepo(ctx, r)
		require.NoError(t, err)
		var valueIDs, joinedIDs []int64
		for _, k := range value {
			valueIDs = append(valueIDs, k.ID)
		}
		for _, k := range joined {
			if k.RepoID == r.ID {
				joinedIDs = append(joinedIDs, k.ID)
			}
		}
		assert.ElementsMatch(t, want[name], valueIDs, "value form: %s", name)
		assert.ElementsMatch(t, want[name], joinedIDs, "joined form: %s", name)
		for _, k := range []*OrgDeployKey{orgKey, projectKey} {
			_, err := GetEffectiveDeployKey(ctx, k.KeyID, r)
			covered := false
			for _, id := range want[name] {
				covered = covered || id == k.ID
			}
			if covered {
				require.NoError(t, err, "%s: %s", name, k.Name)
			} else {
				assert.True(t, IsErrDeployKeyNotExist(err), "%s: %s: %v", name, k.Name, err)
			}
		}
	}
}
