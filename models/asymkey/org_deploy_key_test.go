// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package asymkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newTestDeployKeyContent(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// prepareOrgDeployKeyTest loads the fixtures again afterwards: other tests count the public keys.
func prepareOrgDeployKeyTest(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(func() { require.NoError(t, unittest.PrepareTestDatabase()) })
}

func TestAddOrgDeployKey(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext

	t.Run("refuses a non-organization", func(t *testing.T) {
		for _, ownerID := range []int64{2, 9999} { // a user, nobody
			_, err := AddOrgDeployKey(ctx, ownerID, 0, "ci", newTestDeployKeyContent(t), true, true, nil, 0)
			require.ErrorIs(t, err, util.ErrInvalidArgument)
		}
	})

	t.Run("refuses an organization in the trash", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE `user` SET trashed_unix = 1 WHERE id = 17")
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE `user` SET trashed_unix = 0 WHERE id = 17")
			require.NoError(t, err)
		}()
		_, err = AddOrgDeployKey(ctx, 17, 0, "ci", newTestDeployKeyContent(t), true, true, nil, 0)
		require.ErrorIs(t, err, util.ErrInvalidArgument)
	})

	t.Run("refuses repositories of another owner or in the trash", func(t *testing.T) {
		content := newTestDeployKeyContent(t)
		_, err := AddOrgDeployKey(ctx, 3, 0, "ci", content, true, false, []int64{3, 1}, 0) // repo 1 is user2's
		require.ErrorIs(t, err, util.ErrInvalidArgument)

		_, err = db.Exec(ctx, "UPDATE repository SET trashed_unix = 1 WHERE id = 5")
		require.NoError(t, err)
		_, err = AddOrgDeployKey(ctx, 3, 0, "ci", content, true, false, []int64{5}, 0)
		require.ErrorIs(t, err, util.ErrInvalidArgument)
		_, err = db.Exec(ctx, "UPDATE repository SET trashed_unix = 0 WHERE id = 5")
		require.NoError(t, err)

		unittest.AssertNotExistsBean(t, &OrgDeployKey{OrgID: 3, Name: "ci"})
		unittest.AssertNotExistsBean(t, &PublicKey{Content: content}) // the transaction rolled back
	})

	t.Run("refuses a user's key", func(t *testing.T) {
		userKey := unittest.AssertExistsAndLoadBean(t, &PublicKey{ID: 1})
		_, err := AddOrgDeployKey(ctx, 3, 0, "ci", userKey.Content, true, true, nil, 0)
		assert.True(t, IsErrKeyAlreadyExist(err), "%v", err)
	})

	t.Run("shares the public key with a repository deploy key", func(t *testing.T) {
		content := newTestDeployKeyContent(t)
		repoKey, err := AddDeployKey(ctx, 3, "shared", content, true, 0)
		require.NoError(t, err)
		orgKey, err := AddOrgDeployKey(ctx, 3, 0, "shared", content, false, false, []int64{5, 5}, 0)
		require.NoError(t, err)
		assert.Equal(t, repoKey.KeyID, orgKey.KeyID)
		assert.Equal(t, perm.AccessModeWrite, orgKey.Mode)
		assert.Equal(t, 1, unittest.GetCount(t, &OrgDeployKeyRepo{OrgDeployKeyID: orgKey.ID}))

		_, err = AddOrgDeployKey(ctx, 3, 0, "shared", newTestDeployKeyContent(t), true, true, nil, 0)
		assert.True(t, IsErrDeployKeyNameAlreadyUsed(err), "names are unique per organization: %v", err)
		_, err = AddOrgDeployKey(ctx, 3, 0, "again", content, true, true, nil, 0)
		assert.True(t, IsErrDeployKeyAlreadyExist(err), "a key is added once per organization: %v", err)
		_, err = AddOrgDeployKey(ctx, 3, 0, "no repos", newTestDeployKeyContent(t), true, false, nil, 0)
		require.ErrorIs(t, err, util.ErrInvalidArgument, "selected repositories need at least one")
	})
}

func TestGetEffectiveDeployKey(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext
	repo := func(id int64) *repo_model.Repository {
		return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
	}
	effective := func(t *testing.T, keyID int64, r *repo_model.Repository) *EffectiveDeployKey {
		t.Helper()
		key, err := GetEffectiveDeployKey(ctx, keyID, r)
		require.NoError(t, err)
		return key
	}
	notCovered := func(t *testing.T, keyID int64, r *repo_model.Repository) {
		t.Helper()
		_, err := GetEffectiveDeployKey(ctx, keyID, r)
		assert.True(t, IsErrDeployKeyNotExist(err), "repo %d: %v", r.ID, err)
	}

	// org3 owns repos 3, 5 and 32; org17 owns repo 23; user2 owns repo 1
	allRead, err := AddOrgDeployKey(ctx, 3, 0, "all read", newTestDeployKeyContent(t), true, true, nil, 0)
	require.NoError(t, err)
	selectedWrite, err := AddOrgDeployKey(ctx, 3, 0, "repo5 write", newTestDeployKeyContent(t), false, false, []int64{5}, 0)
	require.NoError(t, err)

	t.Run("all repositories", func(t *testing.T) {
		for _, id := range []int64{3, 5, 32} {
			key := effective(t, allRead.KeyID, repo(id))
			assert.Equal(t, allRead.ID, key.OrgKey.ID)
			assert.Nil(t, key.RepoKey)
			assert.Equal(t, perm.AccessModeRead, key.Mode)
			assert.Equal(t, "all read", key.Name)
		}
		// a repository created later is covered too
		later := &repo_model.Repository{OwnerID: 3, OwnerName: "org3", Name: "later", LowerName: "later"}
		require.NoError(t, db.Insert(ctx, later))
		assert.Equal(t, allRead.ID, effective(t, allRead.KeyID, later).OrgKey.ID)
	})

	t.Run("selected repositories", func(t *testing.T) {
		assert.Equal(t, perm.AccessModeWrite, effective(t, selectedWrite.KeyID, repo(5)).Mode)
		notCovered(t, selectedWrite.KeyID, repo(3))
		notCovered(t, selectedWrite.KeyID, repo(32))
	})

	t.Run("never another owner's repository", func(t *testing.T) {
		// even with a selection row pointing at it
		require.NoError(t, db.Insert(ctx, &OrgDeployKeyRepo{OrgDeployKeyID: selectedWrite.ID, RepoID: 1}))
		require.NoError(t, db.Insert(ctx, &OrgDeployKeyRepo{OrgDeployKeyID: selectedWrite.ID, RepoID: 23}))
		for _, id := range []int64{1, 23} {
			notCovered(t, allRead.KeyID, repo(id))
			notCovered(t, selectedWrite.KeyID, repo(id))
		}
	})

	t.Run("moved repository", func(t *testing.T) {
		moved := repo(5)
		moved.OwnerID = 17
		notCovered(t, allRead.KeyID, moved)
		notCovered(t, selectedWrite.KeyID, moved)
	})

	t.Run("higher mode wins", func(t *testing.T) {
		// repo write + org read: the repository key
		repoWrite, err := AddDeployKey(ctx, 3, "repo write", publicKeyContent(t, allRead), false, 0)
		require.NoError(t, err)
		key := effective(t, allRead.KeyID, repo(3))
		assert.Equal(t, perm.AccessModeWrite, key.Mode)
		assert.Equal(t, repoWrite.ID, key.RepoKey.ID)
		assert.Nil(t, key.OrgKey)

		// repo read + org write: the organization key
		_, err = AddDeployKey(ctx, 5, "repo read", publicKeyContent(t, selectedWrite), true, 0)
		require.NoError(t, err)
		key = effective(t, selectedWrite.KeyID, repo(5))
		assert.Equal(t, perm.AccessModeWrite, key.Mode)
		assert.Equal(t, selectedWrite.ID, key.OrgKey.ID)

		// a tie: the repository key
		repoRead, err := AddDeployKey(ctx, 32, "repo read", publicKeyContent(t, allRead), true, 0)
		require.NoError(t, err)
		assert.Equal(t, repoRead.ID, effective(t, allRead.KeyID, repo(32)).RepoKey.ID)
	})

	t.Run("expired keys", func(t *testing.T) {
		past := timeutil.TimeStampNow() - 10
		content := newTestDeployKeyContent(t)
		orgKey, err := AddOrgDeployKey(ctx, 3, 0, "expired write", content, false, true, nil, past)
		require.NoError(t, err)

		// only an expired key: returned, so the caller can say it expired
		key := effective(t, orgKey.KeyID, repo(3))
		assert.True(t, key.IsExpired())
		assert.Equal(t, orgKey.ID, key.OrgKey.ID)

		// a valid read repository key wins over an expired write organization key
		repoKey, err := AddDeployKey(ctx, 3, "valid read", content, true, 0)
		require.NoError(t, err)
		key = effective(t, orgKey.KeyID, repo(3))
		assert.False(t, key.IsExpired())
		assert.Equal(t, repoKey.ID, key.RepoKey.ID)
		assert.Equal(t, perm.AccessModeRead, key.Mode)
	})

	t.Run("no key", func(t *testing.T) {
		notCovered(t, 999999, repo(3))
	})
}

func publicKeyContent(t *testing.T, key *OrgDeployKey) string {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &PublicKey{ID: key.KeyID}).Content
}

func TestDeleteOrgDeployKeys(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext

	onlyOrg, err := AddOrgDeployKey(ctx, 3, 0, "only org", newTestDeployKeyContent(t), true, false, []int64{3}, 0)
	require.NoError(t, err)
	sharedContent := newTestDeployKeyContent(t)
	shared, err := AddOrgDeployKey(ctx, 3, 0, "shared", sharedContent, true, true, nil, 0)
	require.NoError(t, err)
	_, err = AddDeployKey(ctx, 3, "shared", sharedContent, true, 0)
	require.NoError(t, err)
	other, err := AddOrgDeployKey(ctx, 17, 0, "other org", newTestDeployKeyContent(t), true, true, nil, 0)
	require.NoError(t, err)

	has, err := IsDeployKeyExistByKeyID(ctx, onlyOrg.KeyID)
	require.NoError(t, err)
	assert.True(t, has, "organization keys count as deploy keys")

	deleted, err := DeleteOrgDeployKeys(ctx, 3)
	require.NoError(t, err)
	assert.True(t, deleted)

	unittest.AssertNotExistsBean(t, &OrgDeployKey{OrgID: 3})
	unittest.AssertNotExistsBean(t, &OrgDeployKeyRepo{OrgDeployKeyID: onlyOrg.ID})
	unittest.AssertNotExistsBean(t, &PublicKey{ID: onlyOrg.KeyID})
	unittest.AssertExistsAndLoadBean(t, &PublicKey{ID: shared.KeyID}) // a repository deploy key still uses it
	unittest.AssertExistsAndLoadBean(t, &OrgDeployKey{ID: other.ID})
}

func TestSetOrgDeployKeyRepos(t *testing.T) {
	prepareOrgDeployKeyTest(t)
	ctx := db.DefaultContext

	key, err := AddOrgDeployKey(ctx, 3, 0, "ci", newTestDeployKeyContent(t), true, false, []int64{3}, 0)
	require.NoError(t, err)
	other, err := AddOrgDeployKey(ctx, 17, 0, "other", newTestDeployKeyContent(t), true, true, nil, 0)
	require.NoError(t, err)

	t.Run("a key of another organization is not found", func(t *testing.T) {
		_, err := GetOrgDeployKey(ctx, 3, 0, other.ID)
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		_, err = SetOrgDeployKeyRepos(ctx, 3, other.ID, false, []int64{3})
		assert.True(t, IsErrDeployKeyNotExist(err), "%v", err)
		unittest.AssertNotExistsBean(t, &OrgDeployKeyRepo{OrgDeployKeyID: other.ID})
	})

	t.Run("refused selections change nothing", func(t *testing.T) {
		for _, repoIDs := range [][]int64{nil, {5, 1}, {23}} { // none, user2's repository, org17's repository
			_, err := SetOrgDeployKeyRepos(ctx, 3, key.ID, false, repoIDs)
			require.ErrorIs(t, err, util.ErrInvalidArgument, "%v", repoIDs)
		}
		ids, err := GetOrgDeployKeyRepoIDs(ctx, []int64{key.ID})
		require.NoError(t, err)
		assert.Equal(t, []int64{3}, ids[key.ID])
	})

	t.Run("selected and all repositories", func(t *testing.T) {
		_, err := SetOrgDeployKeyRepos(ctx, 3, key.ID, false, []int64{5, 32, 5})
		require.NoError(t, err)
		ids, err := GetOrgDeployKeyRepoIDs(ctx, []int64{key.ID})
		require.NoError(t, err)
		assert.Equal(t, []int64{5, 32}, ids[key.ID])

		_, err = SetOrgDeployKeyRepos(ctx, 3, key.ID, true, nil)
		require.NoError(t, err)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &OrgDeployKey{ID: key.ID}).IncludesAllRepos)
		unittest.AssertNotExistsBean(t, &OrgDeployKeyRepo{OrgDeployKeyID: key.ID})
	})
}
