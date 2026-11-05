// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT
package repository_test

import (
	"io/fs"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/storage"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteRepository(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	t.Run("Normal", func(t *testing.T) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})

		require.NoError(t, repo_service.DeleteRepository(t.Context(), user2, repo, false))

		unittest.AssertExistsIf(t, false, &repo_model.Repository{ID: 1})
	})

	t.Run("Foreign key reference", func(t *testing.T) {
		repo := forgery.CreateRepository(t, user2, nil)
		accessToken := forgery.CreateAccessToken(t, user2, &forgery.CreateAccessTokenOptions{
			RepositoryIDs: []int64{repo.ID},
		})

		require.NoError(t, repo_service.DeleteRepository(t.Context(), user2, repo, false))

		unittest.AssertExistsIf(t, true, &auth_model.AccessToken{ID: accessToken.ID})
		unittest.AssertExistsIf(t, false, &auth_model.AccessTokenResourceRepo{RepoID: repo.ID})
	})

	t.Run("Dependency graph", func(t *testing.T) {
		repo := forgery.CreateRepository(t, user2, nil)
		other := forgery.CreateRepository(t, user2, nil)
		for _, r := range []*repo_model.Repository{repo, other} {
			require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(),
				&repo_model.DependencyScan{RepoID: r.ID, CommitSHA: "abc", Status: repo_model.DependencyScanOK},
				[]*repo_model.Dependency{{RepoID: r.ID, Ecosystem: "Go", Name: "x", Version: "v1"}}))
		}

		require.NoError(t, repo_service.DeleteRepository(t.Context(), user2, repo, false))

		unittest.AssertExistsIf(t, false, &repo_model.Dependency{RepoID: repo.ID})
		unittest.AssertExistsIf(t, false, &repo_model.DependencyScan{RepoID: repo.ID})
		unittest.AssertExistsIf(t, true, &repo_model.Dependency{RepoID: other.ID})
		unittest.AssertExistsIf(t, true, &repo_model.DependencyScan{RepoID: other.ID})
	})

	t.Run("Branch pushers", func(t *testing.T) {
		repo := forgery.CreateRepository(t, user2, nil)
		other := forgery.CreateRepository(t, user2, nil)
		for _, r := range []*repo_model.Repository{repo, other} {
			require.NoError(t, git_model.AddBranchPusher(t.Context(), r.ID, "main", 4))
		}

		require.NoError(t, repo_service.DeleteRepository(t.Context(), user2, repo, false))

		unittest.AssertExistsIf(t, false, &git_model.BranchPusher{RepoID: repo.ID})
		unittest.AssertExistsIf(t, true, &git_model.BranchPusher{RepoID: other.ID})
	})

	t.Run("Secret scanning", func(t *testing.T) {
		repo := forgery.CreateRepository(t, user2, nil)
		other := forgery.CreateRepository(t, user2, nil)
		for _, r := range []*repo_model.Repository{repo, other} {
			alert := &secretscan_model.Alert{RepoID: r.ID, RuleID: "github-token", Fingerprint: strings.Repeat("a", 64)}
			unittest.AssertSuccessfulInsert(t, &secretscan_model.Scan{RepoID: r.ID, Kind: secretscan_model.KindRepo, Status: secretscan_model.StatusOK})
			require.NoError(t, secretscan_model.InsertAlert(t.Context(), alert))
			loc := secretscan_model.NewLocation(r.ID, secretscan_model.KindRepo, "b1", "a.txt", 1, 1, "", "", "", 0)
			loc.AlertID = alert.ID
			unittest.AssertSuccessfulInsert(t, loc)
		}

		require.NoError(t, repo_service.DeleteRepository(t.Context(), user2, repo, false))

		for _, bean := range []any{&secretscan_model.Scan{RepoID: repo.ID}, &secretscan_model.Alert{RepoID: repo.ID}, &secretscan_model.Location{RepoID: repo.ID}} {
			unittest.AssertExistsIf(t, false, bean)
		}
		indexRows := func(id int64) int64 {
			n, err := db.GetEngine(t.Context()).Table("secret_scanning_alert_index").Where("group_id = ?", id).Count()
			require.NoError(t, err)
			return n
		}
		assert.Zero(t, indexRows(repo.ID))
		assert.EqualValues(t, 1, indexRows(other.ID))
		for _, bean := range []any{&secretscan_model.Scan{RepoID: other.ID}, &secretscan_model.Alert{RepoID: other.ID}, &secretscan_model.Location{RepoID: other.ID}} {
			unittest.AssertExistsIf(t, true, bean)
		}
	})

	t.Run("Attachment", func(t *testing.T) {
		repo := forgery.CreateRepository(t, user2, nil)

		attachment := &repo_model.Attachment{
			RepoID: repo.ID,
			UUID:   "sleepy",
		}
		unittest.AssertSuccessfulInsert(t, attachment)
		storage.Attachments.Save("s/l/sleepy", strings.NewReader("Sleepy cat photo"), 16)

		require.NoError(t, repo_service.DeleteRepository(t.Context(), user2, repo, false))

		unittest.AssertExistsIf(t, false, &repo_model.Attachment{ID: attachment.ID})
		_, err := storage.Attachments.Stat("s/l/sleepy")
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}
