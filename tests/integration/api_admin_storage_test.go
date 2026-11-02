// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"strconv"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/convert"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIAdminStorage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 3, 1<<30, 1<<20, 0)) // org3/repo3
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 1, 10, 1<<31, 0))    // user2/repo1

	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)
	owners := func(t *testing.T, query string) ([]*api.OwnerStorage, *http.Response) {
		t.Helper()
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/storage/owners"+query).AddTokenAuth(token), http.StatusOK)
		var result []*api.OwnerStorage
		DecodeJSON(t, resp, &result)
		return result, resp.Result()
	}

	t.Run("Summary", func(t *testing.T) {
		totals, err := repo_model.GetStorageTotals(db.DefaultContext)
		require.NoError(t, err)
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/storage/summary").AddTokenAuth(token), http.StatusOK)
		var summary api.StorageSummary
		DecodeJSON(t, resp, &summary)
		assert.Equal(t, api.StorageSummary{
			RepoCount:    totals.NumRepos,
			GitSize:      totals.GitSize,
			LFSSize:      totals.LFSSize,
			StorageSizes: convert.ToStorageSizes(totals),
			TotalSize:    totals.Size(),
			AverageSize:  (totals.GitSize + totals.LFSSize) / totals.NumRepos,
		}, summary)
	})

	t.Run("Owners", func(t *testing.T) {
		want, count, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{ListOptions: db.ListOptions{PageSize: 50}})
		require.NoError(t, err)
		got, resp := owners(t, "?limit=50")
		assert.Equal(t, strconv.FormatInt(count, 10), resp.Header.Get("X-Total-Count"))
		require.Len(t, got, len(want))
		for i, o := range want {
			assert.Equal(t, o.OwnerID, got[i].OwnerID)
			assert.Equal(t, o.Owner.Name, got[i].OwnerName)
			assert.Equal(t, o.GitSize, got[i].GitSize)
			assert.Equal(t, o.LFSSize, got[i].LFSSize)
			assert.Equal(t, o.Size(), got[i].TotalSize)
			assert.Equal(t, convert.ToStorageSizes(o.StorageStats), got[i].StorageSizes)
			assert.Equal(t, o.NumRepos, got[i].RepoCount)
		}
		assert.Equal(t, "user2", got[0].OwnerName)
		assert.Equal(t, "user", got[0].OwnerType)
		assert.Positive(t, got[0].Percent)
	})

	t.Run("Sort", func(t *testing.T) {
		def, _ := owners(t, "")
		got, _ := owners(t, "?sort=git")
		assert.Equal(t, "org3", got[0].OwnerName)
		assert.Equal(t, "org", got[0].OwnerType)

		got, _ = owners(t, "?sort=git&order=asc&limit=50")
		for i := 1; i < len(got); i++ {
			assert.LessOrEqual(t, got[i-1].GitSize, got[i].GitSize)
		}

		got, _ = owners(t, "?sort=lfs")
		assert.Equal(t, "user2", got[0].OwnerName)

		got, _ = owners(t, "?sort=logs") // only user5/repo4 has Actions logs in the fixtures
		assert.Equal(t, "user5", got[0].OwnerName)
		assert.Positive(t, got[0].LogsSize)
		got, _ = owners(t, "?sort=artifacts")
		assert.Equal(t, "user5", got[0].OwnerName)
		for _, key := range []string{"wiki", "attachments", "packages", "trash", "total"} {
			got, _ = owners(t, "?sort="+key+"&order=asc&limit=50")
			assert.Len(t, got, len(def), key)
		}

		bogus, _ := owners(t, "?sort=id;DROP%20TABLE%20repository&order=sideways")
		assert.Equal(t, def, bogus)
	})

	t.Run("Pagination", func(t *testing.T) {
		all, _ := owners(t, "?limit=50")
		got, resp := owners(t, "?limit=2&page=2")
		require.Len(t, got, 2)
		assert.Equal(t, all[2:4], got)
		assert.Equal(t, strconv.Itoa(len(all)), resp.Header.Get("X-Total-Count"))
		assert.NotEmpty(t, resp.Header.Get("Link"))
	})

	t.Run("Auth", func(t *testing.T) {
		for _, url := range []string{"/api/v1/admin/storage/summary", "/api/v1/admin/storage/owners"} {
			MakeRequest(t, NewRequest(t, "GET", url), http.StatusUnauthorized)
			MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeReadAdmin)), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository)), http.StatusForbidden)
		}
	})
}
