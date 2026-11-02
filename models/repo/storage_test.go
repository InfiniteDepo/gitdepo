// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	packages_model "forgejo.org/models/packages"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectedStorage computes the storage per owner and in total from the beans, independently of the SQL.
func expectedStorage(t *testing.T) (map[int64]*repo_model.StorageStats, repo_model.StorageStats) {
	t.Helper()
	ctx := db.DefaultContext
	want := map[int64]*repo_model.StorageStats{}
	owner := func(id int64) *repo_model.StorageStats {
		if want[id] == nil {
			want[id] = &repo_model.StorageStats{}
		}
		return want[id]
	}
	var total repo_model.StorageStats
	add := func(ownerID int64, f func(s *repo_model.StorageStats)) {
		f(owner(ownerID))
		f(&total)
	}

	var repos []*repo_model.Repository
	require.NoError(t, db.GetEngine(ctx).Find(&repos))
	repoOwner := map[int64]int64{}
	for _, r := range repos {
		repoOwner[r.ID] = r.OwnerID
		add(r.OwnerID, func(s *repo_model.StorageStats) {
			if r.IsTrashed() {
				s.TrashSize += r.GitSize + r.LFSSize + r.WikiSize
				return
			}
			s.NumRepos++
			s.GitSize += r.GitSize
			s.LFSSize += r.LFSSize
			s.WikiSize += r.WikiSize
		})
	}
	var attachments []*repo_model.Attachment
	require.NoError(t, db.GetEngine(ctx).Find(&attachments))
	for _, a := range attachments {
		if ownerID, ok := repoOwner[a.RepoID]; ok {
			add(ownerID, func(s *repo_model.StorageStats) { s.AttachmentsSize += a.Size })
		}
	}
	var artifacts []*actions_model.ActionArtifact
	require.NoError(t, db.GetEngine(ctx).Find(&artifacts))
	for _, a := range artifacts {
		if ownerID, ok := repoOwner[a.RepoID]; ok && a.Status < int64(actions_model.ArtifactStatusExpired) {
			add(ownerID, func(s *repo_model.StorageStats) { s.ArtifactsSize += a.FileCompressedSize })
		}
	}
	var tasks []*actions_model.ActionTask
	require.NoError(t, db.GetEngine(ctx).Find(&tasks))
	for _, task := range tasks {
		if ownerID, ok := repoOwner[task.RepoID]; ok && !task.LogExpired {
			add(ownerID, func(s *repo_model.StorageStats) { s.LogsSize += task.LogSize })
		}
	}

	// packages: each blob once per owner, and once in the total
	var files []*packages_model.PackageFile
	require.NoError(t, db.GetEngine(ctx).Find(&files))
	ownerBlobs, siteBlobs := map[[2]int64]bool{}, map[int64]bool{}
	for _, f := range files {
		version := &packages_model.PackageVersion{ID: f.VersionID}
		has, err := db.GetEngine(ctx).Get(version)
		require.NoError(t, err)
		require.True(t, has)
		pkg := &packages_model.Package{ID: version.PackageID}
		has, err = db.GetEngine(ctx).Get(pkg)
		require.NoError(t, err)
		require.True(t, has)
		blob := &packages_model.PackageBlob{ID: f.BlobID}
		has, err = db.GetEngine(ctx).Get(blob)
		require.NoError(t, err)
		require.True(t, has)
		if key := [2]int64{pkg.OwnerID, blob.ID}; !ownerBlobs[key] {
			ownerBlobs[key] = true
			owner(pkg.OwnerID).PackagesSize += blob.Size
		}
		if !siteBlobs[blob.ID] {
			siteBlobs[blob.ID] = true
			total.PackagesSize += blob.Size
		}
	}
	return want, total
}

// prepareStorage gives the fixtures every type of storage: wiki, attachments, an expired artifact and log that
// must not count, a trashed repository, a package blob shared by two owners and an owner with only packages.
func prepareStorage(t *testing.T) {
	t.Helper()
	ctx := db.DefaultContext
	require.NoError(t, repo_model.UpdateRepoSize(ctx, 1, 1000, 1<<40, 300)) // user2
	require.NoError(t, repo_model.UpdateRepoSize(ctx, 3, 1<<30, 7, 0))      // org3
	require.NoError(t, repo_model.UpdateRepoSize(ctx, 5, 1<<20, 3, 11))     // org3, trashed below
	_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 5")
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE attachment SET size = id * 100")
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &actions_model.ActionArtifact{RunID: 999, RepoID: 4, ArtifactName: "old", ArtifactPath: "old", FileCompressedSize: 1 << 30, Status: int64(actions_model.ArtifactStatusExpired)}))
	require.NoError(t, db.Insert(ctx, &actions_model.ActionTask{RepoID: 4, LogSize: 1 << 30, LogExpired: true, TokenHash: "expired-log", TokenLastEight: "expired"}))

	blob := &packages_model.PackageBlob{Size: 5000, HashMD5: "md5", HashSHA1: "sha1", HashSHA256: "sha256", HashSHA512: "sha512"}
	require.NoError(t, db.Insert(ctx, blob))
	for i, ownerID := range []int64{3, 8, 8} { // org3, and user8, which has no repositories
		pkg := &packages_model.Package{OwnerID: ownerID, Type: packages_model.TypeGeneric, Name: fmt.Sprint("pkg", i), LowerName: fmt.Sprint("pkg", i)}
		require.NoError(t, db.Insert(ctx, pkg))
		version := &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1"}
		require.NoError(t, db.Insert(ctx, version))
		for _, name := range []string{"a", "b"} { // two files of one blob
			require.NoError(t, db.Insert(ctx, &packages_model.PackageFile{VersionID: version.ID, BlobID: blob.ID, Name: name, LowerName: name}))
		}
	}
}

func TestStorageReport(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	prepareStorage(t)
	want, total := expectedStorage(t)
	require.Equal(t, int64(5000), want[8].PackagesSize, "a blob counts once per owner")
	require.Equal(t, int64(5000), want[3].PackagesSize)
	require.Equal(t, int64(5000), total.PackagesSize, "and once in the total")
	require.Equal(t, int64(1<<20+3+11), want[3].TrashSize)
	require.Positive(t, want[2].AttachmentsSize)
	require.Positive(t, want[5].ArtifactsSize)
	require.Positive(t, want[5].LogsSize)
	require.Less(t, want[5].ArtifactsSize, int64(1<<30), "expired artifacts don't count")

	t.Run("Totals", func(t *testing.T) {
		got, err := repo_model.GetStorageTotals(db.DefaultContext)
		require.NoError(t, err)
		assert.Equal(t, total, got)
		assert.Equal(t, total.GitSize+total.LFSSize+total.WikiSize+total.AttachmentsSize+total.PackagesSize+total.ArtifactsSize+total.LogsSize, got.Size())
	})

	t.Run("AllOwners", func(t *testing.T) {
		owners, count, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{})
		require.NoError(t, err)
		assert.EqualValues(t, len(want), count)
		require.Len(t, owners, len(want))
		for i, o := range owners {
			assert.Equal(t, *want[o.OwnerID], o.StorageStats, "owner %d", o.OwnerID)
			assert.Equal(t, o.OwnerID, o.Owner.ID)
			if i > 0 {
				assert.GreaterOrEqual(t, owners[i-1].Size(), o.Size())
			}
		}
		assert.EqualValues(t, 2, owners[0].OwnerID)
		assert.NotNil(t, want[8], "an owner with only packages is listed")
	})

	t.Run("OwnerTotals", func(t *testing.T) {
		got, err := repo_model.GetOwnerStorageTotals(db.DefaultContext, 3)
		require.NoError(t, err)
		assert.Equal(t, repo_model.StorageStats{NumRepos: want[3].NumRepos, GitSize: want[3].GitSize, LFSSize: want[3].LFSSize, WikiSize: want[3].WikiSize, TrashSize: want[3].TrashSize}, got)
	})

	t.Run("AssetSizesByRepo", func(t *testing.T) {
		sizes, err := repo_model.AssetSizesByRepo(db.DefaultContext)
		require.NoError(t, err)
		var attachments []*repo_model.Attachment
		require.NoError(t, db.GetEngine(db.DefaultContext).Where("repo_id = 1").Find(&attachments))
		var repo1 int64
		for _, a := range attachments {
			repo1 += a.Size
		}
		assert.Equal(t, repo1, sizes[1].AttachmentsSize)
		assert.Equal(t, want[5].ArtifactsSize, sizes[4].ArtifactsSize) // user5 has only repo4
		assert.Equal(t, want[5].LogsSize, sizes[4].LogsSize)
		assert.NotContains(t, sizes, int64(0), "unlinked attachments belong to no repository")
	})

	t.Run("Sort", func(t *testing.T) {
		owners, _, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OrderBy: "reversegitsize"})
		require.NoError(t, err)
		assert.EqualValues(t, 3, owners[0].OwnerID)

		owners, _, err = repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OrderBy: "mostrepos"})
		require.NoError(t, err)
		for i := 1; i < len(owners); i++ {
			assert.GreaterOrEqual(t, owners[i-1].NumRepos, owners[i].NumRepos)
		}

		for key := range repo_model.OwnerStorageOrderBy {
			owners, _, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OrderBy: key})
			require.NoError(t, err, key)
			require.Len(t, owners, len(want), key)
			value := func(o *repo_model.OwnerStorage) int64 {
				return map[string]int64{
					"size": o.Size(), "gitsize": o.GitSize, "lfssize": o.LFSSize, "wikisize": o.WikiSize,
					"attachmentssize": o.AttachmentsSize, "packagessize": o.PackagesSize, "artifactssize": o.ArtifactsSize,
					"logssize": o.LogsSize, "trashsize": o.TrashSize, "fewestrepos": o.NumRepos, "mostrepos": o.NumRepos,
				}[strings.TrimPrefix(key, "reverse")]
			}
			for i := 1; i < len(owners); i++ {
				if strings.HasPrefix(key, "reverse") || key == "mostrepos" {
					assert.GreaterOrEqual(t, value(owners[i-1]), value(owners[i]), key)
				} else {
					assert.LessOrEqual(t, value(owners[i-1]), value(owners[i]), key)
				}
			}
		}

		// an unknown key falls back to reversesize
		owners, _, err = repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OrderBy: "id; DROP TABLE repository"})
		require.NoError(t, err)
		assert.EqualValues(t, 2, owners[0].OwnerID)
	})

	t.Run("Filters", func(t *testing.T) {
		owners, count, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{Keyword: "USER2"})
		require.NoError(t, err)
		assert.EqualValues(t, len(owners), count)
		assert.NotEmpty(t, owners)
		for _, o := range owners {
			assert.Contains(t, o.Owner.LowerName, "user2")
		}

		owners, count, err = repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OwnerType: optional.Some(user_model.UserTypeOrganization)})
		require.NoError(t, err)
		assert.EqualValues(t, len(owners), count)
		assert.NotEmpty(t, owners)
		for _, o := range owners {
			assert.True(t, o.Owner.IsOrganization())
		}
	})

	t.Run("Pagination", func(t *testing.T) {
		owners, count, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{ListOptions: db.ListOptions{Page: 2, PageSize: 2}})
		require.NoError(t, err)
		assert.EqualValues(t, len(want), count)
		assert.Len(t, owners, 2)
	})
}

func TestMedianRepoSize(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	// distinct sizes, with git and LFS both counted
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET git_size = id * 10, lfs_size = id")
	require.NoError(t, err)

	median := func(t *testing.T) (got, want int64) {
		t.Helper()
		var all []*repo_model.Repository
		require.NoError(t, db.GetEngine(db.DefaultContext).Find(&all))
		var sizes []int64
		for _, r := range all {
			if !r.IsTrashed() {
				sizes = append(sizes, r.GitSize+r.LFSSize)
			}
		}
		slices.Sort(sizes)
		if n := len(sizes); n%2 == 1 {
			want = sizes[n/2]
		} else if n > 0 {
			want = (sizes[n/2-1] + sizes[n/2]) / 2
		}
		got, err := repo_model.GetMedianRepoSize(db.DefaultContext, int64(len(sizes)))
		require.NoError(t, err)
		return got, want
	}

	got, want := median(t)
	assert.Equal(t, want, got)

	// flip the parity of the repository count
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Repository{OwnerID: 2, OwnerName: "user2", Name: "median", LowerName: "median", GitSize: 1 << 20}))
	got2, want2 := median(t)
	assert.Equal(t, want2, got2)
	assert.NotEqual(t, want, want2, "the second median is taken at the other parity")

	// trashed repositories are left out, like from the repository count
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id <= 3")
	require.NoError(t, err)
	got3, want3 := median(t)
	assert.Equal(t, want3, got3)
	assert.NotEqual(t, want2, want3)

	got, err = repo_model.GetMedianRepoSize(db.DefaultContext, 0)
	require.NoError(t, err)
	assert.Zero(t, got)
}

func TestParseSizeFilter(t *testing.T) {
	f, err := repo_model.ParseSizeFilter("", "", "")
	require.NoError(t, err)
	assert.Empty(t, f.Field)

	f, err = repo_model.ParseSizeFilter("lfs", "10GB", "")
	require.NoError(t, err)
	assert.Equal(t, repo_model.SizeFilter{Field: "lfs", Min: optional.Some[int64](10_000_000_000)}, f)

	f, err = repo_model.ParseSizeFilter("total", "123", "10 GiB")
	require.NoError(t, err)
	assert.Equal(t, repo_model.SizeFilter{Field: "total", Min: optional.Some[int64](123), Max: optional.Some[int64](10 << 30)}, f)

	for _, bad := range [][3]string{
		{"git", "abc", ""},
		{"git", "-1", ""},
		{"git", "1;DROP TABLE repository", ""},
		{"git", "", "99999999999EB"},
		{"git", "", "16EiB"},
		{"git", "2MB", "1MB"},
		{"size; --", "1", ""},
		{"", "1MB", ""},
		{"GIT", "1MB", ""},
	} {
		_, err := repo_model.ParseSizeFilter(bad[0], bad[1], bad[2])
		assert.Error(t, err, "%q", bad)
	}
}
