// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"path/filepath"
	"strings"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertGroupRepo inserts a repository row in a group the way CreateRepositoryByExample stores it.
func insertGroupRepo(t *testing.T, owner *user_model.User, group *repo_model.RepoGroup, name string) *repo_model.Repository {
	t.Helper()
	repo := &repo_model.Repository{
		OwnerID: owner.ID, OwnerName: owner.Name, GroupID: group.ID, GroupName: group.Name,
		Name: name, LowerName: strings.ToLower(name),
	}
	require.NoError(t, db.Insert(db.DefaultContext, repo))
	return repo
}

func TestRepoGroupNameRules(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	_, err := repo_model.CreateRepoGroup(ctx, user2, "pay", "")
	require.Error(t, err, "users have no projects")

	for _, name := range []string{"", ".", "..", "-", "a.git", "a.wiki", "a.rss", "a.atom", "a b", "a/b", "a@b", strings.Repeat("a", 101)} {
		_, err := repo_model.CreateRepoGroup(ctx, org3, name, "")
		require.Error(t, err, name)
	}

	// a root repository's name, private or trashed, is taken; the error is the generic one
	for _, name := range []string{"repo3", "REPO21"} {
		_, err := repo_model.CreateRepoGroup(ctx, org3, name, "")
		require.True(t, repo_model.IsErrRepoAlreadyExist(err), name)
	}
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 32")
	require.NoError(t, err)
	_, err = repo_model.CreateRepoGroup(ctx, org3, "repo21", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err), "a trashed repository keeps its name")

	group, err := repo_model.CreateRepoGroup(ctx, org3, "Pay", "payments")
	require.NoError(t, err)
	assert.Equal(t, "pay", group.LowerName)
	_, err = repo_model.CreateRepoGroup(ctx, org3, "PAY", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	_, err = repo_model.CreateRepoGroup(ctx, org3, strings.Repeat("a", 100), "")
	require.NoError(t, err)
	_, err = repo_model.CreateRepoGroup(ctx, org17, "pay", "")
	require.NoError(t, err, "another organization's names are its own")

	// a root repository can't take a group's name; a repository in a group claims nothing
	err = repo_model.ClaimRepoName(ctx, &repo_model.Repository{OwnerID: org3.ID, OwnerName: org3.Name, Name: "pay"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	inGroup := insertGroupRepo(t, org3, group, "pay")
	require.NoError(t, repo_model.ClaimRepoName(ctx, inGroup))
	require.NoError(t, repo_model.ReleaseRepoName(ctx, inGroup))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "pay"})

	unittest.CheckRepoGroupNameClaims(t)
}

func TestGetRepositoryByPath(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})

	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	other, err := repo_model.CreateRepoGroup(ctx, org17, "pay", "")
	require.NoError(t, err)
	nested := insertGroupRepo(t, org3, pay, "repo3") // the leaf name of the root repository org3/repo3
	only := insertGroupRepo(t, org3, pay, "only-in-group")
	insertGroupRepo(t, org17, other, "elsewhere")

	repo, err := repo_model.GetRepositoryByPath(ctx, org3.ID, "PAY", "Repo3")
	require.NoError(t, err)
	assert.Equal(t, nested.ID, repo.ID)

	for _, c := range []struct {
		owner       int64
		group, name string
	}{
		{org3.ID, "", "repo3"},        // never a root repository
		{org3.ID, "pay", "repo5"},     // a root repository's name
		{org3.ID, "other", "repo3"},   // no such group
		{org17.ID, "pay", "repo3"},    // another organization's group of the same name
		{org3.ID, "pay", "elsewhere"}, // a repository of the other organization's group
		{org3.ID, "repo3", "repo3"},   // a root repository isn't a group
	} {
		_, err := repo_model.GetRepositoryByPath(ctx, c.owner, c.group, c.name)
		require.True(t, repo_model.IsErrRepoNotExist(err), "%v", c)
	}
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", nested.ID)
	require.NoError(t, err)
	_, err = repo_model.GetRepositoryByPath(ctx, org3.ID, "pay", "repo3")
	require.True(t, repo_model.IsErrRepoNotExist(err), "a trashed repository")

	// the single-segment lookups find root repositories only
	repo, err = repo_model.GetRepositoryByName(ctx, org3.ID, "repo3")
	require.NoError(t, err)
	assert.EqualValues(t, 3, repo.ID)
	repo, err = repo_model.GetRepositoryByOwnerAndName(ctx, "org3", "repo3")
	require.NoError(t, err)
	assert.EqualValues(t, 3, repo.ID)
	_, err = repo_model.GetRepositoryByName(ctx, org3.ID, only.Name)
	require.True(t, repo_model.IsErrRepoNotExist(err))
	_, err = repo_model.GetRepositoryByOwnerAndName(ctx, "org3", only.Name)
	require.True(t, repo_model.IsErrRepoNotExist(err))
	has, err := repo_model.IsRepositoryModelExist(ctx, org3, only.Name)
	require.NoError(t, err)
	assert.False(t, has)
	has, err = repo_model.IsRepositoryModelExistInGroup(ctx, org3.ID, pay.ID, only.Name)
	require.NoError(t, err)
	assert.True(t, has)
}

func TestRepoGroupPaths(t *testing.T) {
	defer test.MockVariableValue(&setting.AppURL, "https://host/")()
	defer test.MockVariableValue(&setting.AppSubURL, "")()
	defer test.MockVariableValue(&setting.SSH, setting.SSH)()
	defer test.MockVariableValue(&setting.Repository, setting.Repository)()
	setting.SSH.User, setting.SSH.Domain, setting.SSH.Port = "git", "host", 22
	setting.Repository.UseCompatSSHURI = false

	root := &repo_model.Repository{OwnerName: "Org3", Name: "Api"}
	assert.Equal(t, "Org3/Api", root.FullName())
	assert.Equal(t, repo_model.RepoPath("Org3", "Api"), root.RepoPath())
	assert.Equal(t, repo_model.WikiPath("Org3", "Api"), root.WikiPath())
	assert.Equal(t, "/Org3/Api", root.Link())
	assert.Equal(t, "https://host/Org3/Api", root.HTMLURL())
	assert.Equal(t, "https://host/api/v1/repos/Org3/Api", root.APIURL())
	assert.Equal(t, &repo_model.CloneLink{SSH: "git@host:Org3/Api.git", HTTPS: "https://host/Org3/Api.git"}, root.CloneLink())
	assert.Equal(t, &repo_model.CloneLink{SSH: "git@host:Org3/Api.wiki.git", HTTPS: "https://host/Org3/Api.wiki.git"}, root.WikiCloneLink())

	nested := &repo_model.Repository{OwnerName: "Org3", GroupID: 5, GroupName: "Pay", Name: "Api"}
	assert.Equal(t, "Org3/Pay/Api", nested.FullName())
	assert.Equal(t, filepath.Join(setting.RepoRootPath, "org3", "pay", "api.git"), nested.RepoPath())
	assert.Equal(t, filepath.Join(setting.RepoRootPath, "org3", "pay", "api.wiki.git"), nested.WikiPath())
	assert.Equal(t, "/Org3/Pay/Api", nested.Link())
	assert.Equal(t, "https://host/Org3/Pay/Api", nested.HTMLURL())
	assert.Equal(t, "https://host/api/v1/repos/Org3/Pay/Api/-", nested.APIURL())
	assert.Equal(t, &repo_model.CloneLink{SSH: "git@host:Org3/Pay/Api.git", HTTPS: "https://host/Org3/Pay/Api.git"}, nested.CloneLink())
	assert.Equal(t, &repo_model.CloneLink{SSH: "git@host:Org3/Pay/Api.wiki.git", HTTPS: "https://host/Org3/Pay/Api.wiki.git"}, nested.WikiCloneLink())

	// a missing group name never falls back to the root of the owner
	drifted := &repo_model.Repository{OwnerName: "Org3", GroupID: 5, Name: "Api"}
	assert.Equal(t, filepath.Join(setting.RepoRootPath, "org3", "@5", "api.git"), drifted.RepoPath())
	assert.NotEqual(t, root.RepoPath(), drifted.RepoPath())
	assert.NotEqual(t, root.WikiPath(), drifted.WikiPath())
	assert.Equal(t, "Org3/@5/Api", drifted.FullName())
}

func TestRepoGroupRenameDelete(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})

	group, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	live := insertGroupRepo(t, org3, group, "api")
	trashed := insertGroupRepo(t, org3, group, "old")
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", trashed.ID)
	require.NoError(t, err)

	require.ErrorIs(t, repo_model.RenameRepoGroup(ctx, org17, group, "billing"), repo_model.ErrRepoGroupNotExist)
	require.True(t, repo_model.IsErrRepoAlreadyExist(repo_model.RenameRepoGroup(ctx, org3, group, "repo5")))
	require.Error(t, repo_model.RenameRepoGroup(ctx, org3, group, "x.git"))

	require.NoError(t, repo_model.RenameRepoGroup(ctx, org3, group, "Billing"))
	for _, id := range []int64{live.ID, trashed.ID} {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
		assert.Equal(t, "Billing", repo.GroupName)
		assert.Equal(t, "org3/Billing/"+repo.Name, repo.FullName())
	}
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "pay"})
	unittest.CheckRepoGroupNameClaims(t)

	require.ErrorIs(t, repo_model.DeleteRepoGroup(ctx, group), repo_model.ErrRepoGroupNotEmpty)
	_, err = db.DeleteByID[repo_model.Repository](ctx, live.ID)
	require.NoError(t, err)
	require.ErrorIs(t, repo_model.DeleteRepoGroup(ctx, group), repo_model.ErrRepoGroupNotEmpty, "a trashed repository keeps its group")
	_, err = db.DeleteByID[repo_model.Repository](ctx, trashed.ID)
	require.NoError(t, err)
	require.NoError(t, repo_model.DeleteRepoGroup(ctx, group))
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroup{ID: group.ID})
	unittest.CheckRepoGroupNameClaims(t)

	_, err = repo_model.CreateRepoGroup(ctx, org3, "billing", "")
	require.NoError(t, err, "the name is free again")
}

func TestSearchRepositoryInProject(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	payments, err := repo_model.CreateRepoGroup(ctx, org, "payments", "")
	require.NoError(t, err)
	other, err := repo_model.CreateRepoGroup(ctx, org, "other", "")
	require.NoError(t, err)
	api := insertGroupRepo(t, org, payments, "api")
	web := insertGroupRepo(t, org, payments, "web")
	otherAPI := insertGroupRepo(t, org, other, "api")

	search := func(opts *repo_model.SearchRepoOptions) []int64 {
		t.Helper()
		opts.Actor, opts.Private = admin, true
		repos, _, err := repo_model.SearchRepository(ctx, opts)
		require.NoError(t, err)
		ids := []int64{}
		for _, repo := range repos {
			ids = append(ids, repo.ID)
		}
		return ids
	}
	assert.ElementsMatch(t, []int64{api.ID}, search(&repo_model.SearchRepoOptions{Keyword: "org3/payments/api"}))
	assert.ElementsMatch(t, []int64{api.ID}, search(&repo_model.SearchRepoOptions{Keyword: "ORG3/Payments/API"}))
	assert.ElementsMatch(t, []int64{api.ID, web.ID}, search(&repo_model.SearchRepoOptions{Keyword: "org3/payments/"}))
	assert.ElementsMatch(t, []int64{otherAPI.ID}, search(&repo_model.SearchRepoOptions{Keyword: "org3/other/api"}))
	// a root repository's name is no project
	assert.Empty(t, search(&repo_model.SearchRepoOptions{Keyword: "org3/repo3/"}))
	// org/repo is unchanged
	assert.Contains(t, search(&repo_model.SearchRepoOptions{Keyword: "org3/repo3"}), int64(3))

	assert.ElementsMatch(t, []int64{api.ID, web.ID}, search(&repo_model.SearchRepoOptions{OwnerID: org.ID, GroupID: payments.ID}))

	counts, err := repo_model.CountReposByGroup(ctx, &repo_model.SearchRepoOptions{Actor: admin, Private: true}, []int64{payments.ID, other.ID})
	require.NoError(t, err)
	assert.Equal(t, map[int64]int64{payments.ID: 2, other.ID: 1}, counts)
}

func TestGetRepositoryByRef(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	nested := insertGroupRepo(t, org3, pay, "repo3") // same leaf name as the root repository org3/repo3

	root, err := repo_model.GetRepositoryByRef(ctx, "ORG3", "", "Repo3")
	require.NoError(t, err)
	assert.EqualValues(t, 3, root.ID)
	inGroup, err := repo_model.GetRepositoryByRef(ctx, "org3", "PAY", "repo3")
	require.NoError(t, err)
	assert.Equal(t, nested.ID, inGroup.ID)

	for _, c := range [][3]string{
		{"org3", "pay", "repo5"}, // a root repository's name inside a project
		{"org3", "nope", "repo3"},
		{"nobody", "pay", "repo3"},
		{"org3", "repo3", "repo3"}, // a root repository isn't a project
	} {
		_, err := repo_model.GetRepositoryByRef(ctx, c[0], c[1], c[2])
		require.True(t, repo_model.IsErrRepoNotExist(err), "%v", c)
	}

	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", nested.ID)
	require.NoError(t, err)
	_, err = repo_model.GetRepositoryByRef(ctx, "org3", "pay", "repo3")
	require.True(t, repo_model.IsErrRepoNotExist(err), "a trashed repository")
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", nested.ID)
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE `user` SET trashed_unix = 1 WHERE id = ?", org3.ID)
	require.NoError(t, err)
	_, err = repo_model.GetRepositoryByRef(ctx, "org3", "pay", "repo3")
	require.True(t, repo_model.IsErrRepoNotExist(err), "a trashed owner")
}
