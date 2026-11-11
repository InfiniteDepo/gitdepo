// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	code_indexer "forgejo.org/modules/indexer/code"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	repo_service "forgejo.org/services/repository"
	files_service "forgejo.org/services/repository/files"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func codeSearchFiles(t *testing.T, repo *repo_model.Repository, branch string, all bool, mode code_indexer.SearchMode, keyword string) []string {
	t.Helper()
	_, res, _, err := code_indexer.PerformSearch(t.Context(), &code_indexer.SearchOptions{
		RepoIDs:     []int64{repo.ID},
		Keyword:     keyword,
		Branch:      branch,
		AllBranches: all,
		Mode:        mode,
		Paginator:   &db.ListOptions{Page: 1, PageSize: 50},
	})
	require.NoError(t, err)
	names := make([]string, 0, len(res))
	for _, r := range res {
		names = append(names, r.Filename)
	}
	return names
}

func setIndexedBranches(t *testing.T, repo *repo_model.Repository, patterns ...string) {
	t.Helper()
	require.NoError(t, repo_service.UpdateRepositoryUnits(db.DefaultContext, repo, []repo_model.RepoUnit{{
		RepoID: repo.ID,
		Type:   unit.TypeCode,
		Config: &repo_model.CodeConfig{IndexedBranches: patterns},
	}}, nil))
}

func newBranchFile(t *testing.T, user *user_model.User, repo *repo_model.Repository, from, to, path, content string) {
	t.Helper()
	_, err := files_service.ChangeRepoFiles(git.DefaultContext, repo, user, &files_service.ChangeRepoFilesOptions{
		Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: path, ContentReader: strings.NewReader(content)}},
		OldBranch: from,
		NewBranch: to,
	})
	require.NoError(t, err)
}

func TestCodeSearchBranches(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)

	newBranchFile(t, user, repo, repo.DefaultBranch, "idxdev", "dev_only.go", "func OnlyOnDevelop() {}")

	// AC5: with no list set only the default branch is indexed and searched.
	code_indexer.UpdateRepoIndexer(repo)
	assert.Empty(t, codeSearchFiles(t, repo, "", false, code_indexer.SearchModeExact, "OnlyOnDevelop"))
	rows, err := repo_model.GetIndexerBranches(db.DefaultContext, repo.ID)
	require.NoError(t, err)
	assert.Empty(t, rows)

	// AC3: found on idxdev and with all branches, not on the default branch.
	setIndexedBranches(t, repo, "idxdev")
	code_indexer.UpdateRepoIndexer(repo)
	assert.Equal(t, []string{"dev_only.go"}, codeSearchFiles(t, repo, "idxdev", false, code_indexer.SearchModeExact, "OnlyOnDevelop"))
	assert.Equal(t, []string{"dev_only.go"}, codeSearchFiles(t, repo, "", true, code_indexer.SearchModeExact, "OnlyOnDevelop"))
	assert.Empty(t, codeSearchFiles(t, repo, "", false, code_indexer.SearchModeExact, "OnlyOnDevelop"))
	assert.Contains(t, codeSearchFiles(t, repo, "", false, code_indexer.SearchModeUnion, "Description"), "README.md")

	// AC4: a push to the indexed branch is re-indexed.
	newBranchFile(t, user, repo, "idxdev", "idxdev", "more.go", "func PushedLater() {}")
	code_indexer.UpdateRepoIndexer(repo)
	assert.Equal(t, []string{"more.go"}, codeSearchFiles(t, repo, "idxdev", false, code_indexer.SearchModeExact, "PushedLater"))

	// AC4: deleting the branch removes its results and its status row.
	gitRepo, err := git.OpenRepository(t.Context(), repo.RepoPath())
	require.NoError(t, err)
	defer gitRepo.Close()
	require.NoError(t, repo_service.DeleteBranch(t.Context(), user, repo, gitRepo, "idxdev", ""))
	code_indexer.UpdateRepoIndexer(repo)
	assert.Empty(t, codeSearchFiles(t, repo, "", true, code_indexer.SearchModeExact, "OnlyOnDevelop"))
	rows, err = repo_model.GetIndexerBranches(db.DefaultContext, repo.ID)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// AC4: the limit is respected for release/* (default branch counts, so 3 total = 2 releases).
func TestCodeSearchBranchLimit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&setting.Indexer.MaxIndexedBranchesPerRepo, 3)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)

	for _, b := range []string{"release/1", "release/2", "release/3"} { // created oldest to newest
		newBranchFile(t, user, repo, repo.DefaultBranch, b, "rel.txt", "marker "+b[len("release/"):])
	}
	for i, b := range []string{"release/1", "release/2", "release/3"} { // commits in the same second
		_, err := db.GetEngine(t.Context()).Exec("UPDATE branch SET commit_time = ? WHERE repo_id = ? AND name = ?", 100*(i+1), repo.ID, b)
		require.NoError(t, err)
	}
	setIndexedBranches(t, repo, "release/*")
	code_indexer.UpdateRepoIndexer(repo)

	rows, err := repo_model.GetIndexerBranches(db.DefaultContext, repo.ID)
	require.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.Contains(t, rows, "release/3")
	assert.Contains(t, rows, "release/2")
	assert.NotContains(t, rows, "release/1")
}

// A default branch change drops IsDefault state: the whole repo is reindexed.
func TestCodeSearchDefaultBranchChange(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	oldDefault := repo.DefaultBranch

	newBranchFile(t, user, repo, oldDefault, "idxdev", "dev_only.go", "func OnlyOnDevelop() {}")
	code_indexer.UpdateRepoIndexer(repo)
	assert.Contains(t, codeSearchFiles(t, repo, "", false, code_indexer.SearchModeUnion, "Description"), "README.md")

	gitRepo, err := git.OpenRepository(t.Context(), repo.RepoPath())
	require.NoError(t, err)
	defer gitRepo.Close()
	// PrepareTestEnv restores the DB but not the on-disk index: switch back through the same path,
	// which resets the index and indexes the original default branch again.
	defer func() {
		require.NoError(t, repo_service.SetRepoDefaultBranch(t.Context(), repo, gitRepo, oldDefault))
	}()
	require.NoError(t, repo_service.SetRepoDefaultBranch(t.Context(), repo, gitRepo, "idxdev"))

	// idxdev is the default now: dev_only.go is found without a branch filter.
	assert.Equal(t, []string{"dev_only.go"}, codeSearchFiles(t, repo, "", false, code_indexer.SearchModeExact, "OnlyOnDevelop"))
}

// AC9: exact mode keeps punctuation; files with the same words in another
// order or without the punctuation don't match.
func TestCodeSearchPunctuation(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)

	cases := []struct{ query, hit, miss string }{
		{"foo.bar(", "x=foo.bar(y)", "bar.foo( foo bar"},
		{"a->b", "if(a->b)", "b->a a b"},
		{"std::map<", "std::map<int> m;", "map::std< std map"},
		{"#include <stdio.h>", "#include <stdio.h>", "include stdio.h <stdio.h> #"},
		{"user_id=", "user_id=5", "id=user_ user id"},
		{"@Override", "@Override void f()", "Override @"},
		{"i++", "for(i++)", "+ + i"},
	}
	for i, c := range cases {
		newBranchFile(t, user, repo, repo.DefaultBranch, repo.DefaultBranch, fmt.Sprintf("hit%d.txt", i), c.hit)
		newBranchFile(t, user, repo, repo.DefaultBranch, repo.DefaultBranch, fmt.Sprintf("miss%d.txt", i), c.miss)
	}
	code_indexer.UpdateRepoIndexer(repo)

	for i, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			assert.Equal(t, []string{fmt.Sprintf("hit%d.txt", i)}, codeSearchFiles(t, repo, "", false, code_indexer.SearchModeExact, c.query))
		})
	}
}

// AC1: only repo admins can save the patterns; other users get 403/404.
func TestCodeSearchSettingsPermission(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	values := map[string]string{"indexed_branches": "develop\nrelease/*"}
	post := func(user string, status int) {
		session := loginUser(t, user)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/code_search", values), status)
	}
	post("user4", http.StatusNotFound) // no access
	post("user2", http.StatusSeeOther) // owner

	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	cu, err := repo.GetUnit(t.Context(), unit.TypeCode)
	require.NoError(t, err)
	assert.Equal(t, []string{"develop", "release/*"}, cu.CodeConfig().IndexedBranches)

	// invalid patterns are refused and don't overwrite the saved list
	values["indexed_branches"] = "[unclosed"
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/code_search", values), http.StatusSeeOther)
	repo, err = repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	cu, err = repo.GetUnit(t.Context(), unit.TypeCode)
	require.NoError(t, err)
	assert.Equal(t, []string{"develop", "release/*"}, cu.CodeConfig().IndexedBranches)
}

// Saving the units form must not wipe the patterns.
func TestCodeSearchPatternsSurviveUnitsForm(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	setIndexedBranches(t, repo, "develop")

	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/units", map[string]string{
		"enable_code":   "on",
		"enable_issues": "on",
	}), http.StatusSeeOther)

	repo, err = repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	cu, err := repo.GetUnit(t.Context(), unit.TypeCode)
	require.NoError(t, err)
	assert.Equal(t, []string{"develop"}, cu.CodeConfig().IndexedBranches)
}
