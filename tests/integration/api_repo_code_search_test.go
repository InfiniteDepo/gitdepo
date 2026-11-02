// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	code_indexer "forgejo.org/modules/indexer/code"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func indexedRepoWithDevBranch(t *testing.T) (*user_model.User, *repo_model.Repository) {
	t.Helper()
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	newBranchFile(t, user, repo, repo.DefaultBranch, "idxdev", "dev_only.go", "func OnlyOnDevelop() {}")
	setIndexedBranches(t, repo, "idxdev")
	code_indexer.UpdateRepoIndexer(repo)
	return user, repo
}

// AC8: branch=<name>|all and mode on the per-repo code search API.
func TestAPIRepoCodeSearch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()
	indexedRepoWithDevBranch(t)

	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
	search := func(params url.Values, status int) []api.CodeSearchResult {
		req := NewRequest(t, "GET", "/api/v1/repos/user2/repo1/search/code?"+params.Encode()).AddTokenAuth(token)
		resp := MakeRequest(t, req, status)
		if status != http.StatusOK {
			return nil
		}
		var results []api.CodeSearchResult
		DecodeJSON(t, resp, &results)
		return results
	}
	q := func(kv ...string) url.Values {
		v := url.Values{"q": {"OnlyOnDevelop"}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}

	got := search(q("branch", "idxdev"), http.StatusOK)
	require.Len(t, got, 1)
	assert.Equal(t, "dev_only.go", got[0].Filename)
	assert.Equal(t, "idxdev", got[0].Branch)
	assert.NotEmpty(t, got[0].CommitID)

	assert.Len(t, search(q("branch", "all"), http.StatusOK), 1)
	assert.Empty(t, search(q(), http.StatusOK), "the default branch doesn't have the symbol")
	assert.Equal(t, "master", search(url.Values{"q": {"Description"}, "branch": {"all"}}, http.StatusOK)[0].Branch)

	search(q("branch", "nosuchbranch"), http.StatusUnprocessableEntity)
	search(q("branch", "master"), http.StatusOK)               // the default branch is always accepted
	search(q("mode", "regex"), http.StatusUnprocessableEntity) // bleve has no regex
	search(q("mode", "fuzzy"), http.StatusUnprocessableEntity) // fuzzy is disabled
	search(q("mode", "bogus"), http.StatusUnprocessableEntity)
	search(url.Values{"q": {""}}, http.StatusUnprocessableEntity)
	search(url.Values{"q": {strings.Repeat("a", 257)}}, http.StatusUnprocessableEntity)
	search(q("mode", "exact"), http.StatusOK)
	search(q("mode", "union"), http.StatusOK)

	// the indexer is off
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, false)()
	search(q(), http.StatusServiceUnavailable)
}

func TestAPIRepoCodeSearchPermissions(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	// private repo, no token
	repo2, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo2")
	require.NoError(t, err)
	require.True(t, repo2.IsPrivate)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2/search/code?q=a"), http.StatusNotFound)

	// a token without the repository scope
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadUser)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/search/code?q=a").AddTokenAuth(token), http.StatusForbidden)
}
