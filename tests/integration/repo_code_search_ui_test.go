// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	code_indexer "forgejo.org/modules/indexer/code"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC6/AC7: the Branch selector, the branch of each result and its link (path-escaped).
func TestRepoCodeSearchBranchUI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Indexer.RepoIndexerEnabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "repo1")
	require.NoError(t, err)
	newBranchFile(t, user, repo, repo.DefaultBranch, "idxdev", "dev_only.go", "func OnlyOnDevelop() {}")
	newBranchFile(t, user, repo, repo.DefaultBranch, "feat/a#b", "odd.go", "func OddBranchName() {}")
	setIndexedBranches(t, repo, "idxdev", "feat/*")
	code_indexer.UpdateRepoIndexer(repo)

	get := func(path string) *HTMLDoc {
		return NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
	}

	// selector: default, every indexed branch, all
	doc := get("/user2/repo1/search?q=OnlyOnDevelop&branch=idxdev")
	options := map[string]bool{}
	doc.doc.Find(`select[name="branch"] option`).Each(func(_ int, s *goquery.Selection) {
		v, _ := s.Attr("value")
		_, selected := s.Attr("selected")
		options[v] = selected
	})
	assert.Equal(t, map[string]bool{"": false, "all": false, "idxdev": true, "feat/a#b": false}, options)

	// result: branch label and a link on that branch
	link := doc.doc.Find(".repo-search-result a.file-link")
	require.Equal(t, 1, link.Length())
	href, _ := link.Attr("href")
	assert.Equal(t, "/user2/repo1/src/branch/idxdev/dev_only.go", href)
	assert.Contains(t, doc.doc.Find(".repo-search-result").Text(), "idxdev")

	// a branch name is escaped in the link
	href, _ = get("/user2/repo1/search?q=OddBranchName&branch=all").doc.Find(".repo-search-result a.file-link").Attr("href")
	assert.Equal(t, "/user2/repo1/src/branch/feat/a%23b/odd.go", href)

	// default branch: as before, no branch in the way
	doc = get("/user2/repo1/search?q=Description")
	href, _ = doc.doc.Find(".repo-search-result a.file-link").Attr("href")
	assert.Contains(t, href, "/src/commit/")
	assert.Zero(t, doc.doc.Find(".repo-search-result .ui.basic.label").Length(), "no branch label on the default branch")
	viewFile, _ := doc.doc.Find(".repo-search-result a.button").Attr("href")
	assert.Contains(t, viewFile, "/src/commit/")
	_, hasDefault := doc.doc.Find(`select[name="branch"] option[value=""]`).Attr("selected")
	assert.True(t, hasDefault)

	// an unknown branch falls back to the default branch
	doc = get("/user2/repo1/search?q=OnlyOnDevelop&branch=nosuch")
	assert.Zero(t, doc.doc.Find(".repo-search-result").Length())

	// regex isn't offered by bleve, and asking for it doesn't break the page
	doc = get("/user2/repo1/search?q=Description&mode=regexp")
	assert.Zero(t, doc.doc.Find(`input[name="mode"][value="regexp"]`).Length())
}
