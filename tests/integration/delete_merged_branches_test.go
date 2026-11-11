// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dmRepo creates org3/<name> with a branch "merged-old" whose tip is behind master, and returns the repository.
func dmRepo(t *testing.T, s *TestSession, name string) *repo_model.Repository {
	t.Helper()
	bwRepo(t, name)
	testAPICreateBranch(t, s, "org3", name, "master", "merged-old", http.StatusCreated)
	testEditFile(t, s, "org3", name, "master", "README.md", "advanced\n")
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: name})
}

func dmBranches(t *testing.T, repo *repo_model.Repository) []string {
	t.Helper()
	gitRepo, err := git.OpenRepository(t.Context(), repo.RepoPath())
	require.NoError(t, err)
	defer gitRepo.Close()
	names, _, err := gitRepo.GetBranchNames(0, 0)
	require.NoError(t, err)
	return names
}

// dmPreview returns the ticked branches ("<repo id>:<name>") of the preview at link.
func dmPreview(t *testing.T, s *TestSession, link string) []string {
	t.Helper()
	resp := s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
	doc := NewHTMLParser(t, resp.Body).doc
	// Only the preview's own form posts to delete_merged; the page's other forms post to the settings page.
	assert.Equal(t, 1, doc.Find(`form[action*="delete_merged"]`).Length())
	return doc.Find(`#delete-merged + .segment input[name="branch"][checked]`).
		Map(func(_ int, i *goquery.Selection) string { return i.AttrOr("value", "") })
}

func dmPost(t *testing.T, s *TestSession, link, confirm string, branches ...string) {
	t.Helper()
	s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link, url.Values{"branch": branches, "confirm_name": {confirm}}), http.StatusSeeOther)
}

func TestDeleteMergedBranches(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"})

		// one repository: only the merged branches are offered, and only the ticked ones go
		repo := dmRepo(t, s, "dm-repo")
		for _, b := range []string{"prot-merged", "pr-base", "merged-keep"} {
			testAPICreateBranch(t, s, "org3", repo.Name, "merged-old", b, http.StatusCreated)
		}
		testAPICreateBranch(t, s, "org3", repo.Name, "master", "at-tip", http.StatusCreated)
		testNewFileToNewBranch(t, s, "org3", repo.Name, "merged-old", "unmerged", "unmerged.txt", "unmerged\n")
		testPullCreate(t, s, "org3", repo.Name, true, "pr-base", "unmerged", "PR into a merged branch")
		ctx := NewAPITestContext(t, "user2", repo.Name, auth_model.AccessTokenScopeWriteRepository)
		bwProtect(t, ctx, repo.Name, "prot-merged", parameterProtectBranch{"enable_push": "true"})

		// the Branches page has its own bulk delete; the settings page stays the place of this tool
		resp := s.MakeRequest(t, NewRequest(t, "GET", path.Join("/org3", repo.Name, "branches")), http.StatusOK)
		NewHTMLParser(t, resp.Body).AssertElement(t, `a[href$="/settings/branch_workflow/delete_merged#delete-merged"]`, false)

		link := path.Join("/org3", repo.Name, "settings/branch_workflow/delete_merged")
		id := strconv.FormatInt(repo.ID, 10)
		assert.ElementsMatch(t, []string{id + ":merged-old", id + ":merged-keep"}, dmPreview(t, s, link))

		other := loginUser(t, "user4")
		other.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
		other.MakeRequest(t, NewRequestWithURLValues(t, "POST", link, url.Values{"branch": {id + ":merged-old"}}), http.StatusNotFound)

		since := auditMaxID(t)
		// a branch that isn't merged is never deleted, even when posted
		dmPost(t, s, link, "", id+":merged-old", id+":unmerged", id+":prot-merged")
		assert.Contains(t, bwFlash(s), "Deleted 1 merged branch.")
		assert.ElementsMatch(t, []string{"master", "merged-keep", "prot-merged", "pr-base", "at-tip", "unmerged"}, dmBranches(t, repo))
		e := repoOne(t, since, "repo.merged_branches.deleted", repo)
		assert.Equal(t, map[string]any{"deleted": float64(1), "failed": float64(0), "repos": float64(1)}, auditData(t, e)["counts"])
		assert.Len(t, auditActions(t, since, "repo.branch.deleted"), 1)
		unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "merged-old", IsDeleted: true}) // restorable

		// a project: only its repositories, after typing its name
		inProject := dmRepo(t, s, "dm-project")
		outside := dmRepo(t, s, "dm-org")
		archived := dmRepo(t, s, "dm-archived")
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", true, archived.ID)
		require.NoError(t, err)
		group, err := repo_model.CreateRepoGroup(audit_model.WithCLI(t.Context()), org, "dm-group", "")
		require.NoError(t, err)
		require.NoError(t, repo_service.MoveRepository(audit_model.WithCLI(t.Context()), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), inProject, group.ID))
		inProject = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: inProject.ID})

		projectLink := group.Link("org3") + "/-/settings/delete_merged"
		ticked := dmPreview(t, s, projectLink)
		assert.Equal(t, []string{strconv.FormatInt(inProject.ID, 10) + ":merged-old"}, ticked)
		since = auditMaxID(t)
		// a repository outside the project can't be named, and a run that deletes nothing records nothing
		dmPost(t, s, projectLink, "org3/dm-group", strconv.FormatInt(outside.ID, 10)+":merged-old")
		assert.Contains(t, dmBranches(t, outside), "merged-old")
		dmPost(t, s, projectLink, "org3", ticked...) // wrong name
		assert.Contains(t, bwFlash(s), "doesn't match")
		assert.Empty(t, auditActions(t, since, "org.project.merged_branches_deleted"))
		dmPost(t, s, projectLink, "org3/dm-group", ticked...)
		assert.Equal(t, []string{"master"}, dmBranches(t, inProject))
		assert.Contains(t, dmBranches(t, outside), "merged-old")
		e = orgOne(t, since, "org.project.merged_branches_deleted")
		assert.Equal(t, group.ID, e.GroupID)

		// the organization: every other repository, archived ones skipped
		orgLink := "/org/org3/settings/branch_workflow/delete_merged"
		other.MakeRequest(t, NewRequest(t, "POST", orgLink), http.StatusNotFound)
		ticked = dmPreview(t, s, orgLink)
		assert.Contains(t, ticked, strconv.FormatInt(outside.ID, 10)+":merged-old")
		assert.Contains(t, ticked, id+":merged-keep")
		assert.NotContains(t, ticked, strconv.FormatInt(archived.ID, 10)+":merged-old")
		since = auditMaxID(t)
		dmPost(t, s, orgLink, "org3", slices.DeleteFunc(ticked, func(v string) bool { return v == id+":merged-keep" })...)
		assert.Equal(t, []string{"master"}, dmBranches(t, outside))
		assert.Contains(t, dmBranches(t, archived), "merged-old")
		assert.ElementsMatch(t, []string{"master", "merged-keep", "prot-merged", "pr-base", "at-tip", "unmerged"}, dmBranches(t, repo))
		orgOne(t, since, "org.merged_branches.deleted")
	})
}
