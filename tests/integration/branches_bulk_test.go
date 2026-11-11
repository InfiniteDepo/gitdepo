// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	repo_module "forgejo.org/modules/repository"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bkBranchRows returns the names of the branches listed by the Branches page at query.
func bkBranchRows(t *testing.T, s *TestSession, repoLink, query string) []string {
	t.Helper()
	resp := s.MakeRequest(t, NewRequest(t, "GET", repoLink+"/branches?"+query), http.StatusOK)
	var names []string
	NewHTMLParser(t, resp.Body).doc.Find(`#branch-list-body tr[data-order]`).Each(func(_ int, tr *goquery.Selection) {
		names = append(names, strings.TrimSpace(tr.Find(".gt-ellipsis").First().Text()))
	})
	return names
}

// bkRepo creates org3/<name> with merged and unmerged branches, a protected one and one that is the base of an open
// pull request, and returns it.
func bkRepo(t *testing.T, s *TestSession, name string) *repo_model.Repository {
	t.Helper()
	repo := dmRepo(t, s, name) // master, merged-old (merged)
	for _, b := range []string{"m-a", "m-b", "m-keep", "prot-merged", "pr-base"} {
		testAPICreateBranch(t, s, "org3", name, "merged-old", b, http.StatusCreated)
	}
	testAPICreateBranch(t, s, "org3", name, "master", "at-tip", http.StatusCreated)
	testNewFileToNewBranch(t, s, "org3", name, "merged-old", "unmerged", "unmerged.txt", "unmerged\n")
	testNewFileToNewBranch(t, s, "org3", name, "merged-old", "unmerged2", "unmerged2.txt", "unmerged2\n")
	testPullCreate(t, s, "org3", name, true, "pr-base", "unmerged", "PR into a merged branch")
	ctx := NewAPITestContext(t, "user2", name, auth_model.AccessTokenScopeWriteRepository)
	bwProtect(t, ctx, name, "prot-merged", parameterProtectBranch{"enable_push": "true"})
	return repo
}

func bkPreview(t *testing.T, s *TestSession, link, query string) (names []string, total, kept int) {
	t.Helper()
	resp := s.MakeRequest(t, NewRequest(t, "GET", link+"/branches/delete_preview?"+query), http.StatusOK)
	var got struct {
		Branches []struct{ Name, Commit string }
		Total    int
		Kept     int
	}
	DecodeJSON(t, resp, &got)
	for _, b := range got.Branches {
		assert.NotEmpty(t, b.Commit)
		names = append(names, b.Name)
	}
	return names, got.Total, got.Kept
}

func bkPost(t *testing.T, s *TestSession, link, confirm string, branches ...string) {
	t.Helper()
	s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/delete_selected", url.Values{"branch": branches, "confirm_name": {confirm}}), http.StatusSeeOther)
}

func bkTip(t *testing.T, repo *repo_model.Repository, branch string) string {
	t.Helper()
	gitRepo, err := git.OpenRepository(t.Context(), repo.RepoPath())
	require.NoError(t, err)
	defer gitRepo.Close()
	id, err := gitRepo.GetBranchCommitID(branch)
	require.NoError(t, err)
	return id
}

func TestBranchesBulkDeleteWeb(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := bkRepo(t, s, "bk-web")
		link := path.Join("/org3", repo.Name)

		t.Run("filters", func(t *testing.T) {
			merged := bkBranchRows(t, s, link, "state=merged")
			assert.ElementsMatch(t, []string{"merged-old", "m-a", "m-b", "m-keep", "prot-merged", "pr-base", "at-tip"}, merged)
			assert.ElementsMatch(t, []string{"unmerged", "unmerged2"}, bkBranchRows(t, s, link, "state=not_merged"))
			assert.Equal(t, merged, bkBranchRows(t, s, link, "state=merged&into=default"))

			// the age is the server's update of the branch row, never a commit date
			assert.Empty(t, bkBranchRows(t, s, link, "stale=1"))
			_, err := db.GetEngine(t.Context()).Exec("UPDATE branch SET updated_unix = updated_unix - ? WHERE repo_id = ? AND name = ?", 40*86400, repo.ID, "m-a")
			require.NoError(t, err)
			assert.Equal(t, []string{"m-a"}, bkBranchRows(t, s, link, "stale=30"))
			assert.Equal(t, []string{"m-a"}, bkBranchRows(t, s, link, "stale=30&state=merged&q=m-"))

			// the pusher the server recorded, not the git author
			assert.ElementsMatch(t, append(merged, "unmerged", "unmerged2"), bkBranchRows(t, s, link, "pusher=user2"))
			assert.Empty(t, bkBranchRows(t, s, link, "pusher=user4"))
			assert.Empty(t, bkBranchRows(t, s, link, "pusher=nobody-here"))

			for _, bad := range []string{"state=x", "into=x", "stale=0", "stale=3651", "stale=abc"} {
				s.MakeRequest(t, NewRequest(t, "GET", link+"/branches?"+bad), http.StatusUnprocessableEntity)
			}
		})

		t.Run("controls and kept reasons", func(t *testing.T) {
			resp := s.MakeRequest(t, NewRequest(t, "GET", link+"/branches?state=merged"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			doc.AssertElement(t, "#branch-bulk-bar", true)
			assert.Equal(t, strconv.Itoa(5), doc.doc.Find("#branch-bulk-bar").AttrOr("data-total", ""))
			disabled := map[string]string{}
			doc.doc.Find("input.branch-select").Each(func(_ int, in *goquery.Selection) {
				if _, ok := in.Attr("disabled"); ok {
					id := in.AttrOr("aria-describedby", "")
					disabled[in.AttrOr("data-name", "")] = strings.TrimSpace(doc.doc.Find("#" + id).Text())
				} else {
					assert.NotEmpty(t, in.AttrOr("aria-label", ""))
				}
			})
			assert.Equal(t, map[string]string{
				"prot-merged": "Kept: protected by a branch rule",
				"pr-base":     "Kept: used by an open pull request",
			}, disabled) // no pull request number: it is shown only where the viewer can read pull requests

			// a reader sees the list and the filters, but no selection and no way to delete
			reader := loginUser(t, "user4")
			resp = reader.MakeRequest(t, NewRequest(t, "GET", link+"/branches?state=merged"), http.StatusOK)
			doc = NewHTMLParser(t, resp.Body)
			doc.AssertElement(t, "#branch-bulk-bar", false)
			doc.AssertElement(t, "input.branch-select", false)
			doc.AssertElement(t, "#delete-selected-modal", false)
			doc.AssertElement(t, "#branch-filters", true)
			assert.NotContains(t, resp.Body.String(), "Kept:")
			reader.MakeRequest(t, NewRequest(t, "GET", link+"/branches/delete_preview"), http.StatusNotFound)
			reader.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/delete_selected", url.Values{"branch": {":m-a"}}), http.StatusNotFound)
			assert.Contains(t, dmBranches(t, repo), "m-a")
		})

		t.Run("preview and a partial refusal", func(t *testing.T) {
			names, total, kept := bkPreview(t, s, link, "state=merged")
			assert.ElementsMatch(t, []string{"merged-old", "m-a", "m-b", "m-keep", "at-tip"}, names)
			assert.Equal(t, 5, total)
			assert.Equal(t, 2, kept)
			s.MakeRequest(t, NewRequest(t, "GET", link+"/branches/delete_preview?state=bogus"), http.StatusUnprocessableEntity)

			since := auditMaxID(t)
			// a protected branch, an open pull request's branch and a missing one are refused one by one; the rest goes
			bkPost(t, s, link, "", bkTip(t, repo, "m-a")+":m-a", bkTip(t, repo, "prot-merged")+":prot-merged", bkTip(t, repo, "pr-base")+":pr-base", ":ghost")
			flash := bwFlash(s)
			assert.Contains(t, flash, "1 branch deleted (")
			assert.Contains(t, flash, "Show deleted branches")
			assert.Contains(t, flash, "3 branches were kept")
			assert.Contains(t, flash, "prot-merged: protected by a branch rule")
			assert.Contains(t, flash, "pr-base: used by an open pull request")
			assert.Contains(t, flash, "ghost: no longer exists")
			assert.NotRegexp(t, `#\d`, flash)
			assert.NotContains(t, dmBranches(t, repo), "m-a")
			assert.Contains(t, dmBranches(t, repo), "prot-merged")
			unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "m-a", IsDeleted: true}) // restorable

			e := repoOne(t, since, "repo.branches.bulk_deleted", repo)
			assert.Equal(t, map[string]any{"deleted": float64(1), "kept": float64(3)}, auditData(t, e)["counts"])
			assert.Len(t, auditActions(t, since, "repo.branch.deleted"), 1)
		})

		t.Run("a push or a new rule after the preview keeps the branch", func(t *testing.T) {
			shown := bkTip(t, repo, "m-b")
			testEditFile(t, s, "org3", repo.Name, "m-b", "README.md", "later\n")
			ctx := NewAPITestContext(t, "user2", repo.Name, auth_model.AccessTokenScopeWriteRepository)
			bwProtect(t, ctx, repo.Name, "m-keep", parameterProtectBranch{"enable_push": "true"})
			bkPost(t, s, link, "", shown+":m-b", bkTip(t, repo, "m-keep")+":m-keep")
			flash := bwFlash(s)
			assert.Contains(t, flash, "Nothing was deleted.")
			assert.Contains(t, flash, "m-b: has new commits since the list was loaded")
			assert.Contains(t, flash, "m-keep: protected by a branch rule")
			assert.ElementsMatch(t, []string{"m-b", "m-keep"}, intersect(dmBranches(t, repo), "m-b", "m-keep"))
		})

		t.Run("restore selected", func(t *testing.T) {
			resp := s.MakeRequest(t, NewRequest(t, "GET", link+"/branches?deleted=1&selected=m-a"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			assert.Equal(t, []string{"m-a"}, bkBranchRows(t, s, link, "deleted=1"))
			assert.Equal(t, 1, doc.doc.Find(`input.branch-select[name="branch_id"][checked]`).Length())
			doc.AssertElement(t, "#delete-selected-modal", false)
			id := doc.doc.Find(`input.branch-select[name="branch_id"]`).AttrOr("value", "")
			s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/restore_selected", url.Values{"branch_id": {id}}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(s), "1 branch restored.")
			assert.Contains(t, dmBranches(t, repo), "m-a")
			s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/restore_selected", url.Values{}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(s), "select between 1 and 200 branches")
		})
	})
}

func intersect(have []string, want ...string) []string {
	var out []string
	for _, w := range want {
		if slices.Contains(have, w) {
			out = append(out, w)
		}
	}
	return out
}

// A request deletes at most 200 branches, and above ten it needs the full name of the repository.
func TestBranchesBulkDeleteCap(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := dmRepo(t, s, "bk-cap")
		link := path.Join("/org3", repo.Name)

		// 205 more branches at the tip of merged-old, written to git and synced like a push would
		tip := bkTip(t, repo, "merged-old")
		var refs strings.Builder
		for i := range 205 {
			fmt.Fprintf(&refs, "create refs/heads/bulk-%03d %s\n", i, tip)
		}
		_, _, runErr := git.NewCommand(t.Context(), "update-ref", "--stdin").RunStdString(&git.RunOpts{Dir: repo.RepoPath(), Stdin: strings.NewReader(refs.String())})
		require.NoError(t, runErr)
		_, err := repo_module.SyncRepoBranches(t.Context(), repo.ID, 0)
		require.NoError(t, err)

		names, total, kept := bkPreview(t, s, link, "state=merged&q=bulk-")
		assert.Len(t, names, 200)
		assert.Equal(t, 205, total)
		assert.Equal(t, 0, kept)
		resp := s.MakeRequest(t, NewRequest(t, "GET", link+"/branches?state=merged&q=bulk-"), http.StatusOK)
		assert.Equal(t, "205", NewHTMLParser(t, resp.Body).doc.Find("#branch-bulk-bar").AttrOr("data-total", ""))

		tipOf := func(n string) string { return tip + ":" + n }
		var posted []string
		for _, n := range names {
			posted = append(posted, tipOf(n))
		}
		// 201 are refused whole
		bkPost(t, s, link, repo.FullName(), append(slices.Clone(posted), tipOf("bulk-204"))...)
		assert.Contains(t, bwFlash(s), "select between 1 and 200 branches")
		assert.Len(t, dmBranches(t, repo), 207)
		// 200 need the name of the repository
		bkPost(t, s, link, "org3", posted...)
		assert.Contains(t, bwFlash(s), "the name you typed doesn't match")
		assert.Len(t, dmBranches(t, repo), 207)

		since := auditMaxID(t)
		bkPost(t, s, link, "ORG3/bk-cap", posted...)
		assert.Contains(t, bwFlash(s), "200 branches deleted (")
		assert.Len(t, dmBranches(t, repo), 7)
		e := repoOne(t, since, "repo.branches.bulk_deleted", repo)
		assert.Equal(t, map[string]any{"deleted": float64(200), "kept": float64(0)}, auditData(t, e)["counts"])
		assert.Len(t, auditActions(t, since, "repo.branch.deleted"), 200)
		// the rest is offered again
		_, total, _ = bkPreview(t, s, link, "state=merged&q=bulk-")
		assert.Equal(t, 5, total)
	})
}

func TestBranchesBulkDeleteAPI(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := bkRepo(t, s, "bk-api")
		endpoint := "/api/v1/repos/org3/" + repo.Name + "/branches/delete"
		write := getTokenForLoggedInUser(t, s, auth_model.AccessTokenScopeWriteRepository)
		post := func(token string, o *api.DeleteBranchesOption, status int) *api.DeleteBranchesResult {
			t.Helper()
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, o).AddTokenAuth(token), status)
			if status != http.StatusOK {
				return nil
			}
			var res api.DeleteBranchesResult
			DecodeJSON(t, resp, &res)
			return &res
		}

		t.Run("who may", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, &api.DeleteBranchesOption{Names: []string{"m-a"}}), http.StatusUnauthorized)
			read := getTokenForLoggedInUser(t, s, auth_model.AccessTokenScopeReadRepository)
			post(read, &api.DeleteBranchesOption{Names: []string{"m-a"}}, http.StatusForbidden)
			reader := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteRepository)
			post(reader, &api.DeleteBranchesOption{Names: []string{"m-a"}}, http.StatusForbidden)

			// a job token with read access only
			job := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
			original := *job
			t.Cleanup(func() {
				require.NoError(t, actions_model.UpdateTask(context.Background(), &original, "repo_id", "owner_id", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
			})
			readAll := actions_model.TokenPermissions{}
			for _, ut := range unit.AllRepoUnitTypes {
				readAll[ut] = perm.AccessModeRead
			}
			job.RepoID, job.OwnerID, job.TokenPermissions = repo.ID, repo.OwnerID, readAll.Encode()
			job.GenerateToken()
			require.NoError(t, actions_model.UpdateTask(t.Context(), job, "repo_id", "owner_id", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))
			post(job.Token, &api.DeleteBranchesOption{Names: []string{"m-a"}}, http.StatusNotFound) // a read-only job token is told the write target does not exist, as on every write route
			assert.Contains(t, dmBranches(t, repo), "m-a")
		})

		t.Run("input", func(t *testing.T) {
			many := make([]string, 101)
			for i := range many {
				many[i] = fmt.Sprintf("n-%d", i)
			}
			post(write, &api.DeleteBranchesOption{Names: many}, http.StatusUnprocessableEntity)
			post(write, &api.DeleteBranchesOption{}, http.StatusUnprocessableEntity)                                  // nothing named, no filter
			post(write, &api.DeleteBranchesOption{Keyword: "m-"}, http.StatusUnprocessableEntity)                     // the keyword alone is no filter
			post(write, &api.DeleteBranchesOption{Merged: "yes"}, http.StatusUnprocessableEntity)                     // outside the closed set
			post(write, &api.DeleteBranchesOption{Merged: "merged", StaleDays: 4000}, http.StatusUnprocessableEntity) // out of range
			post(write, &api.DeleteBranchesOption{Names: []string{"a..b"}}, http.StatusUnprocessableEntity)
			post(write, &api.DeleteBranchesOption{Names: []string{strings.Repeat("x", 256)}}, http.StatusUnprocessableEntity)
			// duplicates count once: 100 names and one more copy are fine
			many = many[:100]
			res := post(write, &api.DeleteBranchesOption{Names: append(slices.Clone(many), many[0])}, http.StatusOK)
			assert.Empty(t, res.Deleted)
			assert.Len(t, res.Kept, 100)
			assert.Equal(t, "not_found", res.Kept[0].Reason)
		})

		t.Run("names: each one decided, reasons are codes", func(t *testing.T) {
			res := post(write, &api.DeleteBranchesOption{Names: []string{"master", "prot-merged", "pr-base", "merged-old", "ghost"}}, http.StatusOK)
			assert.Equal(t, []string{"merged-old"}, res.Deleted)
			reasons := map[string]string{}
			for _, k := range res.Kept {
				reasons[k.Name] = k.Reason
			}
			assert.Equal(t, map[string]string{"master": "default", "prot-merged": "protected", "pr-base": "open_pr", "ghost": "not_found"}, reasons)
			assert.False(t, res.More)
			unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "merged-old", IsDeleted: true})
		})

		t.Run("filters", func(t *testing.T) {
			res := post(write, &api.DeleteBranchesOption{Merged: "merged", MergedInto: "default", PushedBy: "user2"}, http.StatusOK)
			assert.ElementsMatch(t, []string{"m-a", "m-b", "m-keep", "at-tip"}, res.Deleted)
			assert.Empty(t, res.Kept) // protected and used branches are never offered
			assert.ElementsMatch(t, []string{"master", "prot-merged", "pr-base", "unmerged", "unmerged2"}, dmBranches(t, repo))
			res = post(write, &api.DeleteBranchesOption{Merged: "not_merged", PushedBy: "user4"}, http.StatusOK)
			assert.Empty(t, res.Deleted)
		})

		t.Run("the branching model keeps its branches", func(t *testing.T) {
			tip := bkTip(t, repo, "master")
			var refs strings.Builder
			for _, b := range []string{"dev", "prod", "rel/1", "staging", "merge-queue/master/1"} {
				fmt.Fprintf(&refs, "create refs/heads/%s %s\n", b, tip)
			}
			_, _, runErr := git.NewCommand(t.Context(), "update-ref", "--stdin").RunStdString(&git.RunOpts{Dir: repo.RepoPath(), Stdin: strings.NewReader(refs.String())})
			require.NoError(t, runErr)
			_, err := repo_module.SyncRepoBranches(t.Context(), repo.ID, 0)
			require.NoError(t, err)
			ctx := NewAPITestContext(t, "user2", repo.Name, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
			btModel(t, ctx, repo.Name, &api.EditRepoBranchingModelOption{DevelopmentBranch: "dev", ProductionBranch: "prod", ReleasePrefixes: []string{"rel/"}, DefaultPRTarget: "staging"}, http.StatusOK)
			defer btModel(t, ctx, repo.Name, &api.EditRepoBranchingModelOption{Inherit: true}, http.StatusOK)
			res := post(write, &api.DeleteBranchesOption{Names: []string{"dev", "prod", "rel/1", "staging", "merge-queue/master/1"}}, http.StatusOK)
			assert.Empty(t, res.Deleted)
			reasons := map[string]string{}
			for _, k := range res.Kept {
				reasons[k.Name] = k.Reason
			}
			assert.Equal(t, map[string]string{"dev": "development", "prod": "production", "rel/1": "release", "staging": "base", "merge-queue/master/1": "merge_queue"}, reasons)
		})

		t.Run("archived and maintenance", func(t *testing.T) {
			defer test.MockVariableValue(&repo.IsArchived, repo.IsArchived)()
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", true, repo.ID)
			require.NoError(t, err)
			post(write, &api.DeleteBranchesOption{Names: []string{"unmerged2"}}, http.StatusLocked)
			_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", false, repo.ID)
			require.NoError(t, err)
			assert.Contains(t, dmBranches(t, repo), "unmerged2")
		})
	})
}

// The project and ID forms of the repository routes carry the endpoint too.
func TestBranchesBulkDeleteAPIRepoForms(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := dmRepo(t, s, "bk-forms")
		token := getTokenForLoggedInUser(t, s, auth_model.AccessTokenScopeWriteRepository)
		res := func(endpoint string) *api.DeleteBranchesResult {
			var r api.DeleteBranchesResult
			DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, &api.DeleteBranchesOption{Names: []string{"merged-old"}}).AddTokenAuth(token), http.StatusOK), &r)
			return &r
		}
		assert.Equal(t, []string{"merged-old"}, res("/api/v1/repositories/"+strconv.FormatInt(repo.ID, 10)+"/branches/delete").Deleted)
		assert.Equal(t, "not_found", res("/api/v1/repos/org3/" + repo.Name + "/branches/delete").Kept[0].Reason)
	})
}
