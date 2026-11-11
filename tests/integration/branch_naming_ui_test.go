// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bnBranchRows(doc *HTMLDoc) (groups []string, rows map[string][]string) {
	rows = map[string][]string{}
	doc.doc.Find("tr.branch-group-header").Each(func(_ int, s *goquery.Selection) {
		groups = append(groups, s.AttrOr("data-group", ""))
	})
	doc.doc.Find("tr[data-order]").Each(func(_ int, s *goquery.Selection) {
		g := s.AttrOr("data-group", "")
		rows[g] = append(rows[g], strings.TrimSpace(s.Find("a.gt-ellipsis, span.gt-ellipsis").First().Text()))
	})
	return groups, rows
}

// R5, R8: the create dialog offers the types of the model, with "Other" unless a type is required; the branch list
// is grouped by type and can be filtered by type on the server.
func TestBranchDialogAndList(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bn-ui")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		page := func(query string) *HTMLDoc {
			return NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo+"/branches"+query), http.StatusOK).Body)
		}

		t.Run("no types: a flat list and no filter", func(t *testing.T) {
			doc := page("")
			assert.Equal(t, 0, doc.doc.Find("tr.branch-group-header").Length())
			assert.Equal(t, 0, doc.doc.Find("#branch-type-filter").Length())
			assert.Equal(t, 0, doc.doc.Find("input.branch-type-choice").Length())
		})

		btModel(t, ctx, repo, bnOptions(api.BranchNaming{}), http.StatusOK)
		for _, b := range []string{"feature/a", "feature/b", "bugfix/c", "release/1.0", "misc", "chore/x", "feature-x"} {
			bnCreate(t, "user2", repo, b, http.StatusCreated)
		}

		t.Run("grouped by type", func(t *testing.T) {
			groups, rows := bnBranchRows(page(""))
			assert.Equal(t, []string{"Feature", "Bugfix", "Release", ""}, groups, "the model's order, then Release, then No type")
			assert.ElementsMatch(t, []string{"feature/a", "feature/b"}, rows["Feature"])
			assert.Equal(t, []string{"bugfix/c"}, rows["Bugfix"])
			assert.Equal(t, []string{"release/1.0"}, rows["Release"])
			assert.ElementsMatch(t, []string{"misc", "chore/x", "feature-x"}, rows[""], "names without a prefix and a name")
		})

		t.Run("filter by type on the server", func(t *testing.T) {
			_, rows := bnBranchRows(page("?type=Feature"))
			assert.ElementsMatch(t, []string{"feature/a", "feature/b"}, rows["Feature"])
			assert.Len(t, rows, 1)
			_, rows = bnBranchRows(page("?type=release"))
			assert.Equal(t, []string{"release/1.0"}, rows["Release"])
			assert.Len(t, rows, 1)
			_, rows = bnBranchRows(page("?untyped=1"))
			assert.ElementsMatch(t, []string{"misc", "chore/x", "feature-x"}, rows[""])
			assert.Len(t, rows, 1)
			_, rows = bnBranchRows(page("?type=Nope"))
			assert.Empty(t, rows)
			// the filter combines with the keyword search
			_, rows = bnBranchRows(page("?type=Feature&q=feature/b"))
			assert.Equal(t, []string{"feature/b"}, rows["Feature"])
			assert.Len(t, rows, 1)
			assert.Equal(t, "Feature", page("?type=Feature").doc.Find("#branch-type-filter .primary").Text())
		})

		t.Run("the dialog offers the types and Other", func(t *testing.T) {
			doc := page("")
			var choices []string
			doc.doc.Find("input.branch-type-choice").Each(func(_ int, s *goquery.Selection) {
				choices = append(choices, s.AttrOr("value", "")+"|"+s.AttrOr("data-prefix", "")+"|"+s.AttrOr("data-base", ""))
			})
			assert.Equal(t, []string{"Release|release/|master", "Feature|feature/|master", "Bugfix|bugfix/|master", "||master"}, choices)
			assert.Equal(t, "/org3/"+repo+"/branches/_new/branch/", doc.doc.Find("#create-branch-form").AttrOr("data-base-action", ""))
			assert.Equal(t, 1, doc.doc.Find("#create-branch-form fieldset legend").Length())
			assert.Equal(t, 1, doc.doc.Find("#branch-name-preview[aria-live]").Length())
		})

		t.Run("required: no Other, unless exempt", func(t *testing.T) {
			btModel(t, ctx, repo, bnOptions(api.BranchNaming{RequireBranchType: true, ExemptUsers: []string{"user4"}}), http.StatusOK)
			doc := page("")
			assert.Equal(t, 3, doc.doc.Find("input.branch-type-choice").Length())
			assert.Equal(t, 0, doc.doc.Find(`input.branch-type-choice[value=""]`).Length())
			assert.Equal(t, 1, doc.doc.Find("#create-branch-form .help").FilterFunction(func(_ int, s *goquery.Selection) bool { return strings.Contains(s.Text(), "type") }).Length())

			bnCollaborator(t, ctx, repo, "user4")
			exempt := NewHTMLParser(t, loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo+"/branches"), http.StatusOK).Body)
			assert.Equal(t, 1, exempt.doc.Find(`input.branch-type-choice[value=""]`).Length(), "an exempt user may use Other")
		})

		t.Run("the create form builds the name from the type", func(t *testing.T) {
			// the dialog posts the full name; the server applies the same rule as for any other creation
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/branches/_new/branch/master", map[string]string{"new_branch_name": "feature/from-dialog"}), http.StatusSeeOther)
			assert.True(t, bnExists(t, repoIDByName(t, "org3", repo), "feature/from-dialog"))
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/branches/_new/branch/master", map[string]string{"new_branch_name": "nope/from-dialog"}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "feature/")
			assert.False(t, bnExists(t, repoIDByName(t, "org3", repo), "nope/from-dialog"))
		})
	})
}

// R6: the Development section of an issue lists the branches that carry its number and suggests a new one; it is
// shown to viewers who can read the code, and the button only to those who can write it.
func TestIssueDevelopment(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bn-issue")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)
		btModel(t, ctx, repo, bnOptions(api.BranchNaming{}), http.StatusOK)

		var label api.Label
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/labels", &api.CreateLabelOption{Name: "bug", Color: "#ff0000"}).AddTokenAuth(ctx.Token), http.StatusCreated), &label)
		create := func(title string, labels ...int64) int64 {
			var issue api.Issue
			DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/issues", &api.CreateIssueOption{Title: title, Labels: labels}).AddTokenAuth(ctx.Token), http.StatusCreated), &issue)
			return issue.Index
		}
		bugIndex := create("Login fails: SSO ünïcode!", label.ID)
		plainIndex := create("日本語")
		view := func(s *TestSession, index int64) *HTMLDoc {
			return NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo+"/issues/"+strconv.FormatInt(index, 10)), http.StatusOK).Body)
		}
		button := func(doc *HTMLDoc) *goquery.Selection {
			return doc.doc.Find("#issue-development .show-create-branch-modal")
		}

		t.Run("suggestions", func(t *testing.T) {
			b := button(view(owner, bugIndex))
			assert.Equal(t, "Bugfix", b.AttrOr("data-suggest-type", ""))
			assert.Equal(t, strconv.FormatInt(bugIndex, 10)+"-login-fails-sso-n-code", b.AttrOr("data-suggest-name", ""))
			assert.Equal(t, "master", b.AttrOr("data-branch-from", ""))
			b = button(view(owner, plainIndex))
			assert.Equal(t, "Feature", b.AttrOr("data-suggest-type", ""), "the first enabled type")
			assert.Equal(t, "issue-"+strconv.FormatInt(plainIndex, 10), b.AttrOr("data-suggest-name", ""), "no ASCII letters: the fallback")
		})

		t.Run("linked branches by the naming convention", func(t *testing.T) {
			n := strconv.FormatInt(bugIndex, 10)
			for _, name := range []string{"bugfix/" + n + "-login", "feature/" + n, n + "-untyped", "feature/" + n + "0-other", "feature/x" + n} {
				bnCreate(t, "user2", repo, name, http.StatusCreated)
			}
			var linked []string
			view(owner, bugIndex).doc.Find("#issue-development a.gt-ellipsis").Each(func(_ int, s *goquery.Selection) { linked = append(linked, s.Text()) })
			assert.ElementsMatch(t, []string{"bugfix/" + n + "-login", "feature/" + n}, linked, "typed names only, and the number must match exactly")
		})

		t.Run("no create button without write access", func(t *testing.T) {
			reader := loginUser(t, "user8")
			doc := view(reader, bugIndex)
			assert.Equal(t, 1, doc.doc.Find("#issue-development").Length(), "a reader of the code sees the branches")
			assert.Equal(t, 0, button(doc).Length())
			anon := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo+"/issues/"+strconv.FormatInt(bugIndex, 10)), http.StatusOK).Body)
			assert.Equal(t, 1, anon.doc.Find("#issue-development").Length())
			assert.Equal(t, 0, button(anon).Length())
		})

		t.Run("hidden without code read", func(t *testing.T) {
			repoModel := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: repo})
			_, err := db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = ? AND type = 1", repoModel.ID)
			require.NoError(t, err)
			reader := loginUser(t, "user8")
			assert.Equal(t, 0, view(reader, bugIndex).doc.Find("#issue-development").Length())
		})
	})
}

// R7 in a project: the repository takes the organization's model, so the same refusals and allowances apply.
func TestBranchNamingProjectRepo(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		f, _ := prepareRepoGroupGit(t)
		ctx := NewAPITestContext(t, "user2", "pub", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btOrgModel(t, ctx, &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}, Types: bnTypes(), BranchNaming: api.BranchNaming{RequireBranchType: true}}, http.StatusOK)
		project := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: f.org.ID, Name: "pub"}, "group_id <> 0")
		master := branchCommit(t, project.ID)
		hook := func(name string) error {
			return private.HookPreReceive(t.Context(), project.ID, private.HookOptions{
				OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{master},
				RefFullNames: []git.RefName{git.RefNameFromBranch(name)}, UserID: 2, UserName: "user2",
			}).Error
		}
		require.ErrorContains(t, hook("spike/p"), "status=403")
		require.NoError(t, hook("feature/p"))
		// the API of a repository in a project
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		create := func(name string, status int) {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repositories/"+strconv.FormatInt(project.ID, 10)+"/branches", &api.CreateBranchRepoOption{BranchName: name, OldBranchName: project.DefaultBranch}).AddTokenAuth(token), status)
		}
		create("spike/api", http.StatusUnprocessableEntity)
		create("bugfix/api", http.StatusCreated)
	})
}
