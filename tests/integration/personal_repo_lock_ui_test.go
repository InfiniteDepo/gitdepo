// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refusedWrites are the web routes the size limit of personal repositories refuses (the EnforceQuotaWeb and
// personal-limit routes in routers/web/web.go, minus the deletes, which stay allowed). No page may link a viewer to
// one while the owner is locked.
var refusedWrites = map[string]*regexp.Regexp{
	"editor":         regexp.MustCompile(`/_(new|edit|upload|diffpatch|cherrypick)/`),
	"new release":    regexp.MustCompile(`/releases/new`),
	"new branch":     regexp.MustCompile(`/branches/_new/|/_new/branch/`),
	"restore branch": regexp.MustCompile(`/branches/restore`),
	"wiki edit":      regexp.MustCompile(`[?&]action=_(new|edit)`),
	"notes":          regexp.MustCompile(`/notes$`),
	"merge":          regexp.MustCompile(`/pulls/\d+/merge$`),
	"merge stack":    regexp.MustCompile(`/pulls/\d+/merge_stack$`),
	"revert":         regexp.MustCompile(`/pulls/\d+/revert$`),
	"update":         regexp.MustCompile(`/pulls/\d+/update`),
	"suggestion":     regexp.MustCompile(`/apply_suggestion`),
	"sync fork":      regexp.MustCompile(`/sync_fork`),
	"attachments":    regexp.MustCompile(`/(issues|releases)/attachments$`),
}

var linkAttr = regexp.MustCompile(`(?:href|action|data-[a-z.-]+)="([^"]*)"`)

// refusedLinks returns the refused-route kinds that pages link to, with an example each.
func refusedLinks(t *testing.T, session *TestSession, pages []string) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, page := range pages {
		body := session.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String()
		for _, m := range linkAttr.FindAllStringSubmatch(body, -1) {
			for kind, re := range refusedWrites {
				if re.MatchString(m[1]) {
					found[kind] = page + " → " + m[1]
				}
			}
		}
	}
	return found
}

// D: while the owner is locked, no page offers a write that would be refused, to the owner, a collaborator with
// write access or a site admin; deletes stay.
func TestPersonalRepoLockPageWalk(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		ctx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeAll)
		t.Run("AddCollaborator", doAPIAddCollaborator(ctx, "user4", perm.AccessModeWrite))
		// a mergeable pull request
		t.Run("CreateFile", doAPICreateFile(ctx, "lock-merge.txt", &api.CreateFileOptions{
			FileOptions:   api.FileOptions{BranchName: "master", NewBranchName: "lock-merge"},
			ContentBase64: "bG9jaw==",
		}))
		pr, err := doAPICreatePullRequest(ctx, "user2", "repo1", "master", "lock-merge")(t)
		require.NoError(t, err)
		prLink := "/user2/repo1/pulls/" + strconv.FormatInt(pr.Index, 10)
		pages := []string{
			"/user2/repo1",
			"/user2/repo1/src/branch/master/README.md",
			"/user2/repo1/branches",
			"/user2/repo1/tags",
			"/user2/repo1/releases",
			"/user2/repo1/wiki",
			"/user2/repo1/wiki/?action=_pages",
			"/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d",
			"/user2/repo1/pulls/2",
			"/user2/repo1/pulls/3",
			"/user2/repo1/pulls/3/files",
			"/user2/repo1/issues/1",
			"/user2/repo1/issues/new",
			"/user2/repo1/pulls/5", // behind its base: Update branch
			prLink,
		}
		owner := loginUser(t, "user2")
		// the patterns find the actions while unlocked, so an empty result below means hidden, not missed
		unlocked := refusedLinks(t, owner, pages)
		for _, kind := range []string{"editor", "new release", "new branch", "restore branch", "wiki edit", "notes", "update", "attachments"} {
			assert.Contains(t, unlocked, kind)
		}
		// the merge form is a Vue component: its mount point stands for the buttons
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", prLink), http.StatusOK).Body)
		assert.Equal(t, 1, doc.Find("#pull-request-merge-form").Length())

		lockPersonalRepos(t, 2, true)
		for _, name := range []string{"user2", "user4", "user1"} {
			t.Run(name, func(t *testing.T) {
				session := owner
				if name != "user2" {
					session = loginUser(t, name)
				}
				assert.Empty(t, refusedLinks(t, session, pages))

				// deletes stay, and writers see why they can't merge, without the owner's numbers
				doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/master/README.md"), http.StatusOK).Body)
				assert.Equal(t, 1, doc.Find(`a[href*="/_delete/"]`).Length())
				doc = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", prLink), http.StatusOK).Body)
				assert.Contains(t, doc.Find("#personal-repo-merge-locked").Text(), "The owner's personal repositories reached their size limit")
				assert.Equal(t, 1, doc.Find(`#personal-repo-merge-locked + div button[disabled]`).Length())
				assert.Zero(t, doc.Find("#pull-request-merge-form").Length())
				assert.NotContains(t, doc.Find("#personal-repo-merge-locked").Text(), "used")
			})
		}
	})
}

// C: the banner shows only to the owner (with the numbers) and site admins (without).
func TestPersonalRepoLockBannerVisibility(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		ctx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeAll)
		t.Run("AddCollaborator", doAPIAddCollaborator(ctx, "user4", perm.AccessModeWrite))
		lockPersonalRepos(t, 2, true)
		banner := func(session *TestSession, path string) string {
			req := NewRequest(t, "GET", path)
			var body *HTMLDoc
			if session == nil {
				body = NewHTMLParser(t, MakeRequest(t, req, http.StatusOK).Body)
			} else {
				body = NewHTMLParser(t, session.MakeRequest(t, req, http.StatusOK).Body)
			}
			return body.Find("#personal-repo-limit-banner").Text()
		}
		for _, path := range []string{"/user2/repo1", "/user2/repo1/src/branch/master/README.md"} {
			assert.Empty(t, banner(nil, path), "anonymous")
			assert.Empty(t, banner(loginUser(t, "user5"), path), "reader")
			assert.Empty(t, banner(loginUser(t, "user4"), path), "collaborator")
			assert.Contains(t, banner(loginUser(t, "user2"), path), "You can't push or add content")
			admin := banner(loginUser(t, "user1"), path)
			assert.Contains(t, admin, "The owner's personal repositories reached their size limit")
			assert.NotContains(t, admin, "You can't push")
		}
		// the 413 page of a collaborator's refused write has no numbers and no banner either
		doc := NewHTMLParser(t, loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/_new/master/").SetHeader("Accept", "text/html"), http.StatusRequestEntityTooLarge).Body)
		assert.Zero(t, doc.Find("#personal-repo-limit-banner").Length())
		assert.Contains(t, doc.Find(".page-content").Text(), "The owner's personal repositories reached their size limit")

		// I: an API transfer to the locked user2 doesn't tell user5 user2's numbers
		user5Token := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeAll)
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/repo4/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(user5Token), http.StatusRequestEntityTooLarge)
		assert.Contains(t, resp.Body.String(), "The owner's personal repositories reached their size limit")
		assert.NotContains(t, resp.Body.String(), "used")
	})
}

// A, B, F, the empty repository: the banner shows outside the forms, without a wrong message and without a link to
// the page it is on.
func TestPersonalRepoLockBannerPlacement(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-empty"}).AddTokenAuth(token), http.StatusCreated)
		lockPersonalRepos(t, 2, true)
		page := func(s *TestSession, path string) *HTMLDoc {
			return NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
		}

		for _, path := range []string{"/repo/create", "/repo/migrate?service_type=1", "/repo/migrate?service_type=2", "/user5/repo4/fork"} {
			doc := page(session, path)
			assert.Equal(t, 1, doc.Find("#personal-repo-limit-banner").Length(), path)
			assert.Zero(t, doc.Find("form.ui.form #personal-repo-limit-banner").Length(), "%s: Fomantic hides a warning inside a form", path)
		}

		// the empty repository: the banner, no New file/Upload
		doc := page(session, "/user2/lock-empty")
		assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content")
		assert.Zero(t, doc.Find(`a[href*="/_new/"], a[href*="/_upload/"]`).Length())

		// F: the settings page doesn't link to itself; other pages link to it
		doc = page(session, "/user/settings/repos")
		assert.Zero(t, doc.Find(`#personal-repo-limit-banner a[href$="/user/settings/repos"]`).Length())
		doc = page(session, "/user2/lock-empty")
		assert.Equal(t, 1, doc.Find(`#personal-repo-limit-banner a[href$="/user/settings/repos"]`).Length())

		// B: a locked user without organizations sees the size limit, not the repository count message
		adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user8/repos", &api.CreateRepoOption{Name: "user8-repo", AutoInit: true, Readme: "Default"}).AddTokenAuth(adminToken), http.StatusCreated)
		setPersonalRepoSizeLimit(t, 1<<40)
		setPersonalRepoOverride(t, 8, 1)
		defer setPersonalRepoOverride(t, 8, 0)
		doc = page(loginUser(t, "user8"), "/repo/create")
		assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content")
		assert.NotContains(t, doc.Find(".page-content").Text(), "All spaces in which you can create repositories")
	})
}

// G: the site page doesn't round a limit that isn't whole MiB away on an unchanged save; notes follow the limit.
func TestPersonalRepoLockSiteRoundingAndNotes(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		admin := loginUser(t, "user1")
		for _, tc := range []struct{ limit, shown int64 }{{512 << 10, 1}, {3 << 19, 2}} {
			setPersonalRepoSizeLimit(t, tc.limit)
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/personal-repos"), http.StatusOK).Body)
			assert.Equal(t, strconv.FormatInt(tc.shown, 10), doc.Find("#size_limit_mib").AttrOr("value", ""))
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": setting.PersonalReposAllowed, "size_limit_mib": strconv.FormatInt(tc.shown, 10)}), http.StatusSeeOther)
			bumpSettingsRevision(t)
			assert.Equal(t, tc.limit, setting.Config().PersonalRepos.Value(db.DefaultContext).EffectiveSizeLimit())
		}
		// a changed value is whole MiB, and 0 still turns the limit off
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": setting.PersonalReposAllowed, "size_limit_mib": "3"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.EqualValues(t, 3<<20, setting.Config().PersonalRepos.Value(db.DefaultContext).EffectiveSizeLimit())
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": setting.PersonalReposAllowed, "size_limit_mib": "0"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.Zero(t, setting.Config().PersonalRepos.Value(db.DefaultContext).EffectiveSizeLimit())

		// notes: set below the limit, refused at it, removal allowed
		owner := loginUser(t, "user2")
		prNotes := "/user2/repo1/pulls/3/commits/985f0301dba5e7b34be866819cd15ad3d8f508ee/notes"
		commitNotes := "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d/notes"
		lockPersonalRepos(t, 2, false)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", prNotes, map[string]string{"notes": "below the limit"}), http.StatusSeeOther)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", commitNotes, map[string]string{"notes": "below the limit"}), http.StatusSeeOther)
		lockPersonalRepos(t, 2, true)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", prNotes, map[string]string{"notes": "at the limit"}), http.StatusRequestEntityTooLarge)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", prNotes+"/remove", nil), http.StatusSeeOther)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", commitNotes+"/remove", nil), http.StatusSeeOther)
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d"), http.StatusOK).Body)
		require.Zero(t, doc.Find(".git-notes").Length(), "the note is gone")
	})
}

// E: the mode is a dropdown like the other fields, and the MiB field belongs to the custom mode.
func TestPersonalRepoLockAdminEditForm(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")
	field := func() *HTMLDoc {
		return NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/users/2/edit"), http.StatusOK).Body)
	}
	doc := field()
	assert.Equal(t, "site", doc.Find(".ui.selection.dropdown input#personal_repo_size_limit_mode").AttrOr("value", ""))
	assert.Zero(t, doc.Find("select#personal_repo_size_limit_mode").Length())
	assert.True(t, doc.Find("#personal_repo_size_limit_field").HasClass("tw-hidden"))
	_, disabled := doc.Find("#personal_repo_size_limit").Attr("disabled")
	assert.True(t, disabled)

	setPersonalRepoOverride(t, 2, 5<<20)
	defer setPersonalRepoOverride(t, 2, 0)
	doc = field()
	assert.Equal(t, "custom", doc.Find("input#personal_repo_size_limit_mode").AttrOr("value", ""))
	assert.False(t, doc.Find("#personal_repo_size_limit_field").HasClass("tw-hidden"))
	assert.Equal(t, "5", doc.Find("#personal_repo_size_limit").AttrOr("value", ""))
}

// While locked the edit forms have no dropzone and send no files; saving them must keep the attachments.
func TestPersonalRepoLockEditKeepsAttachments(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetPersonalRepoMode(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
	var comment api.Comment
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues/1/comments", &api.CreateIssueCommentOption{Body: "with a file"}).AddTokenAuth(token), http.StatusCreated), &comment)
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Attachment{UUID: uuid.NewString(), RepoID: 1, IssueID: 1, CommentID: comment.ID, Name: "c.txt"}))
	editIssue := func() {
		issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/issues/1/content", map[string]string{
			"content": "edited " + strconv.Itoa(issue.ContentVersion), "content_version": strconv.Itoa(issue.ContentVersion),
		}), http.StatusOK)
	}
	editComment := func() {
		c := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: comment.ID})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/comments/"+strconv.FormatInt(comment.ID, 10), map[string]string{
			"content": "edited " + strconv.Itoa(c.ContentVersion), "content_version": strconv.Itoa(c.ContentVersion),
		}), http.StatusOK)
	}

	lockPersonalRepos(t, 2, true)
	editIssue()
	editComment()
	unittest.AssertExistsAndLoadBean(t, &repo_model.Attachment{ID: 1, IssueID: 1})
	unittest.AssertExistsAndLoadBean(t, &repo_model.Attachment{CommentID: comment.ID})

	// below the limit the form's list decides again: a save without the file removes it
	lockPersonalRepos(t, 2, false)
	editComment()
	unittest.AssertNotExistsBean(t, &repo_model.Attachment{CommentID: comment.ID})
}

// A release is deleted from its edit page, which stays open while locked; saving it is refused.
func TestPersonalRepoLockReleaseEdit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetPersonalRepoMode(t)
	session := loginUser(t, "user2")
	lockPersonalRepos(t, 2, true)

	doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/releases/edit/v1.1"), http.StatusOK).Body)
	assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content")
	assert.Equal(t, 1, doc.Find(".delete-button[data-url$=\"/releases/delete\"]").Length())
	for _, label := range []string{"Update release", "Publish release", "Save draft"} {
		assert.Zero(t, doc.Find("button").FilterFunction(func(_ int, b *goquery.Selection) bool {
			return strings.TrimSpace(b.Text()) == label
		}).Length(), label)
	}
	assert.Zero(t, doc.Find(`.dropzone`).Length(), "no uploads")

	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/releases/edit/v1.1", map[string]string{
		"tag_name": "v1.1", "title": "edited", "content": "",
	}), http.StatusRequestEntityTooLarge)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/releases/delete", map[string]string{"id": "1"}), http.StatusOK)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Release{ID: 1}).IsTag, "the release is gone, its tag stays")
}

// #500: a locked user with no other owner to choose gets the banner and no form (no empty segment); with an
// organization to choose, the forms stay.
func TestPersonalRepoLockOnlyOwner(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetPersonalRepoMode(t)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user8/repos", &api.CreateRepoOption{Name: "user8-repo", AutoInit: true, Readme: "Default"}).AddTokenAuth(adminToken), http.StatusCreated)
	setPersonalRepoSizeLimit(t, 1<<40)
	setPersonalRepoOverride(t, 8, 1)
	defer setPersonalRepoOverride(t, 8, 0)
	setPersonalRepoOverride(t, 2, 1)
	defer setPersonalRepoOverride(t, 2, 0)

	pages := []string{"/repo/create", "/repo/migrate", "/repo/migrate?service_type=2", "/user5/repo4/fork"}
	user8 := loginUser(t, "user8")
	for _, path := range pages {
		doc := NewHTMLParser(t, user8.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
		assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content", path)
		assert.Zero(t, doc.Find("form.ui.form").Length(), "%s: no form", path)
		assert.Zero(t, doc.Find(".ui.attached.segment").Length(), "%s: no empty segment", path)
		assert.Zero(t, doc.Find(".migrate-entry").Length(), "%s: no service tiles", path)
		assert.Zero(t, doc.Find(".ui.negative.message").Length(), "%s: the banner explains it", path)
	}

	// user2 can choose an organization: the forms stay
	user2 := loginUser(t, "user2")
	for _, path := range pages {
		doc := NewHTMLParser(t, user2.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
		assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content", path)
		if path == "/repo/migrate" {
			assert.Positive(t, doc.Find(".migrate-entry").Length(), path)
		} else {
			assert.Equal(t, 1, doc.Find("form.ui.form").Length(), path)
		}
	}
}
