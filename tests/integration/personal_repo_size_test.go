// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	pull_model "forgejo.org/models/pull"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/forms"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const personalLimitMessage = "Personal repository size limit reached ("

// setPersonalRepoSizeLimit stores a site size limit in bytes (policy allowed); the returned function removes it.
func setPersonalRepoSizeLimit(t *testing.T, limit int64) func() {
	t.Helper()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.NoError(t, repo_service.SetPersonalRepoPolicy(db.DefaultContext, admin, setting.PersonalReposAllowed, limit))
	bumpSettingsRevision(t)
	return func() { resetPersonalRepoMode(t) }
}

func personalRepoUsage(t *testing.T, uid int64) int64 {
	t.Helper()
	used, err := quota_model.GetPersonalRepoUsage(db.DefaultContext, uid)
	require.NoError(t, err)
	return used
}

// lockPersonalRepos sets the site limit to the user's current usage (at the limit: locked) or one byte above it.
func lockPersonalRepos(t *testing.T, uid int64, locked bool) {
	t.Helper()
	limit := personalRepoUsage(t, uid)
	if !locked {
		limit++
	}
	require.Positive(t, limit)
	setPersonalRepoSizeLimit(t, limit)
}

func setPersonalRepoOverride(t *testing.T, uid, limit int64) {
	t.Helper()
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, &user_model.User{ID: uid, PersonalRepoSizeLimit: limit}, "personal_repo_size_limit"))
}

func gitPushResult(dir string, args ...string) (string, error) {
	_, stderr, err := git.NewCommand(git.DefaultContext, "push").AddArguments(git.ToTrustedCmdArgs(args)...).RunStdString(&git.RunOpts{Dir: dir})
	return stderr, err
}

func commitFile(t *testing.T, dir, name string, size int) {
	t.Helper()
	data := make([]byte, size)
	_, err := rand.Read(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	require.NoError(t, git.AddChanges(dir, true))
	require.NoError(t, git.CommitChanges(dir, git.CommitChangesOptions{
		Committer: &git.Signature{Email: "user2@example.com", Name: "User Two", When: time.Now()},
		Author:    &git.Signature{Email: "user2@example.com", Name: "User Two", When: time.Now()},
		Message:   "add " + name,
	}))
}

// cloneWiki is doGitClone for a wiki, which has no README.md.
func cloneWiki(t *testing.T, dir string, u *url.URL) {
	t.Helper()
	require.NoError(t, git.CloneWithArgs(t.Context(), git.AllowLFSFiltersArgs(), u.String(), dir, git.CloneRepoOptions{}))
	doGitSetRemoteURL(dir, "origin", u)(t)
}

// AC8, AC10, AC11, M2: every git push at the limit is refused before it starts, a ref delete and a wiki push too;
// one byte under is allowed; orgs, admins and overrides.
func TestPersonalRepoSizeLockGit(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		defer setPersonalRepoOverride(t, 2, 0)
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-git", AutoInit: true, DefaultBranch: "main", Readme: "Default"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-git/wiki/new", &api.CreateWikiPageOptions{Title: "Home", ContentBase64: "aG9tZQ=="}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/lock-git/collaborators/user4", &api.AddCollaboratorOption{}).AddTokenAuth(token), http.StatusNoContent)

		cloneURL := func(user, path string) *url.URL {
			c := *u
			c.Path = path
			c.User = url.UserPassword(user, userPassword)
			return &c
		}
		dir, wikiDir := t.TempDir(), t.TempDir()
		doGitClone(dir, cloneURL("user2", "/user2/lock-git.git"))(t)
		cloneWiki(t, wikiDir, cloneURL("user2", "/user2/lock-git.wiki.git"))
		doGitCreateBranch(dir, "to-delete")(t)
		doGitPushTestRepository(dir, "origin", "to-delete")(t)
		doGitCheckoutBranch(dir, "-b", "work")(t)
		commitFile(t, dir, "a.bin", 1000)
		commitFile(t, wikiDir, "Page.md", 100)

		lockPersonalRepos(t, 2, true)
		for name, args := range map[string][]string{"push at the limit": {"origin", "work"}, "ref delete": {"origin", ":to-delete"}} {
			stderr, err := gitPushResult(dir, args...)
			require.Error(t, err, name)
			assert.Contains(t, stderr, personalLimitMessage, name)
		}
		stderr, err := gitPushResult(wikiDir, "origin", "HEAD")
		require.Error(t, err)
		assert.Contains(t, stderr, personalLimitMessage, "wiki push")

		// a collaborator is refused without the owner's numbers
		collabDir := t.TempDir()
		doGitClone(collabDir, cloneURL("user4", "/user2/lock-git.git"))(t)
		stderr, err = gitPushResult(collabDir, "origin", ":to-delete")
		require.Error(t, err)
		assert.Contains(t, stderr, "The owner's personal repositories reached their size limit")
		assert.NotContains(t, stderr, "KiB")

		// LFS uploads
		req := NewRequestWithJSON(t, "POST", "/user2/lock-git.git/info/lfs/objects/batch", &lfs.BatchRequest{
			Operation: "upload",
			Objects:   []lfs.Pointer{{Oid: "83de2e488b89a0aa1c97496b888120a28b0c1e15463a4adb8405578c540f36d4", Size: 6}},
		}).SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType).AddBasicAuth("user2")
		resp := MakeRequest(t, req, http.StatusRequestEntityTooLarge)
		assert.Contains(t, resp.Body.String(), personalLimitMessage)

		// push-to-create
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateUser, true)()
		newDir := t.TempDir()
		doGitInitTestRepository(newDir, git.Sha1ObjectFormat)(t)
		doGitAddRemote(newDir, "origin", cloneURL("user2", "/user2/lock-new.git"))(t)
		stderr, err = gitPushResult(newDir, "origin", "master")
		require.Error(t, err)
		assert.Contains(t, stderr, personalLimitMessage)
		assert.False(t, repoExists(t, "user2", "lock-new"))

		// organizations and admins are never locked, even with a site limit of one byte
		setPersonalRepoSizeLimit(t, 1)
		orgToken := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "lock-org", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(orgToken), http.StatusCreated)
		orgDir := t.TempDir()
		doGitClone(orgDir, cloneURL("user2", "/org3/lock-org.git"))(t)
		commitFile(t, orgDir, "org.bin", 100)
		doGitPushTestRepository(orgDir, "origin", "HEAD")(t)
		adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-admin", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(adminToken), http.StatusCreated)

		// a per-user override: unlimited, then higher
		setPersonalRepoOverride(t, 2, -1)
		doGitPushTestRepository(dir, "origin", "work")(t)
		setPersonalRepoOverride(t, 2, personalRepoUsage(t, 2)+1)
		doGitPushTestRepository(wikiDir, "origin", "HEAD")(t)
		setPersonalRepoOverride(t, 2, 0)

		// one byte under the limit: allowed; the push that crosses it is accepted, the next is refused
		lockPersonalRepos(t, 2, false)
		before := personalRepoUsage(t, 2)
		commitFile(t, dir, "b.bin", 2000)
		doGitPushTestRepository(dir, "origin", "work")(t)
		assert.Greater(t, personalRepoUsage(t, 2), before, "the push refreshed the size")
		commitFile(t, dir, "c.bin", 10)
		stderr, err = gitPushResult(dir, "origin", "work")
		require.Error(t, err)
		assert.Contains(t, stderr, personalLimitMessage)
		// and the wiki push refreshed the wiki size
		assert.Positive(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", LowerName: "lock-git"}).WikiSize)

		// writes reopen once the usage is below the limit (here by raising it)
		lockPersonalRepos(t, 2, false)
		doGitPushTestRepository(dir, "origin", ":to-delete")(t)
	})
}

// S1: a push to the wiki is measured again.
func TestPersonalRepoSizeWikiPushMeasured(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "wiki-size"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/wiki-size/wiki/new", &api.CreateWikiPageOptions{Title: "Home", ContentBase64: "aG9tZQ=="}).AddTokenAuth(token), http.StatusCreated)
		before := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", LowerName: "wiki-size"}).WikiSize
		dir := t.TempDir()
		c := *u
		c.Path = "/user2/wiki-size.wiki.git"
		c.User = url.UserPassword("user2", userPassword)
		cloneWiki(t, dir, &c)
		commitFile(t, dir, "Big.md", 200000)
		doGitPushTestRepository(dir, "origin", "HEAD")(t)
		assert.Greater(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", LowerName: "wiki-size"}).WikiSize, before+100000)
	})
}

// AC8: the other writes that add content are refused at the limit, with the message; they work again below it.
func TestPersonalRepoSizeLockWrites(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
		defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
		require.NoError(t, migrations_allowlist.Init())
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
		other := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-writes", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(token), http.StatusCreated)
		var release api.Release
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-writes/releases", &api.CreateReleaseOption{TagName: "v1", Title: "v1"}).AddTokenAuth(token), http.StatusCreated), &release)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "transfer-me", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(other), http.StatusCreated)
		var readme api.ContentsResponse
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/lock-writes/contents/README.md").AddTokenAuth(token), http.StatusOK), &readme)
		var branch api.Branch
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/lock-writes/branches/main").AddTokenAuth(token), http.StatusOK), &branch)
		sha := branch.Commit.ID
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/lock-writes/collaborators/user4", &api.AddCollaboratorOption{}).AddTokenAuth(token), http.StatusNoContent)
		collaborator := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeAll)

		lockPersonalRepos(t, 2, true)
		refusedAPI := func(t *testing.T, req *RequestWrapper) {
			t.Helper()
			var apiErr api.APIError
			DecodeJSON(t, MakeRequest(t, req, http.StatusRequestEntityTooLarge), &apiErr)
			assert.Contains(t, apiErr.Message, personalLimitMessage)
		}
		content := "aGVsbG8="
		refusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-new"}).AddTokenAuth(token))
		refusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user27/template1/generate", &api.GenerateRepoOption{Owner: "user2", Name: "lock-tpl", GitContent: true}).AddTokenAuth(token))
		refusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/transfer-me/forks", &api.CreateForkOption{}).AddTokenAuth(token))
		cloneURL := *u
		cloneURL.Path = "/user2/repo1.git"
		refusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: cloneURL.String(), RepoOwner: "user2", RepoName: "lock-mig"}).AddTokenAuth(token))
		refusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-writes/contents/new.txt", &api.CreateFileOptions{ContentBase64: content}).AddTokenAuth(token))
		refusedAPI(t, NewRequestWithJSON(t, "DELETE", "/api/v1/repos/user2/lock-writes/contents/README.md", &api.DeleteFileOptions{SHA: readme.SHA}).AddTokenAuth(token)) // only the web UI deletes
		// a transfer by someone else: refused without user2's numbers
		var transferErr api.APIError
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/transfer-me/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(other), http.StatusRequestEntityTooLarge), &transferErr)
		assert.Contains(t, transferErr.Message, "The owner's personal repositories reached their size limit")
		// git notes add objects too
		refusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-writes/git/notes/"+sha, &api.NoteOptions{Message: "note"}).AddTokenAuth(token))
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-writes/commit/"+sha+"/notes", map[string]string{"notes": "note"}), http.StatusRequestEntityTooLarge)
		// a collaborator is refused without the owner's numbers
		var apiErr api.APIError
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-writes/contents/collab.txt", &api.CreateFileOptions{ContentBase64: content}).AddTokenAuth(collaborator), http.StatusRequestEntityTooLarge), &apiErr)
		assert.Contains(t, apiErr.Message, "The owner's personal repositories reached their size limit")
		assert.NotContains(t, apiErr.Message, "KiB")

		body := &bytes.Buffer{}
		form := multipart.NewWriter(body)
		file, err := form.CreateFormFile("attachment", "a.txt")
		require.NoError(t, err)
		_, _ = file.Write([]byte("attachment"))
		require.NoError(t, form.Close())
		req := NewRequestWithBody(t, "POST", fmt.Sprintf("/api/v1/repos/user2/lock-writes/releases/%d/assets?name=a.txt", release.ID), body).AddTokenAuth(token)
		req.Header.Add("Content-Type", form.FormDataContentType())
		refusedAPI(t, req)

		resp := MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/generic/lock/1.0/f.txt", strings.NewReader("package")).AddBasicAuth("user2"), http.StatusRequestEntityTooLarge)
		assert.Contains(t, resp.Body.String(), personalLimitMessage)

		// the web editor refuses with the 413 page and the message
		// U2: not a dead end: the banner with the link to the repositories list, a way back and the repository header
		doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/lock-writes/_new/main/").SetHeader("Accept", "text/html"), http.StatusRequestEntityTooLarge).Body)
		assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content")
		assert.Equal(t, 1, doc.Find(`#personal-repo-limit-banner a[href$="/user/settings/repos"]`).Length())
		assert.Equal(t, "/user2/lock-writes", doc.Find("#quota-back").AttrOr("href", ""))
		assert.Equal(t, 1, doc.Find(".repo-header").Length())

		// below the limit again: allowed
		lockPersonalRepos(t, 2, false)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-writes/git/notes/"+sha, &api.NoteOptions{Message: "note"}).AddTokenAuth(token), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-writes/contents/new.txt", &api.CreateFileOptions{ContentBase64: content}).AddTokenAuth(token), http.StatusCreated)
	})
}

// S3: writes that copy objects into another user's repositories are checked against that user's limit.
func TestPersonalRepoSizeLockCrossRepo(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		forker := loginUser(t, "user5")
		forkerToken := getTokenForLoggedInUser(t, forker, auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "cross-base", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(owner), http.StatusCreated)
		forkName := "cross-fork"
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/cross-base/forks", &api.CreateForkOption{Name: &forkName}).AddTokenAuth(forkerToken), http.StatusAccepted)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/cross-fork/contents/fork.txt", &api.CreateFileOptions{ContentBase64: "Zm9yaw==", FileOptions: api.FileOptions{NewBranchName: "feature"}}).AddTokenAuth(forkerToken), http.StatusCreated)
		var pr api.PullRequest
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/cross-base/pulls", &api.CreatePullRequestOption{Head: "user5:feature", Base: "main", Title: "first"}).AddTokenAuth(forkerToken), http.StatusCreated), &pr)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/cross-base/contents/base.txt", &api.CreateFileOptions{ContentBase64: "YmFzZQ=="}).AddTokenAuth(owner), http.StatusCreated)

		// the base owner is locked: a PR from the fork copies the head into the base repository
		lockPersonalRepos(t, 2, true)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/cross-fork/contents/two.txt", &api.CreateFileOptions{ContentBase64: "dHdv", FileOptions: api.FileOptions{NewBranchName: "feature2"}}).AddTokenAuth(forkerToken), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/cross-base/pulls", &api.CreatePullRequestOption{Head: "user5:feature2", Base: "main", Title: "second"}).AddTokenAuth(forkerToken), http.StatusRequestEntityTooLarge)
		forker.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/cross-base/compare/main...user5:feature2", map[string]string{"title": "second web"}), http.StatusRequestEntityTooLarge)
		prModel, err := issues_model.GetPullRequestByID(db.DefaultContext, pr.ID)
		require.NoError(t, err)
		require.ErrorAs(t, pull_service.PushToBaseRepo(db.DefaultContext, prModel), &quota_model.ErrPersonalRepoLimit{})
		resetPersonalRepoMode(t)

		// the fork owner is locked: syncing the fork and updating the PR write to the fork
		lockPersonalRepos(t, 5, true)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user5/cross-fork/sync_fork").AddTokenAuth(forkerToken), http.StatusRequestEntityTooLarge)
		forker.MakeRequest(t, NewRequestWithValues(t, "POST", "/user5/cross-fork/sync_fork", map[string]string{"branch": "main"}), http.StatusRequestEntityTooLarge)
		MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/api/v1/repos/user2/cross-base/pulls/%d/update", pr.Index)).AddTokenAuth(forkerToken), http.StatusRequestEntityTooLarge)
		forker.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/user2/cross-base/pulls/%d/update", pr.Index)), http.StatusRequestEntityTooLarge)
		resetPersonalRepoMode(t)
		MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/api/v1/repos/user2/cross-base/pulls/%d/update", pr.Index)).AddTokenAuth(forkerToken), http.StatusOK)
	})
}

// AC9, S2, Q4/Q7: every web delete works at the limit; the gc after it frees the space and writes reopen.
func TestPersonalRepoSizeLockDeletes(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		defer test.MockVariableValue(&repo_service.ShrinkPruneExpire, "now")()
		defer test.MockVariableValue(&setting.LFS.StartServer, true)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-del", AutoInit: true, DefaultBranch: "main", Readme: "Default"}).AddTokenAuth(token), http.StatusCreated)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", LowerName: "lock-del"})
		for _, f := range []string{"a.txt", "b.txt"} {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-del/contents/"+f, &api.CreateFileOptions{ContentBase64: "ZmlsZQ=="}).AddTokenAuth(token), http.StatusCreated)
		}
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-del/tags", &api.CreateTagOption{TagName: "t1"}).AddTokenAuth(token), http.StatusCreated)
		var release api.Release
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-del/releases", &api.CreateReleaseOption{TagName: "v1", Title: "v1"}).AddTokenAuth(token), http.StatusCreated), &release)
		body := &bytes.Buffer{}
		form := multipart.NewWriter(body)
		file, err := form.CreateFormFile("attachment", "a.txt")
		require.NoError(t, err)
		_, _ = file.Write([]byte("attachment"))
		require.NoError(t, form.Close())
		req := NewRequestWithBody(t, "POST", fmt.Sprintf("/api/v1/repos/user2/lock-del/releases/%d/assets?name=a.txt", release.ID), body).AddTokenAuth(token)
		req.Header.Add("Content-Type", form.FormDataContentType())
		var attachment api.Attachment
		DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &attachment)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-del/wiki/new", &api.CreateWikiPageOptions{Title: "Gone", ContentBase64: "Z29uZQ=="}).AddTokenAuth(token), http.StatusCreated)
		lfsData := []byte("lfs object of lock-del")
		oid := storeObjectInRepo(t, repo.ID, &lfsData)
		trash := "lock-trash"
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: trash}).AddTokenAuth(token), http.StatusCreated)

		// a branch with a large file: deleting it frees the space once the gc prunes it
		dir := t.TempDir()
		c := *u
		c.Path = "/user2/lock-del.git"
		c.User = url.UserPassword("user2", userPassword)
		doGitClone(dir, &c)(t)
		doGitCheckoutBranch(dir, "-b", "big")(t)
		commitFile(t, dir, "big.bin", 600000)
		doGitPushTestRepository(dir, "origin", "big")(t)

		lockPersonalRepos(t, 2, true)
		locked := personalRepoUsage(t, 2)

		// the delete page: no new branch, and the default message instead of the user's
		lastCommit := func() string {
			doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/lock-del/_delete/main/a.txt"), http.StatusOK).Body)
			return doc.GetInputValueByName("last_commit")
		}
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-del/_delete/main/a.txt", map[string]string{
			"last_commit": lastCommit(), "commit_choice": "commit-to-new-branch", "new_branch_name": "sneaky", "commit_mail_id": "-1",
		}), http.StatusOK)
		assert.Contains(t, NewHTMLParser(t, resp.Body).Find(".flash-error").Text(), "only deletions are possible")
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-del/_delete/main/a.txt", map[string]string{
			"last_commit": lastCommit(), "commit_choice": "direct", "commit_summary": "big summary", "commit_message": strings.Repeat("x", 100000), "commit_mail_id": "-1",
		}), http.StatusSeeOther)
		gitRepo, err := git.OpenRepository(git.DefaultContext, repo.RepoPath())
		require.NoError(t, err)
		commit, err := gitRepo.GetBranchCommit("main")
		require.NoError(t, err)
		assert.Equal(t, "Delete a.txt\n", commit.CommitMessage)
		assert.False(t, git.IsBranchExist(git.DefaultContext, repo.RepoPath(), "sneaky"))
		gitRepo.Close()

		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-del/tags/delete", map[string]string{"id": strconv.FormatInt(unittest.AssertExistsAndLoadBean(t, &repo_model.Release{RepoID: repo.ID, TagName: "t1"}).ID, 10)}), http.StatusOK)
		unittest.AssertNotExistsBean(t, &repo_model.Release{RepoID: repo.ID, TagName: "t1"})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-del/releases/attachments/remove", map[string]string{"file": attachment.UUID}), http.StatusOK)
		unittest.AssertNotExistsBean(t, &repo_model.Attachment{UUID: attachment.UUID})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-del/releases/delete", map[string]string{"id": strconv.FormatInt(release.ID, 10)}), http.StatusOK)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Release{ID: release.ID}).IsTag, "the release is gone, its tag stays")
		session.MakeRequest(t, NewRequest(t, "POST", "/user2/lock-del/wiki/Gone?action=_delete"), http.StatusOK)
		session.MakeRequest(t, NewRequest(t, "POST", "/user2/lock-del/settings/lfs/delete/"+oid), http.StatusSeeOther)
		unittest.AssertNotExistsBean(t, &git_model.LFSMetaObject{RepositoryID: repo.ID, Pointer: lfs.Pointer{Oid: oid}})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/"+trash+"/settings", map[string]string{"action": "delete", "repo_name": "user2/" + trash}), http.StatusSeeOther)
		assert.False(t, repoExists(t, "user2", trash))

		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/lock-del/branches/delete", map[string]string{"name": "big"}), http.StatusOK)
		assert.False(t, git.IsBranchExist(git.DefaultContext, repo.RepoPath(), "big"))
		assert.Less(t, personalRepoUsage(t, 2), locked-300000, "the gc after the delete freed the space")

		// writes work again
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-del/contents/back.txt", &api.CreateFileOptions{ContentBase64: "YmFjaw=="}).AddTokenAuth(token), http.StatusCreated)
	})
}

// AC4, AC5: the admin page, the per-user override (web and API) and the usage on the admin list and settings.
func TestPersonalRepoSizeAdmin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetPersonalRepoMode(t)
	defer setPersonalRepoOverride(t, 2, 0)
	admin := loginUser(t, "user1")

	logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.INFO)
	logChecker.Filter("Personal repository size limit changed from 0 to 5242880 bytes by user1", "Personal repository size limit of user2 changed from 0 to 1 by user1",
		"Personal repository size limit of user5 changed from 0 to -1 by user1")
	defer cleanup()
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": "allowed", "size_limit_mib": "5"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	assert.EqualValues(t, 5<<20, setting.Config().PersonalRepos.Value(db.DefaultContext).EffectiveSizeLimit())
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": "allowed", "size_limit_mib": "-1"}), http.StatusBadRequest)

	// the API override: bytes; organizations and values below -1 are refused
	adminToken := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeAll)
	one, minusTwo, minusOne := int64(1), int64(-2), int64(-1)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user2", &api.EditUserOption{PersonalRepoSizeLimit: &one}).AddTokenAuth(adminToken), http.StatusOK)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user2", &api.EditUserOption{PersonalRepoSizeLimit: &minusTwo}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/org3", &api.EditUserOption{PersonalRepoSizeLimit: &minusOne}).AddTokenAuth(adminToken), http.StatusNotFound)
	assert.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}).PersonalRepoSizeLimit)

	// the web override: MiB, -1 unlimited
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/5/edit", map[string]string{
		"login_type": "0-0", "login_name": user5.LoginName, "email": user5.Email, "max_repo_creation": "-1", "personal_repo_size_limit_mode": "unlimited",
	}), http.StatusSeeOther)
	defer setPersonalRepoOverride(t, 5, 0)
	assert.EqualValues(t, -1, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).PersonalRepoSizeLimit)
	filtered, _ := logChecker.Check(5 * time.Second)
	assert.Equal(t, []bool{true, true, true}, filtered)

	// user2 is over its 1-byte override: listed, shown in the admin list and on its settings
	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/personal-repos"), http.StatusOK).Body)
	assert.Contains(t, doc.Find("#personal-repo-over-limit").Text(), "user2")
	assert.NotContains(t, doc.Find("#personal-repo-over-limit").Text(), "user5")
	// U4: usage / limit, "unlimited", "exempt" for a site admin; never a bare size
	usageOf := func(name string) string {
		doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/users?q="+name), http.StatusOK).Body)
		return strings.Join(strings.Fields(doc.Find(".personal-repo-usage").First().Text()), " ")
	}
	assert.True(t, strings.HasSuffix(usageOf("user2"), "/ 1 B"), usageOf("user2"))
	assert.True(t, strings.HasSuffix(usageOf("user5"), "/ unlimited"), usageOf("user5"))
	assert.Equal(t, "exempt (site administrator)", usageOf("user1"))
	// U6: the settings page
	doc = NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user/settings/repos"), http.StatusOK).Body)
	assert.Contains(t, doc.Find("#personal-repo-limit-banner").Text(), "You can't push or add content until you delete some")
}

// M3: with the limit off a quota check reads only the cached setting; with it on, the user and the usage.
func TestPersonalRepoSizeQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetPersonalRepoMode(t)
	evaluate := func() {
		_, err := quota_model.EvaluateForUser(db.DefaultContext, 2, quota_model.LimitSubjectSizeReposAll)
		require.NoError(t, err)
	}
	// RepoAssignment's check for every repository page of a signed-in viewer: the owner is loaded already
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repoPage := func() {
		_, err := quota_model.GetPersonalRepoLimitOf(db.DefaultContext, owner)
		require.NoError(t, err)
	}
	assert.EqualValues(t, 0, stableQueryCount(t, evaluate))
	assert.EqualValues(t, 0, stableQueryCount(t, repoPage))
	setPersonalRepoSizeLimit(t, 1<<40)
	assert.EqualValues(t, 2, stableQueryCount(t, evaluate))
	assert.EqualValues(t, 1, stableQueryCount(t, repoPage))
}

// M1: the SSH path, at the internal serv command (ssh can't run in containers).
func TestPersonalRepoSizeLockSSH(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		ctx := t.Context()
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-ssh", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-ssh/wiki/new", &api.CreateWikiPageOptions{Title: "Home", ContentBase64: "aG9tZQ=="}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "lock-ssh-org", AutoInit: true}).AddTokenAuth(token), http.StatusCreated)

		// key 1 is user2's
		servMode := func(mode perm.AccessMode, owner, repo string, verbs ...string) private.ResponseExtra {
			_, extra := private.ServCommand(ctx, 1, owner, repo, mode, "", verbs...)
			return extra
		}
		serv := func(owner, repo string, verbs ...string) private.ResponseExtra {
			return servMode(perm.AccessModeWrite, owner, repo, verbs...)
		}
		writes := map[string][]string{
			"push":        {"user2", "lock-ssh", "git-receive-pack", ""},
			"wiki push":   {"user2", "lock-ssh.wiki", "git-receive-pack", ""},
			"LFS upload":  {"user2", "lock-ssh", "git-lfs-authenticate", "upload"},
			"org push":    {"org3", "lock-ssh-org", "git-receive-pack", ""},
			"push-create": {"user2", "lock-ssh-new", "git-receive-pack", ""},
		}
		lockPersonalRepos(t, 2, true)
		for name, w := range writes {
			extra := serv(w[0], w[1], w[2:]...)
			if w[0] == "org3" {
				require.NoError(t, extra.Error, "organizations are never locked")
				continue
			}
			assert.Equal(t, http.StatusForbidden, extra.StatusCode, name)
			assert.Contains(t, extra.UserMsg, personalLimitMessage, name)
		}
		// reads stay allowed
		require.NoError(t, servMode(perm.AccessModeRead, "user2", "lock-ssh", "git-upload-pack", "").Error)

		// a usable admin owner is never locked
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, &user_model.User{ID: 2, IsAdmin: true}, "is_admin"))
		require.NoError(t, serv("user2", "lock-ssh", "git-receive-pack", "").Error)
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, &user_model.User{ID: 2, IsAdmin: false}, "is_admin"))

		// below the limit
		lockPersonalRepos(t, 2, false)
		for _, name := range []string{"push", "wiki push", "LFS upload"} {
			w := writes[name]
			require.NoError(t, serv(w[0], w[1], w[2:]...).Error, name)
		}
	})
}

// M2: a merge scheduled before the lock waits while the base owner is locked, then merges.
func TestPersonalRepoSizeLockAutoMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-am", AutoInit: true, DefaultBranch: "main"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-am/branch_protections", &api.CreateBranchProtectionOption{RuleName: "main", EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-am/contents/f.txt", &api.CreateFileOptions{ContentBase64: "Zg==", FileOptions: api.FileOptions{NewBranchName: "feature"}}).AddTokenAuth(token), http.StatusCreated)
		var pr api.PullRequest
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-am/pulls", &api.CreatePullRequestOption{Head: "feature", Base: "main", Title: "am"}).AddTokenAuth(token), http.StatusCreated), &pr)
		MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/lock-am/pulls/%d/merge", pr.Index), &forms.MergePullRequestForm{Do: string(repo_model.MergeStyleMerge), MergeWhenChecksSucceed: true}).AddTokenAuth(token), http.StatusCreated)

		status := func() {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/lock-am/statuses/"+pr.Head.Sha, &api.CreateStatusOption{State: api.CommitStatusSuccess, Context: "ci"}).AddTokenAuth(token), http.StatusCreated)
		}
		merged := func() bool {
			return unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged
		}
		lockPersonalRepos(t, 2, true)
		status()
		assert.False(t, merged(), "waits while locked")
		unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})

		lockPersonalRepos(t, 2, false)
		status()
		assert.True(t, merged())
	})
}

// M3: the recipient of a transfer is checked, not the doer; a package goes to the owner in the URL; a trash restore
// to a new owner at its limit is refused. Users are locked by their override, with a large site limit.
func TestPersonalRepoSizeLockTargets(t *testing.T) {
	defer prepareTrash(t)()
	defer resetPersonalRepoMode(t)
	defer setPersonalRepoOverride(t, 2, 0)
	defer setPersonalRepoOverride(t, 5, 0)
	setPersonalRepoSizeLimit(t, 1<<40)
	lock := func(uid int64) { setPersonalRepoOverride(t, uid, personalRepoUsage(t, uid)) }
	user2 := loginUser(t, "user2")
	owner := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeAll)
	user5Token := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeAll)

	// user5 offers a repository to org3; user2, an owner of org3, is locked and accepts for org3, which isn't
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "to-org3"}).AddTokenAuth(user5Token), http.StatusCreated)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/to-org3/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(user5Token), http.StatusCreated)
	lock(2)
	user2.MakeRequest(t, NewRequest(t, "POST", "/user5/to-org3/action/accept_transfer"), http.StatusSeeOther)
	assert.True(t, repoExists(t, "org3", "to-org3"))

	// user2 locked: packages into its own namespace are refused, into org3's allowed
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/generic/lock-own/1.0/f.txt", strings.NewReader("p")).AddBasicAuth("user2"), http.StatusRequestEntityTooLarge)
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/org3/generic/lock-org/1.0/f.txt", strings.NewReader("p")).AddBasicAuth("user2"), http.StatusCreated)
	setPersonalRepoOverride(t, 2, 0)

	// a trash restore to the locked user5
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "trash-to-user5"}).AddTokenAuth(owner), http.StatusCreated)
	id := repoIDByName(t, "user2", "trash-to-user5")
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/trash-to-user5").AddTokenAuth(owner), http.StatusNoContent)
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(db.DefaultContext, id)
	require.NoError(t, err)
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 4, 1000, 0, 0)) // user5's repo4: an override of 0 would mean the site limit
	lock(5)
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	// the web page shows the size refusal, not the own-act one
	assert.Contains(t, trashRestoreFlash(t, id, "user5"), "The new owner or name can't be used")
	require.ErrorAs(t, repo_service.MoveTrashedRepository(audit_model.WithSystem(db.DefaultContext, "test"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), user5, repo, ""), &quota_model.ErrPersonalRepoLimit{})
}

// M5: re-saving the admin edit form keeps an override set in bytes that isn't whole MiB.
func TestPersonalRepoSizeOverrideBytesKept(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer setPersonalRepoOverride(t, 5, 0)
	setPersonalRepoOverride(t, 5, 1500000) // 1.43 MiB, shown as 1
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	edit := func(value string) {
		loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/5/edit", map[string]string{
			"login_type": "0-0", "login_name": user5.LoginName, "email": user5.Email, "max_repo_creation": "-1",
			"personal_repo_size_limit_mode": "custom", "personal_repo_size_limit": value,
		}), http.StatusSeeOther)
	}
	edit("1")
	assert.EqualValues(t, 1500000, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).PersonalRepoSizeLimit)
	edit("2")
	assert.EqualValues(t, 2<<20, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).PersonalRepoSizeLimit)
	// the form: three choices, the custom value in MiB
	doc := NewHTMLParser(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/users/5/edit"), http.StatusOK).Body)
	assert.Equal(t, "custom", doc.Find("input#personal_repo_size_limit_mode").AttrOr("value", ""))
	assert.Equal(t, "2", doc.Find("#personal_repo_size_limit").AttrOr("value", ""))
	loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/5/edit", map[string]string{
		"login_type": "0-0", "login_name": user5.LoginName, "email": user5.Email, "max_repo_creation": "-1", "personal_repo_size_limit_mode": "site",
	}), http.StatusSeeOther)
	assert.EqualValues(t, 0, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).PersonalRepoSizeLimit)
}

// U1: the owner is warned before a write fails, and the pages offer no action that would be refused.
func TestPersonalRepoSizeLockUI(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetPersonalRepoMode(t)
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "lock-ui", AutoInit: true, DefaultBranch: "main", Readme: "Default"}).AddTokenAuth(token), http.StatusCreated)
		page := func(path string) *HTMLDoc {
			return NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
		}
		banner := func(doc *HTMLDoc) string { return doc.Find("#personal-repo-limit-banner").Text() }

		// unlocked: no banner, the actions are there
		doc := page("/user2/lock-ui")
		assert.Empty(t, banner(doc))
		assert.Equal(t, 1, doc.Find(`a[href$="/_new/main/"]`).Length())

		lockPersonalRepos(t, 2, true)
		doc = page("/user2/lock-ui")
		assert.Contains(t, banner(doc), "You can't push or add content")
		assert.Equal(t, 0, doc.Find(`a[href$="/_new/main/"]`).Length(), "no Add file")
		doc = page("/user2/lock-ui/src/branch/main/README.md")
		assert.Contains(t, banner(doc), "You can't push or add content")
		assert.Equal(t, 0, doc.Find(`a[href*="/_edit/"]`).Length(), "no edit")
		assert.Equal(t, 1, doc.Find(`a[href*="/_delete/"]`).Length(), "deletes stay")

		// new repository, fork and migrate: the banner, and the user isn't offered as the owner
		doc = page("/repo/create")
		assert.Contains(t, banner(doc), "You can't push or add content")
		assert.Equal(t, 0, doc.Find(`#repo_owner_label .menu .item[data-value="2"]`).Length())
		assert.Positive(t, doc.Find(`#repo_owner_label .menu .item`).Length(), "user2's organizations stay")
		doc = page("/user5/repo4/fork")
		assert.Contains(t, banner(doc), "You can't push or add content")
		assert.Equal(t, 0, doc.Find(`.menu .item[data-value="2"]`).Length())
		doc = page("/repo/migrate?service_type=1")
		assert.Contains(t, banner(doc), "You can't push or add content")
		assert.Equal(t, 0, doc.Find(`.menu .item[data-value="2"]`).Length())
		assert.NotEqual(t, "2", doc.Find("#uid").AttrOr("value", ""), "an organization is preselected")

		// someone else sees no banner (TestPersonalRepoLockBannerVisibility)
		doc = NewHTMLParser(t, loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/user2/lock-ui"), http.StatusOK).Body)
		assert.Empty(t, banner(doc))
	})
}
