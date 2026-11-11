// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoIDByName returns the ID of the root repository owner/name, for the internal hook routes.
func repoIDByName(t *testing.T, owner, name string) int64 {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: owner, LowerName: strings.ToLower(name)}, "group_id = 0").ID
}

// prepareRepoGroupGit is prepareRepoGroupWeb plus a root repository org3/pub with the leaf name of org3/proj/pub,
// so that a lookup by owner and leaf name would find the wrong one.
func prepareRepoGroupGit(t *testing.T) (*repoGroupWebFixture, *repo_model.Repository) {
	t.Helper()
	f := prepareRepoGroupWeb(t)
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	rootPub, err := repo_service.CreateRepository(db.DefaultContext, user2, f.org, repo_service.CreateRepoOptions{
		Name: "pub", Readme: "Default", AutoInit: true, DefaultBranch: "main",
	})
	require.NoError(t, err)
	return f, rootPub
}

// gitResponse is the status, headers and body of a git or LFS response, with the request path replaced and the
// date left out.
func gitResponse(t *testing.T, req *RequestWrapper, repoPath string) string {
	t.Helper()
	resp := MakeRequest(t, req, NoExpectedStatus)
	header := resp.Header().Clone()
	header.Del("Date")
	header.Del("Set-Cookie")
	return fmt.Sprintf("%d\n%v\n%s", resp.Code, header, strings.ReplaceAll(resp.Body.String(), repoPath, "PATH"))
}

func branchCommit(t *testing.T, repoID int64) string {
	t.Helper()
	branch, err := git_model.GetBranch(db.DefaultContext, repoID, "main")
	require.NoError(t, err)
	return branch.CommitID
}

// Clone, push, wiki and AGit over HTTP for a repository in a project; the hooks find it by ID, never by the leaf
// name it shares with the root repository org3/pub.
func TestRepoGroupGitHTTP(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, rootPub := prepareRepoGroupGit(t)
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		withToken := func(p string) *url.URL {
			c := *u
			c.Path = p
			c.User = url.UserPassword("user2", token)
			return &c
		}
		rootCommit := branchCommit(t, rootPub.ID)

		t.Run("anonymous clone of a public repository", func(t *testing.T) {
			c := *u
			c.Path = "/org3/proj/pub.git"
			dir := t.TempDir()
			doGitClone(dir, &c)(t)
			assert.FileExists(t, path.Join(dir, "README.md"))
		})

		dir := t.TempDir()
		t.Run("clone and push a private repository with a token", func(t *testing.T) {
			doGitClone(dir, withToken("/org3/proj/priv.git"))(t)
			doGitAddSomeCommits(dir, "main")(t)
			doGitPushTestRepository(dir, "origin", "main")(t)
			head, _, err := git.NewCommand(t.Context(), "rev-parse", "HEAD").RunStdString(&git.RunOpts{Dir: dir})
			require.NoError(t, err)
			assert.Equal(t, strings.TrimSpace(head), branchCommit(t, f.priv.ID), "post-receive updated the repository in the project")
		})

		pubDir := t.TempDir()
		doGitClone(pubDir, withToken("/org3/proj/pub.git"))(t)
		t.Run("branch rules of the repository with the same leaf name don't apply", func(t *testing.T) {
			require.NoError(t, git_model.UpdateProtectBranch(db.DefaultContext, rootPub, &git_model.ProtectedBranch{RepoID: rootPub.ID, RuleName: "main"}, git_model.WhitelistOptions{}))
			doGitAddSomeCommits(pubDir, "main")(t)
			doGitPushTestRepository(pubDir, "origin", "main")(t)
			assert.Equal(t, rootCommit, branchCommit(t, rootPub.ID), "the root repository is untouched")
		})

		t.Run("branch rules of the repository in the project apply", func(t *testing.T) {
			require.NoError(t, git_model.UpdateProtectBranch(db.DefaultContext, f.pub, &git_model.ProtectedBranch{RepoID: f.pub.ID, RuleName: "main"}, git_model.WhitelistOptions{}))
			doGitAddSomeCommits(pubDir, "main")(t)
			stderr := doGitPushTestRepositoryFail(t, pubDir, "origin", "main")
			assert.Contains(t, stderr, "protected branch")
		})

		t.Run("AGit pull request", func(t *testing.T) {
			doGitPushTestRepository(pubDir, "origin", "HEAD:refs/for/main/topic", "-o", "title=from agit")(t)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: f.pub.ID, HeadBranch: "user2/topic"})
			assert.Equal(t, issues_model.PullRequestFlowAGit, pr.Flow)
			unittest.AssertNotExistsBean(t, &issues_model.PullRequest{BaseRepoID: rootPub.ID})
		})

		t.Run("wiki", func(t *testing.T) {
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/priv/wiki?action=_new", map[string]string{
				"title": "Home", "content": "wiki in a project",
			}), http.StatusSeeOther)
			wikiDir := t.TempDir()
			require.NoError(t, git.Clone(t.Context(), withToken("/org3/proj/priv.wiki.git").String(), wikiDir, git.CloneRepoOptions{}))
			content, err := os.ReadFile(path.Join(wikiDir, "Home.md"))
			require.NoError(t, err)
			assert.Equal(t, "wiki in a project", string(content))
		})
	})
}

// A repository in a project that the request can't see answers exactly like a missing one, for every git
// endpoint and every kind of requester, and a project path never creates a repository.
func TestRepoGroupGitHTTPHidden(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f, _ := prepareRepoGroupGit(t)
	gone, err := repo_service.CreateRepository(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), f.org, repo_service.CreateRepoOptions{Name: "gone", GroupID: f.pub.GroupID, AutoInit: true, Readme: "Default"})
	require.NoError(t, err)
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", gone.ID)
	require.NoError(t, err)

	nonMember := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository)
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)

	// a job token of user2/repo1
	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	original := *task
	t.Cleanup(func() {
		require.NoError(t, actions_model.UpdateTask(context.Background(), &original, "repo_id", "owner_id", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
	})
	task.RepoID, task.OwnerID, task.TokenPermissions = 1, 2, ""
	task.GenerateToken()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))

	hidden := []string{"/org3/secret/hid", "/privated_org/pp/ppub"}
	missing := []string{"/org3/proj/nope", "/org3/nope/hid", "/org3/proj/gone", "/privated_org/nope/ppub"}
	requests := map[string]func(p string) *RequestWrapper{
		"upload-pack refs": func(p string) *RequestWrapper {
			return NewRequest(t, "GET", p+".git/info/refs?service=git-upload-pack")
		},
		"receive-pack refs": func(p string) *RequestWrapper {
			return NewRequest(t, "GET", p+".git/info/refs?service=git-receive-pack")
		},
		"upload-pack": func(p string) *RequestWrapper {
			return NewRequestWithBody(t, "POST", p+".git/git-upload-pack", strings.NewReader("0000")).SetHeader("Content-Type", "application/x-git-upload-pack-request")
		},
	}
	auths := map[string]func(*RequestWrapper) *RequestWrapper{
		"anonymous":  func(r *RequestWrapper) *RequestWrapper { return r },
		"non-member": func(r *RequestWrapper) *RequestWrapper { r.SetBasicAuth("user8", nonMember); return r },
		"job token":  func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(task.Token) },
	}

	check := func(t *testing.T) {
		for reqName, newReq := range requests {
			for authName, auth := range auths {
				expected := gitResponse(t, auth(newReq(missing[0])), missing[0])
				assert.NotContains(t, expected, "\n200\n")
				for _, p := range append(hidden, missing[1:]...) {
					assertSameResponse(t, expected, gitResponse(t, auth(newReq(p)), p), "%s %s %s", reqName, authName, p)
				}
			}
		}
	}
	t.Run("hidden is missing", check)

	t.Run("archived", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", true, f.hid.ID)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", false, f.hid.ID)
			require.NoError(t, err)
		}()
		check(t)
	})

	t.Run("push to create", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateOrg, true)()
		check(t)
		// not even for the owner of the organization
		for _, method := range []string{"GET", "POST"} {
			req := NewRequestWithBody(t, method, "/org3/proj/new.git/info/refs?service=git-receive-pack", nil)
			if method == "POST" {
				req = NewRequestWithBody(t, method, "/org3/proj/new.git/git-receive-pack", strings.NewReader("0000"))
			}
			resp := MakeRequest(t, req.AddTokenAuth(owner), http.StatusNotFound)
			assert.Equal(t, "Repository not found", resp.Body.String())
		}
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: f.org.ID, LowerName: "new"})
	})

	t.Run("fail closed", func(t *testing.T) {
		for _, p := range []string{
			fmt.Sprintf("/org3/@%d.git/info/refs", f.pub.ID),
			fmt.Sprintf("/org3/proj/@%d.git/info/refs", f.pub.ID),
			fmt.Sprintf("/org3/%%40%d.git/info/refs", f.pub.ID),
			"/org3/proj%2Fpub.git/info/refs",
			"/org3/proj/pub%2F.git/info/refs",
			"/org3/proj%252Fpub.git/info/refs",
			"/org3/proj/pub%5C.git/info/refs",
		} {
			MakeRequest(t, NewRequest(t, "GET", p+"?service=git-upload-pack").AddTokenAuth(owner), http.StatusNotFound)
		}
		// a leaf name never resolves at the root: org3/priv is no repository
		resp := MakeRequest(t, NewRequest(t, "GET", "/org3/priv.git/info/refs?service=git-upload-pack").AddTokenAuth(owner), http.StatusNotFound)
		assert.Equal(t, "Repository not found", resp.Body.String())
	})
}

// withLFSAuth sends an access token as basic auth (LFS takes no bearer access tokens), and a "Bearer " LFS token
// as it is.
func (req *RequestWrapper) withLFSAuth(token string) *RequestWrapper {
	if strings.HasPrefix(token, "Bearer ") || token == "" {
		return req.AddTokenAuth(token)
	}
	req.SetBasicAuth("token", token)
	return req
}

func lfsRequest(t *testing.T, method, p string, v any) *RequestWrapper {
	t.Helper()
	return NewRequestWithJSON(t, method, p, v).SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType)
}

// LFS objects and locks of a repository in a project are bound to that repository, and a hidden one answers like
// a missing one.
func TestRepoGroupLFS(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	if !setting.LFS.StartServer {
		t.Skip()
	}
	f, rootPub := prepareRepoGroupGit(t)
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	nonMember := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository)

	content := []byte("lfs in a project")
	p, err := lfs.GeneratePointer(bytes.NewReader(content))
	require.NoError(t, err)
	batch := func(repoPath, op, token string, status int) *lfs.BatchResponse {
		t.Helper()
		resp := MakeRequest(t, lfsRequest(t, "POST", repoPath+".git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: op, Objects: []lfs.Pointer{p}}).withLFSAuth(token), status)
		if status != http.StatusOK {
			return nil
		}
		var br lfs.BatchResponse
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &br))
		require.Len(t, br.Objects, 1)
		return &br
	}

	t.Run("objects", func(t *testing.T) {
		br := batch("/org3/proj/priv", "upload", owner, http.StatusOK)
		upload := br.Objects[0].Actions["upload"]
		require.NotNil(t, upload)
		assert.Equal(t, setting.AppURL+"org3/proj/priv.git/info/lfs/objects/"+p.Oid+"/"+fmt.Sprint(p.Size), upload.Href)
		assert.Equal(t, setting.AppURL+"org3/proj/priv.git/info/lfs/verify", br.Objects[0].Actions["verify"].Href)
		MakeRequest(t, NewRequestWithBody(t, "PUT", strings.TrimPrefix(upload.Href, setting.AppURL[:len(setting.AppURL)-1]), bytes.NewReader(content)).withLFSAuth(owner), http.StatusOK)
		unittest.AssertExistsAndLoadBean(t, &git_model.LFSMetaObject{RepositoryID: f.priv.ID, Pointer: p})

		br = batch("/org3/proj/priv", "download", owner, http.StatusOK)
		download := br.Objects[0].Actions["download"]
		require.NotNil(t, download)
		assert.Equal(t, setting.AppURL+"org3/proj/priv.git/info/lfs/objects/"+p.Oid, download.Href)
		resp := MakeRequest(t, NewRequest(t, "GET", "/org3/proj/priv.git/info/lfs/objects/"+p.Oid).withLFSAuth(owner), http.StatusOK)
		assert.Equal(t, content, resp.Body.Bytes())

		// the root repository with the same leaf name doesn't have it
		br = batch("/org3/pub", "download", owner, http.StatusOK)
		assert.NotNil(t, br.Objects[0].Error)
	})

	t.Run("an LFS token is bound to its repository", func(t *testing.T) {
		token := func(repoID int64) string {
			jwt, err := setting.LFS.SigningKey.JWT(lfs.Claims{RepoID: repoID, Op: "download", UserID: 2})
			require.NoError(t, err)
			return "Bearer " + jwt
		}
		batch("/org3/proj/priv", "download", token(f.priv.ID), http.StatusOK)
		// a token of the root repository with another leaf name, and one of the repository in the project with the
		// leaf name of the root one
		resp := MakeRequest(t, lfsRequest(t, "POST", "/org3/proj/priv.git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: "download", Objects: []lfs.Pointer{p}}).withLFSAuth(token(rootPub.ID)), NoExpectedStatus)
		assert.NotEqual(t, http.StatusOK, resp.Code)
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET is_private = ? WHERE id = ?", true, rootPub.ID)
		require.NoError(t, err)
		resp = MakeRequest(t, lfsRequest(t, "POST", "/org3/pub.git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: "download", Objects: []lfs.Pointer{p}}).withLFSAuth(token(f.pub.ID)), NoExpectedStatus)
		assert.NotEqual(t, http.StatusOK, resp.Code)
	})

	t.Run("locks", func(t *testing.T) {
		MakeRequest(t, lfsRequest(t, "POST", "/org3/proj/pub.git/info/lfs/locks", &api.LFSLockRequest{Path: "a.bin"}).withLFSAuth(owner), http.StatusCreated)
		lock := unittest.AssertExistsAndLoadBean(t, &git_model.LFSLock{RepoID: f.pub.ID, Path: "a.bin"})
		unittest.AssertNotExistsBean(t, &git_model.LFSLock{RepoID: rootPub.ID})

		count := func(repoPath string) int {
			resp := MakeRequest(t, lfsRequest(t, "GET", repoPath+".git/info/lfs/locks", nil).withLFSAuth(owner), http.StatusOK)
			var list api.LFSLockList
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &list))
			return len(list.Locks)
		}
		assert.Equal(t, 1, count("/org3/proj/pub"))
		assert.Equal(t, 0, count("/org3/pub"))
		MakeRequest(t, lfsRequest(t, "POST", "/org3/proj/pub.git/info/lfs/locks/verify", &api.LFSLockRequest{}).withLFSAuth(owner), http.StatusOK)
		resp := MakeRequest(t, lfsRequest(t, "POST", fmt.Sprintf("/org3/pub.git/info/lfs/locks/%d/unlock", lock.ID), map[string]bool{"force": true}).withLFSAuth(owner), NoExpectedStatus)
		assert.NotEqual(t, http.StatusOK, resp.Code)
		unittest.AssertExistsAndLoadBean(t, &git_model.LFSLock{ID: lock.ID})
		MakeRequest(t, lfsRequest(t, "POST", fmt.Sprintf("/org3/proj/pub.git/info/lfs/locks/%d/unlock", lock.ID), map[string]bool{"force": true}).withLFSAuth(owner), http.StatusOK)
	})

	t.Run("hidden is missing", func(t *testing.T) {
		missing := "/org3/proj/nope"
		for _, token := range []string{"", nonMember} {
			for name, newReq := range map[string]func(p string) *RequestWrapper{
				"batch": func(p string) *RequestWrapper {
					return lfsRequest(t, "POST", p+".git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: "download", Objects: []lfs.Pointer{p0(p)}})
				},
				"object": func(p string) *RequestWrapper { return NewRequest(t, "GET", p+".git/info/lfs/objects/"+p0(p).Oid) },
				"locks":  func(p string) *RequestWrapper { return lfsRequest(t, "GET", p+".git/info/lfs/locks", nil) },
				"lock": func(p string) *RequestWrapper {
					return lfsRequest(t, "POST", p+".git/info/lfs/locks", &api.LFSLockRequest{Path: "b.bin"})
				},
			} {
				expected := gitResponse(t, newReq(missing).withLFSAuth(token), missing)
				assert.Contains(t, expected, "401", name)
				for _, p := range []string{"/org3/secret/hid", "/org3/nope/hid", "/privated_org/pp/ppub"} {
					assertSameResponse(t, expected, gitResponse(t, newReq(p).withLFSAuth(token), p), "%s %q %s", name, token, p)
				}
			}
		}
	})
}

// p0 is the same pointer for every path, so that hidden and missing requests are byte-identical.
func p0(string) lfs.Pointer {
	return lfs.Pointer{Oid: "05eeb4eb5be71f2dd291ca39157d6d9effd7d1ea19cbdc8a99411fe2a8f26a00", Size: 6}
}

// SSH, through the serv command as cmd/serv calls it (there is no ssh client in the test environment): a repository
// in a project is found by its path, and a hidden one is missing for user and deploy keys alike.
func TestRepoGroupServ(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	f, rootPub := prepareRepoGroupGit(t)
	user8Key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(ctx, "test"), 8, "user8 key", newOrgDeployKeyContent(t), 0, 0)
	require.NoError(t, err)

	serv := func(keyID int64, repoPath string, mode perm.AccessMode, verb string) (*private.ServCommandResults, private.ResponseExtra) {
		owner, repo, _ := strings.Cut(repoPath, "/")
		return private.ServCommand(ctx, keyID, owner, repo, mode, "127.0.0.1", verb, "")
	}

	t.Run("resolved by path", func(t *testing.T) {
		results, extra := serv(1, "org3/proj/pub", perm.AccessModeWrite, "git-receive-pack")
		require.NoError(t, extra.Error)
		assert.Equal(t, f.pub.ID, results.RepoID)
		assert.Equal(t, [3]string{"org3", "proj", "pub"}, [3]string{results.OwnerName, results.GroupName, results.RepoName})
		results, extra = serv(1, "org3/PROJ/Pub.wiki", perm.AccessModeRead, "git-upload-pack")
		require.NoError(t, extra.Error)
		assert.Equal(t, f.pub.ID, results.RepoID)
		assert.True(t, results.IsWiki)
		assert.Equal(t, [3]string{"org3", "proj", "pub"}, [3]string{results.OwnerName, results.GroupName, results.RepoName})

		results, extra = serv(1, "org3/pub", perm.AccessModeWrite, "git-receive-pack")
		require.NoError(t, extra.Error)
		assert.Equal(t, rootPub.ID, results.RepoID)
		assert.Empty(t, results.GroupName)
	})

	repoKey, err := asymkey_model.AddDeployKey(ctx, f.priv.ID, "priv key", newOrgDeployKeyContent(t), false, 0)
	require.NoError(t, err)
	rootKey, err := asymkey_model.AddDeployKey(ctx, rootPub.ID, "root key", newOrgDeployKeyContent(t), false, 0)
	require.NoError(t, err)
	orgKey := addOrgDeployKey(t, f.org.ID, "org key", newOrgDeployKeyContent(t), true, f.hid.ID)

	t.Run("deploy keys", func(t *testing.T) {
		results, extra := serv(repoKey.KeyID, "org3/proj/priv", perm.AccessModeWrite, "git-receive-pack")
		require.NoError(t, extra.Error)
		assert.Equal(t, f.priv.ID, results.RepoID)
		assert.Equal(t, repoKey.KeyID, results.DeployKeyKeyID)
		results, extra = serv(orgKey.KeyID, "org3/secret/hid", perm.AccessModeRead, "git-upload-pack")
		require.NoError(t, extra.Error)
		assert.Equal(t, f.hid.ID, results.RepoID)
		_, extra = serv(orgKey.KeyID, "org3/secret/hid", perm.AccessModeWrite, "git-receive-pack")
		assert.Contains(t, extra.UserMsg, "is not authorized to write to", "a read-only key that covers the repository")
	})

	t.Run("hidden is missing", func(t *testing.T) {
		missing := "org3/proj/nope"
		for keyName, keyID := range map[string]int64{"user key": user8Key.ID, "repo key": repoKey.KeyID, "root key": rootKey.KeyID, "org key": orgKey.KeyID} {
			for _, verb := range []string{"git-upload-pack", "git-receive-pack"} {
				mode := perm.AccessModeRead
				if verb == "git-receive-pack" {
					mode = perm.AccessModeWrite
				}
				_, missingExtra := serv(keyID, missing, mode, verb)
				require.Error(t, missingExtra.Error)
				assert.Equal(t, http.StatusNotFound, missingExtra.StatusCode)
				assert.Equal(t, "Cannot find repository: "+missing, missingExtra.UserMsg)
				for _, p := range []string{"org3/secret/hid", "org3/nope/hid", "privated_org/pp/ppub", "org3/proj/pub", "org3/proj/priv"} {
					if keyName == "repo key" && p == "org3/proj/priv" || keyName == "org key" && p == "org3/secret/hid" ||
						keyName == "user key" && p == "org3/proj/pub" {
						continue // they can see these
					}
					_, extra := serv(keyID, p, mode, verb)
					assert.Equal(t, missingExtra.StatusCode, extra.StatusCode, "%s %s %s", keyName, verb, p)
					assert.Equal(t, "Cannot find repository: "+p, extra.UserMsg, "%s %s %s", keyName, verb, p)
				}
			}
		}
	})

	t.Run("no push to create", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateOrg, true)()
		_, extra := serv(1, "org3/proj/new", perm.AccessModeWrite, "git-receive-pack")
		assert.Equal(t, "Cannot find repository: org3/proj/new", extra.UserMsg)
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: f.org.ID, LowerName: "new"})
	})

	t.Run("pre-receive by ID", func(t *testing.T) {
		require.NoError(t, git_model.UpdateProtectBranch(db.DefaultContext, f.pub, &git_model.ProtectedBranch{RepoID: f.pub.ID, RuleName: "feature"}, git_model.WhitelistOptions{}))
		newBranch := func(repoID int64) private.HookOptions {
			return private.HookOptions{UserID: 2, OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{branchCommit(t, repoID)}, RefFullNames: []git.RefName{"refs/heads/feature"}}
		}
		extra := private.HookPreReceive(ctx, f.pub.ID, newBranch(f.pub.ID))
		require.Error(t, extra.Error)
		assert.Contains(t, extra.UserMsg, "protected branch")
		require.NoError(t, private.HookPreReceive(ctx, rootPub.ID, newBranch(rootPub.ID)).Error, "the root repository with the same leaf name has no rule")
		opts := newBranch(rootPub.ID)

		// a trashed or unknown repository is refused
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", rootPub.ID)
		require.NoError(t, err)
		for _, id := range []int64{rootPub.ID, 0, 999999} {
			require.Error(t, private.HookPreReceive(ctx, id, opts).Error, id)
			_, extra := private.HookPostReceive(ctx, id, private.HookOptions{UserID: 2, OldCommitIDs: []string{"a"}, NewCommitIDs: []string{"b"}, RefFullNames: []git.RefName{"refs/heads/main"}})
			require.Error(t, extra.Error, id)
		}
	})
}

// Token downloads (raw, archive) of a repository in a project, on its own routes, so that token authentication works;
// a hidden repository is the same 404 as a missing one and is never served a second time by the web resolver.
func TestRepoGroupTokenDownloads(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareRepoGroupGit(t)
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
	nonMember := getUserToken(t, "user8", auth_model.AccessTokenScopeReadRepository)

	for _, p := range []string{"/org3/proj/priv/raw/branch/main/README.md", "/org3/proj/priv/-/raw/branch/main/README.md"} {
		resp := MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(owner), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "priv")
	}
	MakeRequest(t, NewRequest(t, "GET", "/org3/proj/priv/archive/main.zip").AddTokenAuth(owner), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/org3/proj/priv/raw/branch/main/README.md"), http.StatusNotFound)

	response := func(p string) *httptest.ResponseRecorder {
		return MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(nonMember), NoExpectedStatus)
	}
	for _, rest := range []string{"/raw/branch/main/README.md", "/-/raw/branch/main/README.md", "/archive/main.zip"} {
		expected := gitResponse(t, NewRequest(t, "GET", "/org3/secret/nope"+rest).AddTokenAuth(nonMember), "/org3/secret/nope"+rest)
		assert.Contains(t, expected, "404\n")
		for _, p := range []string{"/org3/secret/hid", "/org3/nope/hid"} {
			resp := response(p + rest)
			assert.NotContains(t, resp.Body.String(), "/@", "never redispatched to the internal form")
			assertSameResponse(t, expected, gitResponse(t, NewRequest(t, "GET", p+rest).AddTokenAuth(nonMember), p+rest), p+rest)
		}
	}
}

// go-get names a repository in a project only to those who can see it; everyone else gets the answer for the
// first two segments, whether or not they name a project.
func TestRepoGroupGoGet(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareRepoGroupGit(t)
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(setting.AppURL, "http://"), "https://"), "/")

	resp := MakeRequest(t, NewRequest(t, "GET", "/org3/proj/pub/sub/pkg?go-get=1"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), fmt.Sprintf(`<meta name="go-import" content="%s/org3/proj/pub git %sorg3/proj/pub.git">`, host, setting.AppURL))
	assert.Contains(t, resp.Body.String(), setting.AppURL+"org3/proj/pub/src/branch/main{/dir}")

	anonymous := func(p string) string {
		return strings.ReplaceAll(MakeRequest(t, NewRequest(t, "GET", p), http.StatusOK).Body.String(), "nope", "secret")
	}
	expected := anonymous("/org3/nope/hid/pkg?go-get=1")
	assert.Contains(t, expected, fmt.Sprintf(`content="%s/org3/secret git`, host))
	assert.Equal(t, expected, anonymous("/org3/secret/hid/pkg?go-get=1"))

	session := loginUser(t, "user2")
	resp = session.MakeRequest(t, NewRequest(t, "GET", "/org3/secret/hid/pkg?go-get=1"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), fmt.Sprintf(`content="%s/org3/secret/hid git %sorg3/secret/hid.git"`, host, setting.AppURL))
}

// Adopting works on root directories only: a project directory is never listed, and a stray root directory is
// listed although a repository with its name exists in a project.
func TestRepoGroupAdopt(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareRepoGroupWeb(t)
	stray := repo_model.RepoPath("org3", "pub")
	require.NoError(t, git.InitRepository(t.Context(), stray, true, git.Sha1ObjectFormat.Name()))
	defer os.RemoveAll(stray)

	unadopted, _, err := repo_service.ListUnadoptedRepositories(db.DefaultContext, "org3", &db.ListOptions{Page: 1, PageSize: 1000})
	require.NoError(t, err)
	assert.Contains(t, unadopted, "org3/pub")
	for _, name := range unadopted {
		assert.NotContains(t, []string{"org3/proj", "org3/secret"}, name)
	}
}
