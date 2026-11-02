// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	mirror_service "forgejo.org/services/mirror"
	repo_service "forgejo.org/services/repository"
	trash_service "forgejo.org/services/trash"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoOne returns the one entry of action written after since, and checks its category and repository scope.
func repoOne(t *testing.T, since int64, action string, repo *repo_model.Repository) *audit_model.Entry {
	t.Helper()
	entries := auditActions(t, since, action)
	require.Len(t, entries, 1, action)
	assert.Equal(t, audit_model.CategoryRepo, entries[0].Category)
	assert.Equal(t, repo.ID, entries[0].RepoID, action)
	return entries[0]
}

func loadRepo(t *testing.T, owner, name string) *repo_model.Repository {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: owner, LowerName: strings.ToLower(name)})
}

func TestAuditRepoLifecycle(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Trash.RetentionDays, 30)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)

	// created, on the API and the web
	since := auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-repo"}).AddTokenAuth(token), http.StatusCreated)
	repo := loadRepo(t, "user2", "audit-repo")
	e := repoOne(t, since, "repo.repository.created", repo)
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 2, e.OwnerID)
	assert.Equal(t, "repo", e.TargetType)
	assert.Equal(t, "user2/audit-repo", e.TargetName)
	assert.Equal(t, false, auditData(t, e)["is_private"])
	created := e.ID

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{"uid": "2", "repo_name": "audit-web"}), http.StatusSeeOther)
	web := loadRepo(t, "user2", "audit-web")
	repoOne(t, since, "repo.repository.created", web)

	// renamed
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/audit-repo", &api.EditRepoOption{Name: new("audit-repo-2")}).AddTokenAuth(token), http.StatusOK)
	data := auditData(t, repoOne(t, since, "repo.repository.renamed", repo))
	assert.Equal(t, map[string]any{"name": "audit-repo"}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-repo-2"}, data["after"])
	assert.Empty(t, auditActions(t, since, "repo.repository.updated"), "a rename changes no setting")

	// trashed, restored to a new owner (transferred + restored), then purged
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/audit-web").AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.repository.trashed", web)
	since = auditMaxID(t)
	require.NoError(t, trash_service.RestoreRepo(asActor(t, 1, "user1"), admin, web.ID, trash_service.RestoreOptions{NewOwner: "user4"}))
	e = repoOne(t, since, "repo.repository.transferred", web)
	assert.EqualValues(t, 2, e.OwnerID, "scoped to the previous owner")
	assert.EqualValues(t, 4, auditData(t, e)["after"].(map[string]any)["owner_id"])
	e = repoOne(t, since, "repo.repository.restored", web)
	assert.EqualValues(t, 4, e.OwnerID)
	assert.EqualValues(t, 1, e.ActorID)

	web = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: web.ID})
	require.NoError(t, repo_service.DeleteRepository(asActor(t, 4, "user4"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}), web, false))
	since = auditMaxID(t)
	require.NoError(t, trash_service.Purge(asActor(t, 1, "user1"), admin, web.ID))
	assert.Equal(t, true, auditData(t, repoOne(t, since, "repo.repository.deleted", web))["purge"])

	// deleted for good, with the counts of what goes with it
	defer test.MockVariableValue(&setting.Trash.RetentionDays, 0)()
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/audit-repo-2/collaborators/user4", &api.AddCollaboratorOption{}).AddTokenAuth(token), http.StatusNoContent)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/audit-repo-2").AddTokenAuth(token), http.StatusNoContent)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	data = auditData(t, repoOne(t, since, "repo.repository.deleted", repo))
	assert.Equal(t, false, data["purge"])
	assert.EqualValues(t, 1, data["counts"].(map[string]any)["collaborators"])
	unittest.AssertExistsAndLoadBean(t, &audit_model.Entry{ID: created})
}

func TestAuditRepoTransfer(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	token4 := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository)
	// private, so that the recipient needs a read collaborator to see it
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-transfer", Private: true}).AddTokenAuth(token), http.StatusCreated)
	repo := loadRepo(t, "user2", "audit-transfer")
	start := func() {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/audit-transfer/transfer", &api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(token), http.StatusCreated)
	}

	// started: the recipient gets read access as a collaborator
	since := auditMaxID(t)
	start()
	data := auditData(t, repoOne(t, since, "repo.transfer.started", repo))
	assert.EqualValues(t, 4, data["to_owner_id"])
	assert.Equal(t, "user4", data["to_owner_name"])
	assert.Equal(t, "read", auditData(t, repoOne(t, since, "repo.collaborator.added", repo))["mode"])

	// rejected by the recipient, canceled by the owner; a cancel without a pending transfer records nothing
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/audit-transfer/transfer/reject").AddTokenAuth(token4), http.StatusOK)
	assert.EqualValues(t, 4, repoOne(t, since, "repo.transfer.rejected", repo).ActorID)
	start()
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/audit-transfer/settings", map[string]string{"action": "cancel_transfer"}), http.StatusSeeOther)
	assert.EqualValues(t, 2, repoOne(t, since, "repo.transfer.canceled", repo).ActorID)
	since = auditMaxID(t)
	require.NoError(t, repo_service.CancelRepositoryTransfer(asActor(t, 2, "user2"), loadRepo(t, "user2", "audit-transfer"), false))
	assert.Empty(t, auditActions(t, since, "repo.transfer.canceled"))

	// accepted: one entry, scoped to the previous owner, with the counts
	start()
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/audit-transfer/transfer/accept").AddTokenAuth(token4), http.StatusAccepted)
	e := repoOne(t, since, "repo.transfer.accepted", repo)
	assert.EqualValues(t, 4, e.ActorID)
	assert.EqualValues(t, 2, e.OwnerID)
	assert.Equal(t, "user2/audit-transfer", e.TargetName)
	data = auditData(t, e)
	assert.Equal(t, map[string]any{"owner_id": float64(2), "owner_name": "user2", "group_id": float64(0), "group_name": ""}, data["before"])
	assert.EqualValues(t, 4, data["after"].(map[string]any)["owner_id"])
	assert.EqualValues(t, 1, data["counts"].(map[string]any)["collaborators"], "the recipient's read access")
	assert.Empty(t, auditActions(t, since, "repo.repository.transferred"))

	// a direct transfer, by a site admin
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user4/audit-transfer/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(adminToken), http.StatusAccepted)
	e = repoOne(t, since, "repo.repository.transferred", repo)
	assert.EqualValues(t, 1, e.ActorID)
	assert.EqualValues(t, 4, e.OwnerID)
	assert.Empty(t, auditActions(t, since, "repo.transfer.started"))
}

func TestAuditRepoProjects(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})

	since := auditMaxID(t)
	group, err := repo_model.CreateRepoGroup(ctx, org, "audit-project", "")
	require.NoError(t, err)
	e := orgOne(t, since, "org.project.created")
	assert.Equal(t, org.ID, e.OwnerID)
	assert.Equal(t, group.ID, e.GroupID)
	assert.Equal(t, "project", e.TargetType)

	repo, err := repo_service.CreateRepository(ctx, user2, org, repo_service.CreateRepoOptions{Name: "audit-moved"})
	require.NoError(t, err)
	since = auditMaxID(t)
	require.NoError(t, repo_service.MoveRepository(ctx, user2, repo, group.ID))
	e = repoOne(t, since, "repo.repository.moved", repo)
	assert.Equal(t, group.ID, e.GroupID)
	data := auditData(t, e)
	assert.Equal(t, map[string]any{"group_id": float64(0), "group_name": ""}, data["before"])
	assert.Equal(t, map[string]any{"group_id": float64(group.ID), "group_name": "audit-project"}, data["after"])

	since = auditMaxID(t)
	require.NoError(t, repo_service.RenameRepoGroup(ctx, org, group, "audit-project-2"))
	assert.Equal(t, map[string]any{"name": "audit-project-2"}, auditData(t, orgOne(t, since, "org.project.renamed"))["after"])

	require.NoError(t, repo_service.MoveRepository(ctx, user2, repo, 0))
	since = auditMaxID(t)
	require.NoError(t, repo_service.DeleteRepoGroup(ctx, org, group))
	counts := auditData(t, orgOne(t, since, "org.project.deleted"))["counts"].(map[string]any)
	assert.Contains(t, counts, "teams")
	assert.Contains(t, counts, "branch_rules")
}

func TestAuditRepoSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	repo := loadRepo(t, "user2", "repo1")
	edit := func(opt api.EditRepoOption) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &opt).AddTokenAuth(token), http.StatusOK)
	}
	updated := func(since int64) map[string]any {
		t.Helper()
		return auditData(t, repoOne(t, since, "repo.repository.updated", repo))
	}

	// visibility and template: before/after of what changed, nothing for an unchanged save
	since := auditMaxID(t)
	edit(api.EditRepoOption{Private: new(true), Template: new(true)})
	data := updated(since)
	assert.Equal(t, map[string]any{"is_private": false, "is_template": false}, data["before"])
	assert.Equal(t, map[string]any{"is_private": true, "is_template": true}, data["after"])
	since = auditMaxID(t)
	edit(api.EditRepoOption{Private: new(true), Description: new("only text")})
	assert.Empty(t, auditActions(t, since, "repo.repository.updated"))

	// default branch, on the API and the web
	since = auditMaxID(t)
	edit(api.EditRepoOption{DefaultBranch: new("branch2")})
	assert.Equal(t, map[string]any{"default_branch": "branch2"}, updated(since)["after"])
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches", map[string]string{"action": "default_branch", "branch": "master"}), http.StatusSeeOther)
	assert.Equal(t, map[string]any{"default_branch": "master"}, updated(since)["after"])

	// visibility on the web
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{"action": "update", "repo_name": "repo1", "private": "false", "template": "true"}), http.StatusSeeOther)
	assert.Equal(t, map[string]any{"is_private": false}, updated(since)["after"])

	// units on/off
	since = auditMaxID(t)
	edit(api.EditRepoOption{HasWiki: new(false)})
	data = auditData(t, repoOne(t, since, "repo.units.changed", repo))
	assert.Contains(t, data["before"].(map[string]any)["units"], "wiki")
	assert.NotContains(t, data["after"].(map[string]any)["units"], "wiki")
	since = auditMaxID(t)
	edit(api.EditRepoOption{HasWiki: new(false)})
	assert.Empty(t, auditActions(t, since, "repo.units.changed"))

	// archive and unarchive
	since = auditMaxID(t)
	edit(api.EditRepoOption{Archived: new(true)})
	repoOne(t, since, "repo.repository.archived", repo)
	edit(api.EditRepoOption{Archived: new(true)})
	edit(api.EditRepoOption{Archived: new(false)})
	repoOne(t, since, "repo.repository.unarchived", repo)
	repoOne(t, since, "repo.repository.archived", repo)
}

// The repo.private push option records the pusher, and writes only the two columns of the row as it is now.
func TestAuditRepoPushOption(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-push"}).AddTokenAuth(token), http.StatusCreated)
		repo := loadRepo(t, "user2", "audit-push")
		// renamed after the push started: the hook must not write the old name back
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/audit-push", &api.EditRepoOption{Name: new("audit-push-2")}).AddTokenAuth(token), http.StatusOK)

		since := auditMaxID(t)
		_, extra := private.HookPostReceive(t.Context(), repo.ID, private.HookOptions{UserID: 2, GitPushOptions: map[string]string{"repo.private": "true"}})
		require.NoError(t, extra.Error)
		e := repoOne(t, since, "repo.repository.updated", repo)
		assert.Equal(t, audit_model.ActorUser, e.ActorType)
		assert.EqualValues(t, 2, e.ActorID)
		assert.Equal(t, "user2", e.ActorName)
		assert.Equal(t, map[string]any{"is_private": true}, auditData(t, e)["after"])
		got := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		assert.True(t, got.IsPrivate)
		assert.Equal(t, "audit-push-2", got.Name)
		assert.EqualValues(t, 2, got.OwnerID)
	})
}

func TestAuditRepoMirror(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer allowLocalImport(t)()
	upstream := newFilterUpstream(t)

	since := auditMaxID(t)
	repo := newFilterMirror(t, "audit-mirror", upstream, "", "")
	assert.Empty(t, auditActions(t, since, "repo.mirror.updated"), "creating a mirror records no settings change")

	// the settings on the web: one entry, nothing for the unchanged address
	session := loginUser(t, "user2")
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/audit-mirror/settings", map[string]string{
		"action": "mirror", "interval": "9h", "enable_prune": "on", "mirror_address": upstream.bare, "mirror_branch_filter": "main",
	}), http.StatusSeeOther)
	data := auditData(t, repoOne(t, since, "repo.mirror.updated", repo))
	assert.Equal(t, map[string]any{"interval": "9h0m0s", "branch_filter": "main"}, data["after"])

	// the address: origins only, and whether the URL or the credentials changed
	ctx := asActor(t, 2, "user2")
	m, err := repo_model.GetMirrorByRepoID(ctx, repo.ID)
	require.NoError(t, err)
	since = auditMaxID(t)
	require.NoError(t, mirror_service.SaveRemoteAddress(ctx, m, "https://alice:s3cr3t-pass@mirror.example.com:8443/team/x.git?token=t0ken"))
	e := repoOne(t, since, "repo.mirror.updated", repo)
	data = auditData(t, e)
	assert.Equal(t, map[string]any{"address": "https://mirror.example.com:8443"}, data["after"])
	assert.Equal(t, true, data["url_changed"])
	assert.Equal(t, true, data["credentials_changed"])
	since = auditMaxID(t)
	require.NoError(t, mirror_service.SaveRemoteAddress(ctx, m, "https://alice:other-pass@mirror.example.com:8443/team/x.git?token=t0ken"))
	data = auditData(t, repoOne(t, since, "repo.mirror.updated", repo))
	assert.Equal(t, false, data["url_changed"])
	assert.Equal(t, true, data["credentials_changed"])
	since = auditMaxID(t)
	require.NoError(t, mirror_service.SaveRemoteAddress(ctx, m, "https://alice:other-pass@mirror.example.com:8443/team/x.git?token=t0ken"))
	assert.Empty(t, auditActions(t, since, "repo.mirror.updated"))
	// no column of any mirror entry holds the user, a password, the query or the path
	for _, e := range auditActions(t, 0, "repo.mirror.updated") {
		row, err := json.Marshal(e)
		require.NoError(t, err)
		for _, secret := range []string{"alice", "s3cr3t-pass", "other-pass", "t0ken", "/team/"} {
			assert.NotContains(t, string(row), secret)
		}
	}

	// LFS endpoint: its origin only
	m.LFSEndpoint = "https://lfs.example.com/path/x"
	since = auditMaxID(t)
	require.NoError(t, repo_model.UpdateMirrorSettings(ctx, m, "lfs_endpoint"))
	assert.Equal(t, map[string]any{"lfs_endpoint": "https://lfs.example.com"}, auditData(t, repoOne(t, since, "repo.mirror.updated", repo))["after"])
}

// The default branch a mirror's first sync sets is recorded with the system actor of the sync.
func TestAuditRepoMirrorSyncActor(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer allowLocalImport(t)()
	root := t.TempDir()
	bare, work := root+"/upstream.git", root+"/work"
	gitIn(t, root, "init", "-q", "--bare", "-b", "main", bare)
	repo := newFilterMirror(t, "audit-empty-mirror", &filterUpstream{bare: bare}, "", "")
	require.True(t, repo.IsEmpty)

	gitIn(t, root, "clone", "-q", bare, work)
	gitIn(t, work, "checkout", "-q", "-b", "dev")
	gitIn(t, work, "commit", "-q", "--allow-empty", "-m", "first")
	gitIn(t, work, "push", "-q", "origin", "dev")

	since := auditMaxID(t)
	require.True(t, mirror_service.SyncPullMirror(audit_model.WithSystem(t.Context(), fmt.Sprintf("mirror:%d", repo.ID)), repo.ID))
	e := repoOne(t, since, "repo.repository.updated", repo)
	assert.Equal(t, audit_model.ActorSystem, e.ActorType)
	assert.Equal(t, fmt.Sprintf("mirror:%d", repo.ID), e.ActorName)
	assert.Equal(t, map[string]any{"default_branch": "dev"}, auditData(t, e)["after"])
}

func TestAuditRepoBranchesTags(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	repo := loadRepo(t, "user2", "repo1")
	newBranch := func(name string) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", &api.CreateBranchRepoOption{BranchName: name, OldRefName: "master"}).AddTokenAuth(token), http.StatusCreated)
	}

	// branch renamed and deleted on the API, deleted on the web
	newBranch("audit-a")
	since := auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branches/audit-a", &api.UpdateBranchRepoOption{Name: "audit-b"}).AddTokenAuth(token), http.StatusNoContent)
	e := repoOne(t, since, "repo.branch.renamed", repo)
	assert.Equal(t, "branch", e.TargetType)
	assert.Equal(t, "audit-b", e.TargetName)
	assert.Equal(t, map[string]any{"from": "audit-a", "to": "audit-b", "default": false}, auditData(t, e))
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/audit-b").AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, "audit-b", auditData(t, repoOne(t, since, "repo.branch.deleted", repo))["name"])
	newBranch("audit-c")
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "POST", "/user2/repo1/branches/delete?name=audit-c"), http.StatusOK)
	assert.Equal(t, "audit-c", repoOne(t, since, "repo.branch.deleted", repo).TargetName)

	// tag created and deleted on the API, created and deleted on the web
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/tags", &api.CreateTagOption{TagName: "audit-t1", Target: "master"}).AddTokenAuth(token), http.StatusCreated)
	e = repoOne(t, since, "repo.tag.created", repo)
	assert.Equal(t, "tag", e.TargetType)
	assert.Equal(t, "audit-t1", e.TargetName)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/tags/audit-t1").AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, "audit-t1", repoOne(t, since, "repo.tag.deleted", repo).TargetName)

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/_new/branch/master", map[string]string{"new_branch_name": "audit-t2", "create_tag": "true"}), http.StatusSeeOther)
	repoOne(t, since, "repo.tag.created", repo)
	rel := unittest.AssertExistsAndLoadBean(t, &repo_model.Release{RepoID: repo.ID, TagName: "audit-t2"})
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/user2/repo1/tags/delete?id=%d", rel.ID)), http.StatusOK)
	repoOne(t, since, "repo.tag.deleted", repo)
}

// A branch deleted after its pull request is merged is recorded once.
func TestAuditRepoBranchDeletedAfterMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		session := loginUser(t, "user2")
		testEditFileToNewBranch(t, session, "user2", "repo1", "master", "audit-merged", "README.md", "Hello, World\n(audit)\n")
		resp := testPullCreate(t, session, "user2", "repo1", true, "master", "audit-merged", "Audit merge")
		elem := strings.Split(test.RedirectURL(resp), "/")
		since := auditMaxID(t)
		testPullMerge(t, session, elem[1], elem[2], elem[4], repo_model.MergeStyleMerge, true)
		e := repoOne(t, since, "repo.branch.deleted", loadRepo(t, "user2", "repo1"))
		assert.Equal(t, "audit-merged", e.TargetName)
		assert.EqualValues(t, 2, e.ActorID)
	})
}

func TestAuditRepoCollaborators(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	repo := loadRepo(t, "user2", "repo1")
	put := func(permission string) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user4", &api.AddCollaboratorOption{Permission: &permission}).AddTokenAuth(token), http.StatusNoContent)
	}

	// API: added at the requested mode, a downgrade of an existing one, nothing for the same mode again
	since := auditMaxID(t)
	put("admin")
	e := repoOne(t, since, "repo.collaborator.added", repo)
	assert.Equal(t, "collaborator", e.TargetType)
	assert.EqualValues(t, 4, e.TargetID)
	assert.Equal(t, "user4", e.TargetName)
	assert.Equal(t, "admin", auditData(t, e)["mode"])
	assert.Empty(t, auditActions(t, since, "repo.collaborator.mode_changed"))
	since = auditMaxID(t)
	put("read")
	data := auditData(t, repoOne(t, since, "repo.collaborator.mode_changed", repo))
	assert.Equal(t, map[string]any{"mode": "admin"}, data["before"])
	assert.Equal(t, map[string]any{"mode": "read"}, data["after"])
	unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: 4, Mode: perm.AccessModeRead})
	since = auditMaxID(t)
	put("read")
	assert.Empty(t, auditActions(t, since, "repo.collaborator.mode_changed"))
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/collaborators/user4").AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.collaborator.removed", repo)

	// web
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration", map[string]string{"collaborator": "user5"}), http.StatusSeeOther)
	assert.Equal(t, "write", auditData(t, repoOne(t, since, "repo.collaborator.added", repo))["mode"])
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration/access_mode", map[string]string{"uid": "5", "mode": "3"}), http.StatusOK)
	assert.Equal(t, map[string]any{"mode": "admin"}, auditData(t, repoOne(t, since, "repo.collaborator.mode_changed", repo))["after"])
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration/delete", map[string]string{"id": "5"}), http.StatusOK)
	repoOne(t, since, "repo.collaborator.removed", repo)

	// blocking a collaborator removes them
	put("write")
	since = auditMaxID(t)
	require.NoError(t, user_service.BlockUser(asActor(t, 2, "user2"), 2, 4))
	e = repoOne(t, since, "repo.collaborator.removed", repo)
	assert.Equal(t, "blocked", auditData(t, e)["reason"])
	assert.EqualValues(t, 4, e.TargetID)
}

// A failed audit insert fails the change and leaves the rows as they were.
func TestAuditRepoFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	defer test.MockVariableValue(&audit_model.InsertEntry, func(ctx context.Context, e *audit_model.Entry) error {
		if strings.HasPrefix(e.Action, "repo.") {
			return errors.New("audit insert failed")
		}
		return db.Insert(ctx, e)
	})()

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-fail"}).AddTokenAuth(token), http.StatusInternalServerError)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 2, LowerName: "audit-fail"})

	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &api.EditRepoOption{Private: new(true)}).AddTokenAuth(token), http.StatusInternalServerError)
	assert.False(t, loadRepo(t, "user2", "repo1").IsPrivate)

	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user4", &api.AddCollaboratorOption{}).AddTokenAuth(token), http.StatusInternalServerError)
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 4})

	defer test.MockVariableValue(&setting.Trash.RetentionDays, 0)()
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1").AddTokenAuth(token), http.StatusInternalServerError)
	loadRepo(t, "user2", "repo1")
}
