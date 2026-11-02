// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"forgejo.org/models"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/migration"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/auth/source"
	"forgejo.org/services/automerge"
	"forgejo.org/services/forms"
	"forgejo.org/services/mailer/incoming"
	incoming_payload "forgejo.org/services/mailer/incoming/payload"
	mirror_service "forgejo.org/services/mirror"
	org_service "forgejo.org/services/org"
	pull_service "forgejo.org/services/pull"
	release_service "forgejo.org/services/release"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/services/usergroup"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// S1: push-to-create and fork into an archived org are refused; the same push works once it is unarchived.
func TestOrgArchiveCreateSinks(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateOrg, true)()
		archiveOrg3(t, false)

		tmpDir := t.TempDir()
		pushURL := *u
		pushURL.Path = "/org3/push-create-archived.git"
		pushURL.User = url.UserPassword("user2", userPassword)
		t.Run("InitTestRepository", doGitInitTestRepository(tmpDir, git.Sha1ObjectFormat))
		t.Run("AddRemote", doGitAddRemote(tmpDir, "origin", &pushURL))
		doGitPushTestRepositoryFail(t, tmpDir, "origin", "master")
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 3, Name: "push-create-archived"})

		token := orgArchiveToken(t, "user2")
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{Organization: new("org3")}).AddTokenAuth(token), http.StatusForbidden)
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 3, ForkID: 1})

		// control: the same push creates the repository once the organization is unarchived
		require.NoError(t, org_service.UnarchiveOrganization(t.Context(), organization.OrgFromUser(archivedOrg(t))))
		t.Run("PushCreate", doGitPushTestRepository(tmpDir, "origin", "master"))
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 3, Name: "push-create-archived"})
	})
}

// S7: a transfer started before the archive cannot be accepted after it.
func TestOrgArchivePendingTransfer(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // user2/repo1
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	require.NoError(t, models.CreatePendingRepositoryTransfer(t.Context(), user2, org3, repo.ID, nil))
	archiveOrg3(t, false)

	token := orgArchiveToken(t, "user2")
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/repo1/transfer/accept").AddTokenAuth(token), http.StatusForbidden)
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/action/accept_transfer", nil), http.StatusForbidden)
	unchanged, err := repo_model.GetRepositoryByID(t.Context(), 1)
	require.NoError(t, err)
	assert.EqualValues(t, 2, unchanged.OwnerID)
}

// S5: no LFS upload into an archived repository.
func TestOrgArchiveLFSUpload(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	setting.LFS.StartServer = true
	repo := createLFSTestRepository(t, "archived")

	upload := func(status int) {
		req := NewRequestWithJSON(t, "POST", "/user2/lfs-archived-repo.git/info/lfs/objects/batch", &lfs.BatchRequest{
			Operation: "upload",
			Objects:   []lfs.Pointer{{Oid: "0000000000000000000000000000000000000000000000000000000000000001", Size: 1}},
		}).SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType)
		req.AddBasicAuth("user2")
		MakeRequest(t, req, status)
	}
	upload(http.StatusOK)
	require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), repo, true))
	upload(http.StatusUnauthorized)
}

// S4: an email reply to an issue of an archived repository is dropped.
func TestOrgArchiveEmailReply(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	payload, err := incoming_payload.CreateReferencePayload(issue)
	require.NoError(t, err)

	reply := func() int {
		require.NoError(t, (&incoming.ReplyHandler{}).Handle(t.Context(), &incoming.MailContent{Content: "a reply"}, doer, payload))
		return unittest.GetCount(t, &issues_model.Comment{IssueID: issue.ID})
	}
	before := unittest.GetCount(t, &issues_model.Comment{IssueID: issue.ID})
	assert.Equal(t, before+1, reply()) // control: replies work while the repository is active

	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: issue.RepoID})
	require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), repo, true))
	assert.Equal(t, before+1, reply())
}

// S3b: the head branch of a pull request cannot be updated when its repositories are archived.
func TestOrgArchivePullUpdate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), pr.BaseRepo, true))
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	err := pull_service.Update(t.Context(), pr, doer, "msg", false)
	require.Error(t, err)
	require.ErrorAs(t, err, &repo_model.ErrRepoIsArchived{})

	mergeAllowed, rebaseAllowed, err := pull_service.IsUserAllowedToUpdate(t.Context(), pr, doer, access_model.Permission{}, access_model.Permission{})
	require.NoError(t, err)
	assert.False(t, mergeAllowed)
	assert.False(t, rebaseAllowed)
}

// S3a: a scheduled automerge waits while the repository is archived and runs once it is active again.
func TestOrgArchiveAutoMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		reviewer := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, nil, &forgery.CreateRepositoryOptions{
			Files:         forgery.FilesInit{},
			Collaborators: map[*user_model.User]perm.AccessMode{reviewer: perm.AccessModeWrite},
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		owner := repo.Owner
		session := loginUser(t, owner.Name)
		reviewerSession := loginUser(t, reviewer.Name)
		apiCtx := NewAPITestContext(t, owner.Name, repo.Name, auth_model.AccessTokenScopeWriteRepository)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/settings/branches/edit", repo.FullName()), map[string]string{
			"rule_name": "main", "required_approvals": "1", "block_on_rejected_reviews": "true",
		}), http.StatusSeeOther)
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()

		now := time.Now()
		defer timeutil.MockUnset()
		timeutil.MockSet(now)

		testEditFileToNewBranch(t, session, owner.Name, repo.Name, "main", "archived-merge", "README.md", "archived-merge")
		testPullCreate(t, session, owner.Name, repo.Name, true, "main", "archived-merge", "archived-merge")
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: "archived-merge"})
		sha, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
		require.NoError(t, err)
		testSubmitReview(t, reviewerSession, owner.Name, repo.Name, strconv.FormatInt(pr.Index, 10), sha, "approve", http.StatusOK)
		apiCtx.ExpectedCode = http.StatusCreated
		doAPIMergePullRequestForm(t, apiCtx, owner.Name, repo.Name, pr.Index, &forms.MergePullRequestForm{
			Do: "merge", MergeWhenChecksSucceed: true, ScheduledAfter: now.Add(time.Hour).Format(time.RFC3339),
		})
		isMerged := func() bool {
			return unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged
		}
		unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})

		dbRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), dbRepo, true))
		timeutil.MockSet(now.Add(2 * time.Hour))
		require.NoError(t, automerge.StartDueScheduledAutoMerges(t.Context()))
		assert.False(t, isMerged())

		// the due merge stays scheduled, and goes through at the next check once the repository is active
		require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), dbRepo, false))
		automerge.StartPRCheckAndAutoMerge(t.Context(), pr)
		assert.True(t, isMerged())
	})
}

// S6: group syncs add nothing to an archived org, still remove, and the adds apply after unarchive.
func TestOrgArchiveGroupSync(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}) // org3 team1
	inTeam := func(uid int64) bool {
		is, err := organization.IsTeamMember(t.Context(), 3, team.ID, uid)
		require.NoError(t, err)
		return is
	}
	stay := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
	leaver := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 11})
	newcomer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 12})
	require.False(t, inTeam(10) || inTeam(11) || inTeam(12))

	group := &organization.UserGroup{Name: "archive-sync", LowerName: "archive-sync"}
	require.NoError(t, usergroup.CreateGroup(t.Context(), group))
	require.NoError(t, usergroup.LinkTeam(t.Context(), group, team))
	require.NoError(t, usergroup.AddMember(t.Context(), group, leaver))
	require.True(t, inTeam(leaver.ID))

	// source (LDAP/OAuth) mapping: a member added before the archive
	mapping := map[string]map[string][]string{"devs": {"org3": {"team1"}}}
	loginSource := createRemoteAuthSource(t, "archive-sync-source", "https://example.com", "")
	sync := func(user *user_model.User, groups container.Set[string]) {
		require.NoError(t, source.SyncGroupsToTeams(t.Context(), user, loginSource.ID, groups, mapping, true, nil, false))
	}
	sync(stay, container.SetOf("devs"))
	require.True(t, inTeam(stay.ID))

	archiveOrg3(t, false)

	// adds are skipped while archived
	require.NoError(t, usergroup.AddMember(t.Context(), group, newcomer))
	assert.False(t, inTeam(newcomer.ID))
	// removals still apply: group removal and source-mapping removal
	require.NoError(t, usergroup.RemoveMember(t.Context(), group, leaver.ID))
	assert.False(t, inTeam(leaver.ID))
	sync(stay, container.SetOf[string]())
	assert.False(t, inTeam(stay.ID))

	// the skipped add applies after unarchive
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/unarchive", nil), http.StatusSeeOther)
	assert.True(t, inTeam(newcomer.ID))
}

// S6 (b)+(c): the Owners team reached through the org-admin role follows the same rules, and removing the
// last owner stays refused for sync removals.
func TestOrgArchiveGroupSyncOwners(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	owners := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1}) // org3 Owners
	inOwners := func(uid int64) bool {
		is, err := organization.IsTeamMember(t.Context(), 3, owners.ID, uid)
		require.NoError(t, err)
		return is
	}
	stay := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
	newcomer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 11})

	group := &organization.UserGroup{Name: "archive-admins", LowerName: "archive-admins", GrantsOrgAdmin: true}
	require.NoError(t, usergroup.CreateGroup(t.Context(), group))
	require.NoError(t, usergroup.AddMember(t.Context(), group, stay))
	require.True(t, inOwners(stay.ID))

	archiveOrg3(t, false)
	require.NoError(t, usergroup.AddMember(t.Context(), group, newcomer))
	assert.False(t, inOwners(newcomer.ID)) // the add is skipped
	require.NoError(t, usergroup.RemoveMember(t.Context(), group, stay.ID))
	assert.False(t, inOwners(stay.ID)) // the removal is applied

	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/unarchive", nil), http.StatusSeeOther)
	assert.True(t, inOwners(newcomer.ID)) // the skipped add arrives

	t.Run("last owner", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		// make user2 the only owner, and an owner only because of a user group
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM team_user WHERE team_id = 1 AND uid <> 2")
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE team SET num_members = 1 WHERE id = 1")
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE team_user SET reason = ? WHERE team_id = 1 AND uid = 2", organization.MembershipReasonAddedByUserGroup)
		require.NoError(t, err)
		sole := &organization.UserGroup{Name: "archive-sole", LowerName: "archive-sole"}
		require.NoError(t, organization.InsertUserGroup(t.Context(), sole))
		require.NoError(t, organization.InsertUserGroupMember(t.Context(), sole.ID, 2, 0))
		require.NoError(t, organization.InsertUserGroupTeam(t.Context(), sole.ID, owners, organization.LinkManual))

		archiveOrg3(t, false)
		err = usergroup.RemoveMember(t.Context(), sole, 2)
		require.Error(t, err)
		assert.True(t, organization.IsErrLastOrgOwner(err), "%v", err)
		assert.True(t, inOwners(2))

		// the same for a login-source mapping removal
		_, err = db.GetEngine(t.Context()).Exec("UPDATE team_user SET reason = ? WHERE team_id = 1 AND uid = 2", organization.MembershipReasonAddedByAuthProvider)
		require.NoError(t, err)
		loginSource := createRemoteAuthSource(t, "archive-owner-source", "https://example.com", "")
		err = source.SyncGroupsToTeams(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), loginSource.ID, container.SetOf[string](),
			map[string]map[string][]string{"admins": {"org3": {"Owners"}}}, true, nil, false)
		require.Error(t, err)
		assert.True(t, inOwners(2))
	})
}

// AC4: pull-mirror sync is skipped for an archived repository.
func TestOrgArchiveMirrorSync(t *testing.T) {
	defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	_, err := db.GetEngine(t.Context()).ID(user.ID).SetExpr("allow_import_local", true).Update(user)
	require.NoError(t, err)

	mirrorRepo, err := repo_service.CreateRepositoryDirectly(t.Context(), user, user, repo_service.CreateRepoOptions{
		Name: "archived_mirror", IsMirror: true, Status: repo_model.RepositoryBeingMigrated,
	})
	require.NoError(t, err)
	mirrorRepo, err = repo_service.MigrateRepositoryGitData(t.Context(), user, mirrorRepo, migration.MigrateOptions{
		RepoName: "archived_mirror", Mirror: true, CloneAddr: repo_model.RepoPath(user.Name, source.Name),
	}, nil)
	require.NoError(t, err)

	gitRepo, err := gitrepo.OpenRepository(t.Context(), source)
	require.NoError(t, err)
	defer gitRepo.Close()
	require.NoError(t, release_service.CreateRelease(gitRepo, &repo_model.Release{
		RepoID: source.ID, Repo: source, PublisherID: user.ID, Publisher: user,
		TagName: "v0.2", Target: "master", Title: "t", Note: "n", IsTag: true,
	}, "", []*release_service.AttachmentChange{}))
	tags := func() int64 {
		n, err := db.Count[repo_model.Release](t.Context(), repo_model.FindReleasesOptions{IncludeDrafts: true, IncludeTags: true, RepoID: mirrorRepo.ID})
		require.NoError(t, err)
		return n
	}
	before := tags()

	require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), mirrorRepo, true))
	assert.False(t, mirror_service.SyncPullMirror(t.Context(), mirrorRepo.ID))
	assert.Equal(t, before, tags())

	require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), mirrorRepo, false))
	assert.True(t, mirror_service.SyncPullMirror(t.Context(), mirrorRepo.ID))
	assert.Equal(t, before+1, tags())
}

// AC6 + AC4: a reader can still clone an archived org's repository over HTTP; a push is refused.
func TestOrgArchiveGitHTTP(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		archiveOrg3(t, false)
		cloneURL := *u
		cloneURL.Path = "/org3/repo3.git"
		cloneURL.User = url.UserPassword("user2", userPassword)

		dst := t.TempDir()
		require.NoError(t, git.CloneWithArgs(t.Context(), git.AllowLFSFiltersArgs(), cloneURL.String(), dst, git.CloneRepoOptions{}))
		doGitSetRemoteURL(dst, "origin", &cloneURL)(t)
		doGitAddSomeCommits(dst, "master")(t)
		doGitPushTestRepositoryFail(t, dst, "origin", "master")
	})
}
