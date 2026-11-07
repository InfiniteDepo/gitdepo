// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bnDeployKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4cn+iXnA4KvcQYSV88vGn0Yi91vG47t1P7okprVmhNTkipNRIHWr6WdCO4VDr/cvsRkuVJAsLO2enwjGWWueOO6BodiBgyAOZ/5t5nJNMCNuLGT5UIo/RI1b0WRQwxEZTRjt6mFNw6lH14wRd8ulsr9toSWBPMOGWoYs1PDeDL0JuTjL+tr1SZi/EyxCngpYszKdXllJEHyI79KQgeD0Vt3pTrkbNVTOEcCNqZePSVmUH8X8Vhugz3bnE0/iE9Pb5fkWO9c4AnM1FgI/8Bvp27Fw2ShryIXuR6kKvUqhVMTuOSDHwu6A8jLE5Owt3GAYugDpDYuwTVNGrHLXKpPzrGGPE/jPmaLCMZcsdkec95dYeU3zKODEm8UQZFhmJmDeWVJ36nGrGZHL4J5aTTaeFUJmmXDaJYiJ+K2/ioKgXqnXvltu0A9R8/LGy4nrTJRr4JMLuJFoUXvGm1gXQ70w2LSpk6yl71RNC0hCtsBe8BP8IhYCM0EP5jh7eCMQZNvM= nocomment\n"

func bnManyPatterns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("p%d/*", i)
	}
	return out
}

func bnTypes() []api.BranchType {
	return []api.BranchType{
		{Name: "Feature", Prefix: "feature/", Base: "development"},
		{Name: "Bugfix", Prefix: "bugfix/", Base: "development"},
	}
}

func bnOptions(n api.BranchNaming) *api.EditRepoBranchingModelOption {
	return &api.EditRepoBranchingModelOption{DevelopmentBranch: "master", ReleasePrefixes: []string{"release/"}, Types: bnTypes(), BranchNaming: n}
}

// bnCollaborator gives a user write access to a repository of org3.
func bnCollaborator(t *testing.T, ctx APITestContext, repo, user string) {
	t.Helper()
	req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/collaborators/"+user, &api.AddCollaboratorOption{Permission: new("write")}).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(t, req, http.StatusNoContent)
}

func bnCreate(t *testing.T, user, repo, name string, status int) *bnResponse {
	t.Helper()
	token := getUserToken(t, user, auth_model.AccessTokenScopeWriteRepository)
	req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/branches", &api.CreateBranchRepoOption{BranchName: name, OldBranchName: "master"}).AddTokenAuth(token)
	return &bnResponse{MakeRequest(t, req, status).Body.String()}
}

type bnResponse struct{ Body string }

func bnRename(t *testing.T, user, repo, from, to string, status int) string {
	t.Helper()
	token := getUserToken(t, user, auth_model.AccessTokenScopeWriteRepository)
	req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+repo+"/branches/"+from, &api.UpdateBranchRepoOption{Name: to}).AddTokenAuth(token)
	return MakeRequest(t, req, status).Body.String()
}

func bnExists(t *testing.T, repoID int64, name string) bool {
	t.Helper()
	ok, err := db.GetEngine(t.Context()).Where("repo_id = ? AND name = ? AND is_deleted = ?", repoID, name, false).Exist(new(git_model.Branch))
	require.NoError(t, err)
	return ok
}

// R7: the settings of "require a branch type" are saved by owners and admins only, validated as a whole, and
// recorded in the audit log together with their lists.
func TestBranchNamingSettings(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bn-settings")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		bnCollaborator(t, ctx, repo, "user5")
		get := func() *api.RepoBranchingModel { return bmRepoAPI(t, ctx, "org3", repo) }

		t.Run("refused values change nothing", func(t *testing.T) {
			// no type, no release prefix, no exception: nothing could be created
			btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{BranchNaming: api.BranchNaming{RequireBranchType: true}}, http.StatusUnprocessableEntity)
			// the same for a type that is off
			off := bnOptions(api.BranchNaming{RequireBranchType: true})
			off.ReleasePrefixes = nil
			for i := range off.Types {
				off.Types[i].Off = true
			}
			btModel(t, ctx, repo, off, http.StatusUnprocessableEntity)
			for _, n := range []api.BranchNaming{
				{Exceptions: []string{"[a-"}},
				{Exceptions: []string{"has\nnewline"}},
				{Exceptions: bnManyPatterns(21)},
				{ExemptUsers: []string{"no-such-user"}},
				{ExemptTeams: []string{"no-such-team"}},
			} {
				btModel(t, ctx, repo, bnOptions(n), http.StatusUnprocessableEntity)
			}
			assert.True(t, get().Inherit, "nothing was stored")
		})

		t.Run("owner saves and the audit entry holds the lists", func(t *testing.T) {
			since := auditMaxID(t)
			btModel(t, ctx, repo, bnOptions(api.BranchNaming{
				RequireBranchType: true, Exceptions: []string{"renovate/**", "gh-pages"}, ExemptUsers: []string{"user4"}, ExemptTeams: []string{"test_team"},
			}), http.StatusOK)
			got := get()
			assert.Equal(t, api.BranchNaming{RequireBranchType: true, Exceptions: []string{"renovate/**", "gh-pages"}, ExemptUsers: []string{"user4"}, ExemptTeams: []string{"test_team"}}, got.Effective.BranchNaming)
			after, _ := auditData(t, auditOne(t, since, "repo.branch_workflow.changed"))["after"].(map[string]any)
			assert.Equal(t, true, after["require_branch_type"])
			assert.Equal(t, []any{"renovate/**", "gh-pages"}, after["branch_exceptions"])
			assert.Len(t, after["exempt_user_ids"], 1)
			assert.Len(t, after["exempt_team_ids"], 1)
		})

		t.Run("a writer is refused", func(t *testing.T) {
			token := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", bnOptions(api.BranchNaming{})).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusForbidden)
			assert.True(t, get().Effective.BranchNaming.RequireBranchType)
		})

		t.Run("the web form", func(t *testing.T) {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/settings/branch_workflow/branching_model", map[string]string{
				"development_branch": "master", "release_prefixes": "release/", "type_name": "Feature", "type_prefix": "feature/", "type_base": "development", "type_on": "0",
				"require_branch_type": "on", "branch_exceptions": "hotfix/*\nlegacy", "exempt_users": "user4", "exempt_teams": "no-such-team",
			}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "no-such-team")
			assert.Equal(t, []string{"renovate/**", "gh-pages"}, get().Effective.BranchNaming.Exceptions, "a refused form stores nothing")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/settings/branch_workflow/branching_model", map[string]string{
				"development_branch": "master", "release_prefixes": "release/", "type_name": "Feature", "type_prefix": "feature/", "type_base": "development", "type_on": "0",
				"require_branch_type": "on", "branch_exceptions": "hotfix/*\nlegacy", "exempt_users": "user4",
			}), http.StatusSeeOther)
			assert.Equal(t, api.BranchNaming{RequireBranchType: true, Exceptions: []string{"hotfix/*", "legacy"}, ExemptUsers: []string{"user4"}, ExemptTeams: []string{}}, get().Effective.BranchNaming)
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo+"/settings/branch_workflow"), http.StatusOK).Body)
			assert.True(t, doc.doc.Find(`input[name="require_branch_type"]`).Is("[checked]"))
			assert.Equal(t, "hotfix/*\nlegacy", doc.doc.Find(`textarea[name="branch_exceptions"]`).Text())
		})

		t.Run("an organization lock counts only the organization's lists", func(t *testing.T) {
			btModel(t, ctx, repo, bnOptions(api.BranchNaming{RequireBranchType: true, ExemptUsers: []string{"user4"}}), http.StatusOK)
			btOrgModel(t, ctx, &api.OrgBranchingModel{
				ReleasePrefixes: []string{"release/"}, Types: bnTypes(), Enforce: true,
				BranchNaming: api.BranchNaming{RequireBranchType: true, Exceptions: []string{"org-x"}, ExemptUsers: []string{"user15"}},
			}, http.StatusOK)
			defer btOrgModel(t, ctx, &api.OrgBranchingModel{}, http.StatusOK)
			got := get()
			assert.True(t, got.Locked)
			assert.Equal(t, api.BranchNaming{RequireBranchType: true, Exceptions: []string{"org-x"}, ExemptUsers: []string{"user15"}, ExemptTeams: []string{}}, got.Effective.BranchNaming)
			bnCreate(t, "user2", repo, "spike/a", http.StatusUnprocessableEntity)
			bnCollaborator(t, ctx, repo, "user4")
			bnCollaborator(t, ctx, repo, "user15")
			bnCreate(t, "user4", repo, "spike/b", http.StatusUnprocessableEntity)
			bnCreate(t, "user15", repo, "spike/c", http.StatusCreated)
			bnCreate(t, "user2", repo, "org-x", http.StatusCreated)
		})
	})
}

// R7: one check on every way to make a branch. Refusals name the allowed prefixes; exempt users and members of
// exempt teams may, leaving an audit entry; nobody else is exempt, a deploy key included.
func TestBranchNamingEnforcement(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bn-enforce")
		ownerSession := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		for _, name := range []string{"user4", "user5", "user15"} {
			bnCollaborator(t, ctx, repo, name)
		}
		repoID := repoIDByName(t, "org3", repo)
		// branches that exist before the rule, and don't match it
		bnCreate(t, "user2", repo, "legacy", http.StatusCreated)
		bnCreate(t, "user2", repo, "legacy-gone", http.StatusCreated)
		btModel(t, ctx, repo, bnOptions(api.BranchNaming{
			RequireBranchType: true, Exceptions: []string{"renovate/**"}, ExemptUsers: []string{"user4"}, ExemptTeams: []string{"test_team"},
		}), http.StatusOK)

		t.Run("api create", func(t *testing.T) {
			body := bnCreate(t, "user5", repo, "spike/x", http.StatusUnprocessableEntity).Body
			assert.Contains(t, body, "spike/x")
			assert.Contains(t, body, "feature/")
			assert.Contains(t, body, "release/")
			assert.False(t, bnExists(t, repoID, "spike/x"))
			bnCreate(t, "user5", repo, "feature/x", http.StatusCreated)
			bnCreate(t, "user5", repo, "renovate/npm/y", http.StatusCreated)
			assert.True(t, bnExists(t, repoID, "feature/x"))
			// an admin and the owner are not exempt either
			bnCreate(t, "user2", repo, "spike/owner", http.StatusUnprocessableEntity)
			// a bare prefix is no type
			bnCreate(t, "user5", repo, "feature/", http.StatusUnprocessableEntity)
		})

		t.Run("web create", func(t *testing.T) {
			s := loginUser(t, "user5")
			s.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/branches/_new/branch/master", map[string]string{"new_branch_name": "spike/web"}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(s), "feature/")
			assert.False(t, bnExists(t, repoID, "spike/web"))
			s.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/branches/_new/branch/master", map[string]string{"new_branch_name": "bugfix/web"}), http.StatusSeeOther)
			assert.True(t, bnExists(t, repoID, "bugfix/web"))
		})

		t.Run("rename", func(t *testing.T) {
			assert.Contains(t, bnRename(t, "user5", repo, "legacy", "spike/renamed", http.StatusUnprocessableEntity), "feature/")
			assert.True(t, bnExists(t, repoID, "legacy"))
			assert.False(t, bnExists(t, repoID, "spike/renamed"))
			s := loginUser(t, "user2") // renaming in the settings needs admin
			s.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/settings/rename_branch", map[string]string{"from": "legacy", "to": "spike/web-renamed"}), http.StatusSeeOther)
			assert.True(t, bnExists(t, repoID, "legacy"), "the web rename is refused too")
			assert.False(t, bnExists(t, repoID, "spike/web-renamed"))
			bnRename(t, "user5", repo, "legacy", "feature/legacy", http.StatusNoContent)
			assert.True(t, bnExists(t, repoID, "feature/legacy"))
			assert.False(t, bnExists(t, repoID, "legacy"))
		})

		t.Run("editor new branch", func(t *testing.T) {
			s := loginUser(t, "user5")
			resp := s.MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo+"/_new/master/"), http.StatusOK)
			last := NewHTMLParser(t, resp.Body).GetInputValueByName("last_commit")
			post := func(branch string) {
				s.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo+"/_new/master/", map[string]string{
					"last_commit": last, "tree_path": "n-" + strings.ReplaceAll(branch, "/", "-") + ".txt", "content": "x",
					"commit_choice": "commit-to-new-branch", "new_branch_name": branch, "commit_mail_id": "-1",
				}), NoExpectedStatus)
			}
			logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.ERROR)
			defer cleanup()
			logChecker.Filter("is refused: new branches") // the file service logs the refused push
			post("spike/editor")
			filtered, _ := logChecker.Check(5 * time.Second)
			assert.Equal(t, []bool{true}, filtered)
			assert.False(t, bnExists(t, repoID, "spike/editor"), "the pre-receive hook refuses the push of the editor")
			post("feature/editor")
			assert.True(t, bnExists(t, repoID, "feature/editor"))
		})

		t.Run("git push", func(t *testing.T) {
			clone := func(user string) (string, *url.URL) {
				c := *u
				c.Path = "/org3/" + repo + ".git"
				c.User = url.UserPassword(user, getUserToken(t, user, auth_model.AccessTokenScopeWriteRepository))
				dir := t.TempDir()
				doGitClone(dir, &c)(t)
				return dir, &c
			}
			dir, _ := clone("user5")
			doGitCreateBranch(dir, "spike/push")(t)
			stderr := doGitPushTestRepositoryFail(t, dir, "origin", "spike/push")
			assert.Contains(t, stderr, "feature/")
			assert.Contains(t, stderr, "release/")
			assert.False(t, bnExists(t, repoID, "spike/push"))
			doGitCreateBranch(dir, "feature/push")(t)
			doGitPushTestRepository(dir, "origin", "feature/push")(t)
			assert.True(t, bnExists(t, repoID, "feature/push"))

			// an existing branch that doesn't match is still pushed to, and deleted
			doGitAddSomeCommits(dir, "legacy-gone")(t)
			doGitPushTestRepository(dir, "origin", "legacy-gone")(t)
			token := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)
			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/"+repo+"/branches/legacy-gone").AddTokenAuth(token), http.StatusNoContent)
			assert.False(t, bnExists(t, repoID, "legacy-gone"))

			// an exempt user pushes anything, and it is recorded
			exemptDir, _ := clone("user4")
			doGitCreateBranch(exemptDir, "spike/exempt")(t)
			since := auditMaxID(t)
			doGitPushTestRepository(exemptDir, "origin", "spike/exempt")(t)
			assert.True(t, bnExists(t, repoID, "spike/exempt"))
			entries := auditActions(t, since, "repo.branch.type_exempt")
			require.Len(t, entries, 1)
			assert.Equal(t, "spike/exempt", entries[0].TargetName)
			assert.EqualValues(t, 4, entries[0].ActorID)
			assert.Equal(t, "push", auditData(t, entries[0])["via"])
			assert.Equal(t, repoID, entries[0].RepoID)
		})

		t.Run("exempt team member and audit", func(t *testing.T) {
			since := auditMaxID(t)
			bnCreate(t, "user15", repo, "spike/team", http.StatusCreated)
			bnCreate(t, "user4", repo, "spike/user", http.StatusCreated)
			entries := auditActions(t, since, "repo.branch.type_exempt")
			require.Len(t, entries, 2)
			assert.Equal(t, []string{"spike/team", "spike/user"}, []string{entries[0].TargetName, entries[1].TargetName})
			assert.EqualValues(t, 15, entries[0].ActorID)

			// an allowed name by an exempt user leaves no exempt entry; a rename by one does
			since = auditMaxID(t)
			bnCreate(t, "user4", repo, "feature/by-exempt", http.StatusCreated)
			assert.Empty(t, auditActions(t, since, "repo.branch.type_exempt"))
			bnRename(t, "user4", repo, "spike/user", "spike/renamed-by-exempt", http.StatusNoContent)
			entries = auditActions(t, since, "repo.branch.type_exempt")
			require.Len(t, entries, 1)
			assert.Equal(t, "spike/renamed-by-exempt", entries[0].TargetName)
			assert.Equal(t, "rename", auditData(t, entries[0])["via"])
		})

		t.Run("hook: no implicit exemption", func(t *testing.T) {
			zero := git.Sha1ObjectFormat.EmptyObjectID().String()
			repoModel := unittestRepo(t, repoID)
			hook := func(branch string, opts private.HookOptions) error {
				opts.OldCommitIDs, opts.NewCommitIDs = []string{zero}, []string{repoModel.head(t)}
				opts.RefFullNames = []git.RefName{git.RefNameFromBranch(branch)}
				return private.HookPreReceive(t.Context(), repoID, opts).Error
			}
			require.NoError(t, hook("spike/hook-user", private.HookOptions{UserID: 4, UserName: "user4"}))
			audit_model.ResetActivity()
			since := auditMaxID(t)
			require.ErrorContains(t, hook("spike/hook-stranger", private.HookOptions{UserID: 5, UserName: "user5"}), "status=403")
			assert.Equal(t, "branch_type", auditData(t, auditActivity(t, since, "activity.git.push.refused"))["reason"])
			require.NoError(t, hook("feature/hook", private.HookOptions{UserID: 5, UserName: "user5"}))
			// an existing branch is never judged by its name
			existing := repoModel.head(t)
			extra := private.HookPreReceive(t.Context(), repoID, private.HookOptions{
				OldCommitIDs: []string{existing}, NewCommitIDs: []string{existing},
				RefFullNames: []git.RefName{git.RefNameFromBranch("legacy-existing")}, UserID: 5, UserName: "user5",
			})
			assert.NotContains(t, fmt.Sprint(extra.Error), "branch_type")

			// a deploy key is not exempt, not even when its owner is
			key := new(api.DeployKey)
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/keys", &api.CreateKeyOption{Title: "bn", Key: bnDeployKey}).AddTokenAuth(ctx.Token)
			DecodeJSON(t, ownerSession.MakeRequest(t, req, http.StatusCreated), key)
			btModel(t, ctx, repo, bnOptions(api.BranchNaming{RequireBranchType: true, ExemptUsers: []string{"user2"}}), http.StatusOK)
			require.NoError(t, hook("spike/hook-owner", private.HookOptions{UserID: 2, UserName: "user2"}))
			require.NoError(t, hook("feature/hook-key", private.HookOptions{UserID: 2, UserName: "user2", DeployKeyKeyID: key.KeyID}), "an allowed name is fine for the key")
			audit_model.ResetActivity()
			since = auditMaxID(t)
			require.ErrorContains(t, hook("spike/hook-key", private.HookOptions{UserID: 2, UserName: "user2", DeployKeyKeyID: key.KeyID}), "status=403")
			assert.Equal(t, "branch_type", auditData(t, auditActivity(t, since, "activity.git.push.refused"))["reason"])
		})
	})
}

type repoHead struct{ id int64 }

func unittestRepo(t *testing.T, id int64) repoHead { return repoHead{id} }

func (r repoHead) head(t *testing.T) string {
	t.Helper()
	b, err := git_model.GetBranch(t.Context(), r.id, "master")
	require.NoError(t, err)
	return b.CommitID
}
