// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// M1: saving Settings > Units keeps the repository's own branching model, so kept branches stay kept.
// M2: the API's legacy default_delete_branch_after_merge is audited like the branch workflow page.
func TestBranchTypesUnitsKeepModelAndAudit(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-units")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, ProductionBranch: "prod"}, http.StatusOK)

		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "settings/units"), map[string]string{
			"enable_code": "on", "enable_pulls": "on", "pulls_allow_merge": "on", "pulls_default_merge_style": "merge",
		}), http.StatusSeeOther)
		var got api.RepoBranchingModel
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &got)
		assert.False(t, got.Inherit)
		require.NotNil(t, got.Own)
		assert.Equal(t, []string{"release/"}, got.Own.ReleasePrefixes)
		assert.Equal(t, "prod", got.Own.ProductionBranch)

		// the same through the API's repository PATCH
		since := auditMaxID(t)
		on := true
		ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+repo, &api.EditRepoOption{DefaultDeleteBranchAfterMerge: &on}).AddTokenAuth(ctx.Token), http.StatusOK)
		data := auditData(t, auditOne(t, since, "repo.branch_workflow.changed"))
		after, _ := data["after"].(map[string]any)
		assert.Equal(t, "default-on", after["mode"])
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &got)
		require.NotNil(t, got.Own)
		assert.Equal(t, "prod", got.Own.ProductionBranch)

		// an unchanged value records nothing
		since = auditMaxID(t)
		ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+repo, &api.EditRepoOption{DefaultDeleteBranchAfterMerge: &on}).AddTokenAuth(ctx.Token), http.StatusOK)
		n, err := db.GetEngine(t.Context()).Table("audit_event").Where("id > ? AND action = ?", since, "repo.branch_workflow.changed").Count()
		require.NoError(t, err)
		assert.Zero(t, n)
	})
}

// L1: a type prefix inside a release prefix is refused, so one classifier decides kept and target.
func TestBranchTypesNestedReleasePrefix(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-nested")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{
			ReleasePrefixes: []string{"release/"},
			Types:           []api.BranchType{{Name: "Hotfix", Prefix: "release/hotfix-", Base: "development"}},
		}, http.StatusUnprocessableEntity)
	})
}

// L4: a form with far more type rows than the limit is refused quickly and stores nothing.
func TestBranchTypesFormManyRows(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-rows")
		owner := loginUser(t, "user2")
		values := url.Values{"release_prefixes": {"release/"}}
		for i := range 600 {
			values.Add("type_name", "t"+strconv.Itoa(i))
			values.Add("type_prefix", "p"+strconv.Itoa(i)+"/")
			values.Add("type_base", "development")
			values.Add("type_on", strconv.Itoa(i))
		}
		owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", path.Join("org3", repo, "settings/branch_workflow/branching_model"), values), http.StatusSeeOther)
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		var got api.RepoBranchingModel
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &got)
		assert.True(t, got.Inherit, "nothing was stored: %+v", got.Own)
	})
}

// L5: a branch that someone else deleted between the check and the deletion is "not found", not a failure.
func TestBranchTypesDeleteGoneMeanwhile(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-gone")
		owner := loginUser(t, "user2")
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "gone", "g.txt", "g\n")
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		gitRepo, err := git.OpenRepository(t.Context(), r.RepoPath())
		require.NoError(t, err)
		defer gitRepo.Close()
		tip := btTip(t, repo, "gone")
		repo_service.DeleteBranchTestHook = func(hr *repo_model.Repository, branch string) {
			_, _, err := git.NewCommand(t.Context(), "update-ref", "-d").AddDynamicArguments("refs/heads/" + branch).RunStdString(&git.RunOpts{Dir: hr.RepoPath()})
			assert.NoError(t, err)
		}
		defer func() { repo_service.DeleteBranchTestHook = nil }()
		err = repo_service.DeleteBranch(t.Context(), doer, r, gitRepo, "gone", tip)
		require.Error(t, err)
		assert.True(t, git.IsErrBranchNotExist(err), "%v", err)
	})
}

// L3: a stored organization model that can't be read must not fail the post-receive hook of a push.
func TestBranchTypesPostReceiveBadModel(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-badmodel")
		owner := loginUser(t, "user2")
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "feature/x", "x.txt", "x\n")
		require.NoError(t, user_model.SetUserSetting(t.Context(), 3, "branch_workflow.branching_model", "{not json"))
		defer func() {
			require.NoError(t, user_model.DeleteUserSetting(t.Context(), 3, "branch_workflow.branching_model"))
		}()
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		res, extra := private.HookPostReceive(t.Context(), r.ID, private.HookOptions{
			UserID: 2, OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{btTip(t, repo, "feature/x")},
			RefFullNames: []git.RefName{git.RefNameFromBranch("feature/x")},
		})
		require.NoError(t, extra.Error)
		require.NotEmpty(t, res.Results)
		assert.Equal(t, r.HTMLURL()+"/compare/master...feature/x", res.Results[0].CreateURL)
	})
}
