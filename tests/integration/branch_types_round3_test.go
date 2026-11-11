// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R3 M1: a branch named exactly like a release prefix is a release branch, so it is kept after a merge.
func TestBranchTypesReleasePrefixNameKept(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-prefix-name")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release", "hotfix-"}}, http.StatusOK)

		for _, head := range []string{"release", "hotfix-"} {
			idx := bwPR(t, owner, "org3", repo, "master", head)
			n, err := strconv.ParseInt(idx, 10, 64)
			require.NoError(t, err)
			ctx.ExpectedCode = http.StatusForbidden
			resp := doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: true})
			ctx.ExpectedCode = 0
			assert.Equal(t, "release", resp.Header().Get("X-Branch-Kept"), head)
			assert.True(t, bwBranchExists("org3", repo, head), head)
		}
	})
}

// R3 L2: a branching model form that Go can't parse (more than 10,000 fields) is refused with 400 and changes
// nothing: the repository keeps inheriting, the organization keeps its model and lock.
func TestBranchTypesUnparsableFormRefused(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-big-form")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		big := url.Values{"development_branch": {"develop"}, "type_name": make([]string, 10001)}

		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/org3/"+repo+"/settings/branch_workflow/branching_model", big), http.StatusBadRequest)
		e, err := branchworkflow.GetEffectiveModel(t.Context(), r)
		require.NoError(t, err)
		assert.NotEqual(t, branchworkflow.SourceRepo, e.Source, "the repository still inherits")

		btOrgModel(t, ctx, &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}, Enforce: true}, http.StatusOK)
		since := auditMaxID(t)
		owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/org/org3/settings/branch_workflow/branching_model", big), http.StatusBadRequest)
		org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"})
		m, locked, err := branchworkflow.GetOrgModel(t.Context(), org)
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.Equal(t, []string{"release/"}, m.ReleasePrefixes)
		assert.True(t, locked)
		assert.Zero(t, auditMaxID(t)-since, "nothing recorded")
		btOrgModel(t, ctx, &api.OrgBranchingModel{}, http.StatusOK)
	})
}

// R3 L3: changing one type of the largest model records that type with its new value, untruncated, and the sha256 of
// both whole models.
func TestBranchTypesAuditRecordsChangedTypes(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-audit-diff")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		types := make([]api.BranchType, 20)
		for i := range types {
			types[i] = api.BranchType{
				Name:   strings.Repeat("&", 40) + string(rune('A'+i)),
				Prefix: strings.Repeat("<", 49) + string(rune('a'+i)) + strings.Repeat(">", 49) + "/",
				Base:   "branch", BaseBranch: strings.Repeat("&", 250) + string(rune('a'+i)),
			}
		}
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, Types: types}, http.StatusOK)

		types[19].BaseBranch = strings.Repeat("&", 250) + "z"
		since := auditMaxID(t)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, Types: types}, http.StatusOK)
		data := auditData(t, auditOne(t, since, "repo.branch_workflow.changed"))
		assert.Nil(t, data["truncated"])
		before, _ := data["before"].(map[string]any)
		after, _ := data["after"].(map[string]any)
		assert.Equal(t, []string{"model_sha256", "types"}, slices.Sorted(maps.Keys(after)))
		require.Len(t, before["types"], 1)
		require.Len(t, after["types"], 1)
		assert.Equal(t, types[19].BaseBranch, after["types"].([]any)[0].(map[string]any)["base_branch"])
		assert.NotEqual(t, before["model_sha256"], after["model_sha256"])
	})
}

// A handler that reads the form with ctx.FormBool (no web.Bind) also refuses a form Go can't parse, and stores nothing.
func TestUnparsableFormRefusedWithoutBind(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	sess := loginUser(t, "user2")
	big := url.Values{"reference": {"true"}, "x": make([]string, 10001)}
	sess.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user/settings/appearance/hidden_comments", big), http.StatusBadRequest)
	v, err := user_model.GetUserSetting(t.Context(), 2, user_model.SettingsKeyHiddenCommentTypes, "unset")
	require.NoError(t, err)
	assert.Equal(t, "unset", v)
}
