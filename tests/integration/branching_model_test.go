// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
)

func bmRepoAPI(t *testing.T, ctx APITestContext, owner, repo string) *api.RepoBranchingModel {
	t.Helper()
	req := NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/branching-model", owner, repo)).AddTokenAuth(ctx.Token)
	var got api.RepoBranchingModel
	DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusOK), &got)
	return &got
}

func TestBranchingModelSettings(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bm-chain")
		owner := loginUser(t, "user2")
		for _, b := range []string{"develop", "release/2.0", "release/1.10", "release/1.9", "release/next", "hotfix/1.9.1", "feature/x"} {
			testAPICreateBranch(t, owner, "org3", repo, "master", b, http.StatusCreated)
		}
		settings := path.Join("org3", repo, "settings/branch_workflow")
		ownerCtx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)

		t.Run("no branching model", func(t *testing.T) {
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", settings), http.StatusOK).Body)
			assert.True(t, doc.doc.Find(`input[name="inherit"]`).Is("[checked]"))
			assert.Equal(t, 0, doc.doc.Find(".branching-model-chain").Length())
			got := bmRepoAPI(t, ownerCtx, "org3", repo)
			assert.True(t, got.Inherit)
			assert.Equal(t, "none", got.Source)
			assert.Equal(t, "master", got.Effective.DevelopmentBranch)
			assert.Empty(t, got.ReleaseBranches)
		})

		t.Run("own model and chain preview", func(t *testing.T) {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", settings+"/branching_model", map[string]string{
				"development_branch": "develop", "release_prefixes": "release/, hotfix/", "production_branch": "master", "merge_forward": "on", "merge_forward_never_bypass": "on",
			}), http.StatusSeeOther)
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", settings), http.StatusOK).Body)
			assert.False(t, doc.doc.Find(`input[name="inherit"]`).Is("[checked]"))
			assert.Equal(t, "release/, hotfix/", doc.doc.Find(`input[name="release_prefixes"]`).AttrOr("value", ""))
			assert.True(t, doc.doc.Find(`input[name="merge_forward"]`).Is("[checked]"))
			assert.True(t, doc.doc.Find(`input[name="merge_forward_never_bypass"]`).Is("[checked]"))
			assert.False(t, doc.doc.Find(`input[name="merge_forward_anyone_may_skip"]`).Is("[checked]"))
			var chain []string
			doc.doc.Find(".branching-model-chain .label").Each(func(_ int, s *goquery.Selection) {
				chain = append(chain, strings.TrimSpace(s.Text()))
			})
			assert.Equal(t, []string{"release/1.9", "hotfix/1.9.1", "release/1.10", "release/2.0", "develop"}, chain)
			assert.Equal(t, "release/next", strings.TrimSpace(doc.doc.Find(".branching-model-ignored code").Text()))
			assert.Equal(t, "masterdevelop", strings.Join(strings.Fields(doc.doc.Find(".branching-model-production").Text()), ""))

			got := bmRepoAPI(t, ownerCtx, "org3", repo)
			assert.False(t, got.Inherit)
			assert.Equal(t, "repo", got.Source)
			assert.Equal(t, &api.BranchingModel{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/", "hotfix/"}, ProductionBranch: "master", Types: []api.BranchType{}, BranchNaming: api.BranchNaming{Exceptions: []string{}, ExemptUsers: []string{}, ExemptTeams: []string{}}, MergeForward: true, MergeForwardNeverBypass: true}, got.Own)
			assert.True(t, got.Effective.MergeForward)
			assert.Equal(t, []string{"release/1.9", "hotfix/1.9.1", "release/1.10", "release/2.0"}, got.ReleaseBranches)
			assert.Equal(t, []string{"release/next"}, got.IgnoredBranches)
		})

		t.Run("invalid values change nothing", func(t *testing.T) {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", settings+"/branching_model", map[string]string{
				"development_branch": "bad..name", "release_prefixes": "release/",
			}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "bad..name cannot be part of a branch name")
			req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"rel ease/"}}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusUnprocessableEntity)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", settings+"/branching_model", map[string]string{
				"release_prefixes": "a,b,c,d,e,f,g,h,i,j,k",
			}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "Enter at most 10 release branch prefixes")
			req = NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", &api.EditRepoBranchingModelOption{ReleasePrefixes: strings.Split("a,b,c,d,e,f,g,h,i,j,k", ",")}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusUnprocessableEntity)
			assert.Equal(t, "develop", bmRepoAPI(t, ownerCtx, "org3", repo).Own.DevelopmentBranch)
		})

		t.Run("organization model, enforced", func(t *testing.T) {
			// enforcing needs a prefix
			req := NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{Enforce: true}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusUnprocessableEntity)

			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/branch_workflow/branching_model", map[string]string{
				"release_prefixes": "release/", "enforce_model": "on",
			}), http.StatusSeeOther)
			var org api.OrgBranchingModel
			req = NewRequest(t, "GET", "/api/v1/orgs/org3/branching-model").AddTokenAuth(ownerCtx.Token)
			DecodeJSON(t, ownerCtx.Session.MakeRequest(t, req, http.StatusOK), &org)
			assert.Equal(t, api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}, Types: []api.BranchType{}, BranchNaming: api.BranchNaming{Exceptions: []string{}, ExemptUsers: []string{}, ExemptTeams: []string{}}, Enforce: true}, org)

			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", settings), http.StatusOK).Body)
			assert.True(t, doc.doc.Find(`input[name="release_prefixes"]`).Is("[disabled]"))
			assert.Equal(t, "release/", doc.doc.Find(`input[name="release_prefixes"]`).AttrOr("value", ""))
			assert.Contains(t, doc.doc.Find("#branching-model + .segment").Text(), "Set by organization org3")

			got := bmRepoAPI(t, ownerCtx, "org3", repo)
			assert.True(t, got.Locked)
			assert.Equal(t, "org3", got.LockedBy)
			assert.Equal(t, "master", got.Effective.DevelopmentBranch, "the org leaves the development branch to each repository's default")
			assert.Equal(t, []string{"release/1.9", "release/1.10", "release/2.0"}, got.ReleaseBranches)
			assert.NotNil(t, got.Own, "the repository's own model is kept")

			owner.MakeRequest(t, NewRequestWithValues(t, "POST", settings+"/branching_model", map[string]string{"inherit": "on"}), http.StatusForbidden)
			req = NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", &api.EditRepoBranchingModelOption{Inherit: true}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusForbidden)

			// unlocking brings the repository's own model back; inheriting then takes the organization's
			req = NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusOK)
			assert.Equal(t, "repo", bmRepoAPI(t, ownerCtx, "org3", repo).Source)
			doc = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", settings), http.StatusOK).Body)
			assert.Contains(t, doc.doc.Find("#branching-model + .segment").Text(), "uses the branching model of organization org3")
			req = NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", &api.EditRepoBranchingModelOption{Inherit: true}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusOK)
			got = bmRepoAPI(t, ownerCtx, "org3", repo)
			assert.Equal(t, "org", got.Source)
			assert.Nil(t, got.Own)

			// an empty list removes the organization's model
			req = NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{}).AddTokenAuth(ownerCtx.Token)
			ownerCtx.Session.MakeRequest(t, req, http.StatusOK)
			assert.Equal(t, "none", bmRepoAPI(t, ownerCtx, "org3", repo).Source)
		})

		t.Run("only owners and admins", func(t *testing.T) {
			other := loginUser(t, "user4")
			other.MakeRequest(t, NewRequestWithValues(t, "POST", settings+"/branching_model", map[string]string{"release_prefixes": "x/"}), http.StatusNotFound)
			other.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/branch_workflow/branching_model", map[string]string{"release_prefixes": "x/"}), http.StatusNotFound)
			otherCtx := NewAPITestContext(t, "user4", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"x/"}}).AddTokenAuth(otherCtx.Token)
			otherCtx.Session.MakeRequest(t, req, http.StatusForbidden)
			req = NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{ReleasePrefixes: []string{"x/"}}).AddTokenAuth(otherCtx.Token)
			otherCtx.Session.MakeRequest(t, req, http.StatusForbidden)
			req = NewRequest(t, "GET", "/api/v1/orgs/org3/branching-model").AddTokenAuth(otherCtx.Token)
			otherCtx.Session.MakeRequest(t, req, http.StatusForbidden)
		})
	})
}
