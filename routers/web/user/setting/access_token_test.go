// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/templates"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/contexttest"
	"forgejo.org/services/forms"

	"code.forgejo.org/go-chi/binding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenCreate(t *testing.T) {
	unittest.PrepareTestEnv(t)

	ctx, resp := contexttest.MockContext(t, "user/settings/keys/tokens/new",
		contexttest.MockContextOption{Render: templates.HTMLRenderer()})
	contexttest.LoadUser(t, ctx, 2)

	web.SetForm(ctx, &forms.NewAccessTokenGetForm{})
	AccessTokenCreate(ctx)

	assert.Equal(t, http.StatusOK, resp.Result().StatusCode)
	assert.False(t, ctx.HasError(), "error: %s", ctx.GetErrMsg())

	// check empty-form GET ctx.Data values
	assert.Equal(t, "name", ctx.Data["Autofocus"])
	assert.Len(t, ctx.Data["Repos"], 10)
	assert.Empty(t, ctx.Data["SelectedRepos"])

	// check that repo in the search is rendered in the content
	assert.Contains(t, resp.Body.String(), "org17/big_test_private_4")
}

func TestAccessTokenCreatePost(t *testing.T) {
	unittest.PrepareTestEnv(t)

	post := func(t *testing.T, form *forms.NewAccessTokenPostForm) (*context.Context, *httptest.ResponseRecorder) {
		t.Helper()

		ctx, resp := contexttest.MockContext(t, "user/settings/keys/tokens/new",
			contexttest.MockContextOption{Render: templates.HTMLRenderer()})
		contexttest.LoadUser(t, ctx, 2)

		ctx.AppendContextValue(context.WebContextKey, ctx)
		binding.Bind(ctx.Req.WithContext(ctx), form)
		web.SetForm(ctx, form)
		AccessTokenCreatePost(ctx)

		return ctx, resp
	}

	render := func(t *testing.T, form *forms.NewAccessTokenPostForm) (*context.Context, string) {
		t.Helper()
		ctx, resp := post(t, form)
		assert.Equal(t, http.StatusOK, resp.Result().StatusCode)
		return ctx, resp.Body.String()
	}

	t.Run("retains form info on missing token name", func(t *testing.T) {
		ctx, body := render(t, &forms.NewAccessTokenPostForm{
			Name:         "", // absent
			Resource:     "repo-specific",
			Scope:        []string{"read:repository"},
			SelectedRepo: []string{"org17/big_test_private_4"},
		})
		require.Contains(t, body, "settings.token_nameform.require_error")

		assert.Equal(t, "repo-specific", ctx.Data["resource"])
		assert.Contains(t, ctx.Data["scope"], "read:repository")
		assert.True(t, slices.ContainsFunc(ctx.Data["SelectedRepos"].([]*repo_model.Repository), func(r *repo_model.Repository) bool {
			return r.OwnerName == "org17" && r.Name == "big_test_private_4"
		}), "SelectedRepos missing org17/big_test_private_4")
	})

	t.Run("retains form info on missing scopes", func(t *testing.T) {
		ctx, body := render(t, &forms.NewAccessTokenPostForm{
			Name:         "my new token",
			Resource:     "repo-specific",
			Scope:        []string{"", "", ""}, // absent
			SelectedRepo: []string{"org17/big_test_private_4"},
		})
		require.Contains(t, body, "settings.at_least_one_permission")

		assert.Equal(t, "my new token", ctx.Data["name"])
		assert.Equal(t, "repo-specific", ctx.Data["resource"])
		assert.True(t, slices.ContainsFunc(ctx.Data["SelectedRepos"].([]*repo_model.Repository), func(r *repo_model.Repository) bool {
			return r.OwnerName == "org17" && r.Name == "big_test_private_4"
		}), "SelectedRepos missing org17/big_test_private_4")
	})

	t.Run("retains form info on duplicate token name", func(t *testing.T) {
		ctx, body := render(t, &forms.NewAccessTokenPostForm{
			Name:         "Token A", // duplicate
			Resource:     "repo-specific",
			Scope:        []string{"read:repository"},
			SelectedRepo: []string{"org17/big_test_private_4"},
		})
		require.Contains(t, body, "settings.generate_token_name_duplicate")

		assert.Equal(t, "Token A", ctx.Data["name"])
		assert.Equal(t, "repo-specific", ctx.Data["resource"])
		assert.Contains(t, ctx.Data["scope"], "read:repository")
		assert.True(t, slices.ContainsFunc(ctx.Data["SelectedRepos"].([]*repo_model.Repository), func(r *repo_model.Repository) bool {
			return r.OwnerName == "org17" && r.Name == "big_test_private_4"
		}), "SelectedRepos missing org17/big_test_private_4")
	})

	t.Run("retains form info on ValidateAccessToken error", func(t *testing.T) {
		ctx, body := render(t, &forms.NewAccessTokenPostForm{
			Name:         "my new token",
			Resource:     "repo-specific",
			Scope:        []string{"read:admin"}, // not permitted for repo-specific
			SelectedRepo: []string{"org17/big_test_private_4"},
		})
		require.Contains(t, body, "access_token.error.specified_repos_and_invalid_scope")

		assert.Equal(t, "my new token", ctx.Data["name"])
		assert.Equal(t, "repo-specific", ctx.Data["resource"])
		assert.Contains(t, ctx.Data["scope"], "read:admin")
		assert.True(t, slices.ContainsFunc(ctx.Data["SelectedRepos"].([]*repo_model.Repository), func(r *repo_model.Repository) bool {
			return r.OwnerName == "org17" && r.Name == "big_test_private_4"
		}), "SelectedRepos missing org17/big_test_private_4")
	})

	t.Run("invalid repo selected", func(t *testing.T) {
		_, resp := post(t, &forms.NewAccessTokenPostForm{
			Name:         "my new token",
			Resource:     "repo-specific",
			Scope:        []string{"read:admin"}, // not permitted for repo-specific
			SelectedRepo: []string{"org17/big_test_private_4000000_does_not_exist"},
		})
		assert.Equal(t, http.StatusBadRequest, resp.Result().StatusCode)
		assert.Equal(t, "getSelectedRepos\n", resp.Body.String())
	})

	t.Run("non-visible repo selected via IDOR", func(t *testing.T) {
		_, resp := post(t, &forms.NewAccessTokenPostForm{
			Name:         "my new token",
			Resource:     "repo-specific",
			Scope:        []string{"read:repository"},
			SelectedRepo: []string{"user30/empty"}, // private repo, user2 has no visibility
		})
		assert.Equal(t, http.StatusBadRequest, resp.Result().StatusCode)
		assert.Equal(t, "getSelectedRepos\n", resp.Body.String()) // should be exact same response as "invalid repo selected" case
	})
}

// moveToProject puts a fixture repository into a project of its owner, under a new name.
func moveToProject(t *testing.T, repoID int64, project, name string) {
	t.Helper()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	group, err := repo_model.GetRepoGroupByName(db.DefaultContext, owner.ID, project)
	if err != nil {
		group, err = repo_model.CreateRepoGroup(db.DefaultContext, owner, project, "")
		require.NoError(t, err)
	}
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET group_id = ?, group_name = ?, name = ?, lower_name = ? WHERE id = ?",
		group.ID, group.Name, name, strings.ToLower(name), repoID)
	require.NoError(t, err)
}

func TestGetSelectedRepos(t *testing.T) {
	unittest.PrepareTestEnv(t)
	moveToProject(t, 5, "proj", "repo3")       // org3/proj/repo3, next to the root org3/repo3
	moveToProject(t, 32, "proj", "gone")       // trashed below
	moveToProject(t, 43, "proj26", "repo26")   // org26 is not visible to user2
	moveToProject(t, 24, "proj17", "private4") // org17 is trashed below
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 32")
	require.NoError(t, err)
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET trashed_unix = 1 WHERE id = 17")
	require.NoError(t, err)

	selected := func(t *testing.T, raw ...string) ([]*repo_model.Repository, error) {
		t.Helper()
		ctx, _ := contexttest.MockContext(t, "user/settings/keys/tokens/new")
		contexttest.LoadUser(t, ctx, 2)
		return getSelectedRepos(ctx, ctx.Doer, raw)
	}

	repos, err := selected(t, "user2/repo1", "org3/repo3", "org3/proj/repo3")
	require.NoError(t, err)
	var ids []int64
	for _, repo := range repos {
		ids = append(ids, repo.ID)
	}
	assert.Equal(t, []int64{5, 3, 1}, ids, "sorted by full name: org3/proj/repo3, org3/repo3, user2/repo1")

	_, missing := selected(t, "org3/proj/nosuch")
	require.ErrorIs(t, missing, errSelectedRepoNotFound)
	for _, raw := range [][]string{
		{"org3/repo5"},         // moved into the project: no root repository of that name
		{"org3/proj26/repo26"}, // another owner's project
		{"org26/proj26/repo26"},
		{"org3/proj/gone"},
		{"org17/proj17/private4"},
		{"org3"},
		{"org3/proj/repo3/x"},
		{"org3//repo3"},
		{"/repo3"},
		{"org3/proj/"},
		{"org3/proj/repo3/"},
		{""},
		{"org3/proj/repo3", "ORG3/Proj/Repo3"},
		{"user2/repo1", "user2/repo1"},
	} {
		_, err := selected(t, raw...)
		assert.Equal(t, missing, err, "%v", raw)
	}
}

func TestAccessTokenCreatePostProjectRepo(t *testing.T) {
	unittest.PrepareTestEnv(t)
	moveToProject(t, 5, "proj", "repo3")

	ctx, resp := contexttest.MockContext(t, "user/settings/keys/tokens/new")
	contexttest.LoadUser(t, ctx, 2)
	web.SetForm(ctx, &forms.NewAccessTokenPostForm{
		Name:         "project token",
		Resource:     "repo-specific",
		Scope:        []string{"read:repository"},
		SelectedRepo: []string{"org3/proj/repo3"},
	})
	AccessTokenCreatePost(ctx)
	require.Equal(t, http.StatusSeeOther, resp.Result().StatusCode, resp.Body.String())

	token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "project token"})
	unittest.AssertExistsAndLoadBean(t, &auth_model.AccessTokenResourceRepo{TokenID: token.ID, RepoID: 5})
	unittest.AssertCount(t, &auth_model.AccessTokenResourceRepo{TokenID: token.ID}, 1)
}

// An authorized integration on a repository in a project keeps that repository through an edit, although a root
// repository of the owner has the same name.
func TestAuthorizedIntegrationFormProjectRepo(t *testing.T) {
	unittest.PrepareTestEnv(t)
	moveToProject(t, 5, "proj", "repo3")
	ctx, _ := contexttest.MockContext(t, "user/settings/authorized-integrations")
	contexttest.LoadUser(t, ctx, 2)

	f := &baseAuthorizedIntegrationForm{}
	require.NoError(t, f.copyAuthorizedIntegrationToForm(ctx, &auth_model.AuthorizedIntegration{Scope: "read:repository"},
		[]*auth_model.AuthorizedIntegResourceRepo{{RepoID: 5}, {RepoID: 3}}))
	assert.Equal(t, []string{"org3/proj/repo3", "org3/repo3"}, f.SelectedRepo)

	rr, err := f.copyFormToAuthorizedIntegration(ctx, &auth_model.AuthorizedIntegration{})
	require.NoError(t, err)
	require.Len(t, rr, 2)
	assert.EqualValues(t, 5, rr[0].RepoID)
	assert.EqualValues(t, 3, rr[1].RepoID)

	t.Run("Actions local", func(t *testing.T) {
		form := &actionsLocalAuthorizedIntegrationForm{}
		cr := &auth_model.ClaimRules{Rules: []auth_model.ClaimRule{
			{Claim: "repository_id", Comparison: auth_model.ClaimEqual, Value: "5"},
			{Claim: "repository_owner_id", Comparison: auth_model.ClaimEqual, Value: "3"},
		}}
		require.NoError(t, form.populateForm(ctx, "urn:forgejo:authorized-integrations:actions", cr))
		assert.Equal(t, "org3/proj/repo3", form.SourceRepo)
		_, again, err := form.convertForm(ctx)
		require.NoError(t, err)
		assert.Equal(t, cr, again)
	})
}

// contexttest.LoadUser keeps an audit actor set before it, so a test can act through a delegated credential.
func TestAccessTokenCreatePostNotOwnAct(t *testing.T) {
	unittest.PrepareTestEnv(t)

	ctx, resp := contexttest.MockContext(t, "user/settings/keys/tokens/new")
	grant := &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", Credential: audit_model.Credential{Type: audit_model.CredentialOAuth2Grant}}
	ctx.AppendContextValue(audit_model.ActorContextKey, grant)
	contexttest.LoadUser(t, ctx, 2)
	require.Same(t, grant, audit_model.ActorFromContext(ctx))

	web.SetForm(ctx, &forms.NewAccessTokenPostForm{
		Name:         "via grant",
		Resource:     "repo-specific",
		Scope:        []string{"read:repository"},
		SelectedRepo: []string{"user2/repo1"},
	})
	AccessTokenCreatePost(ctx)
	assert.Equal(t, http.StatusOK, resp.Result().StatusCode)
	assert.Equal(t, "settings.credential_not_own_act", ctx.Flash.ErrorMsg)
	unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "via grant"})
}
