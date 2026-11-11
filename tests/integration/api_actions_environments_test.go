// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	actions_service "forgejo.org/services/actions"
	secrets_service "forgejo.org/services/secrets"
	"forgejo.org/tests"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entryData decodes the data of an audit entry.
func entryData(t *testing.T, e *audit_model.Entry) map[string]any {
	t.Helper()
	data := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(e.Data), &data))
	return data
}

// The environments API (CRUD, secrets, variables) and the deployments list, through real requests, with the rows and
// audit entries they leave.
// envRules fills every rule the body leaves out with its explicit "no rule" value: the API requires them all.
func envRules(o api.CreateOrUpdateEnvironmentOption) api.CreateOrUpdateEnvironmentOption {
	if o.RepositorySelection == "" { // as a new environment of the organization by default; ignored for a repository
		o.RepositorySelection = "selected"
	}
	if o.RefPolicy == "" {
		o.RefPolicy = "any"
	}
	if o.RefPatterns == nil {
		o.RefPatterns = []*api.ActionEnvironmentRefPattern{}
	}
	if o.WaitTimer == nil {
		o.WaitTimer = new(0)
	}
	if o.PreventSelfReview == nil {
		o.PreventSelfReview = new(false)
	}
	if o.Reviewers == nil {
		o.Reviewers = []*api.ActionEnvironmentReviewer{}
	}
	if o.RunnerLabels == nil {
		o.RunnerLabels = []string{}
	}
	if o.AllowedWorkflows == nil {
		o.AllowedWorkflows = []string{}
	}
	return o
}

func TestAPIActionsEnvironments(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		ownerToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		readOnlyToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeReadRepository)
		publicOnlyToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopePublicOnly)
		writerToken := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository)
		adminCollabToken := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository)
		readerToken := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)
		strangerToken := getUserToken(t, "user10", auth_model.AccessTokenScopeWriteRepository)
		siteAdminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository)

		apiRepo := createActionsTestRepo(t, ownerToken, "api-envs", true)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		ctx := audit_model.WithSystem(t.Context(), "test")
		for user, perm := range map[string]string{"user4": "write", "user8": "admin", "user5": "read"} {
			MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", user2.Name, repo.Name, user),
				&api.AddCollaboratorOption{Permission: new(perm)}).AddTokenAuth(ownerToken), http.StatusNoContent)
		}
		base := fmt.Sprintf("/api/v1/repos/%s/%s/actions/environments", user2.Name, repo.Name)

		put := func(token, name string, opts api.CreateOrUpdateEnvironmentOption, status int) *api.ActionEnvironment {
			t.Helper()
			resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/"+url.PathEscape(name), envRules(opts)).AddTokenAuth(token), status)
			if status != http.StatusOK && status != http.StatusCreated {
				return nil
			}
			out := new(api.ActionEnvironment)
			DecodeJSON(t, resp, out)
			return out
		}
		auditNow := func() int64 {
			var id int64
			_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
			require.NoError(t, err)
			return id
		}
		auditSince := func(since int64, prefix string) []*audit_model.Entry {
			var entries []*audit_model.Entry
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action LIKE ?", since, prefix+"%").OrderBy("id").Find(&entries))
			return entries
		}

		t.Run("create, read, update and delete record one entry each", func(t *testing.T) {
			// a user without a path to the repository (user10) is refused, with the answer every such user gets
			resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/Production", envRules(api.CreateOrUpdateEnvironmentOption{
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}, {Type: "user", ID: 10}},
			})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			assert.Contains(t, resp.Body.String(), "a reviewer is the owner, a member of a team of the repository or a collaborator")
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "production"})

			since := auditNow()
			env := put(ownerToken, "Production", api.CreateOrUpdateEnvironmentOption{
				RefPolicy: "patterns", RefPatterns: []*api.ActionEnvironmentRefPattern{{Type: "branch", Pattern: "release/*"}, {Type: "tag", Pattern: "v*"}},
				WaitTimer: new(5), PreventSelfReview: new(true), RunnerLabels: []string{"deploy"}, AllowedWorkflows: []string{"deploy-*.yml"},
				// a reader is accepted: who may approve is decided at review time
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}, {Type: "user", ID: 5}},
			}, http.StatusCreated)
			assert.Equal(t, "Production", env.Name)
			assert.Equal(t, "patterns", env.RefPolicy)
			assert.Len(t, env.RefPatterns, 2)
			assert.True(t, env.ReviewsRequired)
			assert.False(t, env.CreatedByWorkflow)
			require.Len(t, env.Reviewers, 2)
			assert.Equal(t, "user4", env.Reviewers[0].Name)
			entries := auditSince(since, "repo.actions_env")
			require.Len(t, entries, 1, "a creation with reviewers is one entry")
			assert.Equal(t, "repo.actions_env.created", entries[0].Action)
			assert.Equal(t, []any{"user:4", "user:5"}, entryData(t, entries[0])["reviewers"])

			stored := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: env.ID})
			assert.Equal(t, 5, stored.WaitTimerMinutes)
			assert.Equal(t, []string{"deploy"}, stored.RunnerLabels)

			// the same request again changes nothing; a name in another case is the same environment
			since = auditNow()
			again := put(ownerToken, "PRODUCTION", api.CreateOrUpdateEnvironmentOption{
				RefPolicy: "patterns", RefPatterns: []*api.ActionEnvironmentRefPattern{{Type: "branch", Pattern: "release/*"}, {Type: "tag", Pattern: "v*"}},
				WaitTimer: new(5), PreventSelfReview: new(true), RunnerLabels: []string{"deploy"}, AllowedWorkflows: []string{"deploy-*.yml"},
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 5}, {Type: "user", ID: 4}},
			}, http.StatusOK)
			assert.Equal(t, env.ID, again.ID)
			assert.Equal(t, "Production", again.Name, "the stored name stays")
			assert.Empty(t, auditSince(since, "repo.actions_env"), "an unchanged PUT records nothing")

			// a PUT that leaves the reviewers out removes them: one entry with what changed
			changed := put(ownerToken, "production", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(1)}, http.StatusOK)
			assert.False(t, changed.ReviewsRequired)
			assert.Empty(t, changed.Reviewers)
			assert.Equal(t, "any", changed.RefPolicy)
			entries = auditSince(since, "repo.actions_env")
			require.Len(t, entries, 1)
			assert.Equal(t, "repo.actions_env.updated", entries[0].Action)
			before := entryData(t, entries[0])["before"].(map[string]any)
			assert.Equal(t, []any{"user:4", "user:5"}, before["reviewers"], "the entry has the removed reviewers")
			assert.Equal(t, true, before["reviews_required"])

			resp = MakeRequest(t, NewRequest(t, "GET", base+"/pRoDuCtIoN").AddTokenAuth(readOnlyToken), http.StatusOK)
			got := new(api.ActionEnvironment)
			DecodeJSON(t, resp, got)
			assert.Equal(t, env.ID, got.ID)
			MakeRequest(t, NewRequest(t, "GET", base+"/missing").AddTokenAuth(ownerToken), http.StatusNotFound)

			since = auditNow()
			MakeRequest(t, NewRequest(t, "DELETE", base+"/Production").AddTokenAuth(ownerToken), http.StatusNoContent)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{ID: env.ID})
			entries = auditSince(since, "repo.actions_env")
			require.Len(t, entries, 1)
			assert.Equal(t, "repo.actions_env.deleted", entries[0].Action)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/Production").AddTokenAuth(ownerToken), http.StatusNotFound)
		})

		t.Run("the list carries counts, the last deployment and the workflow mark", func(t *testing.T) {
			auto, err := actions_model.GetOrCreateRepoEnvironment(ctx, repo.ID, "from-workflow")
			require.NoError(t, err)
			listed := put(ownerToken, "listed", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			_, _, err = secrets_service.CreateOrUpdateSecret(ctx, 0, 0, repo.ID, listed.ID, "A", "x-secret-value")
			require.NoError(t, err)
			_, _, err = secrets_service.CreateOrUpdateSecret(ctx, 0, 0, repo.ID, listed.ID, "B", "y-secret-value")
			require.NoError(t, err)
			_, err = actions_service.CreateVariable(ctx, 0, 0, repo.ID, listed.ID, "V", "v")
			require.NoError(t, err)
			for i, status := range []actions_model.DeploymentStatus{actions_model.DeploymentReleased, actions_model.DeploymentRejected} {
				require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{RepoID: repo.ID, EnvironmentID: listed.ID, RunID: 999, JobID: int64(9000 + i), Attempt: 1, Status: status, Ref: "refs/heads/main", CommitSHA: "abc"}))
			}

			resp := MakeRequest(t, NewRequest(t, "GET", base+"?limit=1&page=2").AddTokenAuth(ownerToken), http.StatusOK)
			assert.Equal(t, "2", resp.Header().Get("X-Total-Count"))
			var page []*api.ActionEnvironment
			DecodeJSON(t, resp, &page)
			require.Len(t, page, 1)
			assert.Equal(t, "listed", page[0].Name)
			assert.EqualValues(t, 2, page[0].SecretsCount)
			assert.EqualValues(t, 1, page[0].VariablesCount)
			require.NotNil(t, page[0].LastDeployment)
			assert.Equal(t, "rejected", page[0].LastDeployment.Status)
			assert.Equal(t, "listed", page[0].LastDeployment.Environment)

			resp = MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(ownerToken), http.StatusOK)
			var all []*api.ActionEnvironment
			DecodeJSON(t, resp, &all)
			require.Len(t, all, 2)
			assert.Equal(t, auto.ID, all[0].ID)
			assert.True(t, all[0].CreatedByWorkflow)
			assert.Nil(t, all[0].LastDeployment)
			assert.NotContains(t, resp.Body.String(), "secret-value")
			require.NoError(t, actions_service.DeleteEnvironment(ctx, auto))
		})

		t.Run("refusals", func(t *testing.T) {
			for name, tc := range map[string]struct {
				env  string
				opts api.CreateOrUpdateEnvironmentOption
			}{
				"colon in the name":       {"a:b", api.CreateOrUpdateEnvironmentOption{}},
				"space in the name":       {"a b", api.CreateOrUpdateEnvironmentOption{}},
				"non-ASCII name":          {"prodé", api.CreateOrUpdateEnvironmentOption{}},
				"name too long":           {strings.Repeat("a", 256), api.CreateOrUpdateEnvironmentOption{}},
				"unknown ref policy":      {"x", api.CreateOrUpdateEnvironmentOption{RefPolicy: "some"}},
				"patterns without one":    {"x", api.CreateOrUpdateEnvironmentOption{RefPolicy: "patterns"}},
				"invalid pattern":         {"x", api.CreateOrUpdateEnvironmentOption{RefPolicy: "patterns", RefPatterns: []*api.ActionEnvironmentRefPattern{{Type: "branch", Pattern: "release/["}}}},
				"pattern of another type": {"x", api.CreateOrUpdateEnvironmentOption{RefPolicy: "patterns", RefPatterns: []*api.ActionEnvironmentRefPattern{{Type: "commit", Pattern: "x"}}}},
				"negative wait timer":     {"x", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(-1)}},
				"21 allowed workflows":    {"x", api.CreateOrUpdateEnvironmentOption{AllowedWorkflows: strings.Split(strings.Repeat("w.yml,", 20)+"last.yml", ",")}},
				"7 reviewers": {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{
					{Type: "user", ID: 1}, {Type: "user", ID: 4}, {Type: "user", ID: 5}, {Type: "user", ID: 8}, {Type: "user", ID: 10}, {Type: "user", ID: 11}, {Type: "user", ID: 12},
				}}},
				"reviewer of no type":       {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{ID: 4}}}},
				"unknown user":              {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 99999}}}},
				"an organization":           {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 3}}}},
				"the Actions user":          {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: -2}}}},
				"a team of another owner":   {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "team", ID: 2}}}},
				"a reviewer listed twice":   {"x", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}, {Type: "user", ID: 4}}}},
				"a duplicate runner label":  {"x", api.CreateOrUpdateEnvironmentOption{RunnerLabels: []string{"a", "a"}}},
				"a name of dots":            {"...", api.CreateOrUpdateEnvironmentOption{}},
				"question mark in the name": {"a?b", api.CreateOrUpdateEnvironmentOption{}},
				"hash in the name":          {"a#b", api.CreateOrUpdateEnvironmentOption{}},
				"percent in the name":       {"a%b", api.CreateOrUpdateEnvironmentOption{}},
				"backslash in the name":     {"a\\b", api.CreateOrUpdateEnvironmentOption{}},
			} {
				put(ownerToken, tc.env, tc.opts, http.StatusUnprocessableEntity)
				assert.False(t, unittest.BeanExists(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: strings.ToLower(tc.env)}), name)
			}

			// every rule is required: a body that leaves one out changes nothing, explicit "no rule" values are accepted
			put(ownerToken, "complete", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(5), Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusCreated)
			full := map[string]any{
				"ref_policy": "any", "ref_patterns": []any{}, "wait_timer": 0, "prevent_self_review": false,
				"reviewers": []any{}, "runner_labels": []any{}, "allowed_workflows": []any{},
			}
			for field := range full {
				body := maps.Clone(full)
				delete(body, field)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/complete", body).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
				body[field] = nil
				MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/complete", body).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/never-made", body).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			}
			kept := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "complete"})
			assert.Equal(t, 5, kept.WaitTimerMinutes, "a refused body changes nothing")
			assert.True(t, kept.ReviewsRequired)
			assert.False(t, unittest.BeanExists(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "never-made"}))
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/complete", full).AddTokenAuth(ownerToken), http.StatusOK)
			kept = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "complete"})
			assert.Equal(t, 0, kept.WaitTimerMinutes)
			assert.False(t, kept.ReviewsRequired, "an explicit empty list clears the reviewers")
			require.NoError(t, actions_service.DeleteEnvironment(ctx, kept))

			// the 101st environment
			for i := range actions_model.MaxEnvironments - 1 { // "listed" exists
				require.NoError(t, actions_model.CreateEnvironment(ctx, &actions_model.ActionEnvironment{RepoID: repo.ID, Name: fmt.Sprintf("cap-%d", i)}, nil))
			}
			put(ownerToken, "one-too-many", api.CreateOrUpdateEnvironmentOption{}, http.StatusUnprocessableEntity)
			put(ownerToken, "cap-1", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(2)}, http.StatusOK) // an update at the cap
			_, err := db.GetEngine(ctx).Where("repo_id = ? AND name LIKE 'cap-%'", repo.ID).Delete(new(actions_model.ActionEnvironment))
			require.NoError(t, err)
		})

		t.Run("who may manage environments", func(t *testing.T) {
			put(ownerToken, "guarded", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			for _, token := range []string{writerToken, adminCollabToken, readerToken} {
				MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(token), http.StatusForbidden)
				MakeRequest(t, NewRequest(t, "GET", base+"/guarded").AddTokenAuth(token), http.StatusForbidden)
				put(token, "guarded", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(3)}, http.StatusForbidden)
				MakeRequest(t, NewRequest(t, "DELETE", base+"/guarded").AddTokenAuth(token), http.StatusForbidden)
				MakeRequest(t, NewRequest(t, "GET", base+"/guarded/secrets").AddTokenAuth(token), http.StatusForbidden)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/guarded/secrets/S", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(token), http.StatusForbidden)
			}
			MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(strangerToken), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(publicOnlyToken), http.StatusNotFound)
			put(readOnlyToken, "guarded", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(3)}, http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/guarded").AddTokenAuth(readOnlyToken), http.StatusForbidden)
			put(siteAdminToken, "guarded", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(3)}, http.StatusOK)

			// an owned access token of the repository, even with admin permission, is never its owner
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/tokens", user2.Name, repo.Name),
				api.CreateOwnedAccessTokenOption{Name: "env-admin-token", Scopes: []string{"write:repository"}, Permission: "admin"}).AddTokenAuth(ownerToken), http.StatusCreated)
			var owned api.AccessToken
			DecodeJSON(t, resp, &owned)
			MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(owned.Token), http.StatusForbidden)
			put(owned.Token, "guarded", api.CreateOrUpdateEnvironmentOption{}, http.StatusForbidden)
			assert.Equal(t, 3, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "guarded"}).WaitTimerMinutes)
		})

		t.Run("delegated credentials and sudo change no protection", func(t *testing.T) {
			put(ownerToken, "shielded", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/shielded/secrets/DEPLOY", api.CreateOrUpdateSecretOption{Data: "the-owners-value"}).AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/shielded/variables/TARGET", api.CreateVariableOption{Value: "prod"}).AddTokenAuth(ownerToken), http.StatusNoContent)

			ait := newAITester(t)
			defer ait.close()
			sudoToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteAdmin)
			credentials := map[string]func(*RequestWrapper) *RequestWrapper{
				"authorized integration": func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(ait.signedJWT()) },
				"OAuth2 grant": func(r *RequestWrapper) *RequestWrapper {
					return r.AddTokenAuth(createOAuth2Token(t, loginUser(t, user2.Name), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository}))
				},
				"sudo": func(r *RequestWrapper) *RequestWrapper {
					return r.AddTokenAuth(sudoToken).SetHeader("Sudo", user2.Name)
				},
			}
			for name, auth := range credentials {
				since := auditNow()
				// the credential reaches the owner's environments: reads work
				MakeRequest(t, auth(NewRequest(t, "GET", base+"/shielded")), http.StatusOK)
				for _, req := range []*RequestWrapper{
					NewRequestWithJSON(t, "PUT", base+"/shielded", envRules(api.CreateOrUpdateEnvironmentOption{})),
					NewRequestWithJSON(t, "PUT", base+"/unshielded", envRules(api.CreateOrUpdateEnvironmentOption{})),
					NewRequest(t, "DELETE", base+"/shielded"),
					NewRequestWithJSON(t, "PUT", base+"/shielded/secrets/DEPLOY", api.CreateOrUpdateSecretOption{Data: "replaced"}),
					NewRequestWithJSON(t, "PUT", base+"/shielded/secrets/OTHER", api.CreateOrUpdateSecretOption{Data: "added"}),
					NewRequest(t, "DELETE", base+"/shielded/secrets/DEPLOY"),
					NewRequestWithJSON(t, "POST", base+"/shielded/variables/OTHER", api.CreateVariableOption{Value: "added"}),
					NewRequestWithJSON(t, "PUT", base+"/shielded/variables/TARGET", api.UpdateVariableOption{Value: "staging"}),
					NewRequest(t, "DELETE", base+"/shielded/variables/TARGET"),
				} {
					MakeRequest(t, auth(req), http.StatusForbidden)
				}
				e := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "shielded"})
				assert.True(t, e.ReviewsRequired, name)
				unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: e.ID, UserID: 4})
				assert.False(t, unittest.BeanExists(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "unshielded"}), name)
				rows, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: repo.ID, EnvironmentID: e.ID})
				require.NoError(t, err)
				require.Len(t, rows, 1, name)
				value, err := rows[0].GetDecryptedData()
				require.NoError(t, err)
				assert.Equal(t, "the-owners-value", value, name)
				v := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{RepoID: repo.ID, EnvironmentID: e.ID, Name: "TARGET"})
				assert.Equal(t, "prod", v.Data, name)
				unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{RepoID: repo.ID, EnvironmentID: e.ID, Name: "OTHER"})
				assert.Empty(t, auditSince(since, "repo.actions_env"), name)
			}

			// repository secrets keep their rules: the same credentials may write them
			MakeRequest(t, credentials["OAuth2 grant"](NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/actions/secrets/DELEGATED", user2.Name, repo.Name),
				api.CreateOrUpdateSecretOption{Data: "x"})), http.StatusCreated)
			MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/%s/%s/actions/secrets/DELEGATED", user2.Name, repo.Name)).AddTokenAuth(ownerToken), http.StatusNoContent)

			// the owner's own token still changes them
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/shielded/secrets/DEPLOY", api.CreateOrUpdateSecretOption{Data: "rotated"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			put(ownerToken, "shielded", api.CreateOrUpdateEnvironmentOption{}, http.StatusOK)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/shielded").AddTokenAuth(ownerToken), http.StatusNoContent)
		})

		t.Run("a reviewer the doer can't see is unknown", func(t *testing.T) {
			// user31 is private and shares no organization with user2; user3 is an organization, -2 the Actions user,
			// team 2 belongs to another owner
			messages := map[string]bool{}
			for _, r := range []*api.ActionEnvironmentReviewer{{Type: "user", ID: 31}, {Type: "user", ID: 99999}, {Type: "user", ID: 3}, {Type: "user", ID: -2}, {Type: "team", ID: 2}, {Type: "team", ID: 99999}} {
				resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/hidden-reviewer", envRules(api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{r}})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
				messages[resp.Body.String()] = true
			}
			assert.Len(t, messages, 1, "one answer for unknown, hidden and wrong-type reviewers")
			assert.False(t, unittest.BeanExists(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "hidden-reviewer"}))
			// a site administrator sees user31, who can be listed once a member
			require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: repo.ID, UserID: 31, Mode: perm.AccessModeRead}))
			put(siteAdminToken, "hidden-reviewer", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 31}}}, http.StatusCreated)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/hidden-reviewer").AddTokenAuth(ownerToken), http.StatusNoContent)
		})

		t.Run("concurrent creates of one name make one environment", func(t *testing.T) {
			since := auditNow()
			var wg sync.WaitGroup
			codes := make([]int, 8)
			for i := range codes {
				wg.Go(func() {
					codes[i] = MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/race", envRules(api.CreateOrUpdateEnvironmentOption{
						Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}},
					})).AddTokenAuth(ownerToken), NoExpectedStatus).Code
				})
			}
			wg.Wait()
			created := 0
			for _, code := range codes {
				if code == http.StatusCreated {
					created++
				} else {
					assert.Equal(t, http.StatusOK, code)
				}
			}
			assert.Equal(t, 1, created, codes)
			e := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID, LowerName: "race"})
			assert.Equal(t, 1, unittest.GetCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: e.ID}))
			assert.Len(t, auditSince(since, "repo.actions_env.created"), 1)
			assert.Empty(t, auditSince(since, "repo.actions_env.updated"))
			MakeRequest(t, NewRequest(t, "DELETE", base+"/race").AddTokenAuth(ownerToken), http.StatusNoContent)
		})

		t.Run("secrets and variables of an environment", func(t *testing.T) {
			env := put(ownerToken, "vault", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			since := auditNow()
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/VAULT/secrets/token", api.CreateOrUpdateSecretOption{Data: "env-only-secret"}).AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/vault/secrets/token", api.CreateOrUpdateSecretOption{Data: "env-only-secret-2"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/actions/secrets/token", user2.Name, repo.Name), api.CreateOrUpdateSecretOption{Data: "repo-secret"}).AddTokenAuth(ownerToken), http.StatusCreated)
			rows, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: repo.ID, EnvironmentID: env.ID})
			require.NoError(t, err)
			require.Len(t, rows, 1)
			value, err := rows[0].GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, "env-only-secret-2", value)

			resp := MakeRequest(t, NewRequest(t, "GET", base+"/vault/secrets").AddTokenAuth(ownerToken), http.StatusOK)
			var secrets []*api.Secret
			DecodeJSON(t, resp, &secrets)
			require.Len(t, secrets, 1)
			assert.Equal(t, "TOKEN", secrets[0].Name)
			assert.NotContains(t, resp.Body.String(), "env-only")
			resp = MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/actions/secrets", user2.Name, repo.Name)).AddTokenAuth(ownerToken), http.StatusOK)
			DecodeJSON(t, resp, &secrets)
			require.Len(t, secrets, 1, "the repository list doesn't show the environment's secret")

			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/vault/variables/color", api.CreateVariableOption{Value: "blue"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/vault/variables/color", api.CreateVariableOption{Value: "red"}).AddTokenAuth(ownerToken), http.StatusConflict)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/vault/variables/color", api.UpdateVariableOption{Value: "green"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			resp = MakeRequest(t, NewRequest(t, "GET", base+"/vault/variables/color").AddTokenAuth(ownerToken), http.StatusOK)
			variable := new(api.ActionVariable)
			DecodeJSON(t, resp, variable)
			assert.Equal(t, "green", variable.Data)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/actions/variables/color", user2.Name, repo.Name)).AddTokenAuth(ownerToken), http.StatusNotFound)
			resp = MakeRequest(t, NewRequest(t, "GET", base+"/vault/variables").AddTokenAuth(ownerToken), http.StatusOK)
			var variables []*api.ActionVariable
			DecodeJSON(t, resp, &variables)
			require.Len(t, variables, 1)

			actions := []string{}
			for _, e := range auditSince(since, "repo.actions_") {
				actions = append(actions, e.Action)
			}
			assert.Equal(t, []string{
				"repo.actions_env_secret.created", "repo.actions_env_secret.updated", "repo.actions_secret.created",
				"repo.actions_env_variable.created", "repo.actions_env_variable.updated",
			}, actions)

			// an environment of another repository is never reached by name
			otherRepo := createActionsTestRepo(t, ownerToken, "api-envs-other", true)
			other, err := actions_model.GetOrCreateRepoEnvironment(ctx, otherRepo.ID, "elsewhere")
			require.NoError(t, err)
			_, _, err = secrets_service.CreateOrUpdateSecret(ctx, 0, 0, otherRepo.ID, other.ID, "FOREIGN", "foreign-value")
			require.NoError(t, err)
			MakeRequest(t, NewRequest(t, "GET", base+"/elsewhere/secrets").AddTokenAuth(ownerToken), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/elsewhere/secrets/FOREIGN").AddTokenAuth(ownerToken), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", base+"/elsewhere").AddTokenAuth(ownerToken), http.StatusNotFound)
			// and a secret of another environment of the same repository neither
			put(ownerToken, "sibling", api.CreateOrUpdateEnvironmentOption{}, http.StatusCreated)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/sibling/secrets/token").AddTokenAuth(ownerToken), http.StatusNotFound)

			MakeRequest(t, NewRequest(t, "DELETE", base+"/vault/secrets/token").AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/vault/variables/color").AddTokenAuth(ownerToken), http.StatusNoContent)
			assert.Len(t, auditSince(since, "repo.actions_env_secret.deleted"), 1)
			assert.Len(t, auditSince(since, "repo.actions_env_variable.deleted"), 1)

			// a write into an environment deleted meanwhile leaves no row behind
			stored := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: env.ID})
			require.NoError(t, actions_service.DeleteEnvironment(ctx, stored))
			_, _, err = secrets_service.CreateOrUpdateSecret(ctx, 0, 0, repo.ID, env.ID, "LATE", "late-value")
			require.ErrorIs(t, err, util.ErrNotExist)
			_, err = actions_service.CreateVariable(ctx, 0, 0, repo.ID, env.ID, "LATE", "late")
			require.ErrorIs(t, err, util.ErrNotExist)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{EnvironmentID: env.ID})
			unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{EnvironmentID: env.ID})
		})

		t.Run("read-only maintenance refuses writes", func(t *testing.T) {
			defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
			put(ownerToken, "frozen", api.CreateOrUpdateEnvironmentOption{}, http.StatusServiceUnavailable)
			MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(ownerToken), http.StatusOK)
		})
		t.Run("archived repository", func(t *testing.T) {
			_, err := db.Exec(ctx, "UPDATE repository SET is_archived = ? WHERE id = ?", true, repo.ID)
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(ctx, "UPDATE repository SET is_archived = ? WHERE id = ?", false, repo.ID)
				require.NoError(t, err)
			}()
			put(ownerToken, "frozen", api.CreateOrUpdateEnvironmentOption{}, http.StatusLocked)
			MakeRequest(t, NewRequest(t, "DELETE", base+"/guarded").AddTokenAuth(ownerToken), http.StatusLocked)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/guarded/secrets/S", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(ownerToken), http.StatusLocked)
			MakeRequest(t, NewRequest(t, "GET", base+"/guarded").AddTokenAuth(ownerToken), http.StatusOK)
		})

		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, repo.Name, "env-api-runner", []string{"env-api"})
		files := 0
		pushJob := func(jobLines string) *actions_model.ActionRunJob {
			files++
			path := fmt.Sprintf(".gitea/workflows/api%d.yml", files)
			content := fmt.Sprintf("on:\n  push:\n    paths:\n      - '%s'\njobs:\n  deploy:\n    runs-on: env-api\n%s    steps:\n      - run: echo\n", path, jobLines)
			fileResp := createWorkflowFile(t, ownerToken, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, "add "+path, content))
			var job *actions_model.ActionRunJob
			require.Eventually(t, func() bool {
				r := new(actions_model.ActionRun)
				if has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repo.ID, fileResp.Commit.SHA).Get(r); err != nil || !has {
					return false
				}
				jobs, err := actions_model.GetRunJobsByRunID(db.DefaultContext, r.ID)
				if err == nil && len(jobs) == 1 {
					job = jobs[0]
				}
				return job != nil
			}, 10*time.Second, 100*time.Millisecond)
			return job
		}
		jobStatus := func(job *actions_model.ActionRunJob) actions_model.Status {
			j := new(actions_model.ActionRunJob)
			if has, err := db.GetEngine(db.DefaultContext).ID(job.ID).Get(j); err != nil || !has {
				return actions_model.StatusUnknown
			}
			return j.Status
		}

		t.Run("a PUT that clears the reviewers releases a waiting job", func(t *testing.T) {
			put(ownerToken, "gated", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusCreated)
			job := pushJob("    environment: gated\n")
			d, err := actions_model.GetDeployment(t.Context(), job.ID, 1)
			require.NoError(t, err)
			require.NotNil(t, d)
			require.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
			assert.Nil(t, runner.maybeFetchTask(t))

			// a stricter PUT keeps it waiting, a PUT without reviewers releases it (the break-glass), audited
			put(ownerToken, "gated", api.CreateOrUpdateEnvironmentOption{WaitTimer: new(1), Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusOK)
			assert.Equal(t, actions_model.StatusBlocked, jobStatus(job))
			since := auditNow()
			put(ownerToken, "gated", api.CreateOrUpdateEnvironmentOption{}, http.StatusOK)
			require.Eventually(t, func() bool { return jobStatus(job) == actions_model.StatusWaiting }, 10*time.Second, 100*time.Millisecond)
			d, err = actions_model.GetDeployment(t.Context(), job.ID, 1)
			require.NoError(t, err)
			assert.Equal(t, actions_model.DeploymentReleased, d.Status)
			entries := auditSince(since, "repo.actions_env.updated")
			require.Len(t, entries, 1)
			assert.Equal(t, []any{"user:4"}, entryData(t, entries[0])["before"].(map[string]any)["reviewers"])

			task := runner.fetchTask(t)
			jobToken := task.Context.Fields["token"].GetStringValue()
			require.NotEmpty(t, jobToken)
			// the job token of the repository's own run is no owner either
			MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(jobToken), http.StatusForbidden)
			put(jobToken, "gated", api.CreateOrUpdateEnvironmentOption{}, http.StatusForbidden)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/gated/secrets/S", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(jobToken), http.StatusForbidden)
			runner.execTask(t, task, &mockTaskOutcome{result: runnerv1.Result_RESULT_SUCCESS})

			// the PUT that tightens the rules refuses a job that waits: a ref pattern its branch doesn't match
			put(ownerToken, "gated", api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}}}, http.StatusOK)
			waiting := pushJob("    environment: gated\n")
			put(ownerToken, "gated", api.CreateOrUpdateEnvironmentOption{
				RefPolicy: "patterns", RefPatterns: []*api.ActionEnvironmentRefPattern{{Type: "branch", Pattern: "release/*"}},
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 4}},
			}, http.StatusOK)
			require.Eventually(t, func() bool { return jobStatus(waiting) == actions_model.StatusFailure }, 10*time.Second, 100*time.Millisecond)
			d, err = actions_model.GetDeployment(t.Context(), waiting.ID, 1)
			require.NoError(t, err)
			assert.Equal(t, actions_model.DeploymentReasonRefNotAllowed, d.Reason)
		})

		t.Run("the deployments list", func(t *testing.T) {
			deployments := fmt.Sprintf("/api/v1/repos/%s/%s/actions/deployments", user2.Name, repo.Name)
			resp := MakeRequest(t, NewRequest(t, "GET", deployments+"?environment=GATED").AddTokenAuth(readerToken), http.StatusOK)
			var out []*api.ActionDeployment
			DecodeJSON(t, resp, &out)
			require.Len(t, out, 2)
			assert.Equal(t, "2", resp.Header().Get("X-Total-Count"))
			assert.Equal(t, "refused", out[0].Status, "newest first")
			assert.Equal(t, "ref_not_allowed", out[0].Reason)
			assert.Equal(t, "released", out[1].Status)
			for _, d := range out {
				assert.Equal(t, "gated", d.Environment)
				assert.Equal(t, "deploy", d.JobName)
				assert.Equal(t, repo.DefaultBranch, strings.TrimPrefix(d.Ref, "refs/heads/"))
				assert.NotEmpty(t, d.CommitSHA)
				assert.Contains(t, d.RunURL, fmt.Sprintf("/%s/%s/actions/runs/", user2.Name, repo.Name))
				require.NotNil(t, d.TriggeredBy)
				assert.Equal(t, user2.Name, d.TriggeredBy.UserName)
				assert.Nil(t, d.Reviewers, "who may review is only in the list of a run")
			}

			resp = MakeRequest(t, NewRequest(t, "GET", deployments+"?limit=1").AddTokenAuth(writerToken), http.StatusOK)
			DecodeJSON(t, resp, &out)
			require.Len(t, out, 1)
			resp = MakeRequest(t, NewRequest(t, "GET", deployments+"?environment=no-such").AddTokenAuth(ownerToken), http.StatusOK)
			DecodeJSON(t, resp, &out)
			assert.Empty(t, out)
			MakeRequest(t, NewRequest(t, "GET", deployments).AddTokenAuth(strangerToken), http.StatusNotFound)
		})

		t.Run("a user the reader can't see is the ghost", func(t *testing.T) {
			deployments := fmt.Sprintf("/api/v1/repos/%s/%s/actions/deployments", user2.Name, repo.Name)
			private := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 31})
			require.Equal(t, api.VisibleTypePrivate, private.Visibility)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET reviewed_by = ?, trigger_user_id = ? WHERE repo_id = ?", private.ID, private.ID, repo.ID)
			require.NoError(t, err)
			_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET is_private = ? WHERE id = ?", false, repo.ID)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET is_private = ? WHERE id = ?", true, repo.ID)
				require.NoError(t, err)
			}()

			var out []*api.ActionDeployment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", deployments), http.StatusOK), &out)
			require.NotEmpty(t, out)
			for _, d := range out {
				require.NotNil(t, d.TriggeredBy)
				require.NotNil(t, d.ReviewedBy)
				assert.Equal(t, user_model.GhostUserName, d.TriggeredBy.UserName, "anonymous")
				assert.Equal(t, user_model.GhostUserName, d.ReviewedBy.UserName, "anonymous")
			}
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", deployments).AddTokenAuth(siteAdminToken), http.StatusOK), &out)
			require.NotEmpty(t, out)
			assert.Equal(t, private.Name, out[0].ReviewedBy.UserName, "a site admin sees the user")
		})
	})
}

// The environments and deployments routes of a repository in a project (org3/repo3), through the project and the
// ID mounts.
func TestAPIActionsEnvironmentsInProject(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	group := createProjectForKeys(t, 3, "envproj")
	moveRepoForKeys(t, 3, group.ID)
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{}})
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	stranger := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)

	for i, base := range []string{
		fmt.Sprintf("/api/v1/repos/org3/%s/repo3/-/actions", group.Name),
		"/api/v1/repositories/3/actions",
	} {
		name := fmt.Sprintf("proj-%d", i)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/environments/"+name,
			envRules(api.CreateOrUpdateEnvironmentOption{Reviewers: []*api.ActionEnvironmentReviewer{{Type: "team", ID: 1}}})).AddTokenAuth(owner), http.StatusCreated)
		env := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{RepoID: 3, LowerName: name})
		assert.True(t, env.ReviewsRequired, "a team of the owning organization")
		MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/environments/"+name+"/secrets/S", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(owner), http.StatusCreated)

		resp := MakeRequest(t, NewRequest(t, "GET", base+"/environments").AddTokenAuth(owner), http.StatusOK)
		var envs []*api.ActionEnvironment
		DecodeJSON(t, resp, &envs)
		require.Len(t, envs, i+1)
		assert.Equal(t, "team", envs[i].Reviewers[0].Type)
		assert.EqualValues(t, 1, envs[i].SecretsCount)

		MakeRequest(t, NewRequest(t, "GET", base+"/environments").AddTokenAuth(stranger), http.StatusNotFound)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/environments/"+name, envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(stranger), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", base+"/deployments").AddTokenAuth(owner), http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", base+"/deployments").AddTokenAuth(stranger), http.StatusNotFound)
	}
}
