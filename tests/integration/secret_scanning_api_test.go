// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	maintenance_service "forgejo.org/services/maintenance"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var secretAlertSeq atomic.Int64

// seedSecretAlert stores an alert with one place, without any scan: the tests of the API need rows, not pushes.
func seedSecretAlert(t *testing.T, repo *repo_model.Repository, rule, secretType, kind, path string) *secretscan_model.Alert {
	t.Helper()
	a := &secretscan_model.Alert{
		RepoID: repo.ID, RuleID: rule, SecretType: secretType, LocationCount: 1,
		Fingerprint: fmt.Sprintf("%064x", secretAlertSeq.Add(1)),
	}
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		if err := secretscan_model.InsertAlert(ctx, a); err != nil {
			return err
		}
		l := secretscan_model.NewLocation(repo.ID, kind, "blob"+a.Fingerprint[:8], path, 3, 3, "commitsha1", "An Author", "author@example.com", 1700000000)
		l.AlertID = a.ID
		_, err := db.GetEngine(ctx).Insert(l)
		return err
	}))
	return a
}

func secretAlertRow(t *testing.T, repoID, index int64) *secretscan_model.Alert {
	t.Helper()
	a, err := secretscan_model.GetAlert(t.Context(), repoID, index)
	require.NoError(t, err)
	return a
}

// seedSecretRepo gives a repository the three alerts of the tests: github (repo), aws (repo) and github (wiki).
func seedSecretRepo(t *testing.T, repo *repo_model.Repository) {
	t.Helper()
	seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindRepo, "deploy/env")
	seedSecretAlert(t, repo, "aws-access-key-id", "aws", secretscan_model.KindRepo, "conf/aws.ini")
	seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindWiki, "Home.md")
}

func TestSecretScanningAPI(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		sys := audit_model.WithSystem(db.DefaultContext, "test")
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		group, err := repo_model.CreateRepoGroup(sys, org3, "sproj", "")
		require.NoError(t, err)
		root := depNewRepo(t, org3, user2, "secret-org", true, 0)
		leaf := depNewRepo(t, org3, user2, "leaf", true, group.ID)
		pub := depNewRepo(t, user2, user2, "secret-pub", false, 0)
		other := depNewRepo(t, org3, user2, "secret-other", true, 0)
		for _, r := range []*repo_model.Repository{root, leaf, pub} {
			seedSecretRepo(t, r)
		}
		for range 5 {
			seedSecretAlert(t, other, "github-token", "github", secretscan_model.KindRepo, "x")
		}
		bases := map[string]struct {
			base string
			repo *repo_model.Repository
		}{
			"plain":      {"/api/v1/repos/org3/secret-org/secret-scanning/alerts", root},
			"id":         {fmt.Sprintf("/api/v1/repositories/%d/secret-scanning/alerts", root.ID), root},
			"project":    {"/api/v1/repos/org3/sproj/leaf/-/secret-scanning/alerts", leaf},
			"project id": {fmt.Sprintf("/api/v1/repositories/%d/secret-scanning/alerts", leaf.ID), leaf},
		}
		do := func(t *testing.T, method, path, token string, body any, status int) *httptest.ResponseRecorder {
			t.Helper()
			var req *RequestWrapper
			if body != nil {
				req = NewRequestWithJSON(t, method, path, body)
			} else {
				req = NewRequest(t, method, path)
			}
			if token != "" {
				req.AddTokenAuth(token)
			}
			return MakeRequest(t, req, status)
		}
		writeToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		readToken := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		closeBody := map[string]string{"state": "resolved", "resolution": "revoked", "resolution_comment": "rotated"}
		unchanged := func(t *testing.T, r *repo_model.Repository, index int64) {
			t.Helper()
			assert.Equal(t, secretscan_model.StateOpen, secretAlertRow(t, r.ID, index).State)
		}

		t.Run("the response", func(t *testing.T) {
			for name, b := range bases {
				var list []*api.SecretScanningAlert
				resp := do(t, "GET", b.base, readToken, nil, http.StatusOK)
				DecodeJSON(t, resp, &list)
				require.Len(t, list, 3, name)
				assert.Equal(t, "3", resp.Header().Get("X-Total-Count"))
				assert.Equal(t, []int64{3, 2, 1}, []int64{list[0].Number, list[1].Number, list[2].Number}, "newest first")
				var one api.SecretScanningAlert
				DecodeJSON(t, do(t, "GET", b.base+"/1", readToken, nil, http.StatusOK), &one)
				assert.EqualValues(t, 1, one.Number)
				assert.Equal(t, "open", one.State)
				assert.Equal(t, "github-token", one.SecretType)
				assert.Equal(t, "GitHub token", one.SecretTypeDisplayName)
				assert.Len(t, one.Fingerprint, 64)
				assert.Equal(t, b.repo.HTMLURL()+"/security/secrets/1", one.HTMLURL)
				assert.Equal(t, b.repo.APIURL()+"/secret-scanning/alerts/1/locations", one.LocationsURL)
				assert.Equal(t, b.repo.APIURL()+"/secret-scanning/alerts/1", one.URL)
				assert.Equal(t, 1, one.LocationsCount)
				assert.Nil(t, one.ResolvedBy)
				assert.Empty(t, one.Resolution)
				assert.False(t, one.ViaPull)
				var locs []*api.SecretScanningLocation
				resp = do(t, "GET", b.base+"/1/locations", readToken, nil, http.StatusOK)
				DecodeJSON(t, resp, &locs)
				assert.Equal(t, "1", resp.Header().Get("X-Total-Count"))
				require.Len(t, locs, 1)
				l := locs[0]
				assert.Equal(t, "commit", l.Type)
				d := l.Details
				assert.Equal(t, "deploy/env", d.Path)
				assert.Equal(t, 3, d.StartLine)
				assert.Equal(t, "commitsha1", d.CommitSHA)
				assert.Equal(t, b.repo.APIURL()+"/git/commits/commitsha1", d.CommitURL)
				assert.Equal(t, "An Author", d.CommitAuthorName)
				assert.Equal(t, "author@example.com", d.CommitAuthorEmail)
				require.NotNil(t, d.CommitDate)
				assert.Equal(t, b.repo.HTMLURL()+"/src/commit/commitsha1/deploy/env#L3", d.HTMLURL)
				assert.False(t, d.PullRef)
				locs = nil // decoding into old elements keeps their fields
				DecodeJSON(t, do(t, "GET", b.base+"/3/locations", readToken, nil, http.StatusOK), &locs)
				require.Len(t, locs, 1)
				assert.Equal(t, "wiki_commit", locs[0].Type)
				assert.Equal(t, b.repo.HTMLURL()+"/wiki/Home", locs[0].Details.PageURL)
				assert.Empty(t, locs[0].Details.CommitURL, "the API has no wiki commits")
			}
		})

		t.Run("filters and pages", func(t *testing.T) {
			base := bases["plain"].base
			count := func(query string) (n int, total string) {
				var list []*api.SecretScanningAlert
				resp := do(t, "GET", base+query, readToken, nil, http.StatusOK)
				DecodeJSON(t, resp, &list)
				return len(list), resp.Header().Get("X-Total-Count")
			}
			for query, want := range map[string]int{
				"?state=open": 3, "?state=resolved": 0, "?resolution=revoked": 0, "?secret_type=aws-access-key-id": 1,
				"?secret_type=github-token": 2, "?secret_type=github-token,aws-access-key-id": 3, "?secret_type=aws-access-key-id&state=open": 1,
				"?secret_type=nothing": 0,
			} {
				n, _ := count(query)
				assert.Equal(t, want, n, query)
			}
			var list []*api.SecretScanningAlert
			DecodeJSON(t, do(t, "GET", base+"?direction=asc", readToken, nil, http.StatusOK), &list)
			assert.Equal(t, []int64{1, 2, 3}, []int64{list[0].Number, list[1].Number, list[2].Number})
			DecodeJSON(t, do(t, "GET", base+"?sort=updated&direction=desc", readToken, nil, http.StatusOK), &list)
			assert.Len(t, list, 3)
			n, total := count("?limit=2&page=2")
			assert.Equal(t, 1, n)
			assert.Equal(t, "3", total)
			for _, bad := range []string{"state=closed", "state=revoked", "state=bogus", "resolution=fixed", "resolution=revoked,bogus", "sort=name", "direction=up", "secret_type=" + strings.Repeat("a", 65)} {
				do(t, "GET", base+"?"+bad, readToken, nil, http.StatusUnprocessableEntity)
			}
		})

		t.Run("who is refused, before any validation", func(t *testing.T) {
			missing := do(t, "GET", "/api/v1/repos/org3/no-such-repo/secret-scanning/alerts", readToken, nil, http.StatusNotFound).Body.String()
			session := loginUser(t, "user2")
			publicOnly := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadRepository)
			readIssue := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadIssue)
			user4Token := getUserToken(t, "user4", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", &api.CreateAccessTokenOption{
				Name: "secret-limited", Scopes: []string{string(auth_model.AccessTokenScopeWriteRepository)},
				Repositories: []*api.RepoTargetOption{{Owner: "user2", Name: "repo2"}},
			})
			req.AddBasicAuth("user2")
			var limited api.AccessToken
			DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &limited)

			for name, b := range bases {
				one := b.base + "/1"
				// anonymous, an org member without access, and the bad filter or ID or body behind none of them
				for _, token := range []string{"", user4Token} {
					assert.Equal(t, missing, do(t, "GET", b.base, token, nil, http.StatusNotFound).Body.String(), name)
					do(t, "GET", b.base+"?state=bogus", token, nil, http.StatusNotFound)
					do(t, "GET", b.base+"/abc", token, nil, http.StatusNotFound)
					do(t, "GET", one, token, nil, http.StatusNotFound)
					do(t, "PATCH", one, token, map[string]string{"state": "bogus"}, http.StatusNotFound)
					do(t, "PATCH", b.base+"/999", token, map[string]string{"state": "bogus"}, http.StatusNotFound)
				}
				// a reader of the code is not enough; a writer is
				require.NoError(t, repo_module.AddCollaborator(sys, b.repo, user4, perm_model.AccessModeRead))
				do(t, "GET", b.base, user4Token, nil, http.StatusNotFound)
				do(t, "PATCH", one, user4Token, closeBody, http.StatusNotFound)
				require.NoError(t, repo_module.ChangeCollaborationAccessMode(sys, b.repo, user4.ID, perm_model.AccessModeWrite))
				do(t, "GET", b.base, user4Token, nil, http.StatusOK)
				require.NoError(t, repo_module.ChangeCollaborationAccessMode(sys, b.repo, user4.ID, perm_model.AccessModeAdmin))
				do(t, "GET", one, user4Token, nil, http.StatusOK)
				require.NoError(t, repo_module.DeleteCollaboration(sys, b.repo, user4.ID))
				do(t, "GET", b.base, user4Token, nil, http.StatusNotFound)

				// tokens
				do(t, "GET", b.base, publicOnly, nil, http.StatusNotFound)
				do(t, "GET", b.base, readIssue, nil, http.StatusForbidden)
				do(t, "GET", b.base, limited.Token, nil, http.StatusNotFound) // limited to another repository
				do(t, "PATCH", one, readToken, closeBody, http.StatusForbidden)
				readOwned := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, b.repo.ID, 0, perm_model.AccessModeRead, "write:repository")
				do(t, "GET", b.base, readOwned.Token, nil, http.StatusNotFound)
				do(t, "PATCH", one, readOwned.Token, closeBody, http.StatusNotFound)
				writeOwned := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, b.repo.ID, 0, perm_model.AccessModeWrite, "write:repository")
				do(t, "GET", b.base, writeOwned.Token, nil, http.StatusOK)
				unchanged(t, b.repo, 1)
			}
			// a public repository is no exception
			pubBase := "/api/v1/repos/user2/secret-pub/secret-scanning/alerts"
			do(t, "GET", pubBase, "", nil, http.StatusNotFound)
			do(t, "GET", pubBase, user4Token, nil, http.StatusNotFound)
			do(t, "GET", pubBase, publicOnly, nil, http.StatusOK) // the writer's public-only token reads a public repository
			do(t, "PATCH", pubBase+"/1", "", closeBody, http.StatusNotFound)
		})

		t.Run("who sees them", func(t *testing.T) {
			admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeWriteRepository)
			orgOwner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
			orgOwnedToken := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeWrite, "write:repository")
			for name, b := range bases {
				for _, token := range []string{admin, orgOwner, orgOwnedToken.Token} {
					var locs []*api.SecretScanningLocation
					DecodeJSON(t, do(t, "GET", b.base+"/1/locations", token, nil, http.StatusOK), &locs)
					assert.Len(t, locs, 1, name)
				}
				// a repository admin who is no owner
				require.NoError(t, repo_module.AddCollaborator(sys, b.repo, user4, perm_model.AccessModeAdmin))
				do(t, "GET", b.base+"/1", getUserToken(t, "user4", auth_model.AccessTokenScopeReadRepository), nil, http.StatusOK)
				require.NoError(t, repo_module.DeleteCollaboration(sys, b.repo, user4.ID))
			}
		})

		t.Run("who can resolve", func(t *testing.T) {
			user4Token := getUserToken(t, "user4", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeWriteRepository)
			admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeWriteRepository)
			orgOwned := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeWrite, "write:repository")
			session := loginUser(t, "user2")
			readOnly := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
			req := NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", &api.CreateAccessTokenOption{
				Name: "secret-limited-patch", Scopes: []string{string(auth_model.AccessTokenScopeWriteRepository)},
				Repositories: []*api.RepoTargetOption{{Owner: "user2", Name: "repo2"}},
			})
			req.AddBasicAuth("user2")
			var limited api.AccessToken
			DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &limited)
			for name, b := range bases {
				resolveAndReopen := func(token string) {
					t.Helper()
					var got api.SecretScanningAlert
					DecodeJSON(t, do(t, "PATCH", b.base+"/1", token, closeBody, http.StatusOK), &got)
					assert.Equal(t, "resolved", got.State, name)
					DecodeJSON(t, do(t, "PATCH", b.base+"/1", token, map[string]string{"state": "open"}, http.StatusOK), &got)
					assert.Equal(t, "open", got.State, name)
				}
				resolveAndReopen(admin)
				resolveAndReopen(orgOwned.Token)
				for _, mode := range []perm_model.AccessMode{perm_model.AccessModeWrite, perm_model.AccessModeAdmin} { // a writer, a repository admin
					require.NoError(t, repo_module.AddCollaborator(sys, b.repo, user4, mode))
					resolveAndReopen(user4Token)
					require.NoError(t, repo_module.DeleteCollaboration(sys, b.repo, user4.ID))
				}
				do(t, "PATCH", b.base+"/1", limited.Token, closeBody, http.StatusNotFound) // limited to another repository
				do(t, "PATCH", b.base+"/1", readOnly, closeBody, http.StatusForbidden)
				unchanged(t, b.repo, 1)
			}
		})

		t.Run("auditor reads, never writes", func(t *testing.T) {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", false)
				require.NoError(t, err)
			}()
			auditor := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository)
			for name, b := range bases {
				var list []*api.SecretScanningAlert
				DecodeJSON(t, do(t, "GET", b.base, auditor, nil, http.StatusOK), &list)
				assert.Len(t, list, 3, name)
				do(t, "GET", b.base+"/1", auditor, nil, http.StatusOK)
				do(t, "PATCH", b.base+"/1", auditor, closeBody, http.StatusNotFound)
				unchanged(t, b.repo, 1)
			}
			// not the alerts of a repository whose code the auditor can't read (the Code unit is off)
			removeCodeUnit(t, root.ID)
			for _, name := range []string{"plain", "id"} {
				do(t, "GET", bases[name].base, auditor, nil, http.StatusNotFound)
				do(t, "GET", bases[name].base+"/1", auditor, nil, http.StatusNotFound)
				do(t, "GET", bases[name].base+"/1/locations", auditor, nil, http.StatusNotFound)
				do(t, "GET", strings.TrimSuffix(bases[name].base, "/alerts")+"/status", auditor, nil, http.StatusNotFound)
			}
		})

		t.Run("job tokens", func(t *testing.T) {
			original := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
			t.Cleanup(func() {
				require.NoError(t, actions_model.UpdateTask(db.DefaultContext, original, "repo_id", "owner_id", "is_fork_pull_request", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
			})
			for _, b := range bases {
				task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
				task.RepoID, task.OwnerID, task.IsForkPullRequest, task.TokenPermissions = b.repo.ID, b.repo.OwnerID, false, ""
				task.GenerateToken()
				require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "is_fork_pull_request", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))
				do(t, "GET", b.base, task.Token, nil, http.StatusNotFound)
				do(t, "GET", b.base+"/1", task.Token, nil, http.StatusNotFound)
				do(t, "PATCH", b.base+"/1", task.Token, closeBody, http.StatusForbidden)
				unchanged(t, b.repo, 1)
			}
		})

		t.Run("close and reopen", func(t *testing.T) {
			for name, b := range bases {
				for i, state := range secretscan_model.ClosedStates[:3] {
					index := int64(i + 1)
					since := auditMaxID(t)
					var got api.SecretScanningAlert
					DecodeJSON(t, do(t, "PATCH", fmt.Sprintf("%s/%d", b.base, index), writeToken, map[string]string{"state": "resolved", "resolution": state, "resolution_comment": "because <b>" + state}, http.StatusOK), &got)
					assert.Equal(t, "resolved", got.State, name)
					assert.Equal(t, state, got.Resolution)
					assert.Equal(t, "because <b>"+state, got.ResolutionComment)
					require.NotNil(t, got.ResolvedBy)
					assert.Equal(t, user2.ID, got.ResolvedBy.ID)
					assert.NotNil(t, got.ResolvedAt)
					row := secretAlertRow(t, b.repo.ID, index)
					assert.Equal(t, state, row.State)
					assert.Equal(t, state, row.Reason)
					assert.Equal(t, user2.ID, row.ClosedByID)
					assert.NotZero(t, row.ClosedUnix)
					e := auditOne(t, since, "repo.secret_alert.closed")
					assert.Equal(t, "secret_scanning_alert", e.TargetType)
					assert.Equal(t, b.repo.ID, e.RepoID)
					assert.Equal(t, row.ID, e.TargetID)
					data := auditData(t, e)
					assert.EqualValues(t, index, data["index"])
					assert.Equal(t, row.RuleID, data["rule"])
					assert.Equal(t, row.Fingerprint[:12], data["fingerprint"])
					assert.Equal(t, "open", data["previous_state"])
					assert.Equal(t, state, data["state"])
					assert.Equal(t, "because <b>"+state, data["comment"])
					assert.NotEmpty(t, data["path"])
				}
				// closed alerts are in the closed filter and out of the open one
				var list []*api.SecretScanningAlert
				DecodeJSON(t, do(t, "GET", b.base+"?state=resolved", readToken, nil, http.StatusOK), &list)
				assert.Len(t, list, 3)
				DecodeJSON(t, do(t, "GET", b.base+"?resolution=used_in_tests,wont_fix", readToken, nil, http.StatusOK), &list)
				assert.Len(t, list, 1)

				// a closed alert can't be closed again
				do(t, "PATCH", b.base+"/1", writeToken, map[string]string{"state": "resolved", "resolution": "false_positive"}, http.StatusConflict)
				assert.Equal(t, "revoked", secretAlertRow(t, b.repo.ID, 1).State)

				for index := int64(1); index <= 3; index++ {
					since := auditMaxID(t)
					var got api.SecretScanningAlert
					DecodeJSON(t, do(t, "PATCH", fmt.Sprintf("%s/%d", b.base, index), writeToken, map[string]string{"state": "open"}, http.StatusOK), &got)
					assert.Equal(t, "open", got.State)
					assert.Empty(t, got.Resolution)
					assert.Empty(t, got.ResolutionComment)
					assert.Nil(t, got.ResolvedBy)
					assert.Nil(t, got.ResolvedAt)
					row := secretAlertRow(t, b.repo.ID, index)
					assert.Equal(t, secretscan_model.StateOpen, row.State)
					assert.Empty(t, row.Reason)
					assert.Empty(t, row.Comment)
					assert.Zero(t, row.ClosedByID)
					assert.Zero(t, row.ClosedUnix)
					data := auditData(t, auditOne(t, since, "repo.secret_alert.reopened"))
					assert.EqualValues(t, index, data["index"])
					assert.Equal(t, "open", data["state"])
					assert.NotEqual(t, "open", data["previous_state"])
				}
				// won't fix, the resolution GitHub has besides ours
				since := auditMaxID(t)
				var wf api.SecretScanningAlert
				DecodeJSON(t, do(t, "PATCH", b.base+"/1", writeToken, map[string]string{"state": "resolved", "resolution": "wont_fix", "resolution_comment": "accepted"}, http.StatusOK), &wf)
				assert.Equal(t, "resolved", wf.State, name)
				assert.Equal(t, "wont_fix", wf.Resolution)
				assert.Equal(t, secretscan_model.StateWontFix, secretAlertRow(t, b.repo.ID, 1).State)
				assert.Equal(t, "wont_fix", auditData(t, auditOne(t, since, "repo.secret_alert.closed"))["state"])
				DecodeJSON(t, do(t, "GET", b.base+"?resolution=wont_fix", readToken, nil, http.StatusOK), &list)
				assert.Len(t, list, 1)
				do(t, "PATCH", b.base+"/1", writeToken, map[string]string{"state": "open"}, http.StatusOK)

				// reopening an open alert changes nothing and records nothing
				since = auditMaxID(t)
				do(t, "PATCH", b.base+"/1", writeToken, map[string]string{"state": "open"}, http.StatusOK)
				n, err := db.GetEngine(t.Context()).Where("id > ? AND action LIKE ?", since, "repo.secret_alert.%").Count(new(audit_model.Entry))
				require.NoError(t, err)
				assert.Zero(t, n)
			}
		})

		t.Run("validation", func(t *testing.T) {
			base := bases["plain"].base
			one := base + "/2"
			tok := secretToken("comment")
			body := strings.TrimPrefix(tok, "ghp"+"_")
			lc, cancel := test.NewLogChecker(log.DEFAULT, log.TRACE)
			defer cancel()
			lc.Filter(tok, body).StopMark("secret-comment-stop")
			resolve := func(resolution, comment string) map[string]string {
				return map[string]string{"state": "resolved", "resolution": resolution, "resolution_comment": comment}
			}
			for _, bad := range []map[string]string{
				{"state": "bogus"},
				{"state": "revoked"},
				{"state": ""},
				{"state": "closed"},
				{"state": "RESOLVED", "resolution": "revoked"},
				{"state": "resolved"},
				{"state": "resolved", "resolution": "fixed"},
				{"state": "resolved", "resolution": "REVOKED"},
				resolve("revoked", strings.Repeat("a", 1001)),
				resolve("wont_fix", ""), // won't fix needs a comment that is not empty once cleaned
				resolve("wont_fix", "  \r\n \n"),
				resolve("wont_fix", string([]rune{0x200b, 0x2060, ' ', 0x200d})),
				resolve("revoked", "see "+tok),
				resolve("false_positive", "key="+tok),
				{"state": "open", "resolution_comment": "x"},
				{"state": "open", "resolution": "revoked"},
			} {
				do(t, "PATCH", one, writeToken, bad, http.StatusUnprocessableEntity)
			}
			msg := do(t, "PATCH", one, writeToken, map[string]string{"state": "resolved"}, http.StatusUnprocessableEntity).Body.String()
			assert.Contains(t, msg, "resolution")
			for _, r := range secretscan_model.ClosedStates {
				assert.Contains(t, msg, r)
			}
			do(t, "PATCH", one, writeToken, resolve("revoked", strings.Repeat("é", 500)), http.StatusOK) // 1000 bytes
			do(t, "PATCH", one, writeToken, map[string]string{"state": "open"}, http.StatusOK)
			for _, bad := range []map[string]string{{"state": "bogus"}, resolve("revoked", "see "+tok)} {
				do(t, "PATCH", bases["project"].base+"/2", writeToken, bad, http.StatusUnprocessableEntity)
			}
			// the control characters of a comment are stripped
			var got api.SecretScanningAlert
			DecodeJSON(t, do(t, "PATCH", one, writeToken, resolve("revoked", "a\x00b\x1b[31mc"), http.StatusOK), &got)
			assert.NotContains(t, got.ResolutionComment, "\x00")
			assert.NotContains(t, got.ResolutionComment, "\x1b")
			do(t, "PATCH", one, writeToken, map[string]string{"state": "open"}, http.StatusOK)

			for _, table := range []string{"secret_scanning_alert", "audit_event"} {
				rows, err := db.GetEngine(t.Context()).Query("SELECT * FROM " + table)
				require.NoError(t, err)
				for _, row := range rows {
					for col, v := range row {
						assert.NotContains(t, string(v), tok, "%s.%s", table, col)
						assert.NotContains(t, string(v), body, "%s.%s", table, col)
					}
				}
			}
			log.Info("secret-comment-stop")
			seen, stopped := lc.Check(5 * time.Second)
			require.True(t, stopped)
			assert.Equal(t, []bool{false, false}, seen)
		})

		t.Run("unknown and foreign alerts", func(t *testing.T) {
			for _, b := range bases {
				for _, index := range []string{"999999", "0", "-1", "abc", "4", "5"} {
					do(t, "GET", b.base+"/"+index, readToken, nil, http.StatusNotFound)
					do(t, "PATCH", b.base+"/"+index, writeToken, closeBody, http.StatusNotFound)
				}
			}
			// number 5 is the other repository's alert; it was not touched
			unchanged(t, other, 5)
		})

		t.Run("archived", func(t *testing.T) {
			require.NoError(t, repo_service.SetArchiveRepoState(sys, root, true))
			defer func() { require.NoError(t, repo_service.SetArchiveRepoState(sys, root, false)) }()
			for _, name := range []string{"plain", "id"} {
				do(t, "PATCH", bases[name].base+"/1", writeToken, closeBody, http.StatusLocked)
				do(t, "PATCH", bases[name].base+"/1", writeToken, map[string]string{"state": "open"}, http.StatusLocked)
				do(t, "GET", bases[name].base+"/1", readToken, nil, http.StatusOK)
			}
			unchanged(t, root, 1)
			// the gate comes first: someone who can't see alerts gets 404, not 423
			do(t, "PATCH", bases["plain"].base+"/1", "", closeBody, http.StatusNotFound)
		})

		t.Run("maintenance read-only", func(t *testing.T) {
			require.NoError(t, maintenance_service.Set(sys, nil, setting.MaintenanceReadOnly, "Upgrade", time.Time{}))
			defer func() {
				require.NoError(t, maintenance_service.Set(sys, nil, setting.MaintenanceOff, "", time.Time{}))
			}()
			do(t, "PATCH", bases["plain"].base+"/1", writeToken, closeBody, http.StatusServiceUnavailable)
			do(t, "GET", bases["plain"].base+"/1", writeToken, nil, http.StatusOK)
			unchanged(t, root, 1)
		})

		t.Run("scan status", func(t *testing.T) {
			statusOf := func(name string) string { return strings.TrimSuffix(bases[name].base, "/alerts") + "/status" }
			var st api.SecretScanningStatus
			DecodeJSON(t, do(t, "GET", statusOf("project"), readToken, nil, http.StatusOK), &st)
			assert.Equal(t, "pending", st.Status, "no scan yet")

			tips := `["` + strings.Repeat("a", 40) + `"]`
			save := func(kind, status, code string, holes, skipped int64) {
				require.NoError(t, secretscan_model.Save(t.Context(), nil, &secretscan_model.Scan{
					RepoID: root.ID, Kind: kind, ScannedTips: tips, Status: status, Error: code, Holes: holes, SkippedLarge: skipped,
				}))
			}
			save(secretscan_model.KindRepo, secretscan_model.StatusOK, "", 0, 2)
			save(secretscan_model.KindWiki, secretscan_model.StatusIncomplete, "over_limit", 3, 0)
			save(secretscan_model.KindPull, secretscan_model.StatusOK, "", 1, 0)
			for _, name := range []string{"plain", "id"} {
				resp := do(t, "GET", statusOf(name), readToken, nil, http.StatusOK)
				DecodeJSON(t, resp, &st)
				assert.Equal(t, secretscan_model.StatusIncomplete, st.Status)
				assert.Equal(t, "over_limit", st.Reason)
				assert.EqualValues(t, 4, st.Holes)
				assert.EqualValues(t, 2, st.SkippedLarge)
				require.NotNil(t, st.LastScanned)
				assert.NotContains(t, resp.Body.String(), "scanned_tips")
				assert.NotContains(t, resp.Body.String(), strings.Repeat("a", 40), "no tips")
			}
			// a failed kind decides
			_, err := db.GetEngine(t.Context()).Exec("UPDATE secret_scan SET status = ?, error = ? WHERE repo_id = ? AND kind = ?", secretscan_model.StatusFailed, "git_error", root.ID, secretscan_model.KindPull)
			require.NoError(t, err)
			DecodeJSON(t, do(t, "GET", statusOf("plain"), readToken, nil, http.StatusOK), &st)
			assert.Equal(t, secretscan_model.StatusFailed, st.Status)
			assert.Equal(t, "git_error", st.Reason)
			// the same gate as the alerts
			do(t, "GET", statusOf("plain"), "", nil, http.StatusNotFound)
			do(t, "GET", statusOf("plain"), getUserToken(t, "user4", auth_model.AccessTokenScopeReadRepository), nil, http.StatusNotFound)
		})

		t.Run("an alert only a pull ref reaches says so", func(t *testing.T) {
			a := seedSecretAlert(t, root, "github-token", "github", secretscan_model.KindRepo, "pull.txt")
			_, err := db.GetEngine(t.Context()).Exec("UPDATE secret_scanning_alert SET via_pull = ? WHERE id = ?", true, a.ID)
			require.NoError(t, err)
			var one api.SecretScanningAlert
			DecodeJSON(t, do(t, "GET", fmt.Sprintf("%s/%d", bases["plain"].base, a.Index), readToken, nil, http.StatusOK), &one)
			assert.True(t, one.ViaPull)
			DecodeJSON(t, do(t, "GET", bases["plain"].base+"/1", readToken, nil, http.StatusOK), &one)
			assert.False(t, one.ViaPull)
			_, err = db.GetEngine(t.Context()).Exec("DELETE FROM secret_scanning_location WHERE alert_id = ?", a.ID)
			require.NoError(t, err)
			_, err = db.GetEngine(t.Context()).Exec("DELETE FROM secret_scanning_alert WHERE id = ?", a.ID)
			require.NoError(t, err)
		})

		t.Run("switched off", func(t *testing.T) {
			root.SecretScanningDisabled = true
			require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), root, "secret_scanning_disabled"))
			for _, name := range []string{"plain", "id"} {
				do(t, "GET", bases[name].base, writeToken, nil, http.StatusNotFound)
				do(t, "GET", bases[name].base+"/1", writeToken, nil, http.StatusNotFound)
				do(t, "GET", strings.TrimSuffix(bases[name].base, "/alerts")+"/status", writeToken, nil, http.StatusNotFound)
				do(t, "PATCH", bases[name].base+"/1", writeToken, closeBody, http.StatusNotFound)
			}
			unchanged(t, root, 1)
			do(t, "GET", bases["project"].base, writeToken, nil, http.StatusOK) // another repository
			root.SecretScanningDisabled = false
			require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), root, "secret_scanning_disabled"))
			do(t, "GET", bases["plain"].base, writeToken, nil, http.StatusOK)
		})
	})
}

// the wiki is closed to a Code writer without Wiki access: its places are not listed or counted for them, and an
// alert that is only in the wiki is missing
func TestSecretScanningAPIWikiNeedsWikiRead(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		ctx := db.DefaultContext
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		repo := depNewRepo(t, org3, user2, "secret-wiki-read", true, 0)
		seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindRepo, "code.txt")              // 1: code only
		seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindWiki, "Deploy-Credentials.md") // 2: wiki only
		both := seedSecretAlert(t, repo, "aws-access-key-id", "aws", secretscan_model.KindRepo, "both.txt")    // 3: code and wiki
		l := secretscan_model.NewLocation(repo.ID, secretscan_model.KindWiki, "blobw", "Both.md", 1, 1, "wikicommit", "Wiki Author", "wiki@example.com", 1700000000)
		l.AlertID = both.ID
		_, err := db.GetEngine(ctx).Insert(l)
		require.NoError(t, err)
		require.NoError(t, secretscan_model.Save(ctx, nil, &secretscan_model.Scan{RepoID: repo.ID, Kind: secretscan_model.KindWiki, ScannedTips: "[]", Status: secretscan_model.StatusFailed, Error: "git_error"}))

		team := &organization.Team{OrgID: org3.ID, Name: "codeonly", LowerName: "codeonly", AccessMode: perm_model.AccessModeWrite}
		require.NoError(t, db.Insert(ctx, team))
		require.NoError(t, db.Insert(ctx, &organization.TeamUnit{OrgID: org3.ID, TeamID: team.ID, Type: unit.TypeCode, AccessMode: perm_model.AccessModeWrite}))
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: org3.ID, TeamID: team.ID, RepoID: repo.ID}))
		require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: org3.ID, TeamID: team.ID, UID: user5.ID}))
		require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: org3.ID, UID: user5.ID}))
		require.NoError(t, access_model.RecalculateAccesses(ctx, repo))
		perm, err := access_model.GetUserRepoPermission(ctx, repo, user5)
		require.NoError(t, err)
		require.True(t, perm.CanWrite(unit.TypeCode))
		require.False(t, perm.CanRead(unit.TypeWiki))

		numbers := func(list []*api.SecretScanningAlert) (out []int64) {
			for _, a := range list {
				out = append(out, a.Number)
			}
			return out
		}
		codeOnly := getUserToken(t, "user5", auth_model.AccessTokenScopeReadRepository)
		owner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		check := func(t *testing.T, name, b, token string, wantList []int64, wikiShown bool) {
			t.Helper()
			get := func(path string, code int) *httptest.ResponseRecorder {
				return MakeRequest(t, NewRequest(t, "GET", b+path).AddTokenAuth(token), code)
			}
			var list []*api.SecretScanningAlert
			resp := get("/alerts", http.StatusOK)
			DecodeJSON(t, resp, &list)
			assert.Equal(t, wantList, numbers(list), name)
			assert.Equal(t, fmt.Sprint(len(wantList)), resp.Header().Get("X-Total-Count"), name)

			var one api.SecretScanningAlert
			var locs []*api.SecretScanningLocation
			if wikiShown {
				get("/alerts/2", http.StatusOK)
				DecodeJSON(t, get("/alerts/2/locations", http.StatusOK), &locs)
				require.Len(t, locs, 1, name)
				assert.Equal(t, "Deploy-Credentials.md", locs[0].Details.Path)
			} else {
				get("/alerts/2", http.StatusNotFound)
				get("/alerts/2/locations", http.StatusNotFound)
			}
			// the alert in both: the count is what the locations endpoint's total says
			DecodeJSON(t, get("/alerts/3", http.StatusOK), &one)
			resp = get("/alerts/3/locations", http.StatusOK)
			body := resp.Body.String()
			locs = nil
			DecodeJSON(t, resp, &locs)
			assert.Equal(t, fmt.Sprint(one.LocationsCount), resp.Header().Get("X-Total-Count"), name)
			assert.Len(t, locs, one.LocationsCount, name)
			assert.Equal(t, wikiShown, one.LocationsCount == 2, name)
			assert.Equal(t, wikiShown, strings.Contains(body, "Both.md"), name)
			assert.Equal(t, wikiShown, strings.Contains(body, "wiki@example.com"), name)
		}
		for name, b := range map[string]string{
			"plain": "/api/v1/repos/org3/secret-wiki-read/secret-scanning", "id": fmt.Sprintf("/api/v1/repositories/%d/secret-scanning", repo.ID),
		} {
			check(t, name, b, codeOnly, []int64{3, 1}, false)
			check(t, name, b, owner, []int64{3, 2, 1}, true)
			// the state of the wiki scan is for those who can read the wiki
			var st api.SecretScanningStatus
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", b+"/status").AddTokenAuth(codeOnly), http.StatusOK), &st)
			assert.Equal(t, "pending", st.Status, name)
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", b+"/status").AddTokenAuth(owner), http.StatusOK), &st)
			assert.Equal(t, secretscan_model.StatusFailed, st.Status, name)
			// the wiki alert can't be reached by guessing its number
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", b+"/alerts/2", map[string]string{"state": "resolved", "resolution": "revoked"}).AddTokenAuth(getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)), http.StatusNotFound)
		}
		assert.Equal(t, secretscan_model.StateOpen, secretAlertRow(t, repo.ID, 2).State)

		t.Run("the comment check doesn't confirm a secret that is only in the wiki", func(t *testing.T) {
			wikiSecret := "wJalrXUtn" + "FEMI/K7MDENG/" + "bPxRfiCY" + "Zq3vT8kLm1"
			_, err := db.GetEngine(t.Context()).Exec("UPDATE secret_scanning_alert SET fingerprint = ? WHERE repo_id = ? AND `index` = 2", secretdetection.Fingerprint([]byte(wikiSecret)), repo.ID)
			require.NoError(t, err)
			one := "/api/v1/repos/org3/secret-wiki-read/secret-scanning/alerts/1"
			resolve := func(user, comment string, status int) {
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "resolved", "resolution": "revoked", "resolution_comment": comment}).AddTokenAuth(getUserToken(t, user, auth_model.AccessTokenScopeWriteRepository)), status)
			}
			resolve("user5", "old key "+wikiSecret, http.StatusOK)
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "open"}).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)), http.StatusOK)
			resolve("user2", "old key "+wikiSecret, http.StatusUnprocessableEntity)
		})

		t.Run("an auditor reads the wiki places", func(t *testing.T) {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", false)
				require.NoError(t, err)
			}()
			check(t, "auditor", "/api/v1/repos/org3/secret-wiki-read/secret-scanning", getUserToken(t, "user8", auth_model.AccessTokenScopeReadRepository), []int64{3, 2, 1}, true)
		})

		t.Run("with the Wiki unit off nobody sees wiki places", func(t *testing.T) {
			var row repo_model.RepoUnit
			has, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repo.ID, unit.TypeWiki).Get(&row)
			require.NoError(t, err)
			require.True(t, has)
			_, err = db.GetEngine(t.Context()).ID(row.ID).Delete(new(repo_model.RepoUnit))
			require.NoError(t, err)
			defer func() { require.NoError(t, db.Insert(t.Context(), &row)) }()
			check(t, "owner", "/api/v1/repos/org3/secret-wiki-read/secret-scanning", owner, []int64{3, 1}, false)
		})
	})
}

// the places of an alert are paged, and a place that only a pull ref reaches links to its commit
func TestSecretScanningAPILocations(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo := depNewRepo(t, org3, user2, "secret-locations", true, 0)
		a := seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindRepo, "p0.txt")
		for i := 1; i < 5; i++ {
			l := secretscan_model.NewLocation(repo.ID, secretscan_model.KindRepo, "blobx", fmt.Sprintf("p%d.txt", i), i, i, "commitsha1", "An Author", "author@example.com", 1700000000)
			l.AlertID = a.ID
			_, err := db.GetEngine(t.Context()).Insert(l)
			require.NoError(t, err)
		}
		// a real AGit push: the scan of the pull refs stores the place
		writeToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		inPull := secretToken("api-pull")
		sha := depPush(t, u, writeToken, repo, "refs/for/main", map[string]string{"dir/pull file.txt": strings.Repeat("\n", 6) + "key " + inPull + "\n"})
		pullAlert := secretAlertOf(t, repo.ID, inPull)
		pullLocs := secretLocations(t, pullAlert.ID)
		require.Len(t, pullLocs, 1)
		assert.Equal(t, secretscan_model.KindPull, pullLocs[0].Kind)

		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		base := "/api/v1/repos/org3/secret-locations/secret-scanning/alerts/1/locations"
		var locs []*api.SecretScanningLocation
		resp := MakeRequest(t, NewRequest(t, "GET", base+"?limit=2&page=2").AddTokenAuth(token), http.StatusOK)
		DecodeJSON(t, resp, &locs)
		assert.Equal(t, "5", resp.Header().Get("X-Total-Count"))
		assert.Equal(t, []string{"p2.txt", "p3.txt"}, []string{locs[0].Details.Path, locs[1].Details.Path}, "in the order they were found")
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", base+"?limit=2&page=3").AddTokenAuth(token), http.StatusOK), &locs)
		require.Len(t, locs, 1)
		assert.False(t, locs[0].Details.PullRef)
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/org3/secret-locations/secret-scanning/alerts/%d/locations", pullAlert.Index)).AddTokenAuth(token), http.StatusOK), &locs)
		require.Len(t, locs, 1)
		assert.Equal(t, "commit", locs[0].Type)
		assert.True(t, locs[0].Details.PullRef)
		assert.Equal(t, repo.HTMLURL()+"/src/commit/"+sha+"/dir/pull%20file.txt#L7", locs[0].Details.HTMLURL)
		assert.Equal(t, repo.APIURL()+"/git/blobs/"+pullLocs[0].BlobID, locs[0].Details.BlobURL)
		page := secretPage(t, loginUser(t, "user2"), fmt.Sprintf("/org3/secret-locations/security/secrets/%d", pullAlert.Index), http.StatusOK)
		assert.Equal(t, "Pull request refs", strings.TrimSpace(page.Find(".repo-security-row .ui.basic.mini.label").Text()))
		MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(getUserToken(t, "user4", auth_model.AccessTokenScopeReadRepository)), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/secret-locations/secret-scanning/alerts/9/locations").AddTokenAuth(token), http.StatusNotFound)
	})
}

// the comment of a resolved alert is cleaned, and can't hold the secret of the alert itself
func TestSecretScanningAPIComment(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo := depNewRepo(t, org3, user2, "secret-comment", true, 0)
		// a secret that no rule finds without its context: only the fingerprint of the alert knows it
		bare := "wJalrXUtn" + "FEMI/K7MDENG/" + "bPxRfiCY" + "Zq3vT8kLm1"
		a := seedSecretAlert(t, repo, "aws-secret-access-key", "aws", secretscan_model.KindRepo, "env")
		_, err := db.GetEngine(t.Context()).Exec("UPDATE secret_scanning_alert SET fingerprint = ? WHERE id = ?", secretdetection.Fingerprint([]byte(bare)), a.ID)
		require.NoError(t, err)
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		one := "/api/v1/repos/org3/secret-comment/secret-scanning/alerts/1"
		patch := func(comment string, status int) *httptest.ResponseRecorder {
			return MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "resolved", "resolution": "revoked", "resolution_comment": comment}).AddTokenAuth(token), status)
		}
		zw := "\u200b"
		// secrets of other alerts that are written lower and upper case in a comment
		lowerSecret, upperSecret := strings.ToLower(bare), strings.ToUpper(bare)
		for i, secret := range []string{lowerSecret, upperSecret} {
			a := seedSecretAlert(t, repo, "generic-secret-assignment", "generic", secretscan_model.KindRepo, fmt.Sprintf("case%d", i))
			_, err = db.GetEngine(t.Context()).Exec("UPDATE secret_scanning_alert SET fingerprint = ? WHERE id = ?", secretdetection.Fingerprint([]byte(secret)), a.ID)
			require.NoError(t, err)
		}
		other := seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindRepo, "other")
		otherSecret := "ghp" + "_" + "Ab1Cd2Ef3Gh4" + "Ij5Kl6Mn7Op8" + "Qr9St0Uv1Wx2"
		_, err = db.GetEngine(t.Context()).Exec("UPDATE secret_scanning_alert SET fingerprint = ? WHERE id = ?", secretdetection.Fingerprint([]byte(otherSecret)), other.ID)
		require.NoError(t, err)
		for _, bad := range []string{
			"rotated, the old key was " + bare,
			"AWS_SECRET=" + bare,
			`"` + bare + `"`,
			bare[:10] + zw + bare[10:],
			bare[:10] + "\u2060" + bare[10:],
			bare[:10] + "\u00ad" + bare[10:],
			// punctuation and markdown around it, a path, a URL, a comment key, a suffix, the case
			"the old key was " + bare + ".",
			"old key: **" + bare + "**",
			"old key " + bare + "!",
			bare + "/",
			"#" + bare,
			"https://paste.example/" + bare,
			bare + "-old",
			"cfg.token." + bare,
			bare + "_old", "tok_" + bare, bare + "+1", bare + "==", "a=" + bare + "=b", "/srv/" + bare + "_bak/x",
			strings.ToUpper(lowerSecret),
			strings.ToLower(upperSecret),
			// invisible marks inside it
			bare[:10] + "\u034f" + bare[10:],
			bare[:10] + "\ufe0f" + bare[10:],
			bare[:10] + "\u3164" + bare[10:],
			bare[:10] + "\u2800" + bare[10:],
			// a comment the check can't finish within its budget is refused
			distinctParts(250),
			// a secret between two far clusters of delimiters, whose pairs are all repeats or too long
			strings.Repeat("/", 51) + strings.Repeat("a", 300) + "/" + bare + "/" + strings.Repeat("a", 300) + strings.Repeat("/", 51),
			// another alert's secret is no more welcome here
			"it was " + otherSecret,
			"it was " + otherSecret[:10] + "\u034f" + otherSecret[10:],
		} {
			patch(bad, http.StatusUnprocessableEntity)
			assert.Equal(t, secretscan_model.StateOpen, secretAlertRow(t, repo.ID, 1).State, bad)
		}
		// a token for another alert is no secret of this one, and a short word is none either
		patch("rotated, see INC-4242", http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "open"}).AddTokenAuth(token), http.StatusOK)
		// links with long paths are no secrets
		patch("fixed in https://ci.example.com/job/build-and-test/1234/artifact/report/index.html, docs: https://docs.example.com/guide/security/rotating-credentials/overview.html", http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "open"}).AddTokenAuth(token), http.StatusOK)

		// newlines stay, formatting characters go, the ends are trimmed
		var got api.SecretScanningAlert
		DecodeJSON(t, patch("  line one\nline two \u202e\u2066x  ", http.StatusOK), &got)
		assert.Equal(t, "line one\nline two x", got.ResolutionComment)
		assert.Equal(t, "line one\nline two x", secretAlertRow(t, repo.ID, 1).Comment)

		rows, err := db.GetEngine(t.Context()).Query("SELECT * FROM audit_event")
		require.NoError(t, err)
		for _, row := range rows {
			for col, v := range row {
				assert.NotContains(t, string(v), bare[:20], "audit_event.%s", col)
				assert.NotContains(t, string(v), otherSecret[4:20], "audit_event.%s", col)
			}
		}
	})
}

// removeCodeUnit turns the Code unit of the repository off until the test ends.
func removeCodeUnit(t *testing.T, repoID int64) {
	t.Helper()
	var row repo_model.RepoUnit
	has, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repoID, unit.TypeCode).Get(&row)
	require.NoError(t, err)
	require.True(t, has)
	_, err = db.GetEngine(t.Context()).ID(row.ID).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Insert(db.DefaultContext, &row)) })
}

// distinctParts is a run of n different short parts joined by dots: as many different candidates as the cap allows.
func distinctParts(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%c%c%c.", 'a'+i%26, 'a'+i/26%26, 'a'+i/676)
	}
	return b.String()
}
