// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	app_context "forgejo.org/services/context"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A site admin manages the access tokens of local accounts on Site administration → Users → Edit (#502).
func TestAdminUserTokens(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, _ := prepareRepoGroupGit(t)
		admin := loginUser(t, "user1")
		ctx := db.DefaultContext

		tokensURL := func(uid int64, rest string) string { return fmt.Sprintf("/admin/users/%d/tokens/%s", uid, rest) }
		editURL := func(uid int64) string { return fmt.Sprintf("/admin/users/%d/edit", uid) }
		create := func(t *testing.T, session *TestSession, uid int64, status int, values url.Values) string {
			t.Helper()
			if values.Get("name") == "" {
				values.Set("name", fmt.Sprintf("admin-token-%d", tokenCounter.Add(1)))
			}
			return session.MakeRequest(t, NewRequestWithURLValues(t, "POST", tokensURL(uid, "new"), values), status).Body.String()
		}
		newToken := func(t *testing.T, uid int64) *auth_model.AccessToken {
			t.Helper()
			tok := &auth_model.AccessToken{UID: uid, Name: fmt.Sprintf("fixture-%d", tokenCounter.Add(1)), Scope: auth_model.AccessTokenScopeReadUser, ResourceAllRepos: true}
			require.NoError(t, auth_model.NewAccessToken(ctx, tok, nil))
			return tok
		}
		post := func(t *testing.T, session *TestSession, path string, id int64, status int) {
			t.Helper()
			session.MakeRequest(t, NewRequestWithValues(t, "POST", path, map[string]string{"id": fmt.Sprint(id)}), status)
		}
		setCol := func(t *testing.T, uid int64, col string, value any) func() {
			t.Helper()
			var old any
			_, err := db.GetEngine(ctx).Table("user").Where("id = ?", uid).Cols(col).Get(&old)
			require.NoError(t, err)
			_, err = db.GetEngine(ctx).Exec("UPDATE `user` SET "+col+" = ? WHERE id = ?", value, uid)
			require.NoError(t, err)
			return func() {
				_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET "+col+" = ? WHERE id = ?", old, uid)
				require.NoError(t, err)
			}
		}

		t.Run("section only for local accounts", func(t *testing.T) {
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", editURL(4)), http.StatusOK).Body)
			assert.Equal(t, 1, doc.Find(`a[href$="/admin/users/4/tokens/new"]`).Length())

			noSection := func(t *testing.T, uid int64) {
				t.Helper()
				doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", editURL(uid)), http.StatusOK).Body)
				assert.Equal(t, 1, doc.Find(`form[action="./edit"]`).Length())
				assert.Zero(t, doc.Find(`a[href*="/tokens/"], [data-url*="/tokens/"]`).Length())
			}
			t.Run("ldap", func(t *testing.T) {
				defer setCol(t, 4, "login_type", 2)()
				noSection(t, 4)
			})
			t.Run("oauth2", func(t *testing.T) {
				defer setCol(t, 4, "login_type", 6)()
				noSection(t, 4)
			})
			t.Run("bot", func(t *testing.T) {
				defer setCol(t, 4, "type", int(user_model.UserTypeBot))()
				noSection(t, 4)
			})
			t.Run("organization", func(t *testing.T) {
				admin.MakeRequest(t, NewRequest(t, "GET", editURL(3)), http.StatusNotFound)
			})
		})

		t.Run("refused targets", func(t *testing.T) {
			tok := newToken(t, 8)
			check := func(t *testing.T, uid int64) {
				t.Helper()
				admin.MakeRequest(t, NewRequest(t, "GET", tokensURL(uid, "new")), http.StatusNotFound)
				create(t, admin, uid, http.StatusNotFound, url.Values{"resource": {"all"}, "scope": {"read:user"}})
				post(t, admin, tokensURL(uid, "delete"), tok.ID, http.StatusNotFound)
				post(t, admin, tokensURL(uid, "regenerate"), tok.ID, http.StatusNotFound)
			}
			t.Run("organization", func(t *testing.T) { check(t, 3) })
			t.Run("missing", func(t *testing.T) { check(t, 999999) })
			t.Run("remote", func(t *testing.T) { check(t, 43) })
			t.Run("external login source", func(t *testing.T) {
				defer setCol(t, 8, "login_type", 2)() // LDAP
				check(t, 8)
			})
			t.Run("reserved", func(t *testing.T) {
				defer setCol(t, 8, "type", int(user_model.UserTypeUserReserved))()
				check(t, 8)
			})
			t.Run("bot", func(t *testing.T) {
				defer setCol(t, 8, "type", int(user_model.UserTypeBot))()
				check(t, 8)
			})
			t.Run("trashed", func(t *testing.T) {
				defer setCol(t, 8, "trashed_unix", 1)()
				check(t, 8)
			})
			stored := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID})
			assert.Equal(t, tok.TokenHash, stored.TokenHash)
		})

		t.Run("create with a project repository", func(t *testing.T) {
			since := auditMaxID(t)
			create(t, admin, 2, http.StatusSeeOther, url.Values{
				"name": {"admin-made"}, "resource": {"repo-specific"}, "scope": {"write:repository"},
				"selected_repo": {f.priv.FullName()},
			})
			tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "admin-made"})
			assert.Equal(t, []int64{f.priv.ID}, tokenRepoIDs(t, tok.ID))

			// the value is shown once, in the flash on the edit page
			body := admin.MakeRequest(t, NewRequest(t, "GET", editURL(2)), http.StatusOK).Body.String()
			value := NewHTMLParser(t, bytes.NewBufferString(body)).Find(".ui.info p").Text()
			require.Len(t, value, 40)
			assert.Equal(t, tok.TokenHash, auth_model.HashToken(value, tok.TokenSalt))
			// the list names the token and its project repository by full name
			assert.Contains(t, body, "admin-made")
			assert.Contains(t, body, f.priv.FullName())
			assert.NotContains(t, body, tok.TokenHash)
			// the admin page speaks of this user's account, never of the admin's
			assert.Contains(t, body, "The new token has been generated.")
			assert.Contains(t, body, "These tokens grant access to this user's account")
			assert.Contains(t, body, "revoke access to this user's account")
			assert.NotContains(t, body, "your account")
			assert.NotContains(t, body, "Your new token")
			// the user's own page keeps its wording
			own := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user/settings/keys"), http.StatusOK).Body.String()
			assert.Contains(t, own, "These tokens grant access to your account")
			assert.Contains(t, own, "revoke access to your account")
			assert.NotContains(t, own, "this user's account")

			resp := admin.MakeRequest(t, NewRequest(t, "GET", editURL(2)), http.StatusOK)
			assert.NotContains(t, resp.Body.String(), value)
			assert.NotContains(t, resp.Body.String(), tok.TokenHash)

			e := auditOne(t, since, "credential.access_token.created")
			assert.Equal(t, audit_model.ActorUser, e.ActorType)
			assert.EqualValues(t, 1, e.ActorID)
			assert.EqualValues(t, 2, e.SubjectUserID)
			assert.Equal(t, tok.ID, e.TargetID)
			assert.Equal(t, "admin-made", e.TargetName)
			assert.Equal(t, true, auditData(t, e)["on_behalf"])
			assertNoSecretIn(t, since, value)

			// the list shows scopes, created, expires and last used
			created := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC).Unix()
			used := time.Date(2026, 2, 3, 12, 0, 0, 0, time.UTC).Unix()
			expires := time.Now().AddDate(0, 2, 0).Unix()
			_, err := db.GetEngine(ctx).Exec("UPDATE access_token SET created_unix = ?, updated_unix = ?, expires_unix = ? WHERE id = ?", created, used, expires, tok.ID)
			require.NoError(t, err)
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", editURL(2)), http.StatusOK).Body)
			item := doc.Find(".flex-item").FilterFunction(func(_ int, s *goquery.Selection) bool {
				return s.Find(".flex-item-title").Text() == "admin-made"
			})
			require.Equal(t, 1, item.Length())
			text := strings.Join(strings.Fields(item.Text()), " ")
			day := func(unix int64) string { return time.Unix(unix, 0).Format("2006-01-02") }
			assert.Contains(t, text, "write:repository")
			assert.Contains(t, text, "Added on "+day(created))
			assert.Contains(t, text, "Last used on "+day(used))
			assert.Contains(t, text, "Expires "+day(expires))
			assert.Contains(t, text, f.priv.FullName())
			assert.Equal(t, 1, item.Find(fmt.Sprintf(`[data-url="/admin/users/2/tokens/delete"][data-id="%d"]`, tok.ID)).Length())
			assert.Equal(t, 1, item.Find(fmt.Sprintf(`[data-url="/admin/users/2/tokens/regenerate"][data-id="%d"]`, tok.ID)).Length())

			// the name check is per target: the admin may use the same name for another user
			create(t, admin, 2, http.StatusOK, url.Values{"name": {"admin-made"}, "resource": {"all"}, "scope": {"read:user"}})
			create(t, admin, 4, http.StatusSeeOther, url.Values{"name": {"admin-made"}, "resource": {"all"}, "scope": {"read:user"}})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 4, Name: "admin-made"})
		})

		t.Run("repositories are those of the target", func(t *testing.T) {
			// user4 can't read user2/repo2; the admin can
			body := create(t, admin, 4, http.StatusBadRequest, url.Values{"resource": {"repo-specific"}, "scope": {"write:repository"}, "selected_repo": {"user2/repo2"}})
			missing := create(t, admin, 4, http.StatusBadRequest, url.Values{"resource": {"repo-specific"}, "scope": {"write:repository"}, "selected_repo": {"user2/nope"}})
			assert.Equal(t, missing, body)

			// a token created earlier on a repository the target no longer reads doesn't name it
			tok := &auth_model.AccessToken{UID: 4, Name: "lost-access", Scope: auth_model.AccessTokenScopeReadRepository}
			require.NoError(t, auth_model.NewAccessToken(ctx, tok, []*auth_model.AccessTokenResourceRepo{{RepoID: 2}}))
			resp := admin.MakeRequest(t, NewRequest(t, "GET", editURL(4)), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "lost-access")
			assert.NotContains(t, resp.Body.String(), "user2/repo2")

			// the picker searches the target's repositories
			resp = admin.MakeRequest(t, NewRequest(t, "GET", tokensURL(2, "new?repo_search=repo2")), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "user2/repo2")
			resp = admin.MakeRequest(t, NewRequest(t, "GET", tokensURL(4, "new?repo_search=repo2")), http.StatusOK)
			assert.NotContains(t, resp.Body.String(), "user2/repo2")
		})

		t.Run("expiry policy", func(t *testing.T) {
			defer test.MockVariableValue(&setting.AccessTokenExpiry, setting.DefaultCredentialExpiry)()
			body := create(t, admin, 4, http.StatusOK, url.Values{"name": {"no-expiry"}, "resource": {"all"}, "scope": {"read:user"}})
			assert.Contains(t, body, "expir")
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 4, Name: "no-expiry"})
			body = create(t, admin, 4, http.StatusOK, url.Values{"name": {"too-long"}, "resource": {"all"}, "scope": {"read:user"}, "expires_at": {time.Now().AddDate(1, 1, 0).Format("2006-01-02")}})
			assert.Contains(t, body, "expir")
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 4, Name: "too-long"})
			create(t, admin, 4, http.StatusSeeOther, url.Values{"name": {"in-policy"}, "resource": {"all"}, "scope": {"read:user"}, "expires_at": {time.Now().AddDate(0, 1, 0).Format("2006-01-02")}})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 4, Name: "in-policy"})
		})

		t.Run("scope policy of the target", func(t *testing.T) {
			defer test.MockVariableValue(&setting.AccessTokenScopes, testScopePolicy)()
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", tokensURL(4, "new")), http.StatusOK).Body)
			assert.True(t, doc.Find(`#access-token-scope-issue option[value="read:issue"]`).Is("[disabled]"))
			assert.Zero(t, doc.Find(`#access-token-scope-admin`).Length())

			body := create(t, admin, 4, http.StatusOK, url.Values{"name": {"policy"}, "resource": {"all"}, "scope": {"read:issue"}})
			assert.Contains(t, body, "The scope read:issue is not allowed.")
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 4, Name: "policy"})

			// an admin target is exempt, as on the admin API
			create(t, admin, 1, http.StatusSeeOther, url.Values{"name": {"policy"}, "resource": {"all"}, "scope": {"read:issue"}})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 1, Name: "policy"})
		})

		t.Run("delete and regenerate", func(t *testing.T) {
			mine := &auth_model.AccessToken{UID: 4, Name: "regen", Scope: auth_model.AccessTokenScopeReadRepository, ExpiresUnix: timeutil.TimeStampNow() + 86400}
			require.NoError(t, auth_model.NewAccessToken(ctx, mine, []*auth_model.AccessTokenResourceRepo{{RepoID: 1}}))
			other := newToken(t, 2)

			// another user's token ID is a 404 and the token is untouched
			post(t, admin, tokensURL(4, "regenerate"), other.ID, http.StatusNotFound)
			post(t, admin, tokensURL(4, "delete"), other.ID, http.StatusNotFound)
			assert.Equal(t, other.TokenHash, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: other.ID}).TokenHash)

			since := auditMaxID(t)
			post(t, admin, tokensURL(4, "regenerate"), mine.ID, http.StatusOK)
			assert.Contains(t, flashText(t, admin), "no longer have access to this user's account")
			regenerated := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: mine.ID})
			assert.NotEqual(t, mine.TokenHash, regenerated.TokenHash)
			assert.Equal(t, mine.ExpiresUnix, regenerated.ExpiresUnix)
			assert.Equal(t, mine.Scope, regenerated.Scope)
			assert.False(t, regenerated.ResourceAllRepos)
			assert.Equal(t, []int64{1}, tokenRepoIDs(t, mine.ID))
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(mine.Token), http.StatusUnauthorized)
			value := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", editURL(4)), http.StatusOK).Body).Find(".ui.info p").Text()
			assert.Equal(t, regenerated.TokenHash, auth_model.HashToken(value, regenerated.TokenSalt))
			e := auditOne(t, since, "credential.access_token.regenerated")
			assert.EqualValues(t, 1, e.ActorID)
			assert.EqualValues(t, 4, e.SubjectUserID)
			assert.Equal(t, mine.ID, e.TargetID)
			assert.Equal(t, true, auditData(t, e)["on_behalf"])
			assertNoSecretIn(t, since, value)

			since = auditMaxID(t)
			post(t, admin, tokensURL(4, "delete"), mine.ID, http.StatusOK)
			assert.Contains(t, flashText(t, admin), "no longer have access to this user's account")
			unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: mine.ID})
			e = auditOne(t, since, "credential.access_token.deleted")
			assert.EqualValues(t, 1, e.ActorID)
			assert.EqualValues(t, 4, e.SubjectUserID)
			assert.Equal(t, mine.ID, e.TargetID)
			assert.Equal(t, "regen", e.TargetName)
			assert.Equal(t, true, auditData(t, e)["on_behalf"])
			assertNoSecretIn(t, since, value, mine.Token)
		})

		t.Run("who may act", func(t *testing.T) {
			tok := newToken(t, 8)
			refused := func(t *testing.T, session *TestSession, status int) {
				t.Helper()
				session.MakeRequest(t, NewRequest(t, "GET", tokensURL(8, "new")), status)
				create(t, session, 8, status, url.Values{"resource": {"all"}, "scope": {"read:user"}})
				post(t, session, tokensURL(8, "delete"), tok.ID, status)
				post(t, session, tokensURL(8, "regenerate"), tok.ID, status)
			}
			t.Run("non-admin", func(t *testing.T) { refused(t, loginUser(t, "user2"), http.StatusForbidden) })
			t.Run("signed out", func(t *testing.T) { refused(t, emptyTestSession(t), http.StatusSeeOther) })
			t.Run("auditor", func(t *testing.T) {
				defer setCol(t, 5, "is_auditor", true)()
				refused(t, loginUser(t, "user5"), http.StatusForbidden)
			})
			t.Run("prohibited admin", func(t *testing.T) {
				session := loginUser(t, "user1")
				defer setCol(t, 1, "prohibit_login", true)()
				resp := session.MakeRequest(t, NewRequest(t, "GET", tokensURL(8, "new")), NoExpectedStatus)
				assert.Contains(t, resp.Body.String(), "suspended")
				resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", tokensURL(8, "delete"), map[string]string{"id": fmt.Sprint(tok.ID)}), NoExpectedStatus)
				assert.Contains(t, resp.Body.String(), "suspended")
			})
			t.Run("token auth", func(t *testing.T) {
				adminToken := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteAdmin)
				resp := MakeRequest(t, NewRequestWithValues(t, "POST", tokensURL(8, "delete"), map[string]string{"id": fmt.Sprint(tok.ID)}).AddTokenAuth(adminToken), NoExpectedStatus)
				assert.NotEqual(t, http.StatusOK, resp.Code)
				resp = MakeRequest(t, NewRequestWithValues(t, "POST", tokensURL(8, "delete"), map[string]string{"id": fmt.Sprint(tok.ID)}).AddBasicAuth("user1"), NoExpectedStatus)
				assert.NotEqual(t, http.StatusOK, resp.Code)
			})
			t.Run("cross origin", func(t *testing.T) {
				req := NewRequestWithValues(t, "POST", tokensURL(8, "delete"), map[string]string{"id": fmt.Sprint(tok.ID)})
				req.Header.Set("Sec-Fetch-Site", "cross-site")
				admin.MakeRequest(t, req, http.StatusForbidden)
			})
			t.Run("maintenance read-only", func(t *testing.T) {
				defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
				admin.MakeRequest(t, NewRequest(t, "GET", tokensURL(8, "new")), http.StatusOK)
				create(t, admin, 8, http.StatusSeeOther, url.Values{"name": {"in-maintenance"}, "resource": {"all"}, "scope": {"read:user"}})
				assertMaintenanceFlash(t, admin)
				post(t, admin, tokensURL(8, "delete"), tok.ID, http.StatusSeeOther)
				assertMaintenanceFlash(t, admin)
				post(t, admin, tokensURL(8, "regenerate"), tok.ID, http.StatusSeeOther)
				assertMaintenanceFlash(t, admin)
				unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 8, Name: "in-maintenance"})
			})
			assert.Equal(t, tok.TokenHash, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).TokenHash)
		})

		t.Run("user routes stay bound to the doer", func(t *testing.T) {
			other := newToken(t, 4)
			session := loginUser(t, "user2")
			post(t, session, "/user/settings/keys/tokens/delete", other.ID, http.StatusOK)
			post(t, session, "/user/settings/keys/tokens/regenerate", other.ID, http.StatusOK)
			assert.Equal(t, other.TokenHash, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: other.ID}).TokenHash)
		})
	})
}

func tokenRepoIDs(t *testing.T, tokenID int64) []int64 {
	t.Helper()
	resources, err := auth_model.GetRepositoriesAccessibleWithToken(db.DefaultContext, tokenID)
	require.NoError(t, err)
	ids := make([]int64, 0, len(resources))
	for _, r := range resources {
		ids = append(ids, r.RepoID)
	}
	return ids
}

func flashText(t *testing.T, session *TestSession) string {
	t.Helper()
	cookie := session.GetCookie(app_context.CookieNameFlash)
	require.NotNil(t, cookie)
	v, err := url.QueryUnescape(cookie.Value)
	require.NoError(t, err)
	v, err = url.QueryUnescape(v)
	require.NoError(t, err)
	return v
}
