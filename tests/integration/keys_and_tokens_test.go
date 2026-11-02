// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/modules/translation"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeysAndTokensPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")

	body := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/keys"), http.StatusOK).Body.String()
	sshAt := strings.Index(body, "Manage SSH keys")
	gpgAt := strings.Index(body, "Manage GPG keys")
	tokensAt := strings.Index(body, "Access tokens")
	assert.Positive(t, sshAt)
	assert.Greater(t, gpgAt, sshAt)
	assert.Greater(t, tokensAt, gpgAt)
	assert.Contains(t, body, `href="/user/settings/keys/tokens/new"`)
	assert.Contains(t, body, "Keys and tokens")

	// Applications is OAuth2 only
	apps := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/applications"), http.StatusOK).Body.String()
	assert.NotContains(t, apps, "/tokens/new")
	assert.NotContains(t, apps, `id="delete-token"`)
	assert.Contains(t, apps, translation.NewLocale("en-US").TrString("settings.authorized_oauth2_applications"))
}

func TestKeysAndTokensLifecycle(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")

	createApplicationSettingsToken(t, session, "keys-page-token", auth_model.AccessTokenScopeReadUser)
	token := assertAccessToken(t, session)
	name, id := findLatestTokenID(t, session)
	assert.Equal(t, "keys-page-token", name)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusOK)

	form := map[string]string{"id": strconv.Itoa(id)}
	resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/regenerate", form), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "/user/settings/keys")
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusUnauthorized)

	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/delete", form), http.StatusOK)
	name, _ = findLatestTokenID(t, session)
	assert.NotEqual(t, "keys-page-token", name)
}

func TestOldTokenRoutesGone(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	for _, path := range []string{"new", "delete", "regenerate"} {
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/applications/tokens/"+path, map[string]string{"name": "x"}), http.StatusNotFound)
	}
	session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/applications/tokens/new"), http.StatusNotFound)
}

func TestKeysPostErrorKeepsTokens(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	createApplicationSettingsToken(t, session, "kept-token", auth_model.AccessTokenScopeReadUser)

	content, _ := newTestSSHKey(t)
	form := map[string]string{"type": "ssh", "title": "dup-key", "content": content}
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys", form), http.StatusSeeOther)
	form["title"] = "dup-key-2"
	resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys", form), http.StatusOK)
	body := resp.Body.String()
	assert.Contains(t, body, "kept-token")
	assert.Contains(t, body, `href="/user/settings/keys/tokens/new"`)
}

// #498 J: the new token form selects "Specific repositories" by default; K: adding the last repositories of the last
// search page shows the new last page instead of "No repositories found".
func TestNewTokenFormRepoAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	form := func(query string) *HTMLDoc {
		return NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/keys/tokens/new"+query), http.StatusOK).Body)
	}

	doc := form("")
	_, checked := doc.Find("#resource-repo-specific").Attr("checked")
	assert.True(t, checked)
	assert.Equal(t, 1, doc.Find(`input[name=resource][checked]`).Length())
	// a choice made in the form is kept
	_, checked = form("?resource=all").Find("#resource-all").Attr("checked")
	assert.True(t, checked)

	// select every repository of the last page: the form keeps that page number
	pager := form("").Find(`.pagination button[name=set_page]`)
	last, err := strconv.Atoi(pager.Last().AttrOr("value", ""))
	require.NoError(t, err)
	require.Greater(t, last, 1)
	query := "?page=" + strconv.Itoa(last)
	form(query).Find(`button[name=add_selected_repo]`).Each(func(_ int, b *goquery.Selection) {
		query += "&selected_repo=" + b.AttrOr("value", "")
	})
	doc = form(query)
	assert.Equal(t, strconv.Itoa(last-1), doc.Find(`input[name=page]`).AttrOr("value", ""), "the new last page")
	assert.Positive(t, doc.Find(`button[name=add_selected_repo]`).Length())
	assert.NotContains(t, doc.Find("#repo-selector").Text(), "No repositories found")
}
