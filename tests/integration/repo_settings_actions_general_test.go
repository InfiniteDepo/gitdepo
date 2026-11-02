// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepoSettingsActionsGeneral(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	const link = "/user5/repo4/settings/actions/general"
	stored := func(t *testing.T) string {
		t.Helper()
		return unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 4, Type: unit.TypeActions}).ActionsConfig().DefaultTokenPermissions
	}
	session := loginUser(t, "user5")

	t.Run("instance default", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Actions.DefaultTokenPermissions, "read")()
		doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		doc.AssertElementChecked(t, "#default_token_permissions_instance")
		assert.Contains(t, doc.Find(".repo-setting-content").Text(), "Currently read-only.")
		doc.AssertElement(t, `.menu a.active.item[href="/user5/repo4/settings/actions/general"]`, true)
	})

	t.Run("save", func(t *testing.T) {
		session.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"default_token_permissions": "read"}), http.StatusSeeOther)
		assert.Equal(t, "read", stored(t))
		doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		doc.AssertElementChecked(t, "#default_token_permissions_read")

		session.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"default_token_permissions": "banana"}), http.StatusBadRequest)
		assert.Equal(t, "read", stored(t))

		session.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"default_token_permissions": ""}), http.StatusSeeOther)
		assert.Empty(t, stored(t))
	})

	t.Run("not an admin", func(t *testing.T) {
		other := loginUser(t, "user2")
		other.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
		other.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"default_token_permissions": "write"}), http.StatusNotFound)
		assert.Empty(t, stored(t))
	})

	t.Run("actions disabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Actions.Enabled, false)()
		session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
	})
}

// Saving the Settings > Units form or PATCHing has_actions replaces the Actions unit; the config set on the Actions
// settings page (default token permissions, disabled workflows) must survive.
func TestRepoActionsConfigKeptOnUnitsUpdate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user5")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)

	unitConfig := func(t *testing.T) *repo_model.ActionsConfig {
		t.Helper()
		return unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 4, Type: unit.TypeActions}).ActionsConfig()
	}
	set := func(t *testing.T) {
		t.Helper()
		u := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 4, Type: unit.TypeActions})
		u.Config = &repo_model.ActionsConfig{DefaultTokenPermissions: "read", DisabledWorkflows: []string{"a.yml"}}
		_, err := db.GetEngine(t.Context()).ID(u.ID).Cols("config").Update(u)
		require.NoError(t, err)
	}
	check := func(t *testing.T) {
		t.Helper()
		cfg := unitConfig(t)
		assert.Equal(t, "read", cfg.DefaultTokenPermissions)
		assert.Equal(t, []string{"a.yml"}, cfg.DisabledWorkflows)
	}

	t.Run("units form", func(t *testing.T) {
		set(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user5/repo4/settings/units", map[string]string{
			"enable_code": "on", "enable_actions": "on",
		}), http.StatusSeeOther)
		check(t)
	})

	t.Run("API", func(t *testing.T) {
		set(t)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user5/repo4", &api.EditRepoOption{HasActions: new(true)}).AddTokenAuth(token), http.StatusOK)
		check(t)
	})
}
