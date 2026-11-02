// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"

	"github.com/stretchr/testify/require"
)

// A migration creates its repository through the same claim as every other way: it can't take a project's
// name, and the name it takes is claimed.
func TestRepoGroupMigrateClaim(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
		defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
		require.NoError(t, migrations_allowlist.Init())
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		_, err := repo_model.CreateRepoGroup(db.DefaultContext, org3, "pay", "")
		require.NoError(t, err)

		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		migrate := func(name string, status int) {
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
				CloneAddr: u.String() + "user2/repo1.git",
				RepoOwner: org3.Name,
				RepoName:  name,
				Service:   "git",
			}).AddTokenAuth(token)
			MakeRequest(t, req, status)
		}
		migrate("pay", http.StatusConflict)
		migrate("migrated", http.StatusCreated)
		unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "migrated"})
		unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
	})
}
