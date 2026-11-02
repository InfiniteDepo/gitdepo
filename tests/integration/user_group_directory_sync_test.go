// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	oauth2_source "forgejo.org/services/auth/source/oauth2"
	usergroup_service "forgejo.org/services/usergroup"
	"forgejo.org/tests"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestOAuth2GroupUserGroupSync(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()

	devs := &org_model.UserGroup{Name: "devs"}
	require.NoError(t, org_model.InsertUserGroup(db.DefaultContext, devs))
	ops := &org_model.UserGroup{Name: "ops"}
	require.NoError(t, org_model.InsertUserGroup(db.DefaultContext, ops))

	const sourceName = "gitlab"
	mapping := `{"devs-claim": ["devs"], "ops-claim": ["ops"]}`
	payload := authSourcePayloadGitLabCustom(sourceName)
	payload["oauth2_group_claim_name"] = "groups"
	payload["oauth2_group_user_group_map"] = mapping
	payload["oauth2_group_user_group_map_removal"] = "on"

	t.Run("unknown user group is rejected", func(t *testing.T) {
		bad := authSourcePayloadGitLabCustom("bad-source")
		bad["oauth2_group_user_group_map"] = `{"devs-claim": ["no-such-group"]}`
		req := NewRequestWithValues(t, "POST", "/admin/auths/new", bad)
		resp := loginUser(t, "user1").MakeRequest(t, req, http.StatusOK)
		assert.Contains(t, resp.Body.String(), `User group &#34;no-such-group&#34; does not exist.`)
		unittest.AssertNotExistsBean(t, &auth_model.Source{Name: "bad-source"})
	})

	source := addAuthSource(t, payload)
	cfg := source.Cfg.(*oauth2_source.Source)
	assert.Equal(t, mapping, cfg.GroupUserGroupMap)
	assert.True(t, cfg.GroupUserGroupMapRemoval)

	t.Run("admin form shows the mapping", func(t *testing.T) {
		req := NewRequest(t, "GET", fmt.Sprintf("/admin/auths/%d", source.ID))
		doc := NewHTMLParser(t, loginUser(t, "user1").MakeRequest(t, req, http.StatusOK).Body)
		assert.Equal(t, mapping, doc.Find(`textarea[name="oauth2_group_user_group_map"]`).Text())
		_, checked := doc.Find(`input[name="oauth2_group_user_group_map_removal"]`).Attr("checked")
		assert.True(t, checked)
	})

	signIn := func(groups ...string) {
		t.Helper()
		defer mockCompleteUserAuth(func(http.ResponseWriter, *http.Request) (goth.User, error) {
			return goth.User{
				Provider: sourceName,
				UserID:   "4242",
				NickName: "dir-user",
				Email:    "dir-user@example.com",
				RawData:  map[string]any{"groups": groups},
			}, nil
		})()
		req := NewRequest(t, "GET", fmt.Sprintf("/user/oauth2/%s/callback?code=XYZ&state=XYZ", sourceName))
		MakeRequest(t, req, http.StatusSeeOther)
	}
	var user *user_model.User
	isMember := func(g *org_model.UserGroup, loginSourceID int64) bool {
		return unittest.BeanExists(t, &org_model.UserGroupUser{GroupID: g.ID, UID: user.ID}, builder.Eq{"login_source_id": loginSourceID})
	}

	// sign up: synced into devs
	signIn("devs-claim")
	user = unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "dir-user"})
	assert.True(t, isMember(devs, source.ID))
	assert.False(t, isMember(ops, source.ID))

	// an admin adds the user to ops by hand
	require.NoError(t, usergroup_service.AddMember(db.DefaultContext, ops, user))

	t.Run("admin page shows the source", func(t *testing.T) {
		req := NewRequest(t, "GET", fmt.Sprintf("/admin/groups/%d", devs.ID))
		resp := loginUser(t, "user1").MakeRequest(t, req, http.StatusOK)
		assert.Contains(t, resp.Body.String(), "synced from "+sourceName)
	})

	// sign in without any group: synced membership removed, manual one kept
	signIn()
	assert.False(t, isMember(devs, source.ID))
	assert.True(t, isMember(ops, 0))
}
