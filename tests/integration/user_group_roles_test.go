// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertUserRoles(t *testing.T, uid int64, admin, createOrg bool) {
	t.Helper()
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: uid})
	assert.Equal(t, admin, u.IsAdmin, "IsAdmin")
	assert.Equal(t, createOrg, u.AllowCreateOrganization, "AllowCreateOrganization")
}

// setUser1Admin sets the admin flag of user1, the only site administrator of the fixtures.
func setUser1Admin(t *testing.T, admin bool) {
	t.Helper()
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	u.IsAdmin = admin
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, u, "is_admin"))
}

func TestUserGroupRolesWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user1")
	member := loginUser(t, "user5")
	assertUserRoles(t, 5, false, false)
	member.MakeRequest(t, NewRequest(t, "GET", "/admin/groups"), http.StatusForbidden)

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{
		"name":                       "platform-admins",
		"grants_site_admin":          "on",
		"grants_create_organization": "on",
	}), http.StatusSeeOther)
	group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "platform-admins"})
	assert.True(t, group.GrantsSiteAdmin)
	assert.True(t, group.GrantsCreateOrganization)
	groupURL := fmt.Sprintf("/admin/groups/%d", group.ID)

	resp := admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
	htmlDoc := NewHTMLParser(t, resp.Body)
	htmlDoc.AssertElement(t, `input[name="grants_site_admin"][checked]`, true)
	htmlDoc.AssertElement(t, `input[name="grants_create_organization"][checked]`, true)

	// a member gets both roles, and the admin-only pages open for them
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/members/add", map[string]string{"uname": "user5"}), http.StatusSeeOther)
	assertUserRoles(t, 5, true, true)
	member.MakeRequest(t, NewRequest(t, "GET", "/admin/groups"), http.StatusOK)

	// the user list and the user edit page name the group
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/users?q=user5"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "via group platform-admins")
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/users/5/edit"), http.StatusOK)
	assert.Equal(t, 2, strings.Count(resp.Body.String(), "via group platform-admins"))

	// taking a role off the group takes it off the members
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{
		"name":              "platform-admins",
		"grants_site_admin": "on",
		"confirm_roles":     "create_organization",
	}), http.StatusSeeOther)
	assertUserRoles(t, 5, true, false)

	// the last site administrator cannot be removed
	setUser1Admin(t, false)
	member.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/members/remove", map[string]string{"uid": "5"}), http.StatusSeeOther)
	resp = member.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "You cannot remove the last admin.")
	member.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{"name": "platform-admins", "confirm_roles": "site_admin"}), http.StatusSeeOther)
	member.MakeRequest(t, NewRequest(t, "POST", groupURL+"/delete"), http.StatusOK)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{ID: group.ID}).GrantsSiteAdmin)
	unittest.AssertExistsAndLoadBean(t, &organization.UserGroupUser{GroupID: group.ID, UID: 5})
	assertUserRoles(t, 5, true, false)

	// with another administrator, deleting the group revokes the role
	setUser1Admin(t, true)
	admin.MakeRequest(t, NewRequest(t, "POST", groupURL+"/delete"), http.StatusOK)
	unittest.AssertNotExistsBean(t, &organization.UserGroup{ID: group.ID})
	assertUserRoles(t, 5, false, false)
	member.MakeRequest(t, NewRequest(t, "GET", "/admin/groups"), http.StatusForbidden)
}

func TestUserGroupRolesAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)

	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{
		Name:            "api-admins",
		GrantsSiteAdmin: true,
	}).AddTokenAuth(token), http.StatusCreated)
	var group api.UserGroup
	DecodeJSON(t, resp, &group)
	assert.True(t, group.GrantsSiteAdmin)
	assert.False(t, group.GrantsCreateOrganization)
	groupURL := "/api/v1/admin/groups/api-admins"

	MakeRequest(t, NewRequest(t, "PUT", groupURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	assertUserRoles(t, 5, true, false)

	yes, no := true, false
	resp = MakeRequest(t, NewRequestWithJSON(t, "PATCH", groupURL, &api.EditUserGroupOption{GrantsCreateOrganization: &yes}).AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &group)
	assert.True(t, group.GrantsSiteAdmin)
	assert.True(t, group.GrantsCreateOrganization)
	assertUserRoles(t, 5, true, true)

	resp = MakeRequest(t, NewRequest(t, "GET", groupURL).AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &group)
	assert.True(t, group.GrantsSiteAdmin)

	// the last site administrator cannot be removed
	// (user5 is now an administrator through the group)
	memberToken := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteAdmin)
	setUser1Admin(t, false)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", groupURL, &api.EditUserGroupOption{GrantsSiteAdmin: &no}).AddTokenAuth(memberToken), http.StatusConflict)
	MakeRequest(t, NewRequest(t, "DELETE", groupURL+"/members/user5").AddTokenAuth(memberToken), http.StatusConflict)
	MakeRequest(t, NewRequest(t, "DELETE", groupURL).AddTokenAuth(memberToken), http.StatusConflict)
	assertUserRoles(t, 5, true, true)

	// a manual admin flag is kept when the group goes
	setUser1Admin(t, true)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", groupURL, &api.EditUserGroupOption{GrantsSiteAdmin: &no}).AddTokenAuth(token), http.StatusOK)
	assertUserRoles(t, 5, false, true)
	MakeRequest(t, NewRequest(t, "DELETE", groupURL).AddTokenAuth(token), http.StatusNoContent)
	assertUserRoles(t, 5, false, false)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}).IsAdmin)
}

func TestUserGroupRoleLossWarning(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")

	newGroup := func(name string, grants bool, members ...string) string {
		values := map[string]string{"name": name}
		if grants {
			values["grants_site_admin"] = "on"
			values["grants_create_organization"] = "on"
		}
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", values), http.StatusSeeOther)
		group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: name})
		groupURL := fmt.Sprintf("/admin/groups/%d", group.ID)
		for _, m := range members {
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/members/add", map[string]string{"uname": m}), http.StatusSeeOther)
		}
		return groupURL
	}
	const lossAdmin = "1 member will lose site administrator rights"
	const lossCreateOrg = "1 member will lose the right to create organizations"

	// user5 has both roles only through "admins", user4 also through
	// "other-admins", user1 is an administrator by other means.
	newGroup("other-admins", true, "user4")
	groupURL := newGroup("admins", true, "user4", "user5", "user1")
	assertUserRoles(t, 5, true, true)

	// the delete modal names what deleting the group takes away, and the form states the limit
	resp := admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
	htmlDoc := NewHTMLParser(t, resp.Body)
	modal := htmlDoc.Find("#delete-user-group").Text()
	assert.Contains(t, modal, lossAdmin)
	assert.Contains(t, modal, lossCreateOrg)
	assert.Contains(t, htmlDoc.Find("form").Text(), "only rights a group turned on are tracked")

	// switching site admin off asks first and changes nothing
	edit := func(confirmRoles string, grantsCreateOrg bool) *httptest.ResponseRecorder {
		values := map[string]string{"name": "admins", "confirm_roles": confirmRoles}
		if grantsCreateOrg {
			values["grants_create_organization"] = "on"
		}
		return admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", values), NoExpectedStatus)
	}
	resp = edit("", true)
	require.Equal(t, http.StatusOK, resp.Code)
	htmlDoc = NewHTMLParser(t, resp.Body)
	warning := htmlDoc.Find(".user-group-role-loss").Text()
	assert.Contains(t, warning, lossAdmin)
	assert.NotContains(t, warning, lossCreateOrg)
	htmlDoc.AssertElement(t, `input[name="confirm_roles"][value="site_admin"]`, true)
	htmlDoc.AssertElement(t, `input[name="grants_site_admin"]:not([checked])`, true)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "admins"}).GrantsSiteAdmin)
	assertUserRoles(t, 5, true, true)

	// a role switched off after the first warning is warned about too
	resp = edit("site_admin", false)
	require.Equal(t, http.StatusOK, resp.Code)
	warning = NewHTMLParser(t, resp.Body).Find(".user-group-role-loss").Text()
	assert.Contains(t, warning, lossAdmin)
	assert.Contains(t, warning, lossCreateOrg)
	assertUserRoles(t, 5, true, true)

	// confirming applies the change
	assert.Equal(t, http.StatusSeeOther, edit("site_admin,create_organization", false).Code)
	assertUserRoles(t, 5, false, false)
	assertUserRoles(t, 4, true, true)
	assertUserRoles(t, 1, true, true)

	// switching roles on asks nothing; deleting the group still revokes them
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{
		"name": "admins", "grants_site_admin": "on", "grants_create_organization": "on",
	}), http.StatusSeeOther)
	assertUserRoles(t, 5, true, true)
	admin.MakeRequest(t, NewRequest(t, "POST", groupURL+"/delete"), http.StatusOK)
	assertUserRoles(t, 5, false, false)
	assertUserRoles(t, 4, true, true)

	// a group that grants nothing shows no warning
	groupURL = newGroup("plain", false, "user2")
	resp = admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
	assert.NotContains(t, resp.Body.String(), "will lose")
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{"name": "plain2"}), http.StatusSeeOther)

	t.Run("auditor", func(t *testing.T) {
		const lossAuditor = "1 member will lose auditor access"
		isAuditor := func(uid int64) bool {
			return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: uid}).IsAuditor
		}
		newAuditorGroup := func(name string, members ...string) string {
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{
				"name": name, "grants_site_admin": "on", "grants_auditor": "on",
			}), http.StatusSeeOther)
			group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: name})
			for _, m := range members {
				admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/groups/%d/members/add", group.ID), map[string]string{"uname": m}), http.StatusSeeOther)
			}
			return fmt.Sprintf("/admin/groups/%d", group.ID)
		}
		// user5 is an auditor (and administrator) only through "auditors"; user4 also through "other-auditors".
		newAuditorGroup("other-auditors", "user4")
		groupURL := newAuditorGroup("auditors", "user4", "user5")
		require.True(t, isAuditor(5))
		require.True(t, isAuditor(4))

		resp := admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
		assert.Contains(t, NewHTMLParser(t, resp.Body).Find("#delete-user-group").Text(), lossAuditor)

		edit := func(confirmRoles string, grantsSiteAdmin, grantsAuditor bool) *httptest.ResponseRecorder {
			values := map[string]string{"name": "auditors", "confirm_roles": confirmRoles}
			if grantsSiteAdmin {
				values["grants_site_admin"] = "on"
			}
			if grantsAuditor {
				values["grants_auditor"] = "on"
			}
			return admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", values), NoExpectedStatus)
		}

		// switching auditor off asks first and changes nothing
		resp = edit("", true, false)
		require.Equal(t, http.StatusOK, resp.Code)
		htmlDoc := NewHTMLParser(t, resp.Body)
		warning := htmlDoc.Find(".user-group-role-loss").Text()
		assert.Contains(t, warning, lossAuditor)
		assert.NotContains(t, warning, lossAdmin)
		htmlDoc.AssertElement(t, `input[name="confirm_roles"][value="auditor"]`, true)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "auditors"}).GrantsAuditor)
		assert.True(t, isAuditor(5))

		// confirming a different role does not confirm auditor
		resp = edit("site_admin", true, false)
		require.Equal(t, http.StatusOK, resp.Code)
		assert.Contains(t, NewHTMLParser(t, resp.Body).Find(".user-group-role-loss").Text(), lossAuditor)
		assert.True(t, isAuditor(5))

		// a role switched off after the first warning is warned about too, and the two combine
		resp = edit("auditor", false, false)
		require.Equal(t, http.StatusOK, resp.Code)
		htmlDoc = NewHTMLParser(t, resp.Body)
		warning = htmlDoc.Find(".user-group-role-loss").Text()
		assert.Contains(t, warning, lossAuditor)
		assert.Contains(t, warning, lossAdmin)
		htmlDoc.AssertElement(t, `input[name="confirm_roles"][value="auditor,site_admin"]`, true)
		assert.True(t, isAuditor(5))

		// confirming applies the change; the member covered by the other group keeps the role
		assert.Equal(t, http.StatusSeeOther, edit("auditor,site_admin", false, false).Code)
		assert.False(t, isAuditor(5))
		assert.True(t, isAuditor(4))

		// the group grants nothing now: no warning, and switching on asks nothing
		resp = admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), "will lose")
		assert.Equal(t, http.StatusSeeOther, edit("", false, true).Code)
		assert.True(t, isAuditor(5))
	})
}
