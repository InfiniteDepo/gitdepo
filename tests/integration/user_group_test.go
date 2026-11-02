// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserGroupSharedAcrossOrganizations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user1")
	member := loginUser(t, "user5")

	// org3/repo3 is private and only reachable through org3's teams
	member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusNotFound)

	// a site administrator creates the group
	resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{
		"name":        "release-managers",
		"description": "People who cut releases",
	}), http.StatusSeeOther)
	group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "release-managers"})
	groupURL := fmt.Sprintf("/admin/groups/%d", group.ID)
	assert.Equal(t, groupURL, test.RedirectURL(resp))

	// group names are unique
	resp = admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{
		"name": "Release-Managers",
	}), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "A user group with this name already exists.")

	// add a member; organizations are refused
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/members/add", map[string]string{"uname": "user5"}), http.StatusSeeOther)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/members/add", map[string]string{"uname": "org3"}), http.StatusSeeOther)
	unittest.AssertExistsAndLoadBean(t, &organization.UserGroupUser{GroupID: group.ID, UID: 5})
	unittest.AssertNotExistsBean(t, &organization.UserGroupUser{GroupID: group.ID, UID: 3})

	// a user who is not an owner of the organization cannot link groups
	loginUser(t, "user4").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/group/link", map[string]string{
		"group_name": "release-managers",
	}), http.StatusNotFound)
	unittest.AssertNotExistsBean(t, &organization.UserGroupTeam{GroupID: group.ID})

	// the link form autocompletes group names, for owners only
	searchURL := "/org/org3/teams/team1/groups/search?q=release"
	resp = admin.MakeRequest(t, NewRequest(t, "GET", searchURL), http.StatusOK)
	var search struct {
		Data []struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"data"`
	}
	DecodeJSON(t, resp, &search)
	require.Len(t, search.Data, 1)
	assert.Equal(t, group.ID, search.Data[0].ID)
	assert.Equal(t, "release-managers", search.Data[0].Name)
	assert.Equal(t, "People who cut releases", search.Data[0].Description)
	loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", searchURL), http.StatusNotFound)

	// link the same group to teams of two different organizations
	for _, teamURL := range []string{"/org/org3/teams/team1", "/org/org17/teams/test_team"} {
		resp = admin.MakeRequest(t, NewRequestWithValues(t, "POST", teamURL+"/action/group/link", map[string]string{
			"group_name": "Release-Managers",
		}), http.StatusSeeOther)
		assert.Equal(t, teamURL, test.RedirectURL(resp))
	}
	for _, teamID := range []int64{2, 8} {
		tu := unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: teamID, UID: 5})
		assert.Equal(t, organization.MembershipReasonAddedByUserGroup, tu.Reason)
	}

	// a group that is already linked is no longer suggested
	resp = admin.MakeRequest(t, NewRequest(t, "GET", searchURL), http.StatusOK)
	DecodeJSON(t, resp, &search)
	assert.Empty(t, search.Data)

	// the member now has the access of the team
	member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusOK)

	// a second group linked to the same team, sharing user5
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{"name": "platform-devs"}), http.StatusSeeOther)
	group2 := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "platform-devs"})
	for _, uname := range []string{"user5", "user10"} {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/groups/%d/members/add", group2.ID), map[string]string{"uname": uname}), http.StatusSeeOther)
	}
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/group/link", map[string]string{"group_name": "platform-devs"}), http.StatusSeeOther)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 2, UID: 10})

	// the team page shows the linked groups with their member counts, and which groups each membership comes from
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/team1"), http.StatusOK)
	doc := NewHTMLParser(t, resp.Body)
	groups := doc.Find("#team-user-groups + .segment + .segment .flex-item-title")
	require.Equal(t, 2, groups.Length())
	assert.Equal(t, "platform-devs · 2 members", strings.Join(strings.Fields(groups.Eq(0).Text()), " "))
	assert.Equal(t, "release-managers · 1 member", strings.Join(strings.Fields(groups.Eq(1).Text()), " "))
	assert.Contains(t, doc.Find(".org-team-navbar").Text(), "2 user groups")
	memberLine := func(doc *HTMLDoc, uname string) string {
		return strings.Join(strings.Fields(doc.Find(fmt.Sprintf(`.flex-item:has(a[href="/%s"]) .flex-item-main > div:last-child`, uname)).Text()), " ")
	}
	assert.Contains(t, memberLine(doc, "user5"), "joined via platform-devs, release-managers on")
	assert.Contains(t, memberLine(doc, "user10"), "joined via platform-devs on")
	doc.AssertElement(t, fmt.Sprintf(`#team-user-groups + .segment + .segment a[href="/admin/groups/%d"]`, group2.ID), true)
	doc.AssertElement(t, fmt.Sprintf(`.flex-item:has(a[href="/user5"]) a[href="/admin/groups/%d"]`, group.ID), true)

	// the teams overview hints at the linked groups
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams"), http.StatusOK)
	assert.Contains(t, NewHTMLParser(t, resp.Body).Find(`.team-meta:has(a[href="/org/org3/teams/team1"])`).Text(), "· 2 user groups")

	// an organization owner who is not a site admin sees the names, not the admin links
	resp = loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/team1"), http.StatusOK)
	doc = NewHTMLParser(t, resp.Body)
	assert.Contains(t, memberLine(doc, "user5"), "joined via platform-devs, release-managers on")
	doc.AssertElement(t, `a[href^="/admin/groups/"]`, false)

	// unlinking the second group keeps the memberships the first group grants
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/group/unlink", map[string]string{
		"group_id": fmt.Sprint(group2.ID),
	}), http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &organization.TeamUser{TeamID: 2, UID: 10})
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 2, UID: 5})
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/team1"), http.StatusOK)
	doc = NewHTMLParser(t, resp.Body)
	assert.Contains(t, memberLine(doc, "user5"), "joined via release-managers on")
	assert.Contains(t, doc.Find(".org-team-navbar").Text(), "1 user group")

	// the group page lists both teams
	resp = admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
	doc = NewHTMLParser(t, resp.Body)
	doc.AssertElement(t, `a[href="/org/org3/teams/team1"]`, true)
	doc.AssertElement(t, `a[href="/org/org17/teams/test_team"]`, true)

	// removing a member that comes from a linked group is refused
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/remove", map[string]string{"uid": "5"}), http.StatusOK)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 2, UID: 5})

	// unlinking the group from org3 removes the access there only
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/group/unlink", map[string]string{
		"group_id": fmt.Sprint(group.ID),
	}), http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &organization.TeamUser{TeamID: 2, UID: 5})
	unittest.AssertNotExistsBean(t, &organization.OrgUser{OrgID: 3, UID: 5})
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 8, UID: 5})
	member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusNotFound)

	// deleting the group removes the remaining memberships
	admin.MakeRequest(t, NewRequest(t, "POST", groupURL+"/delete"), http.StatusOK)
	unittest.AssertNotExistsBean(t, &organization.UserGroup{ID: group.ID})
	unittest.AssertNotExistsBean(t, &organization.TeamUser{TeamID: 8, UID: 5})
}

func TestUserGroupAddMembersByInvitations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user1")
	hint := "Members of linked user groups join the team directly, without an invitation."

	resp := admin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/team1"), http.StatusOK)
	assert.NotContains(t, resp.Body.String(), hint)

	defer test.MockVariableValue(&setting.Service.AddMembersByInvitations, true)()
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/team1"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), hint)

	// linking a group still adds its members directly, without an invitation
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{"name": "qa"}), http.StatusSeeOther)
	group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "qa"})
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/groups/%d/members/add", group.ID), map[string]string{"uname": "user5"}), http.StatusSeeOther)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/group/link", map[string]string{"group_name": "qa"}), http.StatusSeeOther)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 2, UID: 5})
	unittest.AssertNotExistsBean(t, &organization.TeamInvite{TeamID: 2})
}

func TestUserGroupAdminPages(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user1")

	resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/groups"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "There are no user groups yet.")

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{"name": "qa"}), http.StatusSeeOther)
	group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "qa"})
	groupURL := fmt.Sprintf("/admin/groups/%d", group.ID)

	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/groups?q=q"), http.StatusOK)
	NewHTMLParser(t, resp.Body).AssertElement(t, fmt.Sprintf(`a[href="%s"]`, groupURL), true)

	// invalid names are rejected
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{"name": "not valid!"}), http.StatusOK)
	assert.Equal(t, "qa", unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{ID: group.ID}).Name)

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{
		"name":        "Quality",
		"description": "QA engineers",
	}), http.StatusSeeOther)
	group = unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{ID: group.ID})
	assert.Equal(t, "quality", group.LowerName)
	assert.Equal(t, "QA engineers", group.Description)

	// the pages are reserved to site administrators
	user := loginUser(t, "user2")
	user.MakeRequest(t, NewRequest(t, "GET", "/admin/groups"), http.StatusForbidden)
	user.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{"name": "sneaky"}), http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &organization.UserGroup{LowerName: "sneaky"})

	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/groups/9999"), http.StatusNotFound)
	require.NotNil(t, resp)
}

// A team of an organization in the trash stays linked: the group pages, the API and the member sync keep working.
func TestUserGroupLinkedTeamOfTrashedOrg(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user1")
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{"name": "trashed-org-group"}), http.StatusSeeOther)
	group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "trashed-org-group"})
	groupURL := fmt.Sprintf("/admin/groups/%d", group.ID)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/group/link", map[string]string{"group_name": "trashed-org-group"}), http.StatusSeeOther)

	_, err := db.GetEngine(t.Context()).ID(3).Cols("trashed_unix").Update(&user_model.User{TrashedUnix: 1})
	require.NoError(t, err)
	// like the trash, which takes the repositories of the organization along
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE owner_id = 3")
	require.NoError(t, err)

	resp := admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "organization in the trash")

	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups/trashed-org-group/teams").AddTokenAuth(token), http.StatusOK)
	var teams []api.Team
	DecodeJSON(t, resp, &teams)
	require.Len(t, teams, 1)
	assert.Equal(t, "org3", teams[0].Organization.UserName)

	// the member sync still reaches the team of the trashed organization
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/members/add", map[string]string{"uname": "user5"}), http.StatusSeeOther)
	isMember, err := organization.IsTeamMember(t.Context(), 3, 2, 5)
	require.NoError(t, err)
	assert.True(t, isMember)

	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/groups/trashed-org-group").AddTokenAuth(token), http.StatusNoContent)
	unittest.AssertNotExistsBean(t, &organization.UserGroup{ID: group.ID})
}
