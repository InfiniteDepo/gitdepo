// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// UserGroup is an instance-wide group of users. Organizations link it to
// their teams, and its members become members of those teams.
type UserGroup struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Number of users in the group
	MembersCount int `json:"members_count"`
	// Number of teams the group is linked to
	TeamsCount int `json:"teams_count"`
	// Members of the group are site administrators
	GrantsSiteAdmin bool `json:"grants_site_admin"`
	// Members of the group may create organizations
	GrantsCreateOrganization bool `json:"grants_create_organization"`
	// Members of the group can read every repository
	GrantsAuditor bool `json:"grants_auditor"`
	// Members of the group are owners of every organization that is not excluded
	GrantsOrgAdmin bool `json:"grants_org_admin"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
	// swagger:strfmt date-time
	Updated time.Time `json:"updated_at"`
}

// CreateUserGroupOption options for creating a user group
type CreateUserGroupOption struct {
	// required: true
	Name        string `json:"name" binding:"Required;AlphaDashDot;MaxSize(255)"`
	Description string `json:"description" binding:"MaxSize(255)"`
	// Members of the group are site administrators
	GrantsSiteAdmin bool `json:"grants_site_admin"`
	// Members of the group may create organizations
	GrantsCreateOrganization bool `json:"grants_create_organization"`
	// Members of the group can read every repository
	GrantsAuditor bool `json:"grants_auditor"`
	// Members of the group are owners of every organization that is not excluded
	GrantsOrgAdmin bool `json:"grants_org_admin"`
}

// EditUserGroupOption options for editing a user group
type EditUserGroupOption struct {
	Name        *string `json:"name" binding:"AlphaDashDot;MaxSize(255)"`
	Description *string `json:"description" binding:"MaxSize(255)"`
	// Members of the group are site administrators
	GrantsSiteAdmin *bool `json:"grants_site_admin"`
	// Members of the group may create organizations
	GrantsCreateOrganization *bool `json:"grants_create_organization"`
	// Members of the group can read every repository
	GrantsAuditor *bool `json:"grants_auditor"`
	// Members of the group are owners of every organization that is not excluded
	GrantsOrgAdmin *bool `json:"grants_org_admin"`
}

// SetOrgAdminExclusionsOption options for replacing the organizations excluded from the org-admin role
type SetOrgAdminExclusionsOption struct {
	// names of the excluded organizations
	// required: true
	Orgs []string `json:"orgs"`
}
