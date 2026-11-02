// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// AccessRow is the access of one identity to a repository, and every path that gives it
type AccessRow struct {
	// person, bot, key, token, team, anyone, signed_in or instance_roles
	Type        string             `json:"type"`
	User        *User              `json:"user,omitempty"`
	DeployKey   *AccessDeployKey   `json:"deploy_key,omitempty"`
	AccessToken *AccessAccessToken `json:"access_token,omitempty"`
	Team        *AccessTeam        `json:"team,omitempty"`
	Repository  string             `json:"repository"`
	// highest access on any unit: none, read, write, admin or owner
	Access string            `json:"access"`
	Units  map[string]string `json:"units"`
	Paths  []*AccessPath     `json:"paths"`
}

// AccessPath is one source of access
type AccessPath struct {
	// owner, site_admin, auditor, org_owner, admin_team, team, collaborator, public, internal, org_member,
	// deploy_key, org_deploy_key, project_deploy_key, repo_token, project_token, org_token or instance_roles
	Kind       string             `json:"kind"`
	Access     string             `json:"access"`
	Units      map[string]string  `json:"units,omitempty"`
	Team       string             `json:"team,omitempty"`
	UserGroups []*AccessUserGroup `json:"user_groups,omitempty"`
	// false when the permission checks don't use this path for any unit
	Applied bool `json:"applied"`
}

// AccessUserGroup is a user group that made a user a member of a team
type AccessUserGroup struct {
	Name string `json:"name"`
	// the login source that synced the membership
	LoginSource string `json:"login_source,omitempty"`
}

// AccessDeployKey is a deploy key in an access report
type AccessDeployKey struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	// swagger:strfmt date-time
	Expires *time.Time `json:"expires_at,omitempty"`
}

// AccessAccessToken is an access token of a repository, a project or an organization in an access report
type AccessAccessToken struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// the API scopes of the token, which can be fewer than the units the permission lists
	Scopes []string `json:"scopes"`
	// swagger:strfmt date-time
	Expires *time.Time `json:"expires_at,omitempty"`
}

// AccessTeam is a team shown as one row, to a viewer outside the organization
type AccessTeam struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	NumMembers int    `json:"num_members"`
}

// AccessCredential is an SSH key, access token or OAuth2 grant of a user
type AccessCredential struct {
	// ssh_key, access_token or oauth2_grant
	Kind string `json:"kind"`
	Name string `json:"name"`
	// SSH key fingerprint
	Fingerprint string `json:"fingerprint,omitempty"`
	// last eight characters of an access token
	LastEight string   `json:"last_eight,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
	// swagger:strfmt date-time
	LastUsed time.Time `json:"last_used_at"`
	// swagger:strfmt date-time
	Expires *time.Time `json:"expires_at,omitempty"`
}

// UserAccess is everything that gives a user access
type UserAccess struct {
	SiteAdmin bool `json:"site_admin"`
	// user groups that granted the role, empty if it was set directly
	SiteAdminVia string   `json:"site_admin_via,omitempty"`
	Auditor      bool     `json:"auditor"`
	AuditorVia   string   `json:"auditor_via,omitempty"`
	Orgs         []string `json:"organizations"`
	// private organizations whose public repositories the user reads as a member
	PrivateOrgs []string            `json:"private_organizations"`
	Teams       []string            `json:"teams"`
	UserGroups  []*AccessUserGroup  `json:"user_groups"`
	Rows        []*AccessRow        `json:"repositories"`
	Credentials []*AccessCredential `json:"credentials"`
}

// AccessReportLine is one path that gives an identity access to one unit of a repository
type AccessReportLine struct {
	// person, bot, key, token, team, anyone, signed_in, org_members or instance_roles
	Type string `json:"type"`
	// user, deploy key, access token or team name
	Name     string `json:"name,omitempty"`
	FullName string `json:"full_name,omitempty"`
	// the API scopes of an access token, which can be fewer than the units its permission lists
	Scopes     []string `json:"scopes,omitempty"`
	Repository string   `json:"repository"`
	// unit, e.g. repo.code, or * for all units
	Unit string `json:"unit"`
	// effective access to the unit
	Access     string             `json:"access"`
	Path       string             `json:"path"`
	Team       string             `json:"team,omitempty"`
	UserGroups []*AccessUserGroup `json:"user_groups,omitempty"`
	// access this path grants to the unit
	Grant string `json:"grant"`
	// false when the permission checks don't use this path for any unit
	Applied bool `json:"applied"`

	// the fields below are only for users, and only for site admins

	// swagger:strfmt date-time
	LastLogin *time.Time `json:"last_login,omitempty"`
	// last push to a repository of the report
	// swagger:strfmt date-time
	LastPush  *time.Time `json:"last_push,omitempty"`
	TwoFactor *bool      `json:"two_factor,omitempty"`
	// login type, and the name of the login source
	AccountSource string `json:"account_source,omitempty"`
	// the user can't sign in, or isn't activated
	Suspended *bool `json:"suspended,omitempty"`
}
