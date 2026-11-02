// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

// Who may register OAuth2 applications.
const (
	OAuth2AppPolicyAdmins   = "admins"
	OAuth2AppPolicyOrgs     = "orgs"
	OAuth2AppPolicyEveryone = "everyone"
)

// OAuth2AppPolicyState is stored as JSON in the "oauth2.app_policy" system setting. An unset or unknown Mode means
// OAuth2AppPolicyAdmins, so an instance without a stored value (fresh or upgraded) is restricted.
type OAuth2AppPolicyState struct {
	Mode        string  `json:"mode"`
	OrgIDs      []int64 `json:"org_ids"`
	UpdatedBy   int64   `json:"updated_by"`
	UpdatedUnix int64   `json:"updated_unix"`
}
