// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

// IPAllowlistSurfaces are the kinds of access the IP allowlist is enforced on
type IPAllowlistSurfaces struct {
	Web      bool `json:"web"`
	API      bool `json:"api"`
	Git      bool `json:"git"`
	SSH      bool `json:"ssh"`
	Packages bool `json:"packages"`
}

// IPAllowlistEntry is an allowed network
type IPAllowlistEntry struct {
	// IPv4 or IPv6 network, e.g. 10.0.0.0/8
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
}

// IPAllowlistToken is an exempt personal access token
type IPAllowlistToken struct {
	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`
}

// IPAllowlist is the instance IP allowlist
type IPAllowlist struct {
	Enabled       bool                `json:"enabled"`
	Surfaces      IPAllowlistSurfaces `json:"surfaces"`
	ExemptAdmins  bool                `json:"exempt_admins"`
	Entries       []*IPAllowlistEntry `json:"entries"`
	ExemptUserIDs []int64             `json:"exempt_user_ids"`
	ExemptTokens  []*IPAllowlistToken `json:"exempt_tokens"`
	// The address of the client making this request, as the allowlist sees it
	YourIP string `json:"your_ip"`
	// Whether [ip_allowlist] ENABLED = false in the configuration file turns the list off, so it can't be changed
	FromConfig bool `json:"from_config"`
}

// EditIPAllowlistOption replaces the instance IP allowlist
type EditIPAllowlistOption struct {
	Enabled  bool                `json:"enabled"`
	Surfaces IPAllowlistSurfaces `json:"surfaces"`
	// Whether site admins are exempt; true if omitted
	ExemptAdmins *bool `json:"exempt_admins"`
	// At most 500 entries, descriptions of at most 255 characters
	Entries        []IPAllowlistEntry `json:"entries"`
	ExemptUserIDs  []int64            `json:"exempt_user_ids"`
	ExemptTokenIDs []int64            `json:"exempt_token_ids"`
}
