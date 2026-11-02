// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import "slices"

// RepoUnitPolicyState is stored as JSON in the "repository.unit_policy" system setting. It decides which repository
// units organizations may use; repositories owned by users are never restricted by it. Nothing stored means every
// unit is allowed and DEFAULT_REPO_UNITS applies, as before.
type RepoUnitPolicyState struct {
	NotAllowed   []string           `json:"not_allowed"`   // unit name keys Not allowed for all organizations
	OrgOverrides map[string][]int64 `json:"org_overrides"` // unit name key -> organizations with the opposite of the default
	DefaultUnits []string           `json:"default_units"` // units on for new repositories; nil = DEFAULT_REPO_UNITS
	UpdatedBy    int64              `json:"updated_by"`
	UpdatedUnix  int64              `json:"updated_unix"`
	Invalid      bool               `json:"-"` // the stored value can't be parsed: nothing is allowed for organizations
}

// OrgAllowed reports whether the organization orgID may use the unit with the name key.
func (s RepoUnitPolicyState) OrgAllowed(key string, orgID int64) bool {
	return !s.Invalid && slices.Contains(s.NotAllowed, key) == slices.Contains(s.OrgOverrides[key], orgID)
}
