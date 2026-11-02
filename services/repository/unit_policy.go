// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"slices"
	"strings"
	"time"

	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
)

// MaxUnitPolicyOrgs caps the organizations selected for one unit.
const MaxUnitPolicyOrgs = 500

// UnitPolicyChange is one unit of the site policy as an admin submits it.
type UnitPolicyChange struct {
	Allowed   bool     // allowed for all organizations by default
	OrgNames  []string // organizations that get the opposite of the default
	OnDefault bool     // on for new repositories
}

// UnitPolicyLocked reports whether app.ini sets the unit: DISABLED_REPO_UNITS locks it entirely.
func UnitPolicyLocked(t unit.Type) bool {
	return t.UnitGlobalDisabled()
}

// DefaultUnitsLocked reports whether app.ini DEFAULT_REPO_UNITS sets the units on for new repositories.
func DefaultUnitsLocked() bool {
	return len(setting.Repository.DefaultRepoUnits) > 0
}

// SetUnitPolicy validates and stores the site policy for the units in changes, keyed by unit type. Units that are
// not in changes keep their stored values; changing a unit app.ini locks is refused.
func SetUnitPolicy(ctx context.Context, doer *user_model.User, changes map[unit.Type]UnitPolicyChange) error {
	old := setting.Config().RepoUnitPolicy.Value(ctx)
	s := setting.RepoUnitPolicyState{OrgOverrides: map[string][]int64{}, UpdatedUnix: time.Now().Unix()}
	if doer != nil {
		s.UpdatedBy = doer.ID
	}
	defaults := old.DefaultUnits
	if defaults == nil {
		for _, t := range unit.DefaultRepoUnits {
			defaults = append(defaults, unit.Units[t].NameKey)
		}
	}
	newDefaults := []string{}
	for _, t := range repo_model.PolicyUnitTypes() {
		key := unit.Units[t].NameKey
		c, changed := changes[t]
		if changed && UnitPolicyLocked(t) {
			return util.NewInvalidArgumentErrorf("%s is disabled in app.ini", key)
		}
		if changed && c.OnDefault && (!t.CanBeDefault() || DefaultUnitsLocked()) {
			return util.NewInvalidArgumentErrorf("%s can't be set on by default", key)
		}
		if !changed {
			if slices.Contains(old.NotAllowed, key) {
				s.NotAllowed = append(s.NotAllowed, key)
			}
			if ids := old.OrgOverrides[key]; len(ids) > 0 {
				s.OrgOverrides[key] = ids
			}
			if slices.Contains(defaults, key) {
				newDefaults = append(newDefaults, key)
			}
			continue
		}
		if !c.Allowed {
			s.NotAllowed = append(s.NotAllowed, key)
		}
		if len(c.OrgNames) > MaxUnitPolicyOrgs {
			return util.NewInvalidArgumentErrorf("%s: at most %d organizations can be selected", key, MaxUnitPolicyOrgs)
		}
		seen := map[string]bool{}
		for _, name := range c.OrgNames {
			lower := strings.ToLower(name)
			if seen[lower] {
				return util.NewInvalidArgumentErrorf("%s: %s is listed twice", key, name)
			}
			seen[lower] = true
			org, err := organization.GetOrgByName(ctx, name)
			if organization.IsErrOrgNotExist(err) {
				return util.NewInvalidArgumentErrorf("%s: %s is not an organization", key, name)
			}
			if err != nil {
				return err
			}
			s.OrgOverrides[key] = append(s.OrgOverrides[key], org.ID)
		}
		if c.OnDefault {
			newDefaults = append(newDefaults, key)
		}
	}
	if !DefaultUnitsLocked() {
		s.DefaultUnits = append([]string{unit.Units[unit.TypeCode].NameKey}, newDefaults...)
	}
	v, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().RepoUnitPolicy.DynKey(): string(v)}); err != nil {
		return err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return nil
}
