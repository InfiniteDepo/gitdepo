// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package oauth2app decides who may create and change OAuth2 applications.
package oauth2app

import (
	"context"
	"slices"
	"time"

	"forgejo.org/models/organization"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
)

// MaxOrgs caps the selected organizations.
const MaxOrgs = 500

// Policy returns the stored policy. Anything but a known mode reads as "site admins only".
func Policy(ctx context.Context) setting.OAuth2AppPolicyState {
	s := setting.Config().OAuth2AppPolicy.Value(ctx)
	if s.Mode != setting.OAuth2AppPolicyOrgs && s.Mode != setting.OAuth2AppPolicyEveryone {
		s.Mode = setting.OAuth2AppPolicyAdmins
	}
	return s
}

// MayManage reports whether doer may create or change (name, redirect URIs, secret) an OAuth2 application owned by
// ownerID: a user, an organization, or 0 for instance-wide ones. Every create and update path calls it.
func MayManage(ctx context.Context, doer *user_model.User, ownerID int64) (bool, error) {
	if doer == nil || !doer.IsActive || doer.ProhibitLogin {
		return false, nil
	}
	if doer.IsAdmin {
		return true, nil
	}
	if ownerID == 0 {
		return false, nil
	}
	p := Policy(ctx)
	if p.Mode == setting.OAuth2AppPolicyAdmins {
		return false, nil
	}
	if ownerID == doer.ID {
		return p.Mode == setting.OAuth2AppPolicyEveryone, nil
	}
	owner, err := user_model.GetUserByID(ctx, ownerID)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !owner.IsOrganization() || (p.Mode == setting.OAuth2AppPolicyOrgs && !slices.Contains(p.OrgIDs, ownerID)) {
		return false, nil
	}
	return organization.OrgFromUser(owner).IsActingOwner(ctx, doer)
}

// OwnerAllowed reports whether the owner of an existing application could create one today, for the admin review
// list. A nil owner (deleted) is not allowed.
func OwnerAllowed(p setting.OAuth2AppPolicyState, owner *user_model.User) bool {
	switch {
	case owner == nil:
		return false
	case owner.IsOrganization():
		return p.Mode == setting.OAuth2AppPolicyEveryone || (p.Mode == setting.OAuth2AppPolicyOrgs && slices.Contains(p.OrgIDs, owner.ID))
	default:
		return owner.IsActive && !owner.ProhibitLogin && (owner.IsAdmin || p.Mode == setting.OAuth2AppPolicyEveryone)
	}
}

// Set validates and stores the policy. orgNames are only read in the selected organizations mode.
func Set(ctx context.Context, doer *user_model.User, mode string, orgNames []string) error {
	if !slices.Contains([]string{setting.OAuth2AppPolicyAdmins, setting.OAuth2AppPolicyOrgs, setting.OAuth2AppPolicyEveryone}, mode) {
		return util.NewInvalidArgumentErrorf("unknown mode %q", mode)
	}
	s := setting.OAuth2AppPolicyState{Mode: mode, UpdatedBy: doer.ID, UpdatedUnix: time.Now().Unix()}
	if mode == setting.OAuth2AppPolicyOrgs {
		if len(orgNames) > MaxOrgs {
			return util.NewInvalidArgumentErrorf("at most %d organizations can be selected", MaxOrgs)
		}
		for _, name := range orgNames {
			org, err := organization.GetOrgByName(ctx, name)
			if organization.IsErrOrgNotExist(err) {
				return util.NewInvalidArgumentErrorf("%s: not an organization", name)
			}
			if err != nil {
				return err
			}
			s.OrgIDs = append(s.OrgIDs, org.ID)
		}
	}
	v, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().OAuth2AppPolicy.DynKey(): string(v)}); err != nil {
		return err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return nil
}
