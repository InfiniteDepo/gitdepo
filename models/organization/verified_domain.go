// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

// OrgVerifiedDomain is a domain an organization proved it controls. Only verified domains have a row: the DNS
// challenge is derived from the organization and the domain, so nothing is stored while it is pending.
type OrgVerifiedDomain struct {
	ID                int64              `xorm:"pk autoincr"`
	OrgID             int64              `xorm:"INDEX NOT NULL"`
	Domain            string             `xorm:"VARCHAR(253) UNIQUE NOT NULL"` // lower-case ASCII (punycode)
	VerifiedUnix      timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	LastCheckedUnix   timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	FailingSinceUnix  timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"` // reserved for the periodic re-check
	VerifiedByAdminID int64              `xorm:"NOT NULL DEFAULT 0"` // 0: DNS, otherwise the site admin who verified it
}

func init() {
	db.RegisterModel(new(OrgVerifiedDomain))
}

// SettingKeyRequireVerifiedDomain is the user_setting of an organization that limits new members to users with an
// activated email address on one of its verified domains. Off means no row.
const SettingKeyRequireVerifiedDomain = "org.require_verified_email_domain"

// ErrDomainVerifiedByOtherOrg is returned when another organization already verified the domain.
var ErrDomainVerifiedByOtherOrg = util.NewInvalidArgumentErrorf("domain already verified by another organization")

// ErrUserNoVerifiedDomainEmail is returned when a user can't join an organization that requires an activated email
// address on one of its verified domains. ConfirmationOff: the restriction is on but the site doesn't confirm email
// addresses any more, so nobody can join.
type ErrUserNoVerifiedDomainEmail struct {
	UID, OrgID      int64
	ConfirmationOff bool
}

func (err ErrUserNoVerifiedDomainEmail) Error() string {
	if err.ConfirmationOff {
		return fmt.Sprintf("organization %d requires a verified email domain but email confirmation is off [uid: %d]", err.OrgID, err.UID)
	}
	return fmt.Sprintf("user has no activated email address on a verified domain of the organization [uid: %d, org_id: %d]", err.UID, err.OrgID)
}

// IsErrUserNoVerifiedDomainEmail checks if an error (or one it wraps) is an ErrUserNoVerifiedDomainEmail.
func IsErrUserNoVerifiedDomainEmail(err error) bool {
	var e ErrUserNoVerifiedDomainEmail
	return errors.As(err, &e)
}

// EmailConfirmationRequired is whether users must confirm every email address they add themselves, the condition
// for trusting activated addresses as proof of a domain.
func EmailConfirmationRequired() bool {
	return setting.Service.RegisterEmailConfirm && setting.OAuth2Client.RegisterEmailConfirm
}

// GetVerifiedDomains returns the verified domains of an organization, sorted by name.
func GetVerifiedDomains(ctx context.Context, orgID int64) ([]*OrgVerifiedDomain, error) {
	domains := make([]*OrgVerifiedDomain, 0, 2)
	return domains, db.GetEngine(ctx).Where("org_id = ?", orgID).Asc("domain").Find(&domains)
}

// AddVerifiedDomain stores a verified domain. The unique key on the domain decides when two organizations verify it
// at the same time.
func AddVerifiedDomain(ctx context.Context, d *OrgVerifiedDomain) error {
	if _, err := db.GetEngine(ctx).Insert(d); err != nil {
		if taken, _ := db.GetEngine(ctx).Exist(&OrgVerifiedDomain{Domain: d.Domain}); taken {
			return ErrDomainVerifiedByOtherOrg
		}
		return err
	}
	return nil
}

// RemoveVerifiedDomain removes a verified domain of an organization; removing the last one also turns the member
// restriction off.
func RemoveVerifiedDomain(ctx context.Context, org *user_model.User, domain string) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if n, err := db.GetEngine(ctx).Where("org_id = ? AND domain = ?", org.ID, domain).Delete(new(OrgVerifiedDomain)); err != nil || n == 0 {
			return err
		}
		if err := user_model.RecordOrg(ctx, "org.verified_domain.removed", org, map[string]any{"domain": domain}); err != nil {
			return err
		}
		if n, err := db.GetEngine(ctx).Where("org_id = ?", org.ID).Count(new(OrgVerifiedDomain)); err != nil || n > 0 {
			return err
		}
		return ClearVerifiedDomainRequired(ctx, org)
	})
}

// ClearVerifiedDomainRequired turns the member restriction of org off, recording it when it was on.
func ClearVerifiedDomainRequired(ctx context.Context, org *user_model.User) error {
	if on, err := IsVerifiedDomainRequired(ctx, org.ID); err != nil || !on {
		return err
	}
	if err := user_model.DeleteUserSetting(ctx, org.ID, SettingKeyRequireVerifiedDomain); err != nil {
		return err
	}
	return user_model.RecordOrg(ctx, "org.verified_domain.required_changed", org, map[string]any{
		"before": map[string]any{"required": true}, "after": map[string]any{"required": false},
	})
}

// IsVerifiedDomainRequired reads the member restriction without the settings cache (the cache is per pod).
func IsVerifiedDomainRequired(ctx context.Context, orgID int64) (bool, error) {
	_, err := user_model.GetSettingNoCache(ctx, orgID, SettingKeyRequireVerifiedDomain)
	if user_model.IsErrUserSettingIsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// emailDomain returns the lower-cased domain of an address, or "" when it isn't plain ASCII: a non-ASCII domain never
// matches a verified domain (strings.ToLower would turn the Kelvin sign into a "k").
func emailDomain(email string) string {
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return ""
	}
	d := email[i+1:]
	for j := 0; j < len(d); j++ {
		if d[j] >= 0x80 {
			return ""
		}
	}
	return strings.ToLower(d)
}

// qualifyingUIDs returns which of the users have an activated email address whose domain is exactly one of the
// organization's verified domains.
func qualifyingUIDs(ctx context.Context, orgID int64, uids []int64) (map[int64]bool, error) {
	domains, err := GetVerifiedDomains(ctx, orgID)
	if err != nil || len(domains) == 0 || len(uids) == 0 {
		return nil, err
	}
	verified := make(map[string]bool, len(domains))
	for _, d := range domains {
		verified[d.Domain] = true
	}
	var emails []*user_model.EmailAddress
	if err := db.GetEngine(ctx).In("uid", uids).And("is_activated = ?", true).Find(&emails); err != nil {
		return nil, err
	}
	ok := map[int64]bool{}
	for _, e := range emails {
		if verified[emailDomain(e.Email)] {
			ok[e.UID] = true
		}
	}
	return ok, nil
}

// UserHasVerifiedDomainEmail is whether the user has an activated email address on one of the organization's
// verified domains (exact domain, no subdomains).
func UserHasVerifiedDomainEmail(ctx context.Context, orgID, uid int64) (bool, error) {
	ok, err := qualifyingUIDs(ctx, orgID, []int64{uid})
	return ok[uid], err
}

// NonQualifyingMembers returns the members of the organization who could not join it under the member restriction.
func NonQualifyingMembers(ctx context.Context, orgID int64) ([]*user_model.User, error) {
	var members []*user_model.User
	if err := db.GetEngine(ctx).Join("INNER", "org_user", "org_user.uid = `user`.id").
		Where("org_user.org_id = ?", orgID).Asc("`user`.lower_name").Find(&members); err != nil {
		return nil, err
	}
	uids := make([]int64, len(members))
	for i, u := range members {
		uids[i] = u.ID
	}
	ok, err := qualifyingUIDs(ctx, orgID, uids)
	if err != nil {
		return nil, err
	}
	var res []*user_model.User
	for _, u := range members {
		if !ok[u.ID] {
			res = append(res, u)
		}
	}
	return res, nil
}

// CheckVerifiedDomainGate refuses a new member of an organization with the member restriction on who has no
// activated email address on a verified domain. Any lookup error refuses too.
func CheckVerifiedDomainGate(ctx context.Context, orgID, uid int64) error {
	required, err := IsVerifiedDomainRequired(ctx, orgID)
	if err != nil || !required {
		return err
	}
	if !EmailConfirmationRequired() {
		return ErrUserNoVerifiedDomainEmail{UID: uid, OrgID: orgID, ConfirmationOff: true}
	}
	ok, err := UserHasVerifiedDomainEmail(ctx, orgID, uid)
	if err != nil {
		return err
	} else if !ok {
		return ErrUserNoVerifiedDomainEmail{UID: uid, OrgID: orgID}
	}
	return nil
}
