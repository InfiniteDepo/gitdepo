// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

// MaxVerifiedDomains is how many domains an organization can verify.
const MaxVerifiedDomains = 10

var (
	ErrInvalidDomain        = util.NewInvalidArgumentErrorf("invalid domain")
	ErrTooManyDomains       = util.NewInvalidArgumentErrorf("too many verified domains")
	ErrDomainRecordNotFound = util.NewInvalidArgumentErrorf("record not found yet")
	ErrNoVerifiedDomains    = util.NewInvalidArgumentErrorf("no verified domains")
	ErrEmailConfirmationOff = util.NewInvalidArgumentErrorf("email confirmation is off")
)

// LookupTXT resolves TXT records; tests replace it.
var LookupTXT = (&net.Resolver{}).LookupTXT

var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain lower-cases and validates a domain: ASCII only (punycode for internationalized names), at most 253
// characters, at least two labels, no trailing dot and no IP address.
func NormalizeDomain(s string) (string, error) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", ErrInvalidDomain
		}
	}
	s = strings.ToLower(s)
	labels := strings.Split(s, ".")
	if len(s) > 253 || len(labels) < 2 || net.ParseIP(s) != nil {
		return "", ErrInvalidDomain
	}
	for _, l := range labels {
		if !domainLabel.MatchString(l) {
			return "", ErrInvalidDomain
		}
	}
	return s, nil
}

// DomainRecordName is the DNS name of the TXT record that verifies a domain.
func DomainRecordName(domain string) string {
	return "_gitdepo-verify." + domain
}

// DomainRecordValue is the TXT record value that proves the organization controls the domain. It is derived from the
// instance secret, the organization and the domain, so it is never stored and no other organization can reuse it.
func DomainRecordValue(orgID int64, domain string) string {
	mac := hmac.New(sha256.New, []byte(setting.SecretKey))
	mac.Write([]byte("org-domain-verify:" + strconv.FormatInt(orgID, 10) + ":" + domain))
	return "gitdepo-verification=" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyDomain verifies a domain for an organization by its TXT record or, withoutDNS, on a site admin's word.
func VerifyDomain(ctx context.Context, org *org_model.Organization, doer *user_model.User, domain string, withoutDNS bool) error {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return err
	}
	if withoutDNS && !(doer.IsAdmin && doer.IsActive && !doer.ProhibitLogin) {
		return util.ErrPermissionDenied
	}
	domains, err := org_model.GetVerifiedDomains(ctx, org.ID)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(domains, func(d *org_model.OrgVerifiedDomain) bool { return d.Domain == domain }) {
		return nil
	}
	if len(domains) >= MaxVerifiedDomains {
		return ErrTooManyDomains
	}
	if taken, err := db.GetEngine(ctx).Exist(&org_model.OrgVerifiedDomain{Domain: domain}); err != nil {
		return err
	} else if taken {
		return org_model.ErrDomainVerifiedByOtherOrg
	}

	d := &org_model.OrgVerifiedDomain{OrgID: org.ID, Domain: domain, VerifiedUnix: timeutil.TimeStampNow()}
	d.LastCheckedUnix = d.VerifiedUnix
	if withoutDNS {
		d.VerifiedByAdminID = doer.ID
	} else if !hasDomainRecord(ctx, org.ID, domain) { // DNS: before the transaction
		return ErrDomainRecordNotFound
	}
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		if err := org_model.AddVerifiedDomain(ctx, d); err != nil {
			return err
		}
		data := map[string]any{"domain": domain}
		if withoutDNS {
			data["verified_by_admin"] = true
		}
		return user_model.RecordOrg(ctx, "org.verified_domain.added", org.AsUser(), data)
	}); err != nil {
		// checked after the rollback: on PostgreSQL the failed insert aborts the transaction
		if taken, _ := db.GetEngine(ctx).Exist(&org_model.OrgVerifiedDomain{Domain: domain}); taken {
			return org_model.ErrDomainVerifiedByOtherOrg
		}
		return err
	}
	return nil
}

func hasDomainRecord(ctx context.Context, orgID int64, domain string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	records, err := LookupTXT(ctx, DomainRecordName(domain)+".")
	if err != nil {
		log.Debug("verify domain %s of org %d: %v", domain, orgID, err)
		return false
	}
	want := []byte(DomainRecordValue(orgID, domain))
	for _, r := range records {
		if subtle.ConstantTimeCompare([]byte(r), want) == 1 {
			return true
		}
	}
	return false
}

// SetVerifiedDomainRequired turns the member restriction of an organization on or off. It can only be on while the
// organization has a verified domain and users must confirm the email addresses they add.
func SetVerifiedDomainRequired(ctx context.Context, org *org_model.Organization, on bool) error {
	if on && !org_model.EmailConfirmationRequired() {
		return ErrEmailConfirmationOff
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		before, err := org_model.IsVerifiedDomainRequired(ctx, org.ID)
		if err != nil || before == on {
			return err
		}
		if !on {
			return org_model.ClearVerifiedDomainRequired(ctx, org.AsUser())
		}
		if domains, err := org_model.GetVerifiedDomains(ctx, org.ID); err != nil {
			return err
		} else if len(domains) == 0 {
			return ErrNoVerifiedDomains
		}
		if err := user_model.SetUserSetting(ctx, org.ID, org_model.SettingKeyRequireVerifiedDomain, "true"); err != nil {
			return err
		}
		return user_model.RecordOrg(ctx, "org.verified_domain.required_changed", org.AsUser(), map[string]any{
			"before": map[string]any{"required": false}, "after": map[string]any{"required": true},
		})
	})
}
