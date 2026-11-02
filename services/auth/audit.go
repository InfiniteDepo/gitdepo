// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"net/netip"
	"strconv"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/timeutil"
)

// RecordSignIn records a successful interactive sign-in of u with its method (e.g. "password", "ldap:3",
// "password+totp"), and makes u the actor of the rest of the request. reason says how a sign-in that isn't a plain
// credential check happened, e.g. "reset_code".
func RecordSignIn(ctx context.Context, u *user_model.User, method, reason string) {
	a := audit_model.ActorFromContext(ctx)
	if a == nil {
		a = &audit_model.Actor{}
		ctx = audit_model.WithActor(ctx, a)
	}
	a.Type, a.ID, a.Name = audit_model.ActorUser, u.ID, u.Name
	a.Credential = audit_model.Credential{Type: audit_model.CredentialSession, OwnerID: u.ID}
	data := map[string]any{"method": method}
	if reason != "" {
		data["reason"] = reason
	}
	audit_model.RecordActivity(ctx, audit_model.Event{
		Action: "auth.signin.success", Result: audit_model.ResultSuccess, OwnerID: u.ID, SubjectUserID: u.ID,
		TargetType: "signin", TargetID: u.ID, TargetName: u.Name, Data: data,
	})
}

// ActorIPKey is the request actor's client IP for aggregation keys (see audit_model.IPKey).
func ActorIPKey(ctx context.Context, bits int) string {
	if a := audit_model.ActorFromContext(ctx); a != nil {
		return audit_model.IPKey(a, bits)
	}
	return ""
}

// RecordSignInFailure records a failed sign-in, aggregated per client IP (/48 for IPv6), user and reason. subject is
// the user when it is known, else 0: a typed name that matches no user is never recorded.
func RecordSignInFailure(ctx context.Context, subject int64, reason string) {
	audit_model.RecordAggregated(ctx, audit_model.Event{
		Action: "auth.signin.failed", Result: audit_model.ResultFailure, OwnerID: subject, SubjectUserID: subject,
		TargetType: "signin", TargetID: subject, Data: map[string]any{"reason": reason},
	}, ActorIPKey(ctx, 48)+"|"+strconv.FormatInt(subject, 10)+"|"+reason)
}

// RecordRefusal records a request refused by a policy (reason "ip_allowlist", "rate_limit", "expired", ...),
// aggregated per key. ownerID is the organization whose policy refused, if any.
func RecordRefusal(ctx context.Context, reason string, ownerID, subject int64, key string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["reason"] = reason
	audit_model.RecordAggregated(ctx, audit_model.Event{
		Action: "auth.refused", Result: audit_model.ResultRefused, OwnerID: ownerID, SubjectUserID: subject,
		TargetType: "refusal", TargetID: subject, Data: data,
	}, reason+"|"+key)
}

// RecordConnectionRefused records, aggregated per rate limit class and client address (an IPv6 /64), that the rate
// limiter closed a connection of remoteAddr ("host:port") before any request: there is no request, so the actor is an
// anonymous one with that address. It writes to the database, so callers outside a request run it off their hot path.
func RecordConnectionRefused(ctx context.Context, class, remoteAddr string) {
	a := &audit_model.Actor{Type: audit_model.ActorAnonymous, IP: "invalid"}
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		a.IP = ap.Addr().Unmap().WithZone("").String()
	}
	RecordRefusal(audit_model.WithActor(ctx, a), "rate_limit", 0, 0, "conn|"+class+"|"+ratelimit.IPKey(remoteAddr), map[string]any{"class": class})
}

// RecordTwoFactorBlocked records once per user, organization and UTC day that the organization's two-factor
// requirement refused the user.
func RecordTwoFactorBlocked(ctx context.Context, uid, orgID int64) {
	key := "2fa|" + strconv.FormatInt(uid, 10) + "|" + strconv.FormatInt(orgID, 10)
	if audit_model.SeenToday(key) {
		return
	}
	if audit_model.RecordActivity(ctx, audit_model.Event{
		Action: "auth.refused", Result: audit_model.ResultRefused, OwnerID: orgID, SubjectUserID: uid,
		TargetType: "refusal", TargetID: uid, Data: map[string]any{"reason": "org_two_factor"},
	}) {
		audit_model.MarkSeenToday(key)
	}
}

// RecordTwoFactorBlockedMember is RecordTwoFactorBlocked for the denial points of the API and of git: it records only
// when owner is an organization whose two-factor requirement blocks doer, who is one of its members. Anything else
// records nothing, and a failed lookup is logged: the denial itself stays as it is.
func RecordTwoFactorBlockedMember(ctx context.Context, doer, owner *user_model.User) {
	if doer == nil || owner == nil || !owner.IsOrganization() || !owner.RequireTwoFactor {
		return
	}
	blocked, err := doer.TwoFactorBlocked(ctx, owner)
	if err == nil && blocked {
		blocked, err = organization.IsOrganizationMember(ctx, owner.ID, doer.ID)
	}
	if err != nil {
		log.Error("RecordTwoFactorBlockedMember: %v", err)
		return
	}
	if blocked {
		RecordTwoFactorBlocked(ctx, doer.ID, owner.ID)
	}
}

var expiredActions = map[string]string{
	audit_model.CredentialAccessToken:      "credential.access_token.expired",
	audit_model.CredentialSSHKey:           "credential.ssh_key.expired",
	audit_model.CredentialDeployKey:        "credential.deploy_key.expired",
	audit_model.CredentialOrgDeployKey:     "credential.org_deploy_key.expired",
	audit_model.CredentialProjectDeployKey: "credential.project_deploy_key.expired",
	audit_model.CredentialOAuth2App:        "credential.oauth2_app.expired",
}

// RecordExpired records the first refusal of an expired credential once (credential.<type>.expired, also across
// pods and restarts: an existing entry counts), and every later one as an aggregated "expired" refusal.
func RecordExpired(ctx context.Context, credType string, id, ownerID int64, name string, expires timeutil.TimeStamp) {
	action := expiredActions[credType]
	key := credType + ":" + strconv.FormatInt(id, 10)
	if !audit_model.Seen("expired|" + key) {
		has, err := audit_model.HasEntry(ctx, action, credType, id)
		if err != nil {
			log.Error("audit: HasEntry: %v", err)
			return
		}
		field := "expires"
		if credType == audit_model.CredentialOAuth2App {
			field = "secret_expires"
		}
		if has || audit_model.RecordActivity(ctx, audit_model.Event{
			Action: action, Result: audit_model.ResultRefused, OwnerID: ownerID, SubjectUserID: ownerID,
			TargetType: credType, TargetID: id, TargetName: name, Data: map[string]any{field: int64(expires)},
		}) {
			audit_model.MarkSeen("expired|" + key)
		}
		if !has {
			return
		}
	}
	RecordRefusal(ctx, "expired", 0, ownerID, key, map[string]any{"class": credType})
}
