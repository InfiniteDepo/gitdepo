// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"context"

	audit_model "forgejo.org/models/audit"
)

// AuditFields are the account fields the audit log keeps for a user (audit_model.Fields["user"]).
func (u *User) AuditFields() map[string]any {
	return map[string]any{
		"name": u.Name, "email": u.Email, "is_admin": u.IsAdmin, "is_restricted": u.IsRestricted, "is_active": u.IsActive,
		"prohibit_login": u.ProhibitLogin, "visibility": int(u.Visibility), "login_source": u.LoginSource,
		"login_type": int(u.LoginType), "must_change_password": u.MustChangePassword, "require_two_factor": u.RequireTwoFactor,
		"is_auditor": u.IsAuditor, "allow_create_organization": u.AllowCreateOrganization, "allow_git_hook": u.AllowGitHook,
		"allow_import_local": u.AllowImportLocal, "max_repo_creation": u.MaxRepoCreation,
		"personal_repo_size_limit": u.PersonalRepoSizeLimit, "category_id": u.CategoryID,
	}
}

// RecordUser records an account event of u in the audit log.
func RecordUser(ctx context.Context, action string, u *User, data map[string]any) error {
	return audit_model.RecordAccount(ctx, action, u.ID, "user", u.ID, u.Name, data)
}

// RecordUserChange records account.user.updated with the audited fields of u that differ from before (an
// AuditFields result), and nothing when none does. Organizations are audited with their settings, not here.
func RecordUserChange(ctx context.Context, before map[string]any, u *User) error {
	if u.IsOrganization() {
		return nil
	}
	b, a := map[string]any{}, map[string]any{}
	for k, v := range u.AuditFields() {
		if before[k] != v {
			b[k], a[k] = before[k], v
		}
	}
	if len(a) == 0 {
		return nil
	}
	return RecordUser(ctx, "account.user.updated", u, map[string]any{"before": b, "after": a})
}

// RecordEmail records an event of the email address e of its user.
func RecordEmail(ctx context.Context, action string, e *EmailAddress) error {
	return audit_model.RecordAccount(ctx, action, e.UID, "email", e.ID, e.Email, map[string]any{
		"address": e.Email, "primary": e.IsPrimary, "activated": e.IsActivated,
	})
}

// OrgAuditFields are the settings the audit log keeps for an organization (audit_model.Fields["org"]).
func (u *User) OrgAuditFields() map[string]any {
	return map[string]any{
		"visibility": int(u.Visibility), "require_two_factor": u.RequireTwoFactor,
		"restrict_repo_visibility_change": u.RestrictRepoVisibilityChange, "private_fork_policy": u.PrivateForkPolicy,
		"repo_admin_change_team_access": u.RepoAdminChangeTeamAccess, "max_repo_creation": u.MaxRepoCreation,
		"category_id": u.CategoryID, "is_active": u.IsActive, "prohibit_login": u.ProhibitLogin,
	}
}

// RecordOrg records an event of the organization org.
func RecordOrg(ctx context.Context, action string, org *User, data map[string]any) error {
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, OwnerID: org.ID, TargetType: "org", TargetID: org.ID,
		TargetName: org.Name, Data: data,
	})
}

// RecordOrgChange records org.organization.updated with the settings of org that differ from before, the row as it
// was stored, and nothing when none does or before is nil (u isn't an organization).
func RecordOrgChange(ctx context.Context, before, org *User) error {
	if before == nil {
		return nil
	}
	if changes := audit_model.Changes(before.OrgAuditFields(), org.OrgAuditFields()); changes != nil {
		return RecordOrg(ctx, "org.organization.updated", org, changes)
	}
	return nil
}
