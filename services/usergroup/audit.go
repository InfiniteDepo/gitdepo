// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package usergroup

import (
	"context"

	audit_model "forgejo.org/models/audit"
	org_model "forgejo.org/models/organization"
)

// groupFields are the audited fields of a user group: its name and the roles it grants.
func groupFields(g *org_model.UserGroup) map[string]any {
	return map[string]any{
		"name": g.Name, "grants_site_admin": g.GrantsSiteAdmin, "grants_create_organization": g.GrantsCreateOrganization,
		"grants_auditor": g.GrantsAuditor, "grants_org_admin": g.GrantsOrgAdmin,
	}
}

// recordGroup records a change of the user group g. A membership change has its user as subject, a team link the
// team's organization as owner.
func recordGroup(ctx context.Context, action string, g *org_model.UserGroup, ownerID, subject int64, data map[string]any) error {
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, OwnerID: ownerID, SubjectUserID: subject,
		TargetType: "user_group", TargetID: g.ID, TargetName: g.Name, Data: data,
	})
}

func memberData(uid, loginSourceID int64) map[string]any {
	data := map[string]any{"user_id": uid}
	if loginSourceID != 0 {
		data["login_source_id"] = loginSourceID
	}
	return data
}

func recordTeamLink(ctx context.Context, action string, g *org_model.UserGroup, team *org_model.Team) error {
	return recordGroup(ctx, action, g, team.OrgID, 0, map[string]any{"team_id": team.ID, "team_name": team.Name, "org_id": team.OrgID})
}
