// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization

import (
	"context"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
)

// UnitName is the short name of a unit in audit entries ("code", "issues", ...).
func UnitName(t unit.Type) string {
	return strings.TrimPrefix(unit.Units[t].NameKey, "repo.")
}

// AuditFields are the fields the audit log keeps for a team (audit_model.Fields["team"]); its units must be loaded.
func (t *Team) AuditFields() map[string]any {
	units := make([]string, 0, len(t.Units))
	for _, u := range t.Units {
		units = append(units, UnitName(u.Type)+":"+u.AccessMode.String())
	}
	slices.Sort(units)
	return map[string]any{
		"name": t.Name, "access_mode": t.AccessMode.String(), "units": units,
		"includes_all_repositories": t.IncludesAllRepositories, "can_create_org_repo": t.CanCreateOrgRepo,
	}
}

// RecordTeam records ev about the team t in its organization; ev names the action and any repository, project,
// subject and data.
func RecordTeam(ctx context.Context, t *Team, ev audit_model.Event) error {
	ev.Result, ev.OwnerID, ev.TargetType, ev.TargetID, ev.TargetName = audit_model.ResultSuccess, t.OrgID, "team", t.ID, t.Name
	return audit_model.Record(ctx, ev)
}

var membershipReasonNames = []string{"unknown", "org_creator", "added_by_user", "added_by_auth_provider", "added_by_user_group"}

// AuditName is how the audit log names r.
func (r MembershipReason) AuditName() string {
	if r < 0 || int(r) >= len(membershipReasonNames) {
		return membershipReasonNames[0]
	}
	return membershipReasonNames[r]
}

// RecordTeamRepo records action (a repository added to or removed from the team t) for repo.
func RecordTeamRepo(ctx context.Context, action string, t *Team, repo *repo_model.Repository) error {
	return RecordTeam(ctx, t, audit_model.Event{
		Action: action, RepoID: repo.ID, GroupID: repo.GroupID, Data: map[string]any{"repo_id": repo.ID, "repo_name": repo.FullName()},
	})
}
