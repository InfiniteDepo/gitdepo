// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package webhook

import (
	"context"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
)

// AuditFields are the settings the audit log keeps before/after for a webhook: of its URL only the origin, never the
// secret, the authorization header or the hook-specific metadata.
func (w *Webhook) AuditFields() map[string]any {
	fields := map[string]any{
		"origin": audit_model.Origin(w.URL), "type": w.Type, "http_method": w.HTTPMethod,
		"content_type": w.ContentType.Name(), "is_active": w.IsActive,
	}
	if w.HookEvent != nil {
		fields["events"], fields["branch_filter"] = w.EventsArray(), w.BranchFilter
	}
	return fields
}

// recordWebhook records the action of actions for w's level, in the scope of its repository, project, organization,
// user or the instance (data.kind system or default). models/repo and models/user import this package, so the scope
// is read with plain SQL.
func recordWebhook(ctx context.Context, actions audit_model.LevelActions, w *Webhook, data map[string]any) error {
	ev := audit_model.Event{
		Result: audit_model.ResultSuccess, TargetType: "webhook", TargetID: w.ID, TargetName: audit_model.Origin(w.URL),
		OwnerID: w.OwnerID, GroupID: w.GroupID, RepoID: w.RepoID, Data: data,
	}
	switch {
	case w.RepoID != 0:
		ev.Action = actions.Repo
		if _, err := db.GetEngine(ctx).Table("repository").Where("id = ?", w.RepoID).Cols("owner_id", "group_id").Get(&ev.OwnerID, &ev.GroupID); err != nil {
			return err
		}
	case w.OwnerID != 0:
		isOrg, err := db.GetEngine(ctx).Table("user").Where("id = ? AND type = ?", w.OwnerID, organizationType).Exist()
		if err != nil {
			return err
		}
		ev.Action = actions.Org
		if !isOrg {
			ev.Action, ev.SubjectUserID = actions.Account, w.OwnerID
		}
	default:
		ev.Action = actions.Admin
		data["kind"] = "default"
		if w.IsSystemWebhook {
			data["kind"] = "system"
		}
	}
	return audit_model.Record(ctx, ev)
}
