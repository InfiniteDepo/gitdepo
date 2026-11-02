// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package quota

import (
	"context"
	"maps"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
)

func ruleFields(r *Rule) map[string]any {
	subjects := make([]string, 0, len(r.Subjects))
	for _, s := range r.Subjects {
		subjects = append(subjects, s.String())
	}
	return map[string]any{"name": r.Name, "limit": r.Limit, "subjects": subjects}
}

func recordRule(ctx context.Context, action string, r *Rule, data map[string]any) error {
	fields := ruleFields(r)
	maps.Copy(fields, data)
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, TargetType: "quota_rule", TargetName: r.Name, Data: fields,
	})
}

// recordGroup records a change of the quota group name; one of a user's membership has the user as subject.
func recordGroup(ctx context.Context, action, name string, subject int64, data map[string]any) error {
	fields := map[string]any{"name": name}
	maps.Copy(fields, data)
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, OwnerID: subject, SubjectUserID: subject,
		TargetType: "quota_group", TargetName: name, Data: fields,
	})
}

// userGroupNames are the quota groups the user is a member of (not the default groups).
func userGroupNames(ctx context.Context, userID int64) ([]string, error) {
	names := make([]string, 0, 4)
	err := db.GetEngine(ctx).Table("quota_group_mapping").Where("kind = ? AND mapped_id = ?", KindUser, userID).
		Cols("group_name").OrderBy("group_name").Find(&names)
	return names, err
}
