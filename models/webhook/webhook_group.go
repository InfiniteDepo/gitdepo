// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package webhook

import (
	"context"

	"forgejo.org/models/db"

	"xorm.io/builder"
)

// organizationType is user_model.UserTypeOrganization; models/user is not imported, its tables would have to be registered
// by every test of this package.
const organizationType = 1

// orphanedGroupWebhooksCond matches project hooks whose project is gone, belongs to another organization, or whose
// owner is not an organization.
func orphanedGroupWebhooksCond() builder.Cond {
	return builder.And(builder.Neq{"group_id": 0}, builder.Or(
		builder.NotIn("owner_id", builder.Select("id").From("`user`").Where(builder.Eq{"type": organizationType})),
		builder.NotIn("group_id", builder.Select("id").From("repo_group").Where(builder.Expr("repo_group.owner_id = webhook.owner_id"))),
	))
}

// CountOrphanedGroupWebhooks counts the hooks DeleteOrphanedGroupWebhooks deletes.
func CountOrphanedGroupWebhooks(ctx context.Context) (int64, error) {
	return db.GetEngine(ctx).Where(orphanedGroupWebhooksCond()).Count(new(Webhook))
}

// DeleteOrphanedGroupWebhooks deletes the orphaned project hooks with their deliveries.
func DeleteOrphanedGroupWebhooks(ctx context.Context) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		ids := []int64{}
		if err := db.GetEngine(ctx).Table("webhook").Where(orphanedGroupWebhooksCond()).Cols("id").Find(&ids); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if _, err := db.GetEngine(ctx).In("hook_id", ids).Delete(new(HookTask)); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).In("id", ids).Delete(new(Webhook))
		return err
	})
}
