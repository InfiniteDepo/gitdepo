// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"context"

	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	repo_service "forgejo.org/services/repository"
)

// TrashOrganization moves the organization and all its repositories to the trash as one item. Only site
// admins can restore it (see services/trash); the row stays, so the name stays reserved. Repositories that were
// trashed earlier stay separate items.
func TrashOrganization(ctx context.Context, doer *user_model.User, org *org_model.Organization) error {
	defer repo_service.LockTrash("org", org.ID)()
	return repo_service.TrashOwnerRepositories(ctx, doer, org.AsUser(), func(ctx context.Context) error {
		res, err := db.Exec(ctx, "UPDATE `user` SET trashed_unix=?, trashed_by_id=?, trashed_by_name=?, trashed_name=? WHERE id=? AND type=? AND trashed_unix=0",
			timeutil.TimeStampNow(), doer.ID, doer.Name, org.Name, org.ID, user_model.UserTypeOrganization)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return org_model.ErrOrgNotExist{ID: org.ID}
		}
		repos, err := db.GetEngine(ctx).Table("repository").Where("owner_id = ? AND trashed_unix = 0", org.ID).Count()
		if err != nil {
			return err
		}
		return user_model.RecordOrg(ctx, "org.organization.trashed", org.AsUser(), map[string]any{"counts": map[string]int64{"repos": repos}})
	})
}

// DeleteOrTrashOrganization deletes the organization the way an owner asks for it: into the trash, or for good
// (which needs it to own nothing) when [trash] RETENTION_DAYS is 0.
func DeleteOrTrashOrganization(ctx context.Context, doer *user_model.User, org *org_model.Organization) error {
	if setting.Trash.RetentionDays == 0 {
		return DeleteOrganization(ctx, org, false)
	}
	return TrashOrganization(ctx, doer, org)
}
