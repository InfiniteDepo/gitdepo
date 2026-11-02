// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"context"

	"forgejo.org/models"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

// ArchiveOrganization makes the organization and every active repository of it read-only. Repositories that
// were already archived are left alone, so UnarchiveOrganization only restores what this archived.
// With removeMembers, everybody but the owners is removed from the organization.
func ArchiveOrganization(ctx context.Context, org *org_model.Organization, doer *user_model.User, removeMembers bool) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		org, err := org_model.GetOrgByID(ctx, org.ID) // fresh row
		if err != nil {
			return err
		}
		if !org.AsUser().IsOrganization() {
			return util.NewInvalidArgumentErrorf("%s is not an organization", org.Name)
		}
		if org.IsArchived {
			return org_model.ErrOrgArchived{Name: org.Name}
		}
		if removeMembers {
			members, err := org_model.GetOrgUsersByOrgID(ctx, &org_model.FindOrgMembersOpts{OrgID: org.ID, Doer: doer, IsDoerMember: true})
			if err != nil {
				return err
			}
			for _, m := range members {
				if isOwner, err := org_model.IsOrganizationOwner(ctx, org.ID, m.UID); err != nil {
					return err
				} else if !isOwner {
					if err := models.RemoveOrgUser(ctx, org.ID, m.UID); err != nil {
						return err
					}
				}
			}
		}
		now := timeutil.TimeStampNow()
		repos, err := db.GetEngine(ctx).Table("repository").NoAutoTime().
			Where("owner_id = ? AND is_archived = ?", org.ID, false).
			Update(map[string]any{"is_archived": true, "archived_unix": now, "archived_by_org": true})
		if err != nil {
			return err
		}
		org.IsArchived, org.ArchivedUnix, org.ArchivedByID = true, now, doer.ID
		if _, err := db.GetEngine(ctx).ID(org.ID).Cols("is_archived", "archived_unix", "archived_by_id").NoAutoTime().Update(org); err != nil {
			return err
		}
		return user_model.RecordOrg(ctx, "org.organization.archived", org.AsUser(), map[string]any{"counts": map[string]int64{"repos": repos}})
	})
}

// UnarchiveOrganization reactivates the organization and the repositories its archive made read-only.
// Callers then run usergroup.SyncOrgTeams (services/usergroup imports this package's dependents, so it
// cannot be called from here) to add the user-group members skipped while it was archived.
func UnarchiveOrganization(ctx context.Context, org *org_model.Organization) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		org, err := org_model.GetOrgByID(ctx, org.ID)
		if err != nil {
			return err
		}
		if !org.AsUser().IsOrganization() || !org.IsArchived {
			return util.NewInvalidArgumentErrorf("%s is not an archived organization", org.Name)
		}
		repos, err := db.GetEngine(ctx).Table("repository").NoAutoTime().
			Where("owner_id = ? AND archived_by_org = ?", org.ID, true).
			Update(map[string]any{"is_archived": false, "archived_unix": 0, "archived_by_org": false})
		if err != nil {
			return err
		}
		org.IsArchived, org.ArchivedUnix, org.ArchivedByID = false, 0, 0
		if _, err := db.GetEngine(ctx).ID(org.ID).Cols("is_archived", "archived_unix", "archived_by_id").NoAutoTime().Update(org); err != nil {
			return err
		}
		return user_model.RecordOrg(ctx, "org.organization.unarchived", org.AsUser(), map[string]any{"counts": map[string]int64{"repos": repos}})
	})
}
