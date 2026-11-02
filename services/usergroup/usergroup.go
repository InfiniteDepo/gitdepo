// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package usergroup manages instance-wide user groups and keeps the
// memberships of the organization teams they are linked to in sync.
//
// A user group carries no permissions of its own. An organization owner
// links a group to one of the organization's teams, and every member of the
// group becomes a member of that team, with the reason
// MembershipReasonAddedByUserGroup. A team membership created that way is
// removed again once the user is no longer in any group linked to the team.
// Memberships created any other way (directly, by invitation, by an
// authentication source) are never touched.
//
// A user group can also grant instance-level roles (site administrator,
// creating organizations, auditor). They are synced into the user's IsAdmin,
// AllowCreateOrganization and IsAuditor flags, and a UserGroupRoleGrant
// records the flags a group turned on. A flag is only turned off again when
// such a grant exists and no remaining group of the user grants the role.
package usergroup

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
)

var (
	// ErrOrganizationCannotBeMember is returned when adding an organization to a user group.
	ErrOrganizationCannotBeMember = errors.New("an organization cannot be a member of a user group")
	// ErrAlreadyMember is returned when adding a user who is already a member of the group.
	ErrAlreadyMember = errors.New("user is already a member of the user group")
	// ErrNotOrganization is returned when an organization name names a user.
	ErrNotOrganization = errors.New("not an organization")
	// ErrAlreadyLinked is returned when linking a group to a team it is already linked to.
	ErrAlreadyLinked = errors.New("user group is already linked to the team")
)

// AddMember adds a user to a user group and to every team the group is linked to.
func AddMember(ctx context.Context, group *org_model.UserGroup, user *user_model.User) error {
	return addMember(ctx, group, user, 0)
}

// addMember is AddMember recording the login source that synced the membership (0 for none).
func addMember(ctx context.Context, group *org_model.UserGroup, user *user_model.User, loginSourceID int64) error {
	if user.IsOrganization() {
		return ErrOrganizationCannotBeMember
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		isMember, err := org_model.IsUserGroupMember(ctx, group.ID, user.ID)
		if err != nil {
			return err
		} else if isMember {
			return ErrAlreadyMember
		}
		if err := org_model.InsertUserGroupMember(ctx, group.ID, user.ID, loginSourceID); err != nil {
			return err
		}
		if err := recordGroup(ctx, "admin.user_group.member_added", group, user.ID, user.ID, memberData(user.ID, loginSourceID)); err != nil {
			return err
		}
		if err := syncRoles(ctx, group.ID, user.ID); err != nil {
			return err
		}
		return syncUserForGroupTeams(ctx, group.ID, user.ID, false)
	})
}

// RemoveMember removes a user from a user group, and from every team the user
// was only a member of because of the group.
func RemoveMember(ctx context.Context, group *org_model.UserGroup, userID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		isMember, err := org_model.IsUserGroupMember(ctx, group.ID, userID)
		if err != nil {
			return err
		}
		if err := org_model.DeleteUserGroupMember(ctx, group.ID, userID); err != nil {
			return err
		}
		if isMember {
			if err := recordGroup(ctx, "admin.user_group.member_removed", group, userID, userID, memberData(userID, 0)); err != nil {
				return err
			}
		}
		if err := syncRoles(ctx, group.ID, userID); err != nil {
			return err
		}
		return syncUserForGroupTeams(ctx, group.ID, userID, false)
	})
}

// SyncDirectoryGroups syncs the user group memberships of a user from the
// directory groups reported by a login source. mapping maps a directory group
// to the names of user groups. The user is added to every group mapped from
// one of their directory groups. With remove, the user is also removed from
// the other mapped groups, but only where this login source added them.
// Memberships added by an admin or another source are never touched.
func SyncDirectoryGroups(ctx context.Context, user *user_model.User, loginSourceID int64, userDirectoryGroups container.Set[string], mapping map[string]container.Set[string], remove bool) error {
	// group syncs wait while maintenance mode is on and run at the next sign-in or sync after it
	if setting.GetMaintenance(ctx).ReadOnly() {
		return nil
	}
	toAdd, toRemove := make(container.Set[string]), make(container.Set[string])
	for dirGroup, names := range mapping {
		target := toRemove
		if userDirectoryGroups.Contains(dirGroup) {
			target = toAdd
		}
		for name := range names {
			target.Add(strings.ToLower(name))
		}
	}

	for name := range toAdd {
		toRemove.Remove(name) // still mapped from another directory group of the user
	}

	addGroups, err := loadGroupsForSync(ctx, toAdd)
	if err != nil {
		return err
	}
	for _, group := range addGroups {
		if err := addMember(ctx, group, user, loginSourceID); err != nil && !errors.Is(err, ErrAlreadyMember) {
			return err
		}
	}

	if !remove {
		return nil
	}
	removeGroups, err := loadGroupsForSync(ctx, toRemove)
	if err != nil {
		return err
	}
	for _, group := range removeGroups {
		err := db.WithTx(ctx, func(ctx context.Context) error {
			deleted, err := org_model.DeleteSyncedUserGroupMember(ctx, group.ID, user.ID, loginSourceID)
			if err != nil || !deleted {
				return err
			}
			data := memberData(user.ID, loginSourceID)
			data["reason"] = "login_source_sync"
			if err := recordGroup(ctx, "admin.user_group.member_removed", group, user.ID, user.ID, data); err != nil {
				return err
			}
			if err := syncRoles(ctx, group.ID, user.ID); err != nil {
				return err
			}
			return syncUserForGroupTeams(ctx, group.ID, user.ID, true)
		})
		if models.IsErrDeleteLastAdminUser(err) {
			log.Warn("user group sync: keeping %s in user group %s: %v", user.Name, group.Name, err)
		} else if err != nil {
			return err
		}
	}
	return nil
}

// loadGroupsForSync returns the user groups with the given names, skipping the ones that do not exist.
func loadGroupsForSync(ctx context.Context, names container.Set[string]) ([]*org_model.UserGroup, error) {
	groups := make([]*org_model.UserGroup, 0, len(names))
	for name := range names {
		group, err := org_model.GetUserGroupByName(ctx, name)
		if org_model.IsErrUserGroupNotExist(err) {
			log.Warn("user group sync: user group %s does not exist", name)
			continue
		} else if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// LinkTeam links a user group to a team and adds the members of the group to the team.
func LinkTeam(ctx context.Context, group *org_model.UserGroup, team *org_model.Team) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if org, err := org_model.GetOrgByID(ctx, team.OrgID); err != nil {
			return err
		} else if org.IsArchived {
			return org_model.ErrOrgArchived{Name: org.Name}
		}
		linked, err := org_model.IsUserGroupLinkedToTeam(ctx, group.ID, team.ID)
		if err != nil {
			return err
		} else if linked {
			return ErrAlreadyLinked
		}
		if err := org_model.InsertUserGroupTeam(ctx, group.ID, team, org_model.LinkManual); err != nil {
			return err
		}
		if err := recordTeamLink(ctx, "admin.user_group.team_linked", group, team); err != nil {
			return err
		}
		return syncGroupMembersForTeam(ctx, group.ID, team)
	})
}

// UnlinkTeam unlinks a user group from a team, and removes the members of the
// group that were only members of the team because of the group.
func UnlinkTeam(ctx context.Context, group *org_model.UserGroup, team *org_model.Team) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if org, err := org_model.GetOrgByIDIncludingTrashed(ctx, team.OrgID); err != nil {
			return err
		} else if org.IsArchived {
			return org_model.ErrOrgArchived{Name: org.Name}
		}
		linked, err := org_model.IsUserGroupLinkedToTeam(ctx, group.ID, team.ID)
		if err != nil {
			return err
		}
		if err := org_model.DeleteUserGroupTeam(ctx, group.ID, team.ID); err != nil {
			return err
		}
		if linked {
			if err := recordTeamLink(ctx, "admin.user_group.team_unlinked", group, team); err != nil {
				return err
			}
		}
		return syncGroupMembersForTeam(ctx, group.ID, team)
	})
}

// CreateOrganization creates an organization owned by owner, and makes the
// members of the user groups granting the org-admin role its owners. It lives
// here, not in services/org, which services/user imports.
func CreateOrganization(ctx context.Context, org *org_model.Organization, owner *user_model.User) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := org_model.CreateOrganization(ctx, org, owner); err != nil {
			return err
		}
		return SyncOrgAdminLinks(ctx, org.ID)
	})
}

// CreateGroup creates a user group. A group granting the org-admin role is
// linked to the Owners team of every organization right away.
func CreateGroup(ctx context.Context, group *org_model.UserGroup) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := org_model.InsertUserGroup(ctx, group); err != nil {
			return err
		}
		if err := recordGroup(ctx, "admin.user_group.created", group, 0, 0, groupFields(group)); err != nil {
			return err
		}
		if !group.GrantsOrgAdmin {
			return nil
		}
		return SyncOrgAdminLinks(ctx)
	})
}

// UpdateGroup updates the name, description and roles of a user group, and
// the role flags of its members.
func UpdateGroup(ctx context.Context, group *org_model.UserGroup) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		old, err := org_model.GetUserGroupByID(ctx, group.ID)
		if err != nil {
			return err
		}
		if err := org_model.UpdateUserGroup(ctx, group); err != nil {
			return err
		}
		if data := audit_model.Changes(groupFields(old), groupFields(group)); data != nil {
			if err := recordGroup(ctx, "admin.user_group.updated", group, 0, 0, data); err != nil {
				return err
			}
		}
		memberIDs, err := org_model.GetUserGroupMemberIDs(ctx, group.ID)
		if err != nil {
			return err
		}
		if err := syncRoles(ctx, group.ID, memberIDs...); err != nil {
			return err
		}
		if old.GrantsOrgAdmin == group.GrantsOrgAdmin {
			return nil
		}
		return SyncOrgAdminLinks(ctx)
	})
}

// DeleteGroup unlinks a user group from all teams and deletes it.
func DeleteGroup(ctx context.Context, group *org_model.UserGroup) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		memberIDs, err := org_model.GetUserGroupMemberIDs(ctx, group.ID)
		if err != nil {
			return err
		}
		linked, err := org_model.GetUserGroupTeams(ctx, group.ID)
		if err != nil {
			return err
		}
		for _, l := range linked {
			if err := UnlinkTeam(ctx, group, l.Team); err != nil {
				return err
			}
		}
		if err := db.DeleteBeans(ctx,
			&org_model.UserGroupUser{GroupID: group.ID},
			&org_model.UserGroup{ID: group.ID},
		); err != nil {
			return err
		}
		data := groupFields(group)
		data["counts"] = map[string]int{"members": len(memberIDs), "teams": len(linked)}
		if err := recordGroup(ctx, "admin.user_group.deleted", group, 0, 0, data); err != nil {
			return err
		}
		return syncRoles(ctx, group.ID, memberIDs...)
	})
}

// HasRoleViaGroup returns true if a user group of the user grants the role.
func HasRoleViaGroup(ctx context.Context, uid int64, role org_model.UserGroupRole) (bool, error) {
	groups, err := org_model.GetUserRoleGroups(ctx, uid, role)
	return len(groups) > 0, err
}

// DirectoryAdmin returns the admin flag a login source should set for a user
// it reports as admin or not. A user group granting site administrator wins
// over the directory: such a user is never demoted.
func DirectoryAdmin(ctx context.Context, user *user_model.User, directoryIsAdmin bool) (bool, error) {
	if directoryIsAdmin || !user.IsAdmin {
		return directoryIsAdmin, nil
	}
	return HasRoleViaGroup(ctx, user.ID, org_model.UserGroupRoleSiteAdmin)
}

// syncRoles makes the role flags of the users match the roles their user
// groups grant. A flag is turned on when a group grants the role, and turned
// off only when a group turned it on and none grants it anymore. It refuses
// to remove the last site administrator with models.ErrDeleteLastAdminUser.
// groupID is the group whose change started the sync, for the audit log.
func syncRoles(ctx context.Context, groupID int64, uids ...int64) error {
	for _, uid := range uids {
		user, err := user_model.GetUserByID(ctx, uid)
		if user_model.IsErrUserNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		for _, role := range org_model.UserGroupRoles {
			var flag *bool
			var col string
			switch role {
			case org_model.UserGroupRoleSiteAdmin:
				flag, col = &user.IsAdmin, "is_admin"
			case org_model.UserGroupRoleCreateOrganization:
				flag, col = &user.AllowCreateOrganization, "allow_create_organization"
			case org_model.UserGroupRoleAuditor:
				flag, col = &user.IsAuditor, "is_auditor"
			default:
				return fmt.Errorf("user group role %q has no user flag", role)
			}
			granted, err := HasRoleViaGroup(ctx, uid, role)
			if err != nil {
				return err
			}
			grant := &org_model.UserGroupRoleGrant{UID: uid, Role: role}
			hasGrant, err := db.GetEngine(ctx).Exist(grant)
			if err != nil {
				return err
			}

			switch {
			case granted && !*flag:
				*flag = true
				if err := user_model.UpdateUserCols(ctx, user, col); err != nil {
					return err
				}
				if err := user_model.RecordUser(ctx, "account.user.role_granted", user, map[string]any{"role": string(role), "group_id": groupID}); err != nil {
					return err
				}
				if !hasGrant {
					if err := db.Insert(ctx, grant); err != nil {
						return err
					}
				}
			case !granted && hasGrant:
				if *flag {
					if role == org_model.UserGroupRoleSiteAdmin && user_model.IsLastAdminUser(ctx, user) {
						return models.ErrDeleteLastAdminUser{UID: uid}
					}
					*flag = false
					if err := user_model.UpdateUserCols(ctx, user, col); err != nil {
						return err
					}
					if err := user_model.RecordUser(ctx, "account.user.role_revoked", user, map[string]any{"role": string(role), "group_id": groupID}); err != nil {
						return err
					}
				}
				if _, err := db.DeleteByBean(ctx, grant); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// syncUserForGroupTeams updates the membership of a user in all teams the group is linked to.
func syncUserForGroupTeams(ctx context.Context, groupID, userID int64, keepLastOwner bool) error {
	linked, err := org_model.GetUserGroupTeams(ctx, groupID)
	if err != nil {
		return err
	}
	for _, l := range linked {
		if err := syncTeamMembership(ctx, l.Team, userID, keepLastOwner); err != nil {
			return err
		}
	}
	return nil
}

// syncGroupMembersForTeam updates the membership of all group members in a team.
func syncGroupMembersForTeam(ctx context.Context, groupID int64, team *org_model.Team) error {
	memberIDs, err := org_model.GetUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		return err
	}
	for _, uid := range memberIDs {
		if err := syncTeamMembership(ctx, team, uid, false); err != nil {
			return err
		}
	}
	return nil
}

// syncTeamMembership makes the membership of a user in a team match the user
// groups linked to the team. Memberships not created by a user group are left alone.
// Removing the last owner of an organization returns ErrLastOrgOwner and
// changes nothing, unless keepLastOwner is set (a directory removed the user
// from the group): then the user stays owner, as if added by a user.
func syncTeamMembership(ctx context.Context, team *org_model.Team, userID int64, keepLastOwner bool) error {
	viaGroup, err := org_model.IsTeamMemberViaUserGroup(ctx, team.ID, userID)
	if err != nil {
		return err
	}
	if viaGroup {
		// Adds wait while the organization is archived (see SyncOrgTeams); removals below always apply.
		if org, err := org_model.GetOrgByIDIncludingTrashed(ctx, team.OrgID); err != nil || org.IsArchived {
			return err
		}
		_, err := models.InsertTeamMember(ctx, team, userID, org_model.MembershipReasonAddedByUserGroup, optional.None[int64](), optional.None[int64]())
		if org_model.IsErrUserNoVerifiedDomainEmail(err) {
			log.Warn("user group sync: skipping user %d for organization %d: %v", userID, team.OrgID, err)
			return nil
		}
		return err
	}

	membership, err := org_model.GetTeamUser(ctx, team.ID, userID)
	if err != nil {
		return err
	}
	if membership == nil || !membership.IsMembershipAddedByUserGroup() {
		return nil
	}
	if team.IsOwnerTeam() && team.NumMembers == 1 {
		if !keepLastOwner {
			return org_model.ErrLastOrgOwner{UID: userID, OrgID: team.OrgID}
		}
		log.Warn("user group sync: keeping user %d as the last owner of organization %d", userID, team.OrgID)
		before := membership.Reason
		membership.Reason = org_model.MembershipReasonAddedByUser
		if _, err := db.GetEngine(ctx).ID(membership.ID).Cols("reason").Update(membership); err != nil {
			return err
		}
		return org_model.RecordTeam(ctx, team, audit_model.Event{
			Action: "org.team.member_reason_changed", SubjectUserID: userID, Data: map[string]any{
				"user_id": userID, "before": map[string]any{"reason": before.AuditName()},
				"after": map[string]any{"reason": membership.Reason.AuditName()},
			},
		})
	}
	return models.RemoveTeamMember(ctx, team, userID)
}

// SyncOrgTeams re-applies the user groups linked to the teams of an organization, adding the members
// that were skipped while it was archived.
func SyncOrgTeams(ctx context.Context, orgID int64) error {
	teams, err := org_model.FindOrgTeams(ctx, orgID)
	if err != nil {
		return err
	}
	for _, team := range teams {
		groups, err := org_model.GetTeamUserGroups(ctx, team.ID)
		if err != nil {
			return err
		}
		for _, group := range groups {
			if err := syncGroupMembersForTeam(ctx, group.ID, team); err != nil {
				return err
			}
		}
	}
	return nil
}

// SyncOrgAdminLinks makes the links between the groups granting the org-admin
// role and the Owners team of each organization (all of them if none is
// given) match the role and the exclusions: it adds missing managed links,
// turns a manual link of a granting group into a manual+managed one, and
// removes links the policy created (or turns manual+managed ones back into
// manual) once the group no longer grants the role or the organization is
// excluded. Memberships follow the links, so only memberships created by a
// user group change. It returns ErrLastOrgOwner, with nothing applied, if an
// organization would be left without an owner.
func SyncOrgAdminLinks(ctx context.Context, orgIDs ...int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		groups, err := org_model.GetOrgAdminGroups(ctx)
		if err != nil {
			return err
		}
		excluded, err := org_model.GetOrgAdminExclusionOrgIDs(ctx)
		if err != nil {
			return err
		}
		if len(orgIDs) == 0 {
			if err := db.GetEngine(ctx).Table("user").Where("type=?", user_model.UserTypeOrganization).Cols("id").Find(&orgIDs); err != nil {
				return err
			}
		}
		for _, orgID := range orgIDs {
			if err := syncOrgAdminLinks(ctx, orgID, groups, excluded.Contains(orgID)); err != nil {
				return err
			}
		}
		return nil
	})
}

func syncOrgAdminLinks(ctx context.Context, orgID int64, groups []*org_model.UserGroup, excluded bool) error {
	team, err := org_model.GetOwnerTeam(ctx, orgID)
	if org_model.IsErrTeamNotExist(err) {
		log.Warn("org-admin role: organization %d has no Owners team", orgID)
		return nil
	} else if err != nil {
		return err
	}
	links := make([]*org_model.UserGroupTeam, 0, 4)
	if err := db.GetEngine(ctx).Where("team_id=?", team.ID).Find(&links); err != nil {
		return err
	}
	want := make(container.Set[int64], len(groups))
	if !excluded {
		for _, g := range groups {
			want.Add(g.ID)
		}
	}
	var changed []int64 // groups whose members' membership of the Owners team may change
	e := db.GetEngine(ctx)
	for _, l := range links {
		switch {
		case want.Contains(l.GroupID):
			want.Remove(l.GroupID)
			if l.Managed == org_model.LinkManual {
				if _, err := e.ID(l.ID).Cols("managed").Update(&org_model.UserGroupTeam{Managed: org_model.LinkManualManaged}); err != nil {
					return err
				}
			}
		case l.Managed == org_model.LinkManaged:
			if _, err := e.ID(l.ID).Delete(new(org_model.UserGroupTeam)); err != nil {
				return err
			}
			changed = append(changed, l.GroupID)
		case l.Managed == org_model.LinkManualManaged:
			if _, err := e.ID(l.ID).Cols("managed").Update(&org_model.UserGroupTeam{Managed: org_model.LinkManual}); err != nil {
				return err
			}
		}
	}
	for groupID := range want {
		if err := org_model.InsertUserGroupTeam(ctx, groupID, team, org_model.LinkManaged); err != nil {
			return err
		}
		changed = append(changed, groupID)
	}
	// the same team is used for every member, so its member count stays current
	for _, groupID := range changed {
		if err := syncGroupMembersForTeam(ctx, groupID, team); err != nil {
			return err
		}
	}
	return nil
}

// SetOrgAdminExclusions replaces the organizations excluded from the org-admin
// role and updates the links of the organizations that changed.
func SetOrgAdminExclusions(ctx context.Context, orgIDs []int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		old, err := org_model.GetOrgAdminExclusionOrgIDs(ctx)
		if err != nil {
			return err
		}
		next := container.SetOf(orgIDs...)
		var changed []int64
		for id := range old {
			if !next.Contains(id) {
				changed = append(changed, id)
			}
		}
		for id := range next {
			if !old.Contains(id) {
				changed = append(changed, id)
			}
		}
		if err := org_model.SetOrgAdminExclusions(ctx, orgIDs); err != nil {
			return err
		}
		if len(changed) == 0 {
			return nil
		}
		if err := audit_model.Record(ctx, audit_model.Event{
			Action: "admin.user_group.org_admin_exclusions_changed", Result: audit_model.ResultSuccess, TargetType: "user_group",
			Data: map[string]any{"before": map[string]any{"org_ids": append([]int64{}, slices.Sorted(maps.Keys(old))...)}, "after": map[string]any{"org_ids": append([]int64{}, slices.Sorted(maps.Keys(next))...)}},
		}); err != nil {
			return err
		}
		return SyncOrgAdminLinks(ctx, changed...)
	})
}

// ResolveOrgIDs returns the IDs of the organizations with the given names.
// It returns user_model.ErrUserNotExist for an unknown name and
// ErrNotOrganization for a name that is not an organization.
func ResolveOrgIDs(ctx context.Context, names []string) ([]int64, error) {
	seen := make(container.Set[int64], len(names))
	ids := make([]int64, 0, len(names))
	for _, name := range names {
		u, err := user_model.GetUserByName(ctx, name)
		if err != nil {
			return nil, err
		} else if !u.IsOrganization() {
			return nil, fmt.Errorf("%s: %w", name, ErrNotOrganization)
		}
		if seen.Add(u.ID) {
			ids = append(ids, u.ID)
		}
	}
	return ids, nil
}
