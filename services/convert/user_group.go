// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package convert

import (
	"context"

	org_model "forgejo.org/models/organization"
	api "forgejo.org/modules/structs"
)

// ToUserGroup converts a user group to its API representation
func ToUserGroup(ctx context.Context, group *org_model.UserGroup) (*api.UserGroup, error) {
	if err := group.LoadCounts(ctx); err != nil {
		return nil, err
	}
	return &api.UserGroup{
		ID:           group.ID,
		Name:         group.Name,
		Description:  group.Description,
		MembersCount: group.NumMembers,
		TeamsCount:   group.NumTeams,
		Created:      group.CreatedUnix.AsTime(),
		Updated:      group.UpdatedUnix.AsTime(),

		GrantsSiteAdmin:          group.GrantsSiteAdmin,
		GrantsCreateOrganization: group.GrantsCreateOrganization,
		GrantsAuditor:            group.GrantsAuditor,
		GrantsOrgAdmin:           group.GrantsOrgAdmin,
	}, nil
}

// ToUserGroups converts a list of user groups to their API representation
func ToUserGroups(ctx context.Context, groups []*org_model.UserGroup) ([]*api.UserGroup, error) {
	result := make([]*api.UserGroup, 0, len(groups))
	for _, g := range groups {
		apiGroup, err := ToUserGroup(ctx, g)
		if err != nil {
			return nil, err
		}
		result = append(result, apiGroup)
	}
	return result, nil
}
