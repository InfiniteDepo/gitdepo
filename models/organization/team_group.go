// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization

import (
	"context"

	"forgejo.org/models/db"
)

// TeamGroup links a team to a project of its organization: the team gets every repository of the project, with its
// own mode and units, as team_repo rows with ViaGroup set.
type TeamGroup struct {
	ID      int64 `xorm:"pk autoincr"`
	OrgID   int64 `xorm:"INDEX NOT NULL"`
	TeamID  int64 `xorm:"UNIQUE(s) NOT NULL"`
	GroupID int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
}

func init() {
	db.RegisterModel(new(TeamGroup))
}

// GetRepoGroupTeams returns the teams linked to the project, by name.
func GetRepoGroupTeams(ctx context.Context, orgID, groupID int64) ([]*Team, error) {
	teams := make([]*Team, 0, 5)
	return teams, db.GetEngine(ctx).Where("org_id = ? AND id IN (SELECT team_id FROM team_group WHERE group_id = ?)", orgID, groupID).
		OrderBy("lower_name").Find(&teams)
}

// ViaGroupRepoIDs returns which of the team's repositories it has only through a linked project.
func ViaGroupRepoIDs(ctx context.Context, teamID int64) (map[int64]bool, error) {
	var ids []int64
	if err := db.GetEngine(ctx).Table("team_repo").Where("team_id = ? AND via_group = ?", teamID, true).Cols("repo_id").Find(&ids); err != nil {
		return nil, err
	}
	via := make(map[int64]bool, len(ids))
	for _, id := range ids {
		via[id] = true
	}
	return via, nil
}

// ViaGroupTeamIDs returns which teams have the repository only through a linked project.
func ViaGroupTeamIDs(ctx context.Context, repoID int64) (map[int64]bool, error) {
	var ids []int64
	if err := db.GetEngine(ctx).Table("team_repo").Where("repo_id = ? AND via_group = ?", repoID, true).Cols("team_id").Find(&ids); err != nil {
		return nil, err
	}
	via := make(map[int64]bool, len(ids))
	for _, id := range ids {
		via[id] = true
	}
	return via, nil
}
