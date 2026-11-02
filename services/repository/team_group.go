// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"
)

// lockTeamGroup checks that doer may link teams to projects of org (acting owner or site admin, org not archived),
// then, in the transaction of ctx, locks the project row and the team row and returns them.
func lockTeamGroup(ctx context.Context, doer *user_model.User, org *organization.Organization, teamID, groupID int64) (*organization.Team, *repo_model.RepoGroup, error) {
	if !doer.IsAdmin {
		if isOwner, err := org.IsActingOwner(ctx, doer); err != nil {
			return nil, nil, err
		} else if !isOwner {
			return nil, nil, util.ErrPermissionDenied
		}
	}
	if org.IsArchived {
		return nil, nil, organization.ErrOrgArchived{Name: org.Name}
	}
	group, err := repo_model.LockRepoGroup(ctx, org.ID, groupID)
	if err != nil {
		return nil, nil, err
	}
	if _, err := db.Exec(ctx, "UPDATE `team` SET org_id = org_id WHERE id = ? AND org_id = ?", teamID, org.ID); err != nil {
		return nil, nil, err
	}
	team, err := organization.GetTeamByID(ctx, teamID)
	if err != nil {
		return nil, nil, err
	} else if team.OrgID != org.ID {
		return nil, nil, organization.ErrTeamNotExist{OrgID: org.ID, TeamID: teamID}
	}
	return team, group, nil
}

// LinkTeamToRepoGroup gives the team every repository of the project, trashed ones included, now and later.
func LinkTeamToRepoGroup(ctx context.Context, doer *user_model.User, org *organization.Organization, teamID, groupID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		team, group, err := lockTeamGroup(ctx, doer, org, teamID, groupID)
		if err != nil {
			return err
		}
		if has, err := db.GetEngine(ctx).Exist(&organization.TeamGroup{TeamID: team.ID, GroupID: group.ID}); err != nil {
			return err
		} else if has {
			return util.ErrAlreadyExist
		}
		if err := db.Insert(ctx, &organization.TeamGroup{OrgID: org.ID, TeamID: team.ID, GroupID: group.ID}); err != nil {
			return err
		}
		var repos []*repo_model.Repository
		if err := db.GetEngine(ctx).Where("owner_id = ? AND group_id = ?", org.ID, group.ID).Find(&repos); err != nil {
			return err
		}
		for _, repo := range repos {
			if err := models.AddRepoGroupTeams(ctx, repo); err != nil {
				return err
			}
		}
		return recordProjectLink(ctx, "org.team.project_linked", team, group, len(repos))
	})
}

func recordProjectLink(ctx context.Context, action string, team *organization.Team, group *repo_model.RepoGroup, repos int) error {
	return organization.RecordTeam(ctx, team, audit_model.Event{Action: action, GroupID: group.ID, Data: map[string]any{
		"group_id": group.ID, "counts": map[string]int{"repos": repos},
	}})
}

// UnlinkTeamFromRepoGroup takes back what the link granted: the team's ViaGroup rows of the project. Repositories
// added to the team directly stay.
func UnlinkTeamFromRepoGroup(ctx context.Context, doer *user_model.User, org *organization.Organization, teamID, groupID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		team, group, err := lockTeamGroup(ctx, doer, org, teamID, groupID)
		if err != nil {
			return err
		}
		if n, err := db.GetEngine(ctx).Delete(&organization.TeamGroup{TeamID: team.ID, GroupID: group.ID}); err != nil {
			return err
		} else if n == 0 {
			return util.ErrNotExist
		}
		var repos []*repo_model.Repository
		if err := db.GetEngine(ctx).Where("owner_id = ? AND group_id = ? AND id IN (SELECT repo_id FROM team_repo WHERE team_id = ? AND via_group = ?)",
			org.ID, group.ID, team.ID, true).Find(&repos); err != nil {
			return err
		}
		for _, repo := range repos {
			if err := dropViaGroupRow(ctx, team, repo); err != nil {
				return err
			}
		}
		return recordProjectLink(ctx, "org.team.project_unlinked", team, group, len(repos))
	})
}

// syncRepoGroupTeams makes the repository's ViaGroup rows match the teams linked to its project, after a move.
func syncRepoGroupTeams(ctx context.Context, repo *repo_model.Repository) error {
	teams := make([]*organization.Team, 0, 5)
	if err := db.GetEngine(ctx).Where("id IN (SELECT team_id FROM team_repo WHERE repo_id = ? AND via_group = ?) AND id NOT IN (SELECT team_id FROM team_group WHERE group_id = ?)",
		repo.ID, true, repo.GroupID).Find(&teams); err != nil {
		return err
	}
	for _, team := range teams {
		if err := dropViaGroupRow(ctx, team, repo); err != nil {
			return err
		}
	}
	return models.AddRepoGroupTeams(ctx, repo)
}

// dropViaGroupRow removes a ViaGroup row like a repository removed from the team, except for a team that includes
// all repositories, which keeps it as a direct row.
func dropViaGroupRow(ctx context.Context, team *organization.Team, repo *repo_model.Repository) error {
	if team.IncludesAllRepositories {
		_, err := db.GetEngine(ctx).Where("team_id = ? AND repo_id = ?", team.ID, repo.ID).Cols("via_group").Update(&organization.TeamRepo{})
		return err
	}
	return removeRepositoryFromTeam(ctx, team, repo, true)
}
