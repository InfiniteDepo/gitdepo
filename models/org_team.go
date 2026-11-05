// Copyright 2018 The Gitea Authors. All rights reserved.
// Copyright 2016 The Gogs Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package models

import (
	"context"
	"fmt"
	"slices"
	"strings"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

func AddRepository(ctx context.Context, t *organization.Team, repo *repo_model.Repository) error {
	_, err := InsertTeamRepository(ctx, t, repo)
	return err
}

func InsertTeamRepository(ctx context.Context, t *organization.Team, repo *repo_model.Repository) (teamRepo *organization.TeamRepo, err error) {
	return insertTeamRepository(ctx, t, repo, false)
}

func insertTeamRepository(ctx context.Context, t *organization.Team, repo *repo_model.Repository, viaGroup bool) (teamRepo *organization.TeamRepo, err error) {
	teamRepo = &organization.TeamRepo{
		OrgID:    t.OrgID,
		TeamID:   t.ID,
		RepoID:   repo.ID,
		ViaGroup: viaGroup,
	}
	if _, err = db.GetEngine(ctx).Insert(teamRepo); err != nil {
		return nil, err
	}

	// a trashed repository is counted back when it is restored
	if !repo.IsTrashed() {
		if err = organization.IncrTeamRepoNum(ctx, t.ID); err != nil {
			return nil, fmt.Errorf("update team: %w", err)
		}
		t.NumRepos++
	}

	if err = access_model.RecalculateTeamAccesses(ctx, repo, 0); err != nil {
		return nil, fmt.Errorf("recalculateAccesses: %w", err)
	}

	// Make all team members watch this repo if enabled in global settings
	if setting.Service.AutoWatchNewRepos {
		if err = t.LoadMembers(ctx); err != nil {
			return nil, fmt.Errorf("getMembers: %w", err)
		}
		for _, u := range t.Members {
			if err = repo_model.WatchIfAutoWatchNewRepos(ctx, u.ID, repo.ID); err != nil {
				return nil, fmt.Errorf("watchRepo: %w", err)
			}
		}
	}

	return teamRepo, nil
}

// AddRepoGroupTeams gives every team linked to the repository's project, that doesn't have the repository yet, a
// ViaGroup row for it. The caller holds the project's row lock (repo_model.LockRepoGroup).
func AddRepoGroupTeams(ctx context.Context, repo *repo_model.Repository) error {
	if repo.GroupID == 0 {
		return nil
	}
	teams := make([]*organization.Team, 0, 5)
	if err := db.GetEngine(ctx).Where("org_id = ? AND id IN (SELECT team_id FROM team_group WHERE group_id = ?) AND id NOT IN (SELECT team_id FROM team_repo WHERE repo_id = ?)",
		repo.OwnerID, repo.GroupID, repo.ID).Find(&teams); err != nil {
		return err
	}
	for _, t := range teams {
		if _, err := insertTeamRepository(ctx, t, repo, true); err != nil {
			return err
		}
	}
	return nil
}

// addAllRepositories adds all repositories to the team.
// If the team already has some repositories they will be left unchanged.
func addAllRepositories(ctx context.Context, t *organization.Team) error {
	orgRepos, err := organization.GetOrgRepositories(ctx, t.OrgID)
	if err != nil {
		return fmt.Errorf("get org repos: %w", err)
	}

	for _, repo := range orgRepos {
		if !organization.HasTeamRepo(ctx, t.OrgID, t.ID, repo.ID) {
			if err := AddRepository(ctx, t, repo); err != nil {
				return fmt.Errorf("AddRepository: %w", err)
			}
		}
	}

	return nil
}

// AddAllRepositories adds all repositories to the team
func AddAllRepositories(ctx context.Context, t *organization.Team) (err error) {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	before, err := countTeamRepos(ctx, t)
	if err != nil {
		return err
	}
	if err = addAllRepositories(ctx, t); err != nil {
		return err
	}
	if err := recordTeamRepoCount(ctx, "org.team.repos_added_all", t, before); err != nil {
		return err
	}

	return committer.Commit()
}

func countTeamRepos(ctx context.Context, t *organization.Team) (int64, error) {
	return db.GetEngine(ctx).Count(&organization.TeamRepo{TeamID: t.ID})
}

// recordTeamRepoCount records action with how many repositories the team t gained or lost since it had before,
// and nothing when that is none.
func recordTeamRepoCount(ctx context.Context, action string, t *organization.Team, before int64) error {
	after, err := countTeamRepos(ctx, t)
	if err != nil || after == before {
		return err
	}
	return organization.RecordTeam(ctx, t, audit_model.Event{Action: action, Data: map[string]any{"counts": map[string]int64{"repos": max(after-before, before-after)}}})
}

// lockTeamGroups locks, in the transaction of ctx, the projects the team is linked to by ascending ID, then the team
// row: the order of link, unlink, move and repository creation, so the team's links and ViaGroup rows hold still
// until the end of the transaction. A link or unlink that ran in between fails it, to be tried again.
func lockTeamGroups(ctx context.Context, t *organization.Team) error {
	linkedGroups := func() ([]int64, error) {
		var ids []int64
		return ids, db.GetEngine(ctx).Table("team_group").Where("team_id = ?", t.ID).Asc("group_id").Cols("group_id").Find(&ids)
	}
	ids, err := linkedGroups()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := repo_model.LockRepoGroup(ctx, t.OrgID, id); err != nil {
			return err
		}
	}
	if _, err := db.Exec(ctx, "UPDATE `team` SET org_id = org_id WHERE id = ?", t.ID); err != nil {
		return err
	}
	if again, err := linkedGroups(); err != nil {
		return err
	} else if !slices.Equal(ids, again) {
		return util.NewInvalidArgumentErrorf("the projects of the team changed meanwhile")
	}
	return nil
}

// RemoveAllRepositories removes all repositories from team and recalculates access
func RemoveAllRepositories(ctx context.Context, t *organization.Team) (err error) {
	if t.IncludesAllRepositories {
		return nil
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	before, err := countTeamRepos(ctx, t)
	if err != nil {
		return err
	}
	if err = removeAllRepositories(ctx, t); err != nil {
		return err
	}
	if err := recordTeamRepoCount(ctx, "org.team.repos_removed_all", t, before); err != nil {
		return err
	}

	return committer.Commit()
}

// removeAllRepositories removes all repositories from team and recalculates access; the repositories of projects the
// team is linked to stay, as ViaGroup rows.
// Note: Shall not be called if team includes all repositories
func removeAllRepositories(ctx context.Context, t *organization.Team) (err error) {
	if err := lockTeamGroups(ctx, t); err != nil {
		return err
	}
	e := db.GetEngine(ctx)

	if err := t.LoadRepositories(ctx); err != nil {
		return fmt.Errorf("load repositories failed: %w", err)
	}
	if err := t.LoadMembers(ctx); err != nil {
		return fmt.Errorf("load repositories failed: %w", err)
	}
	linked := builder.Select("repository.id").From("repository").
		Join("INNER", "team_group", "team_group.group_id = repository.group_id").Where(builder.Eq{"team_group.team_id": t.ID})
	var keep []int64
	if err := e.Table("team_repo").Where(builder.Eq{"team_id": t.ID}.And(builder.In("repo_id", linked))).Cols("repo_id").Find(&keep); err != nil {
		return err
	}

	// Delete all accesses.
	for _, repo := range t.Repos {
		if slices.Contains(keep, repo.ID) {
			continue
		}
		if err := access_model.RecalculateTeamAccesses(ctx, repo, t.ID); err != nil {
			return err
		}

		// Remove watches from all users and now inaccessible repos
		for _, user := range t.Members {
			has, err := access_model.HasAccess(ctx, user.ID, repo)
			if err != nil {
				return err
			} else if has {
				continue
			}

			if err = repo_model.WatchRepoExplicitly(ctx, user.ID, repo.ID, repo_model.WatchNoneSelection); err != nil {
				return err
			}

			// Remove all IssueWatches a user has subscribed to in the repositories
			if err = issues_model.RemoveIssueWatchersByRepoID(ctx, user.ID, repo.ID); err != nil {
				return err
			}
		}
	}

	// Delete team-repo
	if _, err := e.
		Where(builder.Eq{"team_id": t.ID}.And(builder.NotIn("repo_id", keep))).
		Delete(new(organization.TeamRepo)); err != nil {
		return err
	}
	if _, err := e.Where("team_id = ?", t.ID).Cols("via_group").Update(&organization.TeamRepo{ViaGroup: true}); err != nil {
		return err
	}

	n, err := e.Table("team_repo").Join("INNER", "repository", "repository.id = team_repo.repo_id").
		Where("team_repo.team_id = ? AND repository.trashed_unix = 0", t.ID).Count()
	if err != nil {
		return err
	}
	t.NumRepos = int(n)
	if _, err = e.ID(t.ID).Cols("num_repos").Update(t); err != nil {
		return err
	}

	return nil
}

// NewTeam creates a record of new team.
// It's caller's responsibility to assign organization ID.
func NewTeam(ctx context.Context, t *organization.Team) (err error) {
	if len(t.Name) == 0 {
		return util.NewInvalidArgumentErrorf("empty team name")
	}

	if err = organization.IsUsableTeamName(t.Name); err != nil {
		return err
	}

	has, err := db.ExistByID[user_model.User](ctx, t.OrgID)
	if err != nil {
		return err
	}
	if !has {
		return organization.ErrOrgNotExist{ID: t.OrgID}
	}

	t.LowerName = strings.ToLower(t.Name)
	has, err = db.Exist[organization.Team](ctx, builder.Eq{
		"org_id":     t.OrgID,
		"lower_name": t.LowerName,
	})
	if err != nil {
		return err
	}
	if has {
		return organization.ErrTeamAlreadyExist{OrgID: t.OrgID, Name: t.LowerName}
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	if err = db.Insert(ctx, t); err != nil {
		return err
	}

	// insert units for team
	if len(t.Units) > 0 {
		for _, unit := range t.Units {
			unit.TeamID = t.ID
		}
		if err = db.Insert(ctx, &t.Units); err != nil {
			return err
		}
	}

	// Add all repositories to the team if it has access to all of them.
	if t.IncludesAllRepositories {
		err = addAllRepositories(ctx, t)
		if err != nil {
			return fmt.Errorf("addAllRepositories: %w", err)
		}
	}

	// Update organization number of teams.
	if _, err = db.Exec(ctx, "UPDATE `user` SET num_teams=num_teams+1 WHERE id = ?", t.OrgID); err != nil {
		return err
	}
	data := t.AuditFields()
	data["counts"] = map[string]int{"repos": t.NumRepos}
	if err := organization.RecordTeam(ctx, t, audit_model.Event{Action: "org.team.created", Data: data}); err != nil {
		return err
	}
	return committer.Commit()
}

// UpdateTeam updates information of team.
func UpdateTeam(ctx context.Context, t *organization.Team, authChanged, includeAllChanged bool) (err error) {
	if len(t.Name) == 0 {
		return util.NewInvalidArgumentErrorf("empty team name")
	}

	if len(t.Description) > 255 {
		t.Description = t.Description[:255]
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	// The Owners team is found by its name, so it can't be renamed.
	old, err := organization.GetTeamByID(ctx, t.ID)
	if err != nil {
		return err
	} else if old.IsOwnerTeam() && old.Name != t.Name {
		return util.NewInvalidArgumentErrorf("the Owners team cannot be renamed")
	}
	// the audited "before" is the stored team: the caller has already changed t
	if err := old.LoadUnits(ctx); err != nil {
		return err
	}
	before := old.AuditFields()

	t.LowerName = strings.ToLower(t.Name)
	has, err := db.Exist[organization.Team](ctx, builder.Eq{
		"org_id":     t.OrgID,
		"lower_name": t.LowerName,
	}.And(builder.Neq{"id": t.ID}),
	)
	if err != nil {
		return err
	} else if has {
		return organization.ErrTeamAlreadyExist{OrgID: t.OrgID, Name: t.LowerName}
	}

	sess := db.GetEngine(ctx)
	if _, err = sess.ID(t.ID).Cols("name", "lower_name", "description",
		"can_create_org_repo", "authorize", "includes_all_repositories").Update(t); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// update units for team
	if len(t.Units) > 0 {
		for _, unit := range t.Units {
			unit.TeamID = t.ID
		}
		// Delete team-unit.
		if _, err := sess.
			Where("team_id=?", t.ID).
			Delete(new(organization.TeamUnit)); err != nil {
			return err
		}
		if _, err = sess.Cols("org_id", "team_id", "type", "access_mode").Insert(&t.Units); err != nil {
			return err
		}
	}

	// Update access for team members if needed.
	if authChanged {
		if err = t.LoadRepositories(ctx); err != nil {
			return fmt.Errorf("LoadRepositories: %w", err)
		}

		for _, repo := range t.Repos {
			if err = access_model.RecalculateTeamAccesses(ctx, repo, 0); err != nil {
				return fmt.Errorf("recalculateTeamAccesses: %w", err)
			}
		}
	}

	// Add all repositories to the team if it has access to all of them.
	if includeAllChanged && t.IncludesAllRepositories {
		err = addAllRepositories(ctx, t)
		if err != nil {
			return fmt.Errorf("addAllRepositories: %w", err)
		}
	}

	after := t.AuditFields()
	if len(t.Units) == 0 { // the units were left alone
		after["units"] = before["units"]
	}
	if changes := audit_model.Changes(before, after); changes != nil {
		if err := organization.RecordTeam(ctx, t, audit_model.Event{Action: "org.team.updated", Data: changes}); err != nil {
			return err
		}
	}

	return committer.Commit()
}

// DeleteTeam deletes given team.
// It's caller's responsibility to assign organization ID.
func DeleteTeam(ctx context.Context, t *organization.Team) error {
	if t.IsOwnerTeam() {
		return util.NewInvalidArgumentErrorf("the Owners team cannot be deleted")
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	if err := t.LoadRepositories(ctx); err != nil {
		return err
	}

	if err := t.LoadMembers(ctx); err != nil {
		return err
	}

	// update branch protections
	{
		protections := make([]*git_model.ProtectedBranch, 0, 10)
		err := db.GetEngine(ctx).Where(builder.In("repo_id",
			builder.Select("id").From("repository").Where(builder.Eq{"owner_id": t.OrgID})).
			Or(builder.Eq{"repo_id": 0, "org_id": t.OrgID})).
			Find(&protections)
		if err != nil {
			return fmt.Errorf("findProtectedBranches: %w", err)
		}
		for _, p := range protections {
			if err := git_model.RemoveTeamIDFromProtectedBranch(ctx, p, t.ID); err != nil {
				return err
			}
		}
	}

	// unlinked first, so that no repository stays
	if err := lockTeamGroups(ctx, t); err != nil {
		return err
	}
	counts := map[string]int64{"members": int64(len(t.Members)), "repos": int64(len(t.Repos))}
	for name, bean := range map[string]any{
		"projects": &organization.TeamGroup{TeamID: t.ID}, "user_groups": &organization.UserGroupTeam{TeamID: t.ID},
		"invites": &organization.TeamInvite{TeamID: t.ID},
	} {
		if counts[name], err = db.GetEngine(ctx).Count(bean); err != nil {
			return err
		}
	}
	if err := t.LoadUnits(ctx); err != nil {
		return err
	}
	data := t.AuditFields()
	data["counts"] = counts
	if err := organization.RecordTeam(ctx, t, audit_model.Event{Action: "org.team.deleted", Data: data}); err != nil {
		return err
	}
	if err := db.DeleteBeans(ctx, &organization.TeamGroup{TeamID: t.ID}); err != nil {
		return err
	}
	if err := removeAllRepositories(ctx, t); err != nil {
		return err
	}

	// an environment that loses its last reviewer this way keeps requiring reviews (its change of rules is recorded)
	if err := actions_model.RemoveReviewers(ctx, actions_model.TeamReviewerCond(t.ID)); err != nil {
		return err
	}

	if err := db.DeleteBeans(ctx,
		&organization.Team{ID: t.ID},
		&organization.TeamUser{OrgID: t.OrgID, TeamID: t.ID},
		&organization.TeamUnit{TeamID: t.ID},
		&organization.TeamInvite{TeamID: t.ID},
		&organization.UserGroupTeam{TeamID: t.ID},
		&issues_model.Review{Type: issues_model.ReviewTypeRequest, ReviewerTeamID: t.ID}, // batch delete the binding relationship between team and PR (request review from team)
	); err != nil {
		return err
	}

	for _, tm := range t.Members {
		if err := removeInvalidOrgUser(ctx, tm.ID, t.OrgID); err != nil {
			return err
		}
	}

	// Update organization number of teams.
	if _, err := db.Exec(ctx, "UPDATE `user` SET num_teams=num_teams-1 WHERE id=?", t.OrgID); err != nil {
		return err
	}

	return committer.Commit()
}

func AddTeamMemberByCooptation(ctx context.Context, team *organization.Team, userID, inviterID int64) error {
	_, err := InsertTeamMember(ctx, team, userID, organization.MembershipReasonAddedByUser, optional.Some(inviterID), optional.None[int64]())
	return err
}

func AddTeamMemberByLoginSource(ctx context.Context, team *organization.Team, userID, loginSourceID int64) error {
	_, err := InsertTeamMember(ctx, team, userID, organization.MembershipReasonAddedByAuthProvider, optional.None[int64](), optional.Some(loginSourceID))
	return err
}

// AddTeamMember adds new membership of given team to given organization,
// the user will have membership to given organization automatically when needed.
func InsertTeamMember(ctx context.Context, team *organization.Team, userID int64, reason organization.MembershipReason, inviterID, loginSourceID optional.Option[int64]) (*organization.TeamUser, error) {
	isAlreadyMember, err := organization.IsTeamMember(ctx, team.OrgID, team.ID, userID)
	if err != nil || isAlreadyMember {
		return nil, err
	}

	teamUser := &organization.TeamUser{
		UID:                    userID,
		OrgID:                  team.OrgID,
		TeamID:                 team.ID,
		Reason:                 reason,
		CreatedByUserID:        inviterID,
		CreatedByLoginSourceID: loginSourceID,
		CreatedUnix:            optional.Some(timeutil.TimeStampNow()),
	}

	var refused error
	err = db.WithTx(ctx, func(ctx context.Context) error {
		// check in transaction
		isAlreadyMember, err = organization.IsTeamMember(ctx, team.OrgID, team.ID, userID)
		if err != nil || isAlreadyMember {
			return err
		}

		if err := organization.AddOrgUser(ctx, team.OrgID, userID); err != nil {
			if organization.IsErrUserNoVerifiedDomainEmail(err) {
				// nothing was written: commit, so that a shared outer transaction (user group sync skips this user) survives
				refused = err
				return nil
			}
			return err
		}

		sess := db.GetEngine(ctx)

		if err := db.Insert(ctx, teamUser); err != nil {
			return err
		} else if _, err := sess.Incr("num_members").ID(team.ID).Update(new(organization.Team)); err != nil {
			return err
		}

		team.NumMembers++

		if err := team.LoadRepositories(ctx); err != nil {
			return fmt.Errorf("load repositories: %w", err)
		}
		repoIDs := make([]int64, len(team.Repos))
		for i, r := range team.Repos {
			repoIDs[i] = r.ID
		}
		if err := access_model.RecalculateUserAccessForRepos(ctx, userID, repoIDs); err != nil {
			return fmt.Errorf("error recalculating user access: %w", err)
		}

		data := map[string]any{"user_id": userID, "reason": reason.AuditName()}
		if has, id := inviterID.Get(); has {
			data["inviter_id"] = id
		}
		return organization.RecordTeam(ctx, team, audit_model.Event{Action: "org.team.member_added", SubjectUserID: userID, Data: data})
	})
	if err != nil {
		return nil, err
	} else if refused != nil {
		return nil, refused
	}

	// this behaviour may spend much time so run it in a goroutine
	// FIXME: Update watch repos batchly
	if setting.Service.AutoWatchNewRepos {
		// Get team and its repositories.
		if err := team.LoadRepositories(ctx); err != nil {
			log.Error("team.LoadRepositories failed: %v", err)
		}
		// FIXME: in the goroutine, it can't access the "ctx", it could only use db.DefaultContext at the moment
		go func(repos []*repo_model.Repository) {
			for _, repo := range repos {
				if err = repo_model.WatchIfAutoWatchNewRepos(db.DefaultContext, userID, repo.ID); err != nil {
					log.Error("watch repo failed: %v", err)
				}
			}
		}(team.Repos)
	}

	return teamUser, nil
}

func removeTeamMember(ctx context.Context, team *organization.Team, userID int64) error {
	e := db.GetEngine(ctx)
	isMember, err := organization.IsTeamMember(ctx, team.OrgID, team.ID, userID)
	if err != nil || !isMember {
		return err
	}

	// Check if the user to delete is the last member in owner team.
	if team.IsOwnerTeam() && team.NumMembers == 1 {
		return organization.ErrLastOrgOwner{UID: userID, OrgID: team.OrgID}
	}

	team.NumMembers--

	if err := team.LoadRepositories(ctx); err != nil {
		return err
	}

	if _, err := e.Delete(&organization.TeamUser{
		UID:    userID,
		OrgID:  team.OrgID,
		TeamID: team.ID,
	}); err != nil {
		return err
	} else if err := organization.RecordTeam(ctx, team, audit_model.Event{
		Action: "org.team.member_removed", SubjectUserID: userID, Data: map[string]any{"user_id": userID},
	}); err != nil {
		return err
	} else if _, err = e.
		ID(team.ID).
		Cols("num_members").
		Update(team); err != nil {
		return err
	}

	// Delete access to team repositories.
	for _, repo := range team.Repos {
		if err := access_model.RecalculateUserAccess(ctx, repo, userID); err != nil {
			return err
		}

		// Remove watches from now inaccessible
		if err := ReconsiderWatches(ctx, repo, userID); err != nil {
			return err
		}

		// Remove issue assignments from now inaccessible
		if err := ReconsiderRepoIssuesAssignee(ctx, repo, userID); err != nil {
			return err
		}
	}

	return removeInvalidOrgUser(ctx, userID, team.OrgID)
}

func removeInvalidOrgUser(ctx context.Context, userID, orgID int64) error {
	// Check if the user is a member of any team in the organization.
	if count, err := db.GetEngine(ctx).Count(&organization.TeamUser{
		UID:   userID,
		OrgID: orgID,
	}); err != nil {
		return err
	} else if count == 0 {
		return RemoveOrgUser(ctx, orgID, userID)
	}
	return nil
}

// RemoveTeamMember removes member from given team of given organization.
func RemoveTeamMember(ctx context.Context, team *organization.Team, userID int64) error {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()
	if err := removeTeamMember(ctx, team, userID); err != nil {
		return err
	}
	return committer.Commit()
}

func ReconsiderRepoIssuesAssignee(ctx context.Context, repo *repo_model.Repository, uid int64) error {
	user, err := user_model.GetUserByID(ctx, uid)
	if err != nil {
		return err
	}

	if canAssigned, err := access_model.CanBeAssigned(ctx, user, repo, true); err != nil || canAssigned {
		return err
	}

	if _, err := db.GetEngine(ctx).Where(builder.Eq{"assignee_id": uid}).
		In("issue_id", builder.Select("id").From("issue").Where(builder.Eq{"repo_id": repo.ID})).
		Delete(&issues_model.IssueAssignees{}); err != nil {
		return fmt.Errorf("Could not delete assignee[%d] %w", uid, err)
	}
	return nil
}

func ReconsiderWatches(ctx context.Context, repo *repo_model.Repository, uid int64) error {
	if has, err := access_model.HasAccess(ctx, uid, repo); err != nil || has {
		return err
	}
	if err := repo_model.WatchRepoExplicitly(ctx, uid, repo.ID, repo_model.WatchNoneSelection); err != nil {
		return err
	}

	// Remove all IssueWatches a user has subscribed to in the repository
	return issues_model.RemoveIssueWatchersByRepoID(ctx, uid, repo.ID)
}
