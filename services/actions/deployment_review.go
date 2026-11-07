// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/accessreport"
)

var (
	ErrReviewForbidden      = util.NewPermissionDeniedErrorf("you are not allowed to review this deployment")
	ErrReviewNotWaiting     = util.NewInvalidArgumentErrorf("the deployment is no longer waiting for a review")
	ErrReviewCommentMissing = util.NewInvalidArgumentErrorf("a rejection needs a comment")
)

// maxExpiredPerTick is how many deployments one run of the expiry task fails; the next run takes the rest.
const maxExpiredPerTick = 100

// reviewComment returns comment as stored: line breaks as "\n". It must be valid UTF-8 of at most
// actions_model.MaxReviewComment bytes, and hold no control character except newline and tab (C0, DEL and C1), no
// format character (bidi overrides and isolates, zero-width characters) and no line or paragraph separator: a reason
// can't be made to read differently from what was written. A rejection needs one. The comment is plain text; no page of
// this feature renders it as HTML.
func reviewComment(comment string, approve bool) (string, error) {
	comment = strings.TrimSpace(strings.ReplaceAll(comment, "\r\n", "\n"))
	if len(comment) > actions_model.MaxReviewComment || !utf8.ValidString(comment) ||
		strings.ContainsFunc(comment, func(r rune) bool {
			return (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
		}) {
		return "", util.NewInvalidArgumentErrorf("invalid review comment")
	}
	if !approve && comment == "" {
		return "", ErrReviewCommentMissing
	}
	return comment, nil
}

// ReviewCutoff is the creation time before which a deployment waiting for a review has waited too long: it is expired,
// by the gate or the expiry task, and can no longer be approved.
func ReviewCutoff() timeutil.TimeStamp {
	return timeutil.TimeStampNow().Add(-int64(setting.Actions.DeploymentApprovalTimeout.Seconds()))
}

// reviewEnvironment is an environment of the run with its reviewers and whether the doer is one of them.
type reviewEnvironment struct {
	env       *actions_model.ActionEnvironment // nil if the environment is deleted
	reviewers []*actions_model.ActionEnvironmentReviewer
	listed    *bool
}

// ReviewChecker is the one decision of who may review the deployments of one run: ReviewDeployments and the list of
// deployments (can_review) use it, and it loads what it needs once per run, doer and environment.
// Nobody is exempt, site administrators included: whoever is not a listed reviewer edits the rules of the
// environment, which is audited.
type ReviewChecker struct {
	run    *actions_model.ActionRun
	doer   *user_model.User
	doerOK *bool
	envs   map[int64]*reviewEnvironment
}

// NewReviewChecker returns the checker of doer for the run; it loads the repository and its owner.
func NewReviewChecker(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun) (*ReviewChecker, error) {
	if err := run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	if err := run.Repo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	return &ReviewChecker{run: run, doer: doer, envs: map[int64]*reviewEnvironment{}}, nil
}

// Environment returns the environment with its reviewers; the environment is nil if it is deleted.
func (c *ReviewChecker) Environment(ctx context.Context, id int64) (*actions_model.ActionEnvironment, []*actions_model.ActionEnvironmentReviewer, error) {
	e, err := c.environment(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return e.env, e.reviewers, nil
}

func (c *ReviewChecker) environment(ctx context.Context, id int64) (*reviewEnvironment, error) {
	if e, ok := c.envs[id]; ok {
		return e, nil
	}
	e := &reviewEnvironment{}
	env, err := actions_model.GetEnvironmentOfRepo(ctx, c.run.RepoID, id)
	if err != nil && !errors.Is(err, actions_model.ErrEnvironmentNotFound) {
		return nil, err
	}
	if e.env = env; env != nil {
		if e.reviewers, err = actions_model.FindEnvironmentReviewers(ctx, env.ID); err != nil {
			return nil, err
		}
	}
	c.envs[id] = e
	return e, nil
}

// doerMayAct checks what holds for every deployment of the run: the doer is a usable person with read access to the
// repository's Actions.
func (c *ReviewChecker) doerMayAct(ctx context.Context) (bool, error) {
	if c.doerOK != nil {
		return *c.doerOK, nil
	}
	ok := false
	// a decision is its reviewer's own: under sudo, or with a credential another party holds for the reviewer, nobody
	// reviews, so can_review says what the review call will
	if c.doer != nil && audit_model.IsOwnAct(ctx) {
		reason, err := reviewerIneligibility(ctx, c.run.Repo, c.doer)
		if err != nil {
			return false, err
		}
		ok = reason == ""
	}
	c.doerOK = &ok
	return ok, nil
}

// Why a user can't approve any deployment of a repository (the values of reviewerIneligibility)
const (
	ReviewerNotUsable  = "not_usable"   // not a person who can sign in: deactivated, login prohibited, a bot or an organization
	ReviewerTwoFactor  = "two_factor"   // the owner requires two-factor authentication, which the user lacks
	ReviewerNoAccess   = "no_access"    // can't read the repository's Actions
	ReviewerNoneInTeam = "none_in_team" // a team none of whose members can approve
	// ReviewerOutsider is a user without a membership path to the repository (memberPath), whatever their account:
	// such a user can't be added (ErrReviewerNotMember) or approve, and one listed before is not decided for the doer
	ReviewerOutsider = "outsider"
)

// memberKinds are the paths that relate a user to a repository: its owner, an owner of its organization, a member of
// one of its teams or a collaborator. Only for them do the settings pages tell why they can't approve (their account
// state is the business of whoever manages the repository), and only they are offered as reviewers.
var memberKinds = []accessreport.Kind{accessreport.KindOwnerUser, accessreport.KindOrgOwner, accessreport.KindAdminTeam, accessreport.KindTeam, accessreport.KindCollaborator}

// memberPath tells if a row of accessreport.Compute relates its user to the repository (memberKinds).
func memberPath(row *accessreport.Row) bool {
	return slices.ContainsFunc(row.Paths, func(p *accessreport.Path) bool { return slices.Contains(memberKinds, p.Kind) })
}

// reviewerIneligibility is what holds for a reviewer on every deployment of the repository (whose owner is loaded): a
// usable person with a membership path to it and read access to its Actions (approverReason). It returns "" if u may
// review, otherwise why not.
func reviewerIneligibility(ctx context.Context, repo *repo_model.Repository, u *user_model.User) (string, error) {
	if !usableReviewer(u) {
		return ReviewerNotUsable, nil
	}
	missing, err := withoutTwoFactor(ctx, repo.Owner, []int64{u.ID})
	if err != nil {
		return "", err
	}
	rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: []int64{repo.ID}, Users: []int64{u.ID}, RepoPermission: true})
	if err != nil {
		return "", err
	}
	for _, row := range rows {
		if row.User != nil && row.User.ID == u.ID {
			return approverReason(row, missing), nil
		}
	}
	return ReviewerOutsider, nil
}

// SeesReviewers is the one rule of who is shown the reviewers of a repository's deployments (their names, their
// number, that nobody can approve): a signed-in user who may change its Actions. Everyone else, readers of a public
// repository included, learns nothing about the reviewers, their accounts or their memberships.
func SeesReviewers(doer *user_model.User, perm access_model.Permission) bool {
	return doer != nil && perm.CanWrite(unit.TypeActions)
}

// twoFactorRequired tells if deployment approval in a repository of owner requires two-factor authentication: the
// owner is an organization that requires it. It then applies to everyone, site administrators included (repository
// access exempts them, user_model.User.TwoFactorBlocked): this is the one place that decides it.
func twoFactorRequired(owner *user_model.User) bool {
	return owner != nil && owner.IsOrganization() && owner.RequireTwoFactor
}

// usersWithoutTwoFactor returns the users among ids who have no two-factor authentication.
func usersWithoutTwoFactor(ctx context.Context, ids []int64) (container.Set[int64], error) {
	missing := container.Set[int64]{}
	if len(ids) == 0 {
		return missing, nil
	}
	has, err := auth_model.UserIDsWithTwoFactor(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if !has.Contains(id) {
			missing.Add(id)
		}
	}
	return missing, nil
}

// withoutTwoFactor returns the users among ids who may not approve in a repository of owner for lack of two-factor
// authentication.
func withoutTwoFactor(ctx context.Context, owner *user_model.User, ids []int64) (container.Set[int64], error) {
	if !twoFactorRequired(owner) {
		return container.Set[int64]{}, nil
	}
	return usersWithoutTwoFactor(ctx, ids)
}

// usableReviewer tells if u is a person who can sign in.
func usableReviewer(u *user_model.User) bool {
	return u.ID > 0 && !u.IsActions() && !u.IsAccessTokenBot() && u.IsIndividual() && u.IsActive && !u.ProhibitLogin
}

// EnvironmentReviewerCheck says, for the listed reviewers of environments of one repository, who can approve a
// deployment at this moment by the rules every deployment shares (those of one run, such as self-review, are left out).
type EnvironmentReviewerCheck struct {
	// Ineligible maps a reviewer key (ActionEnvironmentReviewer.Key) to why it can't approve; absent = can. A listed
	// user without a membership path gets ReviewerOutsider whatever their account, unless the doer is a site
	// administrator.
	Ineligible map[string]string
	NoReviewer map[int64]bool // environment ID -> it requires reviews and no listed reviewer can approve
	// Users are the listed users that exist (members of listed teams not included)
	Users map[int64]*user_model.User
	// Readers are the users with a membership path to the repository (memberPath) who can approve, in name order:
	// the ones to offer as reviewers.
	Readers []*user_model.User
	// Approvers maps an environment ID to the users who can approve its deployments by the rule of May, the listed
	// users and the members of the listed teams, before the rules of one run (self-review) and whoever the doer is:
	// the recipients of the review mail and the names on the run page (filtered by what the viewer may see).
	Approvers map[int64][]int64
}

// CheckEnvironmentReviewers decides the reviewers of the environments of repo for the doer's settings pages with the
// rule of ReviewChecker.May (reviewerIneligibility), with a fixed number of queries: the members of the listed teams
// in one, and the access of every user to the repository through accessreport.Compute, which replays
// GetUserRepoPermission. A team counts as soon as one member can approve. Only users with a membership path are
// decided in detail, unless the doer is a site administrator: the pages must not tell anyone else's account state.
func CheckEnvironmentReviewers(ctx context.Context, repo *repo_model.Repository, doer *user_model.User, envs []*actions_model.ActionEnvironment, reviewers map[int64][]*actions_model.ActionEnvironmentReviewer) (*EnvironmentReviewerCheck, error) {
	// only a team of the organization that owns the repository counts, as in May
	listedIDs, members, userIDs, err := listedReviewers(ctx, repo.OwnerID, reviewers)
	if err != nil {
		return nil, err
	}
	if err := repo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: []int64{repo.ID}, Users: userIDs, RepoPermission: true})
	if err != nil {
		return nil, err
	}
	var rowUsers []int64
	for _, row := range rows {
		if row.User != nil {
			rowUsers = append(rowUsers, row.User.ID)
		}
	}
	missing, err := withoutTwoFactor(ctx, repo.Owner, rowUsers)
	if err != nil {
		return nil, err
	}
	check := &EnvironmentReviewerCheck{Ineligible: map[string]string{}, NoReviewer: map[int64]bool{}, Users: map[int64]*user_model.User{}, Approvers: map[int64][]int64{}}
	detailed := doer != nil && doer.IsAdmin
	listed := container.SetOf(listedIDs...)
	decided := map[int64]string{} // a user without a row is no individual or no longer exists
	eligible := container.Set[int64]{}
	for _, row := range rows {
		if row.User == nil {
			continue
		}
		why := approverReason(row, missing)
		if why == "" {
			eligible.Add(row.User.ID)
			check.Readers = append(check.Readers, row.User)
		} else if !memberPath(row) && !detailed {
			why = ReviewerOutsider
		}
		decided[row.User.ID] = why
		if listed.Contains(row.User.ID) {
			check.Users[row.User.ID] = row.User
		}
	}
	check.decide(envs, reviewers, members, eligible, decided)
	return check, nil
}

// listedReviewers returns the listed users of the reviewers, the members of their teams of the organization orgID by
// team, and the IDs of both, with one query.
func listedReviewers(ctx context.Context, orgID int64, reviewers map[int64][]*actions_model.ActionEnvironmentReviewer) (listed []int64, members map[int64][]int64, all []int64, err error) {
	var teamIDs []int64
	for _, rs := range reviewers {
		for _, r := range rs {
			if r.TeamID > 0 {
				teamIDs = append(teamIDs, r.TeamID)
			} else {
				listed = append(listed, r.UserID)
			}
		}
	}
	all, members = slices.Clone(listed), map[int64][]int64{}
	if len(teamIDs) > 0 {
		var rows []*org_model.TeamUser
		if err := db.GetEngine(ctx).In("team_id", teamIDs).And("org_id = ?", orgID).Find(&rows); err != nil {
			return nil, nil, nil, err
		}
		for _, r := range rows {
			members[r.TeamID] = append(members[r.TeamID], r.UID)
			all = append(all, r.UID)
		}
	}
	return listed, members, all, nil
}

// decide fills the reviewers of the environments into check, from the members of the listed teams, the users who can
// approve and why the others can't (a user not in decided is no individual or no longer exists).
func (check *EnvironmentReviewerCheck) decide(envs []*actions_model.ActionEnvironment, reviewers map[int64][]*actions_model.ActionEnvironmentReviewer, members map[int64][]int64, eligible container.Set[int64], decided map[int64]string) {
	reason := func(id int64) string {
		if why, ok := decided[id]; ok {
			return why
		}
		return ReviewerNotUsable
	}
	// a team can approve as soon as one member can
	keyReason := func(r *actions_model.ActionEnvironmentReviewer) string {
		if r.TeamID == 0 {
			return reason(r.UserID)
		}
		if slices.ContainsFunc(members[r.TeamID], eligible.Contains) {
			return ""
		}
		return ReviewerNoneInTeam
	}
	for _, env := range envs {
		possible := false
		approvers := container.Set[int64]{}
		for _, r := range reviewers[env.ID] {
			why := keyReason(r)
			if why == "" {
				possible = true
			}
			if why != "" {
				check.Ineligible[r.Key()] = why
			}
			ids := []int64{r.UserID}
			if r.TeamID > 0 {
				ids = members[r.TeamID]
			}
			for _, uid := range ids {
				if eligible.Contains(uid) {
					approvers.Add(uid)
				}
			}
		}
		check.NoReviewer[env.ID] = env.ReviewsRequired && !possible
		check.Approvers[env.ID] = slices.Sorted(maps.Keys(approvers))
	}
}

// MaxOrgReviewerReaders is how many members of an organization CheckOrgEnvironmentReviewers offers as readers at most.
var MaxOrgReviewerReaders = 200

// CheckOrgEnvironmentReviewers is CheckEnvironmentReviewers for the settings pages of environments of the organization
// org, by the rules that don't depend on a repository (who approves a run is decided for its repository by
// approverReason): a listed user is a usable member of the organization (ReviewerOutsider for anyone else, whatever
// their account), with two-factor authentication if the organization requires it. Only the listed users and the
// members of the listed teams are decided, plus, with readers, the first MaxOrgReviewerReaders members by name, of whom
// those who pass are the Readers: the cost doesn't grow with the organization.
func CheckOrgEnvironmentReviewers(ctx context.Context, org *user_model.User, envs []*actions_model.ActionEnvironment, reviewers map[int64][]*actions_model.ActionEnvironmentReviewer, readers bool) (*EnvironmentReviewerCheck, error) {
	listedIDs, members, userIDs, err := listedReviewers(ctx, org.ID, reviewers)
	if err != nil {
		return nil, err
	}
	var memberIDs, offered []int64
	if readers {
		if err := db.GetEngine(ctx).Table("org_user").Join("INNER", "`user`", "`user`.id = org_user.uid").Where("org_user.org_id = ?", org.ID).
			OrderBy("`user`.lower_name").Limit(MaxOrgReviewerReaders).Cols("org_user.uid").Find(&offered); err != nil {
			return nil, err
		}
	}
	if len(userIDs) > 0 {
		if err := db.GetEngine(ctx).Table("org_user").Where("org_id = ?", org.ID).In("uid", userIDs).Cols("uid").Find(&memberIDs); err != nil {
			return nil, err
		}
	}
	memberIDs = append(memberIDs, offered...)
	users, err := user_model.GetUsersByIDs(ctx, slices.Compact(slices.Sorted(slices.Values(append(userIDs, offered...)))))
	if err != nil {
		return nil, err
	}
	missing, err := withoutTwoFactor(ctx, org, users.GetUserIDs())
	if err != nil {
		return nil, err
	}
	isOffered := container.SetOf(offered...)
	slices.SortFunc(users, func(a, b *user_model.User) int { return strings.Compare(a.LowerName, b.LowerName) })
	check := &EnvironmentReviewerCheck{Ineligible: map[string]string{}, NoReviewer: map[int64]bool{}, Users: map[int64]*user_model.User{}, Approvers: map[int64][]int64{}}
	isMember, listed := container.SetOf(memberIDs...), container.SetOf(listedIDs...)
	decided, eligible := map[int64]string{}, container.Set[int64]{}
	for _, u := range users {
		switch {
		case !isMember.Contains(u.ID):
			decided[u.ID] = ReviewerOutsider
		case !usableReviewer(u):
			decided[u.ID] = ReviewerNotUsable
		case missing.Contains(u.ID):
			decided[u.ID] = ReviewerTwoFactor
		default:
			decided[u.ID] = ""
			eligible.Add(u.ID)
			if isOffered.Contains(u.ID) {
				check.Readers = append(check.Readers, u)
			}
		}
		if listed.Contains(u.ID) {
			check.Users[u.ID] = u
		}
	}
	check.decide(envs, reviewers, members, eligible, decided)
	return check, nil
}

// approverReason is the one rule of who may approve, on a row of accessreport.Compute (which replays
// GetUserRepoPermission), with missing the users withoutTwoFactor returned for the repository's owner: a usable person
// with a membership path to the repository (memberPath) who reads its Actions. Reading a public repository is not
// enough: a former collaborator or member listed as a reviewer can't approve.
func approverReason(row *accessreport.Row, missing container.Set[int64]) string {
	switch {
	case !usableReviewer(row.User):
		return ReviewerNotUsable
	case missing.Contains(row.User.ID):
		return ReviewerTwoFactor
	case !row.Perm.CanRead(unit.TypeActions):
		return ReviewerNoAccess
	case !memberPath(row):
		return ReviewerOutsider
	}
	return ""
}

// May decides if the doer may review the deployment d at this moment (its status is not looked at): a listed user, or a
// member of a listed team (read now; only a team of the organization that owns the repository counts), who can read
// the repository's Actions. With the environment's PreventSelfReview, the run's trigger user and the user who started
// this attempt (a rerun) can't review.
func (c *ReviewChecker) May(ctx context.Context, d *actions_model.ActionDeployment) (bool, error) {
	if ok, err := c.doerMayAct(ctx); err != nil || !ok {
		return false, err
	}
	e, err := c.environment(ctx, d.EnvironmentID)
	if err != nil || e.env == nil {
		return false, err
	}
	if e.env.PreventSelfReview && (c.doer.ID == c.run.TriggerUserID || c.doer.ID == d.TriggerUserID) {
		return false, nil
	}
	if e.listed == nil {
		listed := false
		for _, r := range e.reviewers {
			if r.UserID == c.doer.ID {
				listed = true
			} else if r.TeamID > 0 {
				if listed, err = org_model.IsTeamMember(ctx, c.run.Repo.OwnerID, r.TeamID, c.doer.ID); err != nil {
					return false, err
				}
			}
			if listed {
				break
			}
		}
		e.listed = &listed
	}
	return *e.listed, nil
}

// notWaiting lets the gate look at the run (it expires a review that waited too long) and answers that the
// deployment doesn't wait for a review any more.
func notWaiting(runID int64) error {
	if err := EmitJobsIfReady(runID); err != nil {
		log.Error("EmitJobsIfReady for run %d after a review that found nothing waiting: %v", runID, err)
	}
	return ErrReviewNotWaiting
}

// ReviewDeployments approves or rejects the deployments of run that wait for a review: those of jobIDs, which must be
// named (an empty list is an invalid argument, so no review ever covers jobs the reviewer didn't see). One approval releases a job (when its wait timer is due too), one
// rejection fails it. Nothing changes unless every deployment can be reviewed: a job that doesn't wait any more
// (another reviewer, the expiry or a cancel came first, or it waited longer than the timeout) is ErrReviewNotWaiting,
// a deployment the doer may not review is ErrReviewForbidden. A review made under sudo, or with an OAuth2 grant or an
// authorized integration, is refused: a decision about a deployment is its reviewer's own, so neither an
// administrator nor an application can give it in somebody's name.
func ReviewDeployments(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, jobIDs []int64, approve bool, comment string) ([]*actions_model.ActionDeployment, error) {
	if !audit_model.IsOwnAct(ctx) {
		return nil, ErrReviewForbidden
	}
	if len(jobIDs) == 0 {
		return nil, util.NewInvalidArgumentErrorf("name the jobs to review")
	}
	comment, err := reviewComment(comment, approve)
	if err != nil {
		return nil, err
	}
	checker, err := NewReviewChecker(ctx, doer, run)
	if err != nil {
		return nil, err
	}
	jobs, err := actions_model.GetRunJobsByRunID(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	all, err := actions_model.FindRunDeployments(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	// who may review comes first, so a user who may not is always refused and starts no pass of the gate
	for _, id := range jobIDs {
		i := slices.IndexFunc(jobs, func(j *actions_model.ActionRunJob) bool { return j.ID == id })
		if i < 0 {
			return nil, util.NewInvalidArgumentErrorf("job %d is not a job of the run", id)
		}
		j := slices.IndexFunc(all, func(d *actions_model.ActionDeployment) bool { return d.JobID == id && d.Attempt == jobs[i].Attempt })
		if j < 0 {
			return nil, ErrReviewForbidden // nobody reviews a job that doesn't deploy
		}
		if ok, err := checker.May(ctx, all[j]); err != nil {
			return nil, err
		} else if !ok {
			return nil, ErrReviewForbidden // all or nothing
		}
	}
	cutoff := ReviewCutoff()
	waiting, err := actions_model.FindReviewableDeployments(ctx, run.ID, cutoff)
	if err != nil {
		return nil, err
	}
	for _, id := range jobIDs {
		if !slices.ContainsFunc(waiting, func(d *actions_model.ActionDeployment) bool { return d.JobID == id }) {
			return nil, notWaiting(run.ID)
		}
	}
	selected := slices.DeleteFunc(waiting, func(d *actions_model.ActionDeployment) bool { return !slices.Contains(jobIDs, d.JobID) })

	now := timeutil.TimeStampNow()
	action := "repo.actions_deployment.approved"
	to := actions_model.DeploymentWaitingTimer // approved: released by the gate once the wait timer is due
	if !approve {
		action, to = "repo.actions_deployment.rejected", actions_model.DeploymentRejected
	}
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		for _, d := range selected {
			d.Status, d.ReviewedBy, d.ReviewedUnix, d.ReviewComment = to, doer.ID, now, comment
			if moved, err := actions_model.ReviewDeployment(ctx, d, cutoff); err != nil {
				return err
			} else if !moved {
				return ErrReviewNotWaiting
			}
			// every change is recorded in its transaction; the comment is not (its length only)
			ev := audit_model.Event{Result: audit_model.ResultSuccess}
			ev.Action = action
			env, _, err := checker.Environment(ctx, d.EnvironmentID)
			if err != nil {
				return err
			}
			if err := recordDeploymentReview(ctx, run.Repo, env, d, ev, len(comment)); err != nil {
				return err
			}
			if !approve {
				mailDeploymentDecided(ctx, env, d)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// the gate releases or fails the jobs in its one place, outside the transaction as after a rerun
	if err := EmitJobsIfReady(run.ID); err != nil {
		log.Error("EmitJobsIfReady for run %d after a review: %v", run.ID, err)
	}
	// show what the gate did with them
	for i, d := range selected {
		if fresh, has, err := db.GetByID[actions_model.ActionDeployment](ctx, d.ID); err == nil && has {
			selected[i] = fresh
		}
	}
	return selected, nil
}

// recordDeploymentReview records a decision about a deployment: review, rejection or expiry.
func recordDeploymentReview(ctx context.Context, repo *repo_model.Repository, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment, ev audit_model.Event, commentLength int) error {
	ev.OwnerID, ev.GroupID, ev.RepoID = repo.OwnerID, repo.GroupID, repo.ID
	ev.TargetType, ev.TargetID = "actions_deployment", d.ID
	if env != nil {
		ev.TargetName = env.Name
	}
	if ev.Data == nil {
		ev.Data = map[string]any{}
	}
	maps.Copy(ev.Data, map[string]any{
		"environment_id": d.EnvironmentID, "ref": d.Ref, "run_id": d.RunID, "job_id": d.JobID, "attempt": d.Attempt,
		"comment_length": commentLength,
	})
	return audit_model.Record(ctx, ev)
}

// ExpireDeploymentReviews fails the deployments that waited longer than [actions] DEPLOYMENT_APPROVAL_TIMEOUT for a
// review, whatever their wait timer says; the gate fails their jobs. It holds nothing between runs: the deployment moves with
// a conditional update, so two servers can run it. The gate and the review itself enforce the same timeout, so this
// task only makes sure that nothing stays waiting when nobody looks at the run. A deployment that can't be processed
// goes to the back of the line, so it can't block the others.
func ExpireDeploymentReviews(ctx context.Context) error {
	if audit_model.ActorFromContext(ctx) == nil {
		ctx = audit_model.WithSystem(ctx, "actions")
	}
	expired, err := actions_model.FindExpiredReviews(ctx, ReviewCutoff(), maxExpiredPerTick)
	if err != nil {
		return err
	}
	runs := map[int64]bool{}
	for _, d := range expired {
		if err := expireDeployment(ctx, d); err != nil {
			log.Error("expire the review of deployment %d: %v", d.ID, err)
			if err := actions_model.TouchDeployment(ctx, d.ID, timeutil.TimeStampNow()); err != nil {
				log.Error("TouchDeployment %d: %v", d.ID, err)
			}
			continue
		}
		runs[d.RunID] = true
	}
	for runID := range runs {
		if err := EmitJobsIfReady(runID); err != nil {
			log.Error("EmitJobsIfReady for run %d after an expired review: %v", runID, err)
		}
	}
	return nil
}

// expireDeployment expires a deployment that waited too long, unless its environment no longer requires a review: the
// gate decides that one (it releases the job), so an edit that lifted the rule and the expiry can't disagree.
func expireDeployment(ctx context.Context, d *actions_model.ActionDeployment) error {
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, d.RepoID) // only the audit scope is needed
	if err != nil {
		return err
	}
	env, err := actions_model.GetEnvironmentOfRepo(ctx, d.RepoID, d.EnvironmentID)
	if err != nil && !errors.Is(err, util.ErrNotExist) {
		return err
	}
	if env != nil && !env.ReviewsRequired {
		return nil
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		d.Status = actions_model.DeploymentExpired
		if moved, err := actions_model.SetDeploymentStatus(ctx, d, actions_model.DeploymentWaitingReview); err != nil || !moved {
			return err // not waiting any more: nothing to do
		}
		mailDeploymentDecided(ctx, env, d)
		return recordDeploymentReview(ctx, repo, env, d, audit_model.Event{Action: "repo.actions_deployment.expired", Result: audit_model.ResultFailure}, 0)
	})
}
