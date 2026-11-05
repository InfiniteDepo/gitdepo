// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"
	"strings"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/services/mailer"
)

// the mailer's functions; a test replaces them to see who is mailed
var (
	sendReviewMail  = mailer.MailDeploymentReview
	sendDecidedMail = mailer.MailDeploymentDecided
)

// withoutSelfReview drops from the users those the environment's self-review rule bars from reviewing d (as May does):
// the run's trigger user and the user who started the attempt.
func withoutSelfReview(ids []int64, env *actions_model.ActionEnvironment, run *actions_model.ActionRun, d *actions_model.ActionDeployment) []int64 {
	if !env.PreventSelfReview {
		return ids
	}
	return slices.DeleteFunc(slices.Clone(ids), func(id int64) bool { return id == run.TriggerUserID || id == d.TriggerUserID })
}

// DeploymentApprovers returns the users who may review d now by the rule of May, in ID order, with the reviewer
// check of its environment (whose NoReviewer says, for the settings pages' doer, that nobody can approve).
func DeploymentApprovers(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment) ([]int64, *EnvironmentReviewerCheck, error) {
	reviewers, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := run.LoadRepo(ctx); err != nil {
		return nil, nil, err
	}
	check, err := CheckEnvironmentReviewers(ctx, run.Repo, doer, []*actions_model.ActionEnvironment{env}, map[int64][]*actions_model.ActionEnvironmentReviewer{env.ID: reviewers})
	if err != nil {
		return nil, nil, err
	}
	return withoutSelfReview(check.Approvers[env.ID], env, run, d), check, nil
}

// afterCommit runs send once the caller's transaction commits (at once outside one), on a context of its own: the
// transaction's session is done by then, and a mail must never be sent for a change that was rolled back.
func afterCommit(ctx context.Context, what string, send func(ctx context.Context) error) {
	db.AfterTx(ctx, func() {
		// a run, job or repository that is gone (or in the trash) meanwhile has nobody to tell
		if err := send(graceful.GetManager().ShutdownContext()); err != nil && !errors.Is(err, util.ErrNotExist) {
			log.Error("mail about %s: %v", what, err)
		}
	})
}

// mailDeploymentReviewers mails the users who may review d that it waits for them, once the transaction that made it
// wait commits: the gate calls it only when a deployment starts to wait for a review (or does again, when an approval
// is revoked), so a later pass sends nothing and a rerun's new attempt (a new deployment) sends its own. The jobs of a
// run attempt that deploy to one environment (a matrix) share one mail, which one server claims right before sending it.
func mailDeploymentReviewers(ctx context.Context, run *actions_model.ActionRun, jobName string, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment) {
	afterCommit(ctx, "a deployment waiting for a review", func(ctx context.Context) error {
		ids, _, err := DeploymentApprovers(ctx, nil, run, env, d)
		if err != nil || len(ids) == 0 {
			return err
		}
		users, err := user_model.GetUsersByIDs(ctx, ids)
		if err != nil {
			return err
		}
		m, err := deploymentMail(ctx, run, jobName, env.Name, d)
		if err != nil {
			return err
		}
		// claimed last, right before the send: a crash after a successful claim can still drop this one mail, which is
		// accepted for a notification (a second server never sends it twice)
		if claimed, err := actions_model.ClaimDeploymentMail(ctx, d); err != nil || !claimed {
			return err
		}
		return sendReviewMail(ctx, users, m)
	})
}

// mailDeploymentDecided mails the user who started the attempt that d was rejected or expired, once the transaction
// that decided it commits; once for the jobs of a run attempt that deploy to one environment.
func mailDeploymentDecided(ctx context.Context, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment) {
	if d.TriggerUserID <= 0 {
		return
	}
	afterCommit(ctx, "a rejected or expired deployment", func(ctx context.Context) error {
		run, err := actions_model.GetRunByID(ctx, d.RunID)
		if err != nil {
			return err
		}
		u, err := user_model.GetUserByID(ctx, d.TriggerUserID)
		if user_model.IsErrUserNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		job, err := actions_model.GetRunJobByID(ctx, d.JobID)
		if err != nil {
			return err
		}
		name := ""
		if env != nil {
			name = env.Name
		}
		m, err := deploymentMail(ctx, run, job.Name, name, d)
		if err != nil {
			return err
		}
		if d.Status == actions_model.DeploymentRejected {
			if m.Reviewer, err = possibleUser(ctx, d.ReviewedBy); err != nil {
				return err
			}
		}
		// claimed last, right before the send: a crash after a successful claim can still drop this one mail, which is
		// accepted for a notification (a second server never sends it twice)
		if claimed, err := actions_model.ClaimDeploymentMail(ctx, d); err != nil || !claimed {
			return err
		}
		return sendDecidedMail(ctx, u, m)
	})
}

func deploymentMail(ctx context.Context, run *actions_model.ActionRun, jobName, envName string, d *actions_model.ActionDeployment) (*mailer.DeploymentMail, error) {
	if err := run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	trigger, err := possibleUser(ctx, d.TriggerUserID)
	if err != nil {
		return nil, err
	}
	return &mailer.DeploymentMail{
		Run: run, JobName: jobName, Environment: envName, Deployment: d, TriggerUser: trigger,
		Expires: d.Created.AsTime().Add(setting.Actions.DeploymentApprovalTimeout),
	}, nil
}

// possibleUser is the user of the ID, the ghost for one that no longer exists.
func possibleUser(ctx context.Context, id int64) (*user_model.User, error) {
	u, err := user_model.GetPossibleUserByID(ctx, id)
	if user_model.IsErrUserNotExist(err) {
		return user_model.NewGhostUser(), nil
	}
	return u, err
}

// RunReviewers is who may review the waiting deployments of one run, decided once for all their environments: for the
// run page of a viewer who may change the repository's Actions (SeesReviewers), the only one shown the reviewers.
type RunReviewers struct {
	run   *actions_model.ActionRun
	check *EnvironmentReviewerCheck
	users map[int64][]*user_model.User // environment ID -> the listed users who can approve, visible to the viewer
	teams map[int64][]string           // environment ID -> the listed teams one of whose members can approve, as org/team
}

// LoadRunReviewers decides the reviewers of the environments for run with a fixed number of queries: the reviewer
// check of the settings pages, the listed users the doer may see and the listed teams.
func LoadRunReviewers(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, envs []*actions_model.ActionEnvironment, reviewers map[int64][]*actions_model.ActionEnvironmentReviewer) (*RunReviewers, error) {
	if err := run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	check, err := CheckEnvironmentReviewers(ctx, run.Repo, doer, envs, reviewers)
	if err != nil {
		return nil, err
	}
	var userIDs, teamIDs []int64
	for _, rs := range reviewers {
		for _, r := range rs {
			if r.TeamID > 0 {
				teamIDs = append(teamIDs, r.TeamID)
			} else {
				userIDs = append(userIDs, r.UserID)
			}
		}
	}
	users, err := VisibleUsers(ctx, doer, userIDs)
	if err != nil {
		return nil, err
	}
	teams := map[int64]*org_model.Team{}
	if len(teamIDs) > 0 {
		var list []*org_model.Team
		if err := db.GetEngine(ctx).In("id", teamIDs).And("org_id = ?", run.Repo.OwnerID).Find(&list); err != nil {
			return nil, err
		}
		for _, t := range list {
			teams[t.ID] = t
		}
	}
	r := &RunReviewers{run: run, check: check, users: map[int64][]*user_model.User{}, teams: map[int64][]string{}}
	for envID, rs := range reviewers {
		for _, rv := range rs {
			if check.Ineligible[rv.Key()] != "" {
				continue // can't approve: not named
			}
			if rv.TeamID > 0 {
				if t := teams[rv.TeamID]; t != nil {
					r.teams[envID] = append(r.teams[envID], run.Repo.OwnerName+"/"+t.Name)
				}
			} else if u := users[rv.UserID]; u != nil && !u.IsGhost() && slices.Contains(check.Approvers[envID], rv.UserID) {
				r.users[envID] = append(r.users[envID], u)
			}
		}
		slices.Sort(r.teams[envID])
		slices.SortFunc(r.users[envID], func(a, b *user_model.User) int { return strings.Compare(a.GetDisplayName(), b.GetDisplayName()) })
	}
	return r, nil
}

// Names are the listed reviewers who can approve d: the users the doer may see (without those the self-review rule
// bars), then the teams as org/team.
func (r *RunReviewers) Names(env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment) []string {
	var names []string
	for _, u := range r.users[env.ID] {
		if len(withoutSelfReview([]int64{u.ID}, env, r.run, d)) == 1 {
			names = append(names, u.GetDisplayName())
		}
	}
	return append(names, r.teams[env.ID]...)
}

// Nobody tells if no listed reviewer can approve d now, and if that is because of the self-review rule alone.
func (r *RunReviewers) Nobody(env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment) (nobody, selfReview bool) {
	all := r.check.Approvers[env.ID]
	approvers := withoutSelfReview(all, env, r.run, d)
	if r.check.NoReviewer[env.ID] || len(approvers) == 0 {
		return true, len(approvers) < len(all)
	}
	return false, false
}
