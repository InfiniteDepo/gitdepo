// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
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
// wait commits: the gate calls it only when a deployment starts to wait for a review, so a later pass sends nothing
// and a rerun's new attempt (a new deployment) sends its own.
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
		return sendReviewMail(ctx, users, m)
	})
}

// mailDeploymentDecided mails the user who started the attempt that d was rejected or expired, once the transaction
// that decided it commits.
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
