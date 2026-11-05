// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"testing"
	"time"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReviewRulesAreEvaluatedOnEveryPass(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()

	t.Run("reviewers added while the timer runs hold the job for an approval", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: 5}, nil, nil)
		assert.Equal(t, actions_model.DeploymentWaitingTimer, f.status(t))
		require.NoError(t, SetEnvironmentReviewers(f.ctx, f.env, []int64{2}, nil))
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
	})

	t.Run("reviewers removed by an edit release a job that waits for an approval", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		require.NoError(t, SetEnvironmentReviewers(f.ctx, f.env, nil, nil))
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))
	})

	t.Run("reviewers lost by a deletion keep holding, one entry per environment", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
		other := newEnvironment(t, &actions_model.ActionEnvironment{Name: "other"})
		require.NoError(t, SetEnvironmentReviewers(f.ctx, other, []int64{4}, nil))
		since := auditSince(t)
		require.NoError(t, db.WithTx(f.ctx, func(ctx context.Context) error {
			return actions_model.RemoveReviewers(ctx, actions_model.UserReviewerCond(4))
		}))
		assert.Len(t, auditActions(t, since, "repo.actions_env.updated"), 2)
		rs, err := actions_model.FindEnvironmentReviewers(f.ctx, f.env.ID)
		require.NoError(t, err)
		assert.Len(t, rs, 1)
		rs, err = actions_model.FindEnvironmentReviewers(f.ctx, other.ID)
		require.NoError(t, err)
		assert.Empty(t, rs)
		// "other" lost every reviewer: it still holds until someone edits its rules
		stored, err := actions_model.GetRepoEnvironmentByID(f.ctx, 63, other.ID)
		require.NoError(t, err)
		assert.True(t, stored.ReviewsRequired)
		d := &actions_model.ActionDeployment{Status: actions_model.DeploymentWaitingReview, Created: 1 << 40}
		nextDeploymentStatus(d, stored, "", 1)
		assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
		require.NoError(t, SetEnvironmentReviewers(f.ctx, stored, nil, nil))
		stored, err = actions_model.GetRepoEnvironmentByID(f.ctx, 63, other.ID)
		require.NoError(t, err)
		assert.False(t, stored.ReviewsRequired, "an edit is how the rule is lifted")
	})

	t.Run("deleting a team keeps the environment holding", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		teamReadsActions(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		require.NoError(t, SetEnvironmentReviewers(f.ctx, f.env, nil, []int64{2}))
		team, err := org_model.GetTeamByID(f.ctx, 2)
		require.NoError(t, err)
		since := auditSince(t)
		require.NoError(t, models.DeleteTeam(f.ctx, team))
		assert.Len(t, auditActions(t, since, "repo.actions_env.updated"), 1)
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
	})

	t.Run("a transfer drops the teams of the old organization, audited, and keeps requiring a review", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		teamReadsActions(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		require.NoError(t, SetEnvironmentReviewers(f.ctx, f.env, []int64{2}, []int64{2})) // team 2 is organization 3's
		require.NoError(t, db.WithTx(f.ctx, func(ctx context.Context) error {
			return actions_model.RemoveReviewers(ctx, actions_model.ForeignTeamReviewerCond(63, 3))
		}))
		rs, err := actions_model.FindEnvironmentReviewers(f.ctx, f.env.ID)
		require.NoError(t, err)
		assert.Len(t, rs, 2, "the team belongs to the new owner")
		since := auditSince(t)
		require.NoError(t, db.WithTx(f.ctx, func(ctx context.Context) error {
			return actions_model.RemoveReviewers(ctx, actions_model.ForeignTeamReviewerCond(63, 6))
		}))
		rs, err = actions_model.FindEnvironmentReviewers(f.ctx, f.env.ID)
		require.NoError(t, err)
		require.Len(t, rs, 1)
		assert.EqualValues(t, 2, rs[0].UserID)
		assert.Len(t, auditActions(t, since, "repo.actions_env.updated"), 1)
		stored, err := actions_model.GetRepoEnvironmentByID(f.ctx, 63, f.env.ID)
		require.NoError(t, err)
		assert.True(t, stored.ReviewsRequired)
	})

	t.Run("reviewers of an environment of a trashed repository can be removed and are recorded", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
		teamReadsActions(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 63")
		require.NoError(t, err)
		since := auditSince(t)
		require.NoError(t, db.WithTx(f.ctx, func(ctx context.Context) error {
			return actions_model.RemoveReviewers(ctx, actions_model.UserReviewerCond(4))
		}))
		assert.Len(t, auditActions(t, since, "repo.actions_env.updated"), 1)
		// a team of another organization, as after a restore to a new owner
		require.NoError(t, db.WithTx(f.ctx, func(ctx context.Context) error {
			require.NoError(t, actions_model.ReplaceEnvironmentReviewers(ctx, f.env, []actions_model.ActionEnvironmentReviewer{{UserID: 2}, {TeamID: 2}}))
			return actions_model.RemoveReviewers(ctx, actions_model.ForeignTeamReviewerCond(63, 6))
		}))
		rs, err := actions_model.FindEnvironmentReviewers(f.ctx, f.env.ID)
		require.NoError(t, err)
		assert.Len(t, rs, 1)
		// deleting a team that reviews there
		require.NoError(t, actions_model.ReplaceEnvironmentReviewers(f.ctx, f.env, []actions_model.ActionEnvironmentReviewer{{TeamID: 2}}))
		team, err := org_model.GetTeamByID(f.ctx, 2)
		require.NoError(t, err)
		require.NoError(t, models.DeleteTeam(f.ctx, team))
	})

	t.Run("the delete entry says whether reviews were required", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		require.NoError(t, db.WithTx(f.ctx, func(ctx context.Context) error {
			return actions_model.RemoveReviewers(ctx, actions_model.UserReviewerCond(2))
		}))
		since := auditSince(t)
		require.NoError(t, DeleteEnvironment(f.ctx, f.env))
		entries := auditActions(t, since, "repo.actions_env.deleted")
		require.Len(t, entries, 1)
		assert.Contains(t, entries[0].Data, `"reviews_required":true`)
	})

	t.Run("editing the reviewers queues the runs of the waiting jobs, and the gate then releases them", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		queued := make(chan int64, 10)
		cfg, err := setting.NewConfigProviderFromData("[queue.actions_ready_job]\nTYPE = immediate\n")
		require.NoError(t, err)
		defer test.MockVariableValue(&setting.CfgProvider, cfg)()
		q := queue.CreateUniqueQueue(t.Context(), "actions_ready_job", func(items ...*jobUpdate) []*jobUpdate {
			for _, i := range items {
				queued <- i.RunID
			}
			return nil
		})
		require.NotNil(t, q)
		defer test.MockVariableValue(&jobEmitterQueue, q)()
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET task_id = 0 WHERE id = ?", f.job.ID) // no runner took it
		require.NoError(t, err)
		require.NoError(t, SetEnvironmentReviewers(f.ctx, f.env, nil, nil))
		select {
		case id := <-queued:
			assert.Equal(t, f.run.ID, id)
		default:
			t.Fatal("the run was not queued")
		}
		assert.Equal(t, actions_model.StatusWaiting, f.emit(t).Status, "the gate released it")
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))
	})

	t.Run("an environment without reviews is not expired: the gate releases the job", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		defer test.MockVariableValue(&setting.Actions.DeploymentApprovalTimeout, 48*time.Hour)()
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET created = ? WHERE job_id = ?", time.Now().Add(-49*time.Hour).Unix(), f.job.ID)
		require.NoError(t, err)
		require.NoError(t, actions_model.ReplaceEnvironmentReviewers(f.ctx, f.env, nil)) // no emitter pass, as in a race with the cron
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t), "not expired")
		f.emit(t)
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))
	})

	t.Run("a sudo'd list says false where the review is refused", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		check := func(ctx context.Context) bool {
			c, err := NewReviewChecker(ctx, doer, f.run)
			require.NoError(t, err)
			ok, err := c.May(ctx, f.deployment(t))
			require.NoError(t, err)
			return ok
		}
		assert.True(t, check(f.ctx))
		actor := &audit_model.Actor{Type: "user", ID: 1, Name: "admin"}
		actor.SetSudo(2, "user2")
		assert.False(t, check(audit_model.WithActor(t.Context(), actor)))
	})

	t.Run("an environment name has no colon or whitespace", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		for _, name := range []string{"a:b", "a b", "a\tb", "a\u00a0b", "a\u2003b"} {
			require.Error(t, actions_model.CreateEnvironment(audit_model.WithSystem(t.Context(), "test"),
				&actions_model.ActionEnvironment{RepoID: 63, Name: name}), name)
		}
	})
}

func TestReviewExpiryHolds(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	defer test.MockVariableValue(&setting.Actions.DeploymentApprovalTimeout, 48*time.Hour)()
	backdate := func(t *testing.T, f *reviewFixture) {
		t.Helper()
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET created = ? WHERE job_id = ?", time.Now().Add(-49*time.Hour).Unix(), f.job.ID)
		require.NoError(t, err)
	}

	t.Run("the gate expires an overdue waiting deployment without the cron", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		backdate(t, f)
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
		assert.Equal(t, actions_model.DeploymentExpired, f.status(t))
	})

	t.Run("an approval after the timeout is refused", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		backdate(t, f)
		_, err := f.review(t, 2, true, "")
		require.ErrorIs(t, err, ErrReviewNotWaiting)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t), "the approval changed nothing")
		f.emit(t) // the gate, which the refused review queued
		assert.Equal(t, actions_model.DeploymentExpired, f.status(t))
	})

	t.Run("a trashed repository does not stop the expiry", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		backdate(t, f)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 63")
		require.NoError(t, err)
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Equal(t, actions_model.DeploymentExpired, f.status(t))
	})

	t.Run("a row that fails goes to the back and the others are still expired", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		backdate(t, f)
		require.NoError(t, actions_model.TouchDeployment(f.ctx, f.deployment(t).ID, 1<<40))
		ds, err := actions_model.FindExpiredReviews(f.ctx, ReviewCutoff(), 10)
		require.NoError(t, err)
		require.Len(t, ds, 1)
		assert.Equal(t, f.deployment(t).ID, ds[0].ID)
	})
}

func TestReviewIdentity(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()

	t.Run("a review under sudo is refused", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		actor := &audit_model.Actor{Type: "user", ID: 1, Name: "admin"}
		actor.SetSudo(2, "user2")
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		_, err := ReviewDeployments(audit_model.WithActor(t.Context(), actor), doer, f.run, nil, true, "")
		require.ErrorIs(t, err, ErrReviewForbidden)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
	})

	t.Run("who reran can't review under the self-review rule", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{PreventSelfReview: true}, []int64{2, 4}, nil)
		grantActionsRead(t, 4)
		// the run was started by user 2; user 4 started this attempt
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET trigger_user_id = 4 WHERE job_id = ?", f.job.ID)
		require.NoError(t, err)
		_, err = f.review(t, 4, true, "")
		require.ErrorIs(t, err, ErrReviewForbidden)
		_, err = f.review(t, 2, true, "")
		require.ErrorIs(t, err, ErrReviewForbidden, "the run's trigger user too")
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
	})

	t.Run("the attempt's starter is the one recorded", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		assert.EqualValues(t, 2, triggerUser(f.job, f.run))
		f.job.AttemptTriggerUserID = 4
		assert.EqualValues(t, 4, triggerUser(f.job, f.run))
	})

	t.Run("a comment holds no format or separator character", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		for name, c := range map[string]string{
			"c1 control": "a\u0085b", "bidi override": "a\u202eb", "bidi isolate": "a\u2066b", "zero width": "a\u200bb",
			"zero width joiner": "a\u200db", "bom": "a\ufeffb", "line separator": "a\u2028b", "paragraph separator": "a\u2029b",
		} {
			_, err := f.review(t, 2, true, c)
			require.ErrorIs(t, err, util.ErrInvalidArgument, name)
		}
		_, err := f.review(t, 2, true, "ünïcöd\u00e9 ok")
		require.NoError(t, err)
	})
}

func TestReviewDelegatedCredentials(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	as := func(credential string) context.Context {
		return audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", Credential: audit_model.Credential{Type: credential, ID: 7}})
	}
	for _, c := range []string{audit_model.CredentialOAuth2Grant, audit_model.CredentialAuthorizedIntegration} {
		_, err := ReviewDeployments(as(c), doer, f.run, []int64{f.job.ID}, true, "")
		require.ErrorIs(t, err, ErrReviewForbidden, c)
		_, err = ReviewDeployments(as(c), doer, f.run, []int64{f.job.ID}, false, "no")
		require.ErrorIs(t, err, ErrReviewForbidden, c)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t), c)
		checker, err := NewReviewChecker(as(c), doer, f.run)
		require.NoError(t, err)
		ok, err := checker.May(as(c), f.deployment(t))
		require.NoError(t, err)
		assert.False(t, ok, "can_review follows: %s", c)
	}
	// the reviewer's own session or access token
	for _, c := range []string{audit_model.CredentialSession, audit_model.CredentialAccessToken, audit_model.CredentialPassword} {
		checker, err := NewReviewChecker(as(c), doer, f.run)
		require.NoError(t, err)
		ok, err := checker.May(as(c), f.deployment(t))
		require.NoError(t, err)
		assert.True(t, ok, c)
	}
	_, err := ReviewDeployments(as(audit_model.CredentialAccessToken), doer, f.run, []int64{f.job.ID}, true, "")
	require.NoError(t, err)
}

func TestApprovalRevokedWhenApproverIsNoLongerEligible(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	setup := func(t *testing.T) *reviewFixture {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: 60}, []int64{2, 4}, nil)
		grantActionsRead(t, 4)
		_, err := f.review(t, 4, true, "ship it")
		require.NoError(t, err)
		require.Equal(t, actions_model.DeploymentWaitingTimer, f.status(t))
		return f
	}
	timerEnds := func(t *testing.T, f *reviewFixture) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET release_after_unix = ? WHERE job_id = ?", time.Now().Add(-time.Minute).Unix(), f.job.ID)
		require.NoError(t, err)
	}

	t.Run("an approver who is still eligible releases the job", func(t *testing.T) {
		f := setup(t)
		timerEnds(t, f)
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))
	})

	for name, change := range map[string]func(t *testing.T, f *reviewFixture){
		"removed from the reviewers": func(t *testing.T, f *reviewFixture) {
			require.NoError(t, SetEnvironmentReviewers(f.ctx, f.env, []int64{2}, nil))
		},
		"deactivated": func(t *testing.T, f *reviewFixture) {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE user SET is_active = ? WHERE id = 4", false)
			require.NoError(t, err)
		},
		"lost access to Actions": func(t *testing.T, f *reviewFixture) {
			_, err := db.GetEngine(t.Context()).Exec("DELETE FROM collaboration WHERE user_id = 4 AND repo_id = 63")
			require.NoError(t, err)
			_, err = db.GetEngine(t.Context()).Exec("DELETE FROM access WHERE user_id = 4 AND repo_id = 63")
			require.NoError(t, err)
		},
	} {
		t.Run("the approver is "+name+" during the timer", func(t *testing.T) {
			f := setup(t)
			change(t, f)
			since := auditSince(t)
			timerEnds(t, f)
			b, err := gateEnvironment(f.ctx, f.job)
			require.NoError(t, err)
			assert.Equal(t, behaviourHoldJob, b)
			d := f.deployment(t)
			assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
			assert.Zero(t, d.ReviewedBy)
			assert.Zero(t, d.ReviewedUnix)
			assert.Empty(t, d.ReviewComment)
			entries := auditActions(t, since, "repo.actions_deployment.approval_revoked")
			require.Len(t, entries, 1)
			assert.Contains(t, entries[0].Data, `"revoked_reviewer_id":4`)
			// a pass again changes nothing and doesn't record again
			_, err = gateEnvironment(f.ctx, f.job)
			require.NoError(t, err)
			assert.Len(t, auditActions(t, since, "repo.actions_deployment.approval_revoked"), 1)
			// another reviewer decides it afresh
			_, err = f.review(t, 2, true, "")
			require.NoError(t, err)
			assert.EqualValues(t, 2, f.deployment(t).ReviewedBy)
		})
	}
}
