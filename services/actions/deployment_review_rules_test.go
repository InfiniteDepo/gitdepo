// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"testing"
	"time"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
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
		require.NoError(t, setReviewers(f.ctx, f.env, []int64{2}, nil))
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
	})

	t.Run("reviewers removed by an edit release a job that waits for an approval", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		require.NoError(t, setReviewers(f.ctx, f.env, nil, nil))
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourExecuteJob, b)
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))
	})

	t.Run("reviewers lost by a deletion keep holding, one entry per environment", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
		other := newEnvironment(t, &actions_model.ActionEnvironment{Name: "other"})
		require.NoError(t, setReviewers(f.ctx, other, []int64{4}, nil))
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
		require.NoError(t, setReviewers(f.ctx, stored, nil, nil))
		stored, err = actions_model.GetRepoEnvironmentByID(f.ctx, 63, other.ID)
		require.NoError(t, err)
		assert.False(t, stored.ReviewsRequired, "an edit is how the rule is lifted")
	})

	t.Run("deleting a team keeps the environment holding", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		teamReadsActions(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		require.NoError(t, setReviewers(f.ctx, f.env, nil, []int64{2}))
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
		require.NoError(t, setReviewers(f.ctx, f.env, []int64{2}, []int64{2})) // team 2 is organization 3's
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
			require.NoError(t, replaceReviewers(ctx, f.env, []actions_model.ActionEnvironmentReviewer{{UserID: 2}, {TeamID: 2}}))
			return actions_model.RemoveReviewers(ctx, actions_model.ForeignTeamReviewerCond(63, 6))
		}))
		rs, err := actions_model.FindEnvironmentReviewers(f.ctx, f.env.ID)
		require.NoError(t, err)
		assert.Len(t, rs, 1)
		// deleting a team that reviews there
		require.NoError(t, replaceReviewers(f.ctx, f.env, []actions_model.ActionEnvironmentReviewer{{TeamID: 2}}))
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
		require.NoError(t, setReviewers(f.ctx, f.env, nil, nil))
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
		require.NoError(t, replaceReviewers(f.ctx, f.env, nil)) // no emitter pass, as in a race with the cron
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
				&actions_model.ActionEnvironment{RepoID: 63, Name: name}, nil), name)
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
		_, err := ReviewDeployments(audit_model.WithActor(t.Context(), actor), doer, f.run, []int64{f.job.ID}, true, "")
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
			require.NoError(t, setReviewers(f.ctx, f.env, []int64{2}, nil))
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

// A revocation that loses its race is an error of the caller's transaction, which is the emitter's: its earlier writes
// are neither lost while the rest of the pass goes on outside it, nor half kept.
func TestRevokeApprovalLostRace(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: 60}, []int64{2, 4}, nil)
	grantActionsRead(t, 4)
	_, err := f.review(t, 4, true, "")
	require.NoError(t, err)
	require.NoError(t, setReviewers(f.ctx, f.env, []int64{2}, nil)) // the approver is no reviewer any more
	stale := f.deployment(t)                                        // read before the race
	_, err = db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET reviewed_by = 2 WHERE id = ?", stale.ID)
	require.NoError(t, err) // somebody else approved meanwhile
	env, err := actions_model.GetRepoEnvironmentByID(f.ctx, 63, f.env.ID)
	require.NoError(t, err)
	title := func() string {
		return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{ID: f.run.ID}).Title
	}
	before := title()
	since := auditSince(t)

	// the error reaches the caller, and the transaction rolls back as a whole
	err = db.WithTx(f.ctx, func(ctx context.Context) error {
		_, err := db.GetEngine(ctx).Exec("UPDATE action_run SET title = 'marker' WHERE id = ?", f.run.ID)
		require.NoError(t, err)
		revoked, err := revokeApprovalIfIneligible(ctx, f.run, env, stale)
		assert.False(t, revoked)
		return err
	})
	require.Error(t, err)
	assert.Equal(t, before, title(), "rolled back as a whole")
	assert.Empty(t, auditActions(t, since, "repo.actions_deployment.approval_revoked"))

	// even when the caller goes on, the transaction is still the one it had: nothing is autocommitted halfway
	err = db.WithTx(f.ctx, func(ctx context.Context) error {
		_, err := db.GetEngine(ctx).Exec("UPDATE action_run SET title = 'marker' WHERE id = ?", f.run.ID)
		require.NoError(t, err)
		_, _ = revokeApprovalIfIneligible(ctx, f.run, env, stale)
		_, err = db.GetEngine(ctx).Exec("UPDATE action_run SET title = 'marker two' WHERE id = ?", f.run.ID)
		return err
	})
	if err == nil {
		assert.Equal(t, "marker two", title(), "committed together")
	} else {
		assert.Equal(t, before, title(), "rolled back together")
	}
	assert.Equal(t, actions_model.DeploymentWaitingTimer, f.status(t), "the other approval stands")
}

func TestReviewRefusesEmptyJobsAndNoActor(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	for _, jobs := range [][]int64{nil, {}} {
		_, err := ReviewDeployments(f.ctx, doer, f.run, jobs, true, "")
		require.ErrorIs(t, err, util.ErrInvalidArgument, "the jobs must be named")
	}
	assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))

	// without an actor on the request nothing can be told about who acts: refused, and can_review is false
	_, err := ReviewDeployments(t.Context(), doer, f.run, []int64{f.job.ID}, true, "")
	require.ErrorIs(t, err, ErrReviewForbidden)
	checker, err := NewReviewChecker(t.Context(), doer, f.run)
	require.NoError(t, err)
	ok, err := checker.May(t.Context(), f.deployment(t))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))

	_, err = ReviewDeployments(f.ctx, doer, f.run, []int64{f.job.ID}, true, "")
	require.NoError(t, err)
}

// The model checks the reviewers again in the transaction that inserts them, after the services' checks: a user or team
// deleted meanwhile, or a team of an organization that no longer owns the repository, is refused there.
func TestReviewerTeamsCheckedInTransaction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	e := &actions_model.ActionEnvironment{RepoID: 3, Name: "prod"} // repository 3 belongs to organization 3, team 1 too
	require.NoError(t, actions_model.CreateEnvironment(ctx, e, []actions_model.ActionEnvironmentReviewer{{TeamID: 1}}))
	for name, list := range map[string][]actions_model.ActionEnvironmentReviewer{
		"a team of another organization": {{TeamID: 5}},
		"a team that is gone":            {{TeamID: 99999}},
		"a user that is gone":            {{TeamID: 1}, {UserID: 99999}},
	} {
		require.ErrorIs(t, actions_model.UpdateEnvironment(ctx, e, list), util.ErrInvalidArgument, name)
		require.ErrorIs(t, actions_model.CreateEnvironment(ctx, &actions_model.ActionEnvironment{RepoID: 3, Name: "other"}, list), util.ErrInvalidArgument, name)
	}
	rs, err := actions_model.FindEnvironmentReviewers(ctx, e.ID)
	require.NoError(t, err)
	require.Len(t, rs, 1, "a refused list changes nothing")
	assert.EqualValues(t, 1, rs[0].TeamID)
	unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: 3, LowerName: "other"})
}

// The bulk decision of the settings pages gives the reasons of ReviewChecker.May without the rules of one run.
func TestCheckEnvironmentReviewers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // private, of org3
	require.NoError(t, repo.LoadOwner(t.Context()))
	envs := []*actions_model.ActionEnvironment{{ID: 1, ReviewsRequired: true}, {ID: 2, ReviewsRequired: true}, {ID: 3, ReviewsRequired: true}, {ID: 4}}
	reviewers := map[int64][]*actions_model.ActionEnvironmentReviewer{
		1: {{UserID: 2}},                  // an owner of org3
		2: {{UserID: 10}, {TeamID: 7}},    // no access; a team whose member (user15) can't read repo3
		3: {{UserID: 10}, {TeamID: 1}},    // the Owners team of org3 counts
		4: {{UserID: 99999}, {TeamID: 7}}, // a missing user; reviews not required: no warning
	}
	check, err := CheckEnvironmentReviewers(t.Context(), repo, envs, reviewers)
	require.NoError(t, err)
	assert.Equal(t, map[int64]bool{1: false, 2: true, 3: false, 4: false}, check.NoReviewer)
	assert.Equal(t, map[string]string{"user:10": ReviewerNoAccess, "team:7": ReviewerNoneInTeam, "user:99999": ReviewerNotUsable}, check.Ineligible)

	// a reviewer that can't sign in no longer counts
	_, err = db.GetEngine(t.Context()).ID(2).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
	require.NoError(t, err)
	check, err = CheckEnvironmentReviewers(t.Context(), repo, envs[:1], reviewers)
	require.NoError(t, err)
	assert.True(t, check.NoReviewer[1])
	assert.Equal(t, ReviewerNotUsable, check.Ineligible["user:2"])
}

// The bulk check decides every user as reviewerIneligibility does, on public and private repositories of users and
// organizations, with and without a 2FA requirement.
func TestCheckEnvironmentReviewersMatchesIneligibility(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	_, err := db.GetEngine(ctx).ID(17).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
	require.NoError(t, err)
	users := make([]*user_model.User, 0, 50)
	require.NoError(t, db.GetEngine(ctx).OrderBy("id").Find(&users))
	listed := []*actions_model.ActionEnvironmentReviewer{}
	for _, u := range users {
		listed = append(listed, &actions_model.ActionEnvironmentReviewer{UserID: u.ID})
	}
	for _, repoID := range []int64{1, 2, 3, 5, 24, 32} { // public/private, of a user and of orgs (org17 requires 2FA)
		if repoID != 1 {
			require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: repoID, Type: unit.TypeActions}))
		}
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
		require.NoError(t, repo.LoadOwner(ctx))
		check, err := CheckEnvironmentReviewers(ctx, repo, []*actions_model.ActionEnvironment{{ID: 1}}, map[int64][]*actions_model.ActionEnvironmentReviewer{1: listed})
		require.NoError(t, err)
		for _, u := range users {
			expected, err := reviewerIneligibility(ctx, repo, u)
			require.NoError(t, err)
			assert.Equal(t, expected, check.Ineligible[fmt.Sprintf("user:%d", u.ID)], "user %d on repo %d", u.ID, repoID)
		}
		if repoID != 24 { // org17 requires 2FA, which none of its members has
			assert.NotEmpty(t, check.Readers, "repo %d", repoID)
		}
		assert.Less(t, len(check.Ineligible), len(users), "someone can approve on repo %d", repoID)
		for _, r := range check.Readers {
			assert.Empty(t, check.Ineligible[fmt.Sprintf("user:%d", r.ID)], "reader %d of repo %d can approve", r.ID, repoID)
		}
	}
}
