// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/services/mailer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sentMails records who the deployment mails go to, instead of the mailer.
type sentMails struct {
	review  [][]int64 // the recipients of each review mail
	decided []int64   // the recipient of each rejected or expired mail
}

func mockDeploymentMails(t *testing.T) *sentMails {
	t.Helper()
	sent := &sentMails{}
	t.Cleanup(test.MockVariableValue(&sendReviewMail, func(_ context.Context, users []*user_model.User, m *mailer.DeploymentMail) error {
		var ids []int64
		for _, u := range users {
			ids = append(ids, u.ID)
		}
		sent.review = append(sent.review, ids)
		return nil
	}))
	t.Cleanup(test.MockVariableValue(&sendDecidedMail, func(_ context.Context, u *user_model.User, m *mailer.DeploymentMail) error {
		sent.decided = append(sent.decided, u.ID)
		return nil
	}))
	return sent
}

// The reviewers are mailed once per deployment, when it starts to wait, and only after the change committed; the user
// who started the attempt is mailed when it is rejected or expires.
func TestDeploymentMails(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()

	t.Run("the reviewers who may approve are mailed once", func(t *testing.T) {
		sent := mockDeploymentMails(t)
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
		assert.Equal(t, [][]int64{{4}}, sent.review)
		// another pass of the gate, in or out of the emitter's transaction, sends nothing
		_, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		f.emit(t)
		assert.Len(t, sent.review, 1)
		assert.Empty(t, sent.decided)
	})

	t.Run("a rejection mails the user who started the attempt", func(t *testing.T) {
		sent := mockDeploymentMails(t)
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
		_, err := f.review(t, 4, false, "not <b>now</b>")
		require.NoError(t, err)
		assert.Equal(t, []int64{2}, sent.decided)
		f.emit(t) // the gate fails the job: no second mail
		assert.Equal(t, []int64{2}, sent.decided)
	})

	t.Run("an approval mails nobody", func(t *testing.T) {
		sent := mockDeploymentMails(t)
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
		_, err := f.review(t, 4, true, "")
		require.NoError(t, err)
		f.emit(t)
		assert.Empty(t, sent.decided)
	})

	t.Run("an expiry mails the user who started the attempt, by the task or the gate", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Actions.DeploymentApprovalTimeout, time.Hour)()
		for _, byGate := range []bool{false, true} {
			sent := mockDeploymentMails(t)
			f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET created = ? WHERE job_id = ?", time.Now().Add(-2*time.Hour).Unix(), f.job.ID)
			require.NoError(t, err)
			if byGate {
				f.emit(t)
			} else {
				require.NoError(t, ExpireDeploymentReviews(f.ctx))
			}
			assert.Equal(t, actions_model.DeploymentExpired, f.status(t))
			assert.Equal(t, []int64{2}, sent.decided, "by the gate: %v", byGate)
			f.emit(t)
			require.NoError(t, ExpireDeploymentReviews(f.ctx))
			assert.Equal(t, []int64{2}, sent.decided, "once, by the gate: %v", byGate)
		}
	})

	t.Run("the self-review rule and access decide who is mailed", func(t *testing.T) {
		sent := mockDeploymentMails(t)
		newReviewFixture(t, &actions_model.ActionEnvironment{PreventSelfReview: true}, []int64{2, 4}, nil)
		assert.Equal(t, [][]int64{{4}}, sent.review, "the trigger user is not mailed")

		sent = mockDeploymentMails(t)
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment WHERE job_id = ?", f.job.ID)
		require.NoError(t, err)
		revokeActionsRead(t, 4)
		_, err = gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Len(t, sent.review, 1, "a reviewer who can't read the repository's Actions is not mailed")
	})

	t.Run("nothing is sent for a change that was rolled back, and a retry sends one", func(t *testing.T) {
		// the emitter's queue has no audit actor, so the gate wraps the transaction's context: the mail must still
		// wait for the commit
		for name, ctx := range map[string]context.Context{"with an actor": audit_model.WithSystem(t.Context(), "test"), "without an actor": t.Context()} {
			sent := mockDeploymentMails(t)
			f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
			_, err := db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment WHERE job_id = ?", f.job.ID)
			require.NoError(t, err)
			rollback := errors.New("rollback")
			require.ErrorIs(t, db.WithTx(ctx, func(ctx context.Context) error {
				_, err := gateEnvironment(ctx, f.job)
				require.NoError(t, err)
				assert.Len(t, sent.review, 1, "%s: nothing inside the transaction", name)
				return rollback
			}), rollback)
			assert.Len(t, sent.review, 1, "%s: nothing for the rolled-back change", name)
			require.NoError(t, db.WithTx(ctx, func(ctx context.Context) error {
				_, err := gateEnvironment(ctx, f.job)
				return err
			}))
			assert.Len(t, sent.review, 2, "%s: the retry sends one", name)
		}
	})

	t.Run("an approval revoked at release mails the reviewers again", func(t *testing.T) {
		sent := mockDeploymentMails(t)
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
		assert.Equal(t, [][]int64{{2, 4}}, sent.review)
		_, err := f.review(t, 4, true, "")
		require.NoError(t, err)
		revokeActionsRead(t, 4)
		f.emit(t)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
		assert.Equal(t, [][]int64{{2, 4}, {2}}, sent.review)
	})

	t.Run("the jobs of a run attempt that deploy to one environment share a mail", func(t *testing.T) {
		sent := mockDeploymentMails(t)
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)
		first := f.deployment(t)
		other := &actions_model.ActionDeployment{
			RepoID: first.RepoID, RunID: first.RunID, JobID: first.JobID + 1000, Attempt: first.Attempt,
			EnvironmentID: first.EnvironmentID, Status: actions_model.DeploymentWaitingReview, TriggerUserID: first.TriggerUserID,
		}
		require.NoError(t, db.Insert(t.Context(), other))
		mailDeploymentReviewers(f.ctx, f.run, "deploy", f.env, other)
		assert.Len(t, sent.review, 1, "the first job's mail covers it")
		// another server's pass that also finds them waiting: the mail is claimed already
		mailDeploymentReviewers(f.ctx, f.run, "deploy", f.env, first)
		mailDeploymentReviewers(f.ctx, f.run, "deploy", f.env, other)
		assert.Len(t, sent.review, 1, "claimed once")

		other.Attempt++ // a rerun of that job alone
		_, err := db.GetEngine(t.Context()).ID(other.ID).Cols("attempt").Update(other)
		require.NoError(t, err)
		mailDeploymentReviewers(f.ctx, f.run, "deploy", f.env, other)
		assert.Len(t, sent.review, 2)

		other.Attempt--
		_, err = db.GetEngine(t.Context()).ID(other.ID).Cols("attempt").Update(other)
		require.NoError(t, err)
		_, err = f.review(t, 4, false, "no")
		require.NoError(t, err)
		other.Status = actions_model.DeploymentRejected
		_, err = db.GetEngine(t.Context()).ID(other.ID).Cols("status").Update(other)
		require.NoError(t, err)
		mailDeploymentDecided(f.ctx, f.env, other)
		assert.Equal(t, []int64{2}, sent.decided, "one rejection mail for both")
		mailDeploymentDecided(f.ctx, f.env, f.deployment(t))
		assert.Equal(t, []int64{2}, sent.decided, "claimed once")
	})
}

// In an organization that requires two-factor authentication, deployment approval requires it of everyone, site
// administrators included: the review, the check at release, the reviewer check of the settings pages and the
// last-approver warning.
func TestDeploymentApprovalTwoFactorForEveryone(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	setup := func(t *testing.T) *reviewFixture {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		teamReadsActions(t, org3)
		require.NoError(t, setReviewers(f.ctx, f.env, []int64{1}, nil))
		_, err := db.GetEngine(t.Context()).Exec("UPDATE user SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		return f
	}
	check := func(t *testing.T, f *reviewFixture) *EnvironmentReviewerCheck {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 63})
		env, err := actions_model.GetRepoEnvironmentByID(t.Context(), repo.ID, f.env.ID)
		require.NoError(t, err)
		reviewers, err := actions_model.FindEnvironmentReviewers(t.Context(), env.ID)
		require.NoError(t, err)
		c, err := CheckEnvironmentReviewers(t.Context(), repo, admin, []*actions_model.ActionEnvironment{env}, map[int64][]*actions_model.ActionEnvironmentReviewer{env.ID: reviewers})
		require.NoError(t, err)
		return c
	}

	t.Run("a site administrator without two-factor is refused", func(t *testing.T) {
		f := setup(t)
		_, err := f.review(t, 1, true, "")
		require.ErrorIs(t, err, ErrReviewForbidden)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))

		c := check(t, f)
		assert.Equal(t, ReviewerTwoFactor, c.Ineligible["user:1"])
		assert.True(t, c.NoReviewer[f.env.ID])
		assert.Empty(t, c.Approvers[f.env.ID])
		assert.False(t, slices.ContainsFunc(c.Readers, func(u *user_model.User) bool { return u.ID == 1 }), "not offered in the picker")
		found, err := FindEnvironmentLastApprovers(t.Context(), []int64{1})
		require.NoError(t, err)
		assert.Empty(t, found, "can't approve, so leaving changes nothing")
	})

	t.Run("with two-factor set up they may, and losing it revokes the approval at release", func(t *testing.T) {
		f := setup(t)
		require.NoError(t, db.Insert(t.Context(), &auth_model.TwoFactor{UID: 1}))
		c := check(t, f)
		assert.Empty(t, c.Ineligible["user:1"])
		assert.Equal(t, []int64{1}, c.Approvers[f.env.ID])
		found, err := FindEnvironmentLastApprovers(t.Context(), []int64{1})
		require.NoError(t, err)
		require.Len(t, found, 1)
		assert.Equal(t, f.env.ID, found[0].Env.ID)

		_, err = f.review(t, 1, true, "")
		require.NoError(t, err)
		assert.EqualValues(t, 1, f.deployment(t).ReviewedBy)
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM two_factor WHERE uid = 1")
		require.NoError(t, err)
		f.emit(t)
		d := f.deployment(t)
		assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status, "the approval is withdrawn at release")
		assert.Zero(t, d.ReviewedBy)
	})
}

// The last-approver check names the environments where the leaving users are the only ones who can approve.
func TestFindEnvironmentLastApprovers(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{4}, nil)

	found, err := FindEnvironmentLastApprovers(t.Context(), []int64{4})
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.EqualValues(t, 4, found[0].UserID)
	assert.Equal(t, f.env.ID, found[0].Env.ID)
	assert.EqualValues(t, 63, found[0].Repo.ID)

	require.NoError(t, setReviewers(f.ctx, f.env, []int64{2, 4}, nil))
	found, err = FindEnvironmentLastApprovers(t.Context(), []int64{4})
	require.NoError(t, err)
	assert.Empty(t, found, "user2 can still approve")
	found, err = FindEnvironmentLastApprovers(t.Context(), []int64{2, 4})
	require.NoError(t, err)
	assert.Len(t, found, 2, "both leave: one warning for each")

	revokeActionsRead(t, 4)
	found, err = FindEnvironmentLastApprovers(t.Context(), []int64{2})
	require.NoError(t, err)
	assert.Len(t, found, 1, "user4 can't read Actions any more")

	_, err = db.GetEngine(t.Context()).Exec("UPDATE action_environment SET reviews_required = ? WHERE id = ?", false, f.env.ID)
	require.NoError(t, err)
	found, err = FindEnvironmentLastApprovers(t.Context(), []int64{2})
	require.NoError(t, err)
	assert.Empty(t, found, "an environment that requires no review")
}

// "Waiting for a reviewer" names only the listed users who can approve: not one who can't sign in, nor the trigger
// user the self-review rule bars.
func TestRunReviewersNames(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{PreventSelfReview: true}, []int64{2, 4, 5}, nil)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_active = ? WHERE id = 5", false)
	require.NoError(t, err)
	reviewers, err := actions_model.FindEnvironmentReviewers(t.Context(), f.env.ID)
	require.NoError(t, err)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	r, err := LoadRunReviewers(t.Context(), owner, f.run, []*actions_model.ActionEnvironment{f.env}, map[int64][]*actions_model.ActionEnvironmentReviewer{f.env.ID: reviewers})
	require.NoError(t, err)
	assert.Equal(t, []string{"user4"}, r.Names(f.env, f.deployment(t)))
}
