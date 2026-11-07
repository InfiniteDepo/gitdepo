// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/queue"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reviewFixture is a blocked job of environment "prod" in repository 63 (user2's, private) that waits for a review.
type reviewFixture struct {
	job *actions_model.ActionRunJob
	run *actions_model.ActionRun
	env *actions_model.ActionEnvironment
	ctx context.Context
}

// setReviewers makes the users and teams the reviewers of the environment as it is stored, keeping its rules, as the
// site administrator. A listed user is made a read collaborator first if they have no path to the repository (only
// members can be listed): a test takes the access away to see the reviewer refused.
func setReviewers(ctx context.Context, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) error {
	stored, err := actions_model.GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
	if err != nil {
		return err
	}
	repo, err := repo_model.GetRepositoryByID(ctx, e.RepoID)
	if err != nil {
		return err
	}
	for _, id := range userIDs {
		u, err := user_model.GetUserByID(ctx, id)
		if err != nil || !u.IsIndividual() || u.ID == repo.OwnerID {
			continue // refused by the save, or the owner
		}
		if err := repo_module.AddCollaborator(ctx, repo, u, perm.AccessModeRead); err != nil {
			return err
		}
	}
	admin, err := user_model.GetUserByID(ctx, 1) // sees every reviewer
	if err != nil {
		return err
	}
	_, err = SaveEnvironment(ctx, admin, stored, userIDs, teamIDs)
	return err
}

// replaceReviewers is setReviewers without the checks of the users and teams and without the pass of the emitter.
func replaceReviewers(ctx context.Context, e *actions_model.ActionEnvironment, reviewers []actions_model.ActionEnvironmentReviewer) error {
	stored, err := actions_model.GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
	if err != nil {
		return err
	}
	return actions_model.UpdateEnvironment(ctx, stored, reviewers)
}

func newReviewFixture(t *testing.T, env *actions_model.ActionEnvironment, userIDs, teamIDs []int64) *reviewFixture {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	cfg, err := setting.NewConfigProviderFromData("[queue.actions_ready_job]\nTYPE = channel\n")
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.CfgProvider, cfg)()
	q := queue.CreateUniqueQueue(t.Context(), "actions_ready_job", func(items ...*jobUpdate) []*jobUpdate { return nil })
	require.NotNil(t, q)
	t.Cleanup(test.MockVariableValue(&jobEmitterQueue, q))

	f := &reviewFixture{ctx: audit_model.WithSystem(t.Context(), "test")}
	env.Name = "prod"
	f.env = newEnvironment(t, env)
	require.NoError(t, setReviewers(f.ctx, f.env, userIDs, teamIDs))
	f.job = gateJob(t, envWorkflow("    environment: prod\n"), "refs/heads/main")
	b, err := gateEnvironment(f.ctx, f.job)
	require.NoError(t, err)
	require.Equal(t, behaviourHoldJob, b)
	f.run, err = actions_model.GetRunByID(f.ctx, f.job.RunID)
	require.NoError(t, err)
	return f
}

func (f *reviewFixture) deployment(t *testing.T) *actions_model.ActionDeployment {
	t.Helper()
	d, err := actions_model.GetDeployment(t.Context(), f.job.ID, f.job.Attempt)
	require.NoError(t, err)
	require.NotNil(t, d)
	return d
}

func (f *reviewFixture) status(t *testing.T) actions_model.DeploymentStatus {
	return f.deployment(t).Status
}

// emit runs the emitter over the run, as its queue does, and returns the job.
func (f *reviewFixture) emit(t *testing.T) *actions_model.ActionRunJob {
	t.Helper()
	require.NoError(t, checkJobsOfRun(f.ctx, f.run.ID, 0))
	return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: f.job.ID})
}

func (f *reviewFixture) review(t *testing.T, doerID int64, approve bool, comment string) ([]*actions_model.ActionDeployment, error) {
	t.Helper()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: doerID})
	return ReviewDeployments(f.ctx, doer, f.run, []int64{f.job.ID}, approve, comment)
}

func auditActions(t *testing.T, since int64, action string) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, action).Find(&entries))
	return entries
}

// revokeActionsRead removes the collaboration of the user on repository 63 (setReviewers adds one for a listed user).
func revokeActionsRead(t *testing.T, userID int64) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM collaboration WHERE user_id = ? AND repo_id = 63", userID)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("DELETE FROM access WHERE user_id = ? AND repo_id = 63", userID)
	require.NoError(t, err)
}

func grantActionsRead(t *testing.T, userID int64) {
	t.Helper()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 63})
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: userID})
	require.NoError(t, repo_module.AddCollaborator(t.Context(), repo, u, perm.AccessModeRead))
}

func TestReviewDeployments(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()

	t.Run("the gate holds a job of an environment with reviewers, and the label of the environment waits", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		d := f.deployment(t)
		assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
		assert.Zero(t, d.ReleaseAfterUnix)
		assert.Equal(t, actions_model.StatusBlocked, f.emit(t).Status, "never given to a runner while it waits")
		// every pass looks again and holds
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
		// the abandoned-job cron leaves it alone
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET updated = 1 WHERE id = ?", f.job.ID)
		require.NoError(t, err)
		require.NoError(t, CancelAbandonedJobs(f.ctx))
		assert.Equal(t, actions_model.StatusBlocked, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: f.job.ID}).Status)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
	})

	t.Run("an approval releases the job, the audit entry has no comment", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		since := auditSince(t)
		ds, err := f.review(t, 2, true, "looks good\r\nship it")
		require.NoError(t, err)
		require.Len(t, ds, 1)
		d := f.deployment(t)
		assert.EqualValues(t, 2, d.ReviewedBy)
		assert.NotZero(t, d.ReviewedUnix)
		assert.Equal(t, "looks good\nship it", d.ReviewComment)
		job := f.emit(t)
		assert.Equal(t, actions_model.StatusWaiting, job.Status)
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))

		entries := auditActions(t, since, "repo.actions_deployment.approved")
		require.Len(t, entries, 1)
		assert.NotContains(t, entries[0].Data, "ship it")
		assert.Contains(t, entries[0].Data, `"comment_length":18`)
	})

	t.Run("a rejection needs a comment, fails the job and is recorded", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		since := auditSince(t)
		for _, comment := range []string{"", "  \n\t "} {
			_, err := f.review(t, 2, false, comment)
			require.ErrorIs(t, err, ErrReviewCommentMissing)
		}
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
		_, err := f.review(t, 2, false, "<script>alert(1)</script> not now")
		require.NoError(t, err)
		d := f.deployment(t)
		assert.Equal(t, actions_model.DeploymentRejected, d.Status)
		assert.Equal(t, "<script>alert(1)</script> not now", d.ReviewComment, "plain text as written; every page escapes it")
		job := f.emit(t)
		assert.Equal(t, actions_model.StatusFailure, job.Status)
		assert.NotZero(t, job.Stopped)
		assert.Len(t, auditActions(t, since, "repo.actions_deployment.rejected"), 1)
		// the gate keeps failing it
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourFailJob, b)
	})

	t.Run("the comment is plain text of bounded size", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		for name, comment := range map[string]string{
			"too long":       strings.Repeat("a", actions_model.MaxReviewComment+1),
			"invalid utf-8":  "a\xffb",
			"nul":            "a\x00b",
			"escape":         "a\x1b[31mb",
			"bell":           "a\x07b",
			"carriage":       "a\rb",
			"delete":         "a\x7fb",
			"too long bytes": strings.Repeat("ä", actions_model.MaxReviewComment/2+1),
		} {
			_, err := f.review(t, 2, true, comment)
			require.ErrorIs(t, err, util.ErrInvalidArgument, name)
			assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t), name)
		}
		_, err := f.review(t, 2, true, strings.Repeat("a", actions_model.MaxReviewComment-1)+"\n\t")
		require.NoError(t, err, "the longest comment, with a newline and a tab")
	})

	t.Run("only one review: the second finds the deployment no longer waiting", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
		grantActionsRead(t, 4)
		_, err := f.review(t, 2, true, "")
		require.NoError(t, err)
		_, err = f.review(t, 4, true, "")
		require.ErrorIs(t, err, ErrReviewNotWaiting)
		_, err = f.review(t, 4, false, "too late")
		require.ErrorIs(t, err, ErrReviewNotWaiting)
		assert.EqualValues(t, 2, f.deployment(t).ReviewedBy)
	})

	t.Run("the approval of one attempt does not carry to the next", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		_, err := f.review(t, 2, true, "")
		require.NoError(t, err)
		require.Equal(t, actions_model.StatusWaiting, f.emit(t).Status)
		// a rerun: the job is blocked again at its next attempt
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET status = ?, attempt = 2 WHERE id = ?", actions_model.StatusBlocked, f.job.ID)
		require.NoError(t, err)
		f.job.Attempt = 2
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		assert.Equal(t, behaviourHoldJob, b)
		d := f.deployment(t)
		assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
		assert.Zero(t, d.ReviewedBy)
		first, err := actions_model.GetDeployment(t.Context(), f.job.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, actions_model.DeploymentReleased, first.Status, "the first attempt keeps its approval")
	})

	t.Run("a new deployment is not stale against its environment, whatever the gate's clock", func(t *testing.T) {
		// the environment's update time comes from the real clock (xorm), so the deployment's must too
		timeutil.MockSet(time.Now().Add(-time.Hour))
		defer timeutil.MockUnset()
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.deployment(t).Status)
		due, err := actions_model.FindDueDeploymentRunIDs(t.Context(), timeutil.TimeStampNow(), 10)
		require.NoError(t, err)
		assert.Empty(t, due)
	})

	t.Run("the review and the wait timer run in parallel: both are needed", func(t *testing.T) {
		start := time.Now().Truncate(time.Second)
		timeutil.MockSet(start)
		defer timeutil.MockUnset()
		f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: 10}, []int64{2}, nil)
		d := f.deployment(t)
		assert.Equal(t, actions_model.DeploymentWaitingReview, d.Status)
		assert.EqualValues(t, start.Unix()+600, d.ReleaseAfterUnix, "the timer counts from the deployment")

		// the timer is due, nobody approved: held, and the timer task doesn't pick it up
		timeutil.MockSet(start.Add(time.Hour))
		due, err := actions_model.FindDueDeploymentRunIDs(t.Context(), timeutil.TimeStampNow(), 10)
		require.NoError(t, err)
		assert.Empty(t, due)
		assert.Equal(t, actions_model.StatusBlocked, f.emit(t).Status)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))

		// a second deployment: approved before the timer is due: held, then released when due
		timeutil.MockSet(start.Add(time.Minute))
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_deployment")
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET status = ? WHERE id = ?", actions_model.StatusBlocked, f.job.ID)
		require.NoError(t, err)
		b, err := gateEnvironment(f.ctx, f.job)
		require.NoError(t, err)
		require.Equal(t, behaviourHoldJob, b)
		_, err = f.review(t, 2, true, "")
		require.NoError(t, err)
		assert.Equal(t, actions_model.StatusBlocked, f.emit(t).Status, "approved, the timer is not due")
		assert.Equal(t, actions_model.DeploymentWaitingTimer, f.status(t))
		timeutil.MockSet(start.Add(time.Minute + 601*time.Second))
		due, err = actions_model.FindDueDeploymentRunIDs(t.Context(), timeutil.TimeStampNow(), 10)
		require.NoError(t, err)
		assert.Equal(t, []int64{f.run.ID}, due)
		assert.Equal(t, actions_model.StatusWaiting, f.emit(t).Status)
		assert.Equal(t, actions_model.DeploymentReleased, f.status(t))
	})

	t.Run("a review after the timer is due releases at once", func(t *testing.T) {
		start := time.Now().Truncate(time.Second)
		timeutil.MockSet(start)
		defer timeutil.MockUnset()
		f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: 1}, []int64{2}, nil)
		timeutil.MockSet(start.Add(time.Hour))
		_, err := f.review(t, 2, true, "")
		require.NoError(t, err)
		assert.Equal(t, actions_model.StatusWaiting, f.emit(t).Status)
	})

	t.Run("who may review", func(t *testing.T) {
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		for _, tc := range []struct {
			name    string
			setup   func(t *testing.T, f *reviewFixture)
			env     actions_model.ActionEnvironment
			users   []int64
			teams   []int64
			doer    int64
			allowed bool
		}{
			{
				name: "a listed user with read access", users: []int64{4}, doer: 4, allowed: true,
				setup: func(t *testing.T, f *reviewFixture) { grantActionsRead(t, 4) },
			},
			{
				name: "a listed user without access to Actions", users: []int64{4}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) { revokeActionsRead(t, 4) },
			},
			{
				name: "a user with read access who is not listed", users: []int64{2}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) { grantActionsRead(t, 4) },
			},
			{name: "a site administrator who is not listed", users: []int64{2}, doer: 1},
			{name: "a listed site administrator", users: []int64{1}, doer: 1, allowed: true},
			{
				name: "an inactive user", users: []int64{4}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) {
					grantActionsRead(t, 4)
					_, err := db.GetEngine(t.Context()).Exec("UPDATE user SET is_active = ? WHERE id = 4", false)
					require.NoError(t, err)
				},
			},
			{
				name: "a user who may not sign in", users: []int64{4}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) {
					grantActionsRead(t, 4)
					_, err := db.GetEngine(t.Context()).Exec("UPDATE user SET prohibit_login = ? WHERE id = 4", true)
					require.NoError(t, err)
				},
			},
			{name: "the one who triggered the run, self review allowed", users: []int64{2}, doer: 2, allowed: true},
			{
				name: "the one who triggered the run, self review prevented", users: []int64{2}, doer: 2,
				env: actions_model.ActionEnvironment{PreventSelfReview: true},
			},
			{
				name: "another reviewer, self review prevented", users: []int64{2, 4}, doer: 4, allowed: true,
				env:   actions_model.ActionEnvironment{PreventSelfReview: true},
				setup: func(t *testing.T, f *reviewFixture) { grantActionsRead(t, 4) },
			},
			{
				name: "a member of a listed team", teams: []int64{2}, doer: 4, allowed: true,
				setup: func(t *testing.T, f *reviewFixture) { teamReadsActions(t, org3) },
			},
			{
				name: "a member of a team that is not listed", teams: []int64{1}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) { teamReadsActions(t, org3) },
			},
			{
				name: "a user removed from the listed team after the job started", teams: []int64{2}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) {
					teamReadsActions(t, org3)
					_, err := db.GetEngine(t.Context()).Exec("DELETE FROM team_user WHERE team_id = 2 AND uid = 4")
					require.NoError(t, err)
				},
			},
			{
				name: "a team member whose team can't read Actions", teams: []int64{2}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) {
					teamReadsActions(t, org3)
					_, err := db.GetEngine(t.Context()).Exec("DELETE FROM team_unit WHERE team_id = 2 AND type = 10")
					require.NoError(t, err)
				},
			},
			{
				name: "a member of a listed team of an organization that requires two-factor", teams: []int64{2}, doer: 4,
				setup: func(t *testing.T, f *reviewFixture) {
					teamReadsActions(t, org3)
					_, err := db.GetEngine(t.Context()).Exec("UPDATE user SET require_two_factor = ? WHERE id = 3", true)
					require.NoError(t, err)
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := tc.env
				f := newReviewFixture(t, &env, []int64{2}, nil) // replaced below, the job needs one to wait
				if len(tc.teams) > 0 {
					teamReadsActions(t, org3) // the repository belongs to the organization the teams belong to
				}
				require.NoError(t, setReviewers(f.ctx, f.env, tc.users, tc.teams))
				if tc.setup != nil {
					tc.setup(t, f)
				}
				_, err := f.review(t, tc.doer, true, "")
				if tc.allowed {
					require.NoError(t, err)
					assert.Equal(t, tc.doer, f.deployment(t).ReviewedBy)
				} else {
					require.ErrorIs(t, err, ErrReviewForbidden)
					assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
				}
			})
		}
	})

	t.Run("the Actions user and the identity of an access token never review", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		for name, doer := range map[string]*user_model.User{
			"actions user": user_model.NewActionsUser(),
			"token":        user_model.NewAccessTokenBot(&auth_model.AccessToken{ID: 5, OwnerID: 63}),
			"nobody":       nil,
		} {
			_, err := ReviewDeployments(f.ctx, doer, f.run, []int64{f.job.ID}, true, "")
			require.ErrorIs(t, err, ErrReviewForbidden, name)
		}
		// not even when a listed user's ID is the one the identity would carry
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))
	})

	t.Run("jobs named in the request", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		_, err := ReviewDeployments(f.ctx, doer, f.run, []int64{f.job.ID + 1000}, true, "")
		require.ErrorIs(t, err, util.ErrInvalidArgument, "not a job of the run")
		// a job of the run without a deployment
		_, err = ReviewDeployments(f.ctx, doer, f.run, []int64{601}, true, "")
		require.Error(t, err)
		ds, err := ReviewDeployments(f.ctx, doer, f.run, []int64{f.job.ID}, true, "")
		require.NoError(t, err)
		assert.Len(t, ds, 1)
		_, err = ReviewDeployments(f.ctx, doer, f.run, []int64{f.job.ID}, true, "")
		require.ErrorIs(t, err, ErrReviewNotWaiting, "none left")
	})

	t.Run("a run with another environment's job: the doer reviews only what they may", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		other := newEnvironment(t, &actions_model.ActionEnvironment{Name: "other"})
		require.NoError(t, setReviewers(f.ctx, other, []int64{4}, nil))
		grantActionsRead(t, 4)
		// a second blocked job of the same run, gated by "other" (user 4 reviews it, not "prod")
		_, err := db.GetEngine(t.Context()).Exec("INSERT INTO action_deployment (repo_id, environment_id, run_id, job_id, attempt, status, trigger_user_id, created) VALUES (63, ?, ?, 601, 1, ?, 2, ?)",
			other.ID, f.run.ID, actions_model.DeploymentWaitingReview, timeutil.TimeStampNow())
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET status = ?, attempt = 1, run_id = ? WHERE id = 601", actions_model.StatusBlocked, f.run.ID)
		require.NoError(t, err)
		doer4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		ds, err := ReviewDeployments(f.ctx, doer4, f.run, []int64{601}, true, "")
		require.NoError(t, err)
		require.Len(t, ds, 1)
		assert.EqualValues(t, 601, ds[0].JobID)
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t), "prod stays")
		_, err = ReviewDeployments(f.ctx, doer4, f.run, []int64{f.job.ID}, true, "")
		require.ErrorIs(t, err, ErrReviewForbidden)
	})
}

// teamReadsActions makes the repository the organization's and gives its team 2 (members 2 and 4) Actions read access.
func teamReadsActions(t *testing.T, org *user_model.User) {
	t.Helper()
	e := db.GetEngine(t.Context())
	_, err := e.Exec("UPDATE repository SET owner_id = ?, owner_name = ? WHERE id = 63", org.ID, org.Name)
	require.NoError(t, err)
	_, err = e.Exec("DELETE FROM team_repo WHERE repo_id = 63")
	require.NoError(t, err)
	_, err = e.Exec("INSERT INTO team_repo (org_id, team_id, repo_id) VALUES (?, 2, 63)", org.ID)
	require.NoError(t, err)
	_, err = e.Exec("DELETE FROM team_unit WHERE team_id = 2 AND type = 10")
	require.NoError(t, err)
	_, err = e.Exec("INSERT INTO team_unit (org_id, team_id, type, access_mode) VALUES (?, 2, 10, 1)", org.ID)
	require.NoError(t, err)
	_, err = org_model.GetTeamByID(t.Context(), 2)
	require.NoError(t, err)
}

func TestExpireDeploymentReviews(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	timeout := 48 * time.Hour
	defer test.MockVariableValue(&setting.Actions.DeploymentApprovalTimeout, timeout)()

	backdate := func(t *testing.T, f *reviewFixture, age time.Duration) {
		t.Helper()
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET created = ? WHERE job_id = ?", time.Now().Add(-age).Unix(), f.job.ID)
		require.NoError(t, err)
	}

	t.Run("an old deployment expires, the job fails, the entry is written", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		backdate(t, f, timeout-time.Minute)
		since := auditSince(t)
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t), "not old enough")
		assert.Empty(t, auditActions(t, since, "repo.actions_deployment.expired"))

		backdate(t, f, timeout+time.Minute)
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Equal(t, actions_model.DeploymentExpired, f.status(t))
		job := f.emit(t)
		assert.Equal(t, actions_model.StatusFailure, job.Status)
		assert.NotZero(t, job.Stopped)
		entries := auditActions(t, since, "repo.actions_deployment.expired")
		require.Len(t, entries, 1)
		assert.Equal(t, audit_model.ResultFailure, entries[0].Result)

		// nobody can review it any more, and a second run of the task does nothing
		_, err := f.review(t, 2, true, "")
		require.ErrorIs(t, err, ErrReviewNotWaiting)
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Len(t, auditActions(t, since, "repo.actions_deployment.expired"), 1)
	})

	t.Run("it wins over a wait timer that still runs", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: actions_model.MaxWaitTimerMinutes}, []int64{2}, nil)
		backdate(t, f, timeout+time.Hour)
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Equal(t, actions_model.DeploymentExpired, f.status(t))
		assert.Equal(t, actions_model.StatusFailure, f.emit(t).Status)
	})

	t.Run("an approved deployment waiting for its timer does not expire", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{WaitTimerMinutes: actions_model.MaxWaitTimerMinutes}, []int64{2}, nil)
		_, err := f.review(t, 2, true, "")
		require.NoError(t, err)
		backdate(t, f, timeout+time.Hour)
		require.NoError(t, ExpireDeploymentReviews(f.ctx))
		assert.Equal(t, actions_model.DeploymentWaitingTimer, f.status(t))
	})

	t.Run("a deployment decided meanwhile stays decided", func(t *testing.T) {
		f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2}, nil)
		stale := f.deployment(t)
		_, err := f.review(t, 2, false, "no")
		require.NoError(t, err)
		backdate(t, f, timeout+time.Hour)
		old := []*actions_model.ActionDeployment{stale}
		since := auditSince(t)
		require.NoError(t, expireDeployment(f.ctx, old[0]), "a stale read of the deployment")
		assert.Equal(t, actions_model.DeploymentRejected, f.status(t))
		assert.Empty(t, auditActions(t, since, "repo.actions_deployment.expired"))
	})
}

func TestEnvironmentReviewers(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	env := newEnvironment(t, &actions_model.ActionEnvironment{Name: "prod"})

	t.Run("limits and shapes", func(t *testing.T) {
		require.ErrorIs(t, setReviewers(ctx, env, []int64{1, 2, 4, 5, 8, 10, 11}, nil), util.ErrInvalidArgument, "seven")
		require.NoError(t, setReviewers(ctx, env, []int64{1, 2, 4, 5, 8, 10}, nil), "six")
		require.ErrorIs(t, setReviewers(ctx, env, []int64{2, 2}, nil), util.ErrInvalidArgument, "twice")
		require.ErrorIs(t, setReviewers(ctx, env, []int64{0}, nil), util.ErrInvalidArgument)
		require.ErrorIs(t, setReviewers(ctx, env, []int64{-2}, nil), util.ErrInvalidArgument, "the Actions user")
		require.ErrorIs(t, setReviewers(ctx, env, []int64{3}, nil), util.ErrInvalidArgument, "an organization")
		require.ErrorIs(t, setReviewers(ctx, env, []int64{99999}, nil), util.ErrInvalidArgument)
		rs, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
		require.NoError(t, err)
		assert.Len(t, rs, 6, "a refused list changes nothing")
	})

	t.Run("a team must belong to the organization that owns the repository", func(t *testing.T) {
		// repository 63 is user2's: no team belongs to its owner
		require.ErrorIs(t, setReviewers(ctx, env, nil, []int64{2}), util.ErrInvalidArgument)
		teamReadsActions(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		require.NoError(t, setReviewers(ctx, env, []int64{2}, []int64{2}))
		require.ErrorIs(t, setReviewers(ctx, env, nil, []int64{3}), util.ErrInvalidArgument, "team 3 is org 6's")
		require.ErrorIs(t, setReviewers(ctx, env, nil, []int64{999}), util.ErrInvalidArgument)
	})

	t.Run("a change is audited once, an equal list is not", func(t *testing.T) {
		since := auditSince(t)
		require.NoError(t, setReviewers(ctx, env, []int64{4}, nil))
		require.NoError(t, setReviewers(ctx, env, []int64{4}, nil))
		assert.Len(t, auditActions(t, since, "repo.actions_env.updated"), 1)
	})

	t.Run("deleting a team or the environment removes the rows", func(t *testing.T) {
		count := func() int64 {
			n, err := db.GetEngine(ctx).Count(new(actions_model.ActionEnvironmentReviewer))
			require.NoError(t, err)
			return n
		}
		teamReadsActions(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		require.NoError(t, setReviewers(ctx, env, []int64{4, 5}, []int64{2}))
		assert.EqualValues(t, 3, count())
		team, err := org_model.GetTeamByID(ctx, 2)
		require.NoError(t, err)
		require.NoError(t, models.DeleteTeam(ctx, team))
		assert.EqualValues(t, 2, count())
		require.NoError(t, DeleteEnvironment(ctx, env))
		assert.EqualValues(t, 0, count())
	})
}

// A former collaborator still listed as a reviewer can read a public repository's Actions, but without a membership
// path they can't approve, aren't mailed and aren't offered as a reviewer.
func TestReviewDeploymentsFormerMember(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET is_private = ? WHERE id = 63", false)
	require.NoError(t, err)
	revokeActionsRead(t, 4)
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 63})
	require.NoError(t, repo.LoadOwner(t.Context()))
	why, err := reviewerIneligibility(t.Context(), repo, user4)
	require.NoError(t, err)
	assert.Equal(t, ReviewerOutsider, why, "reads the public repository, but is no member")

	_, err = f.review(t, 4, true, "")
	require.ErrorIs(t, err, ErrReviewForbidden)
	assert.Equal(t, actions_model.DeploymentWaitingReview, f.status(t))

	ids, check, err := DeploymentApprovers(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), f.run, f.env, f.deployment(t))
	require.NoError(t, err)
	assert.Equal(t, []int64{2}, ids, "the review mail goes to user2 only")
	assert.Equal(t, ReviewerOutsider, check.Ineligible["user:4"])
	for _, u := range check.Readers {
		assert.NotEqual(t, int64(4), u.ID, "not offered in the picker")
	}
}

// Who may review is decided before whether the deployment still waits: a user who may not is refused whatever its
// state, so they learn nothing and start no pass of the gate.
func TestReviewDeploymentsForbiddenBeforeNotWaiting(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestGetSecretsOfJob")()
	f := newReviewFixture(t, &actions_model.ActionEnvironment{}, []int64{2, 4}, nil)
	_, err := f.review(t, 2, false, "no")
	require.NoError(t, err)
	grantActionsRead(t, 5) // reads the repository's Actions, isn't listed
	_, err = f.review(t, 5, true, "")
	require.ErrorIs(t, err, ErrReviewForbidden)
	_, err = f.review(t, 4, true, "")
	require.ErrorIs(t, err, ErrReviewNotWaiting, "a reviewer is told it doesn't wait")
}
