// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeploymentURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://example.com/app": "https://example.com/app",
		"http://example.com":      "http://example.com",
		"javascript:alert(1)":     "",
		"data:text/html,x":        "",
		"ftp://example.com":       "",
		"//example.com":           "",
		"https:///nohost":         "",
		"/relative":               "",
		"":                        "",
		"https://exa mple.com":    "",
		"https://example.com/" + strings.Repeat("a", 1010): "",
	} {
		assert.Equal(t, want, DeploymentURL(raw), raw)
	}
	assert.Len(t, DeploymentURL("https://example.com/"+strings.Repeat("a", 1000)), 1020)
}

func TestDeploymentStates(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	now := timeutil.TimeStampNow()
	// jobs 192 and 193 are blocked; 194 is not
	_, err := db.GetEngine(ctx).Exec("UPDATE action_run_job SET status = ? WHERE id IN (192, 193)", StatusBlocked)
	require.NoError(t, err)
	insert := func(runID, jobID, attempt int64, status DeploymentStatus, after timeutil.TimeStamp) *ActionDeployment {
		d := &ActionDeployment{RepoID: 4, RunID: runID, JobID: jobID, Attempt: attempt, Status: status, ReleaseAfterUnix: after}
		require.NoError(t, db.Insert(ctx, d))
		return d
	}
	due := insert(791, 192, 3, DeploymentWaitingTimer, now-10)
	insert(792, 193, 1, DeploymentWaitingTimer, now+3600)
	insert(793, 194, 1, DeploymentWaitingTimer, now-10) // its job isn't blocked any more
	insert(793, 195, 1, DeploymentReleased, now-10)
	insert(791, 192, 2, DeploymentWaitingTimer, now-10) // an earlier attempt of a blocked job

	got, err := GetDeployment(ctx, 192, 3)
	require.NoError(t, err)
	assert.Equal(t, due.ID, got.ID)
	got, err = GetDeployment(ctx, 192, 4)
	require.NoError(t, err)
	assert.Nil(t, got)
	require.Error(t, db.Insert(ctx, &ActionDeployment{RepoID: 4, JobID: 192, Attempt: 3}), "one deployment per job attempt")

	runs, err := FindDueDeploymentRunIDs(ctx, now, 10)
	require.NoError(t, err)
	assert.Equal(t, []int64{791}, runs, "the run of a blocked job whose timer ended")
	runs, err = FindDueDeploymentRunIDs(ctx, now+7200, 10)
	require.NoError(t, err)
	assert.ElementsMatch(t, []int64{791, 792}, runs)
	runs, err = FindDueDeploymentRunIDs(ctx, now+7200, 1)
	require.NoError(t, err)
	assert.Len(t, runs, 1, "bounded")

	// a status moves once: the second server finds the first one's change
	due.Status = DeploymentReleased
	moved, err := SetDeploymentStatus(ctx, due, DeploymentWaitingTimer)
	require.NoError(t, err)
	assert.True(t, moved)
	moved, err = SetDeploymentStatus(ctx, due, DeploymentWaitingTimer)
	require.NoError(t, err)
	assert.False(t, moved)
	got, err = GetDeployment(ctx, 192, 3)
	require.NoError(t, err)
	assert.Equal(t, DeploymentReleased, got.Status)
	moved, err = SetDeploymentStatus(ctx, &ActionDeployment{ID: due.ID, Status: DeploymentRefused, Reason: DeploymentReasonRefNotAllowed}, DeploymentReleased)
	require.NoError(t, err)
	assert.True(t, moved)
	got, err = GetDeployment(ctx, 192, 3)
	require.NoError(t, err)
	assert.Equal(t, DeploymentReasonRefNotAllowed, got.Reason)

	require.NoError(t, CancelOpenDeployments(ctx, 193))
	got, err = GetDeployment(ctx, 193, 1)
	require.NoError(t, err)
	assert.Equal(t, DeploymentCancelled, got.Status)
	got, err = GetDeployment(ctx, 195, 1)
	require.NoError(t, err)
	assert.Equal(t, DeploymentReleased, got.Status, "other jobs and finished deployments stay")
	got, err = GetDeployment(ctx, 194, 1)
	require.NoError(t, err)
	assert.Equal(t, DeploymentWaitingTimer, got.Status)
}

func TestDeploymentReviewStates(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	now := timeutil.TimeStampNow()
	_, err := db.GetEngine(ctx).Exec("UPDATE action_run_job SET status = ? WHERE id IN (192, 193)", StatusBlocked)
	require.NoError(t, err)
	insert := func(runID, jobID int64, status DeploymentStatus) *ActionDeployment {
		d := &ActionDeployment{RepoID: 4, RunID: runID, JobID: jobID, Attempt: 3, Status: status}
		if jobID == 193 {
			d.Attempt = 1
		}
		require.NoError(t, db.Insert(ctx, d))
		return d
	}
	waiting := insert(791, 192, DeploymentWaitingReview)
	other := insert(792, 193, DeploymentWaitingReview)
	insert(791, 194, DeploymentWaitingReview) // its job isn't blocked: not reviewable

	ds, err := FindReviewableDeployments(ctx, 791, now-1000)
	require.NoError(t, err)
	require.Len(t, ds, 1)
	assert.Equal(t, waiting.ID, ds[0].ID)
	ds, err = FindRunDeployments(ctx, 791)
	require.NoError(t, err)
	assert.Len(t, ds, 2, "every deployment of the run")

	// only a waiting deployment takes a review, and only once
	waiting.Status, waiting.ReviewedBy, waiting.ReviewedUnix, waiting.ReviewComment = DeploymentWaitingTimer, 2, now, "ok"
	moved, err := ReviewDeployment(ctx, waiting, now-1000)
	require.NoError(t, err)
	assert.True(t, moved)
	waiting.Status, waiting.ReviewedBy = DeploymentRejected, 3
	moved, err = ReviewDeployment(ctx, waiting, now-1000)
	require.NoError(t, err)
	assert.False(t, moved, "no longer waiting for a review")
	got, err := GetDeployment(ctx, 192, 3)
	require.NoError(t, err)
	assert.Equal(t, DeploymentWaitingTimer, got.Status)
	assert.EqualValues(t, 2, got.ReviewedBy)
	assert.Equal(t, "ok", got.ReviewComment)

	// a review after the cutoff is refused
	late := insert(791, 195, DeploymentWaitingReview)
	late.Status = DeploymentWaitingTimer
	moved, err = ReviewDeployment(ctx, late, now+1000)
	require.NoError(t, err)
	assert.False(t, moved, "too late")

	// expiry: the oldest first, bounded, only deployments waiting for a review
	_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET created = ? WHERE id = ?", now-100, other.ID)
	require.NoError(t, err)
	expired, err := FindExpiredReviews(ctx, now-50, 10)
	require.NoError(t, err)
	require.Len(t, expired, 1)
	assert.Equal(t, other.ID, expired[0].ID)
	expired, err = FindExpiredReviews(ctx, now+1000, 1)
	require.NoError(t, err)
	assert.Len(t, expired, 1, "bounded")

	// a cancelled run closes a deployment that waits for a review too
	require.NoError(t, CancelOpenDeployments(ctx, 193))
	got, err = GetDeployment(ctx, 193, 1)
	require.NoError(t, err)
	assert.Equal(t, DeploymentCancelled, got.Status)
	unpicked, err := FindUnpickedEnvironmentJobs(ctx, 4, 0)
	require.NoError(t, err)
	assert.Empty(t, unpicked)
}

// A run whose pass failed goes to the back of the due list, so runs that always fail can't starve the others.
func TestDueDeploymentsRotate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	now := timeutil.TimeStampNow()
	_, err := db.GetEngine(ctx).Exec("UPDATE action_run_job SET status = ? WHERE id IN (192, 193)", StatusBlocked)
	require.NoError(t, err)
	for _, d := range []*ActionDeployment{
		{RepoID: 4, RunID: 791, JobID: 192, Attempt: 3, Status: DeploymentWaitingTimer, ReleaseAfterUnix: now - 100},
		{RepoID: 4, RunID: 792, JobID: 193, Attempt: 1, Status: DeploymentWaitingTimer, ReleaseAfterUnix: now - 50},
	} {
		require.NoError(t, db.Insert(ctx, d))
	}
	_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET updated = ? WHERE run_id = 791", now-1000)
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET updated = ? WHERE run_id = 792", now-500)
	require.NoError(t, err)
	runs, err := FindDueDeploymentRunIDs(ctx, now, 1)
	require.NoError(t, err)
	assert.Equal(t, []int64{791}, runs)
	require.NoError(t, TouchDueDeployments(ctx, 791, now))
	runs, err = FindDueDeploymentRunIDs(ctx, now, 1)
	require.NoError(t, err)
	assert.Equal(t, []int64{792}, runs, "the failed run is behind the other")
}

// Secrets and variables of an environment that is gone are refused, and leave no row.
func TestEnvironmentRowLock(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(db.DefaultContext, "test")
	env := &ActionEnvironment{RepoID: 1, Name: "locked"}
	require.NoError(t, CreateEnvironment(ctx, env, nil))
	require.NoError(t, db.WithTx(ctx, func(ctx context.Context) error { return LockEnvironment(ctx, 1, env.ID) }))
	require.ErrorIs(t, LockEnvironment(ctx, 1, env.ID+1000), ErrEnvironmentNotFound)
	require.ErrorIs(t, LockEnvironment(ctx, 2, env.ID), ErrEnvironmentNotFound, "another repository's environment")

	require.NoError(t, DeleteEnvironment(ctx, env, func(context.Context) error { return nil }))
	_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 1, env.ID, "late", "value")
	require.ErrorIs(t, err, util.ErrNotExist)
	_, err = InsertEnvironmentVariable(ctx, 1, env.ID, "late", "value")
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	unittest.AssertNotExistsBean(t, &secret_model.Secret{EnvironmentID: env.ID})
	unittest.AssertNotExistsBean(t, &ActionVariable{EnvironmentID: env.ID})
}

// A deployment that waits under rules changed after it last did is due, so a change of rules whose own pass of the gate
// failed is decided by the next tick; once that pass is queued, or while the environment doesn't change, it isn't.
func TestStaleDeploymentsAreDue(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	now := timeutil.TimeStampNow()
	_, err := db.GetEngine(ctx).Exec("UPDATE action_run_job SET status = ? WHERE id IN (192, 193)", StatusBlocked)
	require.NoError(t, err)
	env := &ActionEnvironment{RepoID: 4, Name: "prod"}
	require.NoError(t, CreateEnvironment(ctx, env, nil))
	review := &ActionDeployment{RepoID: 4, EnvironmentID: env.ID, RunID: 791, JobID: 192, Attempt: 3, Status: DeploymentWaitingReview}
	timer := &ActionDeployment{RepoID: 4, EnvironmentID: env.ID, RunID: 792, JobID: 193, Attempt: 1, Status: DeploymentWaitingTimer, ReleaseAfterUnix: now + 3600}
	require.NoError(t, db.Insert(ctx, review))
	require.NoError(t, db.Insert(ctx, timer))
	setTimes := func(envUpdated, deploymentsUpdated timeutil.TimeStamp) {
		_, err := db.GetEngine(ctx).Exec("UPDATE action_environment SET updated = ? WHERE id = ?", envUpdated, env.ID)
		require.NoError(t, err)
		_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET updated = ? WHERE environment_id = ?", deploymentsUpdated, env.ID)
		require.NoError(t, err)
	}
	due := func() []int64 {
		runs, err := FindDueDeploymentRunIDs(ctx, now, 10)
		require.NoError(t, err)
		return runs
	}

	setTimes(now-100, now-50) // the environment didn't change since the deployments did
	assert.Empty(t, due())
	setTimes(now-50, now-50) // the same second: not after
	assert.Empty(t, due())

	setTimes(now-10, now-50) // the rules changed after the deployments
	assert.ElementsMatch(t, []int64{791, 792}, due())
	// a pass that failed to queue keeps the change visible (only the time it was looked at moves)
	require.NoError(t, TouchDueDeployments(ctx, 792, now))
	assert.ElementsMatch(t, []int64{791, 792}, due())
	// a queued pass marks them seen
	require.NoError(t, TouchStaleDeployments(ctx, 791))
	assert.Equal(t, []int64{792}, due())
	require.NoError(t, TouchStaleDeployments(ctx, 792))
	assert.Empty(t, due())
	got, err := GetDeployment(ctx, 192, 3)
	require.NoError(t, err)
	assert.Equal(t, now-10, got.Updated, "seen as of the environment's change")

	// a deployment that no longer waits, or of another repository's environment, is never stale
	setTimes(now-10, now-50)
	_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET status = ? WHERE id = ?", DeploymentReleased, review.ID)
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE action_deployment SET repo_id = 5 WHERE id = ?", timer.ID)
	require.NoError(t, err)
	assert.Empty(t, due())
}

// Runs whose pass keeps failing, more of them than one tick takes, never hold back the others: a run is taken again only
// after every run that waits longer, stale ones (whose environment changed) included.
func TestStuckDeploymentsDontStarveOthers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	now := timeutil.TimeStampNow()
	env := &ActionEnvironment{RepoID: 4, Name: "prod"}
	require.NoError(t, CreateEnvironment(ctx, env, nil))
	newDeployment := func(runID int64, status DeploymentStatus, envID int64, updated timeutil.TimeStamp) {
		job := &ActionRunJob{RunID: runID, RepoID: 4, OwnerID: 1, Attempt: 1, JobID: "deploy", Status: StatusBlocked, Handle: fmt.Sprintf("stuck-%d", runID)}
		require.NoError(t, db.Insert(ctx, job))
		d := &ActionDeployment{RepoID: 4, EnvironmentID: envID, RunID: runID, JobID: job.ID, Attempt: 1, Status: status, ReleaseAfterUnix: now - 1}
		require.NoError(t, db.Insert(ctx, d))
		_, err := db.GetEngine(ctx).Exec("UPDATE action_deployment SET updated = ? WHERE id = ?", updated, d.ID)
		require.NoError(t, err)
	}
	// three runs wait under rules changed since (their environment is newer), longest waiting first; a fourth run of
	// another environment's timer became due later
	for i := range int64(3) {
		newDeployment(5001+i, DeploymentWaitingReview, env.ID, now-1000+timeutil.TimeStamp(i))
	}
	newDeployment(5100, DeploymentWaitingTimer, 0, now-10)
	_, err := db.GetEngine(ctx).Exec("UPDATE action_environment SET updated = ? WHERE id = ?", now-100, env.ID)
	require.NoError(t, err)

	seen := map[int64]int{}
	for tick := range 3 {
		runs, err := FindDueDeploymentRunIDs(ctx, now, 2)
		require.NoError(t, err)
		require.Len(t, runs, 2)
		for _, runID := range runs {
			seen[runID]++
			if runID != 5100 { // the stuck runs: their pass fails every time, so each goes to the back of the line
				require.NoError(t, TouchDueDeployments(ctx, runID, now+timeutil.TimeStamp(tick)))
			}
		}
		if seen[5100] > 0 {
			break
		}
	}
	assert.Equal(t, 1, seen[5100], "the other run is taken in spite of more stuck runs than one tick takes")
	assert.Equal(t, map[int64]int{5001: 1, 5002: 1, 5003: 1, 5100: 1}, seen, "each once, in turn")
	// they stay stale, and stay due, until a pass is queued
	runs, err := FindDueDeploymentRunIDs(ctx, now, 10)
	require.NoError(t, err)
	assert.ElementsMatch(t, []int64{5001, 5002, 5003, 5100}, runs)
}
