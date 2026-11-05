// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

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

	ds, err := FindReviewableDeployments(ctx, 791)
	require.NoError(t, err)
	require.Len(t, ds, 1)
	assert.Equal(t, waiting.ID, ds[0].ID)
	ds, err = FindRunDeployments(ctx, 791)
	require.NoError(t, err)
	assert.Len(t, ds, 2, "every deployment of the run")

	// only a waiting deployment takes a review, and only once
	waiting.Status, waiting.ReviewedBy, waiting.ReviewedUnix, waiting.ReviewComment = DeploymentWaitingTimer, 2, now, "ok"
	moved, err := ReviewDeployment(ctx, waiting)
	require.NoError(t, err)
	assert.True(t, moved)
	waiting.Status, waiting.ReviewedBy = DeploymentRejected, 3
	moved, err = ReviewDeployment(ctx, waiting)
	require.NoError(t, err)
	assert.False(t, moved, "no longer waiting for a review")
	got, err := GetDeployment(ctx, 192, 3)
	require.NoError(t, err)
	assert.Equal(t, DeploymentWaitingTimer, got.Status)
	assert.EqualValues(t, 2, got.ReviewedBy)
	assert.Equal(t, "ok", got.ReviewComment)

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
