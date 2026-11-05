// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceEnvironmentReviewers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	e := &ActionEnvironment{RepoID: 1, Name: "prod"}
	require.NoError(t, CreateEnvironment(ctx, e))

	required := func() bool {
		stored, err := GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
		require.NoError(t, err)
		return stored.ReviewsRequired
	}
	assert.False(t, required())

	users := func(ids ...int64) []ActionEnvironmentReviewer {
		var rs []ActionEnvironmentReviewer
		for _, id := range ids {
			rs = append(rs, ActionEnvironmentReviewer{UserID: id})
		}
		return rs
	}
	require.NoError(t, ReplaceEnvironmentReviewers(ctx, e, append(users(2, 3), ActionEnvironmentReviewer{TeamID: 5})))
	rs, err := FindEnvironmentReviewers(ctx, e.ID)
	require.NoError(t, err)
	assert.Len(t, rs, 3)
	assert.True(t, required())

	for name, list := range map[string][]ActionEnvironmentReviewer{
		"seven":         users(1, 2, 3, 4, 5, 6, 7),
		"both set":      {{UserID: 1, TeamID: 1}},
		"none set":      {{}},
		"negative":      {{UserID: -2}},
		"user twice":    users(1, 1),
		"team twice":    {{TeamID: 4}, {TeamID: 4}},
		"negative team": {{TeamID: -1}},
	} {
		require.ErrorIs(t, ReplaceEnvironmentReviewers(ctx, e, list), util.ErrInvalidArgument, name)
	}
	rs, err = FindEnvironmentReviewers(ctx, e.ID)
	require.NoError(t, err)
	assert.Len(t, rs, 3, "a refused list changes nothing")

	require.NoError(t, ReplaceEnvironmentReviewers(ctx, e, nil), "no reviewers")
	assert.False(t, required())

	gone := &ActionEnvironment{ID: 9999, RepoID: 1}
	require.ErrorIs(t, ReplaceEnvironmentReviewers(ctx, gone, users(1)), ErrEnvironmentNotFound)
	other := &ActionEnvironment{ID: e.ID, RepoID: 2}
	require.ErrorIs(t, ReplaceEnvironmentReviewers(ctx, other, users(1)), ErrEnvironmentNotFound, "an environment of another repository")

	require.NoError(t, ReplaceEnvironmentReviewers(ctx, e, users(2)))
	require.NoError(t, DeleteEnvironment(ctx, e, func(context.Context) error { return nil }))
	n, err := db.GetEngine(ctx).Count(new(ActionEnvironmentReviewer))
	require.NoError(t, err)
	assert.Zero(t, n, "the environment takes its reviewers with it")
}

func TestDeploymentReviewStatuses(t *testing.T) {
	for s, name := range map[DeploymentStatus]string{
		DeploymentWaitingTimer: "waiting_timer", DeploymentReleased: "released", DeploymentRefused: "refused",
		DeploymentCancelled: "cancelled", DeploymentWaitingReview: "waiting_review", DeploymentRejected: "rejected",
		DeploymentExpired: "expired", 99: "unknown",
	} {
		assert.Equal(t, name, s.String())
	}
	assert.True(t, DeploymentWaitingReview.IsWaiting())
	assert.True(t, DeploymentWaitingTimer.IsWaiting())
	for _, s := range []DeploymentStatus{DeploymentReleased, DeploymentRefused, DeploymentCancelled, DeploymentRejected, DeploymentExpired} {
		assert.False(t, s.IsWaiting(), s.String())
	}
}
