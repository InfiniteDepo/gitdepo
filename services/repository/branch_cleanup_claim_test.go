// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cron fires in time.Local, the claim's "day" is DefaultUILocation. When the two differ, a repository processed
// after the UI-midnight in one night's run is skipped by the next night's run.
func nextNightLiveBranches(t *testing.T, ui *time.Location) []string {
	defer test.MockVariableValue(&setting.DefaultUILocation, ui)()
	f := newCleanupFixture(t, "cleanup-unit")
	noPushQueue(t)
	f.branch("old-1", f.c1, 90)
	f.setDays(30)
	now := time.Now().In(time.Local)
	night1 := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local) // "@daily" in time.Local
	// night 1's run reached this repository after 1 h 30 min
	_, err := db.GetEngine(t.Context()).Exec("UPDATE branch_cleanup_state SET last_run_unix = ? WHERE repo_id = ?", night1.Add(90*time.Minute).Unix(), f.repo.ID)
	require.NoError(t, err)
	// night 2's run, one minute after it started
	timeutil.MockSet(night1.Add(24*time.Hour + time.Minute))
	defer timeutil.MockUnset()
	require.NoError(t, CleanupMergedBranches(audit_model.WithSystem(t.Context(), "cron:"+CleanupTaskName)))
	return liveBranches(t, f.repo)
}

func TestCleanupClaimDayIsInTheCronZone(t *testing.T) {
	assert.NotContains(t, nextNightLiveBranches(t, time.FixedZone("UTC-1", -3600)), "old-1", "the next night's run must run")
}

func TestCleanupClaimDayInLocalZone(t *testing.T) {
	assert.NotContains(t, nextNightLiveBranches(t, time.Local), "old-1")
}
