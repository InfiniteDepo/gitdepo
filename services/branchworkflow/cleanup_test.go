// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextCleanupState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	later := now.Add(CleanupDelay).Unix()
	st := func(days, pendingDays int, from int64) *repo_model.BranchCleanupState {
		return &repo_model.BranchCleanupState{RepoID: 7, LastRunUnix: 5, Days: days, PendingDays: pendingDays, PendingFrom: from}
	}
	cases := []struct {
		name string
		cur  *repo_model.BranchCleanupState
		want int
		next repo_model.BranchCleanupState
	}{
		{"no record yet, turned on: waits", nil, 30, repo_model.BranchCleanupState{PendingDays: 30, PendingFrom: later}},
		{"no record yet, off", nil, 0, repo_model.BranchCleanupState{}},
		{"fewer days wait, the recorded days keep applying", st(60, 0, 0), 30, *st(60, 30, later)},
		{"more days apply at once", st(30, 0, 0), 60, *st(60, 0, 0)},
		{"the same days change nothing", st(30, 0, 0), 30, *st(30, 0, 0)},
		{"off applies at once", st(30, 0, 0), 0, *st(0, 0, 0)},
		{"off from off", st(0, 0, 0), 0, *st(0, 0, 0)},
		{"on from off waits", st(0, 0, 0), 30, *st(0, 30, later)},
		{"a waiting change seen again isn't postponed", st(0, 30, now.Add(time.Hour).Unix()), 30, *st(0, 30, now.Add(time.Hour).Unix())},
		{"a waiting change that is due takes effect", st(0, 30, now.Add(-time.Second).Unix()), 30, *st(30, 0, 0)},
		{"another value while waiting waits again", st(0, 30, now.Add(time.Hour).Unix()), 20, *st(0, 20, later)},
		{"going back while waiting drops the waiting change", st(60, 30, now.Add(time.Hour).Unix()), 60, *st(60, 0, 0)},
		{"less strict while waiting applies at once", st(60, 30, now.Add(time.Hour).Unix()), 90, *st(90, 0, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NextCleanupState(c.cur, c.want, now)
			if c.cur != nil {
				c.next.RepoID, c.next.LastRunUnix = 7, 5 // kept
			}
			assert.Equal(t, c.next, got)
		})
	}
}

func TestResolveCleanup(t *testing.T) {
	org := &repo_model.BranchCleanup{Days: 60}
	own := &repo_model.BranchCleanup{Days: 10}

	e := ResolveCleanup(nil, false, nil)
	assert.Equal(t, SourceNone, e.Source)
	assert.Zero(t, e.Wanted)

	e = ResolveCleanup(org, false, nil)
	assert.Equal(t, SourceOrg, e.Source)
	assert.Equal(t, 60, e.Wanted)

	e = ResolveCleanup(org, false, own)
	assert.Equal(t, SourceRepo, e.Source)
	assert.Equal(t, 10, e.Wanted)

	e = ResolveCleanup(org, true, own)
	assert.Equal(t, SourceOrg, e.Source)
	assert.True(t, e.Locked)
	assert.Equal(t, 60, e.Wanted, "under the lock the repository has no setting of its own")
	assert.Equal(t, own, e.Configured)

	// the lock needs the organization's own value
	e = ResolveCleanup(nil, true, own)
	assert.False(t, e.Locked)
	assert.Equal(t, 10, e.Wanted)

	// an organization that enforces "off" turns the repository's own setting off
	e = ResolveCleanup(&repo_model.BranchCleanup{}, true, own)
	assert.True(t, e.Locked)
	assert.Zero(t, e.Wanted)
}

func TestSetOrgAndRepoCleanup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	reload := func() *repo_model.Repository {
		return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	}
	days := func(n int) *int { return &n }
	since := int64(0)
	_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&since)
	require.NoError(t, err)

	require.ErrorIs(t, SetOrgCleanup(t.Context(), org, -1, false), ErrInvalidCleanupDays)
	require.NoError(t, SetOrgCleanup(t.Context(), org, 60, false))
	c, locked, err := GetOrgCleanup(t.Context(), org)
	require.NoError(t, err)
	assert.False(t, locked)
	assert.Equal(t, 60, c.Days)

	eff, err := GetEffectiveCleanup(t.Context(), reload())
	require.NoError(t, err)
	assert.Equal(t, SourceOrg, eff.Source)
	assert.Equal(t, org.Name, eff.SetBy)
	assert.Zero(t, eff.Days, "not in force before the delay has passed")
	assert.Equal(t, 60, eff.Wanted)

	// the repository's own value, then the lock refuses further changes
	require.NoError(t, SetRepoCleanup(t.Context(), reload(), days(10)))
	eff, err = GetEffectiveCleanup(t.Context(), reload())
	require.NoError(t, err)
	assert.Equal(t, SourceRepo, eff.Source)
	assert.Equal(t, 10, eff.Setting.Days)
	require.ErrorIs(t, SetRepoCleanup(t.Context(), reload(), days(-5)), ErrInvalidCleanupDays)

	require.NoError(t, SetOrgCleanup(t.Context(), org, 60, true))
	eff, err = GetEffectiveCleanup(t.Context(), reload())
	require.NoError(t, err)
	assert.True(t, eff.Locked)
	require.ErrorIs(t, SetRepoCleanup(t.Context(), reload(), days(5)), ErrLocked)
	require.ErrorIs(t, SetRepoCleanup(t.Context(), reload(), nil), ErrLocked)

	// unlocking brings the repository's own value back; inherit removes it
	require.NoError(t, SetOrgCleanup(t.Context(), org, 60, false))
	require.NoError(t, SetRepoCleanup(t.Context(), reload(), nil))
	eff, err = GetEffectiveCleanup(t.Context(), reload())
	require.NoError(t, err)
	assert.Equal(t, SourceOrg, eff.Source)
	assert.Nil(t, eff.Configured)

	// every change is one audit entry of its own; saving the same again records nothing
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action IN (?, ?)", since, "org.branch_workflow.changed", "repo.branch_workflow.changed").OrderBy("id").Find(&entries))
	n := len(entries)
	assert.Equal(t, 5, n) // org on, repo own, org lock, org unlock, repo inherit
	assert.Contains(t, entries[0].Data, `"cleanup_days"`)
	require.NoError(t, SetOrgCleanup(t.Context(), org, 60, false))
	entries = nil
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action IN (?, ?)", since, "org.branch_workflow.changed", "repo.branch_workflow.changed").Find(&entries))
	assert.Len(t, entries, n)

	// off without a lock removes the organization's setting
	require.NoError(t, SetOrgCleanup(t.Context(), org, 0, false))
	c, _, err = GetOrgCleanup(t.Context(), org)
	require.NoError(t, err)
	assert.Nil(t, c)
}

// cleanupScenario is a repository of org3 whose clock the test moves.
type cleanupScenario struct {
	t     *testing.T
	org   *user_model.User
	now   time.Time
	start time.Time
}

func newCleanupScenario(t *testing.T) *cleanupScenario {
	require.NoError(t, unittest.PrepareTestDatabase())
	sc := &cleanupScenario{t: t, org: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), start: time.Unix(1_800_000_000, 0)}
	sc.at(0)
	t.Cleanup(timeutil.MockUnset)
	return sc
}

// at moves the clock to the given days after the start.
func (sc *cleanupScenario) at(days int) {
	sc.now = sc.start.Add(time.Duration(days) * 24 * time.Hour)
	timeutil.MockSet(sc.now)
}

func (sc *cleanupScenario) repo() *repo_model.Repository {
	return unittest.AssertExistsAndLoadBean(sc.t, &repo_model.Repository{ID: 3})
}

func (sc *cleanupScenario) own(days *int) {
	require.NoError(sc.t, SetRepoCleanup(sc.t.Context(), sc.repo(), days))
}

func (sc *cleanupScenario) org3(days int, locked bool) {
	require.NoError(sc.t, SetOrgCleanup(sc.t.Context(), sc.org, days, locked))
}

// sync is what the scheduled run does first; it returns the days in force.
func (sc *cleanupScenario) sync() EffectiveCleanup {
	e, err := SyncCleanup(sc.t.Context(), sc.repo())
	require.NoError(sc.t, err)
	return e
}

// waits asserts that the recorded days still apply and the wanted ones take effect 7 days after the start.
func (sc *cleanupScenario) waits(e EffectiveCleanup, inForce, wanted int) {
	assert.Equal(sc.t, inForce, e.Days)
	assert.Equal(sc.t, wanted, e.PendingDays)
	assert.Equal(sc.t, sc.now.Add(CleanupDelay).Unix(), e.PendingFrom.Unix())
}

func TestCleanupWaitingPeriodOnTheDaysInForce(t *testing.T) {
	days := func(n int) *int { return &n }

	t.Run("inherit to a shorter organization value waits", func(t *testing.T) {
		sc := newCleanupScenario(t)
		sc.org3(60, false)
		sc.own(days(3650))
		sc.at(8)
		assert.Equal(t, 3650, sc.sync().Days)
		sc.at(10)
		sc.own(nil) // the repository now inherits the organization's 60 days
		e := sc.sync()
		sc.waits(e, 3650, 60)
		sc.at(16)
		assert.Equal(t, 3650, sc.sync().Days, "still waiting")
		sc.at(17)
		assert.Equal(t, 60, sc.sync().Days)
	})

	t.Run("inherit from off waits", func(t *testing.T) {
		sc := newCleanupScenario(t)
		sc.org3(30, false)
		sc.own(days(0))
		assert.Zero(t, sc.sync().Days)
		sc.at(9)
		sc.own(nil)
		sc.waits(sc.sync(), 0, 30)
	})

	t.Run("an organization lock waits", func(t *testing.T) {
		sc := newCleanupScenario(t)
		sc.org3(30, false)
		sc.own(days(365))
		sc.at(8)
		assert.Equal(t, 365, sc.sync().Days)
		sc.at(9)
		sc.org3(30, true)
		sc.waits(sc.sync(), 365, 30)
		sc.at(16)
		assert.Equal(t, 30, sc.sync().Days)
	})

	t.Run("removing the lock lets a shorter own value wait", func(t *testing.T) {
		sc := newCleanupScenario(t)
		sc.org3(60, false)
		sc.own(days(10)) // saved before the lock
		sc.at(8)
		assert.Equal(t, 10, sc.sync().Days)
		sc.org3(60, true) // 10 -> 60: less aggressive, at once
		sc.at(9)
		assert.Equal(t, 60, sc.sync().Days)
		sc.at(20)
		sc.org3(60, false) // the own 10 comes back
		sc.waits(sc.sync(), 60, 10)
	})

	t.Run("a repository that gets an organization's setting by a transfer waits", func(t *testing.T) {
		sc := newCleanupScenario(t)
		// no record: the repository ran no cleanup before; a record of an earlier owner's would be kept as it is
		sc.org3(30, false)
		sc.at(5)
		e, err := GetEffectiveCleanup(t.Context(), sc.repo())
		require.NoError(t, err)
		sc.waits(e, 0, 30) // the page shows the first-run date before anything is stored
		assert.Nil(t, e.State)
		sc.waits(sc.sync(), 0, 30)
		st, err := repo_model.GetBranchCleanupState(t.Context(), 3)
		require.NoError(t, err)
		require.NotNil(t, st)
		assert.Equal(t, 30, st.PendingDays)
	})

	t.Run("raising applies at once and turning off too", func(t *testing.T) {
		sc := newCleanupScenario(t)
		sc.own(days(30))
		sc.at(8)
		assert.Equal(t, 30, sc.sync().Days)
		sc.own(days(60))
		e := sc.sync()
		assert.Equal(t, 60, e.Days)
		assert.True(t, e.PendingFrom.IsZero())
		sc.own(days(0))
		assert.Zero(t, sc.sync().Days)
		// turning it on again waits again: the record is not a licence
		sc.at(9)
		sc.own(days(60))
		sc.waits(sc.sync(), 0, 60)
	})

	t.Run("saving the same days again does not postpone", func(t *testing.T) {
		sc := newCleanupScenario(t)
		sc.own(days(30))
		sc.at(3)
		sc.own(days(30))
		e := sc.sync()
		assert.Equal(t, sc.start.Add(CleanupDelay).Unix(), e.PendingFrom.Unix())
	})
}

// An organization's "off" is recorded at once, so off and on again between two runs still waits.
func TestCleanupOrgOffOnWaits(t *testing.T) {
	sc := newCleanupScenario(t)
	sc.org3(1, false)
	sc.sync() // the scheduled run records the pending turn-on
	sc.at(8)
	assert.Equal(t, 1, sc.sync().Days, "in force after the wait")

	sc.at(30)
	sc.org3(0, false)
	e, err := GetEffectiveCleanup(t.Context(), sc.repo())
	require.NoError(t, err)
	assert.Zero(t, e.Days)
	sc.org3(1, false) // on again before the next run

	e = sc.sync()
	assert.Zero(t, e.Days, "a turn-on from off waits, as at repository level")
	assert.False(t, e.PendingFrom.IsZero())
}

// Fewer days of the organization start waiting when saved, more days apply at once.
func TestCleanupOrgChangeReachesRecords(t *testing.T) {
	sc := newCleanupScenario(t)
	sc.org3(30, false)
	sc.sync()
	sc.at(8)
	sc.sync()
	sc.at(9)
	sc.org3(10, false)
	st, err := repo_model.GetBranchCleanupState(t.Context(), 3)
	require.NoError(t, err)
	assert.Equal(t, 30, st.Days)
	assert.Equal(t, 10, st.PendingDays)
	sc.org3(60, false)
	st, err = repo_model.GetBranchCleanupState(t.Context(), 3)
	require.NoError(t, err)
	assert.Equal(t, 60, st.Days)
	assert.Zero(t, st.PendingFrom)
}
