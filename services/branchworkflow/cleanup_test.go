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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextCleanup(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	later := now.Add(CleanupDelay).Unix()
	cases := []struct {
		name    string
		inForce int
		cur     *repo_model.BranchCleanup
		want    int
		next    *repo_model.BranchCleanup
		err     error
	}{
		{"turn on waits", 0, nil, 30, &repo_model.BranchCleanup{Days: 30, EffectiveFrom: later}, nil},
		{"lowering waits and keeps the old days", 60, &repo_model.BranchCleanup{Days: 60}, 30, &repo_model.BranchCleanup{Days: 30, PreviousDays: 60, EffectiveFrom: later}, nil},
		{"a raise applies at once", 30, &repo_model.BranchCleanup{Days: 30}, 60, &repo_model.BranchCleanup{Days: 60}, nil},
		{"the same days again changes nothing", 30, &repo_model.BranchCleanup{Days: 30}, 30, &repo_model.BranchCleanup{Days: 30}, nil},
		{"off applies at once", 30, &repo_model.BranchCleanup{Days: 30}, 0, &repo_model.BranchCleanup{}, nil},
		{"a waiting turn-on saved again isn't postponed", 0, &repo_model.BranchCleanup{Days: 30, EffectiveFrom: now.Add(time.Hour).Unix()}, 30, &repo_model.BranchCleanup{Days: 30, EffectiveFrom: now.Add(time.Hour).Unix()}, nil},
		{"another value while waiting waits again", 0, &repo_model.BranchCleanup{Days: 30, EffectiveFrom: now.Add(time.Hour).Unix()}, 20, &repo_model.BranchCleanup{Days: 20, EffectiveFrom: later}, nil},
		{"the repository inherits 30 and chooses 10", 30, nil, 10, &repo_model.BranchCleanup{Days: 10, PreviousDays: 30, EffectiveFrom: later}, nil},
		{"negative", 0, nil, -1, nil, ErrInvalidCleanupDays},
		{"too many", 0, nil, MaxCleanupDays + 1, nil, ErrInvalidCleanupDays},
		{"the maximum", 0, nil, MaxCleanupDays, &repo_model.BranchCleanup{Days: MaxCleanupDays, EffectiveFrom: later}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NextCleanup(c.inForce, c.cur, c.want, now)
			require.ErrorIs(t, err, c.err)
			assert.Equal(t, c.next, got)
		})
	}
}

func TestCleanupDays(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	assert.Equal(t, 0, CleanupDays(nil, now))
	assert.Equal(t, 30, CleanupDays(&repo_model.BranchCleanup{Days: 30}, now))
	assert.Equal(t, 0, CleanupDays(&repo_model.BranchCleanup{}, now))

	waiting := &repo_model.BranchCleanup{Days: 30, PreviousDays: 60, EffectiveFrom: now.Add(time.Hour).Unix()}
	assert.True(t, CleanupPending(waiting, now))
	assert.Equal(t, 60, CleanupDays(waiting, now), "a lowering keeps the longer period until it is due")
	assert.Equal(t, 30, CleanupDays(waiting, now.Add(2*time.Hour)))
	assert.Equal(t, 0, CleanupDays(&repo_model.BranchCleanup{Days: 30, EffectiveFrom: now.Add(time.Hour).Unix()}, now), "a turn-on is off until it is due")

	// a time far in the future can only keep the safer period: it is clamped to the delay
	far := &repo_model.BranchCleanup{Days: 30, EffectiveFrom: now.Add(100 * 24 * time.Hour).Unix()}
	assert.Equal(t, 0, CleanupDays(far, now))
	assert.Equal(t, 0, CleanupDays(far, now.Add(CleanupDelay+time.Second)), "the clamp moves with the clock, so it never shortens the wait")
	assert.Equal(t, 30, CleanupDays(far, now.Add(101*24*time.Hour)))
}

func TestResolveCleanup(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	org := &repo_model.BranchCleanup{Days: 60}
	own := &repo_model.BranchCleanup{Days: 10}

	e := ResolveCleanup(nil, false, nil, now)
	assert.Equal(t, SourceNone, e.Source)
	assert.Zero(t, e.Days)

	e = ResolveCleanup(org, false, nil, now)
	assert.Equal(t, SourceOrg, e.Source)
	assert.Equal(t, 60, e.Days)

	e = ResolveCleanup(org, false, own, now)
	assert.Equal(t, SourceRepo, e.Source)
	assert.Equal(t, 10, e.Days)

	e = ResolveCleanup(org, true, own, now)
	assert.Equal(t, SourceOrg, e.Source)
	assert.True(t, e.Locked)
	assert.Equal(t, 60, e.Days, "under the lock the repository has no setting of its own")
	assert.Equal(t, own, e.Configured)

	// the lock needs the organization's own value
	e = ResolveCleanup(nil, true, own, now)
	assert.False(t, e.Locked)
	assert.Equal(t, 10, e.Days)

	// an organization that enforces "off" turns the repository's own setting off
	e = ResolveCleanup(&repo_model.BranchCleanup{}, true, own, now)
	assert.True(t, e.Locked)
	assert.Zero(t, e.Days)
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
	assert.NotZero(t, c.EffectiveFrom, "turning it on waits")

	eff, err := GetEffectiveCleanup(t.Context(), reload())
	require.NoError(t, err)
	assert.Equal(t, SourceOrg, eff.Source)
	assert.Equal(t, org.Name, eff.SetBy)
	assert.Zero(t, eff.Days, "not in force before the delay has passed")

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
