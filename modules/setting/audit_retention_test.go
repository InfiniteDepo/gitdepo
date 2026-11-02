// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC7
func TestAuditRetentionEffective(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	later := now.Add(AuditRetentionLowerDelay)
	assert.Equal(t, 365, AuditRetentionState{}.Effective(now))
	assert.Equal(t, 365, AuditRetentionState{Days: 31}.Effective(now))
	assert.Equal(t, 90, AuditRetentionState{Days: 90}.Effective(now))
	// pending: the longer period; at the 7-day edge the lowering applies
	pending := AuditRetentionState{Days: 30, PreviousDays: 365, EffectiveFrom: later.Unix()}
	assert.Equal(t, 365, pending.Effective(now))
	assert.Equal(t, 365, pending.Effective(later.Add(-time.Second)))
	assert.Equal(t, 30, pending.Effective(later))
	// M1: unknown previous reads as 365, never as the short days
	assert.Equal(t, 365, AuditRetentionState{Days: 30, PreviousDays: 31, EffectiveFrom: later.Unix()}.Effective(now))
	assert.Equal(t, 30, AuditRetentionState{Days: 30, EffectiveFrom: later.Unix()}.Effective(now))
	// a stored time far in the future is clamped to now+7d, so it never shortens
	far := AuditRetentionState{Days: 30, PreviousDays: 365, EffectiveFrom: now.AddDate(10, 0, 0).Unix()}
	assert.Equal(t, 365, far.Effective(now))
	assert.True(t, far.Pending(now))
	// an unknown (e.g. negative or huge) days value reads as 365
	assert.Equal(t, 365, AuditRetentionState{Days: -5}.Effective(now))
}

// AC7
func TestNextAuditRetention(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	from := now.Add(AuditRetentionLowerDelay).Unix()

	s, err := NextAuditRetention(AuditRetentionState{}, 90, now)
	require.NoError(t, err)
	assert.Equal(t, AuditRetentionState{Days: 90, PreviousDays: 365, EffectiveFrom: from}, s)

	// raise: at once, no pending
	s, err = NextAuditRetention(AuditRetentionState{Days: 90}, 730, now)
	require.NoError(t, err)
	assert.Equal(t, AuditRetentionState{Days: 730}, s)

	// second lowering keeps the still longer period in force
	s, err = NextAuditRetention(AuditRetentionState{Days: 90, PreviousDays: 365, EffectiveFrom: from}, 30, now)
	require.NoError(t, err)
	assert.Equal(t, AuditRetentionState{Days: 30, PreviousDays: 365, EffectiveFrom: from}, s)

	// raise while pending clears it
	s, err = NextAuditRetention(AuditRetentionState{Days: 90, PreviousDays: 365, EffectiveFrom: from}, 365, now)
	require.NoError(t, err)
	assert.Equal(t, AuditRetentionState{Days: 365}, s)

	// the same value again while pending does not restart the 7 days
	pending := AuditRetentionState{Days: 90, PreviousDays: 365, EffectiveFrom: from - 100}
	s, err = NextAuditRetention(pending, 90, now)
	require.NoError(t, err)
	assert.Equal(t, pending, s)

	for _, bad := range []int{0, -1, 31, 100000} {
		_, err = NextAuditRetention(AuditRetentionState{}, bad, now)
		require.Error(t, err)
	}
}
