// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"fmt"
	"slices"
	"time"
)

// AuditRetentionDefault is what an unknown stored value reads as; there is no "forever".
const AuditRetentionDefault = 365

// AuditRetentionLowerDelay is how long a lowering waits before the purge job may use it.
const AuditRetentionLowerDelay = 7 * 24 * time.Hour

// AuditRetentionAllowed are the accepted retention periods in days: 30, 90, 182, 365 days and 2, 3, 5, 7, 10, 20 years.
var AuditRetentionAllowed = []int{30, 90, 182, 365, 730, 1095, 1825, 2555, 3650, 7300}

// AuditRetentionState is stored as JSON in the "audit.retention_days" system setting. A lowering keeps the old
// period in PreviousDays until EffectiveFrom (unix seconds).
type AuditRetentionState struct {
	Days          int   `json:"days"`
	PreviousDays  int   `json:"previous_days"`
	EffectiveFrom int64 `json:"effective_from"`
}

func normalizeAuditDays(d int) int {
	if slices.Contains(AuditRetentionAllowed, d) {
		return d
	}
	return AuditRetentionDefault
}

// Pending reports whether a lowering still waits. EffectiveFrom is clamped to now+7 days, so a stored time far in
// the future can only keep the longer period.
func (s AuditRetentionState) Pending(now time.Time) bool {
	return s.PreviousDays != 0 && now.Unix() < min(s.EffectiveFrom, now.Add(AuditRetentionLowerDelay).Unix())
}

// Effective is the retention in days the purge job uses: the stored days, and while a lowering is pending the
// longer of the old and the new period. An unknown value reads as 365.
func (s AuditRetentionState) Effective(now time.Time) int {
	if s.Pending(now) {
		return max(normalizeAuditDays(s.Days), normalizeAuditDays(s.PreviousDays))
	}
	return normalizeAuditDays(s.Days)
}

// NextAuditRetention returns the state after an admin chose want days. A raise applies at once and clears a pending
// lowering; a lowering keeps the period in force until now+7 days.
func NextAuditRetention(cur AuditRetentionState, want int, now time.Time) (AuditRetentionState, error) {
	if !slices.Contains(AuditRetentionAllowed, want) {
		return cur, fmt.Errorf("retention of %d days is not allowed", want)
	}
	eff := cur.Effective(now)
	if want >= eff {
		return AuditRetentionState{Days: want}, nil
	}
	if cur.Pending(now) && want == normalizeAuditDays(cur.Days) {
		return cur, nil
	}
	return AuditRetentionState{Days: want, PreviousDays: eff, EffectiveFrom: now.Add(AuditRetentionLowerDelay).Unix()}, nil
}

// Target is the stored days as the purge job reads them.
func (s AuditRetentionState) Target() int { return normalizeAuditDays(s.Days) }

// PendingUntil is when a pending lowering takes effect.
func (s AuditRetentionState) PendingUntil(now time.Time) time.Time {
	return time.Unix(min(s.EffectiveFrom, now.Add(AuditRetentionLowerDelay).Unix()), 0)
}
