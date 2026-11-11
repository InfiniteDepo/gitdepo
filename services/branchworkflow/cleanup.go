// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"context"
	"errors"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm/convert"
)

const (
	keyCleanup       = "branch_workflow.cleanup"
	keyCleanupLocked = "branch_workflow.cleanup_locked"

	// MaxCleanupDays is the largest number of days of the cleanup of merged branches.
	MaxCleanupDays = 3650
	// CleanupDelay is how long a turn-on or a lowering of the cleanup waits, so a wrong value can be reverted and the
	// preview reviewed before anything is deleted.
	CleanupDelay = 7 * 24 * time.Hour
)

// ErrInvalidCleanupDays is returned for a number of days outside 0 (off) to MaxCleanupDays.
var ErrInvalidCleanupDays = errors.New("the days of the cleanup must be 0 to 3650")

// CleanupPending tells if a turn-on or a lowering of c still waits. EffectiveFrom is clamped to now+CleanupDelay, so a
// stored time far ahead can only keep the safer, longer period.
func CleanupPending(c *repo_model.BranchCleanup, now time.Time) bool {
	return c != nil && c.EffectiveFrom != 0 && now.Unix() < min(c.EffectiveFrom, now.Add(CleanupDelay).Unix())
}

// CleanupDays is the days in force at now: 0 when cleanup is off or its turn-on still waits, the old days while a
// lowering waits.
func CleanupDays(c *repo_model.BranchCleanup, now time.Time) int {
	switch {
	case c == nil:
		return 0
	case CleanupPending(c, now):
		return c.PreviousDays
	}
	return c.Days
}

// CleanupStart is when a waiting change takes effect.
func CleanupStart(c *repo_model.BranchCleanup, now time.Time) time.Time {
	return time.Unix(min(c.EffectiveFrom, now.Add(CleanupDelay).Unix()), 0)
}

// NextCleanup returns the setting after someone chose want days (0 is off) while inForce days apply. Off and a raise
// apply at once; a turn-on and a lowering wait CleanupDelay, and saving the same days again doesn't postpone them.
func NextCleanup(inForce int, cur *repo_model.BranchCleanup, want int, now time.Time) (*repo_model.BranchCleanup, error) {
	switch {
	case want < 0 || want > MaxCleanupDays:
		return nil, ErrInvalidCleanupDays
	case want == 0:
		return &repo_model.BranchCleanup{}, nil
	case CleanupPending(cur, now) && cur.Days == want:
		return cur, nil
	case inForce > 0 && want >= inForce:
		return &repo_model.BranchCleanup{Days: want}, nil
	}
	return &repo_model.BranchCleanup{Days: want, PreviousDays: inForce, EffectiveFrom: now.Add(CleanupDelay).Unix()}, nil
}

// EffectiveCleanup is the cleanup setting that applies to a repository and where it comes from.
type EffectiveCleanup struct {
	Setting    *repo_model.BranchCleanup // the winning level's value, nil when none is set
	Days       int                       // in force now
	Source     string                    // SourceNone when neither the repository nor its organization sets it
	Locked     bool
	SetBy      string                    // name of the organization when Source is SourceOrg
	Configured *repo_model.BranchCleanup // the repository's own value, nil when it inherits
	Org        *repo_model.BranchCleanup // the organization's value, nil when it has none
}

// ResolveCleanup combines the levels like ResolveModel: a locked organization value wins, else the repository's own,
// else the organization's. There is no instance default.
func ResolveCleanup(org *repo_model.BranchCleanup, orgLocked bool, repo *repo_model.BranchCleanup, now time.Time) EffectiveCleanup {
	e := EffectiveCleanup{Source: SourceNone, Configured: repo, Org: org}
	switch {
	case org != nil && orgLocked:
		e.Setting, e.Source, e.Locked = org, SourceOrg, true
	case repo != nil:
		e.Setting, e.Source = repo, SourceRepo
	case org != nil:
		e.Setting, e.Source = org, SourceOrg
	}
	e.Days = CleanupDays(e.Setting, now)
	return e
}

// GetOrgCleanup returns the organization's cleanup setting, nil when it has none, and its lock.
func GetOrgCleanup(ctx context.Context, org *user_model.User) (*repo_model.BranchCleanup, bool, error) {
	stored, err := user_model.GetSettings(ctx, org.ID, []string{keyCleanup, keyCleanupLocked})
	if err != nil {
		return nil, false, err
	}
	var c *repo_model.BranchCleanup
	if s := stored[keyCleanup]; s != nil {
		c = &repo_model.BranchCleanup{}
		if err := json.Unmarshal([]byte(s.SettingValue), c); err != nil {
			return nil, false, err
		}
	}
	return c, c != nil && stored[keyCleanupLocked] != nil && stored[keyCleanupLocked].SettingValue == "true", nil
}

// GetEffectiveCleanup is the only way to read the cleanup setting that applies to a repository.
func GetEffectiveCleanup(ctx context.Context, repo *repo_model.Repository) (EffectiveCleanup, error) {
	if err := repo.LoadOwner(ctx); err != nil {
		return EffectiveCleanup{}, err
	}
	var org *repo_model.BranchCleanup
	orgLocked := false
	if repo.Owner.IsOrganization() {
		var err error
		if org, orgLocked, err = GetOrgCleanup(ctx, repo.Owner); err != nil {
			return EffectiveCleanup{}, err
		}
	}
	var own *repo_model.BranchCleanup
	if u, err := repo.GetUnit(ctx, unit.TypePullRequests); err == nil {
		own = u.PullRequestsConfig().BranchCleanup
	}
	e := ResolveCleanup(org, orgLocked, own, timeutil.TimeStampNow().AsTime())
	if e.Source == SourceOrg {
		e.SetBy = repo.Owner.Name
	}
	return e, nil
}

func cleanupAudit(c *repo_model.BranchCleanup) map[string]any {
	if c == nil {
		c = &repo_model.BranchCleanup{}
	}
	return map[string]any{"cleanup_days": c.Days, "cleanup_previous_days": c.PreviousDays, "cleanup_effective_from": c.EffectiveFrom}
}

// SetOrgCleanup stores the organization's cleanup of merged branches: days (0 is off, which without a lock removes
// the setting) and whether repositories must follow it. A lock needs a value. Changes are audited.
func SetOrgCleanup(ctx context.Context, org *user_model.User, days int, locked bool) error {
	now := timeutil.TimeStampNow().AsTime()
	return db.WithTx(ctx, func(ctx context.Context) error {
		before, beforeLocked, err := GetOrgCleanup(ctx, org)
		if err != nil {
			return err
		}
		next, err := NextCleanup(CleanupDays(before, now), before, days, now)
		if err != nil {
			return err
		}
		if next.Days == 0 && !locked {
			next = nil
		}
		if next == nil {
			err = user_model.DeleteUserSetting(ctx, org.ID, keyCleanup)
		} else {
			var bs []byte
			if bs, err = json.Marshal(next); err == nil {
				err = user_model.SetUserSetting(ctx, org.ID, keyCleanup, string(bs))
			}
		}
		if err != nil {
			return err
		}
		if locked {
			err = user_model.SetUserSetting(ctx, org.ID, keyCleanupLocked, "true")
		} else {
			err = user_model.DeleteUserSetting(ctx, org.ID, keyCleanupLocked)
		}
		if err != nil {
			return err
		}
		b, a := cleanupAudit(before), cleanupAudit(next)
		b["cleanup_locked"], a["cleanup_locked"] = beforeLocked, locked
		if changes := audit_model.Changes(b, a); changes != nil {
			return user_model.RecordOrg(ctx, "org.branch_workflow.changed", org, changes)
		}
		return nil
	})
}

// SetRepoCleanup stores the repository's own cleanup of merged branches: days (0 is off), or nil to inherit the
// organization's, unless the organization enforces one. Changes are audited.
func SetRepoCleanup(ctx context.Context, repo *repo_model.Repository, days *int) error {
	e, err := GetEffectiveCleanup(ctx, repo)
	if err != nil {
		return err
	}
	if e.Locked {
		return ErrLocked
	}
	u, err := repo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return ErrNoPullRequests
	}
	now := timeutil.TimeStampNow().AsTime()
	var newConfig convert.Conversion
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		stored, has, err := repo_model.GetRepoUnitForUpdate(ctx, repo.ID, unit.TypePullRequests)
		if err != nil {
			return err
		} else if !has {
			return ErrNoPullRequests
		}
		cfg := stored.PullRequestsConfig()
		before := cfg.BranchCleanup
		var next *repo_model.BranchCleanup
		if days != nil {
			if next, err = NextCleanup(e.Days, before, *days, now); err != nil {
				return err
			}
		}
		cfg.BranchCleanup = next
		if err := repo_model.UpdateRepoUnit(ctx, stored); err != nil {
			return err
		}
		newConfig = stored.Config
		b, a := cleanupAudit(before), cleanupAudit(next)
		b["cleanup_inherit"], a["cleanup_inherit"] = before == nil, next == nil
		if changes := audit_model.Changes(b, a); changes != nil {
			return repo_model.RecordRepo(ctx, "repo.branch_workflow.changed", repo, changes)
		}
		return nil
	}); err != nil {
		return err
	}
	u.Config = newConfig
	return nil
}
