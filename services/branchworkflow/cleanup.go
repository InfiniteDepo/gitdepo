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

// moreAggressive tells if want days delete sooner than than days: from off to on, or fewer days (0 is off).
func moreAggressive(want, than int) bool {
	return want > 0 && (than == 0 || want < than)
}

// NextCleanupState is the one rule of the waiting period. want is the days the levels (repository, organization,
// lock) resolve to now, 0 for off; cur is the repository's record, nil when it has none (as if off). A change that
// deletes sooner (a turn-on or fewer days) waits CleanupDelay from when it is first seen, and the recorded days keep
// applying meanwhile; any other change applies at once. Whatever made the days change counts, so inherit, an
// organization's lock, turning the unit on or moving into an organization all wait. It doesn't store anything.
func NextCleanupState(cur *repo_model.BranchCleanupState, want int, now time.Time) repo_model.BranchCleanupState {
	var s repo_model.BranchCleanupState
	if cur != nil {
		s = *cur
	}
	switch {
	case !moreAggressive(want, s.Days):
		s.Days, s.PendingDays, s.PendingFrom = want, 0, 0
	case s.PendingFrom != 0 && s.PendingDays == want:
		if now.Unix() >= s.PendingFrom {
			s.Days, s.PendingDays, s.PendingFrom = want, 0, 0
		}
	default:
		s.PendingDays, s.PendingFrom = want, now.Add(CleanupDelay).Unix()
	}
	return s
}

// EffectiveCleanup is the cleanup that applies to a repository and where it comes from.
type EffectiveCleanup struct {
	Setting     *repo_model.BranchCleanup      // the winning level's value, nil when none is set
	Wanted      int                            // the days that value makes of it (0 off)
	Days        int                            // in force now: the recorded days, until a change that waits is due
	PendingDays int                            // the change that waits, valid when PendingFrom is not zero
	PendingFrom time.Time                      // when it takes effect, zero when nothing waits
	State       *repo_model.BranchCleanupState // the stored record, nil when there is none
	Next        repo_model.BranchCleanupState  // the record after the rule ran at now
	Source      string                         // SourceNone when neither the repository nor its organization sets it
	Locked      bool
	SetBy       string                    // name of the organization when Source is SourceOrg
	Configured  *repo_model.BranchCleanup // the repository's own value, nil when it inherits
	Org         *repo_model.BranchCleanup // the organization's value, nil when it has none
}

// ResolveCleanup combines the levels like ResolveModel: a locked organization value wins, else the repository's own,
// else the organization's. There is no instance default. Days and the waiting period come from the repository's
// record: see GetEffectiveCleanup.
func ResolveCleanup(org *repo_model.BranchCleanup, orgLocked bool, repo *repo_model.BranchCleanup) EffectiveCleanup {
	e := EffectiveCleanup{Source: SourceNone, Configured: repo, Org: org}
	switch {
	case org != nil && orgLocked:
		e.Setting, e.Source, e.Locked = org, SourceOrg, true
	case repo != nil:
		e.Setting, e.Source = repo, SourceRepo
	case org != nil:
		e.Setting, e.Source = org, SourceOrg
	}
	if e.Setting != nil {
		e.Wanted = e.Setting.Days
	}
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

// GetEffectiveCleanup is the only way to read the cleanup that applies to a repository: the levels are resolved and
// the rule of the waiting period is applied to the repository's record. It reads only; SyncCleanup stores.
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
	e := ResolveCleanup(org, orgLocked, own)
	if e.Source == SourceOrg {
		e.SetBy = repo.Owner.Name
	}
	var err error
	if e.State, err = repo_model.GetBranchCleanupState(ctx, repo.ID); err != nil {
		return EffectiveCleanup{}, err
	}
	e.Next = NextCleanupState(e.State, e.Wanted, timeutil.TimeStampNow().AsTime())
	e.Days = e.Next.Days
	if e.Next.PendingFrom != 0 {
		e.PendingDays, e.PendingFrom = e.Next.PendingDays, time.Unix(e.Next.PendingFrom, 0)
	}
	return e, nil
}

// SyncCleanup is GetEffectiveCleanup that also records the result, so a change that waits starts its waiting
// period now. The settings forms and the scheduled run call it.
func SyncCleanup(ctx context.Context, repo *repo_model.Repository) (EffectiveCleanup, error) {
	e, err := GetEffectiveCleanup(ctx, repo)
	if err != nil {
		return e, err
	}
	st := e.State
	if st == nil && e.Next.Days == 0 && e.Next.PendingFrom == 0 {
		return e, nil // off and nothing waits: no record needed
	}
	if st == nil || st.Days != e.Next.Days || st.PendingDays != e.Next.PendingDays || st.PendingFrom != e.Next.PendingFrom {
		e.Next.RepoID = repo.ID
		err = repo_model.SaveBranchCleanupState(ctx, &e.Next)
	}
	return e, err
}

func cleanupAudit(c *repo_model.BranchCleanup) map[string]any {
	if c == nil {
		c = &repo_model.BranchCleanup{}
	}
	return map[string]any{"cleanup_days": c.Days}
}

// SetOrgCleanup stores the organization's cleanup of merged branches: days (0 is off, which without a lock removes
// the setting) and whether repositories must follow it. A lock needs a value. Changes are audited.
func SetOrgCleanup(ctx context.Context, org *user_model.User, days int, locked bool) error {
	if days < 0 || days > MaxCleanupDays {
		return ErrInvalidCleanupDays
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		before, beforeLocked, err := GetOrgCleanup(ctx, org)
		if err != nil {
			return err
		}
		next := &repo_model.BranchCleanup{Days: days}
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
	if days != nil && (*days < 0 || *days > MaxCleanupDays) {
		return ErrInvalidCleanupDays
	}
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
			next = &repo_model.BranchCleanup{Days: *days}
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
	_, err = SyncCleanup(ctx, repo) // starts the waiting period of a change that deletes sooner
	return err
}
