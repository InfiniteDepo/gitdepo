// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"maps"
	"slices"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	secretscan_model "forgejo.org/models/secretscan"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/process"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
)

// requeueBatch is the number of repositories read per query when the repositories marked to be scanned again are
// queued.
var requeueBatch = 1000

// requeue queues the repositories marked by a switch that turned on (secretscan_model.MarkRequeue). It is a variable
// so that tests can see what asks for it. The marks are in the database: if the process stops before it is done, the
// cron task queues the rest.
var requeue = startRequeue

// startRequeue runs requeueMarked as a process of its own: after the setting is saved, the request that saved it
// neither waits for it nor fails with it, and a shutdown or a test cleanup can cancel and wait for it. The process
// is registered before the goroutine starts, so a cleanup that waits for processes can't miss it.
func startRequeue() {
	ctx, _, finished := process.GetManager().AddTypedContext(graceful.GetManager().ShutdownContext(), "secret scanning: queue the marked repositories", process.SystemProcessType, true)
	go func() {
		defer finished()
		if err := requeueMarked(ctx, Enqueue); err != nil && ctx.Err() == nil {
			log.Error("secret scanning: queue the marked repositories: %v", err)
		}
	}()
}

// SetOrgSwitch stores an organization's switch and lock. A save that changes nothing does nothing. The setting is
// stored while the site switch is off too (it has no effect until the site turns on). Turning it on queues the
// organization's scanned repositories (marked in the same transaction), since pushes while it was off were not scanned.
func SetOrgSwitch(ctx context.Context, org *user_model.User, on, locked bool) error {
	marked := false
	err := db.WithTx(ctx, func(ctx context.Context) error {
		before, err := readOrgSwitch(ctx, org.ID)
		if err != nil {
			return err
		}
		changes := audit_model.Changes(
			map[string]any{"secret_scanning": before.On, "secret_scanning_locked": before.Locked},
			map[string]any{"secret_scanning": on, "secret_scanning_locked": locked},
		)
		if changes == nil {
			return nil
		}
		if on {
			err = user_model.DeleteUserSetting(ctx, org.ID, secretscan_model.OrgKey)
		} else {
			err = user_model.SetUserSetting(ctx, org.ID, secretscan_model.OrgKey, "false")
		}
		if err != nil {
			return err
		}
		if locked {
			err = user_model.SetUserSetting(ctx, org.ID, secretscan_model.OrgLockedKey, "true")
		} else {
			err = user_model.DeleteUserSetting(ctx, org.ID, secretscan_model.OrgLockedKey)
		}
		if err != nil {
			return err
		}
		// turning it on, or locking it on over repositories that turned it off: pushes while it was off were not scanned
		if on && (!before.On || locked && !before.Locked) {
			if err := secretscan_model.MarkRequeue(ctx, org.ID); err != nil {
				return err
			}
			marked = true
		}
		// the action key is a literal: TestActionCatalog finds it in the code
		return user_model.RecordOrg(ctx, "org.secret_scanning.changed", org, changes)
	})
	if err != nil {
		return err
	}
	if marked {
		requeue()
	}
	return nil
}

// requeueMarked hands the repositories marked by secretscan_model.MarkRequeue to the queue (they are still ready, in no
// trash and not switched off). The mark stays until the scan takes the repository, so a queue that drops it, or a
// restart, loses nothing: the cron task queues marked rows too. The queue drops a repository that is queued already,
// and a scan with nothing new reads no file; whether the tips are unchanged is not checked (it takes git per repository).
func requeueMarked(ctx context.Context, queue func(int64)) error {
	var after int64
	for {
		ids, err := secretscan_model.RequeuedRepoIDsAfter(ctx, after, requeueBatch)
		if err != nil {
			return err
		}
		for _, id := range ids {
			queue(id)
		}
		if len(ids) < requeueBatch {
			return nil
		}
		after = ids[len(ids)-1]
	}
}

// updateSettings reads the two stored site settings under a lock, lets change edit them (it returns which of the
// two it changed) and stores the changed ones with who and when, in one SetSettings call: one audit entry
// (admin.setting.changed), then runs inTx (if any) in the same transaction. It reports whether anything was stored.
func updateSettings(ctx context.Context, doer *user_model.User, change func(*setting.SecretScanningState, *setting.SecretScanningConfig) (state, cfg bool), inTx func(context.Context) error) (stored bool, err error) {
	stateKey, cfgKey := setting.Config().SecretScanning.DynKey(), setting.Config().SecretScanningConfig.DynKey()
	err = db.WithTx(ctx, func(ctx context.Context) error {
		var state setting.SecretScanningState
		var cfg setting.SecretScanningConfig
		// a row that doesn't exist can't be locked on PostgreSQL and MySQL: create both first (in key order, as
		// SetSettings locks them), then lock
		for _, key := range slices.Sorted(slices.Values([]string{stateKey, cfgKey})) {
			if err := system_model.EnsureSetting(ctx, key); err != nil {
				return err
			}
		}
		if err := readLocked(ctx, cfgKey, &cfg); err != nil {
			return err
		}
		if err := readLocked(ctx, stateKey, &state); err != nil {
			return err
		}
		stateChanged, cfgChanged := change(&state, &cfg)
		values := map[string]string{}
		now := time.Now().Unix()
		if stateChanged {
			state.UpdatedBy, state.UpdatedUnix = doer.ID, now
			v, err := json.Marshal(state)
			if err != nil {
				return err
			}
			values[stateKey] = string(v)
		}
		if cfgChanged {
			cfg.UpdatedBy, cfg.UpdatedUnix = doer.ID, now
			v, err := json.Marshal(cfg)
			if err != nil {
				return err
			}
			values[cfgKey] = string(v)
		}
		if len(values) == 0 {
			return nil
		}
		stored = true
		if err := system_model.SetSettings(ctx, values); err != nil {
			return err
		}
		if inTx != nil {
			return inTx(ctx) // in the same transaction: the setting and what follows from it stand or fall together
		}
		return nil
	})
	if err != nil || !stored {
		return false, err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return true, nil
}

// readLocked reads a stored setting and locks its row until the transaction ends. A value that can't be parsed reads as
// not stored (the page showed the app.ini values meanwhile), so the save replaces it.
func readLocked[T any](ctx context.Context, key string, into *T) error {
	raw, has, err := system_model.GetSettingForUpdate(ctx, key)
	if err != nil || !has || raw == "" {
		return err
	}
	if json.Unmarshal([]byte(raw), into) != nil {
		log.Error("%s can't be parsed; the save replaces it", key)
		var zero T
		*into = zero
	}
	return nil
}

// SaveSwitches stores the site switch, the generic rule and the text scan (the first form of the Site administration page). A value
// that is what is in force already is not stored again. Turning the site on queues the scanned repositories; turning
// the text scan on also makes every repository's text scan start again (text written while it was off).
func SaveSwitches(ctx context.Context, doer *user_model.User, enabled, generic, scanText bool) (changed bool, err error) {
	turnedOn, textOn := false, false
	changed, err = updateSettings(ctx, doer, func(state *setting.SecretScanningState, cfg *setting.SecretScanningConfig) (bool, bool) {
		stateChanged, cfgChanged := false, false
		if state.Enabled() != enabled {
			state.Mode, stateChanged, turnedOn = "off", true, enabled
			if enabled {
				state.Mode = "on"
			}
		}
		if cfg.Merge().GenericRules != generic {
			cfg.GenericRules, cfgChanged = &generic, true
		}
		if cfg.Merge().ScanText != scanText {
			cfg.ScanText, cfgChanged, textOn = &scanText, true, scanText
		}
		return stateChanged, cfgChanged
	}, func(ctx context.Context) error {
		if textOn {
			if err := secretscan_model.ResetTextScans(ctx, 0); err != nil {
				return err
			}
		}
		if !turnedOn {
			return nil
		}
		return secretscan_model.MarkRequeue(ctx, 0)
	})
	if err != nil {
		return false, err
	}
	if changed && turnedOn {
		log.Info("Secret scanning turned on by %s", doer.Name)
	}
	if changed && (turnedOn || textOn) {
		requeue()
	}
	return changed, nil
}

// SaveLimits stores the limits (the second form): every limit named in limits gets its value, the ones equal to the
// app.ini value are removed from the stored settings, the others are kept. The values are checked against the
// bounds (an error names the first limit outside them, by SecretScanningLimit.Name via *LimitError).
func SaveLimits(ctx context.Context, doer *user_model.User, limits map[string]int64) (changed bool, err error) {
	for _, l := range setting.SecretScanningLimits {
		if v, ok := limits[l.Name]; ok {
			if err := l.Check(v); err != nil {
				return false, &LimitError{Limit: l}
			}
		}
	}
	return updateSettings(ctx, doer, func(_ *setting.SecretScanningState, cfg *setting.SecretScanningConfig) (bool, bool) {
		next := maps.Clone(cfg.Limits)
		if next == nil {
			next = map[string]int64{}
		}
		for _, l := range setting.SecretScanningLimits {
			v, ok := limits[l.Name]
			if !ok {
				continue
			}
			if v == l.Get(&setting.SecretScanning) {
				delete(next, l.Name)
			} else {
				next[l.Name] = v
			}
		}
		if maps.Equal(next, cfg.Limits) || (len(next) == 0 && len(cfg.Limits) == 0) {
			return false, false
		}
		cfg.Limits = next
		if len(next) == 0 {
			cfg.Limits = nil
		}
		return false, true
	}, nil)
}

// LimitError is a limit outside its bounds.
type LimitError struct {
	Limit setting.SecretScanningLimit
}

func (e *LimitError) Error() string {
	return e.Limit.Check(e.Limit.Min - 1).Error()
}
