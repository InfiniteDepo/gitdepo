// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"strconv"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
)

// MaxRunRetentionDays is the largest retention time an organization or repository can set.
const MaxRunRetentionDays = 36500

const orgRunRetentionKey = "actions.run_retention_days"

// EffectiveRunRetentionDays is the number of days completed runs of a repository are kept: the shortest positive one
// of the repository's setting, its organization's setting, [actions] RUN_RETENTION_DAYS and RUN_RETENTION_MAX_DAYS.
// The settings of an organization and of the instance are ceilings, a repository can only shorten them. 0 keeps the
// runs forever.
func EffectiveRunRetentionDays(repoDays, orgDays int64) int64 {
	var days int64
	for _, d := range []int64{repoDays, orgDays, setting.Actions.RunRetentionDays, setting.Actions.RunRetentionMaxDays} {
		d = min(d, MaxRunRetentionDays) // the settings of the instance are not validated, keep the duration from overflowing
		if d > 0 && (days == 0 || d < days) {
			days = d
		}
	}
	return days
}

// RetentionCutoff returns the creation time before which a run kept for days is expired.
func RetentionCutoff(days int64) timeutil.TimeStamp {
	return timeutil.TimeStampNow().AddDuration(-time.Duration(days) * 24 * time.Hour)
}

// GetOrgRunRetentionDays returns the retention an organization set for its repositories, or 0.
func GetOrgRunRetentionDays(ctx context.Context, orgID int64) (int64, error) {
	v, err := user_model.GetUserSetting(ctx, orgID, orgRunRetentionKey)
	if err != nil {
		return 0, err
	}
	return parseRetentionDays(v), nil
}

// SetOrgRunRetentionDays stores the retention of an organization; 0 removes it.
func SetOrgRunRetentionDays(ctx context.Context, orgID, days int64) error {
	if days == 0 {
		return user_model.DeleteUserSetting(ctx, orgID, orgRunRetentionKey)
	}
	return user_model.SetUserSetting(ctx, orgID, orgRunRetentionKey, strconv.FormatInt(days, 10))
}

// RepoRunRetentionDays returns the effective retention of a repository.
func RepoRunRetentionDays(ctx context.Context, repo *repo_model.Repository) (int64, error) {
	var repoDays, orgDays int64
	if u, err := repo.GetUnit(ctx, unit.TypeActions); err == nil {
		repoDays = u.ActionsConfig().RunRetentionDays
	}
	if err := repo.LoadOwner(ctx); err != nil {
		return 0, err
	}
	if repo.Owner.IsOrganization() {
		var err error
		if orgDays, err = GetOrgRunRetentionDays(ctx, repo.OwnerID); err != nil {
			return 0, err
		}
	}
	return EffectiveRunRetentionDays(repoDays, orgDays), nil
}

// ParseRunRetentionDays parses a number of days from a form; empty means 0 (no setting).
func ParseRunRetentionDays(v string) (int64, bool) {
	if v == "" {
		return 0, true
	}
	days, err := strconv.ParseInt(v, 10, 64)
	return days, err == nil && days >= 0 && days <= MaxRunRetentionDays
}

// ParseOlderThanDays parses the number of days of "delete runs older than": a whole number from 1 to MaxRunRetentionDays.
func ParseOlderThanDays(v string) (int64, bool) {
	days, err := strconv.ParseInt(v, 10, 64)
	return days, err == nil && days >= 1 && days <= MaxRunRetentionDays
}

// parseRetentionDays reads a stored value, which is ignored if it is not valid.
func parseRetentionDays(v string) int64 {
	days, ok := ParseRunRetentionDays(v)
	if !ok {
		return 0
	}
	return days
}

// FindRunRetentionSettings returns the repository and organization retention settings, by repository ID and by
// organization ID, in one query each.
func FindRunRetentionSettings(ctx context.Context) (repoDays, orgDays map[int64]int64, err error) {
	var units []*repo_model.RepoUnit
	if err = db.GetEngine(ctx).Where("type = ? AND config LIKE ?", unit.TypeActions, "%RunRetentionDays%").Find(&units); err != nil {
		return nil, nil, err
	}
	repoDays = make(map[int64]int64, len(units))
	for _, u := range units {
		if d := u.ActionsConfig().RunRetentionDays; d > 0 && d <= MaxRunRetentionDays {
			repoDays[u.RepoID] = d
		}
	}

	var rows []struct {
		UserID       int64
		SettingValue string
	}
	if err = db.GetEngine(ctx).Table("user_setting").
		Join("INNER", "`user`", "`user`.id = user_setting.user_id").
		Where("user_setting.setting_key = ? AND `user`.type = ?", orgRunRetentionKey, user_model.UserTypeOrganization).
		Cols("user_setting.user_id", "user_setting.setting_value").Find(&rows); err != nil {
		return nil, nil, err
	}
	orgDays = make(map[int64]int64, len(rows))
	for _, r := range rows {
		if d := parseRetentionDays(r.SettingValue); d > 0 {
			orgDays[r.UserID] = d
		}
	}
	return repoDays, orgDays, nil
}
