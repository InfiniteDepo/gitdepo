// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"time"

	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
)

// SetPersonalRepoPolicy stores the site policy for personal repositories and the size limit of a user's personal
// repositories (bytes, 0 = off), and logs the change.
func SetPersonalRepoPolicy(ctx context.Context, doer *user_model.User, mode string, sizeLimit int64) error {
	switch mode {
	case setting.PersonalReposAllowed, setting.PersonalReposPrivateOnly, setting.PersonalReposDisabled:
	default:
		return util.NewInvalidArgumentErrorf("unknown personal repository policy %q", mode)
	}
	if sizeLimit < 0 {
		return util.NewInvalidArgumentErrorf("negative size limit")
	}
	oldState := setting.Config().PersonalRepos.Value(ctx)
	old, oldLimit := oldState.EffectiveMode(), oldState.EffectiveSizeLimit()
	v, err := json.Marshal(setting.PersonalReposState{Mode: mode, SizeLimit: sizeLimit, UpdatedBy: doer.ID, UpdatedUnix: time.Now().Unix()})
	if err != nil {
		return err
	}
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().PersonalRepos.DynKey(): string(v)}); err != nil {
		return err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	if old != mode {
		log.Info("Personal repository policy changed from %s to %s by %s", old, mode, doer.Name)
	}
	if oldLimit != sizeLimit {
		log.Info("Personal repository size limit changed from %d to %d bytes by %s", oldLimit, sizeLimit, doer.Name)
	}
	return nil
}
