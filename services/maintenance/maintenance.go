// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package maintenance

import (
	"context"
	"errors"
	"slices"
	"time"

	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
)

// ErrSetByConfig is returned when [maintenance] MODE in app.ini decides the state.
var ErrSetByConfig = errors.New("maintenance mode is set by the configuration file")

// Set stores the maintenance state. A nil doer means the command line. A zero until means no end time.
func Set(ctx context.Context, doer *user_model.User, mode, message string, until time.Time) error {
	if setting.GetMaintenance(ctx).FromConfig {
		return ErrSetByConfig
	}
	if !slices.Contains(setting.MaintenanceModes, mode) {
		return util.NewInvalidArgumentErrorf("invalid maintenance mode %q", mode)
	}
	if len(message) > 255 {
		return util.NewInvalidArgumentErrorf("the message must be at most 255 characters")
	}
	s := setting.MaintenanceState{Mode: mode, Message: message, SetByName: "(command line)"}
	if !until.IsZero() {
		if !until.After(time.Now()) {
			return util.NewInvalidArgumentErrorf("the end time must be in the future")
		}
		s.Until = until.Unix()
	}
	if doer != nil {
		s.SetByID, s.SetByName = doer.ID, doer.Name
	}
	v, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().Maintenance.DynKey(): string(v)}); err != nil {
		return err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return nil
}
