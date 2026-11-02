// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"forgejo.org/models/perm"
	"forgejo.org/models/unit"
	"forgejo.org/modules/json"
)

// TokenPermissions is what the automatic token of a task may do in the task's own repository, per unit; a unit
// that isn't listed gets nothing.
type TokenPermissions map[unit.Type]perm.AccessMode

// Encode returns the value of ActionTask.TokenPermissions: empty only for nil (no `permissions:` and the default
// `write`), so that an explicit block that grants nothing never reads back as the legacy permissions.
func (p TokenPermissions) Encode() string {
	if p == nil {
		return ""
	}
	b, _ := json.Marshal(p)
	return string(b)
}

// GetTokenPermissions returns nil for a task without token permissions (every unit at write, read for a fork pull
// request, as before `permissions:` was supported). A value that doesn't decode grants nothing.
func (task *ActionTask) GetTokenPermissions() (TokenPermissions, error) {
	if task.TokenPermissions == "" {
		return nil, nil //nolint:nilnil // nil is the legacy permissions
	}
	var p TokenPermissions
	if err := json.Unmarshal([]byte(task.TokenPermissions), &p); err != nil || p == nil {
		return TokenPermissions{}, err
	}
	return p, nil
}
