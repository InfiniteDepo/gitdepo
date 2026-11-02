// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

// Trash settings: deleted repositories and organizations stay recoverable by site admins for RetentionDays.
var Trash = struct {
	RetentionDays  int    `ini:"RETENTION_DAYS"`
	RestoreHelpURL string `ini:"RESTORE_HELP_URL"`
	TrashUserRepos bool   `ini:"TRASH_USER_REPOS"`
}{
	RetentionDays:  365,
	TrashUserRepos: true,
}

func loadTrashFrom(rootCfg ConfigProvider) {
	mustMapSetting(rootCfg, "trash", &Trash)
	if Trash.RetentionDays < 0 {
		Trash.RetentionDays = 0
	}
}
