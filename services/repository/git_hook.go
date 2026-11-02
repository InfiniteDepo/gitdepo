// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/git"
)

// UpdateGitHook sets the content of the server-side hook of repo (empty removes it) and records
// repo.git_hook.updated with its name and whether it is active, never its content; nothing when it doesn't change.
func UpdateGitHook(ctx context.Context, repo *repo_model.Repository, hook *git.Hook, content string) error {
	active := strings.TrimSpace(content) != ""
	if active == hook.IsActive && (!active || strings.ReplaceAll(content, "\r", "") == hook.Content) {
		return nil
	}
	hook.Content = content
	// the file write is last, so that a failed record writes nothing
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := repo_model.RecordRepoTarget(ctx, repo, audit_model.Event{
			Action: "repo.git_hook.updated", TargetType: "git_hook", TargetName: hook.Name(),
			Data: map[string]any{"name": hook.Name(), "active": active},
		}); err != nil {
			return err
		}
		return hook.Update()
	})
}
