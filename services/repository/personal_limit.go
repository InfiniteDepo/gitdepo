// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"time"

	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
)

// PersonalRepoLocked reports whether repo's owner is at or over the size limit of personal repositories, for the
// web deletes that stay allowed then; an error is logged and reads as not locked.
func PersonalRepoLocked(ctx context.Context, repo *repo_model.Repository) bool {
	l, err := quota_model.GetPersonalRepoLimit(ctx, repo.OwnerID)
	if err != nil {
		log.Error("GetPersonalRepoLimit: %v", err)
	}
	return l.Reached()
}

// ShrinkPruneExpire is the age of the unreachable objects ShrinkAfterDelete prunes; tests set "now".
var ShrinkPruneExpire = "1.minute.ago"

// ShrinkAfterDelete runs git gc on repo and its wiki and measures them again after a web delete in a namespace
// that was locked by the size limit, so that the space the delete frees counts at once (unreachable objects stay
// on disk for two weeks otherwise). Objects younger than a minute are kept, so a concurrent delete's commit is
// never pruned before its ref is written. Failures are only logged.
func ShrinkAfterDelete(ctx context.Context, repo *repo_model.Repository, locked bool) {
	if !locked {
		return
	}
	for _, dir := range []string{repo.RepoPath(), repo.WikiPath()} {
		if isDir, _ := util.IsDir(dir); !isDir {
			continue
		}
		if _, _, err := git.NewCommand(ctx, "gc").AddOptionFormat("--prune=%s", ShrinkPruneExpire).RunStdString(&git.RunOpts{Dir: dir, Timeout: time.Duration(setting.Git.Timeout.GC) * time.Second}); err != nil {
			log.Error("git gc after a delete in %-v: %v", repo, err)
		}
	}
	if err := repo_module.UpdateRepoSize(ctx, repo); err != nil {
		log.Error("UpdateRepoSize after a delete in %-v: %v", repo, err)
	}
}
