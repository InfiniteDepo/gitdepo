// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package convert

import (
	"context"

	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	api "forgejo.org/modules/structs"
)

// ToMergeGroupPayload is the payload of the merge_group event for the build of entry, which doer added to the queue
func ToMergeGroupPayload(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, entry *pull_model.MergeQueueEntry) (*api.MergeGroupPayload, error) {
	gitRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(ctx, repo)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	commit, err := gitRepo.GetCommit(entry.TempCommitID)
	if err != nil {
		return nil, err
	}
	return &api.MergeGroupPayload{
		Action: api.HookMergeGroupChecksRequested,
		MergeGroup: &api.MergeGroup{
			HeadSHA:    entry.TempCommitID,
			HeadRef:    git.BranchPrefix + entry.TempBranch(),
			BaseSHA:    entry.BaseCommitID,
			BaseRef:    git.BranchPrefix + entry.BaseBranch,
			HeadCommit: ToPayloadCommit(ctx, repo, commit),
		},
		Repository: ToRepo(ctx, repo, access_model.Permission{AccessMode: perm.AccessModeOwner}),
		Sender:     ToUser(ctx, doer, nil),
	}, nil
}
