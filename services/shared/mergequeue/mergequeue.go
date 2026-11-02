// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package mergequeue lets packages that services/mergequeue imports start a pass of a merge queue.
package mergequeue

import (
	"context"
	"errors"
	"strconv"
	"strings"

	pull_model "forgejo.org/models/pull"
	"forgejo.org/modules/log"
	"forgejo.org/modules/queue"
)

// Queue holds the branches whose merge queue is to be looked at again, see Key
var Queue *queue.WorkerPoolQueue[string]

// Key names the merge queue of a branch in Queue.
func Key(repoID int64, branch string) string {
	return strconv.FormatInt(repoID, 10) + ":" + branch
}

// ParseKey is the reverse of Key.
func ParseKey(key string) (int64, string, bool) {
	id, branch, ok := strings.Cut(key, ":")
	if !ok || branch == "" {
		return 0, "", false
	}
	repoID, err := strconv.ParseInt(id, 10, 64)
	return repoID, branch, err == nil
}

// Trigger makes the merge queue of the branch look at its entries again.
func Trigger(repoID int64, branch string) {
	if Queue == nil {
		return
	}
	if err := Queue.Push(Key(repoID, branch)); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
		log.Error("Unable to add the merge queue of %s in repository %d to the queue: %v", branch, repoID, err)
	}
}

// TriggerBySHA triggers the merge queues of the repository with a build at sha, after a status of sha changed.
func TriggerBySHA(ctx context.Context, repoID int64, sha string) {
	keys, err := pull_model.FindMergeQueueKeysByTempCommit(ctx, repoID, sha)
	if err != nil {
		log.Error("FindMergeQueueKeysByTempCommit: %v", err)
		return
	}
	for _, k := range keys {
		Trigger(k.RepoID, k.BaseBranch)
	}
}
