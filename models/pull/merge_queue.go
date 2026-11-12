// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"fmt"
	"strings"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// MergeQueueBranchPrefix is the branch namespace of the merge queue's builds; only the queue writes it.
const MergeQueueBranchPrefix = "merge-queue/"

// IsMergeQueueBranch reports whether name is a branch of the merge queue's builds, or the name that would block them
// (git can't have a branch merge-queue and branches below it).
func IsMergeQueueBranch(name string) bool {
	return strings.HasPrefix(name, MergeQueueBranchPrefix) || name == strings.TrimSuffix(MergeQueueBranchPrefix, "/")
}

// MergeQueueStatus is the state of a merge queue entry.
type MergeQueueStatus int

const (
	MergeQueueWaiting  MergeQueueStatus = iota // not built yet, or to be built again
	MergeQueueBuilding                         // built at TempCommitID, its checks run there
)

// MergeQueueEntry is a pull request in the merge queue of its base branch. An entry is deleted when the pull request
// leaves the queue; the timeline of the pull request records why.
type MergeQueueEntry struct {
	ID            int64                 `xorm:"pk autoincr"`
	RepoID        int64                 `xorm:"INDEX(queue) NOT NULL"`
	BaseBranch    string                `xorm:"INDEX(queue) VARCHAR(255) NOT NULL"`
	PullID        int64                 `xorm:"UNIQUE NOT NULL"`
	Position      int64                 `xorm:"NOT NULL"`
	Status        MergeQueueStatus      `xorm:"NOT NULL DEFAULT 0"`
	MergeStyle    repo_model.MergeStyle `xorm:"VARCHAR(30) NOT NULL"`
	BuildStyle    repo_model.MergeStyle `xorm:"VARCHAR(30) NOT NULL DEFAULT ''"` // the style the build was made with ("" = not built)
	DeleteBranch  bool                  `xorm:"NOT NULL DEFAULT false"`
	SkipForward   bool                  `xorm:"NOT NULL DEFAULT false"` // not merged forward (services/mergeforward)
	Forced        bool                  `xorm:"NOT NULL DEFAULT false"` // an admin added it skipping the branch protections exempt for admins
	BuildFailures int                   `xorm:"NOT NULL DEFAULT 0"`     // failed builds in a row
	MergingUnix   timeutil.TimeStamp    `xorm:"NOT NULL DEFAULT 0"`     // when its build started being pushed to the branch (0 = not): it can't be removed by hand
	HeadCommitID  string                `xorm:"VARCHAR(64) NOT NULL"`   // the head of the pull request when it was added
	BaseCommitID  string                `xorm:"VARCHAR(64)"`            // what the build was made on: the branch or the entry ahead
	TempCommitID  string                `xorm:"INDEX VARCHAR(64)"`      // the build: base + this pull request
	EnqueuedByID  int64                 `xorm:"NOT NULL"`
	EnqueuedUnix  timeutil.TimeStamp    `xorm:"created"`
	StartedUnix   timeutil.TimeStamp    `xorm:"NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(MergeQueueEntry))
}

// TempBranch is the branch the build of e is pushed to.
func (e *MergeQueueEntry) TempBranch() string {
	return fmt.Sprintf("%s%s/%d", MergeQueueBranchPrefix, e.BaseBranch, e.ID)
}

// ErrAlreadyInMergeQueue is returned when a pull request is added to the queue twice.
type ErrAlreadyInMergeQueue struct {
	PullID int64
}

func (err ErrAlreadyInMergeQueue) Error() string {
	return fmt.Sprintf("pull request is already in the merge queue [pull_id: %d]", err.PullID)
}

// AddToMergeQueue appends e to the end of the queue of its repository and base branch.
func AddToMergeQueue(ctx context.Context, e *MergeQueueEntry) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if exist, err := db.GetEngine(ctx).Exist(&MergeQueueEntry{PullID: e.PullID}); err != nil {
			return err
		} else if exist {
			return ErrAlreadyInMergeQueue{PullID: e.PullID}
		}
		var last int64
		if _, err := db.GetEngine(ctx).Table("merge_queue_entry").Where("repo_id = ? AND base_branch = ?", e.RepoID, e.BaseBranch).
			Select("COALESCE(MAX(position), 0)").Get(&last); err != nil {
			return err
		}
		e.Position = last + 1
		e.Status = MergeQueueWaiting
		_, err := db.GetEngine(ctx).Insert(e)
		return err
	})
}

// GetMergeQueueEntryByPullID returns the queue entry of the pull request, nil if it is not queued.
func GetMergeQueueEntryByPullID(ctx context.Context, pullID int64) (*MergeQueueEntry, error) {
	e := &MergeQueueEntry{}
	if has, err := db.GetEngine(ctx).Where("pull_id = ?", pullID).Get(e); err != nil || !has {
		return nil, err
	}
	return e, nil
}

// FindMergeQueue returns the queue of the branch in order.
func FindMergeQueue(ctx context.Context, repoID int64, branch string) ([]*MergeQueueEntry, error) {
	entries := make([]*MergeQueueEntry, 0, 5)
	return entries, db.GetEngine(ctx).Where("repo_id = ? AND base_branch = ?", repoID, branch).Asc("position", "id").Find(&entries)
}

// FindMergeQueueRepoIDs returns the repositories with a merge queue entry or a rule that requires a merge queue: a
// repository rule, or a project or organization rule (every repository of the organization).
func FindMergeQueueRepoIDs(ctx context.Context) ([]int64, error) {
	ids := make([]int64, 0, 10)
	return ids, db.GetEngine(ctx).Table("repository").Where(builder.In("id", builder.Select("repo_id").From("merge_queue_entry")).
		Or(builder.In("id", builder.Select("repo_id").From("protected_branch").Where(builder.Eq{"require_merge_queue": true}.And(builder.Neq{"repo_id": 0})))).
		Or(builder.In("owner_id", builder.Select("org_id").From("protected_branch").Where(builder.Eq{"require_merge_queue": true, "repo_id": 0})))).
		Cols("id").Find(&ids)
}

// MergeQueueKey names the queue of a branch.
type MergeQueueKey struct {
	RepoID     int64
	BaseBranch string
}

// FindMergeQueueKeys returns every branch with a queue.
func FindMergeQueueKeys(ctx context.Context) ([]MergeQueueKey, error) {
	keys := make([]MergeQueueKey, 0, 10)
	return keys, db.GetEngine(ctx).Table("merge_queue_entry").Select("repo_id, base_branch").GroupBy("repo_id, base_branch").Find(&keys)
}

// FindMergeQueueKeysByTempCommit returns the queues of repoID with a build at sha.
func FindMergeQueueKeysByTempCommit(ctx context.Context, repoID int64, sha string) ([]MergeQueueKey, error) {
	keys := make([]MergeQueueKey, 0, 1)
	return keys, db.GetEngine(ctx).Table("merge_queue_entry").Select("repo_id, base_branch").
		Where("repo_id = ? AND temp_commit_id = ?", repoID, sha).GroupBy("repo_id, base_branch").Find(&keys)
}

// FindMergeQueueKeysOfRepo returns the branches of repoID with a queue.
func FindMergeQueueKeysOfRepo(ctx context.Context, repoID int64) ([]MergeQueueKey, error) {
	keys := make([]MergeQueueKey, 0, 1)
	return keys, db.GetEngine(ctx).Table("merge_queue_entry").Select("repo_id, base_branch").
		Where("repo_id = ?", repoID).GroupBy("repo_id, base_branch").Find(&keys)
}

// DeleteMergeQueueEntry removes the entry; false if it was removed meanwhile.
func DeleteMergeQueueEntry(ctx context.Context, id int64) (bool, error) {
	n, err := db.GetEngine(ctx).ID(id).Delete(&MergeQueueEntry{})
	return n > 0, err
}

// StartMergeQueueBuild records the build of a waiting entry; false if the entry is no longer waiting.
func StartMergeQueueBuild(ctx context.Context, id int64, baseCommitID, tempCommitID string, style repo_model.MergeStyle) (bool, error) {
	n, err := db.GetEngine(ctx).Exec("UPDATE merge_queue_entry SET status = ?, base_commit_id = ?, temp_commit_id = ?, build_style = ?, started_unix = ?, build_failures = 0 WHERE id = ? AND status = ?",
		MergeQueueBuilding, baseCommitID, tempCommitID, string(style), timeutil.TimeStampNow(), id, MergeQueueWaiting)
	if err != nil {
		return false, err
	}
	rows, err := n.RowsAffected()
	return rows > 0, err
}

// AddMergeQueueBuildFailure counts a failed build of the entry and returns the failures in a row
func AddMergeQueueBuildFailure(ctx context.Context, id int64) (int, error) {
	if _, err := db.GetEngine(ctx).Exec("UPDATE merge_queue_entry SET build_failures = build_failures + 1 WHERE id = ?", id); err != nil {
		return 0, err
	}
	e := &MergeQueueEntry{}
	_, err := db.GetEngine(ctx).ID(id).Cols("build_failures").Get(e)
	return e.BuildFailures, err
}

// ResetMergeQueueBuilds makes the entries wait to be built again.
func ResetMergeQueueBuilds(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := db.GetEngine(ctx).Where(builder.In("id", ids)).Cols("status", "base_commit_id", "temp_commit_id", "build_style", "started_unix", "merging_unix").
		Update(&MergeQueueEntry{Status: MergeQueueWaiting})
	return err
}

// StartMergeQueueMerge marks the entry as being merged at its build tempCommitID; false if it was removed or built
// again meanwhile.
func StartMergeQueueMerge(ctx context.Context, id int64, tempCommitID string) (bool, error) {
	n, err := db.GetEngine(ctx).Exec("UPDATE merge_queue_entry SET merging_unix = ? WHERE id = ? AND status = ? AND temp_commit_id = ? AND merging_unix = 0",
		timeutil.TimeStampNow(), id, MergeQueueBuilding, tempCommitID)
	if err != nil {
		return false, err
	}
	if rows, err := n.RowsAffected(); err != nil || rows > 0 {
		return rows > 0, err
	}
	// a merge of this build already started (on a server that stopped, or another one): the push decides
	return db.GetEngine(ctx).Where("id = ? AND status = ? AND temp_commit_id = ? AND merging_unix <> 0", id, MergeQueueBuilding, tempCommitID).
		Exist(&MergeQueueEntry{})
}

// DeleteMergeQueueEntryUnlessMerging removes the entry unless it is being merged; false if it wasn't removed.
func DeleteMergeQueueEntryUnlessMerging(ctx context.Context, id int64) (bool, error) {
	n, err := db.GetEngine(ctx).Where("id = ? AND merging_unix = 0", id).Delete(&MergeQueueEntry{})
	return n > 0, err
}
