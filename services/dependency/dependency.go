// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package dependency scans the manifests of a repository's default branch into its dependency graph and builds an
// SBOM from it. Scans run from a unique queue of repository IDs, started after a push to the default branch, after a
// change of the default branch and by a cron task for repositories that were never scanned.
package dependency

import (
	"context"
	"errors"
	"sync"
	"time"

	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/log"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/repository"
	"forgejo.org/modules/timeutil"
	notify_service "forgejo.org/services/notify"

	"xorm.io/builder"
)

const (
	// failedRetry is how long the cron task leaves a repository alone after a failed scan
	failedRetry = 24 * time.Hour
	cronBatch   = 500
)

var (
	scanQueue *queue.WorkerPoolQueue[int64]
	// scanSlots counts the scans and rematches running in this process (AcquireSlot)
	scanSlots struct {
		sync.Mutex
		running int
		freed   chan struct{} // closed and replaced when a slot is given back
	}

	// repoScans holds the repositories being scanned in this process: the unique queue forgets an ID once it is
	// popped, so a push during a scan queues the repository again, and the second scan must wait for the first.
	repoScans = struct {
		sync.Mutex
		running map[int64]*repoScan
	}{running: map[int64]*repoScan{}}
)

type repoScan struct {
	mu   sync.Mutex
	refs int
}

// LockRepoScan waits until no other scan or alert refresh of the repository runs in this process. Take it before a slot. The caller holds no database
// connection or transaction while it waits.
func LockRepoScan(repoID int64) (unlock func()) {
	repoScans.Lock()
	rs := repoScans.running[repoID]
	if rs == nil {
		rs = &repoScan{}
		repoScans.running[repoID] = rs
	}
	rs.refs++
	repoScans.Unlock()
	rs.mu.Lock()
	return func() {
		rs.mu.Unlock()
		repoScans.Lock()
		if rs.refs--; rs.refs == 0 {
			delete(repoScans.running, repoID)
		}
		repoScans.Unlock()
	}
}

// Init starts the queue and listens for pushes. Both are always set up, whatever the switches say: they are read
// when a push happens and again when a scan runs, so turning the dependency graph on or off needs no restart.
func Init() error {
	notify_service.RegisterNotifier(&notifier{})
	scanQueue = queue.CreateUniqueQueue(graceful.GetManager().ShutdownContext(), "dependency_graph", handler)
	if scanQueue == nil {
		return errors.New("unable to create dependency_graph queue")
	}
	go graceful.GetManager().RunWithCancel(scanQueue)
	return nil
}

type notifier struct {
	notify_service.NullNotifier
}

func (*notifier) PushCommits(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, opts *repository.PushUpdateOptions, _ *repository.PushCommits) {
	enqueueDefaultBranch(ctx, repo, opts.RefFullName)
}

func (*notifier) SyncPushCommits(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, opts *repository.PushUpdateOptions, _ *repository.PushCommits) {
	enqueueDefaultBranch(ctx, repo, opts.RefFullName)
}

// MigrateRepository: a migrated or mirrored repository arrives without a push.
func (*notifier) MigrateRepository(ctx context.Context, _, _ *user_model.User, repo *repo_model.Repository) {
	enqueueIfEnabled(ctx, repo)
}

func (*notifier) ChangeDefaultBranch(ctx context.Context, repo *repo_model.Repository) {
	enqueueIfEnabled(ctx, repo)
}

// TransferRepository: the new owner's switch decides now (an organization that is off or locks it, or none).
func (*notifier) TransferRepository(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, _ string) {
	ApplyRepo(ctx, repo.ID)
}

// ApplyRepo brings the stored rows of a repository in line with the switches after its owner changed (a transfer,
// a trash restore to a new owner): deleted at once when it is now off, queued when it needs a scan. Errors are
// logged; the cron task catches up.
func ApplyRepo(ctx context.Context, repoID int64) {
	if err := applyDependencyGraphState(ctx, builder.Eq{"repository.id": repoID}); err != nil {
		log.Error("dependency graph: apply the switches to repository %d after an owner change: %v", repoID, err)
	}
}

// enqueueDefaultBranch queues the repository if ref is its default branch: tags, other branches and refs like
// refs/for/* or refs/pull/* never start a scan.
func enqueueDefaultBranch(ctx context.Context, repo *repo_model.Repository, ref git.RefName) {
	if ref.IsBranch() && ref.BranchName() == repo.DefaultBranch {
		enqueueIfEnabled(ctx, repo)
	}
}

func enqueueIfEnabled(ctx context.Context, repo *repo_model.Repository) {
	if Enabled(ctx, repo) {
		Enqueue(repo.ID)
	}
}

// Enqueue queues a scan of the repository. A repository that is already queued isn't queued twice. It does nothing
// while the site switch is off; the scan checks every switch (Enabled) again before any work.
func Enqueue(repoID int64) {
	if scanQueue == nil || !SiteEnabled(graceful.GetManager().ShutdownContext()) {
		return
	}
	if err := scanQueue.Push(repoID); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
		log.Error("dependency graph: queue repository %d: %v", repoID, err)
	}
}

// EnqueueIfUnscanned queues a scan only for a repository that has no scan row at all; one whose scans fail is left
// to the cron, so a reader can't queue it again with every request.
func EnqueueIfUnscanned(ctx context.Context, repoID int64) {
	if scan, err := repo_model.GetRepoDependencyScan(ctx, repoID); err == nil && scan == nil {
		Enqueue(repoID)
	}
}

func handler(items ...int64) (unhandled []int64) {
	ctx := graceful.GetManager().ShutdownContext()
	for _, id := range items {
		if err := Scan(ctx, id); err != nil {
			if ctx.Err() != nil {
				unhandled = append(unhandled, id) // shutting down: kept for the next start
				continue
			}
			log.Error("dependency graph: scan of repository %d: %v", id, err)
		}
	}
	return unhandled
}

// EnqueueUnscanned queues the repositories that have no scan or whose default branch moved since the last one, in
// batches of 500 per call (the next call takes the next ones once these are scanned). A repository whose last scan
// failed waits a day. Repositories the dependency graph is off for are left out.
func EnqueueUnscanned(ctx context.Context) error {
	return enqueueUnscanned(ctx, nil)
}

// enqueueUnscanned is EnqueueUnscanned for the repositories that match scope (nil for all).
func enqueueUnscanned(ctx context.Context, scope builder.Cond) error {
	if !SiteEnabled(ctx) {
		return nil
	}
	ids, err := repo_model.UnscannedDependencyRepoIDs(ctx, timeutil.TimeStampNow().Add(-int64(failedRetry/time.Second)), scope, cronBatch)
	if err != nil {
		return err
	}
	for _, id := range ids {
		Enqueue(id)
	}
	return nil
}
