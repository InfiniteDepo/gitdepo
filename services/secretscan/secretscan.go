// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package secretscan looks for secrets in the commits of every repository and its wiki and stores alerts
// (models/secretscan). A scan reads the commits of all refs that the stored scan state doesn't cover, so the first
// scan reads the whole history and every later one only what is new. Scans run from a unique queue of repository IDs,
// started by pushes, pull requests, migrations, forks, transfers and wiki changes, and by a cron task for
// repositories that were never scanned or whose scan has to go on or try again.
//
// One queue item is one slice (see Scan): one pass of `git log --raw`, oldest commits first, that ends at a commit
// boundary at a limit and stores the heads of the commits handled as done tips with their alerts. A commit that alone
// is over the limits is scanned as far as it fits, the rest is counted as a hole. The repository, its wiki and
// refs/pull/* (which any reader can write) have a state row each. What only a ref to a tree or a file reaches is not
// scanned.
package secretscan

import (
	"context"
	"errors"
	"sync"
	"time"

	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/log"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/repository"
	"forgejo.org/modules/timeutil"
	notify_service "forgejo.org/services/notify"
	repo_service "forgejo.org/services/repository"
)

// cronBatch is the most repositories one run of the cron task queues
const cronBatch = 500

var (
	scanQueue *queue.WorkerPoolQueue[int64]
	// scanSlots counts the scans running in this process (acquireSlot); secret scans have their own, so a long
	// backfill never holds up the dependency graph scans
	scanSlots struct {
		sync.Mutex
		running int
		freed   chan struct{} // closed and replaced when a slot is given back
	}
)

// Init starts the queue and listens for changes. Both are always set up, whatever the switches say: they are read
// when something happens and again when a scan runs, so turning secret scanning on or off needs no restart.
func Init() error {
	notify_service.RegisterNotifier(&notifier{})
	scanQueue = queue.CreateUniqueQueue(graceful.GetManager().ShutdownContext(), "secret_scanning", handler)
	if scanQueue == nil {
		return errors.New("unable to create secret_scanning queue")
	}
	go graceful.GetManager().RunWithCancel(scanQueue)
	textQueue = queue.CreateUniqueQueue(graceful.GetManager().ShutdownContext(), "secret_scanning_text", textHandler)
	if textQueue == nil {
		return errors.New("unable to create secret_scanning_text queue")
	}
	go graceful.GetManager().RunWithCancel(textQueue)
	repo_service.TextUnitsTurnedOn = EnqueueIfEnabled // its text scan was reset in the change of units
	requeue()                                         // the repositories a switch marked before a stop or a crash: the queue is ready, whether or not the cron task is on
	return nil
}

type notifier struct {
	notify_service.NullNotifier
}

func (*notifier) PushCommits(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, _ *repository.PushUpdateOptions, _ *repository.PushCommits) {
	EnqueueIfEnabled(ctx, repo)
}

func (*notifier) SyncPushCommits(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, _ *repository.PushUpdateOptions, _ *repository.PushCommits) {
	EnqueueIfEnabled(ctx, repo)
}

// MigrateRepository: a migrated or mirrored repository arrives without a push.
func (*notifier) MigrateRepository(ctx context.Context, _, _ *user_model.User, repo *repo_model.Repository) {
	EnqueueIfEnabled(ctx, repo)
}

// TransferRepository: the new owner's switch decides now; a scan that started before the transfer is discarded.
func (*notifier) TransferRepository(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, _ string) {
	EnqueueIfEnabled(ctx, repo)
}

// ForkRepository: a fork shares every object of its parent, so when the parent's scan is complete the fork starts
// from the parent's scanned tips instead of reading the whole history again. The fork gets no alerts of its own for
// what the parent already holds.
func (*notifier) ForkRepository(ctx context.Context, _ *user_model.User, parent, fork *repo_model.Repository) {
	if !Enabled(ctx, fork) {
		return
	}
	if p, err := secretscan_model.GetScan(ctx, parent.ID, secretscan_model.KindRepo); err != nil {
		log.Error("secret scanning: read the scan state of repository %d: %v", parent.ID, err)
	} else if p != nil && p.Status == secretscan_model.StatusOK {
		s := &secretscan_model.Scan{RepoID: fork.ID, Kind: secretscan_model.KindRepo, ScannedTips: p.ScannedTips, Status: secretscan_model.StatusOK, SkippedLarge: p.SkippedLarge}
		if err := secretscan_model.Save(ctx, nil, s); err != nil && !errors.Is(err, secretscan_model.ErrScanMoved) {
			log.Error("secret scanning: store the inherited scan state of repository %d: %v", fork.ID, err)
		}
	}
	Enqueue(fork.ID)
}

// NewPullRequest and PullRequestSynchronized: the head of a pull request from a fork, and of an AGit push, is a ref
// of the base repository that no push event names.
func (*notifier) NewPullRequest(ctx context.Context, pr *issues_model.PullRequest, _ []*user_model.User) {
	if pr.Issue == nil {
		_ = pr.LoadIssue(ctx)
	}
	var poster int64
	if pr.Issue != nil {
		poster = pr.Issue.PosterID
	}
	enqueueIssueText(ctx, pr.IssueID, poster) // its title and body
	enqueuePullRequest(ctx, pr)
}

func (*notifier) PullRequestSynchronized(ctx context.Context, _ *user_model.User, pr *issues_model.PullRequest) {
	enqueuePullRequest(ctx, pr)
}

func enqueuePullRequest(ctx context.Context, pr *issues_model.PullRequest) {
	if err := pr.LoadBaseRepo(ctx); err != nil {
		log.Error("secret scanning: load the base repository of pull request %d: %v", pr.ID, err)
		return
	}
	EnqueueIfEnabled(ctx, pr.BaseRepo)
}

// NewWikiPage and EditWikiPage: a web edit of the wiki. A git push to the wiki calls EnqueueIfEnabled from the hook.
func (*notifier) NewWikiPage(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, _, _ string) {
	EnqueueIfEnabled(ctx, repo)
}

func (*notifier) EditWikiPage(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, _, _ string) {
	EnqueueIfEnabled(ctx, repo)
}

// EnqueueIfEnabled queues a scan of the repository when secret scanning is on for it.
func EnqueueIfEnabled(ctx context.Context, repo *repo_model.Repository) {
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
	if err := pushQueue(repoID); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
		log.Error("secret scanning: queue repository %d: %v", repoID, err)
	}
}

// pushQueue is a variable so that tests can make the queue answer "already queued".
var pushQueue = func(repoID int64) error { return scanQueue.Push(repoID) }

// stuckAfter is how long a repository may stay marked while the unique queue keeps saying it is queued, before the
// cron task scans it directly: the queue writes its unique set and its list separately, so a kill between the two
// leaves an entry in the set that no item stands for, and every later push is refused as a duplicate. maxDirectScans
// bounds the direct scans of one cron run.
const (
	stuckAfter     = time.Hour
	maxDirectScans = 10
)

// markedSince is when this process first found a repository without scan state "already queued" at the cron task (a
// repository with scan state keeps that time in its row, so a restart does not add an hour).
var markedSince = struct {
	sync.Mutex
	at map[int64]time.Time
}{at: map[int64]time.Time{}}

// enqueueRecover queues a repository for the cron task (a marked one, or one that has no scan state or is due). When
// the queue says it is queued already and that has been so for stuckAfter, it scans the repository here instead (Scan
// takes the same per-repository lock as the worker) and logs it. direct counts the direct scans of this run. The
// queue's stale unique entry itself stays: neither modules/queue nor levelqueue can remove one key, so only clearing the
// queue removes it, and until then every push to this repository is dropped as a duplicate and the cron task scans it.
func enqueueRecover(ctx context.Context, id int64, direct *int) {
	if scanQueue == nil || !SiteEnabled(ctx) {
		return
	}
	err := pushQueue(id)
	if !errors.Is(err, queue.ErrAlreadyInQueue) {
		if err != nil {
			log.Error("secret scanning: queue repository %d: %v", id, err)
		}
		return // queued: the scan that runs clears what was noted
	}
	now := timeutil.TimeStampNow()
	since, hasRow, err := secretscan_model.MarkQueueStuck(ctx, id, now)
	if err != nil {
		log.Error("secret scanning: note that repository %d is stuck in the queue: %v", id, err)
		return
	}
	if !hasRow {
		markedSince.Lock()
		first, ok := markedSince.at[id]
		if !ok {
			markedSince.at[id] = now.AsTime()
		}
		markedSince.Unlock()
		if !ok {
			return
		}
		since = timeutil.TimeStamp(first.Unix())
	}
	if int64(now)-int64(since) < int64(stuckAfter/time.Second) || *direct >= maxDirectScans {
		return
	}
	*direct++
	log.Warn("secret scanning: repository %d has been waiting in the queue for %s and the queue says it is queued: scanning it directly", id, time.Duration(int64(now)-int64(since))*time.Second)
	if err := Scan(ctx, id); err != nil {
		log.Error("secret scanning: direct scan of repository %d: %v", id, err)
	}
}

// forgetStuck clears the note that the repository's queue entry was stuck: a scan of it is running.
func forgetStuck(ctx context.Context, id int64) {
	markedSince.Lock()
	delete(markedSince.at, id)
	markedSince.Unlock()
	if err := secretscan_model.ClearQueueStuck(ctx, id); err != nil {
		log.Error("secret scanning: clear the stuck note of repository %d: %v", id, err)
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
			log.Error("secret scanning: scan of repository %d: %v", id, err)
		}
	}
	return unhandled
}

// EnqueueUnscanned queues the repositories that have no scan state (empty ones too: their wiki may hold a secret) or a
// state of either kind (a wiki's too) whose retry time has come: a failed scan after its backoff, or a scan that a
// limit stopped (which goes on from the tips it stored). Repositories secret scanning is off for are left out. It
// queues 500 per call; the next call takes the next ones once these are scanned. The repositories a switch that turned
// on marked (requeueMarked) are queued all at once, outside that limit, so a restart doesn't spread them over hours.
func EnqueueUnscanned(ctx context.Context) error {
	if !SiteEnabled(ctx) {
		return nil
	}
	ids, err := secretscan_model.UnscannedRepoIDs(ctx, timeutil.TimeStampNow(), cronBatch)
	if err != nil {
		return err
	}
	direct := 0
	for _, id := range ids {
		enqueueRecover(ctx, id, &direct)
	}
	return requeueMarked(ctx, func(id int64) { enqueueRecover(ctx, id, &direct) })
}
