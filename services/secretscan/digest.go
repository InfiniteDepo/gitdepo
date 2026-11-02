// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"time"

	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/mailer"
)

// digestMaxAge is how old a mark may be and still send its mail: a repository that was switched off for days
// would otherwise mail the alerts of whatever scan comes first after it is switched on again.
const digestMaxAge = 24 * time.Hour

// sendDigest is a variable so that tests can see it.
var sendDigest = mailer.SendSecretDigest

// MarkPush marks the repository for a digest mail after a push (the post-receive hook calls it before the push is
// handed to the notifiers, which queue the scan): the next scan that brings the pushed kind up to date mails the alerts
// it opened. kind is KindRepo for a branch or tag push, KindWiki for the wiki; ref and commit are what the mail names
// ("" for a wiki push). pusherID is the person who pushed, 0 for a deploy key or an Actions task. Nothing is marked
// while the repository was never scanned to its end (the first scan, a backfill), so those never mail. The digest only
// covers alerts that are new: an existing alert that a push sees again, or that a person reopens, sends none.
func MarkPush(ctx context.Context, repo *repo_model.Repository, pusherID int64, kind, ref, commit string) {
	if !Enabled(ctx, repo) {
		return
	}
	if _, err := secretscan_model.MarkNotify(ctx, repo.ID, pusherID, kind, ref, commit); err != nil {
		log.Error("secret scanning: mark repository %d for a digest: %v", repo.ID, err)
	}
}

// markText marks the repository for a digest of the alerts above boundary after a live scan of one text stored a new alert, and mails it when it is
// due: a text has no push, so nothing waits for a scan, except a code or wiki push marked earlier (that digest waits
// for its own scan, as ever). Backfills and rescans never get here.
func markText(ctx context.Context, repo *repo_model.Repository, boundary int64) {
	if !Enabled(ctx, repo) {
		return
	}
	if marked, err := secretscan_model.MarkNotifyText(ctx, repo.ID, boundary); err != nil {
		log.Error("secret scanning: mark repository %d for a digest of text: %v", repo.ID, err)
		return
	} else if !marked {
		return
	}
	states := map[string]kindState{}
	for _, kind := range []string{secretscan_model.KindRepo, secretscan_model.KindWiki} {
		states[kind] = readKindState(ctx, repo.ID, kind)
	}
	finishDigest(ctx, repo, readMark(ctx, repo.ID), states)
}

// notifyMark is the digest mark as the scan read it before it started.
type notifyMark struct {
	seq, alertID, pusherID int64
	kinds                  int
	after, last            timeutil.TimeStamp
	ref, commit            string
}

// kindState is where a scan pass left one kind of the repository: up to date, or not (a slice left, a failure
// backing off, a scan that was skipped), and whether it is failing.
type kindState struct{ current, failing bool }

// readMark returns the repository's digest mark, nil without one.
func readMark(ctx context.Context, repoID int64) *notifyMark {
	s, err := secretscan_model.GetScan(ctx, repoID, secretscan_model.KindRepo)
	if err != nil {
		log.Error("secret scanning: read the digest mark of repository %d: %v", repoID, err)
		return nil
	}
	if s == nil || s.NotifyAfterUnix == 0 {
		return nil
	}
	return &notifyMark{
		seq: s.NotifySeq, alertID: s.NotifyAlertID, pusherID: s.NotifyPusherID, kinds: s.NotifyKinds,
		after: s.NotifyAfterUnix, last: s.NotifyLastUnix, ref: s.NotifyRef, commit: s.NotifyCommit,
	}
}

// readKindState tells whether the scan row of a kind is up to date after this pass: its last write completed and
// nothing is backing off.
func readKindState(ctx context.Context, repoID int64, kind string) kindState {
	s, err := secretscan_model.GetScan(ctx, repoID, kind)
	if err != nil || s == nil {
		return kindState{}
	}
	return kindState{current: s.RetryUnix == 0, failing: s.FailCount > 0}
}

// finishDigest runs after a pass over a repository. It waits (keeps the mark) until the kinds the push touched (code
// for a branch or tag push, the wiki for a wiki push; never the pull refs) are up to date, then takes the mark once
// (compared with the sequence read before the scan started, so a push that came meanwhile keeps its mark for the next
// scan) and, only after that succeeded and nothing is in a transaction, mails the new alerts. A wiki that keeps failing
// does not hold back the digest of a code push. A mark is dropped, with a warning, after digestMaxAge, and a digest
// that would come within DigestMinInterval of the last one waits (a held digest is mailed by the next pass, so it can
// be up to about 75 minutes late: 15 minutes, then the cron task's hourly pass). A mail that fails to go out is not tried again:
// a digest is sent at most once.
func finishDigest(ctx context.Context, repo *repo_model.Repository, m *notifyMark, states map[string]kindState) {
	if m == nil {
		return
	}
	now := timeutil.TimeStampNow()
	// the newest alert this digest may hold, read before anything else and stored as the floor with the clear: an alert
	// that another server stores meanwhile is above it, so it is mailed once, next time
	upTo, err := secretscan_model.MaxAlertID(ctx, repo.ID)
	if err != nil {
		log.Error("secret scanning: digest of repository %d: %v", repo.ID, err)
		return
	}
	if int64(now)-int64(m.after) > int64(digestMaxAge/time.Second) {
		if took, err := secretscan_model.ClearNotify(ctx, repo.ID, m.seq, m.last, upTo); err == nil && took {
			log.Warn("secret scanning: the digest mark of repository %d is older than %s and is dropped without a mail: its scan did not catch up", repo.ID, digestMaxAge)
		}
		return
	}
	kinds := m.kinds
	if kinds&secretscan_model.DigestKindWiki != 0 && !repo.HasWiki() {
		// the wiki was turned off after the push: nothing of it is left to scan, so the code part is still mailed
		log.Warn("secret scanning: the wiki of repository %d is gone: the digest leaves out the wiki push", repo.ID)
		kinds &^= secretscan_model.DigestKindWiki
		if kinds&secretscan_model.DigestKindCode == 0 {
			_, _ = secretscan_model.ClearNotify(ctx, repo.ID, m.seq, m.last, upTo)
			return
		}
	}
	if kinds&(secretscan_model.DigestKindCode|secretscan_model.DigestKindWiki|secretscan_model.DigestKindText) == 0 {
		kinds |= secretscan_model.DigestKindCode
	}
	if kinds&secretscan_model.DigestKindCode != 0 && !states[secretscan_model.KindRepo].current {
		return // the code scan is yet to catch up: the pass that does mails
	}
	if kinds&secretscan_model.DigestKindWiki != 0 && !states[secretscan_model.KindWiki].current {
		if kinds&secretscan_model.DigestKindCode == 0 || !states[secretscan_model.KindWiki].failing {
			return
		}
		log.Warn("secret scanning: the wiki scan of repository %d is failing: the digest leaves out the wiki push", repo.ID)
		kinds &^= secretscan_model.DigestKindWiki
	}
	if m.last != 0 && int64(m.last) <= int64(now) && int64(now)-int64(m.last) < secretscan_model.DigestMinInterval { // a time in the future is no wait
		return // the next digest carries it
	}
	has, err := secretscan_model.HasAlertsAfter(ctx, repo.ID, m.alertID, upTo)
	if err != nil {
		log.Error("secret scanning: digest of repository %d: %v", repo.ID, err)
		return
	}
	sentAt := now
	if !has || !Enabled(ctx, repo) {
		sentAt = m.last // the push opened no alert, or scanning is off: no mail, no wait for the next one
	}
	took, err := secretscan_model.ClearNotify(ctx, repo.ID, m.seq, sentAt, upTo)
	if err != nil {
		log.Error("secret scanning: clear the digest mark of repository %d: %v", repo.ID, err)
		return
	}
	if !took || sentAt == m.last {
		return
	}
	// at most once: the mark is gone before this call, so a failure here is logged and the digest is not retried
	if err := sendDigest(ctx, repo, mailer.SecretDigestInput{Ref: m.ref, Commit: m.commit, PusherID: m.pusherID, AfterAlertID: m.alertID, UpToAlertID: upTo, Kinds: kinds}); err != nil {
		log.Error("secret scanning: digest of repository %d: %v", repo.ID, err)
	}
}
