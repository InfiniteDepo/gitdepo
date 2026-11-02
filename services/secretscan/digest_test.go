// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/modules/log"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/mailer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureDigests replaces the mailer with a list of what it was asked to send.
func captureDigests(t *testing.T) *[]mailer.SecretDigestInput {
	t.Helper()
	var got []mailer.SecretDigestInput
	t.Cleanup(test.MockVariableValue(&sendDigest, func(ctx context.Context, _ *repo_model.Repository, in mailer.SecretDigestInput) error {
		assert.False(t, db.InTransaction(ctx), "a digest is never mailed inside a transaction")
		got = append(got, in)
		return nil
	}))
	return &got
}

// A push marks the repository, the scan after it mails the alerts it opened once, and a push that opened none, the
// first scan and a scan that goes on in a later slice don't mail.
func TestDigestAfterPush(t *testing.T) {
	repo := enable(t)
	sent := captureDigests(t)
	w := newWork(t, repo)
	ctx := t.Context()

	// the first scan: the row doesn't exist yet, so nothing is marked and nothing is mailed
	MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c0")
	w.commit(map[string]string{"first.env": "T=" + token("first") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	assert.Empty(t, *sent, "the first scan never mails")
	assert.Zero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).NotifyAfterUnix)
	require.Len(t, alertsOf(t, repo.ID), 1)
	boundary := alertsOf(t, repo.ID)[0].ID

	// a push without a secret: the mark is cleared, nothing is mailed
	MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c1")
	assert.NotZero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).NotifyAfterUnix)
	w.commit(map[string]string{"plain.txt": "nothing\n"})
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	assert.Empty(t, *sent)
	assert.Zero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).NotifyAfterUnix, "the scan took the mark")

	// a push with a secret: one digest, with the boundary and the pusher
	MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c2")
	w.commit(map[string]string{"second.env": "T=" + token("second") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	require.Len(t, *sent, 1)
	assert.Equal(t, mailer.SecretDigestInput{Ref: "main", Commit: "c2", PusherID: 2, AfterAlertID: boundary, UpToAlertID: alertsOf(t, repo.ID)[len(alertsOf(t, repo.ID))-1].ID, Kinds: secretscan_model.DigestKindCode | secretscan_model.DigestWikiScanned}, (*sent)[0])
	require.NoError(t, Scan(ctx, repo.ID))
	require.NoError(t, Scan(ctx, repo.ID))
	assert.Len(t, *sent, 1, "at most once: the mark is gone")
}

func TestDigestMarkRules(t *testing.T) {
	repo := enable(t)
	sent := captureDigests(t)
	w := newWork(t, repo)
	ctx := t.Context()
	w.commit(map[string]string{"a.txt": "x\n"})
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	mark := func() *secretscan_model.Scan { return scanOf(t, repo.ID, secretscan_model.KindRepo) }

	t.Run("nothing is marked while scanning is off for the repository", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", true, repo.ID)
		require.NoError(t, err)
		off, err := repo_model.GetRepositoryByID(ctx, repo.ID)
		require.NoError(t, err)
		MarkPush(ctx, off, 2, secretscan_model.KindRepo, "main", "c")
		assert.Zero(t, mark().NotifyAfterUnix)
		_, err = db.GetEngine(ctx).Exec("UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", false, repo.ID)
		require.NoError(t, err)
	})

	noWait := func() { // the digests of the earlier subtests don't hold this one back
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET notify_last_unix = 0 WHERE repo_id = ?", repo.ID)
		require.NoError(t, err)
	}

	t.Run("a repository that was never scanned to its end is not marked", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET completed = ? WHERE repo_id = ?", false, repo.ID)
		require.NoError(t, err)
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c")
		assert.Zero(t, mark().NotifyAfterUnix)
		_, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET completed = ? WHERE repo_id = ?", true, repo.ID)
		require.NoError(t, err)
	})

	t.Run("a push that comes while a scan runs keeps its mark", func(t *testing.T) {
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c1")
		m := readMark(ctx, repo.ID)
		require.NotNil(t, m)
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c2") // after the scan read the mark
		w.commit(map[string]string{"b.env": "T=" + token("racing") + "\n"})
		w.pushDefault()
		finishDigest(ctx, repo, m, upToDate)
		assert.Empty(t, *sent, "the clear was refused")
		assert.NotZero(t, mark().NotifyAfterUnix)
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1, "the next scan mails it")
		assert.Equal(t, "c2", (*sent)[0].Commit)
	})

	t.Run("a push during the last slice of a scan under way is marked and mailed when the scan ends", func(t *testing.T) {
		*sent = nil
		noWait()
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET retry_unix = ? WHERE repo_id = ? AND kind = ?", time.Now().Unix()+3600, repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c3")
		require.NotZero(t, mark().NotifyAfterUnix, "a scan under way doesn't stop the marking")
		w.commit(map[string]string{"c.env": "T=" + token("slices") + "\n"})
		w.pushDefault()
		finishDigest(ctx, repo, readMark(ctx, repo.ID), map[string]kindState{secretscan_model.KindRepo: {}})
		assert.Empty(t, *sent)
		assert.NotZero(t, mark().NotifyAfterUnix, "the mark waits for the code scan")
		require.NoError(t, Scan(ctx, repo.ID))
		assert.Len(t, *sent, 1)
	})

	t.Run("a push during a failure backoff keeps the mark until the scan runs again", func(t *testing.T) {
		*sent = nil
		noWait()
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET retry_unix = ?, fail_count = 1 WHERE repo_id = ? AND kind = ?", time.Now().Unix()+3600, repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c3b")
		w.commit(map[string]string{"e.env": "T=" + token("backoff") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID)) // waits out its backoff: nothing scanned
		assert.Empty(t, *sent)
		assert.NotZero(t, mark().NotifyAfterUnix, "the mark is not taken by a pass that scanned nothing")
		_, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET retry_unix = ? WHERE repo_id = ? AND kind = ?", time.Now().Unix()-1, repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1, "the digest is sent")
		assert.Equal(t, "c3b", (*sent)[0].Commit)
	})

	t.Run("a wiki that keeps failing or a pull scan that never completes does not hold back a code digest", func(t *testing.T) {
		*sent = nil
		n := 0
		mk := func(kinds int) *notifyMark { // a fresh mark with these kinds, as the scan would read it
			noWait()
			MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c")
			_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET notify_kinds = ? WHERE repo_id = ? AND kind = ?", kinds, repo.ID, secretscan_model.KindRepo)
			require.NoError(t, err)
			n++ // an alert the push opened
			_, err = db.GetEngine(ctx).Insert(&secretscan_model.Alert{RepoID: repo.ID, Index: int64(1000 + n), RuleID: "github-token", Fingerprint: fmt.Sprintf("%064d", n)})
			require.NoError(t, err)
			return readMark(ctx, repo.ID)
		}
		const code, wiki = secretscan_model.DigestKindCode, secretscan_model.DigestKindWiki
		failingWiki := map[string]kindState{secretscan_model.KindRepo: {current: true}, secretscan_model.KindWiki: {failing: true}}
		// the pull row is never in the states: the pass doesn't wait for it
		finishDigest(ctx, repo, mk(code), failingWiki)
		require.Len(t, *sent, 1, "a code push doesn't wait for the wiki or the pull refs")
		assert.Equal(t, code, (*sent)[0].Kinds)

		finishDigest(ctx, repo, mk(code|wiki), failingWiki)
		require.Len(t, *sent, 2, "a code and a wiki push: the failing wiki is left out of the digest")
		assert.Equal(t, code, (*sent)[1].Kinds)

		finishDigest(ctx, repo, mk(wiki), failingWiki)
		assert.Len(t, *sent, 2, "a wiki push waits for its own scan")
		assert.NotZero(t, mark().NotifyAfterUnix)
		_, err := secretscan_model.ClearNotify(ctx, repo.ID, mark().NotifySeq, 0, 0)
		require.NoError(t, err)
	})

	t.Run("at most one digest per quarter of an hour, and the next one carries everything", func(t *testing.T) {
		*sent = nil
		noWait()
		t0 := time.Now().Truncate(time.Second)
		timeutil.MockSet(t0)
		defer timeutil.MockUnset()
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "d1")
		w.commit(map[string]string{"f.env": "T=" + token("flood1") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1)

		timeutil.MockSet(t0.Add(5 * time.Minute))
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "d2")
		firstAlert := mark().NotifyAlertID
		w.commit(map[string]string{"g.env": "T=" + token("flood2") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1, "within 15 minutes of the last digest")
		assert.NotZero(t, mark().NotifyAfterUnix, "the mark stays")

		timeutil.MockSet(t0.Add(16 * time.Minute))
		require.NoError(t, Scan(ctx, repo.ID)) // nothing new to scan, the mark is taken
		require.Len(t, *sent, 2)
		assert.Equal(t, firstAlert, (*sent)[1].AfterAlertID)
		assert.Equal(t, "d2", (*sent)[1].Commit)
	})

	t.Run("an old mark is dropped with a warning and no mail", func(t *testing.T) {
		*sent = nil
		noWait()
		lc, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
		defer cleanup()
		lc.Filter("is older than").StopMark("is older than")
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c4")
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET notify_after_unix = ? WHERE repo_id = ? AND kind = ?", time.Now().Add(-48*time.Hour).Unix(), repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		w.commit(map[string]string{"d.env": "T=" + token("old") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		assert.Empty(t, *sent)
		assert.Zero(t, mark().NotifyAfterUnix)
		filtered, _ := lc.Check(5 * time.Second)
		assert.True(t, slices.Contains(filtered, true), "the drop is logged at warn level")
	})

	t.Run("an alert a scan under way stored before the push was marked is still mailed", func(t *testing.T) {
		*sent = nil
		noWait()
		require.NoError(t, Scan(ctx, repo.ID)) // the pass ends: the floor is the newest alert
		stored := &secretscan_model.Alert{RepoID: repo.ID, Index: 5000, RuleID: "github-token", Fingerprint: fmt.Sprintf("%064d", 5000)}
		require.NoError(t, db.Insert(ctx, stored)) // what a scan under way stores before the hook marks
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "r1")
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1)
		assert.Less(t, (*sent)[0].AfterAlertID, stored.ID, "the boundary is the floor: the stored alert is above it")
	})

	t.Run("a mark across a switch off and on keeps its alerts and loses its pusher; the red team's sequence", func(t *testing.T) {
		*sent = nil
		noWait()
		sys := audit_model.WithSystem(ctx, "test")
		t0 := time.Now().Truncate(time.Second)
		timeutil.MockSet(t0)
		defer timeutil.MockUnset()
		require.NoError(t, Scan(ctx, repo.ID))
		// s1 is mailed
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "s1")
		w.commit(map[string]string{"s1.env": "T=" + token("seq-s1") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1)
		afterS1 := (*sent)[0].UpToAlertID
		// s2 comes while the digest is held
		timeutil.MockSet(t0.Add(time.Minute))
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "s2")
		boundary := mark().NotifyAlertID
		assert.Equal(t, afterS1, boundary)
		w.commit(map[string]string{"s2.env": "T=" + token("seq-s2") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1, "held")
		require.NotZero(t, mark().NotifyAfterUnix)
		// the switch goes off and on: the mark stays, its pusher goes
		require.NoError(t, SetRepoSwitch(sys, repo, false))
		require.NoError(t, SetRepoSwitch(sys, repo, true))
		assert.NotZero(t, mark().NotifyAfterUnix, "the mark and its alerts are kept")
		assert.Equal(t, boundary, mark().NotifyAlertID)
		assert.Zero(t, mark().NotifyPusherID)
		// s3 comes after
		timeutil.MockSet(t0.Add(2 * time.Minute))
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "s3")
		assert.Equal(t, boundary, mark().NotifyAlertID)
		w.commit(map[string]string{"s3.env": "T=" + token("seq-s3") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 1, "still held")
		timeutil.MockSet(t0.Add(16 * time.Minute))
		require.NoError(t, Scan(ctx, repo.ID))
		require.Len(t, *sent, 2)
		second := (*sent)[1]
		assert.Equal(t, boundary, second.AfterAlertID)
		assert.Zero(t, second.PusherID, "administrators only")
		d, err := secretscan_model.BuildDigest(ctx, repo.ID, second.AfterAlertID, second.UpToAlertID, []string{secretscan_model.KindRepo})
		require.NoError(t, err)
		assert.Equal(t, 2, d.Alerts, "the digest lists s2 and s3")
	})

	t.Run("an alert another server stores between the clear and the mail is mailed once, next time", func(t *testing.T) {
		*sent = nil
		noWait()
		require.NoError(t, Scan(ctx, repo.ID))
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "m1")
		first := &secretscan_model.Alert{RepoID: repo.ID, Index: 7000, RuleID: "github-token", Fingerprint: fmt.Sprintf("%064d", 7000)}
		require.NoError(t, db.Insert(ctx, first))
		finishDigest(ctx, repo, readMark(ctx, repo.ID), upToDate)
		require.Len(t, *sent, 1)
		assert.Equal(t, first.ID, (*sent)[0].UpToAlertID, "the digest is bounded by the newest alert at the time")
		assert.Equal(t, first.ID, mark().NotifyFloor, "and the clear stores that bound as the floor")
		other := &secretscan_model.Alert{RepoID: repo.ID, Index: 7001, RuleID: "github-token", Fingerprint: fmt.Sprintf("%064d", 7001)}
		require.NoError(t, db.Insert(ctx, other)) // the other server's scan stored it after the bound was read
		noWait()
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "m2")
		finishDigest(ctx, repo, readMark(ctx, repo.ID), upToDate)
		require.Len(t, *sent, 2)
		assert.Equal(t, first.ID, (*sent)[1].AfterAlertID, "the next digest starts after the first one's bound")
		assert.Less(t, (*sent)[1].AfterAlertID, other.ID, "and holds the alert that came between")
	})

	t.Run("a rescan keeps the mark, and re-found alerts are not mailed", func(t *testing.T) {
		*sent = nil
		noWait()
		sys := audit_model.WithSystem(ctx, "test")
		require.NoError(t, Scan(ctx, repo.ID))
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c5")
		require.NotZero(t, mark().NotifyAfterUnix)
		require.NoError(t, Rescan(sys, repo))
		assert.NotZero(t, mark().NotifyAfterUnix, "the mark is kept")
		assert.True(t, mark().Completed, "and so is the completed flag")
		require.NoError(t, Scan(ctx, repo.ID)) // the whole history again: every alert is found again
		for range 3 {
			require.NoError(t, Scan(ctx, repo.ID))
		}
		assert.Empty(t, *sent, "an alert that is found again is no new alert")
		assert.Zero(t, mark().NotifyAfterUnix, "the mark was taken")
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "c6")
		require.NoError(t, Rescan(sys, repo))
		w.commit(map[string]string{"h.env": "T=" + token("during-rescan") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(ctx, repo.ID))
		assert.Len(t, *sent, 1, "a push right before a rescan still mails what is new")
	})

	t.Run("a future last-sent time is no wait", func(t *testing.T) {
		*sent = nil
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET notify_last_unix = ? WHERE repo_id = ? AND kind = ?", time.Now().Unix()+7200, repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "f1")
		_, err = db.GetEngine(ctx).Insert(&secretscan_model.Alert{RepoID: repo.ID, Index: 6000, RuleID: "github-token", Fingerprint: fmt.Sprintf("%064d", 6000)})
		require.NoError(t, err)
		finishDigest(ctx, repo, readMark(ctx, repo.ID), upToDate)
		assert.Len(t, *sent, 1)
	})

	t.Run("a wiki turned off after the push leaves the code part of the mark", func(t *testing.T) {
		*sent = nil
		noWait()
		const code, wiki = secretscan_model.DigestKindCode, secretscan_model.DigestKindWiki
		MarkPush(ctx, repo, 2, secretscan_model.KindRepo, "main", "n2")
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET notify_kinds = ? WHERE repo_id = ? AND kind = ?", code|wiki, repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		_, err = db.GetEngine(ctx).Insert(&secretscan_model.Alert{RepoID: repo.ID, Index: 6001, RuleID: "github-token", Fingerprint: fmt.Sprintf("%064d", 6001)})
		require.NoError(t, err)
		require.NoError(t, os.RemoveAll(repo.WikiPath())) // what deleting the wiki does
		noWiki, err := repo_model.GetRepositoryByID(ctx, repo.ID)
		require.NoError(t, err)
		require.False(t, noWiki.HasWiki())
		finishDigest(ctx, noWiki, readMark(ctx, repo.ID), upToDate)
		require.Len(t, *sent, 1, "the code part is mailed")
		assert.Equal(t, code, (*sent)[0].Kinds&(code|wiki))
	})
}

// The cron task scans a repository itself when the queue has said "already queued" for an hour: the unique queue can
// keep a set entry that no item stands for after a kill. The note is kept in the scan row, so a restart doesn't add
// an hour; a repository that was never scanned has no row, and its note is kept in memory.
func TestStuckQueueIsRecovered(t *testing.T) {
	repo := enable(t)
	mockQueue(t)
	w := newWork(t, repo)
	ctx := t.Context()
	w.commit(map[string]string{"a.txt": "x\n"})
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	defer test.MockVariableValue(&pushQueue, func(int64) error { return queue.ErrAlreadyInQueue })()
	warned := func(lc *test.LogChecker) bool {
		filtered, _ := lc.Check(5 * time.Second)
		return slices.Contains(filtered, true)
	}

	t.Run("a repository with scan state", func(t *testing.T) {
		require.NoError(t, secretscan_model.MarkRequeue(ctx, 0))
		lc, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
		defer cleanup()
		lc.Filter("scanning it directly").StopMark("scanning it directly")
		require.NoError(t, EnqueueUnscanned(ctx))
		assert.NotZero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).Requeue, "the first sighting only notes the time")
		stuck := scanOf(t, repo.ID, secretscan_model.KindRepo).QueueStuckUnix
		require.NotZero(t, stuck, "the note is in the row")
		markedSince.Lock()
		clear(markedSince.at) // a restart: nothing in memory
		markedSince.Unlock()
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET queue_stuck_unix = ? WHERE repo_id = ? AND kind = ?", time.Now().Add(-2*time.Hour).Unix(), repo.ID, secretscan_model.KindRepo)
		require.NoError(t, err)
		require.NoError(t, EnqueueUnscanned(ctx))
		row := scanOf(t, repo.ID, secretscan_model.KindRepo)
		assert.Zero(t, row.Requeue, "the cron task scanned it: the mark is taken")
		assert.Zero(t, row.QueueStuckUnix, "and the note is gone")
		assert.True(t, warned(lc), "and logged it at warn level")
	})

	t.Run("a repository that was never scanned", func(t *testing.T) {
		_, err := secretscan_model.DeleteScans(ctx, repo.ID)
		require.NoError(t, err)
		lc, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
		defer cleanup()
		lc.Filter("scanning it directly").StopMark("scanning it directly")
		require.NoError(t, EnqueueUnscanned(ctx))
		assert.Nil(t, scanOf(t, repo.ID, secretscan_model.KindRepo), "the first sighting scans nothing")
		markedSince.Lock()
		markedSince.at[repo.ID] = time.Now().Add(-2 * time.Hour)
		markedSince.Unlock()
		require.NoError(t, EnqueueUnscanned(ctx))
		assert.NotNil(t, scanOf(t, repo.ID, secretscan_model.KindRepo), "the cron task scanned it")
		assert.True(t, warned(lc))
	})
}

// upToDate is a pass that brought the code up to date.
var upToDate = map[string]kindState{secretscan_model.KindRepo: {current: true}}

// A live scan of one text that opens an alert marks the repository (no pusher, the text bit) and mails the digest once;
// the person who wrote each new place is told, once per text; a place that is stored already, an alert that is old and
// an imported text (no author) tell nobody or mark nothing.
func TestLiveTextDigestAndPosterNotice(t *testing.T) {
	repo := enableText(t)
	sent := captureDigests(t)
	var notices []mailer.SecretPosterNotice
	t.Cleanup(test.MockVariableValue(&sendPosterNotice, func(ctx context.Context, _ *repo_model.Repository, n mailer.SecretPosterNotice) error {
		assert.False(t, db.InTransaction(ctx), "a notice is never mailed inside a transaction")
		notices = append(notices, n)
		return nil
	}))
	ctx := t.Context()
	require.NoError(t, Scan(ctx, repo.ID)) // the code and the text there is: never mailed
	require.Zero(t, scanOf(t, repo.ID, secretscan_model.KindIssue).RetryUnix, "the text backfill is done")
	require.Empty(t, *sent)

	tok := token("live-text")
	issue := newIssue(t, repo, "title", "key: "+tok)
	require.NoError(t, handleText(ctx, fmt.Sprintf("i:%d:2", issue.ID)))
	require.Len(t, *sent, 1)
	in := (*sent)[0]
	assert.NotZero(t, in.Kinds&secretscan_model.DigestKindText)
	assert.Zero(t, in.Kinds&(secretscan_model.DigestKindCode|secretscan_model.DigestKindWiki))
	assert.Zero(t, in.PusherID, "nobody pushed")
	assert.Empty(t, in.Ref)
	assert.Equal(t, []mailer.SecretPosterNotice{{PosterID: 2, IssueID: issue.ID, Field: "body"}}, notices)
	assert.Zero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).NotifyAfterUnix, "the mark is taken with the mail")

	t.Run("the same text again: no new place, no notice", func(t *testing.T) {
		require.NoError(t, handleText(ctx, fmt.Sprintf("i:%d:2", issue.ID)))
		assert.Len(t, notices, 1)
		assert.Len(t, *sent, 1)
	})

	t.Run("a comment with the same secret: its writer is told, no new alert, no digest", func(t *testing.T) {
		c := newComment(t, issue, "me too: "+tok)
		require.NoError(t, handleText(ctx, fmt.Sprintf("c:%d:3", c.ID)))
		require.Len(t, notices, 2)
		assert.Equal(t, mailer.SecretPosterNotice{PosterID: 3, IssueID: issue.ID, CommentID: c.ID}, notices[1])
		assert.Len(t, *sent, 1)
	})

	t.Run("an edit by somebody else tells nobody: only the editor of the live edit is the poster", func(t *testing.T) {
		other := newIssue(t, repo, "other", "key: "+token("edited-in"))
		require.NoError(t, handleText(ctx, fmt.Sprintf("i:%d:4", other.ID))) // user 4 edited it, user 2 posted it
		assert.Len(t, notices, 2)
	})

	t.Run("an imported text has no author to tell, but still marks for a digest", func(t *testing.T) {
		imported := newIssue(t, repo, "imported", "key: "+token("imported"))
		_, err := db.GetEngine(ctx).Table("issue").Where("id = ?", imported.ID).Update(map[string]any{"original_author_id": 99})
		require.NoError(t, err)
		require.NoError(t, handleText(ctx, fmt.Sprintf("i:%d:2", imported.ID)))
		assert.Len(t, notices, 2)
		assert.NotZero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).NotifyAfterUnix, "a digest within 15 minutes of the last waits")
		assert.Len(t, *sent, 1)
	})
}
