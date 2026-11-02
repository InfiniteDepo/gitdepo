// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func scanRow(t *testing.T, repoID int64, kind string) *Scan {
	t.Helper()
	s, err := GetScan(t.Context(), repoID, kind)
	require.NoError(t, err)
	require.NotNil(t, s)
	return s
}

func TestMarkNotify(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	marked := func(repoID, pusher int64, ref string) bool {
		t.Helper()
		ok, err := MarkNotify(ctx, repoID, pusher, KindRepo, ref, "c1")
		require.NoError(t, err)
		return ok
	}
	assert.False(t, marked(1, 2, "main"), "the first scan has no row: nothing is marked")

	_, err := db.GetEngine(ctx).Insert(&Scan{RepoID: 1, Kind: KindRepo, Status: StatusIncomplete, RetryUnix: 99})
	require.NoError(t, err)
	assert.False(t, marked(1, 2, "main"), "the first scan is still under way: it never completed")
	_, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET completed = ? WHERE repo_id = 1", true)
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Insert(&Alert{RepoID: 1, Index: 1, RuleID: "r", Fingerprint: "f0"})
	require.NoError(t, err)
	var old Alert
	_, err = db.GetEngine(ctx).Where("repo_id = 1").Get(&old)
	require.NoError(t, err)

	require.True(t, marked(1, 2, "main"))
	first := scanRow(t, 1, KindRepo)
	assert.NotZero(t, first.NotifyAfterUnix)
	assert.EqualValues(t, 1, first.NotifySeq)
	assert.Equal(t, old.ID, first.NotifyAlertID, "the boundary is the newest alert at the first push")
	assert.EqualValues(t, 2, first.NotifyPusherID)
	assert.Equal(t, "main", first.NotifyRef)

	_, err = db.GetEngine(ctx).Insert(&Alert{RepoID: 1, Index: 2, RuleID: "r", Fingerprint: "f1"})
	require.NoError(t, err)
	require.True(t, marked(1, 2, "dev"))
	second := scanRow(t, 1, KindRepo)
	assert.EqualValues(t, 2, second.NotifySeq, "every push bumps the sequence")
	assert.Equal(t, first.NotifyAlertID, second.NotifyAlertID, "the boundary and the time stay with the first push")
	assert.Equal(t, first.NotifyAfterUnix, second.NotifyAfterUnix)
	assert.Equal(t, "dev", second.NotifyRef, "the newer ref")
	assert.EqualValues(t, 2, second.NotifyPusherID, "the same pusher")

	require.True(t, marked(1, 3, "dev"))
	assert.Zero(t, scanRow(t, 1, KindRepo).NotifyPusherID, "two pushers: nobody is told 'your push'")
	require.True(t, marked(1, 2, "dev"))
	assert.Zero(t, scanRow(t, 1, KindRepo).NotifyPusherID, "and it stays so until the digest is sent")

	// the clear compares the sequence the scan read
	took, err := ClearNotify(ctx, 1, 2, 0, 0)
	require.NoError(t, err)
	assert.False(t, took, "a push came after that read")
	assert.NotZero(t, scanRow(t, 1, KindRepo).NotifyAfterUnix)
	took, err = ClearNotify(ctx, 1, scanRow(t, 1, KindRepo).NotifySeq, 1234, 77)
	require.NoError(t, err)
	assert.True(t, took)
	cleared := scanRow(t, 1, KindRepo)
	assert.Zero(t, cleared.NotifyAfterUnix)
	assert.Empty(t, cleared.NotifyRef)
	assert.EqualValues(t, 1234, cleared.NotifyLastUnix)
	assert.EqualValues(t, 77, cleared.NotifyFloor, "the clear stores the floor it is given")
	took, err = ClearNotify(ctx, 1, cleared.NotifySeq, 0, 0)
	require.NoError(t, err)
	assert.False(t, took, "at most once: nothing left to take")

	// a scan under way or backing off does not stop the marking: the mark waits for it
	_, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET retry_unix = 99, fail_count = 2 WHERE repo_id = 1")
	require.NoError(t, err)
	assert.True(t, marked(1, 2, "main"))
	_, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET retry_unix = 0, fail_count = 0, notify_after_unix = 0, notify_kinds = 0 WHERE repo_id = 1")
	require.NoError(t, err)

	// a wiki push needs a wiki scanned once, and has no ref: the mark keeps the code push's
	ok, err := MarkNotify(ctx, 1, 2, KindWiki, "", "")
	require.NoError(t, err)
	assert.False(t, ok, "the first scan of a wiki never mails")
	require.True(t, marked(1, 2, "main"))
	assert.Equal(t, DigestKindCode, scanRow(t, 1, KindRepo).NotifyKinds, "the wiki was not scanned at mark time")
	_, err = db.GetEngine(ctx).Insert(&Scan{RepoID: 1, Kind: KindWiki, Status: StatusOK, Completed: true})
	require.NoError(t, err)
	ok, err = MarkNotify(ctx, 1, 2, KindWiki, "", "")
	require.NoError(t, err)
	require.True(t, ok)
	row := scanRow(t, 1, KindRepo)
	assert.Equal(t, DigestKindCode|DigestKindWiki|DigestWikiScanned|DigestSeveral, row.NotifyKinds, "a code and a wiki push: no single place to name")
	assert.Equal(t, "main", row.NotifyRef, "a wiki push keeps the ref of the code push")
	assert.Equal(t, "c1", row.NotifyCommit)

	// the ref is cut to the column size on a character boundary
	long := strings.Repeat("a", 254) + "ééé" // byte 255 is the middle of a character
	require.True(t, marked(1, 2, long))
	cut := scanRow(t, 1, KindRepo).NotifyRef
	assert.Len(t, cut, 254, "the half character is dropped")
	assert.True(t, utf8.ValidString(cut))
	require.True(t, marked(1, 2, strings.Repeat("b", 300)))
	assert.Len(t, scanRow(t, 1, KindRepo).NotifyRef, 255)
}

func TestBuildDigest(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	add := func(index int64, rule string, places int, kinds ...string) int64 {
		a := &Alert{RepoID: 1, Index: index, RuleID: rule, Fingerprint: fmt.Sprintf("%064d", index), LocationCount: places}
		_, err := db.GetEngine(ctx).Insert(a)
		require.NoError(t, err)
		for i, kind := range kinds {
			l := NewLocation(1, kind, fmt.Sprintf("blob-%d-%d", index, i), fmt.Sprintf("dir/file%d.txt", index), i+1, i+1, "c", "n", "e", 0)
			l.AlertID = a.ID
			_, err = db.GetEngine(ctx).Insert(l)
			require.NoError(t, err)
		}
		return a.ID
	}
	old := add(1, "old", 1, KindRepo)
	add(2, "aws", 3, KindRepo, KindRepo, KindRepo)
	add(3, "aws", 12, KindRepo, KindRepo, KindRepo, KindRepo, KindRepo, KindRepo, KindRepo, KindRepo, KindRepo, KindRepo) // 2 places over the cap of 10
	add(4, "slack", 2, KindWiki, KindWiki)
	add(5, "slack", 2, KindWiki, KindRepo)

	d, err := BuildDigest(ctx, 1, old, 0, []string{KindRepo, KindWiki, KindPull})
	require.NoError(t, err)
	assert.Equal(t, 4, d.Alerts)
	assert.Equal(t, []DigestType{{"aws", 2}, {"slack", 2}}, d.Types)
	assert.Equal(t, 19, d.TotalLocations)
	assert.Len(t, d.Locations, MaxDigestLocations, "the list is capped")

	d, err = BuildDigest(ctx, 1, old, 0, []string{KindRepo, KindPull})
	require.NoError(t, err)
	assert.Equal(t, 3, d.Alerts, "an alert only in the wiki is not for someone without wiki access")
	assert.Equal(t, []DigestType{{"aws", 2}, {"slack", 1}}, d.Types)
	assert.Equal(t, 19-2-1, d.TotalLocations, "and the wiki's places are left out of the total")
	for _, l := range d.Locations {
		assert.NotEqual(t, KindWiki, l.Kind)
	}

	d, err = BuildDigest(ctx, 1, old, 0, []string{KindWiki})
	require.NoError(t, err)
	assert.Equal(t, 2, d.Alerts, "a pusher of the wiki is told of the wiki's alerts only")
	assert.Zero(t, d.FirstIndex)
	d, err = BuildDigest(ctx, 1, old+3, 0, []string{KindRepo})
	require.NoError(t, err)
	assert.Equal(t, 1, d.Alerts)
	assert.EqualValues(t, 5, d.FirstIndex, "one alert: its number, for a direct link")

	d, err = BuildDigest(ctx, 1, old, old+2, []string{KindRepo, KindWiki, KindPull})
	require.NoError(t, err)
	assert.Equal(t, 2, d.Alerts, "alerts above the upper bound are left for the next digest")
	d, err = BuildDigest(ctx, 1, 1<<40, 0, []string{KindRepo})
	require.NoError(t, err)
	assert.Zero(t, d.Alerts, "nothing above the boundary")
}

// The mark's several-pushes bit, the pusher rule, the floor that starts a boundary, ResetScans and DetachNotifyPushers.
func TestMarkNotifyWindow(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	_, err := db.GetEngine(ctx).Insert(&Scan{RepoID: 1, Kind: KindRepo, Status: StatusOK, Completed: true})
	require.NoError(t, err)
	mark := func(pusher int64, ref, commit string) {
		t.Helper()
		ok, err := MarkNotify(ctx, 1, pusher, KindRepo, ref, commit)
		require.NoError(t, err)
		require.True(t, ok)
	}
	clear := func() {
		t.Helper()
		newest, err := MaxAlertID(ctx, 1)
		require.NoError(t, err)
		took, err := ClearNotify(ctx, 1, scanRow(t, 1, KindRepo).NotifySeq, 0, newest)
		require.NoError(t, err)
		require.True(t, took)
	}

	// the boundary of the first mark is the floor: an alert above it, stored before the mark, is owed a mail
	a1 := &Alert{RepoID: 1, Index: 1, RuleID: "r", Fingerprint: "f1"}
	require.NoError(t, db.Insert(ctx, a1))
	require.NoError(t, AdvanceNotifyFloor(ctx, 1))
	assert.Equal(t, a1.ID, scanRow(t, 1, KindRepo).NotifyFloor)
	a2 := &Alert{RepoID: 1, Index: 2, RuleID: "r", Fingerprint: "f2"} // stored by a scan under way, before the post-receive hook
	require.NoError(t, db.Insert(ctx, a2))
	mark(2, "main", "c1")
	assert.Equal(t, a1.ID, scanRow(t, 1, KindRepo).NotifyAlertID, "the boundary is the floor, not the newest alert")
	require.NoError(t, AdvanceNotifyFloor(ctx, 1))
	assert.Equal(t, a1.ID, scanRow(t, 1, KindRepo).NotifyFloor, "a marked row keeps its floor")

	// one pusher, one ref: named; another ref or another pusher: not
	mark(2, "main", "c2")
	row := scanRow(t, 1, KindRepo)
	assert.Zero(t, row.NotifyKinds&DigestSeveral)
	assert.EqualValues(t, 2, row.NotifyPusherID)
	mark(2, "dev", "c3")
	assert.NotZero(t, scanRow(t, 1, KindRepo).NotifyKinds&DigestSeveral, "two refs")
	clear()
	assert.Equal(t, a2.ID, scanRow(t, 1, KindRepo).NotifyFloor, "taking a mark moves the floor to the newest alert")
	mark(2, "main", "c4")
	mark(0, "", "") // a deploy key
	assert.Zero(t, scanRow(t, 1, KindRepo).NotifyPusherID, "a push by nobody takes the pusher variant away")
	mark(2, "main", "c5")
	assert.Zero(t, scanRow(t, 1, KindRepo).NotifyPusherID, "and it stays gone")
	clear()

	// a mark that waited while scanning was off keeps its boundary and loses its pusher
	mark(2, "main", "c6")
	before := scanRow(t, 1, KindRepo)
	n, err := DetachNotifyPushers(ctx, builder.Eq{"repo_id": 1})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	row = scanRow(t, 1, KindRepo)
	assert.Equal(t, before.NotifyAfterUnix, row.NotifyAfterUnix)
	assert.Equal(t, before.NotifyAlertID, row.NotifyAlertID)
	assert.Zero(t, row.NotifyPusherID)
	mark(2, "main", "c6b")
	assert.Zero(t, scanRow(t, 1, KindRepo).NotifyPusherID, "a later push is not credited to the old pusher")
	clear()

	// a rescan forgets the tips and the holes, and keeps the completed flag and the mark
	mark(2, "main", "c7")
	_, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET scanned_tips = '[\"x\"]', holes = 3 WHERE repo_id = 1")
	require.NoError(t, err)
	n, err = ResetScans(ctx, 1)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	row = scanRow(t, 1, KindRepo)
	assert.Equal(t, "[]", row.ScannedTips)
	assert.Zero(t, row.Holes)
	assert.True(t, row.Completed)
	assert.NotZero(t, row.NotifyAfterUnix)
	n, err = ResetScans(ctx, 1)
	require.NoError(t, err)
	assert.Zero(t, n, "rows that are reset already are not claimed twice")
}

// The stuck note is kept on the row, set once and cleared.
func TestQueueStuck(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	_, hasRow, err := MarkQueueStuck(ctx, 1, 100)
	require.NoError(t, err)
	assert.False(t, hasRow, "no scan state to hold it")
	_, err = db.GetEngine(ctx).Insert(&Scan{RepoID: 1, Kind: KindRepo, Status: StatusOK})
	require.NoError(t, err)
	since, hasRow, err := MarkQueueStuck(ctx, 1, 100)
	require.NoError(t, err)
	assert.True(t, hasRow)
	assert.EqualValues(t, 100, since)
	since, _, err = MarkQueueStuck(ctx, 1, 500)
	require.NoError(t, err)
	assert.EqualValues(t, 100, since, "the first sighting stays")
	require.NoError(t, ClearQueueStuck(ctx, 1))
	since, _, err = MarkQueueStuck(ctx, 1, 900)
	require.NoError(t, err)
	assert.EqualValues(t, 900, since)
}

// A text mark has no pusher and no ref: merged into a push mark, in either order, it must neither clear the pusher nor
// make the digest "several".
func TestMarkNotifyTextMergesWithPush(t *testing.T) {
	setup := func(t *testing.T) {
		unittest.PrepareTestEnv(t)
		_, err := db.GetEngine(t.Context()).Insert(&Scan{RepoID: 1, Kind: KindRepo, Status: StatusOK, Completed: true}, &Scan{RepoID: 1, Kind: KindIssue, Status: StatusOK, Completed: true})
		require.NoError(t, err)
	}
	text := func(t *testing.T) {
		t.Helper()
		ok, err := MarkNotifyText(t.Context(), 1, 0)
		require.NoError(t, err)
		require.True(t, ok)
	}
	push := func(t *testing.T) {
		t.Helper()
		ok, err := MarkNotify(t.Context(), 1, 2, KindRepo, "main", "c1")
		require.NoError(t, err)
		require.True(t, ok)
	}
	check := func(t *testing.T) {
		t.Helper()
		row := scanRow(t, 1, KindRepo)
		assert.Equal(t, DigestKindCode|DigestKindText, row.NotifyKinds, "both kinds, not several")
		assert.EqualValues(t, 2, row.NotifyPusherID, "the pusher stays")
		assert.Equal(t, "main", row.NotifyRef)
		assert.Equal(t, "c1", row.NotifyCommit)
	}
	t.Run("text then push", func(t *testing.T) {
		setup(t)
		text(t)
		push(t)
		check(t)
	})
	t.Run("push A, text, push B on another ref is still several", func(t *testing.T) {
		setup(t)
		push(t)
		text(t)
		ok, err := MarkNotify(t.Context(), 1, 2, KindRepo, "dev", "c2")
		require.NoError(t, err)
		require.True(t, ok)
		assert.NotZero(t, scanRow(t, 1, KindRepo).NotifyKinds&DigestSeveral)
	})
	t.Run("push then text", func(t *testing.T) {
		setup(t)
		push(t)
		text(t)
		check(t)
	})
}
