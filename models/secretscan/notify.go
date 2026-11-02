// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"slices"
	"unicode/utf8"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// MaxDigestLocations is the most places a digest mail lists.
const MaxDigestLocations = 10

// Bits of Scan.NotifyKinds: what the marking pushes touched, and whether the wiki had been scanned to its end when the
// first push marked the repository (the first scan of a wiki never mails).
const (
	DigestKindCode    = 1
	DigestKindWiki    = 2
	DigestWikiScanned = 4
	DigestSeveral     = 8  // the marking pushes were to different refs or kinds: the mail names none
	DigestKindText    = 16 // a live scan of an issue, pull request or comment stored a new alert (no push, no pusher)
)

// DigestMinInterval is the shortest time between two digests of one repository: a mark that comes sooner waits, so the
// next digest carries everything, and a flood of pushes can't flood the administrators.
const DigestMinInterval = 15 * 60 // seconds

// maxNotifyRef is the length (bytes) of the stored ref name, the column's size.
const maxNotifyRef = 255

// truncateUTF8 cuts s to at most n bytes, on a character boundary.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// MarkNotify marks the repository for a digest mail: a push to it (kind is KindRepo for a branch or tag, KindWiki for
// the wiki; KindIssue marks a text that a live scan found a new alert in, with no pusher, ref or commit, and needs the
// repository's text scanned to its end once), by pusherID (0 when no person pushed: a deploy key, an Actions task), ref and commit as shown in the mail.
// Only a repository whose code has been scanned to its end once is marked (a wiki push also needs the wiki scanned
// once), so the first scan, a backfill and a rescan (which removes the rows) never mail; a scan that is under way or
// backing off after a failure does not stop the marking, since the mark waits for the scan. The first mark's alert boundary is the row's floor (the alerts nobody is owed a digest for), so an alert stored by a
// scan under way before this push was marked is still mailed. A second push before the
// digest keeps the first mark's alert boundary and time, takes the newer ref and commit (a wiki push, which has none, keeps them), adds its kind, and keeps the
// pusher only when it is the same one (else 0: nobody is told "your push"). Every call bumps notify_seq, so the clear
// of a scan that started before the push is refused. It reports whether a row was marked.
func MarkNotify(ctx context.Context, repoID, pusherID int64, kind, ref, commit string) (bool, error) {
	return markNotify(ctx, repoID, pusherID, kind, ref, commit, -1)
}

// MarkNotifyText marks the repository for a digest of the alerts above boundary (the newest alert there was before the
// live scan of a text stored its own): the alert is stored before the mark, so the default boundary would leave it out.
// A mark that exists already keeps its own boundary.
func MarkNotifyText(ctx context.Context, repoID, boundary int64) (bool, error) {
	return markNotify(ctx, repoID, 0, KindIssue, "", "", max(boundary, 0))
}

func markNotify(ctx context.Context, repoID, pusherID int64, kind, ref, commit string, boundary int64) (bool, error) {
	wikiScanned, err := db.GetEngine(ctx).Where("repo_id = ? AND kind = ? AND completed = ?", repoID, KindWiki, true).Exist(new(Scan))
	if err != nil {
		return false, err
	}
	bits, isText := DigestKindCode, 0 // a text mark has no person and no ref: it is never "another push"
	switch kind {
	case KindWiki:
		if !wikiScanned {
			return false, nil
		}
		bits = DigestKindWiki
	case KindIssue:
		if done, err := db.GetEngine(ctx).Where("repo_id = ? AND kind = ? AND retry_unix = 0 AND status <> ''", repoID, KindIssue).Exist(new(Scan)); err != nil || !done {
			return false, err
		}
		bits, isText = DigestKindText, 1
	}
	if wikiScanned {
		bits |= DigestWikiScanned
	}
	ref = truncateUTF8(ref, maxNotifyRef)
	// the assignments run in this order: MySQL reads the columns as already assigned, so notify_after_unix is last
	res, err := db.GetEngine(ctx).Exec(
		"UPDATE secret_scan SET notify_seq = notify_seq + 1,"+
			" notify_alert_id = CASE WHEN notify_after_unix = 0 THEN (CASE WHEN ? >= 0 THEN ? WHEN notify_floor > 0 THEN notify_floor ELSE (SELECT COALESCE(MAX(id), 0) FROM secret_scanning_alert WHERE repo_id = ?) END) ELSE notify_alert_id END,"+
			" notify_pusher_id = CASE WHEN ? = 1 THEN notify_pusher_id WHEN notify_after_unix = 0 OR (notify_kinds & 3) = 0 OR notify_pusher_id = ? THEN ? ELSE 0 END,"+
			" notify_kinds = CASE WHEN notify_after_unix = 0 THEN ? ELSE (notify_kinds | ? | CASE WHEN (? <> '' AND notify_ref <> '' AND notify_ref <> ?) OR (? <> 0 AND (notify_kinds & 3) <> 0 AND (notify_kinds & 3) <> ?) THEN 8 ELSE 0 END) END,"+
			" notify_ref = CASE WHEN ? <> '' THEN ? ELSE notify_ref END, notify_commit = CASE WHEN ? <> '' THEN ? ELSE notify_commit END,"+
			" notify_after_unix = CASE WHEN notify_after_unix = 0 THEN ? ELSE notify_after_unix END"+
			" WHERE repo_id = ? AND kind = ? AND completed = ?",
		boundary, boundary, repoID, isText, pusherID, pusherID, bits, bits, ref, ref, bits&3, bits&3, ref, ref, commit, commit, int64(timeutil.TimeStampNow()), repoID, KindRepo, true,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ClearNotify removes the mark if no push marked the repository since seq was read, and reports whether it did:
// only then the caller sends the mail, so a digest is sent at most once and a push during the scan keeps its mark
// for the next scan. lastSent is the value of notify_last_unix to store: now when a digest goes out, else the old one.
// floor is the upper alert bound the digest was built with (MaxAlertID, read before it): the next mark starts there, so an
// alert that another server stored meanwhile is mailed once, next time, and never twice.
func ClearNotify(ctx context.Context, repoID, seq int64, lastSent timeutil.TimeStamp, floor int64) (bool, error) {
	res, err := db.GetEngine(ctx).Exec(
		"UPDATE secret_scan SET notify_after_unix = 0, notify_pusher_id = 0, notify_kinds = 0, notify_ref = '', notify_commit = '', notify_last_unix = ?, notify_floor = ? WHERE repo_id = ? AND kind = ? AND notify_seq = ? AND notify_after_unix <> 0",
		int64(lastSent), floor, repoID, KindRepo, seq,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// HasAlertsAfter tells whether the repository has an alert above the boundary a mark recorded: no digest is built
// for a push that opened none.
func HasAlertsAfter(ctx context.Context, repoID, afterAlertID, upToAlertID int64) (bool, error) {
	return db.GetEngine(ctx).Where(alertWindow(repoID, afterAlertID, upToAlertID)).Exist(new(Alert))
}

// alertWindow is the alerts of a digest: above the boundary and, when upTo is set, not above it.
func alertWindow(repoID, afterAlertID, upToAlertID int64) builder.Cond {
	cond := builder.Eq{"repo_id": repoID}.And(builder.Gt{"id": afterAlertID})
	if upToAlertID > 0 {
		cond = cond.And(builder.Lte{"id": upToAlertID})
	}
	return cond
}

// MaxAlertID is the newest alert of the repository, 0 without one.
func MaxAlertID(ctx context.Context, repoID int64) (int64, error) {
	var id int64
	_, err := db.GetEngine(ctx).Table("secret_scanning_alert").Select("COALESCE(MAX(id), 0)").Where("repo_id = ?", repoID).Get(&id)
	return id, err
}

// DigestType is the number of new alerts of one secret type.
type DigestType struct {
	RuleID string
	Count  int
}

// Digest is what a digest mail says: the new alerts (above afterAlertID) of the kinds asked for, by type, and their
// first places. No fingerprint is read.
type Digest struct {
	Alerts         int
	Types          []DigestType
	Locations      []*Location // at most MaxDigestLocations, in the order found; never a place in text
	TextAlerts     int         // how many of the alerts have a place in text (counted only when kinds has KindIssue)
	TotalLocations int         // every place of the alerts, also those over the cap that have no row
	FirstIndex     int64       // the number of the alert when there is exactly one, else 0
}

// BuildDigest reads the digest of the alerts created after afterAlertID (and, when upToAlertID is set, up to it) that have a place of one of kinds (KindRepo,
// KindWiki, KindPull, and KindIssue for text): a viewer who can't read the wiki, or a wiki that was not scanned before
// the push, leaves KindWiki out, and a pusher is told only of the kind they pushed. Places of other kinds are left out too.
func BuildDigest(ctx context.Context, repoID, afterAlertID, upToAlertID int64, kinds []string) (*Digest, error) {
	opts := &AlertSearchOptions{RepoID: repoID, Kinds: kinds}
	alerts := opts.ToConds().And(builder.Gt{"id": afterAlertID})
	if upToAlertID > 0 {
		alerts = alerts.And(builder.Lte{"id": upToAlertID})
	}
	var rows []struct {
		RuleID string
		N      int
		Places int
	}
	if err := db.GetEngine(ctx).Table("secret_scanning_alert").Select("rule_id, COUNT(*) AS n, SUM(location_count) AS places").
		Where(alerts).GroupBy("rule_id").OrderBy("n DESC, rule_id").Find(&rows); err != nil {
		return nil, err
	}
	d := &Digest{}
	for _, r := range rows {
		d.Types = append(d.Types, DigestType{RuleID: r.RuleID, Count: r.N})
		d.Alerts += r.N
		d.TotalLocations += r.Places
	}
	if d.Alerts == 0 {
		return d, nil
	}
	if d.Alerts == 1 {
		var a Alert
		if has, err := db.GetEngine(ctx).Where(alerts).Cols("id", "index").Get(&a); err != nil {
			return nil, err
		} else if has {
			d.FirstIndex = a.Index
		}
	}
	if slices.Contains(kinds, KindIssue) {
		textOpts := &AlertSearchOptions{RepoID: repoID, Kinds: TextKinds}
		n, err := db.GetEngine(ctx).Where(textOpts.ToConds().And(alertWindow(repoID, afterAlertID, upToAlertID))).Count(new(Alert))
		if err != nil {
			return nil, err
		}
		d.TextAlerts = int(n)
	}
	// a place in text is never listed: the mail names no issue or comment, and the recipient may not read it
	listed := slices.DeleteFunc(slices.Clone(kinds), func(k string) bool { return slices.Contains(TextKinds, k) })
	if len(listed) == 0 {
		d.TotalLocations = 0
		return d, nil
	}
	in := builder.In("alert_id", builder.Select("id").From("secret_scanning_alert").Where(alerts))
	// places of a kind that is left out are not counted (those over the cap, which have no row, can't be told apart)
	other, err := db.GetEngine(ctx).Where(builder.And(in, builder.NotIn("kind", listed))).Count(new(Location))
	if err != nil {
		return nil, err
	}
	d.TotalLocations = max(d.TotalLocations-int(other), 0)
	return d, db.GetEngine(ctx).Where(builder.And(in, builder.In("kind", listed))).OrderBy("id").Limit(MaxDigestLocations).Find(&d.Locations)
}

// AdvanceNotifyFloor moves the floor to the newest alert of the repository, when no push has marked it: called after a
// pass that left the code up to date. The condition is in the statement, so a mark that comes meanwhile keeps its boundary.
func AdvanceNotifyFloor(ctx context.Context, repoID int64) error {
	_, err := db.GetEngine(ctx).Exec(
		"UPDATE secret_scan SET notify_floor = (SELECT COALESCE(MAX(id), 0) FROM secret_scanning_alert WHERE repo_id = ?) WHERE repo_id = ? AND kind = ? AND completed = ? AND notify_after_unix = 0",
		repoID, repoID, KindRepo, true,
	)
	return err
}

// DetachNotifyPushers takes the pusher off the digest marks of the repositories in the condition (on
// secret_scan.repo_id), and reports how many marks there were: a mark that waited across a switch off and on keeps its
// boundary and its alerts, but its digest goes to the administrators only; a later push must not be credited to the
// old pusher.
// cond must not read secret_scan (MySQL refuses an UPDATE that reads its own table in a subquery, error 1093).
func DetachNotifyPushers(ctx context.Context, cond builder.Cond) (int64, error) {
	where, args, err := builder.ToSQL(cond)
	if err != nil {
		return 0, err
	}
	res, err := db.GetEngine(ctx).Exec(append([]any{
		"UPDATE secret_scan SET notify_pusher_id = 0 WHERE kind = ? AND notify_after_unix <> 0 AND notify_pusher_id <> 0 AND " + where,
		KindRepo,
	}, args...)...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
