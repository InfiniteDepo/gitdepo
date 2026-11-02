// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package secretscan stores what the secret scanner (services/secretscan) found: one state row per repository and
// kind (the repository or its wiki), one alert per secret and the places it was found at. No column holds a secret
// or any part of it: an alert has the rule, a keyed fingerprint (modules/secretdetection) and the places.
package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// The git repositories a scan covers, each with its own state row: the refs other than refs/pull/*, the wiki, and
// refs/pull/* (which any reader can write).
const (
	KindRepo = "repo"
	KindWiki = "wiki"
	KindPull = "pull"
)

// The kinds of a place in text people write: the title or body of an issue or pull request, and a comment. KindIssue
// is also the kind of the scan state row of a repository's text (its cursor is kept in ScannedTips). A reader shows
// a place in text only to a viewer who may read that issue or pull request (LoadTextPlaces).
const (
	KindIssue   = "issue"
	KindComment = "comment"
)

var TextKinds = []string{KindIssue, KindComment}

// Scan statuses. Incomplete: the scan is under way (a slice ended at a limit) or has holes, parts that were not
// scanned (Scan.Holes); holes stay until the state is reset, and a trigger with nothing new changes nothing.
const (
	StatusOK         = "ok"
	StatusIncomplete = "incomplete"
	StatusFailed     = "failed"
)

// Alert states.
const (
	StateOpen        = "open"
	StateRevoked     = "revoked"
	StateFalsePos    = "false_positive"
	StateUsedInTests = "used_in_tests"
	StateWontFix     = "wont_fix"
)

// CurrentKeyVersion is the version of the fingerprint key (modules/keying).
const CurrentKeyVersion = 1

// Caps of stored text (bytes).
const (
	maxPathLen   = 4096
	maxAuthorLen = 255
)

// Scan is the state of the scanner for a repository's git repository (Kind) or its wiki.
type Scan struct {
	ID     int64  `xorm:"pk autoincr"`
	RepoID int64  `xorm:"UNIQUE(repo_kind) NOT NULL"`
	Kind   string `xorm:"VARCHAR(8) UNIQUE(repo_kind) NOT NULL"`
	// ScannedTips is a JSON list of commit IDs whose whole history is scanned. It holds ref tips (those of refs/pull/*
	// in the pull row), so it is never shown: no API or page returns it (only status, counts and the error code). In
	// the row of kind issue (the text scan) it holds the backfill's cursor, a JSON object of issue and comment IDs.
	ScannedTips string `xorm:"LONGTEXT"`
	Status      string `xorm:"VARCHAR(16) NOT NULL DEFAULT ''"`
	Error       string `xorm:"VARCHAR(32) NOT NULL DEFAULT ''"` // a code, never text from git
	// Blobs and Bytes count the last scan: the files read and their size. SkippedLarge counts the files over
	// MAX_BLOB_SIZE that were not read since the scan started from the beginning (a rescan resets it), so a later push
	// doesn't make them look read. It is an upper bound: a file reached again (a merged pull ref, a revert) counts again
	Blobs        int64 `xorm:"NOT NULL DEFAULT 0"`
	Bytes        int64 `xorm:"NOT NULL DEFAULT 0"`
	SkippedLarge int64 `xorm:"NOT NULL DEFAULT 0"`
	Version      int64 `xorm:"NOT NULL DEFAULT 0"` // compare-and-swap counter of the row
	// FailCount counts the failed or limit-stopped slices in a row without progress; RetryUnix is when the cron task
	// and the next trigger may try again (0 = nothing to retry; while a scan is under way it is a safety net).
	FailCount int                `xorm:"NOT NULL DEFAULT 0"`
	RetryUnix timeutil.TimeStamp `xorm:"INDEX NOT NULL DEFAULT 0"`
	// Holes counts what was marked done without being scanned: files of a commit that alone was over the slice limits,
	// files the detector could not scan whole, and secrets left out for the alert cap. Error says why for the last.
	Holes int64 `xorm:"NOT NULL DEFAULT 0"`
	// Requeue marks a repository to scan again after a switch turned on (set with the setting, cleared when the scan
	// takes the row), so that a restart doesn't lose it: the cron task queues marked rows too.
	Requeue int64 `xorm:"INDEX NOT NULL DEFAULT 0"`
	// Completed is set once a scan of this git repository has run to its end (no slice left): a push can only be
	// mailed about for a repository that was scanned before (see notify.go).
	Completed bool `xorm:"NOT NULL DEFAULT false"`
	// The digest mark (repository row only, see notify.go): a push marked the repository after its first complete scan,
	// and the scan that finishes next mails the alerts above NotifyAlertID. Zero NotifyAfterUnix means no mark;
	// NotifySeq counts every marking push, so a clear that raced a newer push is refused. NotifyKinds is a bit set of
	// the DigestKind* flags and NotifyLastUnix is when a digest was last sent (at most one per DigestMinInterval).
	NotifyAfterUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	NotifySeq       int64              `xorm:"NOT NULL DEFAULT 0"`
	NotifyAlertID   int64              `xorm:"NOT NULL DEFAULT 0"`
	NotifyPusherID  int64              `xorm:"NOT NULL DEFAULT 0"`
	NotifyKinds     int                `xorm:"NOT NULL DEFAULT 0"`
	NotifyRef       string             `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	NotifyCommit    string             `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	NotifyLastUnix  timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	// NotifyFloor is the newest alert ID that no digest is owed for: set when a pass ends with the code up to date and
	// no mark, and when a digest is taken. A mark's boundary starts there, so an alert that a scan under way stored
	// before the push's post-receive marked is still mailed.
	NotifyFloor int64 `xorm:"NOT NULL DEFAULT 0"`
	// QueueStuckUnix is when the cron task first found this repository marked or due while the unique queue said it
	// was queued already (0 = not stuck): after an hour the cron task scans it directly.
	QueueStuckUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"INDEX updated"`
}

func (*Scan) TableName() string { return "secret_scan" }

// Alert is one secret (by rule and fingerprint) found in a repository.
type Alert struct {
	ID            int64              `xorm:"pk autoincr"`
	RepoID        int64              `xorm:"UNIQUE(repo_rule_fingerprint) UNIQUE(repo_index) INDEX(repo_state) INDEX(repo_fingerprint) NOT NULL"`
	Index         int64              `xorm:"UNIQUE(repo_index) NOT NULL"`
	RuleID        string             `xorm:"VARCHAR(64) UNIQUE(repo_rule_fingerprint) NOT NULL"`
	SecretType    string             `xorm:"VARCHAR(32) NOT NULL DEFAULT ''"`
	Fingerprint   string             `xorm:"VARCHAR(64) UNIQUE(repo_rule_fingerprint) INDEX(repo_fingerprint) NOT NULL"`
	KeyVersion    int                `xorm:"SMALLINT NOT NULL DEFAULT 1"`
	State         string             `xorm:"VARCHAR(16) INDEX(repo_state) NOT NULL DEFAULT 'open'"`
	Reason        string             `xorm:"VARCHAR(16) NOT NULL DEFAULT ''"` // set when the alert is closed (written by the API and the pages)
	Comment       string             `xorm:"TEXT"`
	ClosedByID    int64              `xorm:"NOT NULL DEFAULT 0"`
	ClosedUnix    timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	LocationCount int                `xorm:"NOT NULL DEFAULT 0"` // every place seen, also those over the cap that have no row
	// ViaPull is true while only refs/pull/* (which any reader can write) reach the secret: such alerts have their
	// own share of the alert cap
	ViaPull     bool               `xorm:"NOT NULL DEFAULT false"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*Alert) TableName() string { return "secret_scanning_alert" }

// Location is a place an alert's secret was found: a file at a line, in the commit that brought it.
type Location struct {
	ID        int64  `xorm:"pk autoincr"`
	AlertID   int64  `xorm:"UNIQUE(alert_location) NOT NULL"`
	RepoID    int64  `xorm:"INDEX NOT NULL"`
	Kind      string `xorm:"VARCHAR(8) UNIQUE(alert_location) NOT NULL"`
	BlobID    string `xorm:"VARCHAR(64) UNIQUE(alert_location) NOT NULL"`
	Path      string `xorm:"TEXT"` // text from git: stripped of control characters, capped at maxPathLen
	PathHash  string `xorm:"VARCHAR(64) UNIQUE(alert_location) NOT NULL"`
	StartLine int    `xorm:"UNIQUE(alert_location) NOT NULL DEFAULT 0"`
	EndLine   int    `xorm:"NOT NULL DEFAULT 0"`
	// CommitID is empty for a blob that only a ref reaches (a tag of a file), then Path is the name rev-list gave
	CommitID    string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	AuthorName  string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"` // the commit's text, for display only: spoofable
	AuthorEmail string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	CommitUnix  int64  `xorm:"NOT NULL DEFAULT 0"`

	// Of a place in text (kinds issue and comment): the issue or comment, the issue it belongs to, the field
	// ("title" or "body" for an issue, "" for a comment), who wrote it (0: nobody known) and when the text stopped
	// holding the secret (0: it still does). The text itself is never stored.
	SourceID    int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	IssueID     int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	Field       string `xorm:"VARCHAR(8) NOT NULL DEFAULT ''"`
	PosterID    int64  `xorm:"NOT NULL DEFAULT 0"`
	RemovedUnix int64  `xorm:"NOT NULL DEFAULT 0"`
}

func (*Location) TableName() string { return "secret_scanning_location" }

// SecretScanningAlertIndex is the per-repository alert number (group_id is the repository), like issue_index.
type SecretScanningAlertIndex db.ResourceIndex

func init() {
	db.RegisterModel(new(Scan))
	db.RegisterModel(new(Alert))
	db.RegisterModel(new(Location))
	db.RegisterModel(new(SecretScanningAlertIndex))
}

// The organization's switch, as user settings of the organization: OrgKey is "false" while the owners turned it
// off (no row = on), OrgLockedKey is "true" while repositories can't change their own switch.
const (
	OrgKey       = "secret_scanning.enabled"
	OrgLockedKey = "secret_scanning.locked"
)

// PathHash is the hash that stands for a path in the unique key of a location.
func PathHash(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:])
}

// cleanText makes text of a commit or a path safe to store and show: no control or format characters, valid
// UTF-8, at most max bytes.
func cleanText(s string, max int) string {
	s = util.StripFormatting(util.StripControl(strings.ToValidUTF8(s, "?")))
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// NewLocation fills a location from the text git gave; the caller sets the alert.
func NewLocation(repoID int64, kind, blobID, path string, startLine, endLine int, commitID, authorName, authorEmail string, commitUnix int64) *Location {
	return &Location{
		RepoID: repoID, Kind: kind, BlobID: blobID, Path: cleanText(path, maxPathLen), PathHash: PathHash(path),
		StartLine: startLine, EndLine: endLine, CommitID: commitID,
		AuthorName: cleanText(authorName, maxAuthorLen), AuthorEmail: cleanText(authorEmail, maxAuthorLen), CommitUnix: commitUnix,
	}
}

// NewTextLocation fills a place in the text of an issue (kind issue, field title or body, source the issue) or of a
// comment (kind comment, field ""). The path stands for the text in the unique key; no text is kept.
func NewTextLocation(repoID int64, kind string, sourceID, issueID int64, field string, startLine, endLine int, posterID int64) *Location {
	path := kind + ":" + strconv.FormatInt(sourceID, 10) + ":" + field
	return &Location{
		RepoID: repoID, Kind: kind, Path: field, PathHash: PathHash(path), StartLine: startLine, EndLine: endLine,
		SourceID: sourceID, IssueID: issueID, Field: field, PosterID: posterID,
	}
}

// GetScan returns the state row, or nil when there is none.
func GetScan(ctx context.Context, repoID int64, kind string) (*Scan, error) {
	s := &Scan{}
	has, err := db.GetEngine(ctx).Where("repo_id = ? AND kind = ?", repoID, kind).Get(s)
	if err != nil || !has {
		return nil, err
	}
	return s, nil
}

// FindScans returns the state rows of a repository: its code, its wiki and its pull refs.
func FindScans(ctx context.Context, repoID int64) (scans []*Scan, err error) {
	return scans, db.GetEngine(ctx).Where("repo_id = ?", repoID).OrderBy("kind").Find(&scans)
}

// ErrScanMoved is a state row that another process changed since it was read.
var ErrScanMoved = errors.New("the scan state changed meanwhile")

// Save writes the state row as the scan that read old (nil = no row) leaves it, and returns ErrScanMoved when
// another process wrote it first (a second row of the same repository and kind, or a changed version).
func Save(ctx context.Context, old, s *Scan) error {
	if err := save(ctx, old, s); err != nil {
		return err
	}
	if s.RetryUnix == 0 { // no slice or retry left: the scan of this git repository has been to its end
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET completed = ? WHERE repo_id = ? AND kind = ? AND completed = ?", true, s.RepoID, s.Kind, false)
		return err
	}
	return nil
}

func save(ctx context.Context, old, s *Scan) error {
	if old == nil {
		// the unique key decides who inserts first; no row inserted is the lost race
		insert := "INSERT INTO secret_scan (repo_id, kind, scanned_tips, status, error, blobs, bytes, skipped_large, fail_count, retry_unix, holes, version, updated_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?) ON CONFLICT (repo_id, kind) DO NOTHING"
		if setting.Database.Type.IsMySQL() {
			insert = "INSERT IGNORE INTO secret_scan (repo_id, kind, scanned_tips, status, error, blobs, bytes, skipped_large, fail_count, retry_unix, holes, version, updated_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)"
		}
		res, err := db.Exec(ctx, insert, s.RepoID, s.Kind, s.ScannedTips, s.Status, s.Error, s.Blobs, s.Bytes, s.SkippedLarge, s.FailCount, s.RetryUnix, s.Holes, timeutil.TimeStampNow())
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return util.Iif(err != nil, err, ErrScanMoved)
		}
		return nil
	}
	n, err := db.GetEngine(ctx).Where("id = ? AND version = ?", old.ID, old.Version).
		Cols("scanned_tips", "status", "error", "blobs", "bytes", "skipped_large", "fail_count", "retry_unix", "holes").Incr("version").Update(s)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrScanMoved
	}
	return nil
}

// GetAlertsByFingerprints returns the alerts of a repository with one of the fingerprints, in one query (the
// caller matches the rule: the same fingerprint under another rule is another alert).
func GetAlertsByFingerprints(ctx context.Context, repoID int64, fingerprints []string) ([]*Alert, error) {
	var alerts []*Alert
	if len(fingerprints) == 0 {
		return alerts, nil
	}
	return alerts, db.GetEngine(ctx).Where("repo_id = ?", repoID).In("fingerprint", fingerprints).Find(&alerts)
}

// OpenAlertCounts are the open alerts of a repository by cap: those of built-in rules (Total) and of them those that
// only refs/pull/* reach, and those of custom patterns (Custom), which have a cap of their own, and of them those that
// only refs/pull/* reach. Closed alerts don't count towards the caps.
type OpenAlertCounts struct {
	Total, ViaPull, Custom, CustomViaPull int64
}

// CountOpenAlertsByCap counts the open alerts of a repository by cap, in one query.
func CountOpenAlertsByCap(ctx context.Context, repoID int64) (c OpenAlertCounts, err error) {
	const isCustom = "CASE WHEN secret_type = 'custom' THEN 1 ELSE 0 END"
	var rows []struct {
		ViaPull bool  `xorm:"via_pull"`
		Custom  int   `xorm:"custom"`
		N       int64 `xorm:"n"`
	}
	if err := db.GetEngine(ctx).Table("secret_scanning_alert").Select("via_pull, "+isCustom+" AS custom, COUNT(*) AS n").
		Where("repo_id = ? AND state = ?", repoID, StateOpen).GroupBy("via_pull, " + isCustom).Find(&rows); err != nil {
		return c, err
	}
	for _, r := range rows {
		total, pulls := &c.Total, &c.ViaPull
		if r.Custom == 1 {
			total, pulls = &c.Custom, &c.CustomViaPull
		}
		*total += r.N
		if r.ViaPull {
			*pulls += r.N
		}
	}
	return c, nil
}

// CountOpenAlerts is CountOpenAlertsByCap without the pull-only custom alerts.
func CountOpenAlerts(ctx context.Context, repoID int64) (total, viaPull, custom int64, err error) {
	c, err := CountOpenAlertsByCap(ctx, repoID)
	return c.Total, c.ViaPull, c.Custom, err
}

// ClearViaPull marks alerts as reached by something other than refs/pull/*.
func ClearViaPull(ctx context.Context, alertIDs []int64) error {
	if len(alertIDs) == 0 {
		return nil
	}
	_, err := db.GetEngine(ctx).In("id", alertIDs).Cols("via_pull").Update(&Alert{ViaPull: false})
	return err
}

// InsertAlert stores a new alert and gives it the next number of its repository; call it in a transaction.
func InsertAlert(ctx context.Context, a *Alert) error {
	idx, err := db.GetNextResourceIndex(ctx, "secret_scanning_alert_index", a.RepoID)
	if err != nil {
		return err
	}
	a.Index = idx
	if a.State == "" {
		a.State = StateOpen
	}
	a.KeyVersion = CurrentKeyVersion
	_, err = db.GetEngine(ctx).Insert(a)
	return err
}

// AddLocationCount adds to the number of places seen of an alert.
func AddLocationCount(ctx context.Context, alertID int64, n int) error {
	_, err := db.GetEngine(ctx).Exec("UPDATE secret_scanning_alert SET location_count = location_count + ?, updated_unix = ? WHERE id = ?", n, timeutil.TimeStampNow(), alertID)
	return err
}

// PlaceKey is what makes a place of an alert: its kind, file path and line (the blob may differ: a file edited
// around the secret is the same place).
type PlaceKey struct {
	Kind, PathHash string
	StartLine      int
}

// StoredPlaces returns, for each of the alerts, the places that have a row, in one query. The number of rows is the
// number of stored places.
func StoredPlaces(ctx context.Context, alertIDs []int64) (map[int64]map[PlaceKey]bool, error) {
	places := map[int64]map[PlaceKey]bool{}
	if len(alertIDs) == 0 {
		return places, nil
	}
	var rows []*Location
	if err := db.GetEngine(ctx).Cols("alert_id", "kind", "path_hash", "start_line").In("alert_id", alertIDs).Find(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if places[r.AlertID] == nil {
			places[r.AlertID] = map[PlaceKey]bool{}
		}
		places[r.AlertID][PlaceKey{r.Kind, r.PathHash, r.StartLine}] = true
	}
	return places, nil
}

// InsertLocations stores places in batches of a few rows per statement.
func InsertLocations(ctx context.Context, locs []*Location) error {
	const batch = 50 // 14 columns each: under SQLite's limit of 999 variables
	for len(locs) > 0 {
		n := min(batch, len(locs))
		if _, err := db.GetEngine(ctx).Insert(locs[:n]); err != nil {
			return err
		}
		locs = locs[n:]
	}
	return nil
}

// UnscannedRepoIDs returns up to limit repositories the cron task should scan: ready, not trashed, secret scanning
// not turned off below the site, and without a state row for the repository (an empty one included: its wiki may
// hold a secret, and the scan stores a row for it), or with a state row of either kind (a wiki too) whose retry time
// (a failed or budget-stopped scan) has come.
func UnscannedRepoIDs(ctx context.Context, now timeutil.TimeStamp, limit int) ([]int64, error) {
	var ids []int64
	err := db.GetEngine(ctx).Table("repository").Select("repository.id").
		Join("LEFT", "secret_scan", "secret_scan.repo_id = repository.id AND secret_scan.kind = ?", KindRepo).
		Where(builder.Eq{"repository.status": repo_model.RepositoryReady, "repository.trashed_unix": 0}).
		And(builder.Not{OffCond()}).
		And(builder.Or(
			builder.IsNull{"secret_scan.id"},
			builder.Exists(builder.Select("1").From("secret_scan", "due").Where(builder.And(
				builder.Expr("due.repo_id = repository.id"),
				builder.Gt{"due.retry_unix": 0},
				builder.Lte{"due.retry_unix": int64(now)},
			))),
		)).
		OrderBy("repository.id").Limit(limit).
		Find(&ids)
	return ids, err
}

// OffCond is, on the repository table, the repositories whose organization or own setting turns secret scanning off:
// the SQL form of services/secretscan.Enabled without the site switch (the caller checks that). Only organizations
// store the settings, so for a personal repository only its own flag counts.
func OffCond() builder.Cond {
	return builder.Or(
		orgSettingCond(OrgKey, "false"),
		builder.And(builder.Eq{"repository.secret_scanning_disabled": true}, builder.Not{orgSettingCond(OrgLockedKey, "true")}),
	)
}

// orgSettingCond is an EXISTS on the user setting key = value of the repository's owner, when that owner is an
// organization (as services/secretscan.Enabled reads it: a personal owner's settings never count).
func orgSettingCond(key, value string) builder.Cond {
	return builder.Exists(builder.Select("1").From("user_setting").Where(builder.And(
		builder.Expr("user_setting.user_id = repository.owner_id"),
		builder.Eq{"user_setting.setting_key": key, "user_setting.setting_value": value},
		builder.In("user_setting.user_id", builder.Select("id").From("`user`").Where(builder.Eq{"type": 1})), // user_model.UserTypeOrganization (models/user can't be imported here)
	)))
}

// orgRepoCond is the repositories of an organization (the ones in projects too), the trash left out.
func orgRepoCond(orgID int64) builder.Cond {
	return builder.Eq{"repository.owner_id": orgID, "repository.trashed_unix": 0}
}

// CountOrgRepos counts the repositories of an organization and, of those, the ones whose admins turned secret
// scanning off (their own setting; it counts while the organization neither turns it off nor locks it).
func CountOrgRepos(ctx context.Context, orgID int64) (total, off int64, err error) {
	if total, err = db.GetEngine(ctx).Table("repository").Where(orgRepoCond(orgID)).Count(); err != nil {
		return 0, 0, err
	}
	off, err = db.GetEngine(ctx).Table("repository").Where(orgRepoCond(orgID)).And("secret_scanning_disabled = ?", true).Count()
	return total, off, err
}

// FindOrgOffRepos lists the repositories of an organization whose admins turned secret scanning off, with the total.
func FindOrgOffRepos(ctx context.Context, orgID int64, opts db.ListOptions) (repo_model.RepositoryList, int64, error) {
	repos := repo_model.RepositoryList{}
	cond := builder.And(orgRepoCond(orgID), builder.Eq{"repository.secret_scanning_disabled": true})
	total, err := db.GetEngine(ctx).Where(cond).OrderBy("repository.lower_name").Limit(opts.PageSize, (opts.Page-1)*opts.PageSize).FindAndCount(&repos)
	return repos, total, err
}

// scannedRepoCond is the ready repositories that have a scan state and secret scanning isn't off for below the site
// (an organization's, or all of them with 0).
func scannedRepoCond(orgID int64) builder.Cond {
	return builder.And(readyRepoCond(orgID), builder.Exists(builder.Select("1").From("secret_scan").Where(builder.Expr("secret_scan.repo_id = repository.id"))))
}

// readyRepoCond is scannedRepoCond without the scan state: for an UPDATE of secret_scan rows, whose rows are the scan
// state, and which must not read secret_scan in a subquery (MySQL refuses it, error 1093).
func readyRepoCond(orgID int64) builder.Cond {
	cond := builder.And(
		builder.Eq{"repository.status": repo_model.RepositoryReady, "repository.trashed_unix": 0},
		builder.Not{OffCond()},
	)
	if orgID != 0 {
		cond = cond.And(builder.Eq{"repository.owner_id": orgID})
	}
	return cond
}

// MarkRequeue marks the repositories ScannedRepoIDsAfter would list (their repository scan state) to be scanned again.
// It runs in the transaction that saves the switch, so the mark and the setting stand or fall together.
func MarkRequeue(ctx context.Context, orgID int64) error {
	// a digest mark that waited while scanning was off keeps its alerts, but not its pusher (a later push is not theirs)
	if _, err := DetachNotifyPushers(ctx, builder.In("repo_id", builder.Select("repository.id").From("repository").Where(readyRepoCond(orgID)))); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).NoAutoTime().
		Where(builder.And(builder.Eq{"kind": KindRepo}, builder.In("repo_id", builder.Select("repository.id").From("repository").Where(readyRepoCond(orgID))))).
		Incr("requeue").Update(&Scan{})
	return err
}

// ResetTextScans makes the text scan of the repository (of every repository with 0) start from the beginning (its row
// reset as ResetScans does) and marks it to be scanned again, if it was scanned: in the transaction that turns the text
// scan, or a repository's Issues or Pull requests unit, on (text written or kept while it was off was not scanned).
// The reset cursor '[]' doesn't read as a cursor object, so the backfill starts from the first issue, and the empty
// status tells it the row is not done.
func ResetTextScans(ctx context.Context, repoID int64) error {
	reset := builder.Eq{"kind": KindIssue}
	scanned := readyRepoCond(0) // the rows updated are the scan state
	if repoID != 0 {
		reset["repo_id"] = repoID
		scanned = scanned.And(builder.Eq{"repository.id": repoID})
	}
	if _, err := db.GetEngine(ctx).Where(reset).NoAutoTime().
		SetExpr("scanned_tips", "'[]'").SetExpr("status", "''").SetExpr("error", "''").SetExpr("fail_count", 0).
		SetExpr("retry_unix", 0).SetExpr("holes", 0).Incr("version").Update(&Scan{}); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).NoAutoTime().
		Where(builder.And(builder.Eq{"kind": KindRepo}, builder.In("repo_id", builder.Select("repository.id").From("repository").Where(scanned)))).
		Incr("requeue").Update(&Scan{})
	return err
}

// ClearRequeue removes the mark when the scan takes the repository, if the counter is still seq (what the scan read
// before it started): a switch turned on meanwhile has counted it up, so its mark stays.
func ClearRequeue(ctx context.Context, repoID, seq int64) error {
	_, err := db.GetEngine(ctx).NoAutoTime().Where("repo_id = ? AND kind = ? AND requeue = ? AND requeue > 0", repoID, KindRepo, seq).Cols("requeue").Update(&Scan{Requeue: 0})
	return err
}

// RequeuedRepoIDsAfter returns up to limit ids above after of the repositories marked by MarkRequeue or by a push (a
// digest mark that waits for a scan) that are still ready, in no trash and not switched off since.
func RequeuedRepoIDsAfter(ctx context.Context, after int64, limit int) ([]int64, error) {
	var ids []int64
	return ids, db.GetEngine(ctx).Table("repository").Select("repository.id").
		Where(builder.Gt{"repository.id": after}).And(scannedRepoCond(0)).
		And(builder.Exists(builder.Select("1").From("secret_scan", "marked").Where(builder.And(
			builder.Expr("marked.repo_id = repository.id"), builder.Eq{"marked.kind": KindRepo},
			builder.Or(builder.Gt{"marked.requeue": 0}, builder.Neq{"marked.notify_after_unix": 0}),
		)))).
		OrderBy("repository.id").Limit(limit).Find(&ids)
}

// MarkQueueStuck records when the repository's queue entry was first found stuck (if it isn't recorded yet) and returns
// that time; hasRow is false when the repository has no scan state to hold it.
func MarkQueueStuck(ctx context.Context, repoID int64, now timeutil.TimeStamp) (since timeutil.TimeStamp, hasRow bool, err error) {
	if _, err = db.GetEngine(ctx).Exec("UPDATE secret_scan SET queue_stuck_unix = ? WHERE repo_id = ? AND kind = ? AND queue_stuck_unix = 0", int64(now), repoID, KindRepo); err != nil {
		return 0, false, err
	}
	s, err := GetScan(ctx, repoID, KindRepo)
	if err != nil || s == nil {
		return 0, false, err
	}
	return s.QueueStuckUnix, true, nil
}

// ClearQueueStuck forgets that the repository's queue entry was stuck.
func ClearQueueStuck(ctx context.Context, repoID int64) error {
	_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET queue_stuck_unix = 0 WHERE repo_id = ? AND kind = ? AND queue_stuck_unix <> 0", repoID, KindRepo)
	return err
}
