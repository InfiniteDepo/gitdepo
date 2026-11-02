// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"errors"
	"slices"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// ClosedStates are the states an alert is closed with; its reason is the same word.
var ClosedStates = []string{StateRevoked, StateFalsePos, StateUsedInTests, StateWontFix}

// MaxCommentLen is the longest comment of a closed alert, in bytes.
const MaxCommentLen = 1000

// MaxFilterLen is the longest secret type or rule filter.
const MaxFilterLen = 64

// ErrAlertNotExist is an alert that is not in the repository.
var ErrAlertNotExist = util.NewNotExistErrorf("the secret alert does not exist")

// ErrAlertState is a change that the current state of the alert doesn't allow (it changed meanwhile).
var ErrAlertState = errors.New("the secret alert changed")

// GetAlert returns the alert with this number in the repository.
func GetAlert(ctx context.Context, repoID, index int64) (*Alert, error) {
	a := &Alert{}
	has, err := db.GetEngine(ctx).Where("repo_id = ? AND `index` = ?", repoID, index).Get(a)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, ErrAlertNotExist
	}
	return a, nil
}

// GetVisibleAlert is GetAlert for a viewer: without Wiki read, an alert that is only in the wiki is not there (the
// rule of AlertSearchOptions.CodeOnly, so every alert a list shows can be opened).
func GetVisibleAlert(ctx context.Context, repoID, index int64, canReadWiki bool) (*Alert, error) {
	alert, err := GetAlert(ctx, repoID, index)
	if err != nil || canReadWiki {
		return alert, err
	}
	if has, err := HasCodeLocation(ctx, alert.RepoID, alert.ID); err != nil {
		return nil, err
	} else if !has {
		return nil, ErrAlertNotExist
	}
	return alert, nil
}

// likeContains is "key contains value", case-insensitive, with % and _ in the value taken literally (! escapes).
func likeContains(key, value string) builder.Cond {
	value = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value)
	if setting.Database.Type.IsSQLite3() { // UPPER there only changes ASCII letters
		value = util.ToUpperASCII(value)
	} else {
		value = strings.ToUpper(value)
	}
	return builder.Expr("UPPER("+key+") LIKE ? ESCAPE '!'", "%"+value+"%")
}

// RepoSearchCond matches, on the repository table, the repositories whose name or owner name holds q (a part of a
// name, case-insensitive; % and _ are taken literally).
func RepoSearchCond(q string) builder.Cond {
	return builder.Or(likeContains("`repository`.name", q), likeContains("`repository`.owner_name", q))
}

// HasAlerts tells whether the repository has an alert the viewer can see (one query, stops at the first row).
func HasAlerts(ctx context.Context, repoID int64, codeOnly bool) (bool, error) {
	opts := &AlertSearchOptions{RepoID: repoID, CodeOnly: codeOnly}
	return db.GetEngine(ctx).Table("secret_scanning_alert").Where(opts.ToConds()).Exist()
}

// AlertSearchOptions selects the alerts of one repository, newest first.
type AlertSearchOptions struct {
	db.ListOptions
	RepoID int64
	// RepoCond, if set, replaces RepoID: the alerts of the repositories that match it (a condition on the repository
	// table), for the lists across repositories.
	RepoCond    builder.Cond
	State       string   // open or resolved
	Resolutions []string // closed states
	SecretTypes []string // rule IDs
	Sort        string   // created (the default) or updated
	Ascending   bool
	CodeOnly    bool     // only alerts that have a place outside the wiki
	Kinds       []string // only alerts that have a place of one of these kinds (KindRepo, KindWiki, KindPull, KindIssue, KindComment)
	PathQuery   string   // only alerts with a place whose path holds this text (the wiki's places only without CodeOnly, never the text's)
}

func (o *AlertSearchOptions) ToConds() builder.Cond {
	cond := builder.NewCond().And(builder.Eq{"repo_id": o.RepoID})
	if o.RepoCond != nil {
		cond = builder.In("repo_id", builder.Select("`repository`.id").From("repository").Where(o.RepoCond))
	}
	switch o.State {
	case StateOpen:
		cond = cond.And(builder.Eq{"state": StateOpen})
	case "resolved":
		cond = cond.And(builder.In("state", ClosedStates))
	}
	if len(o.Resolutions) > 0 {
		cond = cond.And(builder.In("state", o.Resolutions))
	}
	if len(o.SecretTypes) > 0 {
		cond = cond.And(builder.In("rule_id", o.SecretTypes))
	}
	if o.CodeOnly {
		cond = cond.And(builder.Expr("EXISTS (SELECT 1 FROM secret_scanning_location WHERE secret_scanning_location.alert_id = secret_scanning_alert.id AND secret_scanning_location.kind <> ?)", KindWiki))
	}
	if len(o.Kinds) > 0 {
		cond = cond.And(builder.Exists(builder.Select("1").From("secret_scanning_location").Where(builder.And(
			builder.Expr("secret_scanning_location.alert_id = secret_scanning_alert.id"), builder.In("secret_scanning_location.kind", o.Kinds),
		))))
	}
	if o.PathQuery != "" {
		in := builder.And(builder.Expr("secret_scanning_location.alert_id = secret_scanning_alert.id"), likeContains("secret_scanning_location.path", o.PathQuery))
		if o.CodeOnly {
			in = in.And(builder.Neq{"secret_scanning_location.kind": KindWiki})
		}
		in = in.And(builder.NotIn("secret_scanning_location.kind", TextKinds)) // a text place's path is only its field name
		cond = cond.And(builder.Exists(builder.Select("1").From("secret_scanning_location").Where(in)))
	}
	return cond
}

func (o *AlertSearchOptions) ToOrders() string {
	col, dir := "id", " DESC"
	if o.Sort == "updated" {
		col = "updated_unix"
	}
	if o.Ascending {
		dir = ""
	}
	return col + dir + ", id" + dir
}

// ParseFilters checks the state, the comma lists and the order of the list filters.
func (o *AlertSearchOptions) ParseFilters(state, resolution, secretType, sort, direction string) error {
	if sort != "" && sort != "created" && sort != "updated" || direction != "" && direction != "asc" && direction != "desc" {
		return util.NewInvalidArgumentErrorf("sort must be created or updated, direction asc or desc")
	}
	o.Sort, o.Ascending = sort, direction == "asc"
	if state != "" && state != StateOpen && state != "resolved" {
		return util.NewInvalidArgumentErrorf("state must be open or resolved")
	}
	if len(resolution) > MaxFilterLen*8 || len(secretType) > MaxFilterLen*8 {
		return util.NewInvalidArgumentErrorf("the filter is too long")
	}
	o.State = state
	for r := range strings.SplitSeq(resolution, ",") {
		if r = strings.TrimSpace(r); r != "" && !slices.Contains(ClosedStates, r) {
			return util.NewInvalidArgumentErrorf("unknown resolution")
		} else if r != "" {
			o.Resolutions = append(o.Resolutions, r)
		}
	}
	for t := range strings.SplitSeq(secretType, ",") {
		if t = strings.TrimSpace(t); len(t) > MaxFilterLen {
			return util.NewInvalidArgumentErrorf("the filter is too long")
		} else if t != "" {
			o.SecretTypes = append(o.SecretTypes, t)
		}
	}
	return nil
}

// LocationSearchOptions pages the places of one alert, in the order they were found.
type LocationSearchOptions struct {
	db.ListOptions
	RepoID, AlertID int64
	NoWiki          bool // leave out the places of the wiki
}

func (o *LocationSearchOptions) ToConds() builder.Cond {
	return builder.NewCond().And(builder.Eq{"repo_id": o.RepoID, "alert_id": o.AlertID}, readableKinds(o.NoWiki))
}

func (o *LocationSearchOptions) ToOrders() string { return "id" }

// AnyFingerprint tells whether an alert of the repository, open or resolved, has one of the fingerprints (looked up
// in chunks). With codeOnly, an alert that is only in the wiki doesn't count.
func AnyFingerprint(ctx context.Context, repoID int64, fingerprints []string, codeOnly bool) (bool, error) {
	for chunk := range slices.Chunk(fingerprints, 500) {
		opts := &AlertSearchOptions{RepoID: repoID, CodeOnly: codeOnly}
		cond := opts.ToConds().And(builder.In("fingerprint", chunk))
		if has, err := db.GetEngine(ctx).Where(cond).Exist(new(Alert)); err != nil || has {
			return has, err
		}
	}
	return false, nil
}

// HasCodeLocation tells whether the alert has a stored place outside the wiki, the rule of AlertSearchOptions.CodeOnly
// (a place in text counts: such an alert is listed, so it can be opened and closed; the place itself is not shown).
func HasCodeLocation(ctx context.Context, repoID, alertID int64) (bool, error) {
	return db.GetEngine(ctx).Where(builder.Eq{"repo_id": repoID, "alert_id": alertID}.And(builder.Neq{"kind": KindWiki})).Exist(new(Location))
}

// LocationKinds returns the kinds of places the alert has (each once), in one query.
func LocationKinds(ctx context.Context, repoID, alertID int64) (kinds []string, err error) {
	return kinds, db.GetEngine(ctx).Table("secret_scanning_location").Distinct("kind").Where(builder.Eq{"repo_id": repoID, "alert_id": alertID}).Find(&kinds)
}

// CountLocations counts the stored places of the alerts in one query, without those in the wiki when noWiki is set.
// A repoID of 0 means the alerts may be of any repository (their IDs are unique).
func CountLocations(ctx context.Context, repoID int64, alertIDs []int64, noWiki bool) (map[int64]int, error) {
	var rows []struct {
		AlertID int64
		N       int
	}
	cond := builder.In("alert_id", alertIDs)
	if repoID != 0 {
		cond = cond.And(builder.Eq{"repo_id": repoID})
	}
	cond = cond.And(readableKinds(noWiki))
	err := db.GetEngine(ctx).Table("secret_scanning_location").Select("alert_id, COUNT(*) AS n").Where(cond).GroupBy("alert_id").Find(&rows)
	out := make(map[int64]int, len(rows))
	for _, r := range rows {
		out[r.AlertID] = r.N
	}
	return out, err
}

// FindLocations returns up to limit places of an alert in the order they were found.
func FindLocations(ctx context.Context, repoID, alertID int64, limit int) ([]*Location, error) {
	var locs []*Location
	return locs, db.GetEngine(ctx).Where(builder.Eq{"repo_id": repoID, "alert_id": alertID}.And(readableKinds(false))).OrderBy("id").Limit(limit).Find(&locs)
}

// CloseAlert closes an open alert as state with the comment; the UPDATE is conditional on the alert being open, so
// of two concurrent closes one gets ErrAlertState. before is the alert as it was.
func CloseAlert(ctx context.Context, repoID, index int64, state, comment string, byID int64) (before *Alert, err error) {
	if before, err = GetAlert(ctx, repoID, index); err != nil {
		return nil, err
	}
	n, err := db.GetEngine(ctx).Where("repo_id = ? AND `index` = ? AND state = ?", repoID, index, StateOpen).
		Cols("state", "reason", "comment", "closed_by_id", "closed_unix").
		Update(&Alert{State: state, Reason: state, Comment: comment, ClosedByID: byID, ClosedUnix: timeutil.TimeStampNow()})
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return before, ErrAlertState
	}
	return before, nil
}

// ReopenAlert reopens a closed alert and clears what closing set. An alert that is open is left as it is
// (changed is false).
func ReopenAlert(ctx context.Context, repoID, index int64) (before *Alert, changed bool, err error) {
	if before, err = GetAlert(ctx, repoID, index); err != nil {
		return nil, false, err
	}
	if before.State == StateOpen {
		return before, false, nil
	}
	n, err := db.GetEngine(ctx).Where("repo_id = ? AND `index` = ? AND state = ?", repoID, index, before.State).
		Cols("state", "reason", "comment", "closed_by_id", "closed_unix").Update(&Alert{State: StateOpen})
	if err != nil {
		return nil, false, err
	}
	if n != 1 {
		return before, false, ErrAlertState
	}
	return before, true, nil
}

// CountByState counts the open and the closed alerts of the repository, in one query; with codeOnly, alerts that are
// only in the wiki are left out.
func CountByState(ctx context.Context, repoID int64, codeOnly bool) (open, closed int64, err error) {
	var rows []struct {
		State string
		N     int64
	}
	opts := &AlertSearchOptions{RepoID: repoID, CodeOnly: codeOnly}
	if err := db.GetEngine(ctx).Table("secret_scanning_alert").Select("state, COUNT(*) AS n").Where(opts.ToConds()).GroupBy("state").Find(&rows); err != nil {
		return 0, 0, err
	}
	for _, r := range rows {
		if r.State == StateOpen {
			open += r.N
		} else {
			closed += r.N
		}
	}
	return open, closed, nil
}

// FindRuleIDs returns the rules the repository has alerts of (for the type filter), without alerts that are only in
// the wiki when codeOnly is set.
func FindRuleIDs(ctx context.Context, repoID int64, codeOnly bool) (ids []string, err error) {
	opts := &AlertSearchOptions{RepoID: repoID, CodeOnly: codeOnly}
	return ids, db.GetEngine(ctx).Table("secret_scanning_alert").Distinct("rule_id").Where(opts.ToConds()).OrderBy("rule_id").Find(&ids)
}

// FirstLocations returns the first stored place of each alert, in one query; with noWiki, a place in the wiki isn't
// one. A repoID of 0 means the alerts may be of any repository.
func FirstLocations(ctx context.Context, repoID int64, alertIDs []int64, noWiki bool) (map[int64]*Location, error) {
	out := make(map[int64]*Location, len(alertIDs))
	if len(alertIDs) == 0 {
		return out, nil
	}
	cond := builder.In("alert_id", alertIDs)
	if repoID != 0 {
		cond = cond.And(builder.Eq{"repo_id": repoID})
	}
	cond = cond.And(readableKinds(noWiki))
	first := builder.Select("MIN(id)").From("secret_scanning_location").Where(cond).GroupBy("alert_id")
	var locs []*Location
	if err := db.GetEngine(ctx).Where(builder.In("id", first)).Find(&locs); err != nil {
		return nil, err
	}
	for _, l := range locs {
		out[l.AlertID] = l
	}
	return out, nil
}

// DeleteScans removes the scan state of the repository, so the next scan starts from the beginning and its holes
// are gone; the alerts stay. It returns the number of rows removed.
func DeleteScans(ctx context.Context, repoID int64) (int64, error) {
	return db.GetEngine(ctx).Where("repo_id = ?", repoID).Delete(new(Scan))
}

// ResetScans makes the repository's scan states forget what was scanned (the done tips, the holes, a failure's
// backoff), so the next scan starts from the beginning; the alerts stay, and so do the completed flag and any digest
// mark: pushes before or during a rescan still mail only the alerts that are new, and a rescan that finds an alert
// again mails nothing. Version moves on, so a scan that read the row before can't save it. It returns the number of
// rows that had something to forget (0 when the rows are already reset: two rescans at once claim it once).
func ResetScans(ctx context.Context, repoID int64) (int64, error) {
	res, err := db.GetEngine(ctx).Exec(
		"UPDATE secret_scan SET scanned_tips = '[]', status = '', error = '', blobs = 0, bytes = 0, skipped_large = 0, fail_count = 0, retry_unix = 0, holes = 0, version = version + 1"+
			" WHERE repo_id = ? AND NOT (status = '' AND scanned_tips = '[]' AND retry_unix = 0 AND fail_count = 0)", repoID,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
