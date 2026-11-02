// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"html"
	"html/template"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	audit_model "forgejo.org/models/audit"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/routers/common"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	logshipping_service "forgejo.org/services/logshipping"
)

const tplAudit base.TplName = "admin/audit"

const auditPageSize = 50

var auditTabs = []string{"changes", "signins", "activity", "all"}

// AuditReq lets a usable site admin or auditor through; it runs after the sign-in check. The auditor only reads:
// IsAuditorView needs a GET or HEAD made with a credential the auditor holds.
func AuditReq(ctx *context.Context) {
	if !common.UsableAuditReader(ctx.Doer) || !ctx.Doer.IsAdmin && !ctx.IsAuditorView() {
		ctx.Error(http.StatusForbidden)
		return
	}
	SetSecuritySearchNav(ctx)
}

// auditRow is an entry as the page shows it.
type auditRow struct {
	*audit_model.Entry
	Time       string
	SudoByName string
	// Event is the translated action; the target fills a %s in the phrase, or follows it after a dot.
	Event   template.HTML
	Changes []auditChange
	Details map[string]string
	// AggregatedCount is the number of events folded into an ".aggregated" entry, 0 for any other entry.
	AggregatedCount                 int64
	AggregatedFirst, AggregatedLast string
	AggregatedLink                  string
}

type auditChange struct {
	Key, Before, After string
}

// auditValue is the text of a data value: a string as it is, anything else as JSON, nothing as "".
func auditValue(v any, ok bool) string {
	if s, isString := v.(string); isString || !ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// auditTimeKeys are the data keys that hold a unix time in seconds.
var auditTimeKeys = []string{"expires", "first", "last"}

// auditTimeValue is v as "date (raw)" in loc when v is a whole number of seconds in a sane range, else its plain text.
func auditTimeValue(v any, loc *time.Location) string {
	if f, ok := v.(float64); ok && f == math.Trunc(f) && f > 0 && f < 1e11 {
		return time.Unix(int64(f), 0).In(loc).Format("2006-01-02 15:04:05") + " (" + strconv.FormatInt(int64(f), 10) + ")"
	}
	return auditValue(v, true)
}

// auditDataValue is the text of the data value k: a time for the known time keys.
func auditDataValue(k string, v any, ok bool, loc *time.Location) string {
	if ok && slices.Contains(auditTimeKeys, k) {
		return auditTimeValue(v, loc)
	}
	return auditValue(v, ok)
}

// setAggregated fills the label and the link of an ".aggregated" entry that counted events in a known window. The
// link lists the entries of the same action in that window, by the same IP when the entry has one.
func (r *auditRow) setAggregated(data map[string]any, loc *time.Location) {
	action, ok := strings.CutSuffix(r.Action, ".aggregated")
	count, _ := data["count"].(float64)
	first, _ := data["first"].(float64)
	last, _ := data["last"].(float64)
	if !ok || count < 1 || first <= 0 || last < first || last >= 1e11 {
		return
	}
	r.AggregatedCount = int64(count)
	r.AggregatedFirst = time.Unix(int64(first), 0).In(loc).Format("2006-01-02 15:04:05")
	r.AggregatedLast = time.Unix(int64(last), 0).In(loc).Format("2006-01-02 15:04:05")
	q := url.Values{
		"category": {"all"}, "action": {action},
		"since":  {time.Unix(int64(first), 0).UTC().Format(time.RFC3339)},
		"before": {time.Unix(int64(last)+1, 0).UTC().Format(time.RFC3339)},
	}
	if r.IP != "" {
		q.Set("ip", r.IP)
	}
	r.AggregatedLink = "?" + q.Encode()
}

func newAuditRow(e *audit_model.Entry, loc *time.Location, names map[int64]string) *auditRow {
	data := convert.AuditData(e.Data)
	r := &auditRow{Entry: e, Time: e.CreatedUnix.AsTime().In(loc).Format("2006-01-02 15:04:05"), Details: map[string]string{}}
	if e.SudoByID != 0 {
		r.SudoByName = names[e.SudoByID]
		if r.SudoByName == "" {
			r.SudoByName = "#" + strconv.FormatInt(e.SudoByID, 10)
		}
	}
	before, _ := data["before"].(map[string]any)
	after, _ := data["after"].(map[string]any)
	for k, v := range data {
		if k != "before" && k != "after" {
			r.Details[k] = auditDataValue(k, v, true, loc)
		}
	}
	r.setAggregated(data, loc)
	var keys []string
	for k := range before {
		keys = append(keys, k)
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		b, hasBefore := before[k]
		a, hasAfter := after[k]
		r.Changes = append(r.Changes, auditChange{Key: k, Before: auditDataValue(k, b, hasBefore, loc), After: auditDataValue(k, a, hasAfter, loc)})
	}
	return r
}

// auditResolved is what a name or ID filter selected, shown next to the filters.
type auditResolved struct {
	Label, Name string
	ID          int64
}

// resolveAuditFilter names the objects of the ID filters, trashed ones included; a missing one has no name.
func resolveAuditFilter(ctx *context.Context, o *audit_model.SearchOptions) ([]auditResolved, error) {
	var out []auditResolved
	for _, u := range []struct {
		label string
		id    int64
	}{
		{ctx.Locale.TrString("admin.audit.org"), o.OwnerID},
		{ctx.Locale.TrString("admin.audit.user"), o.UserID},
		{ctx.Locale.TrString("admin.audit.credential_owner"), o.CredentialOwnerID},
	} {
		if u.id == 0 {
			continue
		}
		r := auditResolved{Label: u.label, ID: u.id}
		if user, err := user_model.GetUserByIDIncludingTrashed(ctx, u.id); err == nil {
			r.Name = user.Name
		} else if !user_model.IsErrUserNotExist(err) {
			return nil, err
		}
		out = append(out, r)
	}
	if o.RepoID != 0 {
		r := auditResolved{Label: ctx.Locale.TrString("admin.audit.repo"), ID: o.RepoID}
		if repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, o.RepoID); err == nil {
			r.Name = repo.FullName()
		} else if !repo_model.IsErrRepoNotExist(err) {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// auditLocation is the time zone the page shows times in: the user's, or UTC when there is none or it can't be loaded.
func auditLocation(tz string) *time.Location {
	if loc, err := time.LoadLocation(tz); tz != "" && err == nil {
		return loc
	}
	return time.UTC
}

// Audit shows the audit log, or exports it with ?format=csv|json.
func Audit(ctx *context.Context) {
	f, err := audit_service.ParseFilter(ctx, ctx.FormString)
	filterErr, _ := errors.AsType[*audit_service.FilterError](err)
	if err != nil && filterErr == nil {
		ctx.ServerError("ParseFilter", err)
		return
	}

	if format := ctx.FormString("format"); format == "csv" || format == "json" {
		if filterErr != nil {
			ctx.PlainText(http.StatusUnprocessableEntity, filterErr.Error())
			return
		}
		if ctx.Req.Method == http.MethodHead {
			return // a HEAD neither costs a heavy token nor records an export
		}
		if common.ChargeHeavyPlain(ctx) {
			common.ExportAudit(ctx.Base, f, format, setting.AppURL+"admin/audit")
		}
		return
	}

	ctx.Data["Title"] = ctx.Tr("admin.audit.title")
	ctx.Data["PageIsAdminAudit"] = true
	ctx.Data["Tabs"] = auditTabs
	ctx.Data["CredentialTypes"] = audit_model.CredentialTypes
	ctx.Data["Results"] = audit_model.Results
	ctx.Data["CategoryOptions"] = append(slices.Clone(auditTabs), slices.DeleteFunc(slices.Clone(audit_model.Categories), func(c string) bool { return slices.Contains(auditTabs, c) })...)
	ctx.Data["ActionKeys"] = audit_service.ActionKeys
	query := ctx.Req.URL.Query()
	ctx.Data["Filter"] = query
	n := 0
	for _, k := range audit_service.Params {
		if query.Get(k) != "" && !slices.Contains([]string{"category", "before_id", "after_id", "credential"}, k) {
			n++
		}
	}
	ctx.Data["FilterCount"] = n
	ctx.Data["ClearLink"] = "?category=" + url.QueryEscape(query.Get("category"))
	if filterErr != nil {
		tabLinks := map[string]string{}
		for _, tab := range auditTabs {
			tabLinks[tab] = "?category=" + tab
		}
		ctx.Data["TabLinks"] = tabLinks
		ctx.Data["FilterError"] = filterErr
		ctx.Data["Category"] = query.Get("category")
		ctx.HTML(http.StatusUnprocessableEntity, tplAudit)
		return
	}
	ctx.Data["Category"] = f.Values.Get("category")

	link := func(change func(q url.Values)) string {
		q := maps.Clone(f.Values)
		q.Del("before_id")
		q.Del("after_id")
		change(q)
		return "?" + q.Encode()
	}
	tabLinks := map[string]string{}
	for _, tab := range auditTabs {
		tabLinks[tab] = link(func(q url.Values) { q.Set("category", tab) })
	}
	ctx.Data["TabLinks"] = tabLinks
	ctx.Data["CSVLink"] = link(func(q url.Values) { q.Set("format", "csv") })
	ctx.Data["JSONLink"] = link(func(q url.Values) { q.Set("format", "json") })
	ctx.Data["RemoveCredentialLink"] = link(func(q url.Values) { q.Del("credential") })
	ctx.Data["OnlyLinkBase"] = ctx.Data["RemoveCredentialLink"]

	resolved, err := resolveAuditFilter(ctx, &f.Opts)
	if err != nil {
		ctx.ServerError("resolveAuditFilter", err)
		return
	}
	ctx.Data["Resolved"] = resolved

	if f.OrgID != 0 {
		projects, err := repo_model.GetRepoGroupsByOwnerIDs(ctx, []int64{f.OrgID})
		if err != nil {
			ctx.ServerError("GetRepoGroupsByOwnerIDs", err)
			return
		}
		ctx.Data["Projects"] = projects
	}

	entries, newer, older, err := audit_service.Page(ctx, f, auditPageSize)
	if err != nil {
		ctx.ServerError("Page", err)
		return
	}
	var sudoIDs []int64
	for _, e := range entries {
		if e.SudoByID != 0 {
			sudoIDs = append(sudoIDs, e.SudoByID)
		}
	}
	users, err := user_model.GetUsersByIDs(ctx, sudoIDs)
	if err != nil {
		ctx.ServerError("GetUsersByIDs", err)
		return
	}
	names := map[int64]string{}
	for _, u := range users {
		names[u.ID] = u.Name
	}
	tz, err := user_model.GetUserTimeZone(ctx, ctx.Doer.ID)
	if err != nil {
		ctx.ServerError("GetUserTimeZone", err)
		return
	}
	loc := auditLocation(tz)
	ctx.Data["TimeZone"] = loc.String()
	rows := make([]*auditRow, 0, len(entries))
	for _, e := range entries {
		r := newAuditRow(e, loc, names)
		if ctx.Locale.HasKey("admin.audit.action." + e.Action) {
			if e.TargetName != "" && strings.Contains(ctx.Locale.TrString("admin.audit.action."+e.Action), "%s") {
				r.Event = ctx.Locale.Tr("admin.audit.action."+e.Action, e.TargetName)
			} else {
				r.Event = ctx.Locale.Tr("admin.audit.action." + e.Action)
				if e.TargetName != "" {
					r.Event += " · " + template.HTML(html.EscapeString(e.TargetName))
				}
			}
		}
		rows = append(rows, r)
	}
	ctx.Data["Rows"] = rows
	if f.Opts.CredentialType != "" && len(rows) > 0 {
		ctx.Data["CredentialName"] = rows[0].CredentialName
	}
	if len(rows) > 0 {
		if newer {
			ctx.Data["NewerLink"] = link(func(q url.Values) { q.Set("after_id", strconv.FormatInt(rows[0].ID, 10)) })
		}
		if older {
			ctx.Data["OlderLink"] = link(func(q url.Values) { q.Set("before_id", strconv.FormatInt(rows[len(rows)-1].ID, 10)) })
		}
	}
	oldest, err := audit_model.OldestEntryTime(ctx)
	if err != nil {
		ctx.ServerError("OldestEntryTime", err)
		return
	}
	ctx.Data["LogEmpty"] = oldest == 0
	if oldest != 0 {
		ctx.Data["OldestEntry"] = oldest.AsTime().In(loc).Format("2006-01-02")
	}
	ctx.Data["ExportCap"] = audit_service.ExportCap
	ctx.Data["StreamingCount"] = logshipping_service.StreamingCount() // a count only: auditors see no destination
	ctx.Data["RetentionLine"] = auditRetentionLine(ctx)
	ctx.Data["CanEditRetention"] = ctx.Doer.IsAdmin
	ctx.Data["LogReads"] = setting.Audit.LogReads
	ctx.Data["WriteErrors"] = audit_model.WriteErrors.Load()
	if err := setSealStatus(ctx); err != nil {
		ctx.ServerError("setSealStatus", err)
		return
	}
	ctx.HTML(http.StatusOK, tplAudit)
}

// setSealStatus sets the line "Sealed through #N (time UTC) · M unsealed" and the anchor help. A stuck sealer shows as
// a growing age of the oldest unsealed entry.
func setSealStatus(ctx *context.Context) error {
	head, err := audit_model.GetHead(ctx)
	if err != nil {
		return err
	}
	n, age, err := audit_model.UnsealedStats(ctx)
	if err != nil {
		return err
	}
	line := ctx.Locale.TrString("admin.audit.sealed_none")
	if head.Seq > 0 {
		last, err := audit_model.GetBySeq(ctx, head.Seq)
		if err != nil || last == nil {
			return err
		}
		line = ctx.Locale.TrString("admin.audit.sealed_through", head.Seq, last.CreatedUnix.AsTime().UTC().Format("2006-01-02 15:04:05"))
		ctx.Data["Anchor"] = ctx.Locale.TrString("admin.audit.anchor_help", head.Seq, head.Hash)
	}
	line += " · " + ctx.Locale.TrString("admin.audit.unsealed", unsealedCount(n))
	if n > 0 {
		line += " (" + ctx.Locale.TrString("admin.audit.unsealed_oldest", age.Round(time.Second).String()) + ")"
	}
	ctx.Data["SealLine"] = line
	return nil
}

// unsealedCount shows a backlog past the count cap as "10000+".
func unsealedCount(n int64) string {
	if n >= audit_model.UnsealedCountCap {
		return strconv.Itoa(audit_model.UnsealedCountCap-1) + "+"
	}
	return strconv.FormatInt(n, 10)
}
