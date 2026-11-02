// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	stdctx "context"
	"encoding/csv"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	audit_model "forgejo.org/models/audit"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	dependency_service "forgejo.org/services/dependency"
	secretscan_service "forgejo.org/services/secretscan"
	vulnerability_service "forgejo.org/services/vulnerability"
)

// The org and instance dependency and vulnerability alert searches are served by the API and by the web pages; the
// parts they share (the audit entries and the export download) are here.

func usageFilters(scope dependency_service.SearchScope, f dependency_service.UsageFilter) map[string]string {
	direct := ""
	if f.Direct.Has() {
		direct = strconv.FormatBool(f.Direct.ValueOrDefault(false))
	}
	return map[string]string{
		"ecosystem": f.Ecosystem, "name": f.Name, "version": f.Version, "range": f.Range, "direct": direct, "owner": scope.Owner, "project": scope.Project,
	}
}

func alertFilters(scope dependency_service.SearchScope, f vulnerability_service.AlertFilter) map[string]string {
	return map[string]string{
		"advisory": f.Advisory, "ecosystem": f.Ecosystem, "name": f.Name, "version": f.Version, "state": f.State, "severity": f.Severity, "owner": scope.Owner, "project": scope.Project,
	}
}

// recordInstanceSearch writes the audit entry of a search across every owner (one per request, aggregated per
// minute and kind, fail open): the route kind, the filters given and the total, never a repository name. The
// organization routes record nothing: an owner reads their own organization.
func recordInstanceSearch(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, kind string, filters map[string]string, total int64) {
	if scope.Org != nil || doer == nil {
		return
	}
	data := map[string]any{"kind": kind, "total": total}
	for k, v := range filters {
		if v != "" {
			data[k] = v
		}
	}
	audit_model.RecordAggregated(ctx.Req.Context(), audit_model.Event{
		Action: "activity.dependency_graph.searched", Result: audit_model.ResultSuccess, OwnerID: doer.ID, SubjectUserID: doer.ID,
		TargetType: "dependency_search", TargetID: doer.ID, TargetName: doer.Name, Data: data,
	}, strconv.FormatInt(doer.ID, 10)+"|"+kind)
}

// RecordUsageSearch records a dependency search (see recordInstanceSearch).
func RecordUsageSearch(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, f dependency_service.UsageFilter, total int64) {
	recordInstanceSearch(ctx, doer, scope, "dependencies", map[string]string{"ecosystem": f.Ecosystem, "name": f.Name, "owner": scope.Owner}, total)
}

// RecordAlertSearch records an alert search (see recordInstanceSearch).
func RecordAlertSearch(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, f vulnerability_service.AlertFilter, total int64) {
	recordInstanceSearch(ctx, doer, scope, "alerts", map[string]string{"advisory": f.Advisory, "ecosystem": f.Ecosystem, "name": f.Name, "owner": scope.Owner, "state": f.State}, total)
}

// exportSlots limits the exports that run at once in this process; an export that finds no free slot is refused.
var exportSlots = make(chan struct{}, 2)

// ExportTimeLimit is how long one export may run; it is checked between batches (a variable for tests).
var ExportTimeLimit = 10 * time.Minute

// ExportStallTime is how long the writes of one batch of an export may wait for a client that stops reading;
// the window starts again with each batch, so a slow but reading client is only bound by ExportTimeLimit.
var ExportStallTime = time.Minute

var (
	exportingMu sync.Mutex
	exporting   = map[int64]bool{} // the doers with an export running: one each
)

// ErrExportBusy and ErrExportTimeLimit are exports that stopped before the first byte.
var (
	ErrExportBusy      = errors.New("too many exports are running, try again shortly")
	ErrExportTimeLimit = errors.New("the export took too long")
)

// TakeExportSlot reserves a slot of the process and the doer's one place; release gives both back.
func TakeExportSlot(doerID int64) (release func(), ok bool) {
	exportingMu.Lock()
	defer exportingMu.Unlock()
	if exporting[doerID] {
		return nil, false
	}
	select {
	case exportSlots <- struct{}{}:
		exporting[doerID] = true
		var once sync.Once
		return func() { // giving back twice is harmless
			once.Do(func() {
				exportingMu.Lock()
				defer exportingMu.Unlock()
				delete(exporting, doerID)
				<-exportSlots
			})
		}, true
	default:
		return nil, false
	}
}

// exportRow is a row of an export: the object of the JSON form and the cells of the CSV form.
type exportRow struct {
	obj   any
	cells []string
}

// recordExport writes the audit entry of an export (fail closed, before the first byte): the kind, the format, the
// filters given (for secret alerts the repository search text too, as typed) and the row count.
func recordExport(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, kind, format string, filters map[string]string, count int64) error {
	data := map[string]any{"kind": kind, "format": format, "count": count}
	for k, v := range filters {
		if v != "" {
			data[k] = v
		}
	}
	e := audit_model.Event{
		Action: "admin.dependency_graph.exported", Result: audit_model.ResultSuccess, TargetType: "dependency_export", Data: data,
	}
	if kind == "secrets" {
		e.Action, e.TargetType = "admin.secret_alerts.exported", "secret_export"
	}
	if scope.Org != nil {
		e.Action, e.OwnerID, e.TargetID, e.TargetName = "org.dependency_graph.exported", scope.Org.ID, scope.Org.ID, scope.Org.Name
		if kind == "secrets" {
			e.Action = "org.secret_alerts.exported"
		}
	} else {
		e.OwnerID, e.TargetID, e.TargetName = doer.ID, doer.ID, doer.Name
	}
	e.SubjectUserID = doer.ID
	return audit_model.Record(ctx.Req.Context(), e)
}

// serveExport streams the rows run reads as a download in format ("csv" or "json"). run calls start with the row
// count once, before any row; start records the audit entry and sends the headers, so an error before it (a wrong
// filter, too many rows, a failed audit insert) is returned with nothing written, for the caller to answer. After the
// first byte a failure aborts the connection, so the client sees a failed download, not a short file.
func serveExport(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, kind, format string, filters map[string]string, header []string,
	run func(start func(total int64) error, emit func([]exportRow) error) error,
) error {
	release, ok := TakeExportSlot(doer.ID)
	if !ok {
		return ErrExportBusy
	}
	defer release()
	deadline := time.Now().Add(ExportTimeLimit)
	// A client that stops reading would block a write, and hold the slot, past the time limit: each batch may wait
	// ExportStallTime for the client, never past the time limit.
	rc, hasDeadline := http.NewResponseController(ctx.Resp), true
	stallDeadline := func() {
		if !hasDeadline {
			return
		}
		until := time.Now().Add(ExportStallTime)
		if until.After(deadline) {
			until = deadline
		}
		if err := rc.SetWriteDeadline(until); err != nil {
			hasDeadline = false
			log.Warn("serveExport: the writes of the export have no deadline: %v", err)
		}
	}
	stallDeadline()
	if hasDeadline {
		defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	}
	batches := 0
	sep := "["
	cw, enc := csv.NewWriter(ctx.Resp), json.NewEncoder(ctx.Resp)
	err := run(func(total int64) error {
		if err := recordExport(ctx, doer, scope, kind, format, filters, total); err != nil {
			return err
		}
		name, owner, contentType := "dependencies", "instance", "text/csv"
		switch kind {
		case "alerts":
			name = "vulnerability-alerts"
		case "secrets":
			name = "secret-alerts"
		}
		if scope.Org != nil {
			owner = scope.Org.Name
		}
		if format == "json" {
			contentType = "application/json"
		}
		ctx.SetServeHeaders(&context.ServeHeaderOptions{
			ContentType: contentType, ContentTypeCharset: "utf-8",
			Filename: name + "-" + owner + "-" + time.Now().UTC().Format("2006-01-02") + "." + format,
		})
		ctx.Resp.Header().Set("Cache-Control", "no-store")
		if format == "csv" {
			return cw.Write(header)
		}
		return nil
	}, func(rows []exportRow) error {
		if batches++; batches > 1 && time.Now().After(deadline) { // before the next batch is written, never after the last
			return ErrExportTimeLimit
		}
		stallDeadline()
		for n, r := range rows {
			if n%100 == 99 && time.Now().After(deadline) {
				return ErrExportTimeLimit
			}
			if format == "json" {
				if _, err := ctx.Resp.Write([]byte(sep)); err != nil {
					return err
				}
				sep = ","
				if err := enc.Encode(r.obj); err != nil {
					return err
				}
				continue
			}
			cells := make([]string, len(r.cells))
			for i, c := range r.cells {
				cells[i] = util.CSVSafe(c)
			}
			if err := cw.Write(cells); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && format == "json" {
		end := "]\n"
		if sep == "[" {
			end = "[]\n"
		}
		_, err = ctx.Resp.Write([]byte(end))
	}
	if err == nil {
		cw.Flush()
		err = cw.Error()
	}
	switch {
	case err == nil:
		return nil
	case ctx.Resp.WrittenStatus() == 0: // no byte is out: an ordinary answer
		h := ctx.Resp.Header()
		h.Del("Content-Disposition")
		h.Del("Content-Type")
		if errors.Is(err, stdctx.Canceled) {
			log.Info("serveExport: cancelled: %v", err)
			ctx.Resp.WriteHeader(500)
			return nil
		}
		if errors.Is(err, ErrExportTimeLimit) {
			log.Info("serveExport: %v", err)
		}
		return err
	default:
		// a client that stops reading ends at the write deadline: os.ErrDeadlineExceeded
		if errors.Is(err, stdctx.Canceled) || errors.Is(err, ErrExportTimeLimit) || errors.Is(err, os.ErrDeadlineExceeded) {
			log.Info("serveExport: %v", err)
		} else {
			log.Error("serveExport: %v", err)
		}
		panic(http.ErrAbortHandler) // abort so the client sees a failed download, not a short file
	}
}

// ExportDependencies sends every row of the dependency search as a download; a non-nil error is an answer not yet
// given (a wrong filter wraps util.ErrInvalidArgument).
func ExportDependencies(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, f dependency_service.UsageFilter, format string) error {
	return serveExport(ctx, doer, scope, "dependencies", format, usageFilters(scope, f),
		[]string{"repository", "ecosystem", "name", "version", "requirement", "manifest", "direct", "uncertain"},
		func(start func(int64) error, emit func([]exportRow) error) error {
			return dependency_service.ExportUsage(ctx, scope, f, start, func(rows []*dependency_service.UsageRow) error {
				out := make([]exportRow, len(rows))
				for i, r := range rows {
					out[i] = exportRow{obj: convert.ToDependencyUsage(r), cells: []string{
						r.Repo.FullName(), r.Ecosystem, r.Name, r.Version, r.Requirement, r.ManifestPath, strconv.FormatBool(r.Direct), strconv.FormatBool(r.Uncertain),
					}}
				}
				return emit(out)
			})
		})
}

// ExportAlerts sends every alert of the alert search as a download, as ExportDependencies does.
func ExportAlerts(ctx *context.Base, doer *user_model.User, scope dependency_service.SearchScope, f vulnerability_service.AlertFilter, format string) error {
	return serveExport(ctx, doer, scope, "alerts", format, alertFilters(scope, f),
		[]string{"repository", "advisory", "aliases", "severity", "ecosystem", "package", "version", "fixed in", "manifest", "state"},
		func(start func(int64) error, emit func([]exportRow) error) error {
			return vulnerability_service.ExportAlerts(ctx, scope, f, start, func(hits []*vulnerability_service.AlertHit) error {
				alerts, err := convert.ToRepoVulnerabilityAlerts(ctx, doer, hits)
				if err != nil {
					return err
				}
				out := make([]exportRow, len(alerts))
				for i, a := range alerts {
					a.Advisory.Details, a.Advisory.References = "", []api.VulnerabilityReference{} // the full texts stay in the paged answer; an export of 100000 rows would carry them each
					out[i] = exportRow{obj: a, cells: []string{
						a.Repository.FullName, a.Advisory.ID, strings.Join(a.Advisory.Aliases, " "), a.Severity, a.Ecosystem, a.Package, a.Version,
						strings.Join(a.FixedVersions, " "), a.ManifestPath, a.State,
					}}
				}
				return emit(out)
			})
		})
}

// ExportSecretAlerts sends every alert of a secret alert list as a CSV download, as ExportAlerts does. The columns are
// those the page lists, with no secret or fingerprint (the scanner stores neither); the comment is the closer's own
// text, CSV-safe as every cell.
func ExportSecretAlerts(ctx *context.Base, doer *user_model.User, scope secretscan_service.Scope, f secretscan_service.Filter, absoluteURL func(*secretscan_model.Alert, *repo_model.Repository) string) error {
	filters := map[string]string{"state": f.State, "reason": f.Reason, "type": f.Type, "owner": scope.Owner, "project": scope.Project, "q": scope.Query}
	return serveExport(ctx, doer, dependency_service.SearchScope{Org: scope.Org}, "secrets", "csv", filters,
		[]string{"state", "reason", "closed_by", "closed_at", "comment", "first_seen", "repository", "type", "location", "alert_url"},
		func(start func(int64) error, emit func([]exportRow) error) error {
			return secretscan_service.Export(ctx, scope, f, start, func(hits []*secretscan_service.Hit) error {
				out := make([]exportRow, len(hits))
				for i, h := range hits {
					state, reason, closedBy, closedAt := h.State, h.Reason, "", ""
					if h.State != secretscan_model.StateOpen {
						state = "closed"
						if h.ClosedBy != nil {
							closedBy = h.ClosedBy.Name
						}
						closedAt = h.ClosedUnix.AsTime().UTC().Format(time.RFC3339)
					}
					location := ""
					if h.First != nil && h.First.IsText() { // a fixed token: lists across repositories never name an issue
						location = "text:" + h.First.Kind
					} else if h.First != nil {
						location = h.First.Path
						if h.First.StartLine > 0 {
							location += ":" + strconv.Itoa(h.First.StartLine)
						}
					}
					out[i] = exportRow{cells: []string{
						state, reason, closedBy, closedAt, h.Comment, h.CreatedUnix.AsTime().UTC().Format(time.RFC3339),
						h.Repo.FullName(), h.Text(ctx.Locale), location, absoluteURL(h.Alert, h.Repo),
					}}
				}
				return emit(out)
			})
		})
}
