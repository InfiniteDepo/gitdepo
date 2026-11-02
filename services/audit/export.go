// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"encoding/csv"
	"io"
	"maps"
	"net/url"
	"strconv"
	"strings"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/json"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/convert"
)

// ExportCap is the most rows a web or API export holds; the CLI export has no cap.
var ExportCap = 100_000 // a variable for tests

// Manifest describes an export.
type Manifest struct {
	Filter      []string
	GeneratedAt time.Time
	Truncated   bool
	Through     time.Time // the time of the last row, when Truncated
	ThroughID   int64
	Rows        int
	SealedSeq   int64 // the chain head after sealing, before the snapshot
	SealedHash  string
}

// FilterHeader returns the filter as a query string, for X-Audit-Filter.
func (m *Manifest) FilterHeader() string {
	filter := make([]string, 0, len(m.Filter))
	for _, kv := range m.Filter {
		k, v, _ := strings.Cut(kv, "=")
		filter = append(filter, k+"="+url.QueryEscape(v))
	}
	return strings.Join(filter, "&")
}

// Next returns the filter parameters that continue a truncated export.
func (m *Manifest) Next(f *Filter) url.Values {
	next := maps.Clone(f.Values)
	next.Set("since", m.Through.Format(time.RFC3339))
	next.Set("after_id", strconv.FormatInt(m.ThroughID, 10))
	return next
}

// CSVHeader names the CSV columns.
var CSVHeader = []string{
	"id", "time", "action", "category", "result", "actor_type", "actor_id", "actor_name", "sudo_by_id",
	"credential_type", "credential_id", "credential_name", "credential_owner_id", "ip", "user_agent", "request_id",
	"owner_id", "group_id", "repo_id", "subject_user_id", "target_type", "target_id", "target_name", "data",
	"seq", "prev_hash", "hash",
}

// Export writes the entries of f as "csv" or "json", oldest first, from a snapshot taken when it starts. With cap > 0
// it stops after cap rows. It records the export before anything is written and calls start (headers, manifest)
// right before the first byte; an error before that means nothing was written.
func Export(ctx context.Context, w io.Writer, f *Filter, format string, cap int, start func(*Manifest) error) (*Manifest, error) {
	if err := SealAll(ctx); err != nil { // a backlog beyond the cap is not an error: the headers name what was reached
		return nil, err
	}
	head, err := audit_model.GetHead(ctx)
	if err != nil {
		return nil, err
	}
	o := f.Opts
	maxID, err := audit_model.MaxEntryID(ctx)
	if err != nil {
		return nil, err
	}
	o.MaxID = maxID
	if maxID == 0 {
		o.MaxID = -1 // an empty table gives an empty export, not one that holds its own entry
	}
	m := &Manifest{Filter: f.List(), GeneratedAt: time.Now().UTC(), SealedSeq: head.Seq, SealedHash: head.Hash}
	if cap > 0 {
		if extra, err := audit_model.NthEntry(ctx, &o, cap); err != nil {
			return nil, err
		} else if extra != nil {
			last, err := audit_model.NthEntry(ctx, &o, cap-1)
			if err != nil {
				return nil, err
			}
			m.Truncated, m.Through, m.ThroughID, o.MaxID = true, last.CreatedUnix.AsTime().UTC(), last.ID, last.ID
		}
	}
	if err := recordExport(ctx, format, m); err != nil {
		return nil, err
	}
	if err := start(m); err != nil {
		return nil, err
	}

	var write func(e *audit_model.Entry) error
	var finish func() error
	if format == "csv" {
		cw := csv.NewWriter(w)
		if err := cw.Write(CSVHeader); err != nil {
			return m, err
		}
		write = func(e *audit_model.Entry) error {
			return cw.Write(csvRow(e))
		}
		finish = func() error {
			cw.Flush()
			return cw.Error()
		}
	} else {
		enc := json.NewEncoder(w)
		sep := "["
		write = func(e *audit_model.Entry) error {
			if _, err := io.WriteString(w, sep); err != nil {
				return err
			}
			sep = ","
			return enc.Encode(convert.ToAuditEvent(e))
		}
		finish = func() error {
			end := "]\n"
			if sep == "[" {
				end = "[]\n"
			}
			_, err := io.WriteString(w, end)
			return err
		}
	}
	err = audit_model.IterateEntries(ctx, o, func(e *audit_model.Entry) error {
		m.Rows++
		return write(e)
	})
	if err == nil {
		err = finish()
	}
	return m, err
}

func recordExport(ctx context.Context, format string, m *Manifest) error {
	data := map[string]any{"format": format, "filter": m.Filter, "capped": m.Truncated}
	for _, v := range m.Filter {
		if len(v) > 255 { // Record cuts each item, so a long value never cuts off the next one
			data["truncated"] = true
		}
	}
	if m.Truncated {
		data["through_id"] = m.ThroughID
	}
	return audit_model.Record(ctx, audit_model.Event{
		Action:     "audit.exported",
		Result:     audit_model.ResultSuccess,
		TargetType: "audit_export",
		Data:       data,
	})
}

func csvRow(e *audit_model.Entry) []string {
	id := func(n int64) string { return strconv.FormatInt(n, 10) }
	ptr := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	seq := ""
	if e.Seq != nil {
		seq = id(*e.Seq)
	}
	data, _ := json.Marshal(convert.AuditData(e.Data))
	row := []string{
		id(e.ID), csvTime(e.CreatedUnix), e.Action, e.Category, e.Result, e.ActorType, id(e.ActorID), e.ActorName, id(e.SudoByID),
		e.CredentialType, id(e.CredentialID), e.CredentialName, id(e.CredentialOwnerID), e.IP, e.UserAgent, e.RequestID,
		id(e.OwnerID), id(e.GroupID), id(e.RepoID), id(e.SubjectUserID), e.TargetType, id(e.TargetID), e.TargetName, string(data),
		seq, ptr(e.PrevHash), ptr(e.Hash),
	}
	for i := range row {
		row[i] = util.CSVSafe(row[i])
	}
	return row
}

func csvTime(t timeutil.TimeStamp) string {
	return t.AsTime().UTC().Format(time.RFC3339)
}
