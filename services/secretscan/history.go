// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"slices"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/json"
	"forgejo.org/modules/timeutil"
)

// Event is one change of an alert as the audit log recorded it: the alert was closed (with State as reason and a
// comment), reopened, or its secret was removed from a text (Redacted; which text is not told: the history is
// shown to people who may not read the issue).
type Event struct {
	Reopened       bool
	Redacted       bool
	HistoryOnly    bool // a redaction that found the secret no longer in the text
	State, Comment string
	ActorID        int64
	ActorName      string
	CreatedUnix    timeutil.TimeStamp
}

const historyLimit = 100

// AlertHistory reads the closes, reopens and redactions of the alert from the audit log, oldest first (at most the last 100).
func AlertHistory(ctx context.Context, repoID, alertID int64) ([]*Event, error) {
	entries, err := audit_model.FindEntries(ctx, &audit_model.SearchOptions{
		RepoID: repoID, TargetType: "secret_scanning_alert", TargetID: alertID, Action: "repo.secret_alert", ActionPrefix: true,
	}, historyLimit)
	if err != nil {
		return nil, err
	}
	events := make([]*Event, 0, len(entries))
	for _, e := range entries {
		var data struct {
			State, Comment string
			HistoryOnly    bool `json:"history_only"`
		}
		_ = json.Unmarshal([]byte(e.Data), &data) // text we wrote ourselves; an unreadable row shows without details
		events = append(events, &Event{
			Reopened: e.Action == "repo.secret_alert.reopened", Redacted: e.Action == "repo.secret_alert.text_redacted", State: data.State, Comment: data.Comment,
			HistoryOnly: data.HistoryOnly, ActorID: e.ActorID, ActorName: e.ActorName, CreatedUnix: e.CreatedUnix,
		})
	}
	slices.Reverse(events)
	return events, nil
}

// SwitchChange is the last time a repository admin turned secret scanning on or off for a repository.
type SwitchChange struct {
	On          bool
	ActorID     int64
	ActorName   string
	CreatedUnix timeutil.TimeStamp
}

// LastSwitchChange reads it from the audit log, from the last 50 settings changes of the repository (the audit search
// can not filter on a data key); nil when it finds none (it is the default, the entry was purged or is older).
func LastSwitchChange(ctx context.Context, repoID int64) (*SwitchChange, error) {
	entries, err := audit_model.FindEntries(ctx, &audit_model.SearchOptions{RepoID: repoID, Action: "repo.repository.updated"}, 50)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		var data struct {
			After map[string]any `json:"after"`
		}
		if json.Unmarshal([]byte(e.Data), &data) != nil {
			continue
		}
		if on, ok := data.After["secret_scanning"].(bool); ok {
			return &SwitchChange{On: on, ActorID: e.ActorID, ActorName: e.ActorName, CreatedUnix: e.CreatedUnix}, nil
		}
	}
	return nil, nil //nolint:nilnil // no switch change on record
}
