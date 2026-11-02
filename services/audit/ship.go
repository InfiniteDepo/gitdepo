// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"maps"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
)

// shipEntries writes the entries a sealer just committed to the "audit" logger, one JSON event each, in seq order.
// It is best effort: the database is the source of truth, and a full writer queue only drops the event. The message
// is the action key; `data` goes out as one string, so it is redacted and capped like every other field. Without a
// writer nothing is built.
func shipEntries(ctx context.Context, rows []*audit_model.Entry) {
	l := log.GetManager().GetLogger("audit")
	if !l.IsEnabled() {
		return
	}
	orgs, projects, repos := entryNames(ctx, rows)
	for _, e := range rows {
		level := log.INFO
		if e.Result != audit_model.ResultSuccess {
			level = log.WARN
		}
		data, promoted := splitData(e)
		fields := map[string]any{
			"timestamp": int64(e.CreatedUnix) * 1000, // when it happened, not when it is shipped
			"action":    e.Action, "category": e.Category, "result": e.Result,
			"ip": e.IP, "ip_ambiguous": false, "user_agent": e.UserAgent, "request_id": e.RequestID,
			"actor_type": e.ActorType, "actor_id": e.ActorID, "actor_name": e.ActorName, "sudo_by_id": e.SudoByID,
			"credential_type": e.CredentialType, "credential_id": e.CredentialID, "credential_name": e.CredentialName, "credential_owner_id": e.CredentialOwnerID,
			"target_type": e.TargetType, "target_id": e.TargetID, "target_name": e.TargetName,
			"org": orgs[e.OwnerID], "project": projects[e.GroupID], "repo": repos[e.RepoID],
			"owner_id": e.OwnerID, "group_id": e.GroupID, "repo_id": e.RepoID, "subject_user_id": e.SubjectUserID,
			"auth_method": "", "kind": "", "bytes": 0,
			"seq": *e.Seq, "prev_hash": *e.PrevHash, "hash": *e.Hash, "data": data,
		}
		maps.Copy(fields, promoted)
		l.LogWithFields(0, level, fields, "%s", e.Action)
	}
}

// splitData moves the keys that are top-level fields of a shipped event out of the entry's data: ip_ambiguous, kind
// and bytes, and the method of a sign-in or credential use as auth_method (the method of an API request is HTTP's).
// Data that isn't a JSON object is shipped as it is.
func splitData(e *audit_model.Entry) (string, map[string]any) {
	var m map[string]any
	if e.Data == "" || json.Unmarshal([]byte(e.Data), &m) != nil || m == nil {
		return e.Data, nil
	}
	promoted := map[string]any{}
	for _, k := range []string{"ip_ambiguous", "kind", "bytes"} {
		if v, ok := m[k]; ok {
			promoted[k] = v
			delete(m, k)
		}
	}
	if v, ok := m["method"]; ok && (e.TargetType == "signin" || e.TargetType == "credential_use") {
		promoted["auth_method"] = v
		delete(m, "method")
	}
	if len(promoted) == 0 {
		return e.Data, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return e.Data, nil
	}
	return string(b), promoted
}

// entryNames resolves the owner, project and repository names of a batch with one query each, trashed ones included.
// A name that can't be resolved stays "".
func entryNames(ctx context.Context, rows []*audit_model.Entry) (orgs, projects, repos map[int64]string) {
	ids := func(id func(*audit_model.Entry) int64) (out []int64) {
		seen := map[int64]bool{0: true}
		for _, e := range rows {
			if i := id(e); !seen[i] {
				seen[i] = true
				out = append(out, i)
			}
		}
		return out
	}
	names := func(table string, ids []int64) map[int64]string {
		out := map[int64]string{}
		if len(ids) == 0 {
			return out
		}
		var found []struct {
			ID   int64
			Name string
		}
		if err := db.GetEngine(ctx).Table(table).In("id", ids).Cols("id", "name").Find(&found); err != nil {
			log.Error("audit: resolving names for shipping: %v", err)
			return out
		}
		for _, f := range found {
			out[f.ID] = f.Name
		}
		return out
	}
	return names("user", ids(func(e *audit_model.Entry) int64 { return e.OwnerID })),
		names("repo_group", ids(func(e *audit_model.Entry) int64 { return e.GroupID })),
		names("repository", ids(func(e *audit_model.Entry) int64 { return e.RepoID }))
}
