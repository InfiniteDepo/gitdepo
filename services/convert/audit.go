// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package convert

import (
	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/json"
	api "forgejo.org/modules/structs"
)

// AuditData decodes the stored data of an entry; data that doesn't decode is kept as {"_raw": data}.
func AuditData(data string) map[string]any {
	m := map[string]any{}
	if data == "" {
		return m
	}
	if err := json.Unmarshal([]byte(data), &m); err != nil || m == nil {
		return map[string]any{"_raw": data}
	}
	return m
}

// ToAuditEvent converts an audit log entry.
func ToAuditEvent(e *audit_model.Entry) *api.AuditEvent {
	return &api.AuditEvent{
		ID:                e.ID,
		Time:              e.CreatedUnix.AsTime().UTC(),
		Action:            e.Action,
		Category:          e.Category,
		Result:            e.Result,
		ActorType:         e.ActorType,
		ActorID:           e.ActorID,
		ActorName:         e.ActorName,
		SudoByID:          e.SudoByID,
		CredentialType:    e.CredentialType,
		CredentialID:      e.CredentialID,
		CredentialName:    e.CredentialName,
		CredentialOwnerID: e.CredentialOwnerID,
		IP:                e.IP,
		UserAgent:         e.UserAgent,
		RequestID:         e.RequestID,
		OwnerID:           e.OwnerID,
		GroupID:           e.GroupID,
		RepoID:            e.RepoID,
		SubjectUserID:     e.SubjectUserID,
		TargetType:        e.TargetType,
		TargetID:          e.TargetID,
		TargetName:        e.TargetName,
		Data:              AuditData(e.Data),
		Seq:               e.Seq,
		PrevHash:          e.PrevHash,
		Hash:              e.Hash,
	}
}
