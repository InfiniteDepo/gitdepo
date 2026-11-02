// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// AuditEvent is one entry of the audit log
type AuditEvent struct {
	ID int64 `json:"id"`
	// swagger:strfmt date-time
	Time              time.Time `json:"time"`
	Action            string    `json:"action"`
	Category          string    `json:"category"`
	Result            string    `json:"result"`
	ActorType         string    `json:"actor_type"`
	ActorID           int64     `json:"actor_id"`
	ActorName         string    `json:"actor_name"`
	SudoByID          int64     `json:"sudo_by_id"`
	CredentialType    string    `json:"credential_type"`
	CredentialID      int64     `json:"credential_id"`
	CredentialName    string    `json:"credential_name"`
	CredentialOwnerID int64     `json:"credential_owner_id"`
	IP                string    `json:"ip"`
	UserAgent         string    `json:"user_agent"`
	RequestID         string    `json:"request_id"`
	OwnerID           int64     `json:"owner_id"`
	GroupID           int64     `json:"group_id"`
	RepoID            int64     `json:"repo_id"`
	SubjectUserID     int64     `json:"subject_user_id"`
	TargetType        string    `json:"target_type"`
	TargetID          int64     `json:"target_id"`
	TargetName        string    `json:"target_name"`
	// the whitelisted details of the entry, e.g. before and after
	Data map[string]any `json:"data"`
	// position in the hash chain, null until the entry is sealed
	Seq      *int64  `json:"seq"`
	PrevHash *string `json:"prev_hash"`
	Hash     *string `json:"hash"`
}
