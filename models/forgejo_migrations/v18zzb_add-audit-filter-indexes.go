// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import "code.forgejo.org/xorm/xorm"

func init() {
	registerMigration(&Migration{
		Description: "add indexes for the audit log filters",
		Upgrade:     addAuditFilterIndexes,
	})
}

type v18zzbAuditEvent struct {
	CreatedUnix       int64   `xorm:"INDEX NOT NULL"`
	Action            string  `xorm:"VARCHAR(64) NOT NULL index(action_id)"`
	Category          string  `xorm:"VARCHAR(16) NOT NULL index(category_id)"`
	Result            string  `xorm:"VARCHAR(16) NOT NULL"`
	ActorType         string  `xorm:"VARCHAR(16) NOT NULL"`
	ActorID           int64   `xorm:"NOT NULL DEFAULT 0 index(actor_id)"`
	ActorName         string  `xorm:"VARCHAR(255)"`
	SudoByID          int64   `xorm:"NOT NULL DEFAULT 0 index(sudo_by_id)"`
	CredentialType    string  `xorm:"VARCHAR(32) index(credential_id)"`
	CredentialID      int64   `xorm:"NOT NULL DEFAULT 0 index(credential_id)"`
	CredentialName    string  `xorm:"VARCHAR(255)"`
	CredentialOwnerID int64   `xorm:"NOT NULL DEFAULT 0 index(credential_owner_id)"`
	IP                string  `xorm:"VARCHAR(64) index(ip_id)"`
	UserAgent         string  `xorm:"VARCHAR(256)"`
	RequestID         string  `xorm:"VARCHAR(32) INDEX"`
	OwnerID           int64   `xorm:"NOT NULL DEFAULT 0 index(owner_id)"`
	GroupID           int64   `xorm:"NOT NULL DEFAULT 0 index(group_id)"`
	RepoID            int64   `xorm:"NOT NULL DEFAULT 0 index(repo_id)"`
	SubjectUserID     int64   `xorm:"NOT NULL DEFAULT 0 index(subject_user_id)"`
	TargetType        string  `xorm:"VARCHAR(32) index(target)"`
	TargetID          int64   `xorm:"NOT NULL DEFAULT 0 index(target)"`
	TargetName        string  `xorm:"VARCHAR(255)"`
	Data              string  `xorm:"LONGTEXT"`
	Seq               *int64  `xorm:"UNIQUE NULL"`
	PrevHash          *string `xorm:"CHAR(64) NULL"`
	Hash              *string `xorm:"CHAR(64) NULL"`
	ID                int64   `xorm:"pk autoincr index(action_id) index(category_id) index(actor_id) index(sudo_by_id) index(credential_id) index(credential_owner_id) index(ip_id) index(owner_id) index(group_id) index(repo_id) index(subject_user_id)"`
}

func (v18zzbAuditEvent) TableName() string { return "audit_event" }

func addAuditFilterIndexes(x *xorm.Engine) error {
	return x.Sync(new(v18zzbAuditEvent))
}
