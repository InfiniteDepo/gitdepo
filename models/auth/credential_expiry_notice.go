// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"
)

// Credential expiry notice stages: a mail 7 days before a credential expires, and one on the day.
const (
	ExpiryNoticeSoon  = 1
	ExpiryNoticeToday = 2
)

// CredentialExpiryNotice records that the expiry mail of a stage went out for a credential (kind: access_token,
// ssh_key, deploy_key, org_deploy_key) and its expiry date, so each is sent once by one pod. A new expiry (rotation,
// a new key) is a new notice.
type CredentialExpiryNotice struct {
	ID           int64              `xorm:"pk autoincr"`
	Kind         string             `xorm:"VARCHAR(20) NOT NULL UNIQUE(notice)"`
	CredentialID int64              `xorm:"NOT NULL UNIQUE(notice)"`
	ExpiresUnix  timeutil.TimeStamp `xorm:"NOT NULL UNIQUE(notice) INDEX"`
	Stage        int                `xorm:"NOT NULL UNIQUE(notice)"`
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
}

func init() {
	db.RegisterModel(new(CredentialExpiryNotice))
}

// ClaimCredentialExpiryNotice reports whether the caller is the one to send the notice: false when it was sent
// already, also by another pod at the same time (the unique key decides).
func ClaimCredentialExpiryNotice(ctx context.Context, kind string, credentialID int64, expires timeutil.TimeStamp, stage int) (bool, error) {
	n := &CredentialExpiryNotice{Kind: kind, CredentialID: credentialID, ExpiresUnix: expires, Stage: stage}
	if has, err := db.GetEngine(ctx).Exist(&CredentialExpiryNotice{Kind: kind, CredentialID: credentialID, ExpiresUnix: expires, Stage: stage}); err != nil || has {
		return false, err
	}
	if _, err := db.GetEngine(ctx).Insert(n); err != nil {
		if has, err2 := db.GetEngine(ctx).Exist(&CredentialExpiryNotice{Kind: kind, CredentialID: credentialID, ExpiresUnix: expires, Stage: stage}); err2 == nil && has {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ReleaseCredentialExpiryNotice takes a claim back, so the next run sends the notice.
func ReleaseCredentialExpiryNotice(ctx context.Context, kind string, credentialID int64, expires timeutil.TimeStamp, stage int) error {
	_, err := db.GetEngine(ctx).Where("kind = ? AND credential_id = ? AND expires_unix = ? AND stage = ?", kind, credentialID, expires, stage).Delete(&CredentialExpiryNotice{})
	return err
}

// DeleteOldCredentialExpiryNotices removes the notices of expiry dates before the given time.
func DeleteOldCredentialExpiryNotices(ctx context.Context, before timeutil.TimeStamp) error {
	_, err := db.GetEngine(ctx).Where("expires_unix < ?", before).Delete(&CredentialExpiryNotice{})
	return err
}
