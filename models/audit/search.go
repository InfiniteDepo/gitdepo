// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"slices"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// Categories, Results and CredentialTypes are the values a filter accepts.
var (
	Categories      = []string{"auth", "credential", "account", "admin", "org", "repo", "activity", "audit"}
	Results         = []string{ResultSuccess, ResultFailure, ResultRefused}
	CredentialTypes = []string{
		CredentialSession, CredentialPassword, CredentialAccessToken, CredentialOAuth2Grant, CredentialAuthorizedIntegration,
		CredentialSSHKey, CredentialDeployKey, CredentialOrgDeployKey, CredentialProjectDeployKey, CredentialActionsTask, CredentialReverseProxy,
		"runner_token", CredentialChefKey, CredentialSystem, CredentialCLI, CredentialUnknown,
	}
)

// SearchOptions selects entries. Every field is ANDed in SQL; zero values select everything.
type SearchOptions struct {
	OwnerID, GroupID, RepoID int64
	UserID                   int64 // the acting user, the admin behind a sudo, or the account the entry concerns
	CredentialOwnerID        int64
	CredentialTypes          []string
	CredentialType           string // with CredentialID: one credential
	CredentialID             int64
	Action                   string // a catalog key, or a prefix when ActionPrefix is set
	ActionPrefix             bool
	Categories               []string
	Result, IP, RequestID    string
	TargetType               string
	TargetID                 int64
	Since, Before            timeutil.TimeStamp // created_unix >= Since, < Before
	BeforeID, AfterID, MaxID int64              // keyset bounds: id < BeforeID, id > AfterID, id <= MaxID
}

func (o *SearchOptions) cond() builder.Cond {
	cond := builder.NewCond()
	eq := func(col string, v int64) {
		if v != 0 {
			cond = cond.And(builder.Eq{col: v})
		}
	}
	str := func(col, v string) {
		if v != "" {
			cond = cond.And(builder.Eq{col: v})
		}
	}
	eq("owner_id", o.OwnerID)
	eq("group_id", o.GroupID)
	eq("repo_id", o.RepoID)
	eq("credential_owner_id", o.CredentialOwnerID)
	eq("target_id", o.TargetID)
	str("target_type", o.TargetType)
	str("result", o.Result)
	str("ip", o.IP)
	str("request_id", o.RequestID)
	if o.UserID != 0 {
		// actor_id names a user only for user actors (a deploy key's ID is not a user ID)
		cond = cond.And(builder.Or(
			builder.Eq{"actor_type": ActorUser, "actor_id": o.UserID},
			builder.Eq{"sudo_by_id": o.UserID},
			builder.Eq{"subject_user_id": o.UserID},
		))
	}
	if len(o.CredentialTypes) > 0 {
		cond = cond.And(builder.In("credential_type", o.CredentialTypes))
	}
	if o.CredentialType != "" {
		cond = cond.And(builder.Eq{"credential_type": o.CredentialType, "credential_id": o.CredentialID})
	}
	if o.Action != "" {
		if o.ActionPrefix {
			// keys are [a-z0-9_.], so "p." <= key < "p/" is every key below p, with no LIKE wildcards
			cond = cond.And(builder.Gte{"action": o.Action + "."}, builder.Lt{"action": o.Action + "/"})
		} else {
			cond = cond.And(builder.Eq{"action": o.Action})
		}
	}
	if len(o.Categories) > 0 {
		cond = cond.And(builder.In("category", o.Categories))
	}
	if o.Since != 0 {
		cond = cond.And(builder.Gte{"created_unix": o.Since})
	}
	if o.Before != 0 {
		cond = cond.And(builder.Lt{"created_unix": o.Before})
	}
	if o.BeforeID != 0 {
		cond = cond.And(builder.Lt{"id": o.BeforeID})
	}
	if o.AfterID != 0 {
		cond = cond.And(builder.Gt{"id": o.AfterID})
	}
	if o.MaxID != 0 {
		cond = cond.And(builder.Lte{"id": o.MaxID})
	}
	return cond
}

// FindEntries returns at most limit entries, newest first. With AfterID set it returns the limit entries just after
// it (the newer page), still newest first.
func FindEntries(ctx context.Context, o *SearchOptions, limit int) ([]*Entry, error) {
	sess := db.GetEngine(ctx).Where(o.cond()).Limit(limit)
	if o.AfterID != 0 {
		sess = sess.Asc("id")
	} else {
		sess = sess.Desc("id")
	}
	entries := make([]*Entry, 0, limit)
	if err := sess.Find(&entries); err != nil {
		return nil, err
	}
	if o.AfterID != 0 {
		slices.Reverse(entries)
	}
	return entries, nil
}

// IterateEntries calls fn for every matching entry, oldest first, in batches.
func IterateEntries(ctx context.Context, o SearchOptions, fn func(*Entry) error) error {
	for {
		batch := make([]*Entry, 0, 1000)
		if err := db.GetEngine(ctx).Where(o.cond()).Asc("id").Limit(1000).Find(&batch); err != nil {
			return err
		}
		for _, e := range batch {
			if err := fn(e); err != nil {
				return err
			}
		}
		if len(batch) < 1000 {
			return nil
		}
		o.AfterID = batch[len(batch)-1].ID
	}
}

// NthEntry returns the n-th matching entry (0-based), oldest first, or nil if there are fewer.
func NthEntry(ctx context.Context, o *SearchOptions, n int) (*Entry, error) {
	e := &Entry{}
	has, err := db.GetEngine(ctx).Where(o.cond()).Asc("id").Limit(1, n).Get(e)
	if err != nil || !has {
		return nil, err
	}
	return e, nil
}

// MaxEntryID returns the ID of the newest entry.
func MaxEntryID(ctx context.Context) (int64, error) {
	var ids []int64
	err := db.GetEngine(ctx).Table("audit_event").Desc("id").Limit(1).Cols("id").Find(&ids)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	return ids[0], nil
}

// OldestEntryTime returns the time of the oldest entry, or 0.
func OldestEntryTime(ctx context.Context) (timeutil.TimeStamp, error) {
	e := &Entry{}
	has, err := db.GetEngine(ctx).Asc("id").Cols("created_unix").Get(e)
	if err != nil || !has {
		return 0, err
	}
	return e.CreatedUnix, nil
}

// CountSince returns how many entries were written at or after since. It reads the created_unix index.
func CountSince(ctx context.Context, since timeutil.TimeStamp) (int64, error) {
	return db.GetEngine(ctx).Where("created_unix >= ?", since).Count(new(Entry))
}

// HasEntry reports whether an entry of the action exists for the target.
func HasEntry(ctx context.Context, action, targetType string, targetID int64) (bool, error) {
	return db.GetEngine(ctx).Where("action = ? AND target_type = ? AND target_id = ?", action, targetType, targetID).Exist(new(Entry))
}
