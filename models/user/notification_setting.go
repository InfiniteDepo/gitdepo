// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"context"
	"slices"

	"forgejo.org/models/db"
	"forgejo.org/modules/setting"

	"xorm.io/builder"
)

// NotifyEvent is one kind of mail a Custom user can tick.
type NotifyEvent string

const (
	NotifyEventPRComment           NotifyEvent = "pr_comment"
	NotifyEventPRApproved          NotifyEvent = "pr_approved"
	NotifyEventPRChangesRequested  NotifyEvent = "pr_changes_requested"
	NotifyEventPRMerged            NotifyEvent = "pr_merged"
	NotifyEventPRClosed            NotifyEvent = "pr_closed"
	NotifyEventPRNewCommits        NotifyEvent = "pr_new_commits"
	NotifyEventReviewRequestedMe   NotifyEvent = "review_requested_me"
	NotifyEventIssueAssigned       NotifyEvent = "issue_assigned"
	NotifyEventIssueComment        NotifyEvent = "issue_comment"
	NotifyEventIssueClosedReopened NotifyEvent = "issue_closed_reopened"
	NotifyEventMention             NotifyEvent = "mention"
	NotifyEventWatchNewIssue       NotifyEvent = "watch_new_issue"
	NotifyEventWatchNewPR          NotifyEvent = "watch_new_pr"
	NotifyEventWatchRelease        NotifyEvent = "watch_release"
	NotifyEventWatchEveryComment   NotifyEvent = "watch_every_comment"
	NotifyEventActionsFailed       NotifyEvent = "actions_failed"
	NotifyEventCredentialExpiry    NotifyEvent = "credential_expiry"
	NotifyEventSecretAlert         NotifyEvent = "secret_alert"
	NotifyEventDeployments         NotifyEvent = "deployments" // a deployment waits for my review, mine was rejected or expired
	// NotifyEventOwnActions is not a mail kind: it decides whether mail about the user's own actions is sent.
	NotifyEventOwnActions NotifyEvent = "own_actions"
)

// AllNotifyEvents is the single list the settings page, the API and the stored rows are validated against.
var AllNotifyEvents = []NotifyEvent{
	NotifyEventPRComment, NotifyEventPRApproved, NotifyEventPRChangesRequested, NotifyEventPRMerged,
	NotifyEventPRClosed, NotifyEventPRNewCommits, NotifyEventReviewRequestedMe, NotifyEventIssueAssigned,
	NotifyEventIssueComment, NotifyEventIssueClosedReopened, NotifyEventMention, NotifyEventWatchNewIssue,
	NotifyEventWatchNewPR, NotifyEventWatchRelease, NotifyEventWatchEveryComment, NotifyEventActionsFailed,
	NotifyEventCredentialExpiry, NotifyEventSecretAlert, NotifyEventDeployments, NotifyEventOwnActions,
}

func (e NotifyEvent) IsValid() bool { return slices.Contains(AllNotifyEvents, e) }

// IsValidEmailNotificationsPreference reports whether p is one of the four presets or custom.
func IsValidEmailNotificationsPreference(p string) bool {
	switch p {
	case EmailNotificationsEnabled, EmailNotificationsOnMention, EmailNotificationsAndYourOwn,
		EmailNotificationsDisabled, EmailNotificationsCustom:
		return true
	}
	return false
}

// NotificationSetting is one stored tick. RepoID 0 is the user's own setting, any other value a per-repo override.
type NotificationSetting struct {
	ID      int64  `xorm:"pk autoincr"`
	UserID  int64  `xorm:"UNIQUE(user_repo_event) NOT NULL"`
	RepoID  int64  `xorm:"UNIQUE(user_repo_event) NOT NULL DEFAULT 0"`
	Event   string `xorm:"UNIQUE(user_repo_event) VARCHAR(40) NOT NULL"`
	Enabled bool   `xorm:"NOT NULL"`
}

func (NotificationSetting) TableName() string { return "user_notification_setting" }

func init() {
	db.RegisterModel(new(NotificationSetting))
}

// NotificationSettings holds the stored rows of one user for one repo. A nil value means no rows.
type NotificationSettings struct {
	User, Repo map[NotifyEvent]bool
}

// HasRepoOverride reports whether the user customised this repo.
func (s *NotificationSettings) HasRepoOverride() bool { return s != nil && len(s.Repo) > 0 }

// Enabled resolves an event: repo row, user row, instance default list, built-in default.
func (s *NotificationSettings) Enabled(e NotifyEvent) bool {
	if s != nil {
		if v, ok := s.Repo[e]; ok {
			return v
		}
		if v, ok := s.User[e]; ok {
			return v
		}
	}
	if list := setting.Admin.DefaultEmailNotificationEvents; len(list) > 0 {
		return slices.Contains(list, string(e))
	}
	return e != NotifyEventWatchEveryComment && e != NotifyEventOwnActions
}

// LoadNotificationSettings loads the user and repo rows of all given users in one query.
func LoadNotificationSettings(ctx context.Context, userIDs []int64, repoID int64) (map[int64]*NotificationSettings, error) {
	res := make(map[int64]*NotificationSettings)
	if len(userIDs) == 0 {
		return res, nil
	}
	var rows []*NotificationSetting
	if err := db.GetEngine(ctx).Where(builder.In("user_id", userIDs).And(builder.In("repo_id", 0, repoID))).Find(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		s := res[r.UserID]
		if s == nil {
			s = &NotificationSettings{User: map[NotifyEvent]bool{}, Repo: map[NotifyEvent]bool{}}
			res[r.UserID] = s
		}
		if r.RepoID == 0 {
			s.User[NotifyEvent(r.Event)] = r.Enabled
		} else {
			s.Repo[NotifyEvent(r.Event)] = r.Enabled
		}
	}
	return res, nil
}

// SaveNotificationSettings replaces the rows of the user (repoID 0) or of the user's override for repoID.
// Callers validate the events against AllNotifyEvents.
func SaveNotificationSettings(ctx context.Context, userID, repoID int64, events map[NotifyEvent]bool) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := DeleteRepoNotificationSettings(ctx, userID, repoID); err != nil {
			return err
		}
		rows := make([]*NotificationSetting, 0, len(events))
		for e, v := range events {
			rows = append(rows, &NotificationSetting{UserID: userID, RepoID: repoID, Event: string(e), Enabled: v})
		}
		if len(rows) == 0 {
			return nil
		}
		return db.Insert(ctx, rows)
	})
}

// DeleteRepoNotificationSettings removes the rows of one user for one repo (0 = the user's own rows).
func DeleteRepoNotificationSettings(ctx context.Context, userID, repoID int64) error {
	_, err := db.GetEngine(ctx).Where("user_id = ? AND repo_id = ?", userID, repoID).Delete(new(NotificationSetting))
	return err
}
