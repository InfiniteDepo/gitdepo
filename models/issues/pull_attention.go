// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues

import (
	"context"

	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/timeutil"
)

// AttentionKind is why a user is in the attention set of a pull request.
type AttentionKind int

const (
	AttentionReviewRequested AttentionKind = iota + 1 // the doer requested their review
	AttentionReviewed                                 // the doer reviewed the author's pull request
	AttentionReplied                                  // the author (the doer) replied to their review
	AttentionPushed                                   // the author (the doer) pushed after their review
	AttentionManual                                   // the doer added them by hand
)

// PullAttention is a user a pull request is waiting on: its attention set is its rows.
type PullAttention struct {
	ID      int64              `xorm:"pk autoincr"`
	IssueID int64              `xorm:"UNIQUE(s) NOT NULL"`
	UserID  int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
	User    *user_model.User   `xorm:"-"`
	DoerID  int64              `xorm:"NOT NULL DEFAULT 0"`
	Doer    *user_model.User   `xorm:"-"`
	Kind    AttentionKind      `xorm:"NOT NULL DEFAULT 0"`
	Reason  string             `xorm:"VARCHAR(255)"`
	Updated timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(PullAttention))
}

// KindLocaleKey returns the locale key that describes the kind; it takes the doer's name.
func (a *PullAttention) KindLocaleKey() string {
	switch a.Kind {
	case AttentionReviewRequested:
		return "repo.pulls.attention.kind.review_requested"
	case AttentionReviewed:
		return "repo.pulls.attention.kind.reviewed"
	case AttentionReplied:
		return "repo.pulls.attention.kind.replied"
	case AttentionPushed:
		return "repo.pulls.attention.kind.pushed"
	default:
		return "repo.pulls.attention.kind.manual"
	}
}

// AddPullAttention adds the users to the attention set of the pull request issueID, or updates why they are in it.
func AddPullAttention(ctx context.Context, issueID int64, userIDs []int64, doerID int64, kind AttentionKind, reason string) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		for _, userID := range userIDs {
			row := &PullAttention{IssueID: issueID, UserID: userID, DoerID: doerID, Kind: kind, Reason: reason}
			n, err := db.GetEngine(ctx).Where("issue_id = ? AND user_id = ?", issueID, userID).
				Cols("doer_id", "kind", "reason").Update(row)
			if err != nil {
				return err
			}
			if n == 0 {
				if err := db.Insert(ctx, row); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// RemovePullAttention removes the users from the attention set of the pull request issueID and returns
// how many were in it.
func RemovePullAttention(ctx context.Context, issueID int64, userIDs ...int64) (int64, error) {
	if len(userIDs) == 0 {
		return 0, nil
	}
	return db.GetEngine(ctx).Where("issue_id = ?", issueID).In("user_id", userIDs).Delete(new(PullAttention))
}

// ClearPullAttention empties the attention set of the pull request issueID and returns how many users
// were in it.
func ClearPullAttention(ctx context.Context, issueID int64) (int64, error) {
	return db.GetEngine(ctx).Where("issue_id = ?", issueID).Delete(new(PullAttention))
}

// GetPullAttentionUserIDs returns the IDs of the users in the attention set of the pull request issueID.
func GetPullAttentionUserIDs(ctx context.Context, issueID int64) ([]int64, error) {
	var ids []int64
	return ids, db.GetEngine(ctx).Table("pull_attention").Where("issue_id = ?", issueID).Cols("user_id").Find(&ids)
}

// LoadPullAttention returns the attention sets of the open pull requests of the list, by issue ID.
func (issues IssueList) LoadPullAttention(ctx context.Context) (map[int64][]*PullAttention, error) {
	var ids []int64
	for _, issue := range issues {
		if issue.IsPull && !issue.IsClosed {
			ids = append(ids, issue.ID)
		}
	}
	return FindPullAttention(ctx, ids...)
}

// FindPullAttention returns the attention sets of the pull requests issueIDs, with their users and
// doers, by issue ID.
func FindPullAttention(ctx context.Context, issueIDs ...int64) (map[int64][]*PullAttention, error) {
	sets := make(map[int64][]*PullAttention)
	if len(issueIDs) == 0 {
		return sets, nil
	}
	var rows []*PullAttention
	if err := db.GetEngine(ctx).In("issue_id", issueIDs).Asc("id").Find(&rows); err != nil {
		return nil, err
	}
	userIDs := make(container.Set[int64], len(rows))
	for _, row := range rows {
		userIDs.AddMultiple(row.UserID, row.DoerID)
	}
	users, err := user_model.GetUsersByIDs(ctx, userIDs.Values())
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*user_model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	for _, row := range rows {
		if row.User = byID[row.UserID]; row.User == nil {
			continue // a user that has just been deleted
		}
		if row.Doer = byID[row.DoerID]; row.Doer == nil {
			row.Doer = user_model.NewGhostUser()
		}
		sets[row.IssueID] = append(sets[row.IssueID], row)
	}
	return sets, nil
}
