// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues

import (
	"context"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

// PullTask is a to-do item on a pull request, standalone or created from a comment.
type PullTask struct {
	ID          int64              `xorm:"pk autoincr"`
	IssueID     int64              `xorm:"INDEX NOT NULL"`
	CommentID   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	Content     string             `xorm:"VARCHAR(255) NOT NULL"`
	CreatorID   int64              `xorm:"NOT NULL"`
	Creator     *user_model.User   `xorm:"-"`
	AssigneeID  int64              `xorm:"NOT NULL DEFAULT 0"`
	Assignee    *user_model.User   `xorm:"-"`
	IsDone      bool               `xorm:"INDEX NOT NULL DEFAULT false"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(PullTask))
}

// ErrPullTaskNotExist is returned for a task that doesn't exist on the pull request, and for a
// comment a task can't be created from.
var ErrPullTaskNotExist = util.NewNotExistErrorf("pull task does not exist")

// FindPullTasks returns the tasks of a pull request in creation order, with their creators and assignees.
func FindPullTasks(ctx context.Context, issueID int64) ([]*PullTask, error) {
	var tasks []*PullTask
	if err := db.GetEngine(ctx).Where("issue_id = ?", issueID).Asc("id").Find(&tasks); err != nil {
		return nil, err
	}
	for _, task := range tasks {
		if err := task.loadUsers(ctx); err != nil {
			return nil, err
		}
	}
	return tasks, nil
}

// GetPullTaskByID returns the task id of the pull request issueID.
func GetPullTaskByID(ctx context.Context, issueID, id int64) (*PullTask, error) {
	task := new(PullTask)
	has, err := db.GetEngine(ctx).Where("id = ? AND issue_id = ?", id, issueID).Get(task)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrPullTaskNotExist
	}
	return task, task.loadUsers(ctx)
}

func (task *PullTask) loadUsers(ctx context.Context) (err error) {
	if task.Creator, err = user_model.GetPossibleUserByID(ctx, task.CreatorID); err != nil {
		return err
	}
	task.Assignee, err = user_model.GetPossibleUserByID(ctx, task.AssigneeID)
	return err
}

// CanCreatePullTask returns whether doer may add tasks to the pull request: like commenting, it is
// refused on a locked pull request without write access, and to users blocked by the repository owner.
func CanCreatePullTask(ctx context.Context, doer *user_model.User, issue *Issue, perm access_model.Permission) bool {
	if err := issue.LoadRepo(ctx); err != nil {
		log.Error("LoadRepo: %v", err)
		return false
	}
	if issue.IsLocked && !perm.CanWriteIssuesOrPulls(true) && !doer.IsAdmin {
		return false
	}
	return !user_model.IsBlocked(ctx, issue.Repo.OwnerID, doer.ID)
}

// CanChangePullTaskStatus returns whether doer may mark the task done or reopen it. The creator may
// only while they can still add tasks, so a blocked creator can't keep reopening their task.
func CanChangePullTaskStatus(ctx context.Context, doer *user_model.User, issue *Issue, task *PullTask, perm access_model.Permission) bool {
	return doer.ID == issue.PosterID || perm.CanWrite(unit.TypePullRequests) ||
		(doer.ID == task.CreatorID && CanCreatePullTask(ctx, doer, issue, perm))
}

// CanDeletePullTask returns whether doer may delete the task.
func CanDeletePullTask(doer *user_model.User, task *PullTask, perm access_model.Permission) bool {
	return doer.ID == task.CreatorID || perm.IsAdmin()
}

func createPullTaskComment(ctx context.Context, typ CommentType, doer *user_model.User, issue *Issue, task *PullTask) error {
	_, err := CreateComment(ctx, &CreateCommentOptions{
		Type:    typ,
		Doer:    doer,
		Repo:    issue.Repo,
		Issue:   issue,
		Content: task.Content,
	})
	return err
}

// CreatePullTask adds a task assigned to the poster of the pull request. A task created from a comment
// must name a plain or code comment of the pull request that is not part of a pending review.
func CreatePullTask(ctx context.Context, doer *user_model.User, issue *Issue, content string, commentID int64) (*PullTask, error) {
	if commentID != 0 {
		comment, err := GetCommentByID(ctx, commentID)
		if IsErrCommentNotExist(err) {
			return nil, ErrPullTaskNotExist
		} else if err != nil {
			return nil, err
		}
		if comment.IssueID != issue.ID || (comment.Type != CommentTypeComment && comment.Type != CommentTypeCode) {
			return nil, ErrPullTaskNotExist
		}
		if comment.ReviewID != 0 {
			pending, err := db.GetEngine(ctx).Where("id = ? AND type = ?", comment.ReviewID, ReviewTypePending).Exist(new(Review))
			if err != nil {
				return nil, err
			} else if pending {
				return nil, ErrPullTaskNotExist
			}
		}
	}

	task := &PullTask{
		IssueID:    issue.ID,
		CommentID:  commentID,
		Content:    content,
		CreatorID:  doer.ID,
		AssigneeID: issue.PosterID,
	}
	return task, db.WithTx(ctx, func(ctx context.Context) error {
		if err := db.Insert(ctx, task); err != nil {
			return err
		}
		if err := createPullTaskComment(ctx, CommentTypePullTaskCreated, doer, issue, task); err != nil {
			return err
		}
		return task.loadUsers(ctx)
	})
}

// SetPullTaskDone marks the task done or reopens it.
func SetPullTaskDone(ctx context.Context, doer *user_model.User, issue *Issue, task *PullTask, done bool) error {
	if task.IsDone == done {
		return nil
	}
	task.IsDone = done
	typ := CommentTypePullTaskReopened
	if done {
		typ = CommentTypePullTaskDone
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).ID(task.ID).Cols("is_done").Update(task); err != nil {
			return err
		}
		return createPullTaskComment(ctx, typ, doer, issue, task)
	})
}

// DeletePullTask deletes the task.
func DeletePullTask(ctx context.Context, doer *user_model.User, issue *Issue, task *PullTask) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.DeleteByID[PullTask](ctx, task.ID); err != nil {
			return err
		}
		return createPullTaskComment(ctx, CommentTypePullTaskDeleted, doer, issue, task)
	})
}

// MergeBlockedByIncompleteTasks returns true if merge is blocked by open tasks
func MergeBlockedByIncompleteTasks(ctx context.Context, protectBranch *git_model.ProtectedBranch, pr *PullRequest) bool {
	if !protectBranch.BlockOnIncompleteTasks {
		return false
	}
	open, err := db.GetEngine(ctx).Where("issue_id = ? AND is_done = ?", pr.IssueID, false).Exist(new(PullTask))
	if err != nil {
		log.Error("MergeBlockedByIncompleteTasks: %v", err)
		return true
	}
	return open
}
