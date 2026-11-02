// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"slices"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	issue_indexer "forgejo.org/modules/indexer/issues"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/util"
	notify_service "forgejo.org/services/notify"
)

var (
	// ErrAttentionNotAllowed is returned when the doer may not make that change to the attention set.
	ErrAttentionNotAllowed = util.NewPermissionDeniedErrorf("not allowed to change the attention set")
	// ErrAttentionInvalidTarget is returned for a user that can't be in the attention set.
	ErrAttentionInvalidTarget = util.NewInvalidArgumentErrorf("user can't be in the attention set")
)

// reindexAttention updates the issue indexer once the attention set is committed.
func reindexAttention(ctx context.Context, issueID int64) {
	db.AfterTx(ctx, func() { issue_indexer.UpdateIssueIndexer(ctx, issueID) })
}

// addAttention adds the existing individual users of userIDs to the attention set and reindexes the pull request.
func addAttention(ctx context.Context, issueID int64, userIDs []int64, doerID int64, kind issues_model.AttentionKind, reason string) error {
	users, err := user_model.GetUsersByIDs(ctx, slices.DeleteFunc(userIDs, func(id int64) bool { return id <= 0 }))
	if err != nil {
		return err
	}
	valid := make([]int64, 0, len(users))
	for _, u := range users {
		if u.IsIndividual() {
			valid = append(valid, u.ID)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	if err := issues_model.AddPullAttention(ctx, issueID, valid, doerID, kind, reason); err != nil {
		return err
	}
	reindexAttention(ctx, issueID)
	return nil
}

func removeAttention(ctx context.Context, issueID int64, userIDs ...int64) error {
	if n, err := issues_model.RemovePullAttention(ctx, issueID, userIDs...); err != nil || n == 0 {
		return err
	}
	reindexAttention(ctx, issueID)
	return nil
}

// authorID returns the poster of the pull request, or 0 for a migrated pull request or a deleted poster.
func authorID(issue *issues_model.Issue) int64 {
	if issue.OriginalAuthorID != 0 || issue.PosterID <= 0 {
		return 0
	}
	return issue.PosterID
}

// reviewerIDs returns the users with a submitted review on the pull request, and the requested reviewers
// if withRequested.
func reviewerIDs(ctx context.Context, issueID int64, withRequested bool) ([]int64, error) {
	types := []issues_model.ReviewType{issues_model.ReviewTypeApprove, issues_model.ReviewTypeReject, issues_model.ReviewTypeComment}
	if withRequested {
		types = append(types, issues_model.ReviewTypeRequest)
	}
	reviews, err := issues_model.FindLatestReviews(ctx, issues_model.FindReviewOptions{IssueID: issueID, Types: types})
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(reviews))
	for _, r := range reviews {
		if r.ReviewerID > 0 && r.OriginalAuthorID == 0 {
			ids = append(ids, r.ReviewerID)
		}
	}
	return ids, nil
}

// authorActed moves the attention from the author to every reviewer whose latest review is a comment or
// a change request: approvers aren't added back.
func authorActed(ctx context.Context, issue *issues_model.Issue, kind issues_model.AttentionKind) error {
	reviews, err := issues_model.FindLatestReviews(ctx, issues_model.FindReviewOptions{
		IssueID:   issue.ID,
		Types:     []issues_model.ReviewType{issues_model.ReviewTypeApprove, issues_model.ReviewTypeReject, issues_model.ReviewTypeComment},
		Dismissed: optional.Some(false),
	})
	if err != nil {
		return err
	}
	var ids []int64
	for _, r := range reviews {
		if r.Type != issues_model.ReviewTypeApprove && r.ReviewerID != issue.PosterID && r.OriginalAuthorID == 0 {
			ids = append(ids, r.ReviewerID)
		}
	}
	if err := removeAttention(ctx, issue.ID, issue.PosterID); err != nil {
		return err
	}
	return addAttention(ctx, issue.ID, ids, issue.PosterID, kind, "")
}

// otherActed moves the attention from doer, a reviewer, to the author.
func otherActed(ctx context.Context, issue *issues_model.Issue, doerID int64, kind issues_model.AttentionKind) error {
	if err := removeAttention(ctx, issue.ID, doerID); err != nil {
		return err
	}
	return addAttention(ctx, issue.ID, []int64{authorID(issue)}, doerID, kind, "")
}

// CanChangeAttention returns whether doer may change the attention set of the pull request at all: the
// author, pulls writers, users in the set and reviewers may, as long as they may comment.
func CanChangeAttention(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission) bool {
	ok, err := canChangeAttention(ctx, doer, issue, perm)
	if err != nil {
		log.Error("canChangeAttention: %v", err)
	}
	return ok
}

func canChangeAttention(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission) (bool, error) {
	if doer == nil || !issue.IsPull || issue.IsClosed || !perm.CanRead(unit.TypePullRequests) {
		return false, nil
	}
	if issue.IsLocked && !perm.CanWriteIssuesOrPulls(true) {
		return false, nil
	}
	if err := issue.LoadRepo(ctx); err != nil {
		return false, err
	}
	if issue.Repo.IsArchived || user_model.IsBlockedMultiple(ctx, []int64{issue.PosterID, issue.Repo.OwnerID}, doer.ID) {
		return false, nil
	}
	if mayAddAnyone(doer, issue, perm) {
		return true, nil
	}
	inSet, err := issues_model.GetPullAttentionUserIDs(ctx, issue.ID)
	if err != nil {
		return false, err
	}
	if slices.Contains(inSet, doer.ID) {
		return true, nil
	}
	reviewers, err := reviewerIDs(ctx, issue.ID, false)
	return slices.Contains(reviewers, doer.ID), err
}

// CanRemoveAttention returns whether doer may remove other users from the attention set: the author and
// pulls writers may.
func CanRemoveAttention(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission) bool {
	return CanChangeAttention(ctx, doer, issue, perm) && mayAddAnyone(doer, issue, perm)
}

func mayAddAnyone(doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission) bool {
	return doer.ID == authorID(issue) || perm.CanWrite(unit.TypePullRequests)
}

// AddAttention adds target to the attention set of the pull request by hand. The author and pulls writers
// may add any user who can read the pull request; other users who may change the set only the author
// or a reviewer.
func AddAttention(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission, target *user_model.User, reason string) error {
	if ok, err := canChangeAttention(ctx, doer, issue, perm); err != nil {
		return err
	} else if !ok {
		return ErrAttentionNotAllowed
	}
	// involvement first, so that a refusal can't tell whether the user can read the repository or blocked the doer
	if !mayAddAnyone(doer, issue, perm) && target.ID != authorID(issue) {
		involved, err := reviewerIDs(ctx, issue.ID, true)
		if err != nil {
			return err
		}
		if !slices.Contains(involved, target.ID) {
			return ErrAttentionNotAllowed
		}
	}
	if target.ID <= 0 || !target.IsIndividual() || !target.IsActive || target.ProhibitLogin || user_model.IsBlocked(ctx, target.ID, doer.ID) {
		return ErrAttentionInvalidTarget
	}
	targetPerm, err := access_model.GetUserRepoPermission(ctx, issue.Repo, target)
	if err != nil {
		return err
	}
	if !targetPerm.CanRead(unit.TypePullRequests) {
		return ErrAttentionInvalidTarget
	}
	return addAttention(ctx, issue.ID, []int64{target.ID}, doer.ID, issues_model.AttentionManual, reason)
}

// AttentionCandidates returns the users doer may pick to add to the attention set, without the users
// already in it: the author, requested reviewers and reviewers, and for the author and pulls writers also
// the extra users (the reviewer candidates). AddAttention still checks the user that is picked.
func AttentionCandidates(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission, extra []*user_model.User) ([]*user_model.User, error) {
	if ok, err := canChangeAttention(ctx, doer, issue, perm); err != nil || !ok {
		return nil, err
	}
	ids, err := reviewerIDs(ctx, issue.ID, true)
	if err != nil {
		return nil, err
	}
	ids = append(ids, authorID(issue))
	if mayAddAnyone(doer, issue, perm) {
		for _, u := range extra {
			ids = append(ids, u.ID)
		}
	}
	inSet, err := issues_model.GetPullAttentionUserIDs(ctx, issue.ID)
	if err != nil {
		return nil, err
	}
	blockedBy, err := user_model.ListBlockedByUsersID(ctx, doer.ID)
	if err != nil {
		return nil, err
	}
	ids = slices.DeleteFunc(ids, func(id int64) bool {
		return id <= 0 || slices.Contains(inSet, id) || slices.Contains(blockedBy, id)
	})
	slices.Sort(ids)
	users, err := user_model.GetUsersByIDs(ctx, slices.Compact(ids))
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(users, func(u *user_model.User) bool {
		return !u.IsIndividual() || !u.IsActive || u.ProhibitLogin
	}), nil
}

// RemoveAttention removes target from the attention set of the pull request by hand. Anyone may remove
// themselves; only the author and pulls writers may remove others.
func RemoveAttention(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, perm access_model.Permission, target *user_model.User) error {
	if doer.ID != target.ID {
		if ok, err := canChangeAttention(ctx, doer, issue, perm); err != nil {
			return err
		} else if !ok || !mayAddAnyone(doer, issue, perm) {
			return ErrAttentionNotAllowed
		}
	}
	return removeAttention(ctx, issue.ID, target.ID)
}

type attentionNotifier struct {
	notify_service.NullNotifier
}

func init() {
	notify_service.RegisterNotifier(&attentionNotifier{})
}

func logAttention(err error) {
	if err != nil {
		log.Error("pull attention: %v", err)
	}
}

func (*attentionNotifier) PullRequestReviewRequest(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, reviewer *user_model.User, isRequest bool, comment *issues_model.Comment) {
	// a team request reaches here once per member, with the team in the comment
	if !issue.IsPull || issue.IsClosed || comment == nil || comment.AssigneeTeamID != 0 || reviewer.ID == issue.PosterID {
		return
	}
	if isRequest {
		logAttention(addAttention(ctx, issue.ID, []int64{reviewer.ID}, doer.ID, issues_model.AttentionReviewRequested, ""))
	} else {
		logAttention(removeAttention(ctx, issue.ID, reviewer.ID))
	}
}

func (*attentionNotifier) PullRequestReview(ctx context.Context, pr *issues_model.PullRequest, review *issues_model.Review, comment *issues_model.Comment, mentions []*user_model.User) {
	if review.Type != issues_model.ReviewTypeApprove && review.Type != issues_model.ReviewTypeReject && review.Type != issues_model.ReviewTypeComment {
		return
	}
	if err := pr.LoadIssue(ctx); err != nil || pr.Issue.IsClosed {
		logAttention(err)
		return
	}
	if review.ReviewerID == pr.Issue.PosterID {
		logAttention(authorActed(ctx, pr.Issue, issues_model.AttentionReplied))
	} else {
		logAttention(otherActed(ctx, pr.Issue, review.ReviewerID, issues_model.AttentionReviewed))
	}
}

func (*attentionNotifier) CreateIssueComment(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, issue *issues_model.Issue, comment *issues_model.Comment, mentions []*user_model.User) {
	if !issue.IsPull || issue.IsClosed || (comment.Type != issues_model.CommentTypeComment && comment.Type != issues_model.CommentTypeCode) {
		return
	}
	if doer.ID == issue.PosterID {
		logAttention(authorActed(ctx, issue, issues_model.AttentionReplied))
		return
	}
	inSet, err := issues_model.GetPullAttentionUserIDs(ctx, issue.ID)
	if err != nil || !slices.Contains(inSet, doer.ID) {
		logAttention(err)
		return
	}
	logAttention(otherActed(ctx, issue, doer.ID, issues_model.AttentionReplied))
}

func (*attentionNotifier) PullRequestPushCommits(ctx context.Context, doer *user_model.User, pr *issues_model.PullRequest, comment *issues_model.Comment) {
	if err := pr.LoadIssue(ctx); err != nil || pr.Issue.IsClosed || doer.ID != pr.Issue.PosterID {
		logAttention(err)
		return
	}
	logAttention(authorActed(ctx, pr.Issue, issues_model.AttentionPushed))
}

func clearAttention(ctx context.Context, issueID int64) {
	if n, err := issues_model.ClearPullAttention(ctx, issueID); err != nil || n == 0 {
		logAttention(err)
		return
	}
	reindexAttention(ctx, issueID)
}

func (*attentionNotifier) IssueChangeStatus(ctx context.Context, doer *user_model.User, prInfo *issues_model.PRNotificationInfo, issue *issues_model.Issue, actionComment *issues_model.Comment, closeOrReopen bool) {
	if issue.IsPull && closeOrReopen {
		clearAttention(ctx, issue.ID)
	}
}

func (*attentionNotifier) MergePullRequest(ctx context.Context, doer *user_model.User, pr *issues_model.PullRequest) {
	clearAttention(ctx, pr.IssueID)
}

func (*attentionNotifier) AutoMergePullRequest(ctx context.Context, doer *user_model.User, pr *issues_model.PullRequest) {
	clearAttention(ctx, pr.IssueID)
}
