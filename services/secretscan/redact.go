// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	activities_model "forgejo.org/models/activities"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	issue_indexer "forgejo.org/modules/indexer/issues"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// RedactTarget names one text of an issue or pull request: its title or body (Issue is its number, Field "title" or
// "body"), or a comment (Comment is its ID, Field empty or "comment").
type RedactTarget struct {
	Issue, Comment int64
	Field          string
}

var (
	// ErrRedactTarget is a target that names no text.
	ErrRedactTarget = util.NewInvalidArgumentErrorf("name the title or body of an issue, or a comment")
	// ErrRedactGone is a text whose place of the alert was already redacted, and that holds the secret nowhere any
	// more (text, edit history, title changes, feed): nothing is left to remove.
	ErrRedactGone = util.NewInvalidArgumentErrorf("the secret is no longer in this text or its history")
	// ErrRedactManual is a text the detector can't read whole (not plain text, cut at the size limit, out of budget):
	// it could miss a copy of the secret, so nothing is changed and the text must be edited by hand.
	ErrRedactManual = util.NewInvalidArgumentErrorf("this text can't be redacted automatically: edit it")
	// ErrRedactPattern is an alert whose rule is not used any more (a custom pattern deleted or turned off, generic
	// rules turned off): the secret can't be found again, the text must be edited by hand.
	ErrRedactPattern = util.NewInvalidArgumentErrorf("the pattern of this alert is no longer used: edit the text")
	// ErrRedactChanged is a text that changed between its read and the write: nothing is changed, try again.
	ErrRedactChanged = errors.New("the text changed meanwhile")
)

// RedactResult is what a redaction did: the copies it replaced in the text, and whether it removed the secret
// anywhere else (edit history, review body, title changes, feed).
type RedactResult struct {
	Replaced int
	Cleaned  bool
}

// RedactedMark is what takes the place of the secret.
const RedactedMark = "[secret removed]"

// redact replaces every span of text where d finds the secret of the rule with that fingerprint. It returns the text,
// the spans it replaced and whether the detector read the text whole.
func redact(d *secretdetection.Detector, text, ruleID, fingerprint string) (string, int, bool) {
	if strings.IndexByte(text, 0) >= 0 || strings.HasPrefix(text, "\xff\xfe") || strings.HasPrefix(text, "\xfe\xff") {
		return text, 0, false // read as UTF-16, its offsets would not be those of text
	}
	findings, complete := scanContent(d, []byte(text))
	n := 0
	for _, f := range slices.Backward(findings) { // ordered by position and never overlapping: from the end, the offsets before stay right
		if f.RuleID == ruleID && f.Fingerprint == fingerprint {
			text = text[:f.Start] + RedactedMark + text[f.End:]
			n++
		}
	}
	return text, n, complete
}

// RedactText removes the secret of an alert from one text of an issue or pull request, for someone who may close the
// alert (the caller checks that) and reads the text (access). The secret is
// found again by the detector in the text as it is now (nothing of it is stored) and every span of it is replaced
// with RedactedMark; a text the detector can't read whole is refused (ErrRedactManual), as a redaction that misses a
// copy would claim too much. In one transaction the text is written back on condition that it did not change since it
// was read (else ErrRedactChanged), the versions of its edit history are emptied (and the secret is removed from a
// review's own copy of its body, from the title changes of the timeline and from the activity feed), the alert's
// places in it are marked removed and an audit entry is recorded. When the secret is already gone from the text, only
// the history versions that hold it are emptied (clean ones stay) and the rest is done, as long as the place is open or
// a copy is left somewhere; else ErrRedactGone.
// It runs no notifier and recreates no cross reference: nobody is mailed and no webhook fires; the edit shows in the
// history as the doer's. A text reported as abusive keeps its moderation copy (made before the write, as any edit
// does). A locked issue can be redacted. An unknown alert or text, a text the alert has no place in and one the doer
// can't read are util.ErrNotExist.
func RedactText(ctx context.Context, repo *repo_model.Repository, doer *user_model.User, index int64, target RedactTarget, access secretscan_model.TextAccess, canReadWiki bool) (RedactResult, error) {
	if repo.IsArchived {
		return RedactResult{}, ErrArchived
	}
	alert, err := secretscan_model.GetVisibleAlert(ctx, repo.ID, index, canReadWiki)
	if err != nil {
		return RedactResult{}, err
	}
	var issue *issues_model.Issue
	var comment *issues_model.Comment
	var src secretscan_model.TextSource
	switch {
	case target.Comment > 0 && (target.Field == "" || target.Field == "comment"):
		if comment, err = issues_model.GetCommentByID(ctx, target.Comment); err != nil {
			return RedactResult{}, err
		}
		if issue, err = issues_model.GetIssueByID(ctx, comment.IssueID); err != nil {
			return RedactResult{}, err
		}
		src = secretscan_model.TextSource{Kind: secretscan_model.KindComment, ID: comment.ID}
	case target.Comment == 0 && target.Issue > 0 && (target.Field == "title" || target.Field == "body"):
		if issue, err = issues_model.GetIssueByIndex(ctx, repo.ID, target.Issue); err != nil {
			return RedactResult{}, err
		}
		src = secretscan_model.TextSource{Kind: secretscan_model.KindIssue, ID: issue.ID, Field: target.Field}
	default:
		return RedactResult{}, ErrRedactTarget
	}
	// a text the doer can't read is missing, as one the alert is not in: the answer tells nothing about it
	if issue.RepoID != repo.ID || !(issue.IsPull && access.Pulls || !issue.IsPull && access.Issues) {
		return RedactResult{}, util.ErrNotExist
	}
	has, open, err := secretscan_model.TextPlaceState(ctx, repo.ID, alert.ID, src)
	if err != nil {
		return RedactResult{}, err
	} else if !has {
		return RedactResult{}, util.ErrNotExist
	}
	d, err := textDetector(ctx, repo, setting.SecretScanningSettings(ctx))
	if err != nil {
		return RedactResult{}, err
	}
	if !d.HasRule(alert.RuleID) {
		return RedactResult{}, ErrRedactPattern
	}
	text := issue.Content
	switch {
	case comment != nil:
		text = comment.Content
	case src.Field == "title":
		text = issue.Title
	}
	redacted, n, complete := redact(d, text, alert.RuleID, alert.Fingerprint)
	if !complete {
		return RedactResult{}, ErrRedactManual
	}
	redactAll := func(s string) (string, bool) {
		out, n, _ := redact(d, s, alert.RuleID, alert.Fingerprint)
		return out, n > 0
	}
	// an old version holds the secret also when it can't be read whole: erasing it is the safe side
	holds := func(s string) bool {
		_, n, complete := redact(d, s, alert.RuleID, alert.Fingerprint)
		return n > 0 || !complete
	}
	cleaned := false
	err = db.WithTx(ctx, func(ctx context.Context) error {
		var left int64 // copies found outside the text: history versions, review body, title changes, feed rows
		var k int64
		var err error
		switch {
		case comment != nil:
			if left, err = eraseHistory(ctx, issue.ID, comment.ID, comment.PosterID, comment.CreatedUnix, n > 0, holds); err != nil {
				return err
			}
			if n > 0 {
				if err := issues_model.IfNeededCreateShadowCopyForComment(ctx, comment, false); err != nil {
					return err
				}
				// content and version only: no cross reference is made again, as the doer's
				if affected, err := db.GetEngine(ctx).ID(comment.ID).Where("content_version = ?", comment.ContentVersion).Cols("content", "content_version").
					Update(&issues_model.Comment{Content: redacted, ContentVersion: comment.ContentVersion + 1}); err != nil {
					return err
				} else if affected == 0 {
					return ErrRedactChanged
				}
				if err := issues_model.SaveIssueContentHistory(ctx, doer.ID, issue.ID, comment.ID, timeutil.TimeStampNow(), redacted, false); err != nil {
					return err
				}
			}
			// a review's body is stored twice: in its comment and in the review itself (the reviews API reads that)
			if comment.Type == issues_model.CommentTypeReview && comment.ReviewID > 0 {
				if k, err = redactReview(ctx, comment.ReviewID, redactAll); err != nil {
					return err
				}
				left += k
			}
			if k, err = redactFeed(ctx, builder.Eq{"repo_id": repo.ID, "comment_id": comment.ID}, redactAll); err != nil {
				return err
			}
			left += k
		case src.Field == "title":
			if n > 0 {
				old := issue.Title
				issue.Title, _ = util.SplitStringAtByteN(redacted, 255) // as ChangeIssueTitle: the mark may be longer than a short secret
				if affected, err := issues_model.UpdateIssueColsWithCond(ctx, issue, builder.Eq{"name": old}, "name"); err != nil {
					return err
				} else if affected == 0 {
					return ErrRedactChanged
				}
			}
			if left, err = redactTitleChanges(ctx, issue.ID, redactAll); err != nil {
				return err
			}
			// the feed keeps the title of a new issue or pull request (and of a merge): ["<index>", "<title>", ...]
			prefix := `["` + strconv.FormatInt(issue.Index, 10) + `",`
			if k, err = redactFeed(ctx, builder.Eq{"repo_id": repo.ID, "comment_id": 0}.And(builder.Like{"content", prefix + "%"}), redactAll); err != nil {
				return err
			}
			left += k
		default:
			if left, err = eraseHistory(ctx, issue.ID, 0, issue.PosterID, issue.CreatedUnix, n > 0, holds); err != nil {
				return err
			}
			if n > 0 {
				if err := issues_model.IfNeededCreateShadowCopyForIssue(ctx, issue); err != nil {
					return err
				}
				version := issue.ContentVersion
				issue.Content, issue.ContentVersion = redacted, version+1
				// content and version only: no cross reference is made again, as the doer's
				if affected, err := issues_model.UpdateIssueColsWithCond(ctx, issue, builder.Eq{"content_version": version}, "content", "content_version"); err != nil {
					return err
				} else if affected == 0 {
					return ErrRedactChanged
				}
				if err := issues_model.SaveIssueContentHistory(ctx, doer.ID, issue.ID, 0, timeutil.TimeStampNow(), redacted, false); err != nil {
					return err
				}
			}
		}
		cleaned = left > 0
		if n == 0 && !open && left == 0 {
			return ErrRedactGone
		}
		if err := secretscan_model.MarkTextPlacesRemoved(ctx, repo.ID, alert.ID, src); err != nil {
			return err
		}
		data := map[string]any{
			"index": alert.Index, "rule": alert.RuleID, "fingerprint": alert.Fingerprint[:min(12, len(alert.Fingerprint))],
			"issue": issue.Index, "field": util.Iif(comment != nil, "comment", src.Field), "replaced": n,
		}
		if comment != nil {
			data["comment_id"] = comment.ID
		}
		if n == 0 {
			data["history_only"] = true
			data["cleaned"] = left > 0
		}
		return repo_model.RecordRepoTarget(ctx, repo, audit_model.Event{
			Action: "repo.secret_alert.text_redacted", TargetType: "secret_scanning_alert", TargetID: alert.ID, TargetName: alert.RuleID, Data: data,
		})
	})
	if err != nil {
		return RedactResult{}, err
	}
	// after the commit: the search index drops the old text, and the text is scanned again (its other places may have
	// moved when a secret of several lines became one); a scan by nobody (0) mails nobody
	issue_indexer.UpdateIssueIndexer(ctx, issue.ID)
	if comment != nil {
		enqueueCommentText(ctx, comment, 0)
	} else {
		enqueueIssueText(ctx, issue.ID, 0)
	}
	return RedactResult{Replaced: n, Cleaned: cleaned}, nil
}

// eraseHistory empties versions in the edit history of a text (an issue's body: commentID 0): all of them when the
// text is rewritten (rewrite), else only the ones that hold the secret. It returns how many it emptied. A text that
// was never edited and is rewritten now first gets the entry of its first version, empty, so that the history shows
// the edit.
func eraseHistory(ctx context.Context, issueID, commentID, posterID int64, created timeutil.TimeStamp, rewrite bool, holds func(string) bool) (int64, error) {
	cond := builder.Eq{"issue_id": issueID, "comment_id": commentID, "is_deleted": false}
	if !rewrite {
		var versions []*issues_model.ContentHistory
		if err := db.GetEngine(ctx).Where(cond).Cols("id", "content_text").Find(&versions); err != nil {
			return 0, err
		}
		var ids []int64
		for _, v := range versions {
			if holds(v.ContentText) {
				ids = append(ids, v.ID)
			}
		}
		if len(ids) == 0 {
			return 0, nil
		}
		return db.GetEngine(ctx).In("id", ids).Cols("is_deleted", "content_text").Update(&issues_model.ContentHistory{IsDeleted: true})
	}
	// soft-deleted versions count here too, so a text redacted before gets no second first version
	has, err := issues_model.HasIssueContentHistory(ctx, issueID, commentID)
	if err != nil {
		return 0, err
	}
	if !has {
		if err := issues_model.SaveIssueContentHistory(ctx, posterID, issueID, commentID, created, "", true); err != nil {
			return 0, err
		}
	}
	return db.GetEngine(ctx).Where(cond).Cols("is_deleted", "content_text").Update(&issues_model.ContentHistory{IsDeleted: true})
}

// redactReview removes the secret from a review's own copy of its body.
func redactReview(ctx context.Context, reviewID int64, redactAll func(string) (string, bool)) (int64, error) {
	review, err := issues_model.GetReviewByID(ctx, reviewID)
	if err != nil {
		if issues_model.IsErrReviewNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	content, ok := redactAll(review.Content)
	if !ok {
		return 0, nil
	}
	return db.GetEngine(ctx).ID(review.ID).Cols("content").NoAutoTime().Update(&issues_model.Review{Content: content})
}

// redactTitleChanges removes the secret from the title changes of the issue's timeline.
func redactTitleChanges(ctx context.Context, issueID int64, redactAll func(string) (string, bool)) (int64, error) {
	var changes []*issues_model.Comment
	if err := db.GetEngine(ctx).Where("issue_id = ? AND type = ?", issueID, issues_model.CommentTypeChangeTitle).Cols("id", "old_title", "new_title").Find(&changes); err != nil {
		return 0, err
	}
	var count int64
	for _, c := range changes {
		oldTitle, a := redactAll(c.OldTitle)
		newTitle, b := redactAll(c.NewTitle)
		if a || b {
			if _, err := db.GetEngine(ctx).ID(c.ID).Cols("old_title", "new_title").NoAutoTime().Update(&issues_model.Comment{OldTitle: oldTitle, NewTitle: newTitle}); err != nil {
				return 0, err
			}
			count++
		}
	}
	return count, nil
}

// redactFeed removes the secret from the activity feed's copies of a text. The feed has one row per watcher, mostly
// with the same content: each distinct content is redacted once and written with one UPDATE by ID list.
func redactFeed(ctx context.Context, cond builder.Cond, redactAll func(string) (string, bool)) (int64, error) {
	var actions []*activities_model.Action
	if err := db.GetEngine(ctx).Where(cond).Cols("id", "content").Find(&actions); err != nil {
		return 0, err
	}
	byContent := map[string][]int64{}
	for _, a := range actions {
		byContent[a.Content] = append(byContent[a.Content], a.ID)
	}
	var count int64
	for old, ids := range byContent {
		content, ok := redactAll(old)
		if !ok {
			continue
		}
		for chunk := range slices.Chunk(ids, 500) { // under every database's limit of bound values
			affected, err := db.GetEngine(ctx).In("id", chunk).Cols("content").Update(&activities_model.Action{Content: content})
			if err != nil {
				return 0, err
			}
			count += affected
		}
	}
	return count, nil
}
