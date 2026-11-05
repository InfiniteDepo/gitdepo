// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/log"
	issue_service "forgejo.org/services/issue"
)

// RequestDefaultReviewers asks the reviewers of the approval rules for a review of the pull request and notifies them,
// see issue_service.DefaultReviewerRequests. oldHead is the head commit before a push, empty when the pull request is
// new or was retargeted. Call it outside a transaction. An error never fails the caller: requests are advisory.
func RequestDefaultReviewers(ctx context.Context, pr *issues_model.PullRequest, oldHead string) {
	if err := pr.LoadIssue(ctx); err != nil {
		log.Error("%-v LoadIssue: %v", pr, err)
		return
	}
	notifiers, err := issue_service.DefaultReviewerRequests(ctx, pr.Issue, pr, oldHead)
	if err != nil {
		log.Error("%-v DefaultReviewerRequests: %v", pr, err)
	}
	issue_service.ReviewRequestNotify(ctx, pr.Issue, pr.Issue.Poster, notifiers)
}
