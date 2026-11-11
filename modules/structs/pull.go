// Copyright 2016 The Gogs Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import (
	"time"
)

// PullRequest represents a pull request
type PullRequest struct {
	ID                      int64      `json:"id"`
	URL                     string     `json:"url"`
	Index                   int64      `json:"number"`
	Poster                  *User      `json:"user"`
	Title                   string     `json:"title"`
	Body                    string     `json:"body"`
	Labels                  []*Label   `json:"labels"`
	Milestone               *Milestone `json:"milestone"`
	Assignee                *User      `json:"assignee"`
	Assignees               []*User    `json:"assignees"`
	RequestedReviewers      []*User    `json:"requested_reviewers"`
	RequestedReviewersTeams []*Team    `json:"requested_reviewers_teams"`
	State                   StateType  `json:"state"`
	Draft                   bool       `json:"draft"`
	IsLocked                bool       `json:"is_locked"`
	Comments                int        `json:"comments"`
	// number of review comments made on the diff of a PR review (not including comments on commits or issues in a PR)
	ReviewComments int `json:"review_comments"`
	Additions      int `json:"additions"`
	Deletions      int `json:"deletions"`
	ChangedFiles   int `json:"changed_files"`

	HTMLURL  string `json:"html_url"`
	DiffURL  string `json:"diff_url"`
	PatchURL string `json:"patch_url"`

	Mergeable bool `json:"mergeable"`
	// Branch protection checks that block merging, e.g. "unresolved_conversations".
	// Only reported when getting a single pull request.
	MergeableReasons []string `json:"mergeable_reasons,omitempty"`
	HasMerged        bool     `json:"merged"`
	// swagger:strfmt date-time
	Merged              *time.Time `json:"merged_at"`
	MergedCommitID      *string    `json:"merge_commit_sha"`
	MergedBy            *User      `json:"merged_by"`
	AllowMaintainerEdit bool       `json:"allow_maintainer_edit"`

	Base      *PRBranchInfo `json:"base"`
	Head      *PRBranchInfo `json:"head"`
	MergeBase string        `json:"merge_base"`

	// swagger:strfmt date-time
	Deadline *time.Time `json:"due_date"`

	// swagger:strfmt date-time
	Created *time.Time `json:"created_at"`
	// swagger:strfmt date-time
	Updated *time.Time `json:"updated_at"`
	// swagger:strfmt date-time
	Closed *time.Time `json:"closed_at"`
	// time after which the pending scheduled auto merge may run; absent when none is scheduled
	// swagger:strfmt date-time
	ScheduledAfter *time.Time `json:"scheduled_after,omitempty"`
	// time after which the pending scheduled auto merge is cancelled if it has not merged; may remain after scheduled_after is gone
	// swagger:strfmt date-time
	GiveUpAfter *time.Time `json:"give_up_after,omitempty"`

	PinOrder int   `json:"pin_order"`
	Flow     int64 `json:"flow"`
}

// PRBranchInfo information about a branch
type PRBranchInfo struct {
	Name       string      `json:"label"`
	Ref        string      `json:"ref"`
	Sha        string      `json:"sha"`
	RepoID     int64       `json:"repo_id"`
	Repository *Repository `json:"repo"`
}

// ListPullRequestsOptions options for listing pull requests
type ListPullRequestsOptions struct {
	Page  int    `json:"page"`
	State string `json:"state"`
}

// CreatePullRequestOption options when creating a pull request
type CreatePullRequestOption struct {
	Head string `json:"head" binding:"Required"`
	// Base is the branch to merge into; an explicit base always wins. Empty: the base of the head branch's type in the branching model, else its default pull request target, else the default branch
	Base      string   `json:"base"`
	Title     string   `json:"title" binding:"Required"`
	Body      string   `json:"body"`
	Assignee  string   `json:"assignee"`
	Assignees []string `json:"assignees"`
	Milestone int64    `json:"milestone"`
	Labels    []int64  `json:"labels"`
	// swagger:strfmt date-time
	Deadline *time.Time `json:"due_date"`
}

// EditPullRequestOption options when modify pull request
type EditPullRequestOption struct {
	Title     string   `json:"title"`
	Body      *string  `json:"body"`
	Base      string   `json:"base"`
	Assignee  string   `json:"assignee"`
	Assignees []string `json:"assignees"`
	Milestone int64    `json:"milestone"`
	Labels    []int64  `json:"labels"`
	State     *string  `json:"state"`
	// swagger:strfmt date-time
	Deadline            *time.Time `json:"due_date"`
	RemoveDeadline      *bool      `json:"unset_due_date"`
	AllowMaintainerEdit *bool      `json:"allow_maintainer_edit"`
}

// ChangedFile store information about files affected by the pull request
type ChangedFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename,omitempty"`
	Status           string `json:"status"`
	Additions        int    `json:"additions"`
	Deletions        int    `json:"deletions"`
	Changes          int    `json:"changes"`
	HTMLURL          string `json:"html_url,omitempty"`
	ContentsURL      string `json:"contents_url,omitempty"`
	RawURL           string `json:"raw_url,omitempty"`
}

// PullApprovalRule is the status of an approval rule of a pull request
type PullApprovalRule struct {
	// Name of the rule; "Default" is the required approvals of the branch protection
	Name string `json:"name"`
	// Required is the number of approvals needed
	Required int64 `json:"required"`
	// Granted is the number of valid approvals from eligible users
	Granted int64 `json:"granted"`
	// Satisfied is true if the rule allows merging
	Satisfied bool `json:"satisfied"`
	// Approvers are the logins of the users whose approvals count; empty for "Default"
	Approvers []string `json:"approvers"`
}

// PullRequestStack is the stack of a pull request: the open pull requests of the repository based on each other's
// head branch, from the bottom one, whose base branch is the stack's, depth-first
type PullRequestStack struct {
	// BaseBranch is the base branch of the bottom pull request
	BaseBranch string `json:"base_branch"`
	// Truncated is true when the stack has more pull requests than are listed
	Truncated    bool                  `json:"truncated"`
	PullRequests []*StackedPullRequest `json:"pull_requests"`
}

// StackedPullRequest is a pull request of a stack
type StackedPullRequest struct {
	Number     int64  `json:"number"`
	Title      string `json:"title"`
	HTMLURL    string `json:"html_url"`
	HeadBranch string `json:"head_branch"`
	BaseBranch string `json:"base_branch"`
	// ParentNumber is the number of the pull request this one is based on, 0 for the bottom one
	ParentNumber int64 `json:"parent_number"`
	Depth        int   `json:"depth"`
	// Current is true for the pull request the stack was requested for
	Current bool `json:"current"`
	// Draft is true for a work-in-progress title
	Draft bool `json:"draft"`
	// ReviewState is "approved", "changes_requested" or "pending", from the official reviews
	// enum: approved,changes_requested,pending
	ReviewState string `json:"review_state"`
	// CheckState is the combined commit status of the head commit, empty without any
	CheckState CommitStatusState `json:"check_state"`
}
