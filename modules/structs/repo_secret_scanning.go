// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// SecretScanningLocationDetails is where a secret was found: a file at a line, in the commit that brought it, as
// GitHub names them. Fields that gitdepo can't fill (the columns, the URLs of a wiki commit) are left out. Path and
// the commit author are text from git, not checked by gitdepo: clients must escape them.
// swagger:model
type SecretScanningLocationDetails struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	BlobSHA   string `json:"blob_sha"`
	// the API URL of the blob (not for the wiki)
	BlobURL   string `json:"blob_url,omitempty"`
	CommitSHA string `json:"commit_sha"`
	// the API URL of the commit (not for the wiki)
	CommitURL string `json:"commit_url,omitempty"`
	// the page, for the wiki
	PageURL string `json:"page_url,omitempty"`
	// gitdepo: the page of the file at that commit, or of the issue, pull request or comment, in the web interface
	// (empty when the place has no commit and no text, and for the wiki)
	HTMLURL string `json:"html_url,omitempty"`
	// gitdepo: the author of the commit, as it names itself (anyone can write any name)
	CommitAuthorName  string `json:"commit_author_name"`
	CommitAuthorEmail string `json:"commit_author_email"`
	// swagger:strfmt date-time
	CommitDate *time.Time `json:"commit_date,omitempty"`
	// gitdepo: true when only a refs/pull/* ref reaches the commit
	PullRef bool `json:"pull_ref,omitempty"`
	// gitdepo: for a place in text the caller may read, the number of the issue or pull request
	IssueNumber int64 `json:"issue_number,omitempty"`
	// gitdepo: for a place in text the caller may read, the part that holds the secret: title, body or comment
	Field string `json:"field,omitempty"`
	// gitdepo: for a place in text the caller may read, the login of who wrote it (empty for an import)
	Poster string `json:"poster,omitempty"`
	// gitdepo: true when the text no longer holds the secret (the alert stays); on an issue_text or comment_text place with no other detail, true when the issue or comment was deleted (only said to a caller who reads issues and pull requests)
	Removed bool `json:"removed,omitempty"`
	// the API URL of the issue, for an issue_title place
	IssueTitleURL string `json:"issue_title_url,omitempty"`
	// the API URL of the issue, for an issue_body place
	IssueBodyURL string `json:"issue_body_url,omitempty"`
	// the API URL of the comment, for an issue_comment place
	IssueCommentURL string `json:"issue_comment_url,omitempty"`
	// the API URL of the pull request, for a pull_request_title place
	PullRequestTitleURL string `json:"pull_request_title_url,omitempty"`
	// the API URL of the pull request, for a pull_request_body place
	PullRequestBodyURL string `json:"pull_request_body_url,omitempty"`
	// the API URL of the comment, for a pull_request_comment place
	PullRequestCommentURL string `json:"pull_request_comment_url,omitempty"`
	// gitdepo: for a place in a comment the caller may read, the ID of the comment
	CommentID int64 `json:"comment_id,omitempty"`
}

// SecretScanningLocation is a place a secret was found.
// swagger:model
type SecretScanningLocation struct {
	// commit (the code of the repository, or a pull ref), wiki_commit, or a place in text:
	// issue_title, issue_body, issue_comment, pull_request_title, pull_request_body, pull_request_comment; for a
	// caller who may not read that issue or pull request it is only issue_text or comment_text, with no details
	Type    string                        `json:"type"`
	Details SecretScanningLocationDetails `json:"details"`
}

// SecretScanningAlert is a secret found in the code or wiki of a repository. It never holds the secret. The shape
// follows GitHub's secret scanning alerts.
// swagger:model
type SecretScanningAlert struct {
	Number int64 `json:"number"`
	// the API URL of the alert
	URL string `json:"url"`
	// open or resolved
	State string `json:"state"`
	// why the alert is resolved: false_positive, wont_fix, revoked or used_in_tests; empty while open
	Resolution        string `json:"resolution"`
	ResolutionComment string `json:"resolution_comment"`
	ResolvedBy        *User  `json:"resolved_by"`
	// swagger:strfmt date-time
	ResolvedAt *time.Time `json:"resolved_at"`
	// the rule that found the secret (aws-access-key-id, ...)
	SecretType string `json:"secret_type"`
	// the name of that rule
	SecretTypeDisplayName string `json:"secret_type_display_name"`
	// the keyed fingerprint of the secret: the same secret has the same one in every location
	Fingerprint string `json:"fingerprint"`
	// swagger:strfmt date-time
	CreatedAt time.Time `json:"created_at"`
	// swagger:strfmt date-time
	UpdatedAt time.Time `json:"updated_at"`
	// the page of the alert in the web interface (not there yet)
	HTMLURL string `json:"html_url"`
	// the places of the alert, paged
	LocationsURL string `json:"locations_url"`
	// the places of the alert as the locations endpoint lists them for the viewer (places in the wiki only count for
	// someone who can read the wiki; with the Wiki unit off nobody does)
	LocationsCount int `json:"locations_count"`
	// true while only refs/pull/* (which any reader can write) reach the secret
	ViaPull bool `json:"via_pull"`
}

// EditSecretScanningAlertOption resolves or reopens an alert.
// swagger:model
type EditSecretScanningAlertOption struct {
	// open to reopen, resolved to resolve
	// required: true
	State string `json:"state"`
	// required when resolving: false_positive, wont_fix, revoked or used_in_tests
	Resolution string `json:"resolution"`
	// optional when resolving, at most 1000 bytes, but required (not empty after trimming) for wont_fix; refused when it looks like a secret
	ResolutionComment string `json:"resolution_comment"`
}

// RedactSecretScanningTextOption names the text to remove the secret of an alert from: the title or body of an issue
// or pull request (issue_number and field), or a comment (comment_id).
// swagger:model
type RedactSecretScanningTextOption struct {
	// the number of the issue or pull request, with field title or body
	IssueNumber int64 `json:"issue_number"`
	// title or body; comment (or empty) with comment_id
	Field string `json:"field"`
	// the ID of the comment
	CommentID int64 `json:"comment_id"`
}

// SecretScanningStatus sums up how far the scan of a repository (its code, its wiki and its pull refs) has come.
// swagger:model
type SecretScanningStatus struct {
	// pending (not scanned yet), ok, incomplete (under way, or with parts that were not scanned) or failed
	Status string `json:"status"`
	// a code (max_scan_bytes, over_limit, max_alerts, timeout, git_error, ...), empty when ok
	Reason string `json:"reason"`
	// files and secrets that were marked done without being scanned
	Holes int64 `json:"holes"`
	// files over the size limit that were not read, counted since the last scan from the beginning (a rescan)
	SkippedLarge int64 `json:"skipped_large"`
	// when the last scan that did not fail ended
	// swagger:strfmt date-time
	LastScanned *time.Time `json:"last_scanned"`
}
