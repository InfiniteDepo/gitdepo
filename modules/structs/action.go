// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import (
	"time"

	"forgejo.org/modules/optional"
)

// ActionRunJob represents a job of a run
// swagger:model
type ActionRunJob struct {
	// Identifier of this job.
	ID int64 `json:"id"`
	// Identifier of the workflow run this job belongs to.
	RunID int64 `json:"run_id"`
	// How many times the job has been attempted including the current attempt.
	Attempt int64 `json:"attempt"`
	// Opaque identifier that uniquely identifies a single attempt of a job.
	Handle string `json:"handle"`
	// the repository id
	RepoID int64 `json:"repo_id"`
	// the owner id
	OwnerID int64 `json:"owner_id"`
	// the action run job name
	Name string `json:"name"`
	// HTMLURL is the URL where a user can view the job using their browser.
	HTMLURL string `json:"html_url"`
	// the action run job needed ids
	Needs []string `json:"needs"`
	// the action run job labels to run on
	RunsOn []string `json:"runs_on"`
	// the action run job latest task id
	TaskID int64 `json:"task_id"`
	// the action run job status
	Status string `json:"status"`
	// the steps that make up this workflow job's execution, including the
	// "Set up job" entry (number=0) and "Complete job" tail. Only populated by
	// endpoints that return a single job (e.g. GET /repos/{owner}/{repo}/actions/jobs/{job_id}).
	Steps []*ActionRunJobStep `json:"steps,omitempty"`
}

// ActionRunJobStep is a step in a workflow job's execution. The slice on
// ActionRunJob.Steps always includes a "Set up job" entry at number=0 and a
// "Complete job" entry as the last element; the entries in between are the
// workflow's real steps in declaration order. The Number field is the value
// accepted by the job-logs endpoint's `?step=` filter.
//
// swagger:model
type ActionRunJobStep struct {
	// position in the job's step list. 0 is the "Set up job" entry; the last
	// index is the "Complete job" entry; real steps are numbered 1..N in
	// declaration order.
	Number int64 `json:"number"`
	// step name (workflow YAML `name:` for real steps; "Set up job" and
	// "Complete job" for the head and tail respectively)
	Name string `json:"name"`
	// step status (success, failure, running, waiting, skipped, cancelled, ...)
	Status string `json:"status"`
	// when the step started
	// swagger:type string
	// swagger:strfmt date-time
	Started optional.Option[time.Time] `json:"started"`
	// when the step stopped
	// swagger:type string
	// swagger:strfmt date-time
	Stopped optional.Option[time.Time] `json:"stopped"`
}

// DeleteActionRunsResult is the result of deleting the workflow runs older than a number of days
// swagger:model
type DeleteActionRunsResult struct {
	// the number of runs deleted
	Deleted int64 `json:"deleted"`
	// whether more runs match: send the request again to delete them
	More bool `json:"more"`
}

// ActionRun represents an action run
// swagger:model
type ActionRun struct {
	// the action run id
	ID int64 `json:"id"`
	// the action run's title
	Title string `json:"title"`
	// the repo this action is part of
	Repo *Repository `json:"repository"`
	// the name of workflow file
	WorkflowID string `json:"workflow_id"`
	// a unique number for each run of a repository
	Index int64 `json:"index_in_repo"`
	// the user that triggered this action run
	TriggerUser *User `json:"trigger_user"`
	// the cron id for the schedule trigger
	ScheduleID int64
	// the commit/tag/… the action run ran on
	PrettyRef string `json:"prettyref"`
	// has the commit/tag/… the action run ran on been deleted
	IsRefDeleted bool `json:"is_ref_deleted"`
	// the commit sha the action run ran on
	CommitSHA string `json:"commit_sha"`
	// If this is triggered by a PR from a forked repository or an untrusted user, we need to check if it is approved and limit permissions when running the workflow.
	IsForkPullRequest bool `json:"is_fork_pull_request"`
	// may need approval if it's a fork pull request
	NeedApproval bool `json:"need_approval"`
	// who approved this action run
	ApprovedBy int64 `json:"approved_by"`
	// the webhook event that causes the workflow to run
	Event string `json:"event"`
	// the payload of the webhook event that causes the workflow to run
	EventPayload string `json:"event_payload"`
	// the trigger event defined in the `on` configuration of the triggered workflow
	TriggerEvent string `json:"trigger_event"`
	// the current status of this run
	Status string `json:"status"`
	// whether the run is exempt from the automatic cleanup of old runs
	Keep bool `json:"keep"`
	// when the action run was started
	// swagger:type string
	// swagger:strfmt date-time
	Started optional.Option[time.Time] `json:"started"`
	// when the action run was stopped
	// swagger:type string
	// swagger:strfmt date-time
	Stopped optional.Option[time.Time] `json:"stopped"`
	// when the action run was created
	Created time.Time `json:"created"`
	// when the action run was last updated
	Updated time.Time `json:"updated"`
	// how long the action run ran for
	Duration time.Duration `json:"duration,omitempty"`
	// the url of this action run
	HTMLURL string `json:"html_url"`
}

// ListActionRunResponse return a list of ActionRun
type ListActionRunResponse struct {
	Entries    []*ActionRun `json:"workflow_runs"`
	TotalCount int64        `json:"total_count"`
}

// ActionRunSummary is a workflow run as listed across the repositories of an organization
// swagger:model
type ActionRunSummary struct {
	// the action run id
	ID int64 `json:"id"`
	// the action run's title
	Title string `json:"title"`
	// the repo this run belongs to
	Repo *RepositoryMeta `json:"repository"`
	// the name of workflow file
	WorkflowID string `json:"workflow_id"`
	// a unique number for each run of a repository
	Index int64 `json:"index_in_repo"`
	// the user that triggered this action run
	TriggerUser *User `json:"trigger_user"`
	// the branch, tag or pull request (#number) the run ran on
	PrettyRef string `json:"prettyref"`
	// the commit sha the action run ran on
	CommitSHA string `json:"commit_sha"`
	// the webhook event that causes the workflow to run
	Event string `json:"event"`
	// the current status of this run
	Status string `json:"status"`
	// whether the run is exempt from the automatic cleanup of old runs
	Keep bool `json:"keep"`
	// when the action run was started
	// swagger:type string
	// swagger:strfmt date-time
	Started optional.Option[time.Time] `json:"started"`
	// when the action run was stopped
	// swagger:type string
	// swagger:strfmt date-time
	Stopped optional.Option[time.Time] `json:"stopped"`
	// when the action run was created
	Created time.Time `json:"created"`
	// when the action run was last updated
	Updated time.Time `json:"updated"`
	// duration of the run, in nanoseconds
	Duration time.Duration `json:"duration,omitempty"`
	// the URL of the run's page
	HTMLURL string `json:"html_url"`
}

// ListActionRunSummaryResponse return a list of ActionRunSummary
type ListActionRunSummaryResponse struct {
	Entries    []*ActionRunSummary `json:"workflow_runs"`
	TotalCount int64               `json:"total_count"`
}

// ActionUsageEntry is the Actions usage of one owner, repository or runner
// swagger:model
type ActionUsageEntry struct {
	// the ID of the owner, repository or runner; 0 for jobs that had no runner
	ID int64 `json:"id"`
	// the name of the owner, the full name of the repository or the name of the runner
	Name string `json:"name"`
	// the run time of the finished jobs, in minutes
	JobMinutes float64 `json:"job_minutes"`
	// the number of finished jobs
	Jobs int64 `json:"jobs"`
	// how many of the jobs failed
	FailedJobs int64 `json:"failed_jobs"`
	// the number of failed runs (only in top_repos_by_failures)
	FailedRuns int64 `json:"failed_runs,omitempty"`
}

// ActionUsage is the Actions usage of the instance in a period
// swagger:model
type ActionUsage struct {
	GroupBy string `json:"group_by"`
	// swagger:strfmt date-time
	From time.Time `json:"from"`
	// swagger:strfmt date-time
	To                 time.Time           `json:"to"`
	Entries            []*ActionUsageEntry `json:"entries"`
	TopReposByMinutes  []*ActionUsageEntry `json:"top_repos_by_minutes"`
	TopReposByFailures []*ActionUsageEntry `json:"top_repos_by_failures"`
}

// ActionArtifact represents an artifact of a workflow run
// swagger:model
type ActionArtifact struct {
	// the artifact's ID
	ID int64 `json:"id"`
	// the artifact's name
	Name string `json:"name"`
	// the total size of the artifact in bytes
	SizeInBytes int64 `json:"size_in_bytes"`
	// the URL to download the artifact zip archive
	ArchiveDownloadURL string `json:"archive_download_url"`
	// whether the artifact has expired
	Expired bool `json:"expired"`
	// the ID of the workflow run that produced this artifact
	RunID int64 `json:"run_id"`
	// swagger:strfmt date-time
	CreatedAt time.Time `json:"created_at"`
	// swagger:strfmt date-time
	UpdatedAt time.Time `json:"updated_at"`
	// swagger:strfmt date-time
	ExpiresAt time.Time `json:"expires_at"`
}

// ReviewDeploymentsOption approves or rejects deployments of a workflow run that wait for a review
// swagger:model
type ReviewDeploymentsOption struct {
	// the jobs to review, at most 100; empty means every waiting job the user may review
	JobIDs []int64 `json:"job_ids"`
	// approved or rejected
	// enum: approved,rejected
	State string `json:"state"`
	// plain text of at most 2000 bytes; a rejection needs one
	Comment string `json:"comment"`
}

// ActionDeploymentReviewers summarizes who may review a deployment
// swagger:model
type ActionDeploymentReviewers struct {
	// how many users the environment lists as reviewers
	Users int `json:"users"`
	// how many teams the environment lists as reviewers
	Teams int `json:"teams"`
	// whether the authenticated user may review the deployment now
	CanReview bool `json:"can_review"`
}

// ActionDeployment is the gate of one attempt of a job that names an environment
// swagger:model
type ActionDeployment struct {
	ID int64 `json:"id"`
	// the job, and the attempt of it that this deployment gates
	JobID   int64  `json:"job_id"`
	JobName string `json:"job_name"`
	Attempt int64  `json:"attempt"`
	// the name of the environment, empty if the job's environment name was invalid
	Environment string `json:"environment"`
	// waiting_timer, waiting_review, released, refused, cancelled, rejected or expired; an approved deployment waits
	// for its wait timer as waiting_timer, with reviewed_by set
	Status string `json:"status"`
	// the short code why the deployment was refused
	Reason    string                     `json:"reason,omitempty"`
	Reviewers *ActionDeploymentReviewers `json:"reviewers"`
	// when the wait timer ends
	// swagger:strfmt date-time
	ReleaseAfter *time.Time `json:"release_after,omitempty"`
	// who approved or rejected it, and when
	ReviewedBy *User `json:"reviewed_by,omitempty"`
	// swagger:strfmt date-time
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	// plain text, never HTML
	ReviewComment string `json:"review_comment,omitempty"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
}
