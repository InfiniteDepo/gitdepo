// Copyright 2024 The Forgejo Authors. All rights reserved.
// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package forms

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"forgejo.org/models"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/web/middleware"
	"forgejo.org/services/context"

	"code.forgejo.org/go-chi/binding"
)

// CreateRepoForm form for creating repository
type CreateRepoForm struct {
	UID           int64  `binding:"Required"`
	GroupID       int64  // the project of the organization to create the repository in, 0 for its root
	RepoName      string `binding:"Required;AlphaDashDot;MaxSize(100)" preprocess:"TrimSpace"`
	Private       bool
	Description   string `binding:"MaxSize(2048)"`
	DefaultBranch string `binding:"GitRefName;MaxSize(100)"`
	AutoInit      bool
	Gitignores    string
	IssueLabels   string
	License       string
	Readme        string
	Template      bool

	RepoTemplate    int64
	GitContent      bool
	Topics          bool
	GitHooks        bool
	Webhooks        bool
	Avatar          bool
	Labels          bool
	ProtectedBranch bool

	ForkSingleBranch string
	ObjectFormatName string
}

// Validate validates the fields
func (f *CreateRepoForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// MigrateRepoForm form for migrating repository
// this is used to interact with web ui
type MigrateRepoForm struct {
	GroupID int64 // the project of the organization to migrate into, 0 for its root
	// required: true
	CloneAddr    string                 `json:"clone_addr" binding:"Required"`
	Service      structs.GitServiceType `json:"service"`
	AuthUsername string                 `json:"auth_username"`
	AuthPassword string                 `json:"auth_password"`
	AuthToken    string                 `json:"auth_token"`
	// required: true
	UID int64 `json:"uid" binding:"Required"`
	// required: true
	RepoName       string `json:"repo_name" binding:"Required;AlphaDashDot;MaxSize(100)"`
	Mirror         bool   `json:"mirror"`
	LFS            bool   `json:"lfs"`
	LFSEndpoint    string `json:"lfs_endpoint"`
	Private        bool   `json:"private"`
	Description    string `json:"description" binding:"MaxSize(2048)"`
	Wiki           bool   `json:"wiki"`
	Milestones     bool   `json:"milestones"`
	Labels         bool   `json:"labels"`
	Issues         bool   `json:"issues"`
	PullRequests   bool   `json:"pull_requests"`
	Releases       bool   `json:"releases"`
	MirrorInterval string `json:"mirror_interval"`

	MirrorBranchFilter string `json:"mirror_branch_filter"`
	MirrorTagFilter    string `json:"mirror_tag_filter"`
}

// NormalizeMirrorFilters validates the branch and tag filters of a migration and returns them normalized. Filters are
// only allowed for pull mirrors of plain git remotes (other services also bring refs/pull heads and non-git data).
func NormalizeMirrorFilters(service structs.GitServiceType, mirror bool, branchFilter, tagFilter string) (string, string, error) {
	if branchFilter == "" && tagFilter == "" {
		return "", "", nil
	}
	if !mirror || service != structs.PlainGitService {
		return "", "", errors.New("branch and tag filters are only for pull mirrors of plain git remotes")
	}
	branchFilter, err := repo_model.NormalizeRefFilter(branchFilter)
	if err != nil {
		return "", "", err
	}
	tagFilter, err = repo_model.NormalizeRefFilter(tagFilter)
	return branchFilter, tagFilter, err
}

// Validate validates the fields
func (f *MigrateRepoForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// scpRegex matches the SCP-like addresses used by Git to access repositories over SSH.
var scpRegex = regexp.MustCompile(`^([a-zA-Z0-9_]+)@([a-zA-Z0-9._-]+):(.*)$`)

// ParseRemoteAddr checks if given remote address is valid,
// and returns composed URL with needed username and password.
func ParseRemoteAddr(remoteAddr, authUsername, authPassword string) (string, error) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	// Remote address can be HTTP/HTTPS/Git URL or local path.
	if strings.HasPrefix(remoteAddr, "http://") ||
		strings.HasPrefix(remoteAddr, "https://") ||
		strings.HasPrefix(remoteAddr, "git://") {
		u, err := url.Parse(remoteAddr)
		if err != nil {
			return "", &models.ErrInvalidCloneAddr{IsURLError: true, Host: remoteAddr}
		}
		if u.User != nil {
			return "", &models.ErrInvalidCloneAddr{Host: remoteAddr, HasCredentials: true}
		}
		if len(authUsername)+len(authPassword) > 0 {
			u.User = url.UserPassword(authUsername, authPassword)
		}
		return u.String(), nil
	}

	// Detect SCP-like remote addresses and return host.
	if m := scpRegex.FindStringSubmatch(remoteAddr); m != nil {
		// Match SCP-like syntax and convert it to a URL.
		// Eg, "git@forgejo.org:user/repo" becomes
		// "ssh://git@forgejo.org/user/repo".
		return fmt.Sprintf("ssh://%s@%s/%s", url.User(m[1]), m[2], m[3]), nil
	}

	return remoteAddr, nil
}

// RepoSettingForm form for changing repository settings
type RepoSettingForm struct {
	RepoName               string `binding:"Required;AlphaDashDot;MaxSize(100)"`
	Description            string `binding:"MaxSize(2048)"`
	Website                string `binding:"ValidSiteUrl;MaxSize(1024)"`
	FollowingRepos         string
	Interval               string
	MirrorAddress          string
	MirrorUsername         string
	MirrorPassword         string
	LFS                    bool   `form:"mirror_lfs"`
	LFSEndpoint            string `form:"mirror_lfs_endpoint"`
	PushMirrorID           string
	PushMirrorAddress      string
	PushMirrorUsername     string
	PushMirrorPassword     string
	PushMirrorSyncOnCommit bool
	PushMirrorInterval     string
	PushMirrorUseSSH       bool
	PushMirrorBranchFilter string `binding:"MaxSize(2048)" preprocess:"TrimSpace"`
	Private                bool
	Template               bool
	EnablePrune            bool
	MirrorBranchFilter     string `binding:"MaxSize(2048)" preprocess:"TrimSpace"`
	MirrorTagFilter        string `binding:"MaxSize(2048)" preprocess:"TrimSpace"`

	// Advanced settings
	IsArchived bool

	// Signing Settings
	TrustModel string

	// Admin settings
	EnableHealthCheck  bool
	RequestReindexType string
}

// Validate validates the fields
func (f *RepoSettingForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// RepoCodeSearchForm form for the branches code search indexes, one name or pattern per line
type RepoCodeSearchForm struct {
	IndexedBranches string `form:"indexed_branches" binding:"MaxSize(4096)"`
}

// RepoUnitSettingForm form for changing repository unit settings
type RepoUnitSettingForm struct {
	EnableCode                            bool
	EnableWiki                            bool
	GloballyWriteableWiki                 bool
	EnableExternalWiki                    bool
	ExternalWikiURL                       string
	WikiSource                            string
	WikiFolder                            string
	WikiBranch                            string
	EnableIssues                          bool
	EnableExternalTracker                 bool
	ExternalTrackerURL                    string
	TrackerURLFormat                      string
	TrackerIssueStyle                     string
	ExternalTrackerRegexpPattern          string
	EnableCloseIssuesViaCommitInAnyBranch bool
	EnableProjects                        bool
	EnableReleases                        bool
	EnablePackages                        bool
	EnablePulls                           bool
	EnableActions                         bool
	PullsIgnoreWhitespace                 bool
	PullsAllowMerge                       bool
	PullsAllowRebase                      bool
	PullsAllowRebaseMerge                 bool
	PullsAllowSquash                      bool
	PullsAllowFastForwardOnly             bool
	PullsAllowManualMerge                 bool
	PullsDefaultMergeStyle                string `binding:"In(merge,rebase,rebase-merge,squash,fast-forward-only,manually-merged,rebase-update-only)"`
	PullsDefaultUpdateStyle               string `binding:"In(merge,rebase)"`
	EnableAutodetectManualMerge           bool
	PullsAllowRebaseUpdate                bool
	DefaultAllowMaintainerEdit            bool
	CancelAutoMergeOnPush                 bool
	EnableTimetracker                     bool
	AllowOnlyContributorsToTrackTime      bool
	EnableIssueDependencies               bool
}

// Validate validates the fields
func (f *RepoUnitSettingForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// __________                             .__
// \______   \____________    ____   ____ |  |__
//  |    |  _/\_  __ \__  \  /    \_/ ___\|  |  \
//  |    |   \ |  | \// __ \|   |  \  \___|   Y  \
//  |______  / |__|  (____  /___|  /\___  >___|  /
//         \/             \/     \/     \/     \/

// ProtectBranchForm form for changing protected branch settings
type ProtectBranchForm struct {
	RuleName                      string `binding:"Required"`
	RuleID                        int64
	EnablePush                    string
	WhitelistUsers                string
	WhitelistTeams                string
	WhitelistDeployKeys           bool
	WhitelistDeployKeyIDs         string `form:"whitelist_deploy_key_ids"`
	EnableMergeWhitelist          bool
	MergeWhitelistUsers           string
	MergeWhitelistTeams           string
	EnableStatusCheck             bool
	StatusCheckContexts           string
	RequiredApprovals             int64
	EnableApprovalsWhitelist      bool
	ApprovalsWhitelistUsers       string
	ApprovalsWhitelistTeams       string
	BlockOnRejectedReviews        bool
	BlockOnOfficialReviewRequests bool
	BlockOnOutdatedBranch         bool
	DismissStaleApprovals         bool
	IgnoreStaleApprovals          bool
	IgnorePusherApprovals         bool
	RequireSignedCommits          bool
	ProtectedFilePatterns         string
	UnprotectedFilePatterns       string
	ApplyToAdmins                 bool

	BlockOnUnresolvedConversations bool
	IgnoreOutdatedConversations    bool
	BlockOnIncompleteTasks         bool

	RequireMergeQueue             bool
	MergeQueueMergeStyle          string
	AllowedMergeStyles            []string `form:"allowed_merge_styles"`
	DefaultMergeStyle             string   `form:"default_merge_style"`
	MergeQueueBuildConcurrency    int
	MergeQueueMinGroupSize        int
	MergeQueueMaxGroupSize        int
	MergeQueueWaitMinutes         int
	MergeQueueCheckTimeoutMinutes int

	DeleteAllowlistUsers           string `form:"delete_allowlist_users"`
	DeleteAllowlistTeams           string `form:"delete_allowlist_teams"`
	DeleteAllowlistDeployKeyIDs    string `form:"delete_allowlist_deploy_key_ids"`
	ForcePushAllowlistUsers        string `form:"force_push_allowlist_users"`
	ForcePushAllowlistTeams        string `form:"force_push_allowlist_teams"`
	ForcePushAllowlistDeployKeyIDs string `form:"force_push_allowlist_deploy_key_ids"`

	// Organization rules only
	ApplyToSelectedRepos bool
	SelectedRepoIDs      string `form:"selected_repo_ids"`
}

// Validate validates the fields
func (f *ProtectBranchForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

//  __      __      ___.   .__                   __
// /  \    /  \ ____\_ |__ |  |__   ____   ____ |  | __
// \   \/\/   // __ \| __ \|  |  \ /  _ \ /  _ \|  |/ /
//  \        /\  ___/| \_\ \   Y  (  <_> |  <_> )    <
//   \__/\  /  \___  >___  /___|  /\____/ \____/|__|_ \
//        \/       \/    \/     \/                   \/

// WebhookCoreForm form for changing web hook (common to all webhook types)
type WebhookCoreForm struct {
	Events                   string
	Create                   bool
	Delete                   bool
	Fork                     bool
	Issues                   bool
	IssueAssign              bool
	IssueLabel               bool
	IssueMilestone           bool
	IssueComment             bool
	Release                  bool
	Push                     bool
	PullRequest              bool
	PullRequestAssign        bool
	PullRequestLabel         bool
	PullRequestMilestone     bool
	PullRequestComment       bool
	PullRequestReview        bool
	PullRequestSync          bool
	PullRequestReviewRequest bool
	Wiki                     bool
	Repository               bool
	Package                  bool
	ActionFailure            bool
	ActionSuccess            bool
	WorkflowRunBlocked       bool
	WorkflowRunCancelled     bool
	WorkflowRunFailure       bool
	WorkflowRunRunning       bool
	WorkflowRunSkipped       bool
	WorkflowRunSuccess       bool
	WorkflowRunWaiting       bool
	WorkflowJobBlocked       bool
	WorkflowJobCancelled     bool
	WorkflowJobFailure       bool
	WorkflowJobRunning       bool
	WorkflowJobSkipped       bool
	WorkflowJobSuccess       bool
	WorkflowJobWaiting       bool
	MergeGroup               bool
	Active                   bool
	BranchFilter             string `binding:"GlobPattern"`
	AuthorizationHeader      string
}

// PushOnly if the hook will be triggered when push
func (f WebhookCoreForm) PushOnly() bool {
	return f.Events == "push_only"
}

// SendEverything if the hook will be triggered any event
func (f WebhookCoreForm) SendEverything() bool {
	return f.Events == "send_everything"
}

// ChooseEvents if the hook will be triggered choose events
func (f WebhookCoreForm) ChooseEvents() bool {
	return f.Events == "choose_events"
}

// WebhookForm form for changing web hook (specific handling depending on the webhook type)
type WebhookForm struct {
	WebhookCoreForm
	URL         string
	ContentType webhook_model.HookContentType
	Secret      string
	HTTPMethod  string
	Metadata    any
}

// .___
// |   | ______ ________ __   ____
// |   |/  ___//  ___/  |  \_/ __ \
// |   |\___ \ \___ \|  |  /\  ___/
// |___/____  >____  >____/  \___  >
//          \/     \/            \/

// CreateIssueForm form for creating issue
type CreateIssueForm struct {
	Title               string `binding:"Required;MaxSize(255)"`
	LabelIDs            string `form:"label_ids"`
	AssigneeIDs         string `form:"assignee_ids"`
	Ref                 string `form:"ref"`
	MilestoneID         int64
	ProjectID           int64
	AssigneeID          int64
	Content             string
	Files               []string
	AllowMaintainerEdit bool
}

// Validate validates the fields
func (f *CreateIssueForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// CreateCommentForm form for creating comment
type CreateCommentForm struct {
	Content string
	Status  string `binding:"OmitEmpty;In(reopen,close)"`
	Files   []string
}

// Validate validates the fields
func (f *CreateCommentForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// PullAttentionForm form for adding a user to the attention set of a pull request or removing one
type PullAttentionForm struct {
	UserName string `form:"username" binding:"Required"`
	Reason   string `binding:"MaxSize(255)"`
}

// Validate validates the fields
func (f *PullAttentionForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// PullTaskForm form for adding a task to a pull request
type PullTaskForm struct {
	Content   string `binding:"Required;MaxSize(255)"`
	CommentID int64  `form:"comment_id"`
}

// Validate validates the fields
func (f *PullTaskForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// ReactionForm form for adding and removing reaction
type ReactionForm struct {
	Content string `binding:"Required"`
}

// Validate validates the fields
func (f *ReactionForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// IssueLockForm form for locking an issue
type IssueLockForm struct {
	Reason string `binding:"Required"`
}

// Validate validates the fields
func (i *IssueLockForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, i, ctx.Locale)
}

// HasValidReason checks to make sure that the reason submitted in
// the form matches any of the values in the config
func (i IssueLockForm) HasValidReason() bool {
	if strings.TrimSpace(i.Reason) == "" {
		return true
	}

	return slices.Contains(setting.Repository.Issue.LockReasons, i.Reason)
}

// CreateProjectForm form for creating a project
type CreateProjectForm struct {
	Title        string `binding:"Required;MaxSize(100)"`
	Content      string
	TemplateType string
	CardType     string
}

// EditProjectColumnForm is a form for editing a project column
type EditProjectColumnForm struct {
	Title   string `binding:"Required;MaxSize(100)"`
	Sorting int8
	Color   string `binding:"MaxSize(7)"`
}

// CreateMilestoneForm form for creating milestone
type CreateMilestoneForm struct {
	Title    string `binding:"Required;MaxSize(50)"`
	Content  string
	Deadline string
}

// Validate validates the fields
func (f *CreateMilestoneForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// CreateLabelForm form for creating label
type CreateLabelForm struct {
	ID          int64
	Title       string `binding:"Required;MaxSize(50)" locale:"repo.issues.label_title"`
	Exclusive   bool   `form:"exclusive"`
	IsArchived  bool   `form:"is_archived"`
	Description string `binding:"MaxSize(200)" locale:"repo.issues.label_description"`
	Color       string `binding:"Required;MaxSize(7)" locale:"repo.issues.label_color"`
}

// Validate validates the fields
func (f *CreateLabelForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// InitializeLabelsForm form for initializing labels
type InitializeLabelsForm struct {
	TemplateName string `binding:"Required"`
}

// Validate validates the fields
func (f *InitializeLabelsForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// MergePullRequestForm form for merging Pull Request
// swagger:model MergePullRequestOption
type MergePullRequestForm struct {
	// required: true
	// enum: ["merge", "rebase", "rebase-merge", "squash", "fast-forward-only", "manually-merged"]
	Do                     string `binding:"Required;In(merge,rebase,rebase-merge,squash,fast-forward-only,manually-merged)"`
	MergeTitleField        string
	MergeMessageField      string
	MergeCommitID          string // only used for manually-merged
	HeadCommitID           string `json:"head_commit_id,omitempty"`
	ForceMerge             bool   `json:"force_merge,omitempty"`
	MergeWhenChecksSucceed bool   `json:"merge_when_checks_succeed,omitempty"`
	DeleteBranchAfterMerge bool   `json:"delete_branch_after_merge,omitempty"`
	// false merges without merging forward into later branches of the branching model
	MergeForward *bool `json:"merge_forward,omitempty" form:"-"`
	// the web merge box's "Don't merge forward"
	SkipMergeForward bool `json:"-"`
	// do not merge before this time, only with merge_when_checks_succeed; the merge is pinned to the current head
	// swagger:strfmt date-time
	ScheduledAfter string `json:"scheduled_after,omitempty"`
	// cancel the scheduled merge if it has not merged by this time, only with scheduled_after and after it
	// swagger:strfmt date-time
	GiveUpAfter string `json:"give_up_after,omitempty"`
}

// MergeStackForm is the form of the "Merge stack" dialog.
type MergeStackForm struct {
	Do string `binding:"Required;In(merge,rebase,rebase-merge,squash,fast-forward-only)"`
	// "<index>:<head commit>" of each pull request, from the bottom of the stack to the one merged from, as the page showed them
	Heads                  []string `form:"head"`
	DeleteBranchAfterMerge bool
}

// SkipsMergeForward reports whether the merge is not to be merged forward.
func (f *MergePullRequestForm) SkipsMergeForward() bool {
	return f.SkipMergeForward || f.MergeForward != nil && !*f.MergeForward
}

// ErrInvalidGiveUpAfter is returned for a give_up_after without scheduled_after, or not after it
var ErrInvalidGiveUpAfter = errors.New("give_up_after requires scheduled_after and must be after it")

// ScheduleTimeStamps parses ScheduledAfter, which must be in the future, and GiveUpAfter, which must be after it.
// Each is 0 if it is empty.
func (f *MergePullRequestForm) ScheduleTimeStamps() (scheduledAfter, giveUpAfter timeutil.TimeStamp, err error) {
	if f.ScheduledAfter == "" {
		if f.GiveUpAfter != "" {
			return 0, 0, ErrInvalidGiveUpAfter
		}
		return 0, 0, nil
	}
	if !f.MergeWhenChecksSucceed {
		return 0, 0, errors.New("scheduled_after requires merge_when_checks_succeed")
	}
	t, err := time.Parse(time.RFC3339, f.ScheduledAfter)
	if err != nil {
		return 0, 0, err
	}
	if !t.After(timeutil.TimeStampNow().AsTime()) {
		return 0, 0, errors.New("scheduled_after must be in the future")
	}
	if f.GiveUpAfter == "" {
		return timeutil.TimeStamp(t.Unix()), 0, nil
	}
	g, err := time.Parse(time.RFC3339, f.GiveUpAfter)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrInvalidGiveUpAfter, err)
	}
	if !g.After(t) {
		return 0, 0, ErrInvalidGiveUpAfter
	}
	return timeutil.TimeStamp(t.Unix()), timeutil.TimeStamp(g.Unix()), nil
}

// ChangeAutoMergeTimeForm is the form of the "Change time" action of a scheduled merge
type ChangeAutoMergeTimeForm struct {
	ScheduledAfter string
	GiveUpAfter    string
}

// ScheduleTimeStamps parses both times like MergePullRequestForm does; the merge time is required.
func (f *ChangeAutoMergeTimeForm) ScheduleTimeStamps() (scheduledAfter, giveUpAfter timeutil.TimeStamp, err error) {
	if f.ScheduledAfter == "" {
		return 0, 0, errors.New("scheduled_after is required")
	}
	return (&MergePullRequestForm{MergeWhenChecksSucceed: true, ScheduledAfter: f.ScheduledAfter, GiveUpAfter: f.GiveUpAfter}).ScheduleTimeStamps()
}

// Validate validates the fields
func (f *MergePullRequestForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// CodeCommentForm form for adding code comments for PRs
type CodeCommentForm struct {
	Origin          string `binding:"Required;In(timeline,diff)"`
	Content         string `binding:"Required"`
	Side            string `binding:"Required;In(previous,proposed)"`
	Line            int64
	ExtraLinesCount int64  `form:"extra_lines_count"`
	TreePath        string `form:"path" binding:"Required"`
	SingleReview    bool   `form:"single_review"`
	Reply           int64  `form:"reply"`
	BeforeCommitID  string
	LatestCommitID  string
	Files           []string
}

// Validate validates the fields
func (f *CodeCommentForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// SubmitReviewForm for submitting a finished code review
type SubmitReviewForm struct {
	Content  string
	Type     string
	CommitID string
	Files    []string
}

// Validate validates the fields
func (f *SubmitReviewForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// ReviewType will return the corresponding ReviewType for type
func (f SubmitReviewForm) ReviewType() issues_model.ReviewType {
	switch f.Type {
	case "approve":
		return issues_model.ReviewTypeApprove
	case "comment":
		return issues_model.ReviewTypeComment
	case "reject":
		return issues_model.ReviewTypeReject
	case "":
		return issues_model.ReviewTypeComment // default to comment when doing quick-submit (Ctrl+Enter) on the review form
	default:
		return issues_model.ReviewTypeUnknown
	}
}

// HasEmptyContent checks if the content of the review form is empty.
func (f SubmitReviewForm) HasEmptyContent() bool {
	reviewType := f.ReviewType()

	return (reviewType == issues_model.ReviewTypeComment || reviewType == issues_model.ReviewTypeReject) &&
		len(strings.TrimSpace(f.Content)) == 0
}

// DismissReviewForm for dismissing stale review by repo admin
type DismissReviewForm struct {
	ReviewID int64 `binding:"Required"`
	Message  string
}

// UpdateAllowEditsForm form for changing if PR allows edits from maintainers
type UpdateAllowEditsForm struct {
	AllowMaintainerEdit bool
}

// __________       .__
// \______   \ ____ |  |   ____ _____    ______ ____
//  |       _// __ \|  | _/ __ \\__  \  /  ___// __ \
//  |    |   \  ___/|  |_\  ___/ / __ \_\___ \\  ___/
//  |____|_  /\___  >____/\___  >____  /____  >\___  >
//         \/     \/          \/     \/     \/     \/

// NewReleaseForm form for creating release
type NewReleaseForm struct {
	TagName          string `binding:"Required;GitRefName;MaxSize(255)"`
	Target           string `form:"tag_target" binding:"Required;MaxSize(255)"`
	Title            string `binding:"MaxSize(255)"`
	Content          string
	Draft            string
	TagOnly          string
	Prerelease       bool
	AddTagMsg        bool
	HideArchiveLinks bool
	Files            []string
}

// Validate validates the fields
func (f *NewReleaseForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// GenerateReleaseNotesForm form for generating release notes
type GenerateReleaseNotesForm struct {
	TagName         string `binding:"Required;GitRefName;MaxSize(255)" locale:"repo.release.tag_name"`
	Target          string `form:"tag_target" binding:"MaxSize(255)"`
	PreviousTagName string `binding:"GitRefName;MaxSize(255)"`

	IncludeDirectCommits bool
}

// Validate validates the fields
func (f *GenerateReleaseNotesForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// EditReleaseForm form for changing release
type EditReleaseForm struct {
	Title            string `form:"title" binding:"Required;MaxSize(255)"`
	Content          string `form:"content"`
	Draft            string `form:"draft"`
	Prerelease       bool   `form:"prerelease"`
	HideArchiveLinks bool
	Files            []string
}

// Validate validates the fields
func (f *EditReleaseForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

//  __      __.__ __   .__
// /  \    /  \__|  | _|__|
// \   \/\/   /  |  |/ /  |
//  \        /|  |    <|  |
//   \__/\  / |__|__|_ \__|
//        \/          \/

// NewWikiForm form for creating wiki
type NewWikiForm struct {
	Title   string `binding:"Required"`
	Content string `binding:"Required"`
	Message string
}

// Validate validates the fields
// FIXME: use code generation to generate this method.
func (f *NewWikiForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// ___________    .___.__  __
// \_   _____/  __| _/|__|/  |_
//  |    __)_  / __ | |  \   __\
//  |        \/ /_/ | |  ||  |
// /_______  /\____ | |__||__|
//         \/      \/

// EditRepoFileForm form for changing repository file
type EditRepoFileForm struct {
	TreePath      string `binding:"Required;MaxSize(500)"`
	Content       string
	CommitSummary string `binding:"MaxSize(100)"`
	CommitMessage string
	CommitChoice  string `binding:"Required;MaxSize(50)"`
	NewBranchName string `binding:"GitRefName;MaxSize(100)"`
	LastCommit    string
	CommitMailID  int64 `binding:"Required"`
	Signoff       bool
}

// Validate validates the fields
func (f *EditRepoFileForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// EditPreviewDiffForm form for changing preview diff
type EditPreviewDiffForm struct {
	Content string
}

// Validate validates the fields
func (f *EditPreviewDiffForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// _________ .__                                 __________.__        __
// \_   ___ \|  |__   __________________ ___.__. \______   \__| ____ |  | __
// /    \  \/|  |  \_/ __ \_  __ \_  __ <   |  |  |     ___/  |/ ___\|  |/ /
// \     \___|   Y  \  ___/|  | \/|  | \/\___  |  |    |   |  \  \___|    <
//  \______  /___|  /\___  >__|   |__|   / ____|  |____|   |__|\___  >__|_ \
//         \/     \/     \/              \/                        \/     \/

// CherryPickForm form for changing repository file
type CherryPickForm struct {
	CommitSummary string `binding:"MaxSize(100)"`
	CommitMessage string
	CommitChoice  string `binding:"Required;MaxSize(50)"`
	NewBranchName string `binding:"GitRefName;MaxSize(100)"`
	LastCommit    string
	CommitMailID  int64 `binding:"Required"`
	Revert        bool
	Signoff       bool
}

// Validate validates the fields
func (f *CherryPickForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

//  ____ ___        .__                    .___
// |    |   \______ |  |   _________     __| _/
// |    |   /\____ \|  |  /  _ \__  \   / __ |
// |    |  / |  |_> >  |_(  <_> ) __ \_/ /_/ |
// |______/  |   __/|____/\____(____  /\____ |
//           |__|                   \/      \/
//

// UploadRepoFileForm form for uploading repository file
type UploadRepoFileForm struct {
	TreePath      string `binding:"MaxSize(500)"`
	CommitSummary string `binding:"MaxSize(100)"`
	CommitMessage string
	CommitChoice  string `binding:"Required;MaxSize(50)"`
	NewBranchName string `binding:"GitRefName;MaxSize(100)"`
	Files         []string
	FullPaths     []string
	CommitMailID  int64 `binding:"Required"`
	Signoff       bool
}

// Validate validates the fields
func (f *UploadRepoFileForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// RemoveUploadFileForm form for removing uploaded file
type RemoveUploadFileForm struct {
	File string `binding:"Required;MaxSize(50)"`
}

// Validate validates the fields
func (f *RemoveUploadFileForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// ________         .__          __
// \______ \   ____ |  |   _____/  |_  ____
// |    |  \_/ __ \|  | _/ __ \   __\/ __ \
// |    `   \  ___/|  |_\  ___/|  | \  ___/
// /_______  /\___  >____/\___  >__|  \___  >
//         \/     \/          \/          \/

// DeleteRepoFileForm form for deleting repository file
type DeleteRepoFileForm struct {
	CommitSummary string `binding:"MaxSize(100)"`
	CommitMessage string
	CommitChoice  string `binding:"Required;MaxSize(50)"`
	NewBranchName string `binding:"GitRefName;MaxSize(100)"`
	LastCommit    string
	CommitMailID  int64 `binding:"Required"`
	Signoff       bool
}

// Validate validates the fields
func (f *DeleteRepoFileForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// ___________.__                 ___________                     __
// \__    ___/|__| _____   ____   \__    ___/___________    ____ |  | __ ___________
// |    |   |  |/     \_/ __ \    |    |  \_  __ \__  \ _/ ___\|  |/ // __ \_  __ \
// |    |   |  |  Y Y  \  ___/    |    |   |  | \// __ \\  \___|    <\  ___/|  | \/
// |____|   |__|__|_|  /\___  >   |____|   |__|  (____  /\___  >__|_ \\___  >__|
// \/     \/                        \/     \/     \/    \/

// AddTimeManuallyForm form that adds spent time manually.
type AddTimeManuallyForm struct {
	Hours   int `binding:"Range(0,1000)" locale:"repo.issues.add_time_hours"`
	Minutes int `binding:"Range(0,1000)" locale:"repo.issues.add_time_minutes"`
}

// Validate validates the fields
func (f *AddTimeManuallyForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// SaveTopicForm form for save topics for repository
type SaveTopicForm struct {
	Topics []string `binding:"topics;Required;"`
}

type CommitNotesForm struct {
	Notes string
}

// EnvironmentForm is the rules of an Actions environment as the settings page posts them: the reviewers as "user:<id>"
// and "team:<id>" separated by commas, one pattern row per pattern_type/pattern pair, labels and workflows one per line.
type EnvironmentForm struct {
	Name              string
	Reviewers         string
	PreventSelfReview bool
	WaitTimer         string // parsed by the handler, so text that is no number is refused, not read as 0
	RefPolicy         string
	PatternTypes      []string `form:"pattern_type"`
	Patterns          []string `form:"pattern"`
	RunnerLabels      string
	AllowedWorkflows  string
	Scope             string // of an organization environment: "all" repositories, else the selected RepoIDs
	RepoIDs           string `form:"repo_ids"`
}

func (f *EnvironmentForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}
