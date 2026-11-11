// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	quota_model "forgejo.org/models/quota"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/git/pushoptions"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/web"
	app_context "forgejo.org/services/context"
	"forgejo.org/services/mergeforward"
	pull_service "forgejo.org/services/pull"
)

type preReceiveContext struct {
	*app_context.PrivateContext

	// loadedPusher indicates that where the following information are loaded
	loadedPusher        bool
	user                *user_model.User // it's the org user if a DeployKey is used
	userPerm            access_model.Permission
	deployKeyAccessMode perm_model.AccessMode
	deployKeyKeyID      int64 // public key ID of the deploy key in use
	// the user a branch push is credited to (see recordPusher): the user, the run's trigger user, the creator of the
	// token or of the deploy key; 0 when no real person can be named (recorded as a marker that blocks flagged rules),
	// noPusher for a server push as the Actions user without a task
	pusherID int64
	// the pusher is an Actions task whose token has permissions (`permissions:` or a read default)
	actionTokenPermissions bool

	protectedTags    []*git_model.ProtectedTag
	gotProtectedTags bool

	pushRule            *git_model.PushRule
	gotPushRule         bool
	pushRuleCheckedTips []string // branch tips that passed the push rule in this request
	pushRulePaths       int      // changed paths read for the push rule in this request

	env []string

	opts *private.HookOptions

	isOverQuota bool
}

// canWriteCodeToBranch returns true if pusher can write code to the specified branch name on the ctx repository.
// Permitted if the user has write access to the code unit of the repository, or if there is a PR that allows maintainer
// edit, or if a write deploy key is in-use.
func (ctx *preReceiveContext) canWriteCodeToBranch(branchName string) bool {
	if !ctx.loadPusherAndPermission() {
		return false
	}
	return issues_model.CanMaintainerWriteToBranch(ctx, ctx.userPerm, branchName, ctx.user, access_model.GetUserRepoPermission) || ctx.deployKeyAccessMode >= perm_model.AccessModeWrite
}

// assertCanWriteCodeToBranch verifies that the pusher can write code to the specified branch name on the ctx
// repository.  If the user cannot write, an error response is written to the HTTP context.
func (ctx *preReceiveContext) assertCanWriteCodeToBranch(branchName string) bool {
	if !ctx.canWriteCodeToBranch(branchName) {
		if ctx.Written() {
			return false
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "User '%s' is not allowed to push to branch '%s' in '%s/%s'.", ctx.user.Name, branchName, ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name)

		if ctx.CanCreatePullRequest() {
			fmt.Fprintf(&sb, "\nIf you instead wanted to create a pull request to the branch '%s', please use:", branchName)
			fmt.Fprintf(&sb, "\ngit push origin HEAD:refs/for/%s/choose-a-descriptor", branchName)
			sb.WriteString("\nYou might want to replace 'origin' with the name of your Git remote if it is different from origin. You can freely choose the descriptor to set it to a topic.")
			sb.WriteString("\nYou can learn about creating pull requests with AGit in the documentation: ")
			sb.WriteString(setting.AppDocsURL("user/git-cli/agit-support/"))
		}
		ctx.refuse(http.StatusForbidden, "permission", git.BranchPrefix+branchName, sb.String())
		return false
	}
	return true
}

// canWriteCodeToBranch returns true if pusher can write code to the ctx repository.  Use [canWriteCodeToBranch] instead
// if the write is to a named branch.  Permitted if the user has write access to the code unit, or if a write deploy key
// is in-use.
func (ctx *preReceiveContext) canWriteCode() bool {
	if !ctx.loadPusherAndPermission() {
		return false
	}
	return ctx.userPerm.CanWrite(unit.TypeCode) || ctx.deployKeyAccessMode >= perm_model.AccessModeWrite
}

// assertCanWriteCode verifies that the pusher can write code to the repository.  Use [assertCanWriteCodeToBranch]
// instead if the write is to a named branch.  If the user cannot write, an error response is written to the HTTP
// context.
func (ctx *preReceiveContext) assertCanWriteCode() bool {
	if !ctx.canWriteCode() {
		if ctx.Written() {
			return false
		}
		ctx.refuse(http.StatusForbidden, "permission", "", fmt.Sprintf("User '%s' is not allowed to push to repository '%s/%s'.", ctx.user.Name, ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name))
		return false
	}
	return true
}

// CanCreatePullRequest returns true if pusher can create pull requests
func (ctx *preReceiveContext) CanCreatePullRequest() bool {
	if !ctx.loadPusherAndPermission() {
		return false
	}
	if ctx.actionTokenPermissions || ctx.user.IsAccessTokenBot() {
		// a token with permissions must be granted pull-requests: write
		return ctx.userPerm.CanWrite(unit.TypePullRequests)
	}
	return ctx.userPerm.CanRead(unit.TypePullRequests)
}

// AssertCreatePullRequest returns true if can create pull requests
func (ctx *preReceiveContext) AssertCreatePullRequest() bool {
	if !ctx.CanCreatePullRequest() {
		if ctx.Written() {
			return false
		}
		ctx.refuse(http.StatusForbidden, "permission", "", "User permission denied for creating pull-request.")
		return false
	}
	return true
}

var errPermissionDenied = errors.New("permission denied for changing repo settings")

func (ctx *preReceiveContext) canChangeSettings() error {
	if !ctx.loadPusherAndPermission() {
		return errPermissionDenied
	}

	if !ctx.userPerm.IsOwner() && !ctx.userPerm.IsAdmin() {
		return errPermissionDenied
	}

	if ctx.Repo.Repository.IsFork {
		return errPermissionDenied
	}

	return nil
}

func (ctx *preReceiveContext) validatePushOptions() error {
	opts := web.GetForm(ctx).(*private.HookOptions)

	if opts.GetGitPushOptions().ChangeRepoSettings() {
		if err := ctx.canChangeSettings(); err != nil {
			return err
		}
		// the visibility policy of the repository's organization (a deploy key has no permission, canChangeSettings refused it)
		repo := ctx.Repo.Repository
		if private := opts.GetGitPushOptions().GetBool(pushoptions.RepoPrivate, repo.IsPrivate); private != repo.IsPrivate {
			if err := repo_module.CheckOrgPolicy(ctx, ctx.user, repo, repo_module.OrgPolicyVisibility, nil); err != nil || private {
				return err
			}
			if err := repo.LoadOwner(ctx); err != nil {
				return err
			}
			return repo_module.CheckPersonalRepoPolicy(ctx, ctx.user, repo.Owner, false)
		}
	}

	return nil
}

func (ctx *preReceiveContext) assertPushOptions() bool {
	if err := ctx.validatePushOptions(); err != nil {
		reason := "org_policy"
		if errors.Is(err, errPermissionDenied) {
			reason = "permission"
		}
		ctx.refuse(http.StatusForbidden, reason, "", fmt.Sprintf("options validation failed: %v", err))
		return false
	}
	return true
}

func (ctx *preReceiveContext) checkQuota() error {
	if !setting.Quota.Enabled {
		ctx.isOverQuota = false
		return nil
	}

	if !ctx.loadPusherAndPermission() {
		ctx.isOverQuota = true
		return nil
	}

	ok, err := quota_model.EvaluateQuotaGroupsForUser(ctx, ctx.Repo.Repository.OwnerID, quota_model.LimitSubjectSizeReposAll)
	if err != nil {
		log.Error("quota_model.EvaluateForUser: %v", err)
		ctx.JSON(http.StatusInternalServerError, private.Response{
			UserMsg: "Error checking user quota",
		})
		return err
	}

	ctx.isOverQuota = !ok
	return nil
}

func (ctx *preReceiveContext) quotaExceeded() {
	ctx.refuse(http.StatusRequestEntityTooLarge, "size_lock", "", "Quota exceeded")
}

// refuse refuses the push with msg and records it in the audit log with its reason and the ref it refused, if any.
func (ctx *preReceiveContext) refuse(status int, reason, ref, msg string) {
	recordPushRefused(ctx.PrivateContext, ctx.opts, reason, ref)
	ctx.JSON(status, private.Response{UserMsg: msg})
}

// HookPreReceive checks whether a individual commit is acceptable
func HookPreReceive(ctx *app_context.PrivateContext) {
	opts := web.GetForm(ctx).(*private.HookOptions)

	if s := setting.GetMaintenance(ctx); s.ReadOnly() {
		ctx.JSON(http.StatusForbidden, private.Response{UserMsg: s.Refusal()})
		return
	}

	ourCtx := &preReceiveContext{
		PrivateContext: ctx,
		env:            generateGitEnv(opts), // Generate git environment for checking commits
		opts:           opts,
	}

	// a deploy key that no longer applies is refused before anything else looks at the push
	if opts.DeployKeyKeyID != 0 && !ourCtx.loadPusherAndPermission() {
		return
	}

	if !ourCtx.assertPushOptions() {
		log.Trace("Git push options validation failed")
		return
	}
	log.Trace("Git push options validation succeeded")

	if err := ourCtx.checkQuota(); err != nil {
		return
	}

	// Iterate across the provided old commit IDs
	for i := range opts.OldCommitIDs {
		oldCommitID := opts.OldCommitIDs[i]
		newCommitID := opts.NewCommitIDs[i]
		refFullName := opts.RefFullNames[i]

		switch {
		case refFullName.IsBranch():
			preReceiveBranch(ourCtx, oldCommitID, newCommitID, refFullName)
		case refFullName.IsTag():
			preReceiveTag(ourCtx, oldCommitID, newCommitID, refFullName)
		case refFullName.IsFor():
			preReceiveFor(ourCtx, oldCommitID, newCommitID, refFullName)
		case refFullName.IsPull():
			preReceivePull(ourCtx, oldCommitID, newCommitID, refFullName)
		default:
			if ourCtx.isOverQuota {
				ourCtx.quotaExceeded()
				return
			}
			ourCtx.assertCanWriteCode()
		}
		if ctx.Written() {
			return
		}
	}

	ctx.PlainText(http.StatusOK, "ok")
}

func preReceiveBranch(ctx *preReceiveContext, oldCommitID, newCommitID string, refFullName git.RefName) {
	branchName := refFullName.BranchName()
	// the merge queue writes its builds without hooks: every push that runs them is someone else's
	if pull_model.IsMergeQueueBranch(branchName) {
		ctx.refuse(http.StatusForbidden, "protected_branch", refFullName.String(), fmt.Sprintf("branches under %s are written by the merge queue only", pull_model.MergeQueueBranchPrefix))
		return
	}
	if !ctx.assertCanWriteCodeToBranch(branchName) {
		return
	}

	repo := ctx.Repo.Repository
	objectFormat := ctx.Repo.GetObjectFormat()

	// a name that could be read as another ref is never created (an existing one can still be updated and deleted)
	if oldCommitID == objectFormat.EmptyObjectID().String() && git.IsReservedRefName(branchName) {
		ctx.refuse(http.StatusForbidden, "reserved_name", refFullName.String(), fmt.Sprintf("branch name %s is reserved", branchName))
		return
	}

	if oldCommitID == objectFormat.EmptyObjectID().String() {
		exempt, ok := ctx.checkBranchType(refFullName)
		if !ok {
			return
		}
		if exempt {
			// only once every other check of this ref has passed
			defer func() {
				if !ctx.Written() {
					ctx.recordBranchTypeExempt(refFullName)
				}
			}()
		}
	}

	if newCommitID != objectFormat.EmptyObjectID().String() && !ctx.recordPusher(branchName) {
		return
	}

	if branchName == repo.DefaultBranch && newCommitID == objectFormat.EmptyObjectID().String() {
		log.Warn("Forbidden: Branch: %s is the default branch in %-v and cannot be deleted", branchName, repo)
		ctx.refuse(http.StatusForbidden, "protected_branch", refFullName.String(), fmt.Sprintf("branch %s is the default branch and cannot be deleted", branchName))
		return
	}

	if !ctx.checkPushRules(oldCommitID, newCommitID, branchName) {
		return
	}

	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, repo.ID, branchName)
	if err != nil {
		log.Error("Unable to get protected branch: %s in %-v Error: %v", branchName, repo, err)
		ctx.JSON(http.StatusInternalServerError, private.Response{
			Err: err.Error(),
		})
		return
	}

	// Allow pushes to non-protected branches
	if len(rules) == 0 {
		// ...unless the user is over quota, and the operation is not a delete
		if newCommitID != objectFormat.EmptyObjectID().String() && ctx.isOverQuota {
			ctx.quotaExceeded()
		}

		return
	}

	// The push must pass the repository rule and the organization rule
	for _, protectBranch := range rules {
		if !preReceiveBranchRule(ctx, protectBranch, oldCommitID, newCommitID, branchName) {
			return
		}
	}
}

const noPusher = int64(-1)

// creditedPusher returns the person a push by id is credited to: a token identity gives its creator, and anything that
// is not an existing user (the Actions user of a schedule, a deleted or unknown creator, 0) gives 0, which no
// approval can satisfy.
func creditedPusher(ctx context.Context, id int64) (int64, error) {
	if user_model.IsAccessTokenBotID(id) {
		bot, err := user_model.GetAccessTokenBot(ctx, id)
		if user_model.IsErrUserNotExist(err) {
			return 0, nil
		} else if err != nil {
			return 0, err
		}
		id = bot.BotToken.CreatorID
	}
	if id <= 0 {
		return 0, nil
	}
	if _, err := user_model.GetUserByID(ctx, id); err != nil {
		if user_model.IsErrUserNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return id, nil
}

// recordPusher remembers who pushed to the branch for the rules that ignore pusher approvals. It runs before the
// push is accepted and fails closed: a push that a rule refuses later leaves an extra pusher, which only makes those
// rules stricter. A push that can't be credited to a person (a deploy key or token with no recorded owner, a scheduled
// run) is recorded as user 0, which no approval can satisfy.
func (ctx *preReceiveContext) recordPusher(branchName string) bool {
	if !ctx.loadPusherAndPermission() {
		return false
	}
	if ctx.pusherID == noPusher {
		return true // a push by the server as the Actions user, without a task
	}
	if err := git_model.AddBranchPusher(ctx, ctx.Repo.Repository.ID, branchName, ctx.pusherID); err != nil {
		log.Error("Unable to record the pusher of branch %s in %-v: %v", branchName, ctx.Repo.Repository, err)
		ctx.JSON(http.StatusInternalServerError, private.Response{Err: "Unable to record the pusher of the branch"})
		return false
	}
	return true
}

// preReceiveBranchRule checks the push against one protected branch rule. It returns false after
// writing the response if the rule refuses the push.
func preReceiveBranchRule(ctx *preReceiveContext, protectBranch *git_model.ProtectedBranch, oldCommitID, newCommitID, branchName string) bool {
	repo := ctx.Repo.Repository
	gitRepo := ctx.Repo.GitRepo
	objectFormat := ctx.Repo.GetObjectFormat()
	protectBranch.Repo = repo

	// This ref is a protected branch.
	//
	// First of all we need to enforce absolutely:
	//
	// 1. Detect and prevent deletion of the branch, unless the pusher is in the delete allow-list
	if newCommitID == objectFormat.EmptyObjectID().String() {
		if ctx.opts.DeployKeyKeyID != 0 && protectBranch.CanDeployKeyDelete(ctx.deployKeyKeyID) ||
			ctx.opts.DeployKeyKeyID == 0 && protectBranch.CanUserDelete(ctx, ctx.user) {
			return true
		}
		log.Warn("Forbidden: Branch: %s in %-v is protected from deletion", branchName, repo)
		ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("branch %s is protected from deletion", branchName))
		return false
	}

	// 2. Disallow force pushes to protected branches, unless the pusher is in the force push allow-list.
	// An allowed force push still goes through the checks below.
	if oldCommitID != objectFormat.EmptyObjectID().String() {
		output, _, err := git.NewCommand(ctx, "rev-list", "--max-count=1").AddDynamicArguments(oldCommitID, "^"+newCommitID).RunStdString(&git.RunOpts{Dir: repo.RepoPath(), Env: ctx.env})
		if err != nil {
			log.Error("Unable to detect force push between: %s and %s in %-v Error: %v", oldCommitID, newCommitID, repo, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Fail to detect force push: %v", err),
			})
			return false
		} else if len(output) > 0 && !(ctx.opts.DeployKeyKeyID != 0 && protectBranch.CanDeployKeyForcePush(ctx.deployKeyKeyID) ||
			ctx.opts.DeployKeyKeyID == 0 && protectBranch.CanUserForcePush(ctx, ctx.user)) {
			log.Warn("Forbidden: Branch: %s in %-v is protected from force push", branchName, repo)
			ctx.refuse(http.StatusForbidden, "force_push", git.BranchPrefix+branchName, fmt.Sprintf("branch %s is protected from force push", branchName))
			return false
		}
	}

	// 3. Enforce require signed commits
	if protectBranch.RequireSignedCommits {
		err := verifyCommits(oldCommitID, newCommitID, gitRepo, ctx.env)
		if err != nil {
			if !isErrUnverifiedCommit(err) {
				log.Error("Unable to check commits from %s to %s in %-v: %v", oldCommitID, newCommitID, repo, err)
				ctx.JSON(http.StatusInternalServerError, private.Response{
					Err: fmt.Sprintf("Unable to check commits from %s to %s: %v", oldCommitID, newCommitID, err),
				})
				return false
			}
			unverifiedCommit := err.(*errUnverifiedCommit).sha
			log.Warn("Forbidden: Branch: %s in %-v is protected from unverified commit %s", branchName, repo, unverifiedCommit)
			ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("branch %s is protected from unverified commit %s", branchName, unverifiedCommit))
			return false
		}
	}

	// A merge into a branch whose rule requires a merge queue comes from the queue. Pushes are not merges: whoever may
	// push to the branch still can.
	if protectBranch.RequireMergeQueue && ctx.opts.PullRequestID != 0 && ctx.opts.PushTrigger == repo_module.PushTriggerPRMergeToBase {
		log.Warn("Forbidden: Branch: %s in %-v requires a merge queue, pull request %d was merged directly", branchName, repo, ctx.opts.PullRequestID)
		ctx.refuse(http.StatusForbidden, "merge_queue", git.BranchPrefix+branchName, fmt.Sprintf("branch %s requires a merge queue: add the pull request to the merge queue", branchName))
		return false
	}

	// Now there are several tests which can be overridden:
	//
	// 4. Check protected file patterns - this is overridable from the UI
	changedProtectedfiles := false
	protectedFilePath := ""

	globs := protectBranch.GetProtectedFilePatterns()
	if len(globs) > 0 {
		_, err := pull_service.CheckFileProtection(gitRepo, oldCommitID, newCommitID, globs, 1, ctx.env)
		if err != nil {
			if !models.IsErrFilePathProtected(err) {
				log.Error("Unable to check file protection for commits from %s to %s in %-v: %v", oldCommitID, newCommitID, repo, err)
				ctx.JSON(http.StatusInternalServerError, private.Response{
					Err: fmt.Sprintf("Unable to check file protection for commits from %s to %s: %v", oldCommitID, newCommitID, err),
				})
				return false
			}

			changedProtectedfiles = true
			protectedFilePath = err.(models.ErrFilePathProtected).Path
		}
	}

	// 5. Check if the doer is allowed to push
	var canPush bool
	if ctx.opts.DeployKeyKeyID != 0 {
		canPush = !changedProtectedfiles && protectBranch.CanDeployKeyPush(ctx.deployKeyKeyID)
	} else {
		getUser := user_model.GetUserByID
		if user_model.IsAccessTokenBotID(ctx.opts.UserID) {
			getUser = user_model.GetAccessTokenBot
		}
		user, err := getUser(ctx, ctx.opts.UserID)
		// a token of an organization, a project or a repository revoked or expired since the push was authenticated
		if user_model.IsAccessTokenBotID(ctx.opts.UserID) && (user_model.IsErrUserNotExist(err) || err == nil && !user.BotToken.IsUsable()) {
			ctx.refuse(http.StatusForbidden, "permission", "", "The access token is no longer valid.")
			return false
		}
		if err != nil {
			log.Error("Unable to GetUserByID for commits from %s to %s in %-v: %v", oldCommitID, newCommitID, repo, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to GetUserByID for commits from %s to %s: %v", oldCommitID, newCommitID, err),
			})
			return false
		}
		canPush = !changedProtectedfiles && protectBranch.CanUserPush(ctx, user)
	}

	// 6. If we're not allowed to push directly
	if !canPush {
		// A merge forward step that counts as an extension of the approved pull request: whoever merged it must be
		// allowed to merge into this branch; its approvals and status checks are not required. Protected files are
		// never bypassed.
		if ctx.opts.PullRequestID == 0 && ctx.opts.MergeForwardPRID != 0 && !changedProtectedfiles {
			return preReceiveMergeForwardStep(ctx, protectBranch, oldCommitID, newCommitID, branchName)
		}

		// Is this is a merge from the UI/API?
		if ctx.opts.PullRequestID == 0 {
			// 6a. If we're not merging from the UI/API then there are two ways we got here:
			//
			// We are changing a protected file and we're not allowed to do that
			if changedProtectedfiles {
				log.Warn("Forbidden: Branch: %s in %-v is protected from changing file %s", branchName, repo, protectedFilePath)
				ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("branch %s is protected from changing file %s", branchName, protectedFilePath))
				return false
			}

			// Allow commits that only touch unprotected files
			globs := protectBranch.GetUnprotectedFilePatterns()
			if len(globs) > 0 {
				unprotectedFilesOnly, err := pull_service.CheckUnprotectedFiles(gitRepo, oldCommitID, newCommitID, globs, ctx.env)
				if err != nil {
					log.Error("Unable to check file protection for commits from %s to %s in %-v: %v", oldCommitID, newCommitID, repo, err)
					ctx.JSON(http.StatusInternalServerError, private.Response{
						Err: fmt.Sprintf("Unable to check file protection for commits from %s to %s: %v", oldCommitID, newCommitID, err),
					})
					return false
				}
				if unprotectedFilesOnly {
					// Commit only touches unprotected files, this is allowed
					return true
				}
			}

			// Or we're simply not able to push to this protected branch
			log.Warn("Forbidden: User %d is not allowed to push to protected branch: %s in %-v", ctx.opts.UserID, branchName, repo)
			ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("Not allowed to push to protected branch %s", branchName))
			return false
		}
		// 6b. Merge (from UI or API)

		// Get the PR, user and permissions for the user in the repository
		pr, err := issues_model.GetPullRequestByID(ctx, ctx.opts.PullRequestID)
		if err != nil {
			log.Error("Unable to get PullRequest %d Error: %v", ctx.opts.PullRequestID, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to get PullRequest %d Error: %v", ctx.opts.PullRequestID, err),
			})
			return false
		}

		// although we should have called `loadPusherAndPermission` before, here we call it explicitly again because we need to access ctx.user below
		if !ctx.loadPusherAndPermission() {
			// if error occurs, loadPusherAndPermission had written the error response
			return false
		}

		// Now check if the user is allowed to merge PRs for this repository
		// Note: we can use ctx.perm and ctx.user directly as they will have been loaded above
		allowedMerge, err := pull_service.IsUserAllowedToMerge(ctx, pr, ctx.userPerm, ctx.user)
		if err != nil {
			log.Error("Error calculating if allowed to merge: %v", err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Error calculating if allowed to merge: %v", err),
			})
			return false
		}

		if !allowedMerge {
			log.Warn("Forbidden: User %d is not allowed to push to protected branch: %s in %-v and is not allowed to merge pr #%d", ctx.opts.UserID, branchName, repo, pr.Index)
			ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("Not allowed to push to protected branch %s", branchName))
			return false
		}

		// a merge queue entry an admin added without force gets no admin exemption, as when the queue checked it
		noExempt := false
		if ctx.opts.PushTrigger == repo_module.PushTriggerMergeQueue {
			e, err := pull_model.GetMergeQueueEntryByPullID(ctx, pr.ID)
			if err != nil {
				log.Error("GetMergeQueueEntryByPullID: %v", err)
				ctx.JSON(http.StatusInternalServerError, private.Response{Err: "GetMergeQueueEntryByPullID failed"})
				return false
			}
			noExempt = e == nil || !e.Forced
		}

		// If we're an admin for the instance, we can ignore checks
		if ctx.user.IsAdmin && !noExempt {
			return true
		}

		// The rule may be skipped by admins if it doesn't apply to them: repository admins for a
		// repository rule, organization owners for an organization rule.
		exempt := func(pb *git_model.ProtectedBranch) bool {
			if noExempt {
				return false
			}
			ok, err := pb.IsAdminExempt(ctx, ctx.user, ctx.userPerm.IsAdmin())
			if err != nil {
				log.Error("IsAdminExempt: %v", err)
			}
			return ok
		}

		// It's not allowed t overwrite protected files. Unless if the user is an
		// admin and the protected branch rule doesn't apply to admins.
		if changedProtectedfiles && !exempt(protectBranch) {
			log.Warn("Forbidden: Branch: %s in %-v is protected from changing file %s", branchName, repo, protectedFilePath)
			ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("branch %s is protected from changing file %s", branchName, protectedFilePath))
			return false
		}

		// Check all status checks and reviews are ok
		if _, err := pull_service.CheckPullBranchProtections(ctx, pr, true, exempt); err != nil {
			if models.IsErrDisallowedToMerge(err) {
				log.Warn("Forbidden: User %d is not allowed push to protected branch %s in %-v and pr #%d is not ready to be merged: %s", ctx.opts.UserID, branchName, repo, pr.Index, err.Error())
				ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("Not allowed to push to protected branch %s and pr #%d is not ready to be merged: %s", branchName, ctx.opts.PullRequestID, err.Error()))
				return false
			}
			log.Error("Unable to check if mergeable: protected branch %s in %-v and pr #%d. Error: %v", ctx.opts.UserID, branchName, repo, pr.Index, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to get status of pull request %d. Error: %v", ctx.opts.PullRequestID, err),
			})
			return false
		}
	}
	return true
}

func preReceiveMergeForwardStep(ctx *preReceiveContext, protectBranch *git_model.ProtectedBranch, oldCommitID, newCommitID, branchName string) bool {
	repo := ctx.Repo.Repository
	if !ctx.loadPusherAndPermission() {
		return false
	}
	allowed, err := mergeforward.AllowsStep(ctx, repo, ctx.opts.MergeForwardPRID, ctx.user, branchName, oldCommitID, newCommitID, ctx.env)
	if err != nil {
		log.Error("Unable to check the merge forward step of pull request %d into %s in %-v: %v", ctx.opts.MergeForwardPRID, branchName, repo, err)
		ctx.JSON(http.StatusInternalServerError, private.Response{Err: fmt.Sprintf("Unable to check the merge forward step: %v", err)})
		return false
	}
	if !allowed || !git_model.IsUserMergeWhitelisted(ctx, protectBranch, ctx.user.ID, ctx.userPerm) {
		log.Warn("Forbidden: User %d is not allowed to merge forward into protected branch: %s in %-v", ctx.opts.UserID, branchName, repo)
		ctx.refuse(http.StatusForbidden, "protected_branch", git.BranchPrefix+branchName, fmt.Sprintf("Not allowed to push to protected branch %s", branchName))
		return false
	}
	return true
}

func preReceiveTag(ctx *preReceiveContext, oldCommitID, newCommitID string, refFullName git.RefName) {
	if !ctx.assertCanWriteCode() {
		return
	}

	tagName := refFullName.TagName()

	if oldCommitID == ctx.Repo.GetObjectFormat().EmptyObjectID().String() && git.IsReservedRefName(tagName) {
		ctx.refuse(http.StatusForbidden, "reserved_name", refFullName.String(), fmt.Sprintf("tag name %s is reserved", tagName))
		return
	}

	if !ctx.gotProtectedTags {
		var err error
		ctx.protectedTags, err = git_model.GetProtectedTags(ctx, ctx.Repo.Repository.ID)
		if err != nil {
			log.Error("Unable to get protected tags for %-v Error: %v", ctx.Repo.Repository, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: err.Error(),
			})
			return
		}
		ctx.gotProtectedTags = true
	}

	var isAllowed bool
	var err error
	if ctx.opts.DeployKeyKeyID != 0 {
		// ctx.opts.UserID is the repository owner for deploy keys, so only the key itself decides.
		isAllowed, err = git_model.IsDeployKeyAllowedToControlTag(ctx.protectedTags, tagName, ctx.deployKeyKeyID)
	} else {
		isAllowed, err = git_model.IsUserAllowedToControlTag(ctx, ctx.protectedTags, tagName, ctx.opts.UserID)
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, private.Response{
			Err: err.Error(),
		})
		return
	}
	if !isAllowed {
		log.Warn("Forbidden: Tag %s in %-v is protected", tagName, ctx.Repo.Repository)
		ctx.refuse(http.StatusForbidden, "protected_tag", refFullName.String(), fmt.Sprintf("Tag %s is protected", tagName))
		return
	}

	// If the user is over quota, and the push isn't a tag deletion, deny it
	if ctx.isOverQuota {
		objectFormat := ctx.Repo.GetObjectFormat()
		if newCommitID != objectFormat.EmptyObjectID().String() {
			ctx.quotaExceeded()
			return
		}
	}
}

func preReceiveFor(ctx *preReceiveContext, oldCommitID, newCommitID string, refFullName git.RefName) { //nolint:unparam
	if !ctx.AssertCreatePullRequest() {
		return
	}

	if ctx.Repo.Repository.IsEmpty {
		ctx.JSON(http.StatusForbidden, private.Response{
			UserMsg: "Can't create pull request for an empty repository.",
		})
		return
	}

	if ctx.opts.IsWiki {
		ctx.JSON(http.StatusForbidden, private.Response{
			UserMsg: "Pull requests are not supported on the wiki.",
		})
		return
	}

	baseBranchName := refFullName.ForBranchName()

	baseBranchExist := ctx.Repo.GitRepo.IsBranchExist(baseBranchName)

	if !baseBranchExist {
		for p, v := range baseBranchName {
			if v == '/' && ctx.Repo.GitRepo.IsBranchExist(baseBranchName[:p]) && p != len(baseBranchName)-1 {
				baseBranchExist = true
				break
			}
		}
	}

	if !baseBranchExist {
		ctx.JSON(http.StatusForbidden, private.Response{
			UserMsg: fmt.Sprintf("Unexpected ref: %s", refFullName),
		})
		return
	}
}

func preReceivePull(ctx *preReceiveContext, oldCommitID, newCommitID string, refFullName git.RefName) { //nolint:unparam
	pullIndex, _ := strconv.ParseInt(refFullName.PullName(), 10, 64)
	if pullIndex <= 0 {
		ctx.JSON(http.StatusForbidden, private.Response{
			UserMsg: fmt.Sprintf("Invalid ref: %s", refFullName),
		})
		return
	}

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo.Repository.ID, pullIndex)
	if err != nil {
		ctx.JSON(http.StatusForbidden, private.Response{
			UserMsg: fmt.Sprintf("Unable to get pull request %d", pullIndex),
		})
		return
	}
	if pr.Flow != issues_model.PullRequestFlowAGit {
		userMsg := fmt.Sprintf("Only AGit pull-requests can be pushed via %s", refFullName)

		if pr.HeadRepoID == ctx.Repo.Repository.ID {
			userMsg += fmt.Sprintf("\nPush to branch %q instead", pr.HeadBranch)
		} else if pr.LoadHeadRepo(ctx) == nil {
			userMsg += "\nPush to the fork repo instead:"

			cloneLink := pr.HeadRepo.CloneLink()
			if !setting.Repository.DisableHTTPGit {
				userMsg += fmt.Sprintf("\n  git push %s HEAD:%s", cloneLink.HTTPS, pr.HeadBranch)
			}
			if !setting.SSH.Disabled {
				userMsg += fmt.Sprintf("\n  git push %s HEAD:%s", cloneLink.SSH, pr.HeadBranch)
			}
		}
		ctx.JSON(http.StatusForbidden, private.Response{
			UserMsg: userMsg,
		})
		return
	}

	// user must have repo write rights or be the PR creator
	if !ctx.canWriteCode() {
		if ctx.Written() {
			return
		}
		if ctx.user.ID != pr.Issue.PosterID {
			msg := fmt.Sprintf("User '%s' is not allowed to push to pull request %d of repository '%s/%s'.", ctx.user.Name, pr.Index, ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name)
			ctx.refuse(http.StatusForbidden, "permission", refFullName.String(), msg)
			return
		}
	}
}

func generateGitEnv(opts *private.HookOptions) (env []string) {
	env = os.Environ()
	if opts.GitAlternativeObjectDirectories != "" {
		env = append(env,
			private.GitAlternativeObjectDirectories+"="+opts.GitAlternativeObjectDirectories)
	}
	if opts.GitObjectDirectory != "" {
		env = append(env,
			private.GitObjectDirectory+"="+opts.GitObjectDirectory)
	}
	if opts.GitQuarantinePath != "" {
		env = append(env,
			private.GitQuarantinePath+"="+opts.GitQuarantinePath)
	}
	return env
}

// loadPusherAndPermission returns false if an error occurs, and it writes the error response
func (ctx *preReceiveContext) loadPusherAndPermission() bool {
	if ctx.loadedPusher {
		return true
	}

	if ctx.opts.DeployKeyKeyID != 0 {
		// A deploy key acts as itself: decided from the key and the repository as they are now, never from the
		// pusher ID, and without the owner's permission. The owner is only the name the push is recorded under.
		repo := ctx.Repo.Repository
		deployKey, err := asymkey_model.GetEffectiveDeployKey(ctx, ctx.opts.DeployKeyKeyID, repo)
		if err != nil && !asymkey_model.IsErrDeployKeyNotExist(err) {
			log.Error("Unable to get the deploy key of public key %d in %-v: %v", ctx.opts.DeployKeyKeyID, repo, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to get the deploy key of public key %d", ctx.opts.DeployKeyKeyID),
			})
			return false
		}
		if err != nil || deployKey.IsExpired() {
			ctx.refuse(http.StatusForbidden, "deploy_key", "", fmt.Sprintf("The deploy key is not authorized to push to %s/%s.", repo.OwnerName, repo.Name))
			return false
		}
		if err := repo.LoadOwner(ctx); err != nil {
			log.Error("Unable to load the owner of %-v: %v", repo, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to load the owner of %s/%s", repo.OwnerName, repo.Name),
			})
			return false
		}
		ctx.user = repo.Owner
		ctx.deployKeyAccessMode = deployKey.Mode
		ctx.deployKeyKeyID = deployKey.KeyID
		if ctx.pusherID, err = creditedPusher(ctx, deployKey.CreatorID); err != nil {
			log.Error("Unable to resolve the creator of deploy key %d: %v", deployKey.KeyID, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{Err: "Unable to resolve the creator of the deploy key"})
			return false
		}
	} else if ctx.opts.UserID == user_model.ActionsUserID {
		ctx.user = user_model.NewActionsUser()
		ctx.pusherID = noPusher
		// Without a task (a push made by the server as the Actions user), the Actions user may do nothing.
		if ctx.opts.ActionTaskID != 0 {
			task, err := actions_model.GetTaskByID(ctx, ctx.opts.ActionTaskID)
			if err == nil {
				ctx.userPerm, err = access_model.GetActionRepoPermission(ctx, ctx.Repo.Repository, task)
				ctx.actionTokenPermissions = task.TokenPermissions != ""
			}
			if err == nil {
				if err = task.LoadJob(ctx); err == nil {
					if err = task.Job.LoadRun(ctx); err == nil {
						ctx.pusherID, err = creditedPusher(ctx, task.Job.Run.TriggerUserID)
					}
				}
			}
			if err != nil {
				log.Error("Unable to get the permission of Actions task %d: %v", ctx.opts.ActionTaskID, err)
				ctx.JSON(http.StatusInternalServerError, private.Response{
					Err: fmt.Sprintf("Unable to get the permission of Actions task %d", ctx.opts.ActionTaskID),
				})
				return false
			}
		}
	} else {
		getUser := user_model.GetUserByID
		if user_model.IsAccessTokenBotID(ctx.opts.UserID) {
			getUser = user_model.GetAccessTokenBot
		}
		user, err := getUser(ctx, ctx.opts.UserID)
		// a token of an organization, a project or a repository revoked or expired since the push was authenticated
		if user_model.IsAccessTokenBotID(ctx.opts.UserID) && (user_model.IsErrUserNotExist(err) || err == nil && !user.BotToken.IsUsable()) {
			ctx.refuse(http.StatusForbidden, "permission", "", "The access token is no longer valid.")
			return false
		}
		if err != nil {
			log.Error("Unable to get User id %d Error: %v", ctx.opts.UserID, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to get User id %d Error: %v", ctx.opts.UserID, err),
			})
			return false
		}
		ctx.user = user
		ctx.pusherID = user.ID
		if user.IsAccessTokenBot() {
			var err error
			if ctx.pusherID, err = creditedPusher(ctx, user.ID); err != nil {
				log.Error("Unable to resolve the creator of token %d: %v", user.ID, err)
				ctx.JSON(http.StatusInternalServerError, private.Response{Err: "Unable to resolve the creator of the token"})
				return false
			}
		}
		userPerm, err := access_model.GetUserRepoPermission(ctx, ctx.Repo.Repository, user)
		if err != nil {
			log.Error("Unable to get Repo permission of repo %s/%s of User %s: %v", ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name, user.Name, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{
				Err: fmt.Sprintf("Unable to get Repo permission of repo %s/%s of User %s: %v", ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name, user.Name, err),
			})
			return false
		}
		ctx.userPerm = userPerm
	}

	ctx.loadedPusher = true
	return true
}
