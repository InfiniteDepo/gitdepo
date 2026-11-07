// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	timeutil "forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/branchworkflow"
	app_context "forgejo.org/services/context"
	repo_service "forgejo.org/services/repository"
	secretscan_service "forgejo.org/services/secretscan"
)

// hookPusherID is the person who pushed: a deploy key or an Actions task pushes under the repository owner's or the
// Actions user's ID, which names nobody who pushed.
func hookPusherID(opts *private.HookOptions) int64 {
	if opts.DeployKeyKeyID != 0 || opts.ActionTaskID != 0 {
		return 0
	}
	return opts.UserID
}

// HookPostReceive updates services and users
func HookPostReceive(ctx *app_context.PrivateContext) {
	opts := web.GetForm(ctx).(*private.HookOptions)

	// We don't rely on RepoAssignment here because:
	// a) we don't need the git repo in this function
	//    OUT OF DATE: we do need the git repo to sync the branch to the db now.
	// b) our update function will likely change the repository in the db so we will need to refresh it
	// c) we don't always need the repo

	repoID := ctx.ParamsInt64(":repoid")

	// a wiki push is measured again, for the size limit of personal repositories, and scanned for secrets (no feeds for wikis)
	if opts.IsWiki {
		repo := loadRepository(ctx)
		if ctx.Written() {
			return
		}
		if err := repo_module.UpdateRepoSize(ctx, repo); err != nil {
			log.Error("UpdateRepoSize after a wiki push to %-v: %v", repo, err)
		}
		if slices.ContainsFunc(opts.NewCommitIDs, func(id string) bool { return !git.IsEmptyCommitID(id, nil) }) { // not only deletions
			secretscan_service.MarkPush(ctx, repo, hookPusherID(opts), secretscan_model.KindWiki, "", "")
		}
		secretscan_service.EnqueueIfEnabled(ctx, repo)
		ctx.JSON(http.StatusOK, private.HookPostReceiveResult{})
		return
	}

	// defer getting the repository at this point - as we should only retrieve it if we're going to call update
	var repo *repo_model.Repository

	updates := make([]*repo_module.PushUpdateOptions, 0, len(opts.OldCommitIDs))
	wasEmpty := false

	for i := range opts.OldCommitIDs {
		refFullName := opts.RefFullNames[i]

		// Only trigger activity updates for changes to branches or
		// tags.  Updates to other refs (eg, refs/notes, refs/changes,
		// or other less-standard refs spaces are ignored since there
		// may be a very large number of them).
		if refFullName.IsBranch() || refFullName.IsTag() {
			if repo == nil {
				repo = loadRepository(ctx)
				if ctx.Written() {
					// Error handled in loadRepository
					return
				}
				wasEmpty = repo.IsEmpty
			}

			option := &repo_module.PushUpdateOptions{
				RefFullName:  refFullName,
				OldCommitID:  opts.OldCommitIDs[i],
				NewCommitID:  opts.NewCommitIDs[i],
				PusherID:     opts.UserID,
				PusherName:   opts.UserName,
				RepoID:       repo.ID,
				RepoUserName: repo.OwnerName,
				RepoName:     repo.Name,
				TimeNano:     time.Now().UnixNano(),
			}
			updates = append(updates, option)
			if repo.IsEmpty && (refFullName.BranchName() == "master" || refFullName.BranchName() == "main") {
				// put the master/main branch first
				// FIXME: It doesn't always work, since the master/main branch may not be the first batch of updates.
				//        If the user pushes many branches at once, the Git hook will call the internal API in batches, rather than all at once.
				//        See https://github.com/go-gitea/gitea/blob/cb52b17f92e2d2293f7c003649743464492bca48/cmd/hook.go#L27
				//        If the user executes `git push origin --all` and pushes more than 30 branches, the master/main may not be the default branch.
				copy(updates[1:], updates)
				updates[0] = option
			}
		}
	}

	if repo != nil && len(updates) > 0 {
		branchesToSync := make([]*repo_module.PushUpdateOptions, 0, len(updates))
		for _, update := range updates {
			if !update.RefFullName.IsBranch() {
				continue
			}
			if repo == nil {
				repo = loadRepository(ctx)
				if ctx.Written() {
					return
				}
				wasEmpty = repo.IsEmpty
			}

			if update.IsDelRef() {
				if err := git_model.AddDeletedBranch(ctx, repo.ID, update.RefFullName.BranchName(), update.PusherID); err != nil {
					log.Error("Failed to add deleted branch: %d Error: %v", repoID, err)
					ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
						Err: fmt.Sprintf("Failed to add deleted branch: %d Error: %v", repoID, err),
					})
					return
				}
			} else {
				branchesToSync = append(branchesToSync, update)
			}
		}
		if len(branchesToSync) > 0 {
			gitRepo, err := gitrepo.OpenRepository(ctx, repo)
			if err != nil {
				log.Error("Failed to open repository: %d Error: %v", repoID, err)
				ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
					Err: fmt.Sprintf("Failed to open repository: %d Error: %v", repoID, err),
				})
				return
			}

			var (
				branchNames = make([]string, 0, len(branchesToSync))
				commitIDs   = make([]string, 0, len(branchesToSync))
			)
			for _, update := range branchesToSync {
				branchNames = append(branchNames, update.RefFullName.BranchName())
				commitIDs = append(commitIDs, update.NewCommitID)
			}

			err = repo_service.SyncBranchesToDB(ctx, repo.ID, opts.UserID, branchNames, commitIDs, gitRepo.GetCommit)
			gitRepo.Close()
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
					Err: fmt.Sprintf("Failed to sync branch to DB in repository: %d Error: %v", repoID, err),
				})
				return
			}
		}

		for _, u := range updates { // the digest names the first ref that isn't a deletion
			if !u.IsDelRef() {
				secretscan_service.MarkPush(ctx, repo, hookPusherID(opts), secretscan_model.KindRepo, u.RefFullName.ShortName(), u.NewCommitID)
				break
			}
		}
		if err := repo_service.PushUpdates(updates); err != nil {
			log.Error("Failed to Update: %d Total Updates: %d", repoID, len(updates))
			for i, update := range updates {
				log.Error("Failed to Update: %d Update: %d/%d: Branch: %s", repoID, i, len(updates), update.RefFullName.BranchName())
			}
			log.Error("Failed to Update: %d Error: %v", repoID, err)

			ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
				Err: fmt.Sprintf("Failed to Update: %d Error: %v", repoID, err),
			})
			return
		}
	}

	// handle pull request merging, a pull request action should push at least 1 commit
	if opts.PushTrigger == repo_module.PushTriggerPRMergeToBase || opts.PushTrigger == repo_module.PushTriggerMergeQueue {
		handlePullRequestMerging(ctx, opts, repoID, updates)
		if ctx.Written() {
			return
		}
	}

	// Handle Push Options
	if !opts.GetGitPushOptions().Empty() {
		// load the repository
		if repo == nil {
			repo = loadRepository(ctx)
			if ctx.Written() {
				// Error handled in loadRepository
				return
			}
			wasEmpty = repo.IsEmpty
		}

		if err := repo_service.UpdateRepositoryFromPushOptions(pusherActor(ctx, opts.UserID), repoID, opts.GetGitPushOptions()); err != nil {
			log.Error("Failed to Update: %d Error: %v", repoID, err)
			ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
				Err: fmt.Sprintf("Failed to Update: %d Error: %v", repoID, err),
			})
			return
		}
	}

	results := make([]private.HookPostReceiveBranchResult, 0, len(opts.OldCommitIDs))

	// We have to reload the repo in case its state is changed above
	repo = nil
	var baseRepo *repo_model.Repository
	var baseReadable *bool
	var baseModel branchworkflow.EffectiveModel
	var err error

	// Now handle the pull request notification trailers
	for i := range opts.OldCommitIDs {
		refFullName := opts.RefFullNames[i]
		newCommitID := opts.NewCommitIDs[i]

		// post update for agit pull request
		// FIXME: use pr.Flow to test whether it's an Agit PR or a GH PR
		if refFullName.IsPull() {
			if repo == nil {
				repo = loadRepository(ctx)
				if ctx.Written() {
					return
				}
			}

			pullIndex, _ := strconv.ParseInt(refFullName.PullName(), 10, 64)
			if pullIndex <= 0 {
				continue
			}

			pr, err := issues_model.GetPullRequestByIndex(ctx, repo.ID, pullIndex)
			if err != nil && !issues_model.IsErrPullRequestNotExist(err) {
				log.Error("Failed to get PR by index %v Error: %v", pullIndex, err)
				ctx.JSON(http.StatusInternalServerError, private.Response{
					Err: fmt.Sprintf("Failed to get PR by index %v Error: %v", pullIndex, err),
				})
				return
			}
			if pr == nil {
				continue
			}

			results = append(results, private.HookPostReceiveBranchResult{
				Message:   setting.Git.PullRequestPushMessage && repo.AllowsPulls(ctx),
				Create:    false,
				Branch:    "",
				CreateURL: "",
				PullURLS:  []string{fmt.Sprintf("%s/pulls/%d", repo.HTMLURL(), pr.Index)},
			})
			continue
		}

		// If we've pushed a branch (and not deleted it)
		if !git.IsEmptyCommitID(newCommitID, nil) && refFullName.IsBranch() {
			// First ensure we have the repository loaded, we're allowed pulls requests and we can get the base repo
			if repo == nil {
				repo = loadRepository(ctx)
				if ctx.Written() {
					return
				}

				baseRepo = repo

				if repo.IsFork {
					if err := repo.GetBaseRepo(ctx); err != nil {
						log.Error("Failed to get Base Repository of Forked repository: %-v Error: %v", repo, err)
						ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
							Err:          fmt.Sprintf("Failed to get Base Repository of Forked repository: %-v Error: %v", repo, err),
							RepoWasEmpty: wasEmpty,
						})
						return
					}
					if repo.BaseRepo != nil && repo.BaseRepo.AllowsPulls(ctx) {
						baseRepo = repo.BaseRepo
					}
				}

				if !baseRepo.AllowsPulls(ctx) {
					// We can stop there's no need to go any further
					ctx.JSON(http.StatusOK, private.HookPostReceiveResult{
						RepoWasEmpty: wasEmpty,
					})
					return
				}
			}

			branch := refFullName.BranchName()

			// The branching model of the base repository chooses the branch the pull request would target
			// (only for a pusher who can read it: a fork's pusher may have lost access to the repository it was forked from)
			if baseReadable == nil {
				readable := repo.ID == baseRepo.ID || (opts.DeployKeyKeyID == 0 && opts.ActionTaskID == 0 && pusherCanReadCode(ctx, baseRepo, opts.UserID))
				baseReadable = &readable
				if readable {
					if baseModel, err = branchworkflow.GetEffectiveModel(ctx, baseRepo); err != nil {
						// the suggestion is cosmetic: an unreadable model must not fail every push
						log.Error("Failed to read the branching model of %-v, suggesting the default branch: %v", baseRepo, err)
						baseModel, *baseReadable = branchworkflow.EffectiveModel{}, false
					}
				}
			}
			target := branchworkflow.Target{Branch: baseRepo.DefaultBranch, Rule: branchworkflow.TargetRuleDefault}
			var err error
			if *baseReadable {
				target, err = branchworkflow.ResolveTargetWith(ctx, baseRepo, baseModel, branch)
			}
			if err != nil {
				log.Error("Failed to resolve the pull request target of %-v branch %s: %v", baseRepo, branch, err)
				ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
					Err:          fmt.Sprintf("Failed to resolve the pull request target of %-v branch %s: %v", baseRepo, branch, err),
					RepoWasEmpty: wasEmpty,
				})
				return
			}

			// If our branch is the default branch of an unforked repo - there's no PR to create or refer to
			if !repo.IsFork && (branch == baseRepo.DefaultBranch || branch == target.Branch) {
				results = append(results, private.HookPostReceiveBranchResult{})
				continue
			}

			// Check if there is an existing pull request for this branch.
			prList, err := issues_model.GetUnmergedPullRequestsAnyTarget(ctx, repo.ID, baseRepo.ID, branch, issues_model.PullRequestFlowGithub)
			if err != nil {
				log.Error("Failed to get active PR in: %-v Branch: %s to: %-v Error: %v", repo, branch, baseRepo, err)
				ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
					Err: fmt.Sprintf(
						"Failed to get active PR in: %-v Branch: %s to: %-v Error: %v", repo, branch, baseRepo, err,
					),
					RepoWasEmpty: wasEmpty,
				})
				return
			}
			err = prList.LoadRepositories(ctx)
			if err != nil {
				log.Error("Failed to load repositories for PullRequestList: %s", err)
				ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
					Err:          fmt.Sprintf("Failed to load repositories for PullRequestList: %s", err),
					RepoWasEmpty: wasEmpty,
				})
				return
			}

			if repo.IsFork {
				branch = fmt.Sprintf("%s:%s", repo.OwnerName, branch)
			}
			createURL := fmt.Sprintf("%s/compare/%s...%s", baseRepo.HTMLURL(), util.PathEscapeSegments(target.Branch), util.PathEscapeSegments(branch))
			var urls []string
			foundDefaultBranch := false
			for _, pr := range prList {
				var baseBranchDisplay string
				if pr.HeadRepoID == pr.BaseRepoID {
					// Inside the same repository: just show base branch name
					baseBranchDisplay = pr.BaseBranch
				} else {
					// We are merging this into another repo: display user/repo:branch
					baseBranchDisplay = fmt.Sprintf("%s:%s", pr.BaseRepo.FullName(), pr.BaseBranch)
				}
				urls = append(urls, fmt.Sprintf("%s/pulls/%d merges into %s", baseRepo.HTMLURL(), pr.Index, baseBranchDisplay))
				if pr.BaseBranch == target.Branch {
					foundDefaultBranch = true
				}
			}
			if foundDefaultBranch {
				createURL = ""
			}
			results = append(results, private.HookPostReceiveBranchResult{
				Message:   setting.Git.PullRequestPushMessage && baseRepo.AllowsPulls(ctx),
				Create:    !foundDefaultBranch,
				Branch:    branch,
				CreateURL: createURL,
				PullURLS:  urls,
			})
		}
	}
	ctx.JSON(http.StatusOK, private.HookPostReceiveResult{
		Results:      results,
		RepoWasEmpty: wasEmpty,
	})
}

func loadContextCacheUser(ctx context.Context, id int64) (*user_model.User, error) {
	return cache.GetWithContextCache(ctx, "hook_post_receive_user", id, func() (*user_model.User, error) {
		return user_model.GetUserByID(ctx, id)
	})
}

// handlePullRequestMerging handle pull request merging, a pull request action should push at least 1 commit
func handlePullRequestMerging(ctx *app_context.PrivateContext, opts *private.HookOptions, repoID int64, updates []*repo_module.PushUpdateOptions) {
	if len(updates) == 0 {
		ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{
			Err: fmt.Sprintf("Pushing a merged PR (pr:%d) no commits pushed ", opts.PullRequestID),
		})
		return
	}

	pr, err := issues_model.GetPullRequestByID(ctx, opts.PullRequestID)
	if err != nil {
		log.Error("GetPullRequestByID[%d]: %v", opts.PullRequestID, err)
		ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{Err: "GetPullRequestByID failed"})
		return
	}

	pusher, err := loadContextCacheUser(ctx, opts.UserID)
	if err != nil {
		log.Error("Failed to Update: %d Error: %v", repoID, err)
		ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{Err: "Load pusher user failed"})
		return
	}

	pr.MergedCommitID = updates[len(updates)-1].NewCommitID
	pr.MergedBaseCommitID = updates[len(updates)-1].OldCommitID
	pr.MergedUnix = timeutil.TimeStampNow()
	pr.Merger = pusher
	pr.MergerID = pusher.ID
	err = db.WithTx(ctx, func(ctx context.Context) error {
		// Removing an auto merge pull and ignore if not exist
		if err := pull_model.DeleteScheduledAutoMerge(ctx, pr.ID); err != nil && !db.IsErrNotExist(err) {
			return fmt.Errorf("DeleteScheduledAutoMerge[%d]: %v", opts.PullRequestID, err)
		}
		if _, err := pr.SetMerged(ctx); err != nil {
			return fmt.Errorf("SetMerged failed: %d Error: %v", repoID, err)
		}
		return nil
	})
	if err != nil {
		log.Error("Failed to update PR to merged: %v", err)
		ctx.JSON(http.StatusInternalServerError, private.HookPostReceiveResult{Err: "Failed to update PR to merged"})
	}
}

// pusherActor is ctx with the pusher userID, read from the user row, as the audit actor; the request ID stays.
func pusherActor(ctx *app_context.PrivateContext, userID int64) context.Context {
	a := &audit_model.Actor{Type: audit_model.ActorUser, ID: userID}
	if outer := audit_model.ActorFromContext(ctx); outer != nil {
		a.RequestID = outer.RequestID
	}
	if u, err := user_model.GetPossibleUserByID(ctx, userID); err == nil {
		a.Name = u.Name
	}
	return audit_model.WithActor(ctx, a)
}

// pusherCanReadCode tells if the user may read the code of repo; an unknown user can't.
func pusherCanReadCode(ctx *app_context.PrivateContext, repo *repo_model.Repository, userID int64) bool {
	user, err := loadContextCacheUser(ctx, userID)
	if err != nil {
		return false
	}
	perm, err := access_model.GetUserRepoPermission(ctx, repo, user)
	return err == nil && perm.CanRead(unit.TypeCode)
}
