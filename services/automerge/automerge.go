// Copyright 2021 Gitea. All rights reserved.
// SPDX-License-Identifier: MIT

package automerge

import (
	"context"
	"errors"
	"fmt"

	"forgejo.org/models"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/log"
	"forgejo.org/modules/process"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/mergequeue"
	notify_service "forgejo.org/services/notify"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
	shared_automerge "forgejo.org/services/shared/automerge"
)

// Init runs the task queue to that handles auto merges
func Init() error {
	notify_service.RegisterNotifier(NewNotifier())

	shared_automerge.PRAutoMergeQueue = queue.CreateUniqueQueue(graceful.GetManager().ShutdownContext(), "pr_auto_merge", handler)
	if shared_automerge.PRAutoMergeQueue == nil {
		return errors.New("unable to create pr_auto_merge queue")
	}
	go graceful.GetManager().RunWithCancel(shared_automerge.PRAutoMergeQueue)
	return nil
}

// handle passed PR IDs and test the PRs
func handler(items ...string) []string {
	// the queue retries unhandled items, so auto merges wait while maintenance mode is on
	if setting.GetMaintenance(graceful.GetManager().ShutdownContext()).ReadOnly() {
		return items
	}
	for _, s := range items {
		var id int64
		var sha string
		if _, err := fmt.Sscanf(s, "%d_%s", &id, &sha); err != nil {
			log.Error("could not parse data from pr_auto_merge queue (%v): %v", s, err)
			continue
		}
		handlePullRequestAutoMerge(id, sha)
	}
	return nil
}

// ScheduleAutoMerge if schedule is false and no error, pull can be merged directly.
// A merge scheduled for a later time is pinned to the current head, so commits pushed before that time are not merged.
// A ctx from pull_service.WithoutMergeForward stores that the merge is not merged forward.
func ScheduleAutoMerge(ctx context.Context, doer *user_model.User, pull *issues_model.PullRequest, style repo_model.MergeStyle, message string, deleteBranch bool, scheduledAfter, giveUpAfter timeutil.TimeStamp, expectedHeadCommitID string) (scheduled bool, err error) {
	var headCommitID string
	if scheduledAfter != 0 {
		if err := pull.LoadBaseRepo(ctx); err != nil {
			return false, err
		}
		gitRepo, err := gitrepo.OpenRepository(ctx, pull.BaseRepo)
		if err != nil {
			return false, err
		}
		defer gitRepo.Close()
		if headCommitID, err = gitRepo.GetRefCommitID(pull.GetGitRefName()); err != nil {
			return false, err
		}
		if expectedHeadCommitID != "" && expectedHeadCommitID != headCommitID {
			return false, models.ErrSHADoesNotMatch{GivenSHA: expectedHeadCommitID, CurrentSHA: headCommitID}
		}
	}

	err = db.WithTx(ctx, func(ctx context.Context) error {
		if err := pull_model.ScheduleAutoMerge(ctx, doer, pull.ID, style, message, deleteBranch, scheduledAfter, giveUpAfter, headCommitID, pull_service.MergeForwardSkipped(ctx)); err != nil {
			return err
		}
		scheduled = true

		_, err = issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRScheduledToAutoMerge, pull, doer, issues_model.AutoMergeInfo{After: int64(scheduledAfter), GiveUp: int64(giveUpAfter)})
		return err
	})
	return scheduled, err
}

// ChangeScheduledAutoMerge changes the time of the scheduled merge of pull. Who may do it is the same as for cancelling;
// the user who scheduled it, the merge style, message, branch deletion and pinned head stay.
func ChangeScheduledAutoMerge(ctx context.Context, doer *user_model.User, pull *issues_model.PullRequest, repoPerms access_model.Permission, scheduledAfter, giveUpAfter timeutil.TimeStamp) error {
	exist, autoMerge, err := pull_model.GetScheduledMergeByPullID(ctx, pull.ID)
	if err != nil {
		return err
	}
	if !exist {
		return db.ErrNotExist{Resource: "auto_merge", ID: pull.ID}
	}
	if err := checkMayChangeAutoMerge(ctx, doer, pull, repoPerms, autoMerge); err != nil {
		return err
	}

	var headCommitID string
	if autoMerge.HeadCommitID == "" {
		if err := pull.LoadBaseRepo(ctx); err != nil {
			return err
		}
		gitRepo, err := gitrepo.OpenRepository(ctx, pull.BaseRepo)
		if err != nil {
			return err
		}
		defer gitRepo.Close()
		if headCommitID, err = gitRepo.GetRefCommitID(pull.GetGitRefName()); err != nil {
			return err
		}
	}

	return db.WithTx(ctx, func(ctx context.Context) error {
		if changed, err := pull_model.ChangeAutoMergeTime(ctx, autoMerge, scheduledAfter, giveUpAfter, headCommitID); err != nil {
			return err
		} else if !changed {
			return db.ErrNotExist{Resource: "auto_merge", ID: pull.ID}
		}
		_, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRAutoMergeTimeChanged, pull, doer, issues_model.AutoMergeInfo{
			Old: int64(autoMerge.ScheduledAfterUnix), New: int64(scheduledAfter), GiveUp: int64(giveUpAfter),
		})
		return err
	})
}

// checkMayChangeAutoMerge allows the user who scheduled the merge and everyone who may merge the pull request
func checkMayChangeAutoMerge(ctx context.Context, doer *user_model.User, pull *issues_model.PullRequest, repoPerms access_model.Permission, autoMerge *pull_model.AutoMerge) error {
	if doer.ID == autoMerge.DoerID {
		return nil
	}
	allowed, err := pull_service.IsUserAllowedToMerge(ctx, pull, repoPerms, doer)
	if err != nil {
		return err
	}
	if !allowed {
		return util.ErrPermissionDenied
	}
	return nil
}

// RemoveScheduledAutoMerge cancels a previously scheduled pull request
func RemoveScheduledAutoMerge(ctx context.Context, doer *user_model.User, pull *issues_model.PullRequest, repoPerms access_model.Permission) error {
	exist, autoMerge, err := pull_model.GetScheduledMergeByPullID(ctx, pull.ID)
	if err != nil {
		return err
	}
	if !exist {
		return db.ErrNotExist{Resource: "auto_merge", ID: pull.ID}
	}

	if err := checkMayChangeAutoMerge(ctx, doer, pull, repoPerms, autoMerge); err != nil {
		return err
	}

	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := pull_model.DeleteScheduledAutoMerge(ctx, pull.ID); err != nil {
			return err
		}

		_, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRUnScheduledToAutoMerge, pull, doer, issues_model.AutoMergeInfo{})
		return err
	})
}

// StartDueScheduledAutoMerges cancels the scheduled merges whose deadline has passed, then turns the ones that are due
// into normal auto merges and checks them now
func StartDueScheduledAutoMerges(ctx context.Context) error {
	now := timeutil.TimeStampNow()
	// cancel first, so a merge whose time and deadline have both passed is cancelled, not started
	expired, err := pull_model.TakeExpiredScheduledAutoMerges(ctx, now)
	if err != nil {
		return err
	}
	for _, am := range expired {
		pr, err := issues_model.GetPullRequestByID(ctx, am.PullID)
		if err != nil {
			log.Error("GetPullRequestByID[%d]: %v", am.PullID, err)
			continue
		}
		doer, err := user_model.GetPossibleUserByID(ctx, am.DoerID)
		if user_model.IsErrUserNotExist(err) {
			doer = user_model.NewGhostUser()
		} else if err != nil {
			log.Error("GetPossibleUserByID[%d]: %v", am.DoerID, err)
			continue
		}
		if _, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRUnScheduledToAutoMerge, pr, doer, issues_model.AutoMergeInfo{Reason: "give_up"}); err != nil {
			log.Error("CreateAutoMergeComment[%d]: %v", pr.ID, err)
		}
	}

	pullIDs, err := pull_model.TakeDueScheduledAutoMerges(ctx, now)
	if err != nil {
		return err
	}
	for _, id := range pullIDs {
		pr, err := issues_model.GetPullRequestByID(ctx, id)
		if err != nil {
			log.Error("GetPullRequestByID[%d]: %v", id, err)
			continue
		}
		StartPRCheckAndAutoMerge(ctx, pr)
	}
	return nil
}

// skipAutoMerge records in the timeline why the scheduled merge of pr cannot go ahead, once per reason and head
func skipAutoMerge(ctx context.Context, pr *issues_model.PullRequest, am *pull_model.AutoMerge, reason, sha string) {
	info := issues_model.AutoMergeInfo{Reason: reason, SHA: sha}
	if err := pr.LoadIssue(ctx); err != nil {
		log.Error("%-v LoadIssue: %v", pr, err)
		return
	}
	if recorded, err := issues_model.IsAutoMergeSkipRecorded(ctx, pr.IssueID, info); err != nil || recorded {
		if err != nil {
			log.Error("%-v IsAutoMergeSkipRecorded: %v", pr, err)
		}
		return
	}
	if _, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRAutoMergeSkipped, pr, am.Doer, info); err != nil {
		log.Error("%-v CreateAutoMergeComment: %v", pr, err)
	}
}

// canStillMerge reports whether doer, who scheduled the auto merge of pr, may still merge it
func canStillMerge(ctx context.Context, pr *issues_model.PullRequest, doer *user_model.User) (access_model.Permission, bool, error) {
	if doer == nil || doer.ID <= 0 || !doer.IsActive || doer.ProhibitLogin {
		return access_model.Permission{}, false, nil
	}
	perm, err := access_model.GetUserRepoPermission(ctx, pr.BaseRepo, doer)
	if err != nil {
		return perm, false, err
	}
	allowed, err := pull_service.IsUserAllowedToMerge(ctx, pr, perm, doer)
	return perm, allowed, err
}

// cancelAutoMerge cancels an auto merge whose scheduler may no longer merge
func cancelAutoMerge(ctx context.Context, pr *issues_model.PullRequest, am *pull_model.AutoMerge) {
	log.Info("Cancelling the auto merge of %-v: %s may no longer merge it", pr, am.Doer.Name)
	if err := pull_service.CancelAutoMerge(ctx, pr, am, am.Doer, "permission"); err != nil {
		log.Error("%-v CancelAutoMerge: %v", pr, err)
	}
}

// StartPRCheckAndAutoMergeBySHA start an automerge check and auto merge task for all pull requests of repository and SHA
func StartPRCheckAndAutoMergeBySHA(ctx context.Context, sha string, repo *repo_model.Repository) error {
	return shared_automerge.StartPRCheckAndAutoMergeBySHA(ctx, sha, repo)
}

// StartPRCheckAndAutoMerge start an automerge check and auto merge task for a pull request
func StartPRCheckAndAutoMerge(ctx context.Context, pull *issues_model.PullRequest) {
	shared_automerge.StartPRCheckAndAutoMerge(ctx, pull)
}

// handlePullRequestAutoMerge merge the pull request if all checks are successful
func handlePullRequestAutoMerge(pullID int64, sha string) {
	ctx, _, finished := process.GetManager().AddContext(graceful.GetManager().HammerContext(),
		fmt.Sprintf("Handle AutoMerge of PR[%d] with sha[%s]", pullID, sha))
	defer finished()
	// one pass is one request: the head of the pull request is read once for the checks and the merge
	ctx = cache.WithCacheContext(ctx)

	pr, err := issues_model.GetPullRequestByID(ctx, pullID)
	if err != nil {
		log.Error("GetPullRequestByID[%d]: %v", pullID, err)
		return
	}

	// Check if there is a scheduled pr in the db
	exists, scheduledPRM, err := pull_model.GetScheduledMergeByPullID(ctx, pr.ID)
	if err != nil {
		log.Error("%-v GetScheduledMergeByPullID: %v", pr, err)
		return
	}
	if !exists {
		log.Trace("GetScheduledMergeByPullID found nothing for PR %d", pullID)
		return
	}
	if scheduledPRM.ScheduledAfterUnix > timeutil.TimeStampNow() {
		log.Trace("Scheduled auto merge %-v waits until %v", pr, scheduledPRM.ScheduledAfterUnix)
		return
	}
	if scheduledPRM.GiveUpAfterUnix > 0 && scheduledPRM.GiveUpAfterUnix <= timeutil.TimeStampNow() {
		log.Trace("Scheduled auto merge %-v gave up at %v", pr, scheduledPRM.GiveUpAfterUnix)
		return
	}

	if err = pr.LoadBaseRepo(ctx); err != nil {
		log.Error("%-v LoadBaseRepo: %v", pr, err)
		return
	}
	if pr.BaseRepo.IsArchived {
		log.Trace("Scheduled auto merge %-v waits: the repository is archived", pr)
		return
	}
	// the merge commit goes to the base repository, which the size limit of its owner's personal repositories
	// locks: wait, the merge happens on a later event once the usage is below the limit again
	if l, err := quota_model.GetPersonalRepoLimit(ctx, pr.BaseRepo.OwnerID); err != nil {
		log.Error("%-v GetPersonalRepoLimit: %v", pr, err)
		return
	} else if l.Reached() {
		log.Info("Scheduled auto merge %-v waits: the size limit of the owner's personal repositories is reached", pr)
		return
	}

	// cancel as soon as the user who scheduled it may no longer merge, even while checks are pending
	doer := scheduledPRM.Doer
	perm, allowed, err := canStillMerge(ctx, pr, doer)
	if err != nil {
		log.Error("%-v canStillMerge: %v", pr, err)
		return
	}
	if !allowed {
		cancelAutoMerge(ctx, pr, scheduledPRM)
		return
	}

	// check the sha is the same as pull request head commit id
	baseGitRepo, err := gitrepo.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		log.Error("OpenRepository: %v", err)
		return
	}
	defer baseGitRepo.Close()

	headCommitID, err := baseGitRepo.GetRefCommitID(pr.GetGitRefName())
	if err != nil {
		log.Error("GetRefCommitID: %v", err)
		return
	}
	if scheduledPRM.HeadCommitID != "" && headCommitID != scheduledPRM.HeadCommitID {
		log.Info("Scheduled auto merge %-v is pinned to %s but the head is now %s, not merging", pr, scheduledPRM.HeadCommitID, headCommitID)
		skipAutoMerge(ctx, pr, scheduledPRM, "head_moved", headCommitID)
		return
	}
	if headCommitID != sha {
		log.Warn("Head commit id of auto merge %-v does not match sha [%s], it may means the head branch has been updated. Just ignore this request because a new request expected in the queue", pr, sha)
		return
	}

	// Get all checks for this pr
	// We get the latest sha commit hash again to handle the case where the check of a previous push
	// did not succeed or was not finished yet.
	if err = pr.LoadHeadRepo(ctx); err != nil {
		log.Error("%-v LoadHeadRepo: %v", pr, err)
		return
	}

	var headGitRepo *git.Repository
	if pr.BaseRepoID == pr.HeadRepoID {
		headGitRepo = baseGitRepo
	} else {
		headGitRepo, err = gitrepo.OpenRepository(ctx, pr.HeadRepo)
		if err != nil {
			log.Error("OpenRepository %-v: %v", pr.HeadRepo, err)
			return
		}
		defer headGitRepo.Close()
	}

	switch pr.Flow {
	case issues_model.PullRequestFlowGithub:
		headBranchExist := headGitRepo.IsBranchExist(pr.HeadBranch)
		if pr.HeadRepo == nil || !headBranchExist {
			log.Warn("Head branch of auto merge %-v does not exist [HeadRepoID: %d, Branch: %s]", pr, pr.HeadRepoID, pr.HeadBranch)
			skipAutoMerge(ctx, pr, scheduledPRM, "branch_missing", headCommitID)
			return
		}
	case issues_model.PullRequestFlowAGit:
		headBranchExist := baseGitRepo.IsReferenceExist(pr.GetGitRefName())
		if !headBranchExist {
			log.Warn("Head branch of auto merge %-v does not exist [HeadRepoID: %d, Branch(Agit): %s]", pr, pr.HeadRepoID, pr.HeadBranch)
			skipAutoMerge(ctx, pr, scheduledPRM, "branch_missing", headCommitID)
			return
		}
	default:
		log.Error("wrong flow type %d", pr.Flow)
		return
	}

	// Check if all checks succeeded
	pass, err := pull_service.IsPullCommitStatusPass(ctx, pr)
	if err != nil {
		log.Error("%-v IsPullCommitStatusPass: %v", pr, err)
		return
	}
	if !pass {
		log.Info("Scheduled auto merge %-v has unsuccessful status checks", pr)
		if failed, err := pull_service.IsPullCommitStatusFailed(ctx, pr); err != nil {
			log.Error("%-v IsPullCommitStatusFailed: %v", pr, err)
		} else if failed {
			skipAutoMerge(ctx, pr, scheduledPRM, "checks_failed", headCommitID)
		} // pending checks: nothing to report yet
		return
	}

	// Merge if all checks succeeded, checking the permission again right before the merge
	if perm, allowed, err = canStillMerge(ctx, pr, doer); err != nil {
		log.Error("%-v canStillMerge: %v", pr, err)
		return
	} else if !allowed {
		cancelAutoMerge(ctx, pr, scheduledPRM)
		return
	}
	if err := pull_service.CheckPullMergeable(ctx, doer, &perm, pr, pull_service.MergeCheckTypeGeneral, false, scheduledPRM.MergeStyle); err != nil {
		if errors.Is(err, pull_service.ErrUserNotAllowedToMerge) {
			cancelAutoMerge(ctx, pr, scheduledPRM)
			return
		}
		switch {
		case errors.Is(err, pull_service.ErrNotMergeableState):
			skipAutoMerge(ctx, pr, scheduledPRM, "conflict", headCommitID)
		case errors.Is(err, pull_service.ErrIsWorkInProgress):
			skipAutoMerge(ctx, pr, scheduledPRM, "wip", headCommitID)
		case models.IsErrDisallowedToMerge(err):
			skipAutoMerge(ctx, pr, scheduledPRM, "blocked", headCommitID)
		default:
			log.Error("%-v CheckPullMergeable: %v", pr, err)
		}
		return
	}

	if deleted, err := pull_model.DeleteAutoMergeByID(ctx, scheduledPRM.ID); err != nil {
		log.Error("DeleteAutoMergeByID[%d]: %v", pr.ID, err)
		return
	} else if !deleted {
		log.Trace("Auto merge %-v was removed meanwhile", pr)
		return
	}

	// a branch with a merge queue merges only through it: join the queue now that the checks succeeded
	if rule, err := mergequeue.Rule(ctx, pr); err != nil {
		log.Error("%-v mergequeue.Rule: %v", pr, err)
		return
	} else if rule != nil {
		if err := mergequeue.Add(ctx, doer, &perm, pr, mergequeue.AddOptions{Style: scheduledPRM.MergeStyle, ExpectedHead: sha, DeleteBranch: scheduledPRM.DeleteBranchAfterMerge, SkipForward: scheduledPRM.SkipMergeForward}); err != nil {
			log.Warn("Auto merge of %-v was removed but adding it to the merge queue failed: %v", pr, err)
			skipAutoMerge(ctx, pr, scheduledPRM, "merge_failed", sha)
		}
		return
	}

	if scheduledPRM.SkipMergeForward {
		ctx = pull_service.WithoutMergeForward(ctx)
	}
	// only merge the head validated above: the merge fetches the head branch, which may have moved since
	if err := pull_service.Merge(ctx, pr, doer, baseGitRepo, scheduledPRM.MergeStyle, sha, scheduledPRM.Message, true); err != nil {
		log.Warn("Auto merge of %-v was removed but the merge failed: %v", pr, err)
		skipAutoMerge(ctx, pr, scheduledPRM, "merge_failed", sha)
		// FIXME: if merge failed, we should display some error message to the pull request page.
		// The resolution is add a new column on automerge table named `error_message` to store the error message and displayed
		// on the pull request page. But this should not be finished in a bug fix PR which will be backport to release branch.
		return
	}

	// a scheduled merge is pinned to its head; its time was reset to 0 when it became due
	if scheduledPRM.HeadCommitID != "" {
		if _, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRMergedBySchedule, pr, doer, issues_model.AutoMergeInfo{}); err != nil {
			log.Error("%-v CreateAutoMergeComment: %v", pr, err)
		}
	}

	alwaysDelete, err := branchworkflow.IsAlways(ctx, pr.BaseRepo)
	if err != nil {
		log.Error("%d branchworkflow.IsAlways: %v", pr.ID, err)
	}
	if scheduledPRM.DeleteBranchAfterMerge || alwaysDelete {
		err := repo_service.DeleteBranchAfterMerge(ctx, doer, pr, headGitRepo)
		if err != nil {
			log.Error("%d repo_service.DeleteBranchIfUnused: %v", pr.ID, err)
		}
	}
}
