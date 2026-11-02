// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"errors"
	"fmt"

	"forgejo.org/models"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
)

// ErrMergeQueueEmptyBuild is returned for a pull request that changes nothing on top of the commit it is built onto
var ErrMergeQueueEmptyBuild = errors.New("the pull request changes nothing on top of the branch and the ones ahead of it")

// ErrMergeQueueNotRecorded is returned when the push of a build went through but its hook didn't record the merge;
// the queue records it later
var ErrMergeQueueNotRecorded = errors.New("the push of the build was not recorded as its merge")

// BuildMergeQueueCommit merges pr, at expectedHeadCommitID, with mergeStyle and the default message on top of the
// commit onto of the base repository, as doer. It calls start with the new commit, and if start reports true it pushes
// the commit to branch of the base repository without running the hooks. It returns the new commit, "" when start
// reported false.
func BuildMergeQueueCommit(ctx context.Context, pr *issues_model.PullRequest, doer *user_model.User, mergeStyle repo_model.MergeStyle, expectedHeadCommitID, onto, branch string, start func(sha string) (bool, error)) (string, error) {
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return "", err
	}
	if err := pr.LoadIssue(ctx); err != nil {
		return "", err
	}

	mergeCtx, cancel, err := createTemporaryRepoForMergeOnto(ctx, pr, doer, expectedHeadCommitID, onto)
	if err != nil {
		return "", err
	}
	defer cancel()

	baseGitRepo, err := gitrepo.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		return "", err
	}
	message, body, err := getMergeMessage(ctx, baseGitRepo, pr, mergeStyle, nil)
	baseGitRepo.Close()
	if err != nil {
		return "", err
	}
	if message != "" && body != "" {
		message += "\n\n" + body
	}

	if err := doMergeStyle(mergeCtx, mergeStyle, message); err != nil {
		return "", err
	}

	mergeCommitID, err := git.GetFullCommitID(ctx, mergeCtx.tmpBasePath, baseBranch)
	if err != nil {
		return "", fmt.Errorf("failed to get full commit id for the merge queue build: %w", err)
	}
	if setting.LFS.StartServer {
		mergeBaseSHA, err := git.GetFullCommitID(ctx, mergeCtx.tmpBasePath, "original_"+baseBranch)
		if err != nil {
			return "", fmt.Errorf("failed to get full commit id for original_%s: %w", baseBranch, err)
		}
		if err := LFSPush(ctx, mergeCtx.tmpBasePath, mergeCommitID, mergeBaseSHA, pr); err != nil {
			return "", err
		}
	}

	if mergeCommitID == onto {
		return "", ErrMergeQueueEmptyBuild
	}
	if started, err := start(mergeCommitID); err != nil || !started {
		return "", err
	}
	// the build is no push of a user: no hooks, so no push events, feeds or branch rows
	mergeCtx.env = repo_module.InternalPushingEnvironment(ctx, doer, pr.BaseRepo)
	if err := git.NewCommand(ctx, "push", "--force", "origin").AddDynamicArguments(baseBranch + ":" + git.BranchPrefix + branch).
		Run(mergeCtx.RunOpts()); err != nil {
		return "", fmt.Errorf("git push of the merge queue build of %v: %w\n%s", pr, err, mergeCtx.errbuf.String())
	}
	return mergeCommitID, nil
}

// MergeQueued fast-forwards base, the base branch of pr, from expectedOld to sha, a tested merge queue build that has pr
// on top of expectedOld, as doer. The push runs the hooks: they check the branch protection again and mark pr merged.
// An error after the push is only logged: the branch has moved.
func MergeQueued(ctx context.Context, pr *issues_model.PullRequest, doer *user_model.User, base, expectedOld, sha string, record bool) error {
	defer pullWorkingPool.Lock(fmt.Sprint(pr.ID))()

	pr, err := issues_model.GetPullRequestByID(ctx, pr.ID)
	if err != nil {
		return err
	}
	if pr.HasMerged {
		return models.ErrPullRequestHasMerged{ID: pr.ID, IssueID: pr.IssueID, HeadRepoID: pr.HeadRepoID, BaseRepoID: pr.BaseRepoID, HeadBranch: pr.HeadBranch, BaseBranch: pr.BaseBranch}
	}
	if sha == expectedOld {
		return ErrMergeQueueEmptyBuild // the push would change nothing and nothing would record the merge
	}
	if pr.BaseBranch != base {
		return &git.ErrPushOutOfDate{Err: fmt.Errorf("%v was retargeted from %s", pr, base)} // the next pass removes it
	}
	if err := pr.LoadIssue(ctx); err != nil {
		return err
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return err
	}
	if err := pr.LoadHeadRepo(ctx); err != nil {
		return err
	}

	defer func() {
		AddTestPullRequestTask(ctx, doer, pr.BaseRepo.ID, pr.BaseBranch, false, "", "", 0)
	}()

	headUser := doer
	if pr.HeadRepo != nil {
		if err := pr.HeadRepo.LoadOwner(ctx); err == nil {
			headUser = pr.HeadRepo.Owner
		} else if !user_model.IsErrUserNotExist(err) {
			return err
		}
	}
	env := append(repo_module.FullPushingEnvironment(ctx, headUser, doer, pr.BaseRepo, pr.BaseRepo.Name, pr.ID),
		repo_module.EnvPushTrigger+"="+string(repo_module.PushTriggerMergeQueue))
	// only from the commit the build is on top of, so the push is a fast-forward and a branch moved meanwhile (also
	// back to an ancestor) refuses it
	ref := git.BranchPrefix + base
	tip, err := git.GetFullCommitID(ctx, pr.BaseRepo.RepoPath(), ref)
	if err != nil {
		return err
	}
	if tip == sha {
		if !record {
			return fmt.Errorf("%v: %w", pr, ErrMergeQueueNotRecorded) // the queue records it once nobody else may
		}
		// an earlier push of the build went through, but its post-receive hook never recorded the merge
		pr.MergedCommitID, pr.MergedBaseCommitID, pr.MergedUnix = sha, expectedOld, timeutil.TimeStampNow()
		pr.Merger, pr.MergerID = doer, doer.ID
		if err := db.WithTx(ctx, func(ctx context.Context) error {
			if err := pull_model.DeleteScheduledAutoMerge(ctx, pr.ID); err != nil && !db.IsErrNotExist(err) {
				return err
			}
			ok, err := pr.SetMerged(ctx)
			if err == nil && !ok { // the hook recorded it meanwhile and its merge sends the events
				err = models.ErrPullRequestHasMerged{ID: pr.ID, IssueID: pr.IssueID, HeadRepoID: pr.HeadRepoID, BaseRepoID: pr.BaseRepoID, HeadBranch: pr.HeadBranch, BaseBranch: pr.BaseBranch}
			}
			return err
		}); err != nil {
			return err
		}
	} else if err := git.Push(ctx, pr.BaseRepo.RepoPath(), git.PushOptions{Remote: ".", Branch: sha + ":" + ref, ForceWithLease: ref + ":" + expectedOld, Env: env}); err != nil {
		return err
	}
	if merged, err := issues_model.GetPullRequestByID(ctx, pr.ID); err != nil {
		return fmt.Errorf("%v: %w: %w", pr, ErrMergeQueueNotRecorded, err) // the branch moved: never removed as failed
	} else if !merged.HasMerged {
		return fmt.Errorf("%v: %w", pr, ErrMergeQueueNotRecorded)
	}
	log.Trace("Merge queue fast-forwarded %s of %-v to %s for %-v", base, pr.BaseRepo, sha, pr)
	if err := afterMerge(ctx, pr, doer, false); err != nil {
		log.Error("after the merge queue merged %-v: %v", pr, err)
	}
	return nil
}
