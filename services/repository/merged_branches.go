// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"maps"
	"slices"
	"strings"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"

	"xorm.io/builder"
)

// MaxDeleteMergedBranches is how many branches one preview shows and one DeleteMergedBranches call deletes at most.
const MaxDeleteMergedBranches = 200

// MergedBranchScope names the repositories of a "delete merged branches" run: one repository, the repositories of
// a project or every repository of an organization. Exactly one field is set.
type MergedBranchScope struct {
	Repo  *repo_model.Repository
	Group *repo_model.RepoGroup
	Org   *user_model.User
}

// MergedBranches are the branches of one repository that DeleteMergedBranches would delete.
type MergedBranches struct {
	Repo     *repo_model.Repository
	Branches []string
}

// mergedBranchRepos lists the repositories of the scope, without archived, mirror, empty, trashed and unfinished ones.
// ids, when given, narrows them to those repositories.
func mergedBranchRepos(ctx context.Context, scope MergedBranchScope, ids ...int64) ([]*repo_model.Repository, error) {
	cond := builder.Eq{"is_archived": false, "is_mirror": false, "is_empty": false, "trashed_unix": 0, "status": repo_model.RepositoryReady}
	switch {
	case scope.Repo != nil:
		cond["id"] = scope.Repo.ID
	case scope.Group != nil:
		cond["owner_id"], cond["group_id"] = scope.Group.OwnerID, scope.Group.ID
	default:
		cond["owner_id"] = scope.Org.ID
	}
	sess := db.GetEngine(ctx).Where(cond)
	if len(ids) > 0 {
		sess.In("id", ids)
	}
	repos := make([]*repo_model.Repository, 0, 10)
	return repos, sess.OrderBy("group_name, lower_name").Find(&repos)
}

// mergedBranches returns the branches of repo whose tip is in the default branch, without the default branch, branches
// at its tip, branches matched by a protection rule and the head or base branches of open pull requests.
func mergedBranches(ctx context.Context, repo *repo_model.Repository, gitRepo *git.Repository) ([]mergedBranch, error) {
	tip, err := gitRepo.GetBranchCommitID(repo.DefaultBranch)
	if err != nil {
		if git.IsErrNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out, _, err := git.NewCommand(ctx, "for-each-ref", "--format=%(objectname) %(refname)").
		AddOptionFormat("--merged=%s", tip).AddArguments("refs/heads/").RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
	if err != nil {
		return nil, err
	}
	rules, err := git_model.FindProtectedBranchRulesForRepo(ctx, repo)
	if err != nil {
		return nil, err
	}
	var prs []*issues_model.PullRequest
	if err := db.GetEngine(ctx).Join("INNER", "issue", "issue.id = pull_request.issue_id").
		Where(builder.Eq{"issue.is_closed": false, "pull_request.has_merged": false}).
		And(builder.Eq{"pull_request.head_repo_id": repo.ID}.Or(builder.Eq{"pull_request.base_repo_id": repo.ID})).
		Find(&prs); err != nil {
		return nil, err
	}
	inUse := map[string]bool{repo.DefaultBranch: true}
	for _, pr := range prs {
		if pr.HeadRepoID == repo.ID {
			inUse[pr.HeadBranch] = true
		}
		if pr.BaseRepoID == repo.ID {
			inUse[pr.BaseBranch] = true
		}
	}
	var branches []mergedBranch
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		sha, ref, ok := strings.Cut(line, " ")
		name, isBranch := strings.CutPrefix(ref, git.BranchPrefix)
		if !ok || !isBranch || sha == tip || inUse[name] || rules.GetFirstMatched(name) != nil {
			continue
		}
		branches = append(branches, mergedBranch{name, sha})
	}
	return branches, nil
}

type mergedBranch struct{ name, commit string }

// FindMergedBranches lists, per repository of the scope, the first limit branches DeleteMergedBranches may delete.
// more tells that there are others; the walk stops there, so a large organization costs one page at a time. A
// repository that can't be read is logged and left out. It deletes nothing.
func FindMergedBranches(ctx context.Context, scope MergedBranchScope, limit int) (found []*MergedBranches, more bool, err error) {
	repos, err := mergedBranchRepos(ctx, scope)
	if err != nil {
		return nil, false, err
	}
	total := 0
	for _, repo := range repos {
		if total >= limit {
			return found, true, nil
		}
		branches, err := readMergedBranches(ctx, repo)
		if err != nil {
			log.Error("FindMergedBranches: %-v: %v", repo, err)
			continue
		}
		names := make([]string, 0, len(branches))
		for _, b := range branches {
			names = append(names, b.name)
		}
		if shown := min(len(names), limit-total); shown > 0 {
			found = append(found, &MergedBranches{Repo: repo, Branches: names[:shown]})
			more = more || shown < len(names)
			total += shown
		}
	}
	return found, more, nil
}

func readMergedBranches(ctx context.Context, repo *repo_model.Repository) ([]mergedBranch, error) {
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return nil, err
	}
	defer gitRepo.Close()
	return mergedBranches(ctx, repo, gitRepo)
}

// DeleteMergedBranches deletes, through DeleteBranch, the selected branches (by repository ID) that are still merged
// branches of the scope and still at the commit found merged, at most MaxDeleteMergedBranches, and records who
// started it with the totals when it tried any. A branch or repository that fails is logged and counted as failed.
func DeleteMergedBranches(ctx context.Context, doer *user_model.User, scope MergedBranchScope, selected map[int64][]string) (deleted, failed int, err error) {
	if len(selected) == 0 {
		return 0, 0, nil
	}
	repos, err := mergedBranchRepos(ctx, scope, slices.Collect(maps.Keys(selected))...)
	if err != nil {
		return 0, 0, err
	}
	touched, budget := 0, MaxDeleteMergedBranches
	for _, repo := range repos {
		if budget == 0 {
			break
		}
		n, f, err := deleteMergedBranchesOf(ctx, doer, repo, selected[repo.ID], budget)
		if err != nil {
			log.Error("DeleteMergedBranches: %-v: %v", repo, err)
			f = min(len(selected[repo.ID]), budget)
		}
		deleted, failed, budget = deleted+n, failed+f, budget-n-f
		if n > 0 {
			touched++
		}
	}
	if deleted+failed == 0 {
		return 0, 0, nil
	}
	data := map[string]any{"counts": map[string]any{"deleted": deleted, "failed": failed, "repos": touched}}
	switch {
	case scope.Repo != nil:
		err = repo_model.RecordRepo(ctx, "repo.merged_branches.deleted", scope.Repo, data)
	case scope.Group != nil:
		err = repo_model.RecordProject(ctx, "org.project.merged_branches_deleted", scope.Group, data)
	default:
		err = user_model.RecordOrg(ctx, "org.merged_branches.deleted", scope.Org, data)
	}
	return deleted, failed, err
}

func deleteMergedBranchesOf(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, selected []string, limit int) (deleted, failed int, err error) {
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return 0, 0, err
	}
	defer gitRepo.Close()
	merged, err := mergedBranches(ctx, repo, gitRepo)
	if err != nil {
		return 0, 0, err
	}
	branches := slices.DeleteFunc(merged, func(b mergedBranch) bool { return !slices.Contains(selected, b.name) })
	branches = branches[:min(len(branches), limit)]
	if len(branches) == 0 {
		return 0, 0, nil
	}
	locked := PersonalRepoLocked(ctx, repo)
	for _, b := range branches {
		// a push since the merged check would lose its commits: leave the branch for the next run
		if commit, err := gitRepo.GetBranchCommitID(b.name); err != nil || commit != b.commit {
			failed++
			continue
		}
		if err := DeleteBranch(ctx, doer, repo, gitRepo, b.name); err != nil {
			log.Error("DeleteMergedBranches: branch %q of %-v: %v", b.name, repo, err)
			failed++
			continue
		}
		deleted++
	}
	ShrinkAfterDelete(ctx, repo, locked && deleted > 0)
	return deleted, failed, nil
}
