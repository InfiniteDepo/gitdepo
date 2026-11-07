// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"context"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"

	"xorm.io/builder"
)

// The reasons a branch is never deleted by a cleanup. This is a closed set: callers show them through literal locale keys.
const (
	KeptDefault     = "default"
	KeptDevelopment = "development"
	KeptProduction  = "production"
	KeptRelease     = "release"
	KeptProtected   = "protected"
	KeptOpenPR      = "open_pr"
	KeptMergeQueue  = "merge_queue"
	KeptBase        = "base" // the named base of a branch type, or the default pull request target
)

// KeptChecker says why branches of one repository must never be deleted. It loads what it needs once, so a list of
// branches costs a handful of queries. The branching model is the one of the repository that owns the branches.
type KeptChecker struct {
	repo  *repo_model.Repository
	model EffectiveModel
	dev   string
	rules git_model.ProtectedBranchRules
	inUse map[string]bool
	bases map[string]bool
}

// NewKeptChecker loads the model, the protection rules and, with openPRs, the branches the open pull requests use.
func NewKeptChecker(ctx context.Context, repo *repo_model.Repository, openPRs bool) (*KeptChecker, error) {
	model, err := GetEffectiveModel(ctx, repo)
	if err != nil {
		return nil, err
	}
	rules, err := git_model.FindProtectedBranchRulesForRepo(ctx, repo)
	if err != nil {
		return nil, err
	}
	k := &KeptChecker{repo: repo, model: model, dev: model.DevelopmentBranch(repo), rules: rules, inUse: map[string]bool{}, bases: map[string]bool{}}
	for _, t := range model.Model.Types {
		if !t.Off && t.Base == repo_model.BranchTypeBaseBranch {
			k.bases[t.BaseBranch] = true
		}
	}
	if model.Model.DefaultPRTarget != "" {
		k.bases[model.Model.DefaultPRTarget] = true
	}
	if !openPRs {
		return k, nil
	}
	var prs []*issues_model.PullRequest
	if err := db.GetEngine(ctx).Join("INNER", "issue", "issue.id = pull_request.issue_id").
		Where(builder.Eq{"issue.is_closed": false, "pull_request.has_merged": false}).
		And(builder.Eq{"pull_request.head_repo_id": repo.ID}.Or(builder.Eq{"pull_request.base_repo_id": repo.ID})).
		Find(&prs); err != nil {
		return nil, err
	}
	for _, pr := range prs {
		// the head branch of an AGit pull request is not a real branch
		if pr.HeadRepoID == repo.ID && pr.Flow != issues_model.PullRequestFlowAGit {
			k.inUse[pr.HeadBranch] = true
		}
		if pr.BaseRepoID == repo.ID {
			k.inUse[pr.BaseBranch] = true
		}
	}
	return k, nil
}

// Model returns the branching model the checker decided with, so a caller needs no second read of it.
func (k *KeptChecker) Model() EffectiveModel { return k.model }

// Reason returns why the branch must be kept, one of the Kept constants, or "".
func (k *KeptChecker) Reason(name string) string {
	switch {
	case name == k.repo.DefaultBranch:
		return KeptDefault
	case name == k.dev:
		return KeptDevelopment
	case k.model.Model.ProductionBranch != "" && name == k.model.Model.ProductionBranch:
		return KeptProduction
	case isReleaseBranch(k.model.Model, name):
		return KeptRelease
	case k.rules.GetFirstMatched(name) != nil:
		return KeptProtected
	case k.bases[name]:
		return KeptBase
	case pull_model.IsMergeQueueBranch(name):
		return KeptMergeQueue
	case k.inUse[name]:
		return KeptOpenPR
	}
	return ""
}

// KeptReason says why a branch of repo must never be deleted, "" when it may be. With openPRs the head and base
// branches of open pull requests count; the delete after merge, which retargets the children of the merged pull
// request and has its own check of the open ones, passes false.
func KeptReason(ctx context.Context, repo *repo_model.Repository, name string, openPRs bool) (string, error) {
	k, err := NewKeptChecker(ctx, repo, openPRs)
	if err != nil {
		return "", err
	}
	return k.Reason(name), nil
}

// isReleaseBranch uses MatchType, the one classifier of branch types, so a branch is a release branch for the kept
// rule exactly when it is one for the pull request target.
func isReleaseBranch(m repo_model.BranchingModel, name string) bool {
	t, ok := MatchType(m, name)
	return ok && t.Name == ReleaseTypeName
}
