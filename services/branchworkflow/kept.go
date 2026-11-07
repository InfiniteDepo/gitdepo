// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"context"
	"slices"
	"strings"
	"time"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/setting"

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
)

// KeptChecker says why branches of one repository must never be deleted. It loads what it needs once, so a list of
// branches costs a handful of queries. The branching model is the one of the repository that owns the branches.
type KeptChecker struct {
	repo  *repo_model.Repository
	model EffectiveModel
	dev   string
	rules git_model.ProtectedBranchRules
	inUse map[string]bool
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
	k := &KeptChecker{repo: repo, model: model, dev: model.DevelopmentBranch(repo), rules: rules, inUse: map[string]bool{}}
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

// Reason returns why the branch must be kept, one of the Kept constants, or "".
func (k *KeptChecker) Reason(name string) string {
	switch {
	case name == k.repo.DefaultBranch:
		return KeptDefault
	case name == k.dev:
		return KeptDevelopment
	case k.model.Model.ProductionBranch != "" && name == k.model.Model.ProductionBranch:
		return KeptProduction
	case slices.ContainsFunc(k.model.Model.ReleasePrefixes, func(p string) bool { return strings.HasPrefix(name, p) }):
		return KeptRelease
	case k.rules.GetFirstMatched(name) != nil:
		return KeptProtected
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

// RestoreWindow tells how a deleted branch can be restored, from the configured deleted-branch cleanup: restorable
// is false when the cleanup purges at once, and hours is the time a deleted branch stays restorable, 0 when the
// cleanup is switched off and a branch stays restorable until the repository is deleted.
func RestoreWindow() (hours int, restorable bool) {
	sec := setting.CfgProvider.Section("cron.deleted_branches_cleanup")
	if !sec.Key("ENABLED").MustBool(true) {
		return 0, true
	}
	d, err := time.ParseDuration(sec.Key("OLDER_THAN").MustString("24h"))
	if err != nil {
		d = 24 * time.Hour
	}
	return int((d + time.Hour - 1) / time.Hour), d > 0
}
