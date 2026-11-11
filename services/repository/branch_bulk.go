// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"slices"
	"strings"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/branchworkflow"

	"xorm.io/builder"
)

// MaxDeleteSelectedBranchesAPI is how many branches one API request names or deletes.
const MaxDeleteSelectedBranchesAPI = 100

// The codes of BranchResult.Reason that are no branchworkflow.Kept reason.
const KeptNotFound = "not_found"

// The values of BranchFilter.State and BranchFilter.Into.
const (
	BranchMerged       = "merged"
	BranchNotMerged    = "not_merged"
	MergedIntoDev      = "development"
	MergedIntoDefault  = "default"
	maxBranchStaleDays = 3650
)

// BranchFilter is the one set of filters of the Branches page, its "select all matching" and the bulk delete API.
// Keyword and type work as before; State is "merged" or "not_merged" into the development branch (else the default
// branch) or the one Into names; StaleDays is the days since the server last updated the branch row (never commit
// time, which the pusher forges); PushedBy a user name (the server-recorded pusher, never the git author). Deleted
// lists the deleted branches only, with the keyword, type and pusher filters.
type BranchFilter struct {
	Keyword   string
	Type      string
	Untyped   bool
	State     string
	Into      string
	StaleDays int
	PushedBy  string
	Deleted   bool
	Viewer    *user_model.User // who asks: a pusher the viewer can't see matches nothing
}

// IsSet tells if a filter other than the keyword and the type restricts the list.
func (f BranchFilter) IsSet() bool {
	return f.State != "" || f.StaleDays != 0 || f.PushedBy != "" || f.Deleted
}

// Validate refuses values outside the closed sets.
func (f BranchFilter) Validate() error {
	switch {
	case !slices.Contains([]string{"", BranchMerged, BranchNotMerged}, f.State):
		return util.NewInvalidArgumentErrorf("unknown merged filter %q", f.State)
	case !slices.Contains([]string{"", MergedIntoDev, MergedIntoDefault}, f.Into):
		return util.NewInvalidArgumentErrorf("unknown merged_into %q", f.Into)
	case f.StaleDays < 0 || f.StaleDays > maxBranchStaleDays:
		return util.NewInvalidArgumentErrorf("stale days must be 1 to %d", maxBranchStaleDays)
	}
	return nil
}

// BranchQuery is what BranchFilter.Query makes of a filter, for LoadBranches and FindBranchOptions.
type BranchQuery struct {
	Deleted optional.Option[bool]
	Keyword string
	Cond    builder.Cond
	// Merged, when not nil, is the merged filter: the branches git says are (not) merged with the tip it saw. The
	// names stay out of SQL (a big repository has more than a statement can bind): rows match by the other
	// conditions and are kept only when name and commit equal an entry, compared exactly in Go.
	Merged map[string]string
}

// Query turns the filter into a database condition: the one builder behind the page, its count, "select all
// matching" and the API. Without a filter other than keyword and type it keeps the page's list of live and
// deleted branches.
func (f BranchFilter) Query(ctx context.Context, repo *repo_model.Repository, gitRepo *git.Repository, model branchworkflow.EffectiveModel) (BranchQuery, error) {
	if err := f.Validate(); err != nil {
		return BranchQuery{}, err
	}
	q := BranchQuery{Keyword: f.Keyword, Cond: builder.NewCond()}
	if cond := branchworkflow.TypeFilter(model.Model, f.Type, f.Untyped); cond != nil {
		q.Cond = q.Cond.And(cond)
	}
	if f.PushedBy != "" {
		pusher := builder.Expr("1 = 0")
		if u, err := user_model.GetUserByName(ctx, f.PushedBy); err == nil {
			if user_model.IsUserVisibleToViewer(ctx, u, f.Viewer) {
				pusher = builder.Eq{"pusher_id": u.ID}
			}
		} else if !user_model.IsErrUserNotExist(err) {
			return q, err
		}
		q.Cond = q.Cond.And(pusher)
	}
	if f.Deleted {
		q.Deleted = optional.Some(true)
		return q, nil
	}
	if f.IsSet() {
		q.Deleted = optional.Some(false)
	}
	if f.StaleDays > 0 {
		q.Cond = q.Cond.And(builder.Lt{"updated_unix": int64(timeutil.TimeStampNow()) - int64(f.StaleDays)*86400})
	}
	if f.State != "" {
		into := model.DevelopmentBranch(repo)
		if f.Into == MergedIntoDefault {
			into = repo.DefaultBranch
		}
		walked, err := branchesMergedInto(ctx, repo, gitRepo, into, f.State == BranchMerged)
		if err != nil {
			return q, err
		}
		q.Merged = walked
	}
	return q, nil
}

// rows loads the live branch rows matching the query without the default branch, in the order of the Branches
// page; only id, name and commit are read. With the merged filter a row stays if it is at the tip git walked.
func (q BranchQuery) rows(ctx context.Context, repo *repo_model.Repository) ([]*git_model.Branch, error) {
	opts := git_model.FindBranchOptions{
		RepoID: repo.ID, IsDeletedBranch: optional.Some(false), Keyword: q.Keyword, Cond: q.Cond,
		ExcludeBranchNames: []string{repo.DefaultBranch},
	}
	var rows []*git_model.Branch
	if err := db.GetEngine(ctx).Table("branch").Cols("id", "name", "commit_id").Where(opts.ToConds()).OrderBy(opts.ToOrders()).Find(&rows); err != nil {
		return nil, err
	}
	if q.Merged != nil {
		rows = slices.DeleteFunc(rows, func(b *git_model.Branch) bool {
			tip, ok := q.Merged[b.Name]
			return !ok || tip != b.CommitID
		})
	}
	rows = slices.DeleteFunc(rows, func(b *git_model.Branch) bool { return b.Name == repo.DefaultBranch })
	return rows, nil
}

// Page narrows a query with the merged filter to the rows of one page, for LoadBranches, and returns how many rows
// match in all. Without the merged filter it returns q as it is and -1.
func (q BranchQuery) Page(ctx context.Context, repo *repo_model.Repository, page, pageSize int) (BranchQuery, int64, error) {
	if q.Merged == nil {
		return q, -1, nil
	}
	rows, err := q.rows(ctx, repo)
	if err != nil {
		return q, 0, err
	}
	total := int64(len(rows))
	rows = rows[min(len(rows), max(page-1, 0)*pageSize):]
	rows = rows[:min(len(rows), pageSize)]
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return BranchQuery{Deleted: q.Deleted, Cond: builder.In("id", ids)}, total, nil
}

// branchesMergedInto maps the branches whose tip is (merged) or is not (!merged) in the branch into to that tip: one
// walk. The map is never nil.
func branchesMergedInto(ctx context.Context, repo *repo_model.Repository, gitRepo *git.Repository, into string, merged bool) (map[string]string, error) {
	tip, err := gitRepo.GetBranchCommitID(into)
	if err != nil {
		if git.IsErrNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	opt := "--no-merged=%s"
	if merged {
		opt = "--merged=%s"
	}
	out, _, err := git.NewCommand(ctx, "for-each-ref", "--format=%(objectname) %(refname)").
		AddOptionFormat(opt, tip).AddArguments("refs/heads/").RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		sha, ref, ok := strings.Cut(line, " ")
		if name, isBranch := strings.CutPrefix(ref, git.BranchPrefix); ok && isBranch {
			names[name] = sha
		}
	}
	return names, nil
}

// SelectedBranch is a branch to delete and the commit the doer saw it at; an empty Commit means the tip as it is.
type SelectedBranch struct {
	Name   string
	Commit string
}

// BranchDeletion is what a bulk delete found for the filter: the first limit branches that may be deleted, how many
// there are in all and how many matching branches are kept.
type BranchDeletion struct {
	Branches []SelectedBranch
	Total    int
	Kept     int
}

// FindDeletableBranches lists the live branches matching q that no kept rule protects, newest first, at most limit.
// It deletes nothing; DeleteSelectedBranches decides again.
func FindDeletableBranches(ctx context.Context, repo *repo_model.Repository, q BranchQuery, limit int) (*BranchDeletion, error) {
	if has, deleted := q.Deleted.Get(); has && deleted {
		return nil, util.NewInvalidArgumentErrorf("deleted branches can't be deleted again")
	}
	rows, err := q.rows(ctx, repo)
	if err != nil {
		return nil, err
	}
	kept, err := branchworkflow.NewKeptChecker(ctx, repo, true)
	if err != nil {
		return nil, err
	}
	found := &BranchDeletion{}
	for _, b := range rows {
		if kept.Reason(b.Name) != "" {
			found.Kept++
			continue
		}
		found.Total++
		if len(found.Branches) < limit {
			found.Branches = append(found.Branches, SelectedBranch{b.Name, b.CommitID})
		}
	}
	return found, nil
}

// BranchResult is what happened to one selected branch: Reason is "" when it was deleted, else a
// branchworkflow.Kept reason, KeptNewCommits, KeptPermission, KeptNotFound or "error" (a closed set of codes).
type BranchResult struct {
	Name   string
	Reason string
}

// maxRefusedAudited is how many refused branches (name and reason) the summary audit entry lists.
const maxRefusedAudited = 50

type bulkDeleteKey struct{}

// DeleteSelectedBranches deletes the selected branches one by one and reports each. Every branch is decided again
// right before its own deletion: the kept rule (default, development, production, release, protected, merge queue
// and open pull request branches stay) read fresh for that branch, the doer's own permission on it and, through
// DeleteBranch, the commit it was at when the doer saw it, so a push, a pull request or a rule added since keeps
// it. A refused branch never stops the others. Each deletion is audited by DeleteBranch (marked "bulk") and the run
// once, with the refused branches and their reasons; every deleted branch can be restored from the deleted branches.
func DeleteSelectedBranches(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, gitRepo *git.Repository, selected []SelectedBranch) ([]BranchResult, error) {
	if repo.IsMirror { // the next mirror sync brings them back
		return nil, util.NewPermissionDeniedErrorf("branches of a mirror can't be deleted")
	}
	locked := PersonalRepoLocked(ctx, repo)
	var results []BranchResult
	deleted := 0
	seen := map[string]bool{}
	for _, b := range selected {
		if seen[b.Name] {
			continue
		}
		seen[b.Name] = true
		reason, err := branchworkflow.KeptReason(ctx, repo, b.Name, true)
		if err != nil {
			log.Error("DeleteSelectedBranches: kept check of %q in %-v: %v", b.Name, repo, err)
			reason = "error"
		}
		if reason == "" {
			reason = deleteSelectedBranch(context.WithValue(ctx, bulkDeleteKey{}, true), doer, repo, gitRepo, b)
		}
		if reason == "" {
			deleted++
		}
		results = append(results, BranchResult{b.Name, reason})
	}
	ShrinkAfterDelete(ctx, repo, locked && deleted > 0)
	if len(results) == 0 {
		return results, nil
	}
	var refused []string
	for _, r := range results {
		if r.Reason != "" && len(refused) < maxRefusedAudited {
			refused = append(refused, r.Name+": "+r.Reason)
		}
	}
	data := map[string]any{"counts": map[string]any{"deleted": deleted, "kept": len(results) - deleted}, "refused": refused}
	return results, repo_model.RecordRepo(ctx, "repo.branches.bulk_deleted", repo, data)
}

func deleteSelectedBranch(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, gitRepo *git.Repository, b SelectedBranch) string {
	err := DeleteBranch(ctx, doer, repo, gitRepo, b.Name, b.Commit)
	if err == nil {
		return ""
	}
	if git.IsErrBranchNotExist(err) {
		return KeptNotFound
	}
	if code, ok := KeptCode(err); ok {
		return code
	}
	log.Error("DeleteSelectedBranches: branch %q of %-v: %v", b.Name, repo, err)
	return "error"
}

// CheckSelectedBranchNames removes duplicates from names and refuses more than max, empty or over-long names and
// names git would not accept.
func CheckSelectedBranchNames(names []string, maxNames int) ([]string, error) {
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	if len(names) == 0 || len(names) > maxNames {
		return nil, util.NewInvalidArgumentErrorf("name 1 to %d branches", maxNames)
	}
	for _, n := range names {
		if n == "" || len(n) > 255 || !git.IsValidRefPattern(n) || git.IsReservedRefName(n) {
			return nil, util.NewInvalidArgumentErrorf("invalid branch name %q", n)
		}
	}
	return names, nil
}
