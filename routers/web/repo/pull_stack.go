// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	stdCtx "context"
	"errors"
	"html/template"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"forgejo.org/models"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/templates"
	"forgejo.org/modules/web"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
)

// stackState is a review or check state of a pull request of a stack, in words and an icon, never by colour only.
type stackState struct {
	Text  template.HTML
	Icon  string
	Class string
}

// stackRow is a pull request of the stack panel.
type stackRow struct {
	Index        int64
	Title        string
	Link         string
	Indent       bool      // it has a sibling: the stack branches here
	AlsoOn       *stackRow // the pull request its branch is also stacked on, for the later siblings
	Current      bool
	Commits      int64
	HeadCommitID string
	Review       stackState
	Check        stackState
	Conflict     bool
	Block        string // what the merge would refuse: "conflict", "checks_pending", "checks_failed", "review" or ""
	Warn         string // what the merge allows but the viewer should know: "checks", "review" or ""
}

type stackStyle struct {
	Value string
	Text  template.HTML
}

// stackView is the stack panel and the merge stack part of the merge box.
type stackView struct {
	Rows      []*stackRow
	Base      string
	Truncated bool

	Parent        *stackRow   // the pull request this one is based on, nil if it is the bottom
	Chain         []*stackRow // the pull requests merged by Merge stack, bottom first, this one last
	ChainLinks    template.HTML
	CanMerge      bool          // the viewer may merge the stack
	MergeQueue    bool          // the base requires the merge queue, so there is no Merge stack
	TooLong       bool          // the chain is longer than one merge takes
	MaxMerge      int           // the most pull requests one merge takes
	Blocked       template.HTML // why Merge stack is disabled
	Warnings      []template.HTML
	Children      template.HTML // links of the other open pull requests that move onto the base
	ChildrenCount int
	Styles        []stackStyle
	DefaultStyle  string
	DeleteDefault bool
	DeleteForced  bool
	Deletable     int // the branches of the merged pull requests that are deleted after the merge
	Kept          int // the ones that are not: the branching model, a protection rule or the repository keeps them
}

func stackReviewState(ctx *context.Context, review string) stackState {
	switch review {
	case pull_service.StackReviewApproved:
		return stackState{ctx.Tr("repo.pulls.stack.review.approved"), "octicon-check", "green"}
	case pull_service.StackReviewChangesRequested:
		return stackState{ctx.Tr("repo.pulls.stack.review.changes_requested"), "octicon-x", "red"}
	}
	return stackState{ctx.Tr("repo.pulls.stack.review.pending"), "octicon-circle", "grey"}
}

func stackCheckState(ctx *context.Context, check api.CommitStatusState) stackState {
	switch check {
	case api.CommitStatusSuccess:
		return stackState{ctx.Tr("repo.pulls.stack.check.success"), "octicon-dot-fill", "green"}
	case api.CommitStatusPending:
		return stackState{ctx.Tr("repo.pulls.stack.check.pending"), "octicon-dot-fill", "yellow"}
	case api.CommitStatusFailure:
		return stackState{ctx.Tr("repo.pulls.stack.check.failure"), "octicon-x", "red"}
	case api.CommitStatusError:
		return stackState{ctx.Tr("repo.pulls.stack.check.error"), "octicon-x", "red"}
	case api.CommitStatusWarning:
		return stackState{ctx.Tr("repo.pulls.stack.check.warning"), "octicon-dot-fill", "yellow"}
	}
	return stackState{ctx.Tr("repo.pulls.stack.check.none"), "octicon-circle", "grey"}
}

// prepareStack sets the data of the stack panel and of Merge stack for the open pull request pull. allowMerge is
// whether the viewer may merge it.
func prepareStack(ctx *context.Context, pull *issues_model.PullRequest, allowMerge bool) {
	if pull.HasMerged || pull.Issue.IsClosed {
		return
	}
	stack, err := pull_service.GetStack(ctx, pull)
	if err != nil {
		ctx.ServerError("GetStack", err)
		return
	}
	if len(stack.Entries) == 0 {
		return
	}
	statuses, err := pull_service.StackStatuses(ctx, ctx.Repo.Repository, ctx.Repo.GitRepo, stack)
	if err != nil {
		ctx.ServerError("StackStatuses", err)
		return
	}

	view := &stackView{Base: stack.BaseBranch, Truncated: stack.Truncated, Rows: make([]*stackRow, len(stack.Entries))}
	current := 0
	siblings := map[int64]int{} // pull requests by the index of their parent
	for _, e := range stack.Entries {
		siblings[e.ParentIndex]++
	}
	for i, e := range stack.Entries {
		st := statuses[e.PR.ID]
		row := &stackRow{
			Index:        e.PR.Index,
			Title:        e.PR.Issue.Title,
			Link:         e.PR.Issue.Link(),
			Indent:       e.ParentIndex != 0 && siblings[e.ParentIndex] > 1,
			Current:      e.PR.ID == pull.ID,
			Commits:      int64(e.PR.CommitsAhead),
			HeadCommitID: st.HeadCommitID,
			Review:       stackReviewState(ctx, st.Review),
			Check:        stackCheckState(ctx, st.Check),
			Conflict:     e.PR.Status == issues_model.PullRequestStatusConflict,
		}
		// like the merge: a check or a rejection the rules of the base don't act on is a warning only
		switch {
		case row.Conflict:
			row.Block = "conflict"
		case st.RequiredCheck != "" && st.RequiredCheck.IsPending():
			row.Block = "checks_pending"
		case st.RequiredCheck != "" && !st.RequiredCheck.IsSuccess():
			row.Block = "checks_failed"
		case st.ReviewBlocks:
			row.Block = "review"
		case st.Check == api.CommitStatusFailure || st.Check == api.CommitStatusError:
			row.Warn = "checks"
		case st.Review == pull_service.StackReviewChangesRequested:
			row.Warn = "review"
		}
		view.Rows[i] = row
		if row.Current {
			current = i
		}
	}
	rowsByIndex := make(map[int64]*stackRow, len(view.Rows))
	for _, row := range view.Rows {
		rowsByIndex[row.Index] = row
	}
	firstChild := map[int64]bool{}
	for i, e := range stack.Entries {
		if row := view.Rows[i]; row.Indent {
			if firstChild[e.ParentIndex] {
				row.AlsoOn = rowsByIndex[e.ParentIndex]
			}
			firstChild[e.ParentIndex] = true
		}
	}
	view.Parent = rowsByIndex[stack.Entries[current].ParentIndex]
	view.Chain = view.Rows[:current+1]
	ctx.Data["Stack"] = view
	if view.Parent == nil {
		return
	}

	chainIndexes := make([]int64, len(view.Chain))
	for i, row := range view.Chain {
		chainIndexes[i] = row.Index
	}
	view.ChainLinks = stackLinks(ctx, chainIndexes)
	view.MaxMerge = pull_service.MaxMergeStackSize
	view.TooLong = len(view.Chain) > view.MaxMerge
	for _, row := range view.Chain {
		link := stackLink(ctx, row.Index)
		switch row.Block {
		case "conflict":
			view.Blocked = ctx.Tr("repo.pulls.stack.blocked_conflict", link)
		case "checks_pending":
			view.Blocked = ctx.Tr("repo.pulls.stack.blocked_checks_pending", link)
		case "checks_failed":
			view.Blocked = ctx.Tr("repo.pulls.stack.blocked_checks", link)
		case "review":
			view.Blocked = ctx.Tr("repo.pulls.stack.blocked_review", link)
		}
		switch row.Warn {
		case "checks":
			view.Warnings = append(view.Warnings, ctx.Tr("repo.pulls.stack.warn_checks", link))
		case "review":
			view.Warnings = append(view.Warnings, ctx.Tr("repo.pulls.stack.warn_review", link))
		}
		if view.Blocked != "" {
			break
		}
	}

	cfg := ctx.Repo.Repository.MustGetUnit(ctx, unit.TypePullRequests).PullRequestsConfig()
	for _, s := range []stackStyle{
		{string(repo_model.MergeStyleMerge), ctx.Tr("repo.pulls.merge_pull_request")},
		{string(repo_model.MergeStyleRebase), ctx.Tr("repo.pulls.rebase_merge_pull_request")},
		{string(repo_model.MergeStyleRebaseMerge), ctx.Tr("repo.pulls.rebase_merge_commit_pull_request")},
		{string(repo_model.MergeStyleSquash), ctx.Tr("repo.pulls.squash_merge_pull_request")},
		{string(repo_model.MergeStyleFastForwardOnly), ctx.Tr("repo.pulls.fast_forward_only_merge_pull_request")},
	} {
		if cfg.IsMergeStyleAllowed(repo_model.MergeStyle(s.Value)) {
			view.Styles = append(view.Styles, s)
		}
	}
	view.DefaultStyle = string(cfg.GetDefaultMergeStyle())
	view.DeleteDefault, _ = ctx.Data["DefaultDeleteBranchAfterMerge"].(bool)
	view.DeleteForced, _ = ctx.Data["DeleteBranchForced"].(bool)
	// the same decision as after the merge: only branches that DeleteBranchAfterMerge would delete are counted
	kept, err := branchworkflow.NewKeptChecker(ctx, ctx.Repo.Repository, false)
	if err != nil {
		ctx.ServerError("NewKeptChecker", err)
		return
	}
	for _, e := range stack.Entries[:current+1] {
		if e.PR.HeadRepoID == e.PR.BaseRepoID && e.PR.Flow != issues_model.PullRequestFlowAGit && kept.Reason(e.PR.HeadBranch) == "" {
			view.Deletable++
		} else {
			view.Kept++
		}
	}
	if view.MergeQueue, err = pull_service.StackRequiresMergeQueue(ctx, ctx.Repo.Repository.ID, stack.BaseBranch); err != nil {
		ctx.ServerError("StackRequiresMergeQueue", err)
		return
	}
	view.CanMerge = allowMerge && !view.MergeQueue && !ctx.Repo.PersonalRepoLocked && len(view.Styles) > 0
	if view.CanMerge && !view.TooLong && view.Blocked == "" {
		prepareStackChildren(ctx, view, stack, current)
	}
}

// maxStackChildren is the most pull requests the merge dialog lists by name.
const maxStackChildren = 20

// prepareStackChildren sets the other open pull requests that Merge stack moves onto the base: the ones based on the
// head branch of a pull request it merges, whether the panel shows them or not.
func prepareStackChildren(ctx *context.Context, view *stackView, stack *pull_service.Stack, current int) {
	chain := stack.Entries[:current+1]
	heads := make([]string, 0, len(chain))
	for _, e := range chain {
		if e.PR.CanBeStackParent() {
			heads = append(heads, e.PR.HeadBranch)
		}
	}
	prs, err := issues_model.GetUnmergedPullRequestsByBranches(ctx, ctx.Repo.Repository.ID, heads)
	if err != nil {
		ctx.ServerError("GetUnmergedPullRequestsByBranches", err)
		return
	}
	slices.SortFunc(prs, func(a, b *issues_model.PullRequest) int { return int(a.Index - b.Index) })
	var links []template.HTML
	for _, q := range prs {
		if !slices.Contains(heads, q.BaseBranch) || slices.ContainsFunc(chain, func(e *pull_service.StackEntry) bool { return e.PR.ID == q.ID }) {
			continue
		}
		view.ChildrenCount++
		if len(links) < maxStackChildren {
			links = append(links, stackLink(ctx, q.Index))
		}
	}
	if len(links) > 0 {
		sep := template.HTML(", ")
		view.Children = links[0]
		for _, l := range links[1:] {
			view.Children = templates.HTMLFormat("%s%s%s", view.Children, sep, l)
		}
		if view.ChildrenCount > len(links) {
			view.Children = templates.HTMLFormat("%s %s", view.Children, ctx.Tr("repo.pulls.stack.and_more", view.ChildrenCount-len(links)))
		}
	}
}

// stackLink returns a link to the pull request with the index in the repository.
func stackLink(ctx *context.Context, index int64) template.HTML {
	return templates.HTMLFormat(`<a href="%s/pulls/%d">#%d</a>`, ctx.Repo.RepoLink, index, index)
}

// stackLinks returns links to the pull requests with the indexes, as in "#1, #2 and #3".
func stackLinks(ctx *context.Context, indexes []int64) template.HTML {
	var out template.HTML
	for i, index := range indexes {
		switch {
		case i == 0:
			out = stackLink(ctx, index)
		case i == len(indexes)-1:
			out = templates.HTMLFormat("%s %s %s", out, ctx.Tr("repo.pulls.stack.and"), stackLink(ctx, index))
		default:
			out = templates.HTMLFormat("%s, %s", out, stackLink(ctx, index))
		}
	}
	return out
}

// lowerFirst returns s with its first letter in lower case, to follow a colon.
func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToLower(r)) + s[n:]
}

// stackCause returns why the cause of a failed Merge stack is a failure, and whether it stands for itself: it is not
// about the pull request that stopped the merge but about the stack as a whole.
func stackCause(ctx *context.Context, issue *issues_model.Issue, stopped int64, merged int, cause error) (reason any, alone, ok bool) {
	var disallowed models.ErrDisallowedToMerge
	switch {
	case errors.Is(cause, pull_service.ErrNotMergeableState):
		return ctx.Tr("repo.pulls.stack.not_mergeable"), false, true
	case errors.As(cause, &disallowed) && disallowed.Reason != "": // without a reason it is the viewer who may not merge
		return ctx.Tr("repo.pulls.stack.disallowed", lowerFirst(disallowed.Reason)), false, true
	case errors.Is(cause, pull_service.ErrIsChecking):
		return ctx.Tr("repo.pulls.stack.checking"), false, true
	}
	if message, ok := mergeCheckMessage(ctx, issue, cause); ok {
		return message, false, true
	}
	switch {
	case errors.Is(cause, pull_service.ErrStackChanged):
		return ctx.Tr("repo.pulls.stack.changed"), true, true
	case errors.Is(cause, pull_service.ErrStackTooLong):
		return ctx.Tr("repo.pulls.stack.too_long"), true, true
	case errors.Is(cause, pull_service.ErrStackMergeQueue):
		return ctx.Tr("repo.pulls.stack.merge_queue_refused"), true, true
	case errors.Is(cause, pull_service.ErrStackBaseIsHead):
		return ctx.Tr("repo.pulls.stack.base_is_head"), false, true
	case issues_model.IsErrPullRequestAlreadyExists(cause):
		return ctx.Tr("repo.pulls.stack.already_exists"), false, true
	case models.IsErrSHADoesNotMatch(cause):
		if merged == 0 {
			return ctx.Tr("repo.pulls.stack.head_changed", stackLink(ctx, stopped)), true, true
		}
		return ctx.Tr("repo.pulls.head_out_of_date"), false, true
	case models.IsErrInvalidMergeStyle(cause):
		return ctx.Tr("repo.pulls.invalid_merge_option"), false, true
	case models.IsErrMergeConflicts(cause):
		return ctx.Tr("repo.pulls.merge_conflict"), false, true
	case models.IsErrRebaseConflicts(cause):
		return ctx.Tr("repo.pulls.rebase_conflict", cause.(models.ErrRebaseConflicts).CommitSHA), false, true
	case models.IsErrMergeUnrelatedHistories(cause):
		return ctx.Tr("repo.pulls.unrelated_histories"), false, true
	case models.IsErrPullRequestHasMerged(cause):
		return ctx.Tr("repo.pulls.has_merged"), false, true
	case git.IsErrPushOutOfDate(cause):
		return ctx.Tr("repo.pulls.merge_out_of_date"), false, true
	case git.IsErrPushRejected(cause):
		return ctx.Tr("repo.pulls.push_rejected"), false, true
	}
	return nil, false, false
}

// MergeStack merges the pull requests of the stack of a pull request, from the bottom up to it.
func MergeStack(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.MergeStackForm)
	issue, ok := getPullInfo(ctx)
	if !ok {
		return
	}
	pr := issue.PullRequest
	pr.Issue = issue
	pr.Issue.Repo = ctx.Repo.Repository

	heads := make([]pull_service.StackHead, len(form.Heads))
	for i, h := range form.Heads {
		index, sha, _ := strings.Cut(h, ":")
		heads[i].Index, _ = strconv.ParseInt(index, 10, 64) // 0 never matches a pull request
		heads[i].HeadCommitID = sha
	}

	merged, mergeErr := pull_service.MergeStack(ctx, ctx.Doer, &ctx.Repo.Permission, pr, repo_model.MergeStyle(form.Do), heads)

	// If the HTTP request is cancelled by the user agent, don't stop work: the pull requests are merged.
	workCtx, cancelWorkCtx := stdCtx.WithTimeout(stdCtx.WithoutCancel(ctx), time.Duration(setting.Git.Timeout.Default)*time.Second)
	defer cancelWorkCtx()

	base := ""
	if len(merged) > 0 {
		alwaysDelete, err := branchworkflow.IsAlways(workCtx, ctx.Repo.Repository)
		if err != nil {
			ctx.ServerError("IsAlways", err)
			return
		}
		var kept []string
		for _, index := range merged {
			mpr, err := issues_model.GetPullRequestByIndex(workCtx, ctx.Repo.Repository.ID, index)
			if err == nil {
				err = mpr.LoadIssue(workCtx)
			}
			if err == nil {
				err = mpr.LoadHeadRepo(workCtx)
			}
			if err == nil {
				err = mpr.LoadBaseRepo(workCtx)
			}
			if err != nil {
				ctx.ServerError("GetPullRequestByIndex", err)
				return
			}
			base = mpr.BaseBranch
			if err := stopTimerIfAvailable(workCtx, ctx.Doer, mpr.Issue); err != nil {
				ctx.ServerError("stopTimerIfAvailable", err)
				return
			}
			if !form.DeleteBranchAfterMerge && !alwaysDelete {
				continue
			}
			headRepo := ctx.Repo.GitRepo
			if mpr.HeadRepoID != ctx.Repo.Repository.ID {
				if headRepo, err = gitrepo.OpenRepository(workCtx, mpr.HeadRepo); err != nil {
					ctx.ServerError("OpenRepository", err)
					return
				}
				defer headRepo.Close()
			}
			if err := repo_service.DeleteBranchAfterMerge(workCtx, ctx.Doer, mpr, headRepo); err != nil {
				message, ok := branchKeptMessage(ctx, err)
				if !ok {
					log.Error("DeleteBranchAfterMerge %-v: %v", mpr, err)
					message = ctx.Tr("repo.branch.deletion_failed", mpr.HeadBranch)
				}
				kept = append(kept, string(ctx.Tr("repo.pulls.stack.branch_kept", index, message)))
			}
		}
		if len(kept) > 0 {
			flash := ctx.Flash.Error
			if !form.DeleteBranchAfterMerge {
				flash = ctx.Flash.Info // deletion was forced by the setting: a kept branch is not an error
			}
			flash(template.HTML(strings.Join(kept, "<br>")))
		}
	}

	total := len(heads)
	if mergeErr == nil {
		ctx.Flash.Success(ctx.Locale.TrPluralString(len(merged), "repo.pulls.stack.merged", len(merged), base))
		ctx.Redirect(issue.Link())
		return
	}

	var stopped pull_service.ErrStackMerge
	cause := mergeErr
	if errors.As(mergeErr, &stopped) {
		cause = stopped.Err
	}
	reason, alone, ok := stackCause(ctx, issue, stopped.Index, len(merged), cause)
	if !ok {
		if len(merged) == 0 {
			ctx.ServerError("MergeStack", mergeErr)
			return
		}
		// some are merged already: say so and what is left
		log.Error("MergeStack %-v: %v", pr, mergeErr)
		reason, alone = ctx.Tr("repo.pulls.stack.unexpected"), false
	}
	switch {
	case len(merged) > 0:
		partial := ctx.Locale.TrPluralString(total, "repo.pulls.stack.merged_partial", len(merged), total, stackLink(ctx, stopped.Index), reason)
		ctx.Flash.Error(templates.HTMLFormat("%s<br> %s", partial, stackWhatNow(ctx, pr.Index, base, heads, len(merged))))
	case alone:
		ctx.Flash.Error(ctx.Tr("repo.pulls.stack.nothing_merged", reason))
	default:
		ctx.Flash.Error(ctx.Tr("repo.pulls.stack.nothing_merged", ctx.Tr("repo.pulls.stack.cant_merge", stackLink(ctx, stopped.Index), reason)))
	}
	ctx.Redirect(issue.Link())
}

// stackWhatNow says which pull requests of a stack that stopped are merged, which are still open, where they point
// now and what to do next. The first merged of heads are merged, base is where they went and top the pull request the
// merge was started from.
func stackWhatNow(ctx *context.Context, top int64, base string, heads []pull_service.StackHead, merged int) template.HTML {
	links := func(heads []pull_service.StackHead) template.HTML {
		indexes := make([]int64, len(heads))
		for i, h := range heads {
			indexes[i] = h.Index
		}
		return stackLinks(ctx, indexes)
	}
	done, open := heads[:merged], heads[merged:]
	next := stackLink(ctx, open[0].Index)
	var parts []template.HTML
	if len(done) == 1 {
		parts = append(parts, ctx.Tr("repo.pulls.stack.now_merged_one", links(done), base))
	} else {
		parts = append(parts, ctx.Tr("repo.pulls.stack.now_merged_many", links(done), base))
	}
	if len(open) == 1 {
		parts = append(parts, ctx.Tr("repo.pulls.stack.now_open_one", links(open), base))
	} else {
		parts = append(parts, ctx.Tr("repo.pulls.stack.now_open_many", links(open), next, base))
	}
	if open[len(open)-1].Index == top && len(open) == 1 {
		parts = append(parts, ctx.Tr("repo.pulls.stack.fix_again", next))
	} else {
		parts = append(parts, ctx.Tr("repo.pulls.stack.fix_from", next, stackLink(ctx, top)))
	}
	return templates.HTMLFormat("%s %s %s", parts[0], parts[1], parts[2])
}
