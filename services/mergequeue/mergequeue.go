// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package mergequeue merges pull requests one after the other, each tested combined with the ones ahead of it.
//
// Each entry of the queue of a branch is built on top of the entry ahead of it (the first on the branch): the
// pull request is merged with its merge style and the result pushed to the branch TempBranch, without hooks. The
// required status checks of the branch protection must pass on that commit. When the first entry passes, or a later
// one within the group size, the branch is fast-forwarded to each tested commit in turn through the normal hooks, so
// what lands is exactly what was tested. An entry that fails leaves the queue; the ones behind it are built again.
package mergequeue

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
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
	issue_service "forgejo.org/services/issue"
	notify_service "forgejo.org/services/notify"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
	shared "forgejo.org/services/shared/mergequeue"
)

var (
	// ErrNotRequired is returned when a pull request is added to the queue of a branch that has none
	ErrNotRequired = errors.New("the target branch does not use a merge queue")
	// ErrNotQueued is returned when a pull request that is not queued is removed
	ErrNotQueued = errors.New("the pull request is not in the merge queue")
	// ErrMerging is returned when the pull request can no longer be removed: the queue is merging it
	ErrMerging = errors.New("the pull request is being merged")
)

// Reasons an entry leaves the queue without being merged, shown by repo/issue/view_content/merge_queue_reason
const (
	ReasonRemoved       = "removed" // by a user
	ReasonEmpty         = "empty"   // it changes nothing on top of the branch and the entries ahead
	ReasonBuildFailed   = "build_failed"
	ReasonChecksFailed  = "checks_failed"
	ReasonTimeout       = "timeout"
	ReasonHeadMoved     = "head_moved"
	ReasonClosed        = "closed"
	ReasonRetargeted    = "retargeted"
	ReasonPermission    = "permission"
	ReasonBlocked       = "blocked"
	ReasonConflict      = "conflict"
	ReasonWIP           = "wip"
	ReasonDisabled      = "disabled"
	ReasonBranchMissing = "branch_missing"
	ReasonMergeFailed   = "merge_failed"
)

// one pass at a time per branch in this process; between processes, every state change is a conditional update and
// the fast-forward push refuses anything else. A pass asked for while one runs (from another worker, or from a
// notifier of the running pass when the queue runs immediately) makes the running one go again.
var running = struct {
	sync.Mutex
	again map[string]bool // the branches with a running pass, true when it must run again
}{again: map[string]bool{}}

// maxRounds bounds the passes in a row; more are left to the queue
const maxRounds = 20

// mergeStuckAfter is how long after a merge push started its build at the branch tip counts as merged but not
// recorded (a server that stopped between the push and its post-receive hook)
var mergeStuckAfter = 10 * time.Minute

// maxBuildFailures is how many failed builds in a row take an entry out of the queue
const maxBuildFailures = 3

func claim(key string) bool {
	running.Lock()
	defer running.Unlock()
	if _, ok := running.again[key]; ok {
		running.again[key] = true
		return false
	}
	running.again[key] = false
	return true
}

// next reports whether the pass must run again, and clears the request
func next(key string, again bool) bool {
	running.Lock()
	defer running.Unlock()
	again = again || running.again[key]
	running.again[key] = false
	return again
}

// release ends the claim; it reports whether a pass was asked for since the last next
func release(key string) bool {
	running.Lock()
	defer running.Unlock()
	again := running.again[key]
	delete(running.again, key)
	return again
}

// Init starts the queue that runs the passes
func Init() error {
	notify_service.RegisterNotifier(&notifier{})
	shared.Queue = queue.CreateUniqueQueue(graceful.GetManager().ShutdownContext(), "merge_queue", handler)
	if shared.Queue == nil {
		return errors.New("unable to create merge_queue queue")
	}
	go graceful.GetManager().RunWithCancel(shared.Queue)
	return nil
}

func handler(items ...string) []string {
	// the queue retries unhandled items, so the merge queues wait while maintenance mode is on
	if setting.GetMaintenance(graceful.GetManager().ShutdownContext()).ReadOnly() {
		return items
	}
	for _, key := range items {
		repoID, branch, ok := shared.ParseKey(key)
		if !ok {
			log.Error("could not parse merge queue key %q", key)
			continue
		}
		ctx, _, finished := process.GetManager().AddContext(audit_model.WithSystem(graceful.GetManager().HammerContext(), "merge_queue:"+key), fmt.Sprintf("Merge queue of %s in repository %d", branch, repoID))
		if err := Process(ctx, repoID, branch); err != nil {
			log.Error("Merge queue of %s in repository %d: %v", branch, repoID, err)
		}
		finished()
	}
	return nil
}

// TriggerAll starts a pass of every queue, for the time-outs and the wait times
func TriggerAll(ctx context.Context) error {
	keys, err := pull_model.FindMergeQueueKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		shared.Trigger(k.RepoID, k.BaseBranch)
	}
	return nil
}

// Rule returns the protection rule that sets the merge queue of the base branch of pr, nil if it has none
func Rule(ctx context.Context, pr *issues_model.PullRequest) (*git_model.ProtectedBranch, error) {
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		return nil, err
	}
	return git_model.MergeQueueRule(rules), nil
}

// queueStyle is the merge style the queue uses for a pull request the user chose style for
func queueStyle(rule *git_model.ProtectedBranch, style repo_model.MergeStyle) repo_model.MergeStyle {
	if rule.MergeQueueMergeStyle != "" {
		return repo_model.MergeStyle(rule.MergeQueueMergeStyle)
	}
	return style
}

// AddOptions are the choices of a merge that adds a pull request to the merge queue
type AddOptions struct {
	Style        repo_model.MergeStyle
	ExpectedHead string // if set, the head of the pull request must be this commit
	DeleteBranch bool
	SkipForward  bool // don't merge it forward; the caller checked that doer may skip it
	Force        bool // a site or repository admin's merge that skips the exempt branch protections
}

// Add adds pr to the merge queue of its base branch for doer, after the checks of a merge with opts.
func Add(ctx context.Context, doer *user_model.User, perm *access_model.Permission, pr *issues_model.PullRequest, opts AddOptions) error {
	// the queue merges as the user who added it, and access token identities and the Actions user are no users
	if doer == nil || doer.ID <= 0 {
		return util.ErrPermissionDenied
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return err
	}
	rule, err := Rule(ctx, pr)
	if err != nil {
		return err
	} else if rule == nil {
		return ErrNotRequired
	}
	style := queueStyle(rule, opts.Style)
	// fast-forward only can't be combined with the pull requests ahead
	if style != repo_model.MergeStyleMerge && style != repo_model.MergeStyleRebase && style != repo_model.MergeStyleRebaseMerge && style != repo_model.MergeStyleSquash {
		return models.ErrInvalidMergeStyle{ID: pr.BaseRepoID, Style: style}
	}
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return err
	}
	if !prUnit.PullRequestsConfig().IsMergeStyleAllowed(style) {
		return models.ErrInvalidMergeStyle{ID: pr.BaseRepoID, Style: style}
	}
	if l, err := quota_model.GetPersonalRepoLimit(ctx, pr.BaseRepo.OwnerID); err != nil {
		return err
	} else if l.Reached() {
		return quota_model.ErrPersonalRepoLimit{PersonalRepoLimit: l, OwnerID: pr.BaseRepo.OwnerID}
	}
	if err := pull_service.CheckPullMergeable(ctx, doer, perm, pr, pull_service.MergeCheckTypeGeneral, opts.Force, style); err != nil {
		return err
	}

	gitRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(ctx, pr.BaseRepo)
	if err != nil {
		return err
	}
	defer closer.Close()
	head, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
	if err != nil {
		return err
	}
	if opts.ExpectedHead != "" && opts.ExpectedHead != head {
		return models.ErrSHADoesNotMatch{GivenSHA: opts.ExpectedHead, CurrentSHA: head}
	}

	if err := db.WithTx(ctx, func(ctx context.Context) error {
		if err := pull_model.AddToMergeQueue(ctx, &pull_model.MergeQueueEntry{
			RepoID:       pr.BaseRepoID,
			BaseBranch:   pr.BaseBranch,
			PullID:       pr.ID,
			MergeStyle:   style,
			DeleteBranch: opts.DeleteBranch,
			SkipForward:  opts.SkipForward,
			Forced:       opts.Force,
			HeadCommitID: head,
			EnqueuedByID: doer.ID,
		}); err != nil {
			return err
		}
		_, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRAddedToMergeQueue, pr, doer, issues_model.AutoMergeInfo{})
		return err
	}); err != nil {
		return err
	}
	shared.Trigger(pr.BaseRepoID, pr.BaseBranch)
	return nil
}

// MayRemove reports whether doer may take pr, queued by entry, out of the queue: the author of the pull request, who
// added it, and everyone who may merge it
func MayRemove(ctx context.Context, doer *user_model.User, perm access_model.Permission, pr *issues_model.PullRequest, entry *pull_model.MergeQueueEntry) (bool, error) {
	if doer == nil {
		return false, nil
	}
	if err := pr.LoadIssue(ctx); err != nil {
		return false, err
	}
	if doer.ID == entry.EnqueuedByID || doer.ID == pr.Issue.PosterID {
		return true, nil
	}
	return pull_service.IsUserAllowedToMerge(ctx, pr, perm, doer)
}

// Remove takes pr out of the merge queue for doer; the pull requests behind it are built again
func Remove(ctx context.Context, doer *user_model.User, perm access_model.Permission, pr *issues_model.PullRequest) error {
	entry, err := pull_model.GetMergeQueueEntryByPullID(ctx, pr.ID)
	if err != nil {
		return err
	} else if entry == nil {
		return ErrNotQueued
	}
	if ok, err := MayRemove(ctx, doer, perm, pr, entry); err != nil {
		return err
	} else if !ok {
		return util.ErrPermissionDenied
	}
	if err := removeEntry(ctx, pr, entry, doer, ReasonRemoved, ""); err != nil {
		return err
	}
	shared.Trigger(entry.RepoID, entry.BaseBranch)
	return nil
}

// removeEntry deletes entry with a timeline comment by doer, unless it was deleted meanwhile
func removeEntry(ctx context.Context, pr *issues_model.PullRequest, entry *pull_model.MergeQueueEntry, doer *user_model.User, reason, sha string) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		del := pull_model.DeleteMergeQueueEntry
		if reason == ReasonRemoved {
			del = pull_model.DeleteMergeQueueEntryUnlessMerging // a merge under way wins over a removal by hand
		}
		if deleted, err := del(ctx, entry.ID); err != nil {
			return err
		} else if !deleted {
			if reason == ReasonRemoved {
				if e, err := pull_model.GetMergeQueueEntryByPullID(ctx, pr.ID); err != nil {
					return err
				} else if e != nil {
					return ErrMerging
				}
			}
			return nil
		}
		_, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRRemovedFromMergeQueue, pr, doer, issues_model.AutoMergeInfo{Reason: reason, SHA: sha})
		return err
	})
}

// item is an entry of the queue during a pass
type item struct {
	*pull_model.MergeQueueEntry
	pr     *issues_model.PullRequest
	doer   *user_model.User
	passed bool
}

type pass struct {
	ctx     context.Context
	repo    *repo_model.Repository
	gitRepo *git.Repository
	branch  string
	rules   git_model.ProtectedBranchRules
	cfg     git_model.MergeQueueConfig
	again   bool // start another pass when this one ends
}

// Process looks at the merge queue of the branch: it removes the entries that may no longer be merged, merges the
// ones whose builds passed, and builds the next ones.
func Process(ctx context.Context, repoID int64, branch string) error {
	key := shared.Key(repoID, branch)
	if !claim(key) {
		return nil
	}
	more := false
	defer func() {
		// on every way out, errors and panics included, so the branch is never left claimed
		if release(key) || more {
			shared.Trigger(repoID, branch)
		}
	}()
	for range maxRounds {
		again, err := processOnce(ctx, repoID, branch)
		if err != nil {
			return err
		}
		if !next(key, again) {
			return nil
		}
	}
	more = true
	return nil
}

func processOnce(ctx context.Context, repoID int64, branch string) (again bool, err error) {
	entries, err := pull_model.FindMergeQueue(ctx, repoID, branch)
	if err != nil {
		return false, err
	}
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if repo_model.IsErrRepoNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return false, err
	}
	defer gitRepo.Close()

	p := &pass{ctx: ctx, repo: repo, gitRepo: gitRepo, branch: branch}
	defer func() {
		p.deleteStaleBranches()
		again = p.again
	}()
	if len(entries) == 0 || repo.IsArchived {
		return false, nil
	}
	if err := repo.LoadOwner(ctx); err != nil {
		return false, err
	} else if repo.Owner.IsArchived { // an archived organization's repositories take no writes
		return false, nil
	}
	// the builds and merges go to this repository, which the size limit of its owner's personal repositories locks
	if l, err := quota_model.GetPersonalRepoLimit(ctx, repo.OwnerID); err != nil {
		return false, err
	} else if l.Reached() {
		return false, nil
	}

	if p.rules, err = git_model.GetMatchedProtectedBranchRules(ctx, repoID, branch); err != nil {
		return false, err
	}
	rule := git_model.MergeQueueRule(p.rules)
	tip, tipErr := gitRepo.GetBranchCommitID(branch)
	if rule == nil || tipErr != nil {
		reason := ReasonDisabled
		if tipErr != nil {
			reason = ReasonBranchMissing
		}
		for _, e := range entries {
			if err := p.removeByID(e, reason); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	p.cfg = rule.MergeQueueConfig()

	live, err := p.checkEntries(entries)
	if err != nil {
		return false, err
	}
	if merging, err := p.checkChain(live, tip); err != nil || merging {
		return false, err
	}
	if live, err = p.checkResults(live); err != nil {
		return false, err
	}
	merged, ok := p.merge(live)
	if !ok {
		return false, nil
	}
	if merged > 0 {
		tip = live[merged-1].TempCommitID
	}
	return false, p.build(live[merged:], tip)
}

// removeByID removes an entry whose pull request is not loaded yet
func (p *pass) removeByID(e *pull_model.MergeQueueEntry, reason string) error {
	pr, err := issues_model.GetPullRequestByID(p.ctx, e.PullID)
	if issues_model.IsErrPullRequestNotExist(err) {
		_, err := pull_model.DeleteMergeQueueEntry(p.ctx, e.ID)
		return err
	} else if err != nil {
		return err
	}
	return removeEntry(p.ctx, pr, e, p.poster(e), reason, "")
}

// poster is who the timeline comments of the queue about e are posted as: whoever added it, or a ghost
func (p *pass) poster(e *pull_model.MergeQueueEntry) *user_model.User {
	u, err := user_model.GetPossibleUserByID(p.ctx, e.EnqueuedByID)
	if err != nil {
		return user_model.NewGhostUser()
	}
	return u
}

func (p *pass) remove(it *item, reason, sha string) error {
	log.Info("Merge queue of %s in %-v: removing %-v (%s)", p.branch, p.repo, it.pr, reason)
	p.again = true
	return removeEntry(p.ctx, it.pr, it.MergeQueueEntry, it.doer, reason, sha)
}

// checkEntries removes the entries whose pull requests may no longer be merged and returns the others in order
func (p *pass) checkEntries(entries []*pull_model.MergeQueueEntry) ([]*item, error) {
	live := make([]*item, 0, len(entries))
	for _, e := range entries {
		pr, err := issues_model.GetPullRequestByID(p.ctx, e.PullID)
		if issues_model.IsErrPullRequestNotExist(err) {
			if _, err := pull_model.DeleteMergeQueueEntry(p.ctx, e.ID); err != nil {
				return nil, err
			}
			continue
		} else if err != nil {
			return nil, err
		}
		pr.BaseRepo = p.repo
		if pr.HasMerged {
			if _, err := pull_model.DeleteMergeQueueEntry(p.ctx, e.ID); err != nil {
				return nil, err
			}
			continue
		}
		it := &item{MergeQueueEntry: e, pr: pr, doer: p.poster(e)}
		reason, err := p.ineligible(it)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			if err := p.remove(it, reason, ""); err != nil {
				return nil, err
			}
			continue
		}
		live = append(live, it)
	}
	return live, nil
}

// ineligible returns why it may no longer be merged, "" if it may. The branch protection is checked as when the entry
// was added: rules exempt for admins are skipped only if an admin added it with force, and is still exempt.
func (p *pass) ineligible(it *item) (string, error) {
	pr := it.pr
	if err := pr.LoadIssue(p.ctx); err != nil {
		return "", err
	}
	if pr.Issue.IsClosed {
		return ReasonClosed, nil
	}
	if pr.BaseBranch != it.BaseBranch {
		return ReasonRetargeted, nil
	}
	if head, err := p.gitRepo.GetRefCommitID(pr.GetGitRefName()); err != nil || head != it.HeadCommitID {
		return ReasonHeadMoved, nil
	}

	doer := it.doer
	if doer.ID <= 0 || !doer.IsActive || doer.ProhibitLogin {
		return ReasonPermission, nil
	}
	perm, err := access_model.GetUserRepoPermission(p.ctx, p.repo, doer)
	if err != nil {
		return "", err
	}
	if allowed, err := pull_service.IsUserAllowedToMerge(p.ctx, pr, perm, doer); err != nil {
		return "", err
	} else if !allowed {
		return ReasonPermission, nil
	}

	if pr.IsWorkInProgress(p.ctx) {
		return ReasonWIP, nil
	}
	if err := issue_service.CheckPRTitleRule(p.ctx, p.repo, p.branch, pr.Issue.Title, true); err != nil {
		if git_model.IsErrPRTitleRule(err) {
			return ReasonBlocked, nil
		}
		return "", err
	}
	if noDeps, err := issues_model.IssueNoDependenciesLeft(p.ctx, pr.Issue); err != nil {
		return "", err
	} else if !noDeps {
		return ReasonBlocked, nil
	}
	exempt := func(pb *git_model.ProtectedBranch) bool {
		if !it.Forced {
			return false
		}
		ok, err := pb.IsAdminExempt(p.ctx, doer, perm.IsAdmin())
		if err != nil {
			log.Error("IsAdminExempt: %v", err)
		}
		return ok
	}
	if _, err := pull_service.CheckPullBranchProtections(p.ctx, pr, false, exempt); err != nil {
		if models.IsErrDisallowedToMerge(err) {
			return ReasonBlocked, nil
		}
		return "", err
	}
	return "", nil
}

// checkChain makes the builds that are not on top of the branch tip and the builds ahead of them wait to be built
// again: after a push to the branch, or when an entry ahead left the queue
func (p *pass) checkChain(live []*item, tip string) (merging bool, err error) {
	// the branch is at a build of the chain: another server merged it and marks the pull requests merged, its pass
	// goes on from there
	for i, prev := 0, ""; i < len(live) && live[i].Status != pull_model.MergeQueueWaiting && (i == 0 || live[i].BaseCommitID == prev); i++ {
		if live[i].BaseCommitID == tip {
			break
		}
		if live[i].TempCommitID == tip {
			// its build is in the branch: pushed by the queue and never recorded, or pushed by a user who may push
			if i == 0 && (live[0].MergingUnix == 0 || since(live[0].MergingUnix) > mergeStuckAfter) {
				p.finishMerge(live[0])
			}
			return true, nil
		}
		prev = live[i].TempCommitID
	}
	prev, valid := tip, true
	var reset []int64
	for _, it := range live {
		if it.Status != pull_model.MergeQueueBuilding {
			valid = false
			continue
		}
		if valid && it.BaseCommitID == prev {
			prev = it.TempCommitID
			continue
		}
		valid = false
		reset = append(reset, it.ID)
		it.Status, it.BaseCommitID, it.TempCommitID, it.StartedUnix = pull_model.MergeQueueWaiting, "", "", 0
	}
	return false, pull_model.ResetMergeQueueBuilds(p.ctx, reset)
}

// checkResults reads the required status checks of the builds. The first failed build leaves the queue and the builds
// behind it wait to be built again without it.
func (p *pass) checkResults(live []*item) ([]*item, error) {
	for i, it := range live {
		if it.Status != pull_model.MergeQueueBuilding {
			break
		}
		state, err := p.checksState(it.TempCommitID, it.StartedUnix)
		if err != nil {
			return nil, err
		}
		var reason string
		switch {
		case state.IsSuccess():
			it.passed = true
			continue
		case state.IsFailure() || state.IsError():
			reason = ReasonChecksFailed
		case since(it.StartedUnix) > p.cfg.CheckTimeout:
			reason = ReasonTimeout
		default:
			continue
		}
		if err := p.remove(it, reason, it.TempCommitID); err != nil {
			return nil, err
		}
		behind := live[i+1:]
		var reset []int64
		for _, b := range behind {
			if b.Status == pull_model.MergeQueueBuilding {
				reset = append(reset, b.ID)
				b.Status, b.BaseCommitID, b.TempCommitID, b.StartedUnix = pull_model.MergeQueueWaiting, "", "", 0
			}
		}
		if err := pull_model.ResetMergeQueueBuilds(p.ctx, reset); err != nil {
			return nil, err
		}
		return append(live[:i:i], behind...), nil
	}
	return live, nil
}

// checksState is the state of the required status checks of every matching rule on sha; success without any
func (p *pass) checksState(sha string, started timeutil.TimeStamp) (stateResult, error) {
	statuses, _, err := git_model.GetLatestCommitStatus(p.ctx, p.repo.ID, sha, db.ListOptionsAll)
	if err != nil {
		return stateResult{}, err
	}
	// only statuses reported for the build count: a build can be the head commit of the pull request (rebase onto an
	// up-to-date branch), whose own pull request checks don't test it in the queue
	statuses = slices.DeleteFunc(statuses, func(s *git_model.CommitStatus) bool { return s.CreatedUnix < started })
	result := stateResult{success: true}
	for _, pb := range p.rules {
		if !pb.EnableStatusCheck {
			continue
		}
		state := pull_service.MergeRequiredContextsCommitStatus(statuses, pb.StatusCheckContexts)
		if state.IsFailure() || state.IsError() {
			return stateResult{failure: true}, nil
		}
		if !state.IsSuccess() {
			result.success = false
		}
	}
	return result, nil
}

type stateResult struct {
	success, failure bool
}

func (s stateResult) IsSuccess() bool { return s.success }
func (s stateResult) IsFailure() bool { return s.failure }
func (s stateResult) IsError() bool   { return false }

// merge fast-forwards the branch to the passed builds: the first one, or up to the last passed one within the group
// size, whose build has all the ones ahead of it. It returns how many entries it merged, and false when the pass
// must stop.
func (p *pass) merge(live []*item) (int, bool) {
	maxGroup := min(p.cfg.MaxGroupSize, p.cfg.BuildConcurrency)
	last := -1
	for i := 0; i < len(live) && i < maxGroup && live[i].Status == pull_model.MergeQueueBuilding; i++ {
		if live[i].passed {
			last = i
		}
	}
	if last < 0 {
		return 0, true
	}
	if last+1 < p.cfg.MinGroupSize && since(live[0].EnqueuedUnix) < p.cfg.WaitTime {
		return 0, true // wait for more pull requests
	}
	for i := 0; i <= last; i++ {
		it := live[i]
		if ok, err := pull_model.StartMergeQueueMerge(p.ctx, it.ID, it.TempCommitID); err != nil || !ok {
			if err != nil {
				log.Error("StartMergeQueueMerge[%d]: %v", it.ID, err)
			}
			p.again = true // removed or built again meanwhile
			return i, false
		}
		ctx := p.ctx
		if it.SkipForward {
			ctx = pull_service.WithoutMergeForward(ctx)
		}
		if err := pull_service.MergeQueued(ctx, it.pr, it.doer, p.branch, it.BaseCommitID, it.TempCommitID, false); err != nil {
			p.again = true
			if errors.Is(err, pull_service.ErrMergeQueueNotRecorded) {
				log.Error("Merge queue of %s in %-v: %v", p.branch, p.repo, err) // checkChain records it later
				return i, false
			}
			if git.IsErrPushOutOfDate(err) {
				// the branch moved: the next pass builds again on top of it
				log.Info("Merge queue of %s in %-v: the branch moved before %-v was merged", p.branch, p.repo, it.pr)
				return i, false
			}
			if models.IsErrPullRequestHasMerged(err) {
				_, err = pull_model.DeleteMergeQueueEntry(p.ctx, it.ID)
			} else {
				reason := ReasonMergeFailed
				if git.IsErrPushRejected(err) {
					reason = ReasonBlocked
				}
				log.Warn("Merge queue of %s in %-v: merging %-v failed: %v", p.branch, p.repo, it.pr, err)
				err = p.remove(it, reason, "")
			}
			if err != nil {
				log.Error("Merge queue of %s in %-v: %v", p.branch, p.repo, err)
			}
			return i, false
		}
		if _, err := pull_model.DeleteMergeQueueEntry(p.ctx, it.ID); err != nil {
			log.Error("DeleteMergeQueueEntry[%d]: %v", it.ID, err)
		}
		p.deleteHeadBranch(it)
	}
	p.again = true
	return last + 1, true
}

// finishMerge records the merge of a build the branch is already at
func (p *pass) finishMerge(it *item) {
	// a server that started merging it since this pass read the queue records it itself
	if e, err := pull_model.GetMergeQueueEntryByPullID(p.ctx, it.PullID); err != nil || e == nil || e.ID != it.ID ||
		(e.MergingUnix != 0 && since(e.MergingUnix) <= mergeStuckAfter) {
		return
	}
	log.Warn("Merge queue of %s in %-v: recording the merge of %-v at %s", p.branch, p.repo, it.pr, it.TempCommitID)
	ctx := p.ctx
	if it.SkipForward {
		ctx = pull_service.WithoutMergeForward(ctx)
	}
	if err := pull_service.MergeQueued(ctx, it.pr, it.doer, p.branch, it.BaseCommitID, it.TempCommitID, true); err != nil && !models.IsErrPullRequestHasMerged(err) {
		log.Error("Merge queue of %s in %-v: recording the merge of %-v: %v", p.branch, p.repo, it.pr, err)
		return
	}
	if _, err := pull_model.DeleteMergeQueueEntry(p.ctx, it.ID); err != nil {
		log.Error("DeleteMergeQueueEntry[%d]: %v", it.ID, err)
	}
	p.deleteHeadBranch(it)
	p.again = true
}

// deleteHeadBranch deletes the head branch of a merged pull request if that was asked for, or the repository always
// does it
func (p *pass) deleteHeadBranch(it *item) {
	alwaysDelete, err := branchworkflow.IsAlways(p.ctx, p.repo)
	if err != nil {
		log.Error("branchworkflow.IsAlways: %v", err)
	}
	if !it.DeleteBranch && !alwaysDelete {
		return
	}
	if err := it.pr.LoadHeadRepo(p.ctx); err != nil || it.pr.HeadRepo == nil {
		return
	}
	headRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(p.ctx, it.pr.HeadRepo)
	if err != nil {
		log.Error("OpenRepository: %v", err)
		return
	}
	defer closer.Close()
	if err := repo_service.DeleteBranchAfterMerge(p.ctx, it.doer, it.pr, headRepo); err != nil {
		log.Info("Merge queue: the head branch of %-v was kept: %v", it.pr, err)
	}
}

// build builds the waiting entries within the build concurrency, each on top of the one ahead of it
func (p *pass) build(live []*item, tip string) error {
	prev := tip
	for i, it := range live {
		if i >= p.cfg.BuildConcurrency {
			break
		}
		if it.Status == pull_model.MergeQueueBuilding {
			prev = it.TempCommitID
			continue
		}
		rule := git_model.MergeQueueRule(p.rules)
		// the build is claimed before it is pushed, so another server building the same entry never pushes over it
		started := false
		sha, err := pull_service.BuildMergeQueueCommit(p.ctx, it.pr, it.doer, queueStyle(rule, it.MergeStyle), it.HeadCommitID, prev, it.TempBranch(), func(sha string) (ok bool, err error) {
			started, err = pull_model.StartMergeQueueBuild(p.ctx, it.ID, prev, sha)
			return started, err
		})
		if err != nil {
			switch {
			case models.IsErrMergeConflicts(err), models.IsErrRebaseConflicts(err), models.IsErrMergeUnrelatedHistories(err):
				if err := p.remove(it, ReasonConflict, ""); err != nil {
					return err
				}
				continue
			case models.IsErrSHADoesNotMatch(err):
				if err := p.remove(it, ReasonHeadMoved, ""); err != nil {
					return err
				}
				continue
			case errors.Is(err, pull_service.ErrMergeQueueEmptyBuild):
				if err := p.remove(it, ReasonEmpty, ""); err != nil {
					return err
				}
				continue
			case !started && p.ctx.Err() == nil:
				// a build that keeps failing (its head repository is gone, say) would stop the queue on every pass
				if n, ferr := pull_model.AddMergeQueueBuildFailure(p.ctx, it.ID); ferr != nil {
					log.Error("AddMergeQueueBuildFailure[%d]: %v", it.ID, ferr)
				} else if n >= maxBuildFailures {
					log.Warn("Merge queue of %s in %-v: building %-v failed %d times: %v", p.branch, p.repo, it.pr, n, err)
					if err := p.remove(it, ReasonBuildFailed, ""); err != nil {
						return err
					}
					continue
				}
			}
			if started { // the push failed: build it again
				if rerr := pull_model.ResetMergeQueueBuilds(p.ctx, []int64{it.ID}); rerr != nil {
					log.Error("ResetMergeQueueBuilds [%d]: %v", it.ID, rerr)
				}
			}
			return fmt.Errorf("build of %v: %w", it.pr, err)
		}
		if sha == "" {
			return nil // another server builds it
		}
		it.Status, it.BaseCommitID, it.TempCommitID, it.StartedUnix = pull_model.MergeQueueBuilding, prev, sha, timeutil.TimeStampNow()
		log.Trace("Merge queue of %s in %-v: built %-v at %s", p.branch, p.repo, it.pr, sha)
		notify_service.MergeGroupChecksRequested(p.ctx, it.doer, p.repo, it.MergeQueueEntry)
		p.again = true // a build without required checks passes at once
		prev = sha
	}
	return nil
}

// deleteStaleBranches deletes the build branches of the queue that belong to no entry
func (p *pass) deleteStaleBranches() {
	deleteStaleBuildBranches(p.ctx, p.repo, p.branch)
}

// deleteStaleBuildBranches deletes the build branches of branch in repo that belong to no entry of its queue. It lists
// the branches before it reads the entries, so a build another server makes meanwhile is never taken for a stale one.
func deleteStaleBuildBranches(ctx context.Context, repo *repo_model.Repository, branch string) {
	prefix := git.BranchPrefix + pull_model.MergeQueueBranchPrefix + branch + "/"
	stdout, _, err := git.NewCommand(ctx, "for-each-ref", "--format=%(refname)").AddDynamicArguments(prefix).RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
	if err != nil {
		log.Error("for-each-ref %s in %-v: %v", prefix, repo, err)
		return
	}
	refs := strings.Fields(stdout)
	if len(refs) == 0 {
		return
	}
	entries, ferr := pull_model.FindMergeQueue(ctx, repo.ID, branch)
	if ferr != nil {
		log.Error("FindMergeQueue: %v", ferr)
		return
	}
	live := make(map[int64]bool, len(entries))
	for _, e := range entries {
		live[e.ID] = true
	}
	for _, ref := range refs {
		id, err := strconv.ParseInt(strings.TrimPrefix(ref, prefix), 10, 64)
		if err != nil || live[id] {
			continue // another branch's build ("main" and "main/x"), or a live one
		}
		if err := git.NewCommand(ctx, "update-ref", "-d").AddDynamicArguments(ref).Run(&git.RunOpts{Dir: repo.RepoPath()}); err != nil {
			log.Error("Unable to delete %s in %-v: %v", ref, repo, err)
		}
	}
}

// DeleteStaleBranches deletes the build branches that belong to no entry in the repositories that have a merge
// queue rule (repository, project or organization), or entries: the ones a pass that ended early left behind
func DeleteStaleBranches(ctx context.Context) error {
	repoIDs, err := pull_model.FindMergeQueueRepoIDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range repoIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		repo, err := repo_model.GetRepositoryByID(ctx, id)
		if repo_model.IsErrRepoNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		stdout, _, err := git.NewCommand(ctx, "for-each-ref", "--format=%(refname:lstrip=3)").AddDynamicArguments(git.BranchPrefix + pull_model.MergeQueueBranchPrefix).RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
		if err != nil {
			log.Error("for-each-ref in %-v: %v", repo, err)
			continue
		}
		// one branch at a time, so a build of the branch "a/1" is never taken for build 1 of the branch "a"
		branches := map[string]bool{}
		for name := range strings.FieldsSeq(stdout) {
			if i := strings.LastIndexByte(name, '/'); i > 0 {
				branches[name[:i]] = true
			}
		}
		for branch := range branches {
			deleteStaleBuildBranches(ctx, repo, branch)
		}
	}
	return nil
}

// since is the time from t to now, on the clock the tests can set
func since(t timeutil.TimeStamp) time.Duration {
	return timeutil.TimeStampNow().AsTime().Sub(t.AsTime())
}
