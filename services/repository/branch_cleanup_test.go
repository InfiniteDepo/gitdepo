// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/queue"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupFixture is a bare repository user2/cleanup-unit made of c1 <- c2 <- c3 (master) and c2 <- c4 (unmerged).
type cleanupFixture struct {
	t          *testing.T
	repo       *repo_model.Repository
	c1, c2, c3 string
	c4         string
	issues     int64
}

func (f *cleanupFixture) git(env []string, args ...string) string {
	f.t.Helper()
	cmd := exec.CommandContext(f.t.Context(), "git", append([]string{"-C", f.repo.RepoPath()}, args...)...)
	cmd.Env = append([]string{"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "HOME=" + f.t.TempDir()}, env...)
	out, err := cmd.CombinedOutput()
	require.NoError(f.t, err, string(out))
	return strings.TrimSpace(string(out))
}

func (f *cleanupFixture) commit(date time.Time, parent string) string {
	f.t.Helper()
	d := fmt.Sprintf("%d +0000", date.Unix())
	args := []string{"commit-tree", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "-m", "c"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	return f.git([]string{"GIT_AUTHOR_DATE=" + d, "GIT_COMMITTER_DATE=" + d}, args...)
}

func newCleanupFixture(t *testing.T, name string) *cleanupFixture {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := &repo_model.Repository{
		ID: 9100, OwnerID: 2, OwnerName: "user2", Name: name, LowerName: name, DefaultBranch: "master",
		Status: repo_model.RepositoryReady, ObjectFormatName: "sha1",
	}
	require.NoError(t, git.InitRepository(t.Context(), repo.RepoPath(), true, "sha1"))
	_, err := db.GetEngine(t.Context()).Insert(repo)
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypePullRequests, Config: &repo_model.PullRequestsConfig{}}))
	f := &cleanupFixture{t: t, repo: repo}
	// the commit dates are old: they must never decide anything
	old := time.Now().AddDate(-5, 0, 0)
	f.c1 = f.commit(old, "")
	f.c2 = f.commit(old, f.c1)
	f.c3 = f.commit(old, f.c2)
	f.c4 = f.commit(time.Now(), f.c2)
	f.git(nil, "update-ref", "refs/heads/master", f.c3)
	f.git(nil, "symbolic-ref", "HEAD", "refs/heads/master")
	f.branch("master", f.c3, 0)
	return f
}

// branch creates the ref and its row, updated daysAgo days ago (the row's own clock, never the commit's).
func (f *cleanupFixture) branch(name, commit string, daysAgo int) {
	f.t.Helper()
	f.git(nil, "update-ref", "refs/heads/"+name, commit)
	require.NoError(f.t, db.Insert(f.t.Context(), &git_model.Branch{RepoID: f.repo.ID, Name: name, CommitID: commit, PusherID: 2}))
	f.backdate(name, daysAgo)
}

func (f *cleanupFixture) backdate(name string, daysAgo int) {
	f.t.Helper()
	_, err := db.GetEngine(f.t.Context()).Exec("UPDATE branch SET updated_unix = ? WHERE repo_id = ? AND name = ?", time.Now().Unix()-int64(daysAgo)*86400, f.repo.ID, name)
	require.NoError(f.t, err)
}

func (f *cleanupFixture) merged(head string, daysAgo int) {
	f.t.Helper()
	pr := &issues_model.PullRequest{IssueID: f.issue(true).ID, HeadRepoID: f.repo.ID, BaseRepoID: f.repo.ID, HeadBranch: head, BaseBranch: "master", HasMerged: true}
	require.NoError(f.t, db.Insert(f.t.Context(), pr))
	f.backdatePR(pr, daysAgo)
}

// backdatePR sets the merge time by UPDATE: xorm stamps merged_unix itself on insert.
func (f *cleanupFixture) backdatePR(pr *issues_model.PullRequest, daysAgo int) {
	f.t.Helper()
	_, err := db.GetEngine(f.t.Context()).Exec("UPDATE pull_request SET merged_unix = ? WHERE id = ?", time.Now().Unix()-int64(daysAgo)*86400, pr.ID)
	require.NoError(f.t, err)
}

// issue inserts the issue row of a pull request.
func (f *cleanupFixture) issue(closed bool) *issues_model.Issue {
	f.t.Helper()
	f.issues++
	issue := &issues_model.Issue{RepoID: f.repo.ID, Index: f.issues, PosterID: 2, Title: "x", IsPull: true, IsClosed: closed}
	require.NoError(f.t, db.Insert(f.t.Context(), issue))
	return issue
}

func (f *cleanupFixture) setDays(days int) *repo_model.Repository {
	f.t.Helper()
	stored, has, err := repo_model.GetRepoUnitForUpdate(f.t.Context(), f.repo.ID, unit.TypePullRequests)
	require.NoError(f.t, err)
	require.True(f.t, has)
	stored.PullRequestsConfig().BranchCleanup = &repo_model.BranchCleanup{Days: days}
	require.NoError(f.t, repo_model.UpdateRepoUnit(f.t.Context(), stored))
	// the days are in force, as if their waiting period had passed
	require.NoError(f.t, repo_model.SaveBranchCleanupState(f.t.Context(), &repo_model.BranchCleanupState{RepoID: f.repo.ID, Days: days}))
	repo, err := repo_model.GetRepositoryByID(f.t.Context(), f.repo.ID)
	require.NoError(f.t, err)
	return repo
}

// noPushQueue replaces the push queue by one that drops what it gets, for tests that delete branches.
func noPushQueue(t *testing.T) {
	t.Helper()
	q := queue.CreateSimpleQueue(t.Context(), "push_update_test", func(items ...[]*repo_module.PushUpdateOptions) [][]*repo_module.PushUpdateOptions { return nil })
	go q.Run()
	t.Cleanup(func() { q.ShutdownWait(time.Second) })
	old := pushQueue
	pushQueue = q
	t.Cleanup(func() { pushQueue = old })
}

func names(list []CleanupBranch) []string {
	out := []string{}
	for _, b := range list {
		out = append(out, b.Name)
	}
	return out
}

func TestPlanBranchCleanupAge(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	f.branch("pr-old", f.c2, 90)
	f.merged("pr-old", 60)
	f.branch("pr-then-push", f.c2, 2) // merged 60 days ago, pushed to 2 days ago: the push restarts the clock
	f.merged("pr-then-push", 60)
	f.branch("no-pr-old", f.c1, 45)
	f.branch("no-pr-new", f.c1, 0) // its commits are five years old: the commit time is never used
	f.branch("at-tip", f.c3, 90)   // nothing was committed to it: not a merged branch
	f.branch("unmerged", f.c4, 90)

	plan, err := PlanBranchCleanup(t.Context(), f.repo, 30, time.Now())
	require.NoError(t, err)
	assert.Empty(t, plan.Skip)
	assert.Equal(t, []string{"master"}, plan.Targets)
	assert.Equal(t, []string{"pr-old", "no-pr-old"}, names(plan.Due)) // oldest first
	assert.ElementsMatch(t, []string{"pr-then-push", "no-pr-new"}, names(plan.NotDue))
	assert.Empty(t, plan.Kept)
	assert.Equal(t, f.c2, plan.Due[0].Commit)
	assert.Equal(t, "master", plan.Due[0].Into)

	// the same branches with another age
	plan, err = PlanBranchCleanup(t.Context(), f.repo, 365, time.Now())
	require.NoError(t, err)
	assert.Empty(t, plan.Due)
	assert.Len(t, plan.NotDue, 4)
	plan, err = PlanBranchCleanup(t.Context(), f.repo, 1, time.Now())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"pr-old", "no-pr-old", "pr-then-push"}, names(plan.Due))

	// a pull request from elsewhere or into a branch that is no target says nothing about the age
	f.branch("other-base", f.c1, 0)
	for _, pr := range []*issues_model.PullRequest{
		{IssueID: f.issue(true).ID, HeadRepoID: f.repo.ID, BaseRepoID: f.repo.ID, HeadBranch: "other-base", BaseBranch: "unmerged", HasMerged: true},
		{IssueID: f.issue(true).ID, HeadRepoID: f.repo.ID, BaseRepoID: 1, HeadBranch: "other-base", BaseBranch: "master", HasMerged: true},
	} {
		require.NoError(t, db.Insert(t.Context(), pr))
		f.backdatePR(pr, 90)
	}
	plan, err = PlanBranchCleanup(t.Context(), f.repo, 30, time.Now())
	require.NoError(t, err)
	assert.Contains(t, names(plan.NotDue), "other-base")
}

func TestPlanBranchCleanupKeptAndSkipped(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	f.branch("prot-1", f.c1, 90)
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: f.repo.ID, RuleName: "prot-*"}))
	f.branch("open-head", f.c1, 90)
	f.branch("plain", f.c1, 90)
	issue := f.issue(false)
	require.NoError(t, db.Insert(t.Context(), &issues_model.PullRequest{IssueID: issue.ID, Index: issue.Index, HeadRepoID: f.repo.ID, BaseRepoID: f.repo.ID, HeadBranch: "open-head", BaseBranch: "unmerged"}))

	plan, err := PlanBranchCleanup(t.Context(), f.repo, 30, time.Now())
	require.NoError(t, err)
	assert.Equal(t, []string{"plain"}, names(plan.Due))
	reasons := map[string]string{}
	for _, b := range plan.Kept {
		reasons[b.Name] = b.Reason
	}
	assert.Equal(t, map[string]string{"prot-1": "protected", "open-head": "open_pr"}, reasons)

	for reason, change := range map[string]func(r *repo_model.Repository){
		CleanupSkipArchived: func(r *repo_model.Repository) { r.IsArchived = true },
		CleanupSkipMirror:   func(r *repo_model.Repository) { r.IsMirror = true },
		CleanupSkipEmpty:    func(r *repo_model.Repository) { r.IsEmpty = true },
		CleanupSkipNotReady: func(r *repo_model.Repository) { r.Status = repo_model.RepositoryBeingMigrated },
		CleanupSkipTrashed:  func(r *repo_model.Repository) { r.TrashedUnix = 1 },
	} {
		r := *f.repo
		change(&r)
		plan, err := PlanBranchCleanup(t.Context(), &r, 30, time.Now())
		require.NoError(t, err, reason)
		assert.Equal(t, reason, plan.Skip)
		assert.Empty(t, plan.Due)
	}

	// the development branch of the model is missing
	stored, _, err := repo_model.GetRepoUnitForUpdate(t.Context(), f.repo.ID, unit.TypePullRequests)
	require.NoError(t, err)
	stored.PullRequestsConfig().BranchingModel = &repo_model.BranchingModel{DevelopmentBranch: "no-such-develop"}
	require.NoError(t, repo_model.UpdateRepoUnit(t.Context(), stored))
	r, err := repo_model.GetRepositoryByID(t.Context(), f.repo.ID)
	require.NoError(t, err)
	plan, err = PlanBranchCleanup(t.Context(), r, 30, time.Now())
	require.NoError(t, err)
	assert.Equal(t, CleanupSkipDevMissing, plan.Skip)

	// Pull requests off: no merge time is known
	_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", f.repo.ID, unit.TypePullRequests).Delete(&repo_model.RepoUnit{})
	require.NoError(t, err)
	r, err = repo_model.GetRepositoryByID(t.Context(), f.repo.ID)
	require.NoError(t, err)
	plan, err = PlanBranchCleanup(t.Context(), r, 30, time.Now())
	require.NoError(t, err)
	assert.Equal(t, CleanupSkipPullsOff, plan.Skip)
}

// A branch merged into the development branch counts as well as one merged into the default branch.
func TestPlanBranchCleanupDevelopmentBranch(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	tip := f.commit(time.Now(), f.c4)
	f.branch("develop", tip, 0)
	f.branch("into-both", f.c2, 90)
	f.branch("into-dev-only", f.c4, 90) // not in master
	stored, _, err := repo_model.GetRepoUnitForUpdate(t.Context(), f.repo.ID, unit.TypePullRequests)
	require.NoError(t, err)
	stored.PullRequestsConfig().BranchingModel = &repo_model.BranchingModel{DevelopmentBranch: "develop"}
	require.NoError(t, repo_model.UpdateRepoUnit(t.Context(), stored))
	r, err := repo_model.GetRepositoryByID(t.Context(), f.repo.ID)
	require.NoError(t, err)

	plan, err := PlanBranchCleanup(t.Context(), r, 30, time.Now())
	require.NoError(t, err)
	assert.Equal(t, []string{"develop", "master"}, plan.Targets)
	into := map[string]string{}
	for _, b := range plan.Due {
		into[b.Name] = b.Into
	}
	assert.Equal(t, map[string]string{"into-both": "develop", "into-dev-only": "develop"}, into)
	assert.Empty(t, plan.Kept) // the development and default branches are at their own tips: nothing to list
}

func newCleanupAudit(t *testing.T) *cleanupAudit {
	t.Helper()
	return &cleanupAudit{t: t}
}

type cleanupAudit struct{ t *testing.T }

// entries returns the audit entries of the action with the data of each.
func (a *cleanupAudit) entries(since int64, action string) []*audit_model.Entry {
	var out []*audit_model.Entry
	require.NoError(a.t, db.GetEngine(a.t.Context()).Where("id > ? AND action = ?", since, action).OrderBy("id").Find(&out))
	return out
}

func (a *cleanupAudit) max() int64 {
	var id int64
	_, err := db.GetEngine(a.t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(a.t, err)
	return id
}

func TestRunBranchCleanup(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	noPushQueue(t)
	f.branch("old-1", f.c1, 90)
	f.branch("old-2", f.c2, 90)
	f.branch("young", f.c2, 1)
	f.branch("moves", f.c2, 90) // a push lands between the plan and the delete
	f.branch("prot", f.c1, 90)
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: f.repo.ID, RuleName: "prot"}))
	ctx := audit_model.WithSystem(t.Context(), "cron:"+CleanupTaskName)
	a := newCleanupAudit(t)

	// off: nothing happens
	run, err := RunBranchCleanup(ctx, f.repo)
	require.NoError(t, err)
	assert.Equal(t, &CleanupRun{}, run)
	assert.Len(t, liveBranches(t, f.repo), 6)

	repo := f.setDays(30)

	// read-only maintenance pauses it
	func() {
		defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
		run, err := RunBranchCleanup(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, &CleanupRun{}, run)
		require.NoError(t, CleanupMergedBranches(ctx))
		assert.Len(t, liveBranches(t, f.repo), 6)
	}()

	since := a.max()
	defer test.MockVariableValue(&DeleteBranchTestHook, func(_ *repo_model.Repository, name string) {
		if name == "moves" { // pushed to after the plan: it must survive
			f.git(nil, "update-ref", "refs/heads/moves", f.c4)
		}
	})()
	run, err = RunBranchCleanup(ctx, repo)
	require.NoError(t, err)
	assert.Equal(t, &CleanupRun{Deleted: 2, Kept: 1}, run)
	assert.ElementsMatch(t, []string{"master", "young", "moves", "prot"}, liveBranches(t, f.repo))

	// one entry per branch, marked as the cleanup's, and one summary with the totals
	deleted := a.entries(since, "repo.branch.deleted")
	require.Len(t, deleted, 2)
	for _, e := range deleted {
		assert.Contains(t, e.Data, `"via":"cleanup"`)
		assert.Equal(t, audit_model.ActorSystem, e.ActorType)
	}
	summary := a.entries(since, "repo.branches.cleanup_deleted")
	require.Len(t, summary, 1)
	assert.Contains(t, summary[0].Data, `"days":30`)
	assert.Contains(t, summary[0].Data, `"deleted":2`)
	assert.Contains(t, summary[0].Data, "moves: new_commits")
	assert.Empty(t, a.entries(since, "repo.branches.bulk_deleted"))

	// every deleted branch can be restored: its row is kept as a deleted branch, at its commit
	deletedRow := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: f.repo.ID, Name: "old-1"})
	assert.True(t, deletedRow.IsDeleted)
	assert.Equal(t, f.c1, deletedRow.CommitID)
	assert.EqualValues(t, -1, deletedRow.DeletedByID) // the system

	// nothing left to do: a second run records nothing
	since = a.max()
	run, err = RunBranchCleanup(ctx, repo)
	require.NoError(t, err)
	assert.Equal(t, &CleanupRun{}, run)
	assert.Empty(t, a.entries(since, "repo.branches.cleanup_deleted"))
}

func liveBranches(t *testing.T, repo *repo_model.Repository) []string {
	t.Helper()
	var out []string
	require.NoError(t, db.GetEngine(t.Context()).Table("branch").Where("repo_id = ? AND is_deleted = ?", repo.ID, false).Cols("name").Find(&out))
	return out
}

func TestRunBranchCleanupCap(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	noPushQueue(t)
	const n = MaxCleanupPerRepo + 5
	rows := make([]*git_model.Branch, 0, n)
	var refs strings.Builder
	for i := range n {
		name := fmt.Sprintf("b%03d", i)
		refs.WriteString(fmt.Sprintf("create refs/heads/%s %s\n", name, f.c1))
		rows = append(rows, &git_model.Branch{RepoID: f.repo.ID, Name: name, CommitID: f.c1, PusherID: 2})
	}
	cmd := exec.CommandContext(t.Context(), "git", "-C", f.repo.RepoPath(), "update-ref", "--stdin")
	cmd.Stdin = strings.NewReader("start\n" + refs.String() + "prepare\ncommit\n")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	for _, b := range rows {
		require.NoError(t, db.Insert(t.Context(), b))
	}
	// the oldest go first: b000..b004 are the youngest of the due ones, so they are the ones left
	_, err = db.GetEngine(t.Context()).Exec("UPDATE branch SET updated_unix = ? WHERE repo_id = ? AND name <> 'master'", time.Now().Unix()-90*86400, f.repo.ID)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE branch SET updated_unix = ? WHERE repo_id = ? AND name < 'b005'", time.Now().Unix()-40*86400, f.repo.ID)
	require.NoError(t, err)

	repo := f.setDays(30)
	ctx := audit_model.WithSystem(t.Context(), "cron:"+CleanupTaskName)
	since := newCleanupAudit(t).max()
	run, err := RunBranchCleanup(ctx, repo)
	require.NoError(t, err)
	assert.Equal(t, &CleanupRun{Deleted: MaxCleanupPerRepo, More: 5}, run)
	assert.ElementsMatch(t, []string{"master", "b000", "b001", "b002", "b003", "b004"}, liveBranches(t, f.repo))
	summary := newCleanupAudit(t).entries(since, "repo.branches.cleanup_deleted")
	require.Len(t, summary, 1)
	assert.Contains(t, summary[0].Data, `"waiting":5`)
	assert.Len(t, newCleanupAudit(t).entries(since, "repo.branch.deleted"), MaxCleanupPerRepo)
}

// The cron task finds the repositories with a setting of their own and those of an organization that sets one.
func TestCleanupCandidates(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	ids, err := cleanupCandidates(t.Context())
	require.NoError(t, err)
	assert.NotContains(t, ids, f.repo.ID)
	f.setDays(30)
	ids, err = cleanupCandidates(t.Context())
	require.NoError(t, err)
	assert.Contains(t, ids, f.repo.ID)

	// an organization's setting reaches its repositories, not trashed ones
	require.NoError(t, db.Insert(t.Context(), &repo_model.Repository{ID: 9101, OwnerID: 3, OwnerName: "org3", Name: "cu-org", LowerName: "cu-org", Status: repo_model.RepositoryReady}))
	require.NoError(t, db.Insert(t.Context(), &repo_model.Repository{ID: 9102, OwnerID: 3, OwnerName: "org3", Name: "cu-trash", LowerName: "cu-trash", TrashedUnix: 5}))
	_, err = db.GetEngine(t.Context()).Exec("INSERT INTO user_setting (user_id, setting_key, setting_value) VALUES (3, 'branch_workflow.cleanup', '{\"Days\":30}')")
	require.NoError(t, err)
	ids, err = cleanupCandidates(t.Context())
	require.NoError(t, err)
	assert.Contains(t, ids, int64(9101))
	assert.NotContains(t, ids, int64(9102))
}

// Two servers (or two starts of the task) at once: one run, one summary per repository.
func TestCleanupMergedBranchesClaimsTheRun(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	noPushQueue(t)
	f.branch("old-1", f.c1, 90)
	f.branch("old-2", f.c2, 90)
	f.setDays(30)
	ctx := audit_model.WithSystem(t.Context(), "cron:"+CleanupTaskName)
	since := newCleanupAudit(t).max()

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			assert.NoError(t, CleanupMergedBranches(ctx))
		})
	}
	wg.Wait()
	assert.ElementsMatch(t, []string{"master"}, liveBranches(t, f.repo))
	assert.Len(t, newCleanupAudit(t).entries(since, "repo.branches.cleanup_deleted"), 1)

	// the claim holds for the day; a later day claims again
	f.branch("old-3", f.c1, 90)
	require.NoError(t, CleanupMergedBranches(ctx))
	assert.Contains(t, liveBranches(t, f.repo), "old-3")
	_, err := db.GetEngine(t.Context()).Exec("UPDATE branch_cleanup_state SET last_run_unix = ? WHERE repo_id = ?", time.Now().Add(-25*time.Hour).Unix(), f.repo.ID)
	require.NoError(t, err)
	require.NoError(t, CleanupMergedBranches(ctx))
	assert.NotContains(t, liveBranches(t, f.repo), "old-3")
}

// A change that deletes sooner is recorded as waiting by the run and deletes nothing until it is due.
func TestCleanupMergedBranchesWaitsForAChange(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	noPushQueue(t)
	f.branch("old-1", f.c1, 90)
	f.setDays(0)
	stored, _, err := repo_model.GetRepoUnitForUpdate(t.Context(), f.repo.ID, unit.TypePullRequests)
	require.NoError(t, err)
	stored.PullRequestsConfig().BranchCleanup = &repo_model.BranchCleanup{Days: 30} // turned on without a record of its own
	require.NoError(t, repo_model.UpdateRepoUnit(t.Context(), stored))
	ctx := audit_model.WithSystem(t.Context(), "cron:"+CleanupTaskName)
	require.NoError(t, CleanupMergedBranches(ctx))
	assert.Contains(t, liveBranches(t, f.repo), "old-1", "30 days wait 7 more")
	st, err := repo_model.GetBranchCleanupState(t.Context(), f.repo.ID)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Zero(t, st.Days)
	assert.Equal(t, 30, st.PendingDays)
	assert.NotZero(t, st.PendingFrom)
}

// Maintenance that starts in the middle of a run stops it between two deletions and the summary says what is left.
func TestRunBranchCleanupStopsInMaintenance(t *testing.T) {
	f := newCleanupFixture(t, "cleanup-unit")
	noPushQueue(t)
	for _, n := range []string{"m1", "m2", "m3"} {
		f.branch(n, f.c1, 90)
	}
	repo := f.setDays(30)
	ctx := audit_model.WithSystem(t.Context(), "cron:"+CleanupTaskName)
	since := newCleanupAudit(t).max()
	calls := 0
	defer test.MockVariableValue(&DeleteBranchTestHook, func(_ *repo_model.Repository, _ string) {
		if calls++; calls == 1 { // maintenance starts while the first branch is deleted
			setting.Maintenance.Mode = setting.MaintenanceReadOnly
		}
	})()
	defer func(m string) { setting.Maintenance.Mode = m }(setting.Maintenance.Mode)

	run, err := RunBranchCleanup(ctx, repo)
	require.NoError(t, err)
	assert.Equal(t, 1, run.Deleted)
	assert.Len(t, liveBranches(t, f.repo), 3) // master and two of the three
	summary := newCleanupAudit(t).entries(since, "repo.branches.cleanup_deleted")
	require.Len(t, summary, 1)
	assert.Contains(t, summary[0].Data, `"deleted":1`)
	assert.Contains(t, summary[0].Data, `"waiting":2`)
}
