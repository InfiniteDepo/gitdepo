// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"slices"
	"strings"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/branchworkflow"

	"xorm.io/builder"
)

// MaxCleanupPerRepo is how many branches one run of the cleanup deletes in one repository; the rest wait for the next run.
const MaxCleanupPerRepo = 200

// CleanupTaskName is the cron task of the cleanup of merged branches.
const CleanupTaskName = "cleanup_merged_branches"

// The reasons a repository is skipped by the cleanup (CleanupPlan.Skip): a closed set, shown through literal locale keys.
const (
	CleanupSkipArchived    = "archived"     // the repository is archived
	CleanupSkipOrgArchived = "org_archived" // its organization is archived
	CleanupSkipTrashed     = "trashed"      // it or its owner is in the trash
	CleanupSkipMirror      = "mirror"
	CleanupSkipEmpty       = "empty"
	CleanupSkipNotReady    = "not_ready" // being migrated or failed
	CleanupSkipPullsOff    = "pulls_off" // the Pull requests unit is off: no merge time is known
	CleanupSkipDevMissing  = "dev_missing"
)

// CleanupBranch is a merged branch of a cleanup plan. At is the age's start: the merge time of its pull request
// (never later than the last push to the branch row), otherwise the server's last update of the branch row. The
// commit time is never used: the pusher forges it. Into is the target it is merged into; Reason is set for kept ones.
type CleanupBranch struct {
	Name   string
	Commit string
	Into   string
	At     timeutil.TimeStamp
	FromPR bool // At is the merge time of the pull request; otherwise the last change of the branch row
	Reason string
}

// CleanupPlan is what the cleanup of a repository would do now. It is the one decision behind the preview and the
// scheduled run; the run still checks each branch again when it deletes it.
type CleanupPlan struct {
	Skip    string          // a CleanupSkip reason, then nothing else is set
	Days    int             // the age the plan was made for
	Targets []string        // the development branch and the default branch
	Due     []CleanupBranch // merged for at least Days, oldest first
	NotDue  []CleanupBranch // merged, younger than Days
	Kept    []CleanupBranch // merged, but never deleted: Reason says why
}

// cleanupSkip says why the cleanup leaves the repository alone, "" when it may work on it.
func cleanupSkip(ctx context.Context, repo *repo_model.Repository) (string, error) {
	if repo.IsTrashed() {
		return CleanupSkipTrashed, nil
	}
	if err := repo.LoadOwner(ctx); err != nil {
		if user_model.IsErrUserNotExist(err) {
			return CleanupSkipTrashed, nil
		}
		return "", err
	}
	switch {
	case repo.IsArchived:
		return CleanupSkipArchived, nil
	case repo.Owner.IsOrganization() && repo.Owner.IsArchived:
		return CleanupSkipOrgArchived, nil
	case repo.IsMirror:
		return CleanupSkipMirror, nil
	case repo.IsEmpty:
		return CleanupSkipEmpty, nil
	case repo.Status != repo_model.RepositoryReady:
		return CleanupSkipNotReady, nil
	}
	if _, err := repo.GetUnit(ctx, unit.TypePullRequests); err != nil {
		return CleanupSkipPullsOff, nil
	}
	return "", nil
}

// PlanBranchCleanup works out which merged branches of repo a cleanup of the given days deletes at now. A branch is
// merged when its tip is in the development branch or the default branch (and is not at their tip: a branch nobody
// committed to is not "merged"). It deletes nothing.
func PlanBranchCleanup(ctx context.Context, repo *repo_model.Repository, days int, now time.Time) (*CleanupPlan, error) {
	plan := &CleanupPlan{Days: days}
	skip, err := cleanupSkip(ctx, repo)
	if err != nil || skip != "" {
		plan.Skip = skip
		return plan, err
	}
	kept, err := branchworkflow.NewKeptChecker(ctx, repo, true)
	if err != nil {
		return nil, err
	}
	dev := kept.Model().DevelopmentBranch(repo)
	plan.Targets = []string{dev}
	if dev != repo.DefaultBranch {
		plan.Targets = append(plan.Targets, repo.DefaultBranch)
	}
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return nil, err
	}
	defer gitRepo.Close()
	// name -> tip of the branches merged into any target, and into which; a branch at the tip of a target is no merge
	merged, into, tips := map[string]string{}, map[string]string{}, map[string]bool{}
	for _, target := range plan.Targets {
		tip, err := gitRepo.GetBranchCommitID(target)
		if err != nil {
			plan.Skip = CleanupSkipDevMissing
			return plan, nil
		}
		tips[tip] = true
		walked, err := branchesMergedInto(ctx, repo, gitRepo, target, true)
		if err != nil {
			return nil, err
		}
		for name, sha := range walked {
			if _, ok := merged[name]; !ok {
				merged[name], into[name] = sha, target
			}
		}
	}
	rows, err := BranchQuery{Cond: builder.NewCond(), Merged: merged}.rows(ctx, repo)
	if err != nil {
		return nil, err
	}
	mergedAt, err := mergedPullTimes(ctx, repo, plan.Targets)
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour).Unix()
	for _, b := range rows {
		if tips[b.CommitID] {
			continue
		}
		// the merge time of the pull request, but a later push to the branch restarts the clock
		pr := timeutil.TimeStamp(mergedAt[b.Name])
		at := max(pr, b.UpdatedUnix)
		cb := CleanupBranch{Name: b.Name, Commit: b.CommitID, Into: into[b.Name], At: at, FromPR: pr != 0 && pr >= b.UpdatedUnix, Reason: kept.Reason(b.Name)}
		switch {
		case cb.Reason != "":
			plan.Kept = append(plan.Kept, cb)
		case int64(at) <= cutoff:
			plan.Due = append(plan.Due, cb)
		default:
			plan.NotDue = append(plan.NotDue, cb)
		}
	}
	slices.SortFunc(plan.Due, func(a, b CleanupBranch) int {
		if a.At != b.At {
			return int(a.At - b.At)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return plan, nil
}

// mergedPullTimes maps the head branches of repo to the merge time of their latest pull request into one of the
// targets, in one grouped query. A pull request from another repository or by AGit flow names no branch of repo.
func mergedPullTimes(ctx context.Context, repo *repo_model.Repository, targets []string) (map[string]int64, error) {
	var rows []struct {
		HeadBranch string `xorm:"head_branch"`
		MergedUnix int64  `xorm:"merged_unix"`
	}
	err := db.GetEngine(ctx).Table("pull_request").Select("head_branch, MAX(merged_unix) AS merged_unix").
		Where(builder.Eq{"head_repo_id": repo.ID, "base_repo_id": repo.ID, "has_merged": true}).
		And(builder.In("base_branch", targets)).And(builder.Neq{"flow": issues_model.PullRequestFlowAGit}).
		GroupBy("head_branch").Find(&rows)
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.HeadBranch] = r.MergedUnix
	}
	return out, err
}

// FindCleanupPulls maps the given head branches to the number of their latest merged pull request into one of the
// targets, for a page that shows it to someone who can read pull requests.
func FindCleanupPulls(ctx context.Context, repo *repo_model.Repository, targets, names []string) (map[string]int64, error) {
	if len(names) == 0 {
		return map[string]int64{}, nil
	}
	var rows []struct {
		HeadBranch string `xorm:"head_branch"`
		Index      int64  `xorm:"index"`
	}
	err := db.GetEngine(ctx).Table("pull_request").Join("INNER", "issue", "issue.id = pull_request.issue_id").
		Select("pull_request.head_branch, issue.`index`").
		Where(builder.Eq{"pull_request.head_repo_id": repo.ID, "pull_request.base_repo_id": repo.ID, "pull_request.has_merged": true}).
		And(builder.In("pull_request.base_branch", targets)).And(builder.In("pull_request.head_branch", names)).
		And(builder.Neq{"pull_request.flow": issues_model.PullRequestFlowAGit}).OrderBy("pull_request.merged_unix, issue.id").Find(&rows)
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.HeadBranch] = r.Index
	}
	return out, err
}

// CleanupRun is what one run of the cleanup did in one repository.
type CleanupRun struct {
	Deleted int
	Kept    int // due, but refused when deleting
	More    int // due beyond MaxCleanupPerRepo, left for the next run
}

// RunBranchCleanup runs the cleanup of repo once: it reads the days in force (see branchworkflow.SyncCleanup), plans, and deletes at most
// MaxCleanupPerRepo of the due branches through the same per-branch decision as the bulk delete (kept rule read
// again, the doer's permission, the tip the plan saw), as the system. Each deletion is audited with via "cleanup",
// and the run once. It does nothing while the instance is in read-only maintenance. Every branch can be restored.
func RunBranchCleanup(ctx context.Context, repo *repo_model.Repository) (*CleanupRun, error) {
	run := &CleanupRun{}
	if setting.GetMaintenance(ctx).ReadOnly() {
		return run, nil
	}
	eff, err := branchworkflow.GetEffectiveCleanup(ctx, repo)
	if err != nil || eff.Days == 0 {
		return run, err
	}
	now := timeutil.TimeStampNow().AsTime()
	plan, err := PlanBranchCleanup(ctx, repo, eff.Days, now)
	if err != nil || plan.Skip != "" || len(plan.Due) == 0 {
		return run, err
	}
	due := plan.Due[:min(len(plan.Due), MaxCleanupPerRepo)]
	run.More = len(plan.Due) - len(due)
	selected := make([]SelectedBranch, len(due))
	for i, b := range due {
		selected[i] = SelectedBranch{b.Name, b.Commit}
	}
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return run, err
	}
	defer gitRepo.Close()
	results, err := deleteSelected(ctx, user_model.NewGhostUser(), repo, gitRepo, selected, "cleanup", map[string]any{"days": eff.Days, "waiting": run.More})
	for _, r := range results {
		if r.Reason == "" {
			run.Deleted++
		} else {
			run.Kept++
		}
	}
	return run, err
}

// ownCleanupLike matches a Pull requests unit config that holds a BranchCleanup setting: the key is followed by an
// object, and a quote inside a user's string is escaped in the JSON, so no value can look like it.
var ownCleanupLike = builder.Like{"config", `"BranchCleanup":{`}

// cleanupCandidates lists the repositories whose cleanup setting may be on: those of an organization that sets it,
// and those whose own Pull requests unit holds one (the config is JSON, so a LIKE on its key and object narrows it; the
// setting in force is read again for each). Trashed repositories are left out.
func cleanupCandidates(ctx context.Context) ([]int64, error) {
	var orgs []int64
	if err := db.GetEngine(ctx).Table("user_setting").Where("setting_key = ?", "branch_workflow.cleanup").Cols("user_id").Find(&orgs); err != nil {
		return nil, err
	}
	var ids []int64
	if len(orgs) > 0 {
		if err := db.GetEngine(ctx).Table("repository").Where(builder.In("owner_id", orgs)).And(builder.Eq{"trashed_unix": 0}).Cols("id").Find(&ids); err != nil {
			return nil, err
		}
	}
	var own []int64
	if err := db.GetEngine(ctx).Table("repo_unit").Where(builder.Eq{"type": unit.TypePullRequests}).And(ownCleanupLike).Cols("repo_id").Find(&own); err != nil {
		return nil, err
	}
	ids = append(ids, own...)
	// repositories with a record that is on or waits, so that turning it off (by whatever level) is recorded too
	var recorded []int64
	if err := db.GetEngine(ctx).Table("branch_cleanup_state").Where("days > 0 OR pending_from <> 0").Cols("repo_id").Find(&recorded); err != nil {
		return nil, err
	}
	ids = append(ids, recorded...)
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// startOfDay is midnight of now's calendar day in server time: a repository's scheduled run is claimed per calendar
// day (a second server, a second start of the task or a manual run from the admin page that day skips it), so there
// is one run, and one summary, per repository per day, and a later-running night is never skipped.
// The day is cut in time.Local, the zone the cron scheduler fires in (gocron.NewScheduler(time.Local) in
// services/cron), never in the UI zone.
func startOfDay(now time.Time) time.Time {
	now = now.In(time.Local)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

// runClaimedCleanup records the days in force of repo (starting the waiting period of a change that deletes sooner),
// and when cleanup is on claims the repository's run with a conditional UPDATE and runs it. Whoever loses the claim
// does nothing.
func runClaimedCleanup(ctx context.Context, repo *repo_model.Repository) error {
	e, err := branchworkflow.SyncCleanup(ctx, repo)
	if err != nil || e.Days == 0 {
		return err
	}
	now := timeutil.TimeStampNow().AsTime()
	claimed, err := repo_model.ClaimBranchCleanupRun(ctx, repo.ID, startOfDay(now).Unix(), now.Unix())
	if err != nil || !claimed {
		return err
	}
	_, err = RunBranchCleanup(ctx, repo)
	return err
}

// CleanupMergedBranches is the cron task: it runs the cleanup in every repository that has it on. It stops when
// the instance goes into read-only maintenance (checked for each repository, and between the deletions of one) or is
// shutting down, and a repository that fails is logged and skipped. Each repository's run is claimed in its
// branch_cleanup_state record, so several servers run it once; the deletion itself only succeeds at the tip it was
// planned for.
func CleanupMergedBranches(ctx context.Context) error {
	if audit_model.ActorFromContext(ctx) == nil {
		ctx = audit_model.WithSystem(ctx, "cron:"+CleanupTaskName)
	}
	ids, err := cleanupCandidates(ctx)
	if err != nil {
		return err
	}
	for chunk := range slices.Chunk(ids, 50) {
		var repos []*repo_model.Repository
		if err := db.GetEngine(ctx).In("id", chunk).Asc("id").Find(&repos); err != nil {
			return err
		}
		for _, repo := range repos {
			if ctx.Err() != nil {
				return nil
			}
			if setting.GetMaintenance(ctx).ReadOnly() {
				log.Info("%s: stopping, maintenance mode is on", CleanupTaskName)
				return nil
			}
			if err := runClaimedCleanup(ctx, repo); err != nil {
				log.Error("%s: %-v: %v", CleanupTaskName, repo, err)
			}
		}
	}
	return nil
}

// cleanupRepoCond selects the repositories of org the cleanup works on at all (not archived, mirror, empty, trashed
// or unfinished, and with the Pull requests unit); the plan still decides each one.
func cleanupRepoCond(org *user_model.User) builder.Cond {
	return builder.Eq{"owner_id": org.ID, "is_archived": false, "is_mirror": false, "is_empty": false, "trashed_unix": 0, "status": repo_model.RepositoryReady}.
		And(builder.Exists(builder.Select("1").From("repo_unit").Where(builder.Expr("repo_unit.repo_id = repository.id").And(builder.Eq{"repo_unit.type": unit.TypePullRequests}))))
}

// CountCleanupRepos counts the repositories the organization's cleanup setting reaches. Unless the organization
// enforces it, those with a setting of their own are left out.
func CountCleanupRepos(ctx context.Context, org *user_model.User, locked bool) (int64, error) {
	if org.IsArchived {
		return 0, nil
	}
	cond := cleanupRepoCond(org)
	if !locked {
		cond = cond.And(builder.NotExists(builder.Select("1").From("repo_unit").Where(builder.Expr("repo_unit.repo_id = repository.id").
			And(builder.Eq{"repo_unit.type": unit.TypePullRequests}).And(builder.Like{"repo_unit.config", `"BranchCleanup":{`}))))
	}
	return db.GetEngine(ctx).Where(cond).Count(&repo_model.Repository{})
}

// FindOrgCleanupRepos lists one page of the repositories of the organization, trashed ones left out, with how many
// there are: the rows of the organization's cleanup preview, whose plans are made one repository at a time.
func FindOrgCleanupRepos(ctx context.Context, org *user_model.User, page, pageSize int) ([]*repo_model.Repository, int64, error) {
	cond := builder.Eq{"owner_id": org.ID, "trashed_unix": 0}
	total, err := db.GetEngine(ctx).Where(cond).Count(&repo_model.Repository{})
	if err != nil {
		return nil, 0, err
	}
	repos := make([]*repo_model.Repository, 0, pageSize)
	return repos, total, db.GetEngine(ctx).Where(cond).OrderBy("group_name, lower_name").Limit(pageSize, max(page-1, 0)*pageSize).Find(&repos)
}
