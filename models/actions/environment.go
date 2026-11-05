// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/gobwas/glob"
)

// Values of ActionEnvironment.RefPolicy
const (
	EnvironmentRefAny               = 0 // every ref may deploy
	EnvironmentRefProtectedBranches = 1 // only branches that have a branch protection rule
	EnvironmentRefPatterns          = 2 // only the refs that match RefPatterns
)

const (
	MaxEnvironmentsPerRepo = 100
	MaxEnvironmentName     = 255
	MaxRefPatterns         = 50
	MaxRunnerLabels        = 20
	MaxAllowedWorkflows    = 20
	MaxWaitTimerMinutes    = 43200 // 30 days
)

// Types of EnvironmentRefPattern
const (
	EnvironmentPatternBranch = "branch"
	EnvironmentPatternTag    = "tag"
)

var (
	ErrEnvironmentNotFound = util.NewNotExistErrorf("environment does not exist")
	ErrEnvironmentExists   = util.NewAlreadyExistErrorf("environment already exists")
	ErrEnvironmentLimit    = util.NewInvalidArgumentErrorf("too many environments in the repository")
)

// EnvironmentRefPattern is one entry of the ref patterns of an environment: Pattern is matched against the name of
// the branch (not "refs/heads/..."), or of the tag, by the glob where "*" doesn't cross "/" and "**" does.
type EnvironmentRefPattern struct {
	Type    string `json:"type"` // EnvironmentPatternBranch or EnvironmentPatternTag
	Pattern string `json:"pattern"`
}

// ActionEnvironment is a deployment target that jobs name with `environment:`. A repository environment has
// RepoID set and OwnerID 0; an organization environment (later) has OwnerID set and RepoID 0. The name is unique per
// owner and repository ignoring case (LowerName), so "Production" and "production" are one environment.
type ActionEnvironment struct {
	ID                int64
	OwnerID           int64                   `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID            int64                   `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	Name              string                  `xorm:"VARCHAR(255) NOT NULL"`
	LowerName         string                  `xorm:"VARCHAR(255) UNIQUE(owner_repo_name) NOT NULL"`
	RefPolicy         int                     `xorm:"NOT NULL DEFAULT 0"`
	RefPatterns       []EnvironmentRefPattern `xorm:"JSON TEXT"`
	WaitTimerMinutes  int                     `xorm:"NOT NULL DEFAULT 0"`
	PreventSelfReview bool                    `xorm:"NOT NULL DEFAULT false"` // the run's triggering user can't review its deployment
	RunnerLabels      []string                `xorm:"JSON TEXT"`              // appended to the runs-on of the jobs that deploy here
	AllowedWorkflows  []string                `xorm:"JSON TEXT"`              // patterns over the workflow file name, empty = any workflow
	// ReviewsRequired is the rule that a deployment needs a reviewer's approval. Only an edit of the reviewers sets or
	// clears it, never the deletion of a listed user or team: an environment whose reviewers all vanished that way
	// keeps holding its deployments (nobody can approve) until someone edits its rules, which is audited.
	ReviewsRequired   bool               `xorm:"NOT NULL DEFAULT false"`
	CreatedByWorkflow bool               `xorm:"NOT NULL DEFAULT false"` // a job named it before it existed
	Created           timeutil.TimeStamp `xorm:"created"`
	Updated           timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(ActionEnvironment))
}

// isPrintableASCII tells if s holds only the printable ASCII characters 0x20 to 0x7E. Names, ref patterns and runner
// labels are limited to them: no control, format or look-alike character (Cyrillic о, fullwidth letters, combining
// marks) can make one name pass for another, and no Unicode lower-casing (the Kelvin sign is a "k") can merge two.
func isPrintableASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e })
}

// lowerName returns the name as stored in lower_name: without the spaces around it, in ASCII lower case; ok is false
// for a name no environment can have.
func lowerName(name string) (lower string, ok bool) {
	name = strings.Trim(name, " ")
	return strings.ToLower(name), name != "" && isPrintableASCII(name)
}

// compilePattern compiles a ref pattern as matchPattern uses it.
func compilePattern(pattern string) (glob.Glob, error) {
	return glob.Compile(pattern, '/')
}

// matchPattern reports if name matches pattern. gobwas/glob can panic in Match on a pattern that compiles, which
// counts as no match.
func matchPattern(pattern, name string) (matched bool) {
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()
	g, err := compilePattern(pattern)
	return err == nil && g.Match(name)
}

// Normalize trims and lowercases the name and removes empty slices, then validates every rule of the environment.
// Every writer calls it.
func (e *ActionEnvironment) Normalize() error {
	e.Name = strings.Trim(e.Name, " ")
	lower, ok := lowerName(e.Name)
	e.LowerName = lower
	// ":" delimits the environment in the subject of an ID token (`...:environment:<name>`), so neither it nor a space is allowed
	if !ok || len(e.Name) > MaxEnvironmentName || strings.ContainsAny(e.Name, ": ") {
		return util.NewInvalidArgumentErrorf("invalid environment name")
	}
	if e.RefPolicy < EnvironmentRefAny || e.RefPolicy > EnvironmentRefPatterns {
		return util.NewInvalidArgumentErrorf("invalid deployment ref policy")
	}
	if e.RefPolicy != EnvironmentRefPatterns && len(e.RefPatterns) > 0 {
		return util.NewInvalidArgumentErrorf("ref patterns need the pattern policy")
	}
	if e.RefPolicy == EnvironmentRefPatterns && len(e.RefPatterns) == 0 {
		return util.NewInvalidArgumentErrorf("the pattern policy needs a pattern")
	}
	if len(e.RefPatterns) > MaxRefPatterns {
		return util.NewInvalidArgumentErrorf("too many ref patterns")
	}
	for _, p := range e.RefPatterns {
		if p.Type != EnvironmentPatternBranch && p.Type != EnvironmentPatternTag {
			return util.NewInvalidArgumentErrorf("invalid ref pattern type")
		}
		if p.Pattern == "" || len(p.Pattern) > 255 || !isPrintableASCII(p.Pattern) {
			return util.NewInvalidArgumentErrorf("invalid ref pattern")
		}
		if _, err := compilePattern(p.Pattern); err != nil {
			return util.NewInvalidArgumentErrorf("invalid ref pattern")
		}
	}
	if e.WaitTimerMinutes < 0 || e.WaitTimerMinutes > MaxWaitTimerMinutes {
		return util.NewInvalidArgumentErrorf("invalid wait timer")
	}
	if len(e.RunnerLabels) > MaxRunnerLabels {
		return util.NewInvalidArgumentErrorf("too many runner labels")
	}
	for i, l := range e.RunnerLabels {
		if l == "" || len(l) > 255 || !isPrintableASCII(l) || slices.Contains(e.RunnerLabels[:i], l) {
			return util.NewInvalidArgumentErrorf("invalid runner label")
		}
	}
	if len(e.AllowedWorkflows) > MaxAllowedWorkflows {
		return util.NewInvalidArgumentErrorf("too many allowed workflows")
	}
	for _, p := range e.AllowedWorkflows {
		if _, err := compilePattern(p); err != nil || p == "" || len(p) > 255 || !isPrintableASCII(p) {
			return util.NewInvalidArgumentErrorf("invalid allowed workflow")
		}
	}
	if e.AllowedWorkflows == nil {
		e.AllowedWorkflows = []string{}
	}
	if e.RefPatterns == nil {
		e.RefPatterns = []EnvironmentRefPattern{}
	}
	if e.RunnerLabels == nil {
		e.RunnerLabels = []string{}
	}
	return nil
}

// AllowsRef reports if the environment accepts a deployment from ref ("refs/heads/..." or "refs/tags/...") by its
// patterns. A ref of another kind, such as "refs/pull/1/head", matches no pattern. It doesn't decide the protected
// branch policy, which needs the branch protection rules: the caller does.
func (e *ActionEnvironment) AllowsRef(ref string) bool {
	switch e.RefPolicy {
	case EnvironmentRefAny:
		return true
	case EnvironmentRefPatterns:
		kind, name := EnvironmentRefKind(ref)
		for _, p := range e.RefPatterns {
			if p.Type == kind && matchPattern(p.Pattern, name) {
				return true
			}
		}
	}
	return false
}

// AllowsWorkflow reports if a run of the workflow file (its name without the directory, such as "deploy.yml") may
// deploy to the environment: it has no allowed workflows, or one of its patterns matches ("*" doesn't cross "/").
func (e *ActionEnvironment) AllowsWorkflow(workflowID string) bool {
	if len(e.AllowedWorkflows) == 0 {
		return true
	}
	return slices.ContainsFunc(e.AllowedWorkflows, func(p string) bool { return matchPattern(p, workflowID) })
}

// EnvironmentRefKind splits ref into EnvironmentPatternBranch or EnvironmentPatternTag and its short name; the kind
// is "" for any other ref.
func EnvironmentRefKind(ref string) (kind, name string) {
	if name, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return EnvironmentPatternBranch, name
	}
	if name, ok := strings.CutPrefix(ref, "refs/tags/"); ok {
		return EnvironmentPatternTag, name
	}
	return "", ""
}

// auditData lists the settings of the environment that its entries record.
func (e *ActionEnvironment) auditData() map[string]any {
	patterns := make([]string, len(e.RefPatterns))
	for i, p := range e.RefPatterns {
		patterns[i] = p.Type + ":" + p.Pattern
	}
	return map[string]any{
		"name": e.Name, "ref_policy": e.RefPolicy, "ref_patterns": patterns, "wait_timer_minutes": e.WaitTimerMinutes,
		"prevent_self_review": e.PreventSelfReview, "runner_labels": e.RunnerLabels, "allowed_workflows": e.AllowedWorkflows,
		"reviews_required": e.ReviewsRequired,
	}
}

func recordEnvironment(ctx context.Context, actions audit_model.LevelActions, e *ActionEnvironment, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	data["name"] = e.Name
	return repo_model.RecordScoped(ctx, actions, e.OwnerID, 0, e.RepoID, audit_model.Event{
		TargetType: "actions_environment", TargetID: e.ID, TargetName: e.Name, Data: data,
	})
}

// insertEnvironmentIfAbsent inserts e unless its name exists (the insert does nothing on a conflict, so concurrent
// callers don't fail, and a failed statement doesn't abort a PostgreSQL transaction) and reports if it inserted.
func insertEnvironmentIfAbsent(ctx context.Context, e *ActionEnvironment) (bool, error) {
	patterns, err := json.Marshal(e.RefPatterns)
	if err != nil {
		return false, err
	}
	labels, err := json.Marshal(e.RunnerLabels)
	if err != nil {
		return false, err
	}
	workflows, err := json.Marshal(e.AllowedWorkflows)
	if err != nil {
		return false, err
	}
	verb, suffix := "INSERT INTO", " ON CONFLICT (owner_id, repo_id, lower_name) DO NOTHING"
	if setting.Database.Type.IsMySQL() {
		verb, suffix = "INSERT IGNORE INTO", ""
	}
	insert := verb + " action_environment (owner_id, repo_id, name, lower_name, ref_policy, ref_patterns, wait_timer_minutes, prevent_self_review, runner_labels, allowed_workflows, reviews_required, created_by_workflow, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" + suffix
	now := timeutil.TimeStampNow()
	res, err := db.GetEngine(ctx).Exec(insert, e.OwnerID, e.RepoID, e.Name, e.LowerName, e.RefPolicy, string(patterns), e.WaitTimerMinutes, e.PreventSelfReview, string(labels), string(workflows), e.ReviewsRequired, e.CreatedByWorkflow, now, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// CreateEnvironment validates and inserts a repository environment with its reviewers (see UpdateEnvironment) and
// records its creation. It returns ErrEnvironmentExists when the name (ignoring case) is taken and ErrEnvironmentLimit
// past MaxEnvironmentsPerRepo.
func CreateEnvironment(ctx context.Context, e *ActionEnvironment, reviewers []ActionEnvironmentReviewer) error {
	return createEnvironment(ctx, e, false, reviewers)
}

// createEnvironment inserts e; with auto, an environment that already exists is no error and e.ID stays 0.
func createEnvironment(ctx context.Context, e *ActionEnvironment, auto bool, reviewers []ActionEnvironmentReviewer) error {
	e.OwnerID = 0 // repository environments only, for now
	if e.RepoID == 0 {
		return util.NewInvalidArgumentErrorf("an environment belongs to a repository")
	}
	if err := e.Normalize(); err != nil {
		return err
	}
	keys, err := reviewerListKeys(reviewers)
	if err != nil {
		return err
	}
	e.ReviewsRequired, e.CreatedByWorkflow = len(keys) > 0, auto
	// The cap is checked before the insert, so concurrent creations can pass it together by a few. The refusal is
	// returned outside the transaction below: an error from a nested transaction rolls the caller's back.
	if n, err := db.GetEngine(ctx).Where("owner_id = 0 AND repo_id = ?", e.RepoID).Count(new(ActionEnvironment)); err != nil {
		return err
	} else if n >= MaxEnvironmentsPerRepo {
		return ErrEnvironmentLimit
	}
	created := false
	err = db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if created, err = insertEnvironmentIfAbsent(ctx, e); err != nil || !created {
			return err
		}
		stored, err := GetRepoEnvironmentByName(ctx, e.RepoID, e.Name)
		if err != nil {
			return err
		}
		*e = *stored
		if err := insertReviewers(ctx, e.ID, reviewers); err != nil {
			return err
		}
		data := e.auditData()
		data["auto"] = auto
		data["reviewers"] = keys
		return recordEnvironment(ctx, audit_model.LevelActions{Repo: "repo.actions_env.created"}, e, data)
	})
	if err != nil {
		return err
	}
	if !created && !auto {
		return ErrEnvironmentExists
	}
	return nil
}

// GetOrCreateRepoEnvironment returns the environment of the repository with that name (ignoring case); a name that
// doesn't exist is created without any rule. Concurrent first uses of a name don't fail on SQLite and PostgreSQL; on
// MySQL, inside a transaction that already read (REPEATABLE READ), the one that lost the race may not see the row of
// the winner and fails once, and the emitter, which calls this, runs its pass again.
func GetOrCreateRepoEnvironment(ctx context.Context, repoID int64, name string) (*ActionEnvironment, error) {
	if env, err := GetRepoEnvironmentByName(ctx, repoID, name); !errors.Is(err, ErrEnvironmentNotFound) {
		return env, err
	}
	e := &ActionEnvironment{RepoID: repoID, Name: name}
	if err := createEnvironment(ctx, e, true, nil); err != nil {
		return nil, err
	}
	if e.ID != 0 {
		return e, nil
	}
	return GetRepoEnvironmentByName(ctx, repoID, name) // another call created it first
}

// GetRepoEnvironmentByName finds the environment of the repository by name, ignoring case.
func GetRepoEnvironmentByName(ctx context.Context, repoID int64, name string) (*ActionEnvironment, error) {
	lower, ok := lowerName(name)
	if !ok {
		return nil, ErrEnvironmentNotFound
	}
	e := new(ActionEnvironment)
	has, err := db.GetEngine(ctx).Where("owner_id = 0 AND repo_id = ? AND lower_name = ?", repoID, lower).Get(e)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrEnvironmentNotFound
	}
	return e, nil
}

// GetRepoEnvironmentByID finds the environment with that ID if it belongs to the repository.
func GetRepoEnvironmentByID(ctx context.Context, repoID, id int64) (*ActionEnvironment, error) {
	e := new(ActionEnvironment)
	has, err := db.GetEngine(ctx).Where("id = ? AND owner_id = 0 AND repo_id = ?", id, repoID).Get(e)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrEnvironmentNotFound
	}
	return e, nil
}

// FindRepoEnvironments lists a page of the environments of the repository by name, and how many it has.
func FindRepoEnvironments(ctx context.Context, repoID int64, opts db.ListOptions) ([]*ActionEnvironment, int64, error) {
	var envs []*ActionEnvironment
	sess := db.GetEngine(ctx).Where("owner_id = 0 AND repo_id = ?", repoID).OrderBy("lower_name")
	if opts.PageSize > 0 {
		sess = db.SetSessionPagination(sess, &opts)
	}
	count, err := sess.FindAndCount(&envs)
	return envs, count, err
}

// UpdateEnvironment validates and saves the rules of e (its name only in letter case) and makes reviewers its whole
// list of reviewers, and records one entry with what changed (none without a change). The environment requires reviews
// when the list is not empty: editing the list is how that rule changes, also to none at all. Only the shape of the list
// is checked here (at most MaxEnvironmentReviewers, each a user or a team, none twice); the caller checks that they
// exist and that a team belongs to the owner of the repository.
func UpdateEnvironment(ctx context.Context, e *ActionEnvironment, reviewers []ActionEnvironmentReviewer) error {
	if err := e.Normalize(); err != nil {
		return err
	}
	keys, err := reviewerListKeys(reviewers)
	if err != nil {
		return err
	}
	e.ReviewsRequired = len(keys) > 0
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockEnvironment(ctx, e.RepoID, e.ID); err != nil {
			return err
		}
		stored, err := GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
		if err != nil {
			return err
		}
		// the name only changes in letter case: a new name would let the secrets of a job follow a rename
		if stored.LowerName != e.LowerName {
			return util.NewInvalidArgumentErrorf("an environment can't be renamed")
		}
		before, err := FindEnvironmentReviewers(ctx, stored.ID)
		if err != nil {
			return err
		}
		old, now := stored.auditData(), e.auditData()
		old["reviewers"], now["reviewers"] = reviewerKeys(before), keys
		changes := audit_model.Changes(old, now)
		if changes == nil {
			return nil
		}
		if err := recordEnvironment(ctx, audit_model.LevelActions{Repo: "repo.actions_env.updated"}, e, changes); err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).ID(e.ID).Cols("name", "ref_policy", "ref_patterns", "wait_timer_minutes", "prevent_self_review", "runner_labels", "allowed_workflows", "reviews_required").Update(e); err != nil {
			return err
		}
		if slices.Equal(reviewerKeys(before), keys) {
			return nil
		}
		if _, err := db.GetEngine(ctx).Where("environment_id = ?", e.ID).Delete(new(ActionEnvironmentReviewer)); err != nil {
			return err
		}
		return insertReviewers(ctx, e.ID, reviewers)
	})
}

// LockEnvironment takes the row lock of the environment (a no-op UPDATE: a write lock on SQLite, a row lock elsewhere)
// and returns ErrEnvironmentNotFound if it is gone. Every insert of a secret or variable of an environment and its delete
// take it first, so a concurrent delete can't leave rows of a deleted environment behind. Call it inside a transaction.
func LockEnvironment(ctx context.Context, repoID, id int64) error {
	if err := secret_model.LockEnvironment(ctx, repoID, id); err != nil {
		if errors.Is(err, util.ErrNotExist) {
			return ErrEnvironmentNotFound
		}
		return err
	}
	return nil
}

// DeleteEnvironment deletes the environment with its secrets and variables and records it. Its deployments stay as
// history. It doesn't touch the jobs that wait for the environment: failUnpickedJobs does, in the same transaction and
// before the rows go (it is required, so no caller forgets them). Only services/actions DeleteEnvironment should call it.
func DeleteEnvironment(ctx context.Context, e *ActionEnvironment, failUnpickedJobs func(context.Context) error) error {
	if failUnpickedJobs == nil {
		return errors.New("DeleteEnvironment needs a function that fails the jobs waiting for the environment")
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockEnvironment(ctx, e.RepoID, e.ID); err != nil {
			return err
		}
		if err := failUnpickedJobs(ctx); err != nil {
			return err
		}
		stored, err := GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
		if err != nil {
			return err
		}
		reviewers, err := FindEnvironmentReviewers(ctx, stored.ID)
		if err != nil {
			return err
		}
		eng := db.GetEngine(ctx)
		if _, err := eng.Where("environment_id = ?", stored.ID).Delete(new(ActionEnvironmentReviewer)); err != nil {
			return err
		}
		secrets, err := eng.Table("secret").Where("repo_id = ? AND environment_id = ?", stored.RepoID, stored.ID).Delete()
		if err != nil {
			return err
		}
		variables, err := eng.Table("action_variable").Where("repo_id = ? AND environment_id = ?", stored.RepoID, stored.ID).Delete()
		if err != nil {
			return err
		}
		// the entry keeps the rules that were removed, and how many secrets and variables (never their values)
		data := stored.auditData()
		data["reviewers"] = reviewerKeys(reviewers)
		data["counts"] = map[string]int64{"secrets": secrets, "variables": variables}
		if err := recordEnvironment(ctx, audit_model.LevelActions{Repo: "repo.actions_env.deleted"}, stored, data); err != nil {
			return err
		}
		_, err = db.DeleteByID[ActionEnvironment](ctx, stored.ID)
		return err
	})
}

// countByEnvironment counts the rows of table (secret or action_variable) of each of the environments of the
// repository, in one query.
func countByEnvironment(ctx context.Context, table string, repoID int64, ids []int64) (map[int64]int64, error) {
	var rows []struct {
		EnvironmentID int64
		N             int64
	}
	err := db.GetEngine(ctx).Table(table).Select("environment_id, COUNT(*) AS n").
		Where("repo_id = ?", repoID).In("environment_id", ids).GroupBy("environment_id").Find(&rows)
	out := make(map[int64]int64, len(rows))
	for _, r := range rows {
		out[r.EnvironmentID] = r.N
	}
	return out, err
}

// CountEnvironmentSecretsAndVariables counts the secrets and the variables of each of the environments of the
// repository, with one query each.
func CountEnvironmentSecretsAndVariables(ctx context.Context, repoID int64, ids []int64) (secrets, variables map[int64]int64, err error) {
	if secrets, err = countByEnvironment(ctx, "secret", repoID, ids); err != nil {
		return nil, nil, err
	}
	variables, err = countByEnvironment(ctx, "action_variable", repoID, ids)
	return secrets, variables, err
}
