// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package branchworkflow resolves the branch workflow settings: instance (app.ini) -> organization -> repository.
package branchworkflow

import (
	"context"
	"errors"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/translation"
)

const (
	keyDeleteAfterMerge       = "branch_workflow.delete_after_merge"
	keyDeleteAfterMergeLocked = "branch_workflow.delete_after_merge_locked"

	SourceInstance = "instance"
	SourceNone     = "none" // no branching model on any level
	SourceOrg      = "org"
	SourceRepo     = "repo"
)

var (
	ErrLocked           = errors.New("the setting is enforced by the organization")
	ErrLockWithoutValue = errors.New("a setting can only be enforced with an explicit value")
	ErrNoPullRequests   = errors.New("pull requests are not enabled for the repository")
)

// Effective is the value that applies to a repository and where it comes from.
type Effective struct {
	Mode       repo_model.DeleteBranchMode
	Source     string
	Locked     bool
	SetBy      string                      // name of the organization when Source is SourceOrg
	Configured repo_model.DeleteBranchMode // the repository's own value
}

func instanceMode() repo_model.DeleteBranchMode {
	if m, ok := repo_model.ParseDeleteBranchMode(setting.Repository.BranchWorkflow.DeleteSourceBranchAfterMerge); ok && m != repo_model.DeleteBranchInherit {
		return m
	}
	return repo_model.DeleteBranchOff
}

// Resolve combines the three levels. orgMode is Inherit for repositories of users.
func Resolve(instance, orgMode repo_model.DeleteBranchMode, orgLocked bool, repoMode repo_model.DeleteBranchMode) Effective {
	e := Effective{Mode: instance, Source: SourceInstance, Configured: repoMode}
	switch {
	case orgMode != repo_model.DeleteBranchInherit && orgLocked:
		e.Mode, e.Source, e.Locked = orgMode, SourceOrg, true
	case repoMode != repo_model.DeleteBranchInherit:
		e.Mode, e.Source = repoMode, SourceRepo
	case orgMode != repo_model.DeleteBranchInherit:
		e.Mode, e.Source = orgMode, SourceOrg
	}
	return e
}

// GetOrg returns the organization's value and its lock.
func GetOrg(ctx context.Context, org *user_model.User) (repo_model.DeleteBranchMode, bool, error) {
	v, err := user_model.GetUserSetting(ctx, org.ID, keyDeleteAfterMerge)
	if err != nil {
		return repo_model.DeleteBranchInherit, false, err
	}
	locked, err := user_model.GetUserSetting(ctx, org.ID, keyDeleteAfterMergeLocked)
	if err != nil {
		return repo_model.DeleteBranchInherit, false, err
	}
	mode, _ := repo_model.ParseDeleteBranchMode(v)
	return mode, locked == "true", nil
}

// GetEffective is the only way to read the setting that applies to a repository.
func GetEffective(ctx context.Context, repo *repo_model.Repository) (Effective, error) {
	if err := repo.LoadOwner(ctx); err != nil {
		return Effective{}, err
	}
	orgMode, orgLocked := repo_model.DeleteBranchInherit, false
	if repo.Owner.IsOrganization() {
		var err error
		if orgMode, orgLocked, err = GetOrg(ctx, repo.Owner); err != nil {
			return Effective{}, err
		}
	}
	repoMode := repo_model.DeleteBranchInherit
	if u, err := repo.GetUnit(ctx, unit.TypePullRequests); err == nil {
		repoMode = u.PullRequestsConfig().GetDeleteBranchAfterMerge()
	}
	e := Resolve(instanceMode(), orgMode, orgLocked, repoMode)
	if e.Source == SourceOrg {
		e.SetBy = repo.Owner.Name
	}
	return e, nil
}

// IsAlways tells if every merge into the repository deletes the head branch.
func IsAlways(ctx context.Context, repo *repo_model.Repository) (bool, error) {
	e, err := GetEffective(ctx, repo)
	return e.Mode == repo_model.DeleteBranchAlways, err
}

// SetOrg stores the organization's value. Inherit removes it. Enforcing needs an explicit value.
func SetOrg(ctx context.Context, org *user_model.User, mode repo_model.DeleteBranchMode, locked bool) error {
	if locked && mode == repo_model.DeleteBranchInherit {
		return ErrLockWithoutValue
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		stored, err := user_model.GetSettings(ctx, org.ID, []string{keyDeleteAfterMerge, keyDeleteAfterMergeLocked})
		if err != nil {
			return err
		}
		before := map[string]any{"mode": repo_model.DeleteBranchInherit.String(), "locked": false}
		if s := stored[keyDeleteAfterMerge]; s != nil {
			m, _ := repo_model.ParseDeleteBranchMode(s.SettingValue)
			before["mode"] = m.String()
		}
		if s := stored[keyDeleteAfterMergeLocked]; s != nil {
			before["locked"] = s.SettingValue == "true"
		}
		set := func(key, value string, keep bool) error {
			if !keep {
				return user_model.DeleteUserSetting(ctx, org.ID, key)
			}
			return user_model.SetUserSetting(ctx, org.ID, key, value)
		}
		if err := set(keyDeleteAfterMerge, mode.String(), mode != repo_model.DeleteBranchInherit); err != nil {
			return err
		}
		if err := set(keyDeleteAfterMergeLocked, "true", locked); err != nil {
			return err
		}
		if changes := audit_model.Changes(before, map[string]any{"mode": mode.String(), "locked": locked}); changes != nil {
			return user_model.RecordOrg(ctx, "org.branch_workflow.changed", org, changes)
		}
		return nil
	})
}

// SetRepo stores the repository's own value unless the organization enforces one.
func SetRepo(ctx context.Context, repo *repo_model.Repository, mode repo_model.DeleteBranchMode) error {
	e, err := GetEffective(ctx, repo)
	if err != nil {
		return err
	}
	if e.Locked {
		return ErrLocked
	}
	u, err := repo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return ErrNoPullRequests
	}
	cfg := u.PullRequestsConfig()
	before := cfg.GetDeleteBranchAfterMerge()
	cfg.DeleteBranchAfterMerge, cfg.DefaultDeleteBranchAfterMerge = mode, false
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := repo_model.UpdateRepoUnit(ctx, u); err != nil {
			return err
		}
		if changes := audit_model.Changes(map[string]any{"mode": before.String()}, map[string]any{"mode": mode.String()}); changes != nil {
			return repo_model.RecordRepo(ctx, "repo.branch_workflow.changed", repo, changes)
		}
		return nil
	})
}

// SetByText says who decided the value, for the merge box and the settings pages.
func SetByText(l translation.Locale, e Effective) string {
	switch e.Source {
	case SourceOrg:
		return l.TrString("repo.pulls.delete_after_merge.set_by_org", e.SetBy)
	case SourceRepo:
		return l.TrString("repo.pulls.delete_after_merge.set_by_repo")
	}
	return l.TrString("repo.pulls.delete_after_merge.set_by_instance")
}
