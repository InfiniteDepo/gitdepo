// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"errors"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"

	"xorm.io/builder"
)

var (
	// ErrSwitchLocked is a change of a switch that a higher level decides.
	ErrSwitchLocked = errors.New("the secret scanning switch is set by a higher level")
	// ErrNotEnabled is a rescan of a repository secret scanning is off for.
	ErrNotEnabled = errors.New("secret scanning is off for the repository")
)

// RepoSwitch is the state of the switches for a repository.
type RepoSwitch struct {
	Site    bool
	Org     *OrgSwitch // nil for a personal repository
	Own     bool       // the repository's own setting
	Enabled bool
}

// CanChange reports whether the repository's own setting decides: the site and the organization are on and the
// organization doesn't lock it.
func (s RepoSwitch) CanChange() bool {
	return s.Site && (s.Org == nil || s.Org.On && !s.Org.Locked)
}

// GetRepoSwitch reads every level for a repository.
func GetRepoSwitch(ctx context.Context, repo *repo_model.Repository) (RepoSwitch, error) {
	s := RepoSwitch{Site: SiteEnabled(ctx), Own: !repo.SecretScanningDisabled}
	if err := repo.LoadOwner(ctx); err != nil {
		return s, err
	}
	org := OrgSwitch{On: true}
	if repo.Owner.IsOrganization() {
		var err error
		if org, err = GetOrgSwitch(ctx, repo.OwnerID); err != nil {
			return s, err
		}
		s.Org = &org
	}
	s.Enabled = Resolve(s.Site, org.On, org.Locked, s.Own)
	return s, nil
}

// SetRepoSwitch stores the repository's own switch and audits the change. Turning it off keeps the alerts; turning
// it on queues a scan. While the site or the organization decides, it returns ErrSwitchLocked.
func SetRepoSwitch(ctx context.Context, repo *repo_model.Repository, on bool) error {
	s, err := GetRepoSwitch(ctx, repo)
	if err != nil {
		return err
	}
	if !s.CanChange() {
		return ErrSwitchLocked
	}
	if s.Own == on {
		return nil
	}
	err = db.WithTx(ctx, func(ctx context.Context) error {
		repo.SecretScanningDisabled = !on
		if err := repo_model.RecordRepoChange(ctx, repo); err != nil {
			return err
		}
		if err := repo_model.UpdateRepositoryCols(ctx, repo, "secret_scanning_disabled"); err != nil {
			return err
		}
		if !on {
			return nil
		}
		// a digest mark that waited while it was off keeps its alerts, but its pusher must not be credited with a later push
		_, err := secretscan_model.DetachNotifyPushers(ctx, builder.Eq{"repo_id": repo.ID})
		return err
	})
	if err != nil {
		repo.SecretScanningDisabled = !s.Own
		return err
	}
	if on {
		Enqueue(repo.ID)
	}
	return nil
}

// Rescan forgets what was scanned (and so the holes) and scans the repository from the beginning; the alerts stay.
// The scan runs only while secret scanning is on. Without scan state (a scan is queued or running, or none ran yet)
// there is nothing to forget: it only queues the repository (the queue drops duplicates) and writes no audit entry.
func Rescan(ctx context.Context, repo *repo_model.Repository) error {
	if !Enabled(ctx, repo) {
		return ErrNotEnabled
	}
	err := db.WithTx(ctx, func(ctx context.Context) error {
		// the reset is the claim: of two rescans at once only one changes a row and is audited; a scan already running
		// finds its state row moved and its write fails (secretscan_model.Save: ErrScanMoved), so it is queued again, never saved
		n, err := secretscan_model.ResetScans(ctx, repo.ID)
		if err != nil || n == 0 {
			return err
		}
		// the action key is a literal: TestActionCatalog finds it in the code
		return repo_model.RecordRepo(ctx, "repo.secret_scanning.rescanned", repo, map[string]any{})
	})
	if err != nil {
		return err
	}
	Enqueue(repo.ID)
	return nil
}
