// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
)

// The switches of secret scanning, at three levels:
//   - site: the dynamic setting secret_scanning.enabled, whose default is app.ini [secret_scanning] ENABLED;
//   - organization: owners turn it off for every repository of the organization, or lock it, so repositories can't
//     change it (user settings secretscan_model.OrgKey and OrgLockedKey; no row = on);
//   - repository: admins turn it off (repository.secret_scanning_disabled), unless the organization locked it.
//
// Enabled is the one rule; secretscan_model.OffCond is its SQL form. Off means: no scan. The stored alerts are kept
// (they are deleted with the repository), and turning it on again scans from the stored state.

// Resolve is the rule: the site switch, then the organization's, then the repository's own unless the organization
// locked it.
func Resolve(site, orgOn, orgLocked, repoOn bool) bool {
	return site && orgOn && (orgLocked || repoOn)
}

// SiteEnabled is the site switch in force.
func SiteEnabled(ctx context.Context) bool {
	return setting.Config().SecretScanning.Value(ctx).Enabled()
}

// OrgSwitch is an organization's switch.
type OrgSwitch struct {
	On, Locked bool
}

// GetOrgSwitch reads the switch of an organization, once per request.
func GetOrgSwitch(ctx context.Context, orgID int64) (OrgSwitch, error) {
	return cache.GetWithContextCache(ctx, "secret_scanning_org", orgID, func() (OrgSwitch, error) {
		return readOrgSwitch(ctx, orgID)
	})
}

// readOrgSwitch reads the stored switch of an organization (no cache).
func readOrgSwitch(ctx context.Context, orgID int64) (OrgSwitch, error) {
	stored, err := user_model.GetSettings(ctx, orgID, []string{secretscan_model.OrgKey, secretscan_model.OrgLockedKey})
	if err != nil {
		return OrgSwitch{}, err
	}
	s := OrgSwitch{On: true} // no row = on, unlocked
	if v := stored[secretscan_model.OrgKey]; v != nil && v.SettingValue == "false" {
		s.On = false
	}
	if v := stored[secretscan_model.OrgLockedKey]; v != nil && v.SettingValue == "true" {
		s.Locked = true
	}
	return s, nil
}

// Enabled tells whether secret scanning is on for the repository. An error reads as off.
func Enabled(ctx context.Context, repo *repo_model.Repository) bool {
	if !SiteEnabled(ctx) {
		return false // no query while the site is off
	}
	if err := repo.LoadOwner(ctx); err != nil {
		log.Error("secret scanning: load the owner of repository %d: %v", repo.ID, err)
		return false
	}
	org := OrgSwitch{On: true}
	if repo.Owner.IsOrganization() {
		var err error
		if org, err = GetOrgSwitch(ctx, repo.OwnerID); err != nil {
			log.Error("secret scanning: read the switch of organization %d: %v", repo.OwnerID, err)
			return false
		}
	}
	return Resolve(true, org.On, org.Locked, !repo.SecretScanningDisabled)
}

// enabledStored is Enabled read from the stored rows, without a cache, inside the caller's transaction: the scan's
// last check before it writes. It also returns the repository's owner, which the scan compares with the one it
// started with. When the site setting has a row, it is locked until the transaction ends, so a site switch stored
// meanwhile either waits for the write or is seen here. The organization's settings are read without a lock; a
// change that commits during the write only leaves rows, which turning it off keeps anyway.
func enabledStored(ctx context.Context, repoID int64) (enabled bool, ownerID int64, err error) {
	// Lock the repository row until the transaction ends: DeleteRepositoryDirectly takes the same lock first, so a
	// delete either waits for this write (and removes its rows) or has committed (the lookup below finds nothing).
	// The affected rows aren't checked: MySQL counts changed rows, so this no-op UPDATE reports 0 there.
	if _, err := db.Exec(ctx, "UPDATE repository SET id = id WHERE id = ?", repoID); err != nil {
		return false, 0, err
	}
	raw, has, err := system_model.GetSettingForUpdate(ctx, setting.Config().SecretScanning.DynKey())
	if err != nil {
		return false, 0, err
	}
	var site setting.SecretScanningState
	if has && raw != "" && json.Unmarshal([]byte(raw), &site) != nil {
		return false, 0, nil // as the setting reads it: a value that can't be parsed is off
	}
	if !site.Enabled() {
		return false, 0, nil
	}
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if repo_model.IsErrRepoNotExist(err) {
		return false, 0, nil // deleted or trashed
	}
	if err != nil {
		return false, 0, err
	}
	if err := repo.LoadOwner(ctx); err != nil {
		return false, 0, err
	}
	org := OrgSwitch{On: true}
	if repo.Owner.IsOrganization() {
		if org, err = readOrgSwitch(ctx, repo.OwnerID); err != nil {
			return false, 0, err
		}
	}
	return Resolve(true, org.On, org.Locked, !repo.SecretScanningDisabled), repo.OwnerID, nil
}
