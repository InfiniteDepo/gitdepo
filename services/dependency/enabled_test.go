// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"fmt"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestResolve(t *testing.T) {
	for _, site := range []bool{false, true} {
		for _, orgOn := range []bool{false, true} {
			for _, locked := range []bool{false, true} {
				for _, repoOn := range []bool{false, true} {
					want := site && orgOn && (locked || repoOn)
					assert.Equal(t, want, Resolve(site, orgOn, locked, repoOn), "site %v org %v locked %v repo %v", site, orgOn, locked, repoOn)
				}
			}
		}
	}
	// the cases the settings pages name
	assert.False(t, Resolve(false, true, true, true), "the site switch is the master")
	assert.False(t, Resolve(true, false, true, true), "an organization that is off is off for every repository")
	assert.True(t, Resolve(true, true, true, false), "a lock keeps a repository that turned it off on")
	assert.False(t, Resolve(true, true, false, false), "without a lock the repository's own switch decides")
}

// lastRevision is the highest settings revision a test of this package stored.
var lastRevision int

// bumpRevision moves the settings revision past every one an earlier test stored: fixtures reset it, and a value is
// cached by revision, so two tests storing different values under one revision would read the first one's.
func bumpRevision(t *testing.T) {
	t.Helper()
	lastRevision = max(lastRevision, system_model.GetRevision(db.DefaultContext)) + 1
	_, err := db.Exec(db.DefaultContext, "UPDATE system_setting SET version=? WHERE setting_key='revision'", lastRevision)
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
}

// storeSiteSwitch stores the site switch as the admin page does and moves the settings revision past the cached one.
func storeSiteSwitch(t *testing.T, mode string) {
	t.Helper()
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().DependencyGraph.DynKey(): `{"mode":"` + mode + `"}`}))
	bumpRevision(t)
}

func setOrgSwitch(t *testing.T, orgID int64, on, locked bool) {
	t.Helper()
	for k, v := range map[string]bool{repo_model.DependencyGraphOrgKey: !on, repo_model.DependencyGraphOrgLockedKey: locked} {
		value := "true"
		if k == repo_model.DependencyGraphOrgKey {
			value = "false"
		}
		if v {
			require.NoError(t, user_model.SetUserSetting(db.DefaultContext, orgID, k, value))
		} else {
			require.NoError(t, user_model.DeleteUserSetting(db.DefaultContext, orgID, k))
		}
	}
}

// The SQL form of the rule (used by the cron task and the purge) agrees with Enabled for every fixture repository
// in every combination of the organization's switch, its lock and the repository's own switch.
func TestDependencyGraphOffCondMatchesEnabled(t *testing.T) {
	enable(t)
	var repos []*repo_model.Repository
	require.NoError(t, db.GetEngine(t.Context()).Find(&repos))
	for _, orgOn := range []bool{false, true} {
		for _, locked := range []bool{false, true} {
			for _, repoOff := range []bool{false, true} {
				name := fmt.Sprintf("org %v locked %v repo off %v", orgOn, locked, repoOff)
				setOrgSwitch(t, 3, orgOn, locked)
				// every other repository keeps its own value: repoOff applies to the even IDs
				_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET dependency_graph_disabled = (id % 2 = 0 AND ?)", repoOff)
				require.NoError(t, err)
				var off []int64
				require.NoError(t, db.GetEngine(t.Context()).Table("repository").Where(repo_model.DependencyGraphOffCond()).Cols("id").Find(&off))
				offSet := map[int64]bool{}
				for _, id := range off {
					offSet[id] = true
				}
				for _, r := range repos {
					fresh := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: r.ID})
					assert.Equal(t, !offSet[r.ID], Enabled(t.Context(), fresh), "%s: repository %d", name, r.ID)
				}
			}
		}
	}
	setOrgSwitch(t, 3, true, false)
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET dependency_graph_disabled = ?", false)
	require.NoError(t, err)
}

func storeRows(t *testing.T, repoIDs ...int64) {
	t.Helper()
	for _, id := range repoIDs {
		require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), &repo_model.DependencyScan{RepoID: id, CommitSHA: "abc", Status: repo_model.DependencyScanOK},
			[]*repo_model.Dependency{{RepoID: id, Ecosystem: "Go", Name: "x", Version: "v1"}}))
	}
}

func hasRows(t *testing.T, repoID int64) bool {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Where("repo_id = ?", repoID).Count(new(repo_model.Dependency))
	require.NoError(t, err)
	s, err := repo_model.GetRepoDependencyScan(t.Context(), repoID)
	require.NoError(t, err)
	return n > 0 || s != nil
}

func lastAudit(t *testing.T, action string) *audit_model.Entry {
	t.Helper()
	e := new(audit_model.Entry)
	has, err := db.GetEngine(t.Context()).Where(builder.Eq{"action": action}).OrderBy("id DESC").Get(e)
	require.NoError(t, err)
	require.True(t, has, "no %s entry", action)
	return e
}

func TestSetRepoSwitch(t *testing.T) {
	enable(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // of org 3
	storeRows(t, 3, 5)

	// off deletes the repository's rows, in the same transaction as the setting, and is recorded
	require.NoError(t, SetRepoSwitch(t.Context(), repo, false))
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}).DependencyGraphDisabled)
	assert.False(t, hasRows(t, 3))
	assert.True(t, hasRows(t, 5), "another repository keeps its rows")
	e := lastAudit(t, "repo.repository.updated")
	assert.EqualValues(t, 3, e.RepoID)
	assert.Contains(t, e.Data, `"dependency_graph":false`)

	// the organization's lock decides: the repository can't change it, either way
	setOrgSwitch(t, 3, true, true)
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	assert.True(t, Enabled(t.Context(), repo), "a locked organization keeps it on")
	require.ErrorIs(t, SetRepoSwitch(t.Context(), repo, true), ErrSwitchLocked)
	setOrgSwitch(t, 3, false, false)
	require.ErrorIs(t, SetRepoSwitch(t.Context(), repo, true), ErrSwitchLocked, "the organization turned it off")
	setOrgSwitch(t, 3, true, false)
	require.NoError(t, SetRepoSwitch(t.Context(), repo, true))
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}).DependencyGraphDisabled)

	// a personal repository has no organization level
	personal := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	sw, err := GetRepoSwitch(t.Context(), personal)
	require.NoError(t, err)
	assert.Nil(t, sw.Org)
	assert.True(t, sw.CanChange())
}

func TestSetOrgSwitch(t *testing.T) {
	enable(t)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	// repository 5 of the organization is trashed: its rows go too
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 5")
	require.NoError(t, err)
	storeRows(t, 1, 3, 5)

	require.NoError(t, SetOrgSwitch(t.Context(), org, false, false))
	assert.False(t, hasRows(t, 3))
	assert.False(t, hasRows(t, 5))
	assert.True(t, hasRows(t, 1), "a repository of another owner keeps its rows")
	e := lastAudit(t, "org.dependency_graph.changed")
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Contains(t, e.Data, `"dependency_graph":false`)
	sw, err := GetOrgSwitch(t.Context(), 3)
	require.NoError(t, err)
	assert.Equal(t, OrgSwitch{On: false, Locked: false}, sw)

	require.NoError(t, SetOrgSwitch(t.Context(), org, true, true))
	sw, err = GetOrgSwitch(t.Context(), 3)
	require.NoError(t, err)
	assert.Equal(t, OrgSwitch{On: true, Locked: true}, sw)
	assert.Contains(t, lastAudit(t, "org.dependency_graph.changed").Data, `"dependency_graph_locked":true`)

	// the site switch is the master: the organization can't change anything while it is off
	defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
	config.GetDynGetter().InvalidateCache()
	require.ErrorIs(t, SetOrgSwitch(t.Context(), org, true, false), ErrSwitchLocked)
	setOrgSwitch(t, 3, true, false)
}

// Every change of an organization's switch deletes the rows of its repositories that are now off at once, and of
// no other owner's; a save that changes nothing does nothing.
func TestSetOrgSwitchApplies(t *testing.T) {
	enable(t)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	t.Cleanup(func() {
		setOrgSwitch(t, 3, true, false)
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET dependency_graph_disabled = ?", false)
		require.NoError(t, err)
	})
	// repository 3 (org 3) and 23 (org 17) turned it off themselves, then org 3 locked it on
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id IN (3, 23)", true)
	require.NoError(t, err)
	require.NoError(t, SetOrgSwitch(t.Context(), org, true, true))
	storeRows(t, 3, 23) // 23's rows are left over: another organization's, which org 3's switch must not touch

	// the lock lifted: repository 3's own off applies again, and its rows go now, not at the next cron run
	require.NoError(t, SetOrgSwitch(t.Context(), org, true, false))
	assert.False(t, Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})))
	assert.False(t, hasRows(t, 3))
	assert.True(t, hasRows(t, 23), "another organization's repository")

	// the same values again: nothing is recorded or deleted
	storeRows(t, 3)
	before := lastAudit(t, "org.dependency_graph.changed").ID
	require.NoError(t, SetOrgSwitch(t.Context(), org, true, false))
	assert.Equal(t, before, lastAudit(t, "org.dependency_graph.changed").ID)
	assert.True(t, hasRows(t, 3))
}

// A transfer changes the organization whose switch decides: the notifier applies the new owner's at once.
func TestTransferAppliesSwitches(t *testing.T) {
	enable(t)
	t.Cleanup(func() {
		setOrgSwitch(t, 3, true, false)
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET owner_id = 2, dependency_graph_disabled = ? WHERE id = 1", false)
		require.NoError(t, err)
	})
	transfer := func(repoID, ownerID int64) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET owner_id = ? WHERE id = ?", ownerID, repoID)
		require.NoError(t, err)
		(&notifier{}).TransferRepository(t.Context(), nil, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID}), "")
	}

	// into an organization that is off
	setOrgSwitch(t, 3, false, false)
	storeRows(t, 1)
	transfer(1, 3)
	assert.False(t, hasRows(t, 1))

	// out of an organization that locked it on, to an owner where its own off applies
	setOrgSwitch(t, 3, true, true)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = 1", true)
	require.NoError(t, err)
	storeRows(t, 1)
	transfer(1, 3)
	assert.True(t, hasRows(t, 1), "still on: locked")
	transfer(1, 2)
	assert.False(t, hasRows(t, 1))
}

// The check inside the scan's write transaction reads the stored rows, and agrees with Enabled.
func TestEnabledStored(t *testing.T) {
	enable(t)
	t.Cleanup(func() {
		setOrgSwitch(t, 3, true, false)
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET dependency_graph_disabled = ?", false)
		require.NoError(t, err)
		storeSiteSwitch(t, "")
	})
	stored := func(id int64) bool {
		var on bool
		require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) (err error) {
			on, err = enabledStored(ctx, id)
			return err
		}))
		return on
	}
	for _, c := range []struct {
		site          string
		orgOn, locked bool
		repoOff       bool
	}{
		{"", true, false, false}, {"off", true, false, false}, {"", false, false, false}, {"", true, false, true}, {"", true, true, true}, {"maybe", true, false, false},
	} {
		storeSiteSwitch(t, c.site)
		setOrgSwitch(t, 3, c.orgOn, c.locked)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id IN (1, 3)", c.repoOff)
		require.NoError(t, err)
		for _, id := range []int64{1, 3} {
			want := Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id}))
			assert.Equal(t, want, stored(id), "%+v: repository %d", c, id)
		}
	}
	assert.False(t, stored(1_000_000), "a repository that is gone")
}

func TestSetSiteEnabled(t *testing.T) {
	enable(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	storeRows(t, 1, 3)
	t.Cleanup(func() {
		require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().DependencyGraph.DynKey(): ""}))
		bumpRevision(t)
	})

	// a stored value wins over app.ini, both ways
	require.NoError(t, SetSiteEnabled(t.Context(), admin, false))
	bumpRevision(t)
	assert.False(t, SiteEnabled(t.Context()), "stored off wins over ENABLED = true")
	assert.False(t, hasRows(t, 1))
	assert.False(t, hasRows(t, 3))
	e := lastAudit(t, "admin.setting.changed")
	assert.Contains(t, e.Data, "dependency_graph.enabled")
	assert.Contains(t, e.Data, `off`)

	defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
	require.NoError(t, SetSiteEnabled(t.Context(), admin, true))
	bumpRevision(t)
	assert.True(t, SiteEnabled(t.Context()), "stored on wins over ENABLED = false")

	// a value that can't be read fails closed
	storeSiteSwitch(t, "maybe")
	assert.False(t, SiteEnabled(t.Context()))
}
