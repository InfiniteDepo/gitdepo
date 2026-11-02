// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetOrgRetention removes the retention of org3 after the test: user_setting has no fixture, so PrepareTestEnv
// leaves the row to the next test (a cleanup that deletes runs would find it).
func resetOrgRetention(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { require.NoError(t, actions_model.SetOrgRunRetentionDays(db.DefaultContext, 3, 0)) })
}

func reloadedActionsConfig(t *testing.T) *repo_model.ActionsConfig {
	t.Helper()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	u, err := repo.GetUnit(t.Context(), unit.TypeActions)
	require.NoError(t, err)
	return u.ActionsConfig()
}

func TestActionsRunRetentionRepoSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user2")
	collaborator := loginUser(t, "user5") // write access, no admin
	postURL := "/user2/repo1/settings/actions/retention"
	days := func() int64 {
		return reloadedActionsConfig(t).RunRetentionDays
	}
	post := func(sess *TestSession, value string, status int) {
		sess.MakeRequest(t, NewRequestWithValues(t, "POST", postURL, map[string]string{"run_retention_days": value}), status)
	}

	t.Run("admin sets and clears it", func(t *testing.T) {
		post(admin, "7", http.StatusSeeOther)
		assert.EqualValues(t, 7, days())

		page := admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/actions/general"), http.StatusOK).Body.String()
		assert.Contains(t, page, `name="run_retention_days"`)
		assert.Contains(t, page, `value="7"`)
		// the runs list tells everyone the effective period
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/actions"), http.StatusOK).Body.String(), "Runs older than 7 days are deleted automatically.")

		post(admin, "", http.StatusSeeOther)
		assert.Zero(t, days())
	})

	t.Run("invalid values are refused", func(t *testing.T) {
		post(admin, "7", http.StatusSeeOther)
		for _, value := range []string{"abc", "-1", "36501", "1.5", "99999999999999999999"} {
			post(admin, value, http.StatusSeeOther)
			assert.EqualValues(t, 7, days(), value)
		}
	})

	t.Run("the general form keeps it", func(t *testing.T) {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general", map[string]string{"default_token_permissions": "read"}), http.StatusSeeOther)
		cfg := reloadedActionsConfig(t)
		assert.EqualValues(t, 7, cfg.RunRetentionDays)
		assert.Equal(t, "read", cfg.DefaultTokenPermissions)
	})

	t.Run("an archived repository is refused", func(t *testing.T) {
		require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), &repo_model.Repository{ID: 1, IsArchived: true}, "is_archived"))
		post(admin, "1", http.StatusNotFound)
		assert.EqualValues(t, 7, days())
		require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), &repo_model.Repository{ID: 1, IsArchived: false}, "is_archived"))
	})

	t.Run("only repository admins", func(t *testing.T) {
		post(collaborator, "1", http.StatusNotFound)
		MakeRequest(t, NewRequestWithValues(t, "POST", postURL, map[string]string{"run_retention_days": "1"}), http.StatusSeeOther) // sign-in redirect
		assert.EqualValues(t, 7, days())
	})
}

func TestActionsRunRetentionOrgSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	resetOrgRetention(t)

	owner := loginUser(t, "user2")  // owner of org3
	member := loginUser(t, "user4") // member of org3, not an owner
	other := loginUser(t, "user8")
	pageURL := "/org/org3/settings/actions/retention"
	days := func() int64 {
		d, err := actions_model.GetOrgRunRetentionDays(t.Context(), 3)
		require.NoError(t, err)
		return d
	}
	post := func(sess *TestSession, value string, status int) {
		sess.MakeRequest(t, NewRequestWithValues(t, "POST", pageURL, map[string]string{"run_retention_days": value}), status)
	}

	t.Run("owner sets and clears it", func(t *testing.T) {
		assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body.String(), `name="run_retention_days"`)

		post(owner, "14", http.StatusSeeOther)
		assert.EqualValues(t, 14, days())
		assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body.String(), `value="14"`)

		post(owner, "", http.StatusSeeOther)
		assert.Zero(t, days())
	})

	t.Run("invalid values are refused", func(t *testing.T) {
		post(owner, "14", http.StatusSeeOther)
		for _, value := range []string{"abc", "-1", "36501"} {
			post(owner, value, http.StatusSeeOther)
			assert.EqualValues(t, 14, days(), value)
		}
	})

	t.Run("only owners see and change it", func(t *testing.T) {
		for _, sess := range []*TestSession{member, other} {
			sess.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusNotFound)
			post(sess, "1", http.StatusNotFound)
		}
		MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusSeeOther) // sign-in redirect
		MakeRequest(t, NewRequestWithValues(t, "POST", pageURL, map[string]string{"run_retention_days": "1"}), http.StatusSeeOther)
		assert.EqualValues(t, 14, days())
	})
}

// An owner the two-factor requirement of the organization blocks is no owner.
func TestActionsRunRetentionOrgTwoFactor(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	resetOrgRetention(t)

	owner := loginUser(t, "user2") // before anyone enrols: the login form would ask for the second factor
	pageURL := "/org/org3/settings/actions/retention"
	_, err := db.GetEngine(t.Context()).ID(3).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
	require.NoError(t, err)

	owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusNotFound)
	owner.MakeRequest(t, NewRequestWithValues(t, "POST", pageURL, map[string]string{"run_retention_days": "14"}), http.StatusNotFound)
	days, err := actions_model.GetOrgRunRetentionDays(t.Context(), 3)
	require.NoError(t, err)
	assert.Zero(t, days)

	enrolTOTP(t, 2)
	// the table is only reset by the next test that prepares its environment: a test that logs in first (e.g.
	// TestActionRunPrioritization) would meet a user who asks for the second factor
	t.Cleanup(func() { unenrolTOTP(t, 2) })
	owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK)
	owner.MakeRequest(t, NewRequestWithValues(t, "POST", pageURL, map[string]string{"run_retention_days": "14"}), http.StatusSeeOther)
	days, err = actions_model.GetOrgRunRetentionDays(t.Context(), 3)
	require.NoError(t, err)
	assert.EqualValues(t, 14, days)
}

// A repository admin who is no organization owner sees the effective period of the repository, never the
// organization's own value.
func TestActionsRunRetentionOrgValueHidden(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	resetOrgRetention(t)
	ctx := db.DefaultContext

	// user28 is in an admin team of org3 that is given repo3; the repository's own setting is shorter
	require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: 12, RepoID: 3}))
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{RunRetentionDays: 100}})
	require.NoError(t, actions_model.SetOrgRunRetentionDays(ctx, 3, 3999))
	teamAdmin := loginUser(t, "user28")

	general := teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/settings/actions/general"), http.StatusOK).Body.String()
	assert.Contains(t, general, "currently deleted after 100 days")
	list := teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/actions"), http.StatusOK).Body.String()
	assert.Contains(t, list, "Runs older than 100 days are deleted automatically.")
	for name, page := range map[string]string{"general": general, "list": list} {
		assert.NotContains(t, page, "3999", name)
	}
	// and the organization's page is not theirs
	teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/actions/retention"), http.StatusNotFound)
}

// AC2: the cleanup reads the settings once; its queries don't grow with the runs or the repositories with a setting.
func TestCleanupRunsQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	resetOrgRetention(t)
	defer test.MockVariableValue(&setting.Actions.RunRetentionDays, 30)()
	ctx := db.DefaultContext

	nextID := int64(700000)
	insertRuns := func(n int, days int64) {
		for range n {
			nextID++
			unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: nextID, Index: nextID, RepoID: 4, OwnerID: 5, Ref: "refs/heads/feature", WorkflowID: "a.yaml", Status: actions_model.StatusSuccess})
			_, err := db.GetEngine(ctx).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-time.Duration(days)*24*time.Hour), nextID)
			require.NoError(t, err)
		}
	}
	cleanup := func() { require.NoError(t, actions_service.CleanupRuns(ctx)) }

	// a short setting of another repository makes the scan reach back to the 10 day old runs, which the default
	// of 30 days spares: they are read but not deleted
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{RunRetentionDays: 1}})
	cleanup() // removes the old fixture runs, warms the caches
	insertRuns(5, 10)
	few := stableQueryCount(t, cleanup)

	insertRuns(120, 10) // more than one batch
	for i := range 5 {
		unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: int64(60 + i), Type: unit.TypeActions, Config: &repo_model.ActionsConfig{RunRetentionDays: int64(2 + i)}})
	}
	require.NoError(t, actions_model.SetOrgRunRetentionDays(ctx, 3, 50))
	many := stableQueryCount(t, cleanup)

	unittest.AssertCount(t, &actions_model.ActionRun{RepoID: 4, Ref: "refs/heads/feature"}, 125)
	// one more batch read, nothing per run, repository or organization
	assert.LessOrEqual(t, many-few, int64(1), "few: %d, many: %d", few, many)
}
