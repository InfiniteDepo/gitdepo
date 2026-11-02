// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oldRunsFixture removes the runs of user2/repo1 and inserts runs for the rules of "delete runs older than":
// the IDs of those that are deleted at 30 days, and of those that are not.
type oldRunsFixture struct {
	deleted, spared []int64
	otherRepo       int64
}

func newOldRunsFixture(t *testing.T) *oldRunsFixture {
	t.Helper()
	_, err := db.GetEngine(db.DefaultContext).Exec("DELETE FROM action_run WHERE repo_id = 1 OR id >= 900000") // earlier cases of the same test
	require.NoError(t, err)
	f := &oldRunsFixture{}
	nextID := int64(900000)
	insert := func(repoID, days int64, status actions_model.Status, ref string, keep bool) int64 {
		nextID++
		unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: nextID, Index: nextID, RepoID: repoID, OwnerID: 2, Ref: ref, WorkflowID: "a.yaml", Status: status, Keep: keep})
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-time.Duration(days)*24*time.Hour), nextID)
		require.NoError(t, err)
		return nextID
	}
	f.deleted = []int64{
		insert(1, 40, actions_model.StatusSuccess, "refs/heads/feature", false),
		insert(1, 35, actions_model.StatusFailure, "refs/heads/feature", false),
	}
	f.spared = []int64{
		insert(1, 5, actions_model.StatusSuccess, "refs/heads/feature", false),  // recent
		insert(1, 40, actions_model.StatusSuccess, "refs/heads/feature", true),  // kept
		insert(1, 40, actions_model.StatusRunning, "refs/heads/feature", false), // running
		insert(1, 40, actions_model.StatusWaiting, "refs/heads/feature", false), // waiting
		insert(1, 90, actions_model.StatusSuccess, "refs/heads/master", false),  // the latest run on the default branch
	}
	f.otherRepo = insert(4, 40, actions_model.StatusSuccess, "refs/heads/feature", false)
	return f
}

func (f *oldRunsFixture) exists(t *testing.T, id int64) bool {
	t.Helper()
	has, err := db.GetEngine(db.DefaultContext).ID(id).Exist(new(actions_model.ActionRun))
	require.NoError(t, err)
	return has
}

func (f *oldRunsFixture) assertUntouched(t *testing.T) {
	t.Helper()
	for _, id := range append(append([]int64{}, f.deleted...), append(f.spared, f.otherRepo)...) {
		assert.True(t, f.exists(t, id), id)
	}
}

func (f *oldRunsFixture) assertDeleted(t *testing.T) {
	t.Helper()
	for _, id := range f.deleted {
		assert.False(t, f.exists(t, id), id)
	}
	for _, id := range append(f.spared, f.otherRepo) {
		assert.True(t, f.exists(t, id), id)
	}
}

func TestActionsDeleteOldRunsWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user2")
	collaborator := loginUser(t, "user5") // write access, no admin
	base := "/user2/repo1/settings/actions/runs/delete"
	page := func(sess *TestSession, query string, status int) string {
		return sess.MakeRequest(t, NewRequest(t, "GET", base+query), status).Body.String()
	}
	post := func(sess *TestSession, days string, status int) {
		sess.MakeRequest(t, NewRequestWithValues(t, "POST", base, map[string]string{"older_than": days}), status)
	}

	t.Run("the settings page offers it", func(t *testing.T) {
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/actions/general"), http.StatusOK).Body.String(), `name="older_than"`)
	})

	t.Run("the preview counts and deletes nothing", func(t *testing.T) {
		f := newOldRunsFixture(t)
		body := page(admin, "?older_than=30", http.StatusOK)
		assert.Contains(t, body, "Matching runs that can be deleted: 2")
		assert.Contains(t, body, "Delete these runs")
		f.assertUntouched(t)

		assert.Contains(t, page(admin, "?older_than=100", http.StatusOK), "No runs match.")
		f.assertUntouched(t)
	})

	t.Run("invalid values are refused", func(t *testing.T) {
		f := newOldRunsFixture(t)
		for _, days := range []string{"", "0", "-3", "36501", "abc", "1.5", "99999999999999999999"} {
			page(admin, "?older_than="+url.QueryEscape(days), http.StatusSeeOther)
			post(admin, days, http.StatusSeeOther)
		}
		f.assertUntouched(t)
	})

	t.Run("the confirmation deletes", func(t *testing.T) {
		f := newOldRunsFixture(t)
		post(admin, "30", http.StatusSeeOther)
		f.assertDeleted(t)
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/actions/general"), http.StatusOK).Body.String(), "Deleted 2 runs.")
	})

	t.Run("at most 100 runs at once", func(t *testing.T) {
		f := newOldRunsFixture(t)
		for i := range 105 {
			id := int64(910000 + i)
			unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: id, Index: id, RepoID: 1, OwnerID: 2, Ref: "refs/heads/feature", WorkflowID: "b.yaml", Status: actions_model.StatusSuccess})
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-40*24*time.Hour), id)
			require.NoError(t, err)
		}
		assert.Contains(t, page(admin, "?older_than=30", http.StatusOK), "Matching runs that can be deleted: 107")

		post(admin, "30", http.StatusSeeOther)
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/actions/general"), http.StatusOK).Body.String(), "More runs match: delete again to continue.")
		left, err := db.GetEngine(db.DefaultContext).Where("repo_id = 1 AND status = ? AND created < ?", actions_model.StatusSuccess, timeutil.TimeStampNow().AddDuration(-30*24*time.Hour)).Count(new(actions_model.ActionRun))
		require.NoError(t, err)
		assert.EqualValues(t, 107-100+2, left) // + the kept run and the latest run on the default branch

		post(admin, "30", http.StatusSeeOther)
		f.assertDeleted(t)
	})

	t.Run("runs with unfinished jobs are skipped, and the page doesn't offer endless repeats", func(t *testing.T) {
		f := newOldRunsFixture(t)
		for i := range 101 {
			id := int64(920000 + i)
			unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: id, Index: id, RepoID: 1, OwnerID: 2, Ref: "refs/heads/feature", WorkflowID: "c.yaml", Status: actions_model.StatusSuccess})
			unittest.AssertSuccessfulInsert(t, &actions_model.ActionRunJob{ID: id, Handle: fmt.Sprintf("stuck-%d", id), RunID: id, RepoID: 1, OwnerID: 2, Status: actions_model.StatusRunning})
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-40*24*time.Hour), id)
			require.NoError(t, err)
		}
		post(admin, "30", http.StatusSeeOther)
		assert.False(t, f.exists(t, f.deleted[0]))
		// what is left selected are the stuck runs only: nothing more can be deleted
		post(admin, "30", http.StatusSeeOther)
		body := admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/actions/general"), http.StatusOK).Body.String()
		assert.Contains(t, body, "No run was deleted: the matching runs have jobs that have not finished")
		assert.NotContains(t, body, "delete again to continue")
		assert.True(t, f.exists(t, 920000))
	})

	t.Run("an access token doesn't sign in to the web page", func(t *testing.T) {
		f := newOldRunsFixture(t)
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		MakeRequest(t, NewRequestWithValues(t, "POST", base, map[string]string{"older_than": "30"}).AddTokenAuth(token), http.StatusSeeOther) // sign-in redirect
		f.assertUntouched(t)
	})

	t.Run("only repository admins", func(t *testing.T) {
		f := newOldRunsFixture(t)
		page(collaborator, "?older_than=30", http.StatusNotFound)
		post(collaborator, "30", http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", base+"?older_than=30"), http.StatusSeeOther) // sign-in redirect
		MakeRequest(t, NewRequestWithValues(t, "POST", base, map[string]string{"older_than": "30"}), http.StatusSeeOther)
		f.assertUntouched(t)
	})

	t.Run("an archived repository", func(t *testing.T) {
		f := newOldRunsFixture(t)
		require.NoError(t, repo_model.UpdateRepositoryCols(db.DefaultContext, &repo_model.Repository{ID: 1, IsArchived: true}, "is_archived"))
		t.Cleanup(func() {
			require.NoError(t, repo_model.UpdateRepositoryCols(db.DefaultContext, &repo_model.Repository{ID: 1, IsArchived: false}, "is_archived"))
		})
		page(admin, "?older_than=30", http.StatusOK)
		post(admin, "30", http.StatusNotFound)
		f.assertUntouched(t)
	})
}

func TestActionsDeleteOldRunsAPI(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		writeToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		readToken := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		collaboratorToken := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)
		endpoint := "/api/v1/repos/user2/repo1/actions/runs"
		del := func(query, token string, status int) *api.DeleteActionRunsResult {
			req := NewRequest(t, "DELETE", endpoint+query)
			if token != "" {
				req.AddTokenAuth(token)
			}
			resp := MakeRequest(t, req, status)
			if status != http.StatusOK {
				return nil
			}
			var result api.DeleteActionRunsResult
			DecodeJSON(t, resp, &result)
			return &result
		}

		// a job token of a task of this repository, with the default (write) permissions
		repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
		original := *task
		t.Cleanup(func() {
			require.NoError(t, actions_model.UpdateTask(context.Background(), &original, "repo_id", "owner_id", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
		})
		task.RepoID, task.OwnerID, task.TokenPermissions = repo1.ID, repo1.OwnerID, ""
		task.GenerateToken()
		require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))

		t.Run("deletes what is old, done and not kept", func(t *testing.T) {
			f := newOldRunsFixture(t)
			assert.Equal(t, &api.DeleteActionRunsResult{Deleted: 2, More: false}, del("?older_than=30", writeToken, http.StatusOK))
			f.assertDeleted(t)
			assert.Equal(t, &api.DeleteActionRunsResult{Deleted: 0, More: false}, del("?older_than=30", writeToken, http.StatusOK))
		})

		t.Run("invalid older_than is a 422", func(t *testing.T) {
			f := newOldRunsFixture(t)
			for _, query := range []string{"", "?older_than=", "?older_than=0", "?older_than=-1", "?older_than=36501", "?older_than=abc", "?older_than=1.5", "?older_than=99999999999999999999"} {
				del(query, writeToken, http.StatusUnprocessableEntity)
			}
			f.assertUntouched(t)
		})

		t.Run("at most 100 runs per request", func(t *testing.T) {
			f := newOldRunsFixture(t)
			for i := range 105 {
				id := int64(910000 + i)
				unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: id, Index: id, RepoID: 1, OwnerID: 2, Ref: "refs/heads/feature", WorkflowID: "b.yaml", Status: actions_model.StatusSuccess})
				_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-40*24*time.Hour), id)
				require.NoError(t, err)
			}
			assert.Equal(t, &api.DeleteActionRunsResult{Deleted: 100, More: true}, del("?older_than=30", writeToken, http.StatusOK))
			assert.Equal(t, &api.DeleteActionRunsResult{Deleted: 7, More: false}, del("?older_than=30", writeToken, http.StatusOK))
			f.assertDeleted(t)
		})

		t.Run("admins only", func(t *testing.T) {
			f := newOldRunsFixture(t)
			del("?older_than=30", readToken, http.StatusForbidden)
			del("?older_than=30", collaboratorToken, http.StatusForbidden)
			del("?older_than=30", task.Token, http.StatusForbidden)
			del("?older_than=30", "", http.StatusUnauthorized)
			f.assertUntouched(t)
		})

		t.Run("an archived repository is locked", func(t *testing.T) {
			f := newOldRunsFixture(t)
			require.NoError(t, repo_model.UpdateRepositoryCols(db.DefaultContext, &repo_model.Repository{ID: 1, IsArchived: true}, "is_archived"))
			t.Cleanup(func() {
				require.NoError(t, repo_model.UpdateRepositoryCols(db.DefaultContext, &repo_model.Repository{ID: 1, IsArchived: false}, "is_archived"))
			})
			del("?older_than=30", writeToken, http.StatusLocked)
			f.assertUntouched(t)
		})

		t.Run("another repository's runs survive, and are not reachable", func(t *testing.T) {
			f := newOldRunsFixture(t)
			// old done runs of a second, existing repository (user5/repo4) of another owner
			var others []int64
			for i := range 3 {
				id := int64(930000 + i)
				others = append(others, id)
				unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: id, Index: id, RepoID: 4, OwnerID: 5, Ref: "refs/heads/feature", WorkflowID: "d.yaml", Status: actions_model.StatusSuccess})
				_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-40*24*time.Hour), id)
				require.NoError(t, err)
			}
			assert.Equal(t, &api.DeleteActionRunsResult{Deleted: 2, More: false}, del("?older_than=30", writeToken, http.StatusOK))
			f.assertDeleted(t)
			for _, id := range others {
				assert.True(t, f.exists(t, id), id)
			}
			// user2 is no admin there (or sees no such repository) and deletes nothing
			status := MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user5/repo4/actions/runs?older_than=30").AddTokenAuth(writeToken), NoExpectedStatus).Code
			assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, status)
			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/no-such-repo/actions/runs?older_than=30").AddTokenAuth(writeToken), http.StatusNotFound)
			for _, id := range others {
				assert.True(t, f.exists(t, id), id)
			}
		})
	})
}

// A maintenance read-only mode refuses both ways to delete runs, and still shows the preview.
func TestActionsDeleteOldRunsMaintenance(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	f := newOldRunsFixture(t)
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()

	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/actions/runs/delete?older_than=30"), http.StatusOK)

	req := NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/runs/delete", map[string]string{"older_than": "30"})
	req.Header.Set("Referer", setting.AppURL+"user2/repo1")
	resp := session.MakeRequest(t, req, http.StatusSeeOther)
	assert.Equal(t, setting.AppURL+"user2/repo1", resp.Header().Get("Location"))
	assertMaintenanceFlash(t, session)

	resp = MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/actions/runs?older_than=30").AddTokenAuth(token), http.StatusServiceUnavailable)
	assert.JSONEq(t, `{"message":"read-only mode","detail":"`+maintenanceMessage+`"}`, resp.Body.String())
	f.assertUntouched(t)
}
