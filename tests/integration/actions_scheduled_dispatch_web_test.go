// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsScheduledDispatchWeb(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer timeutil.MockUnset()
		defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 30)()

		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		writer := forgery.CreateUser(t, nil)
		writer2 := forgery.CreateUser(t, nil)
		reader := forgery.CreateUser(t, nil)
		repoAdmin := forgery.CreateUser(t, nil)
		files := forgery.MapFS{".forgejo/workflows/dispatch.yml": forgery.MapFile(scheduledDispatchWorkflow)}
		repo := forgery.CreateRepository(t, owner, &forgery.CreateRepositoryOptions{
			Files:     files,
			IsPrivate: false,
			Collaborators: map[*user_model.User]perm.AccessMode{
				writer: perm.AccessModeWrite, writer2: perm.AccessModeWrite, reader: perm.AccessModeRead, repoAdmin: perm.AccessModeAdmin,
			},
		})
		forgery.EnableRepoUnit(t, repo, unit_model.TypeActions, nil)
		other := forgery.CreateRepository(t, owner, &forgery.CreateRepositoryOptions{Files: files})
		forgery.EnableRepoUnit(t, other, unit_model.TypeActions, nil)

		base := fmt.Sprintf("/%s/%s/actions", repo.OwnerName, repo.Name)
		writerSess, writer2Sess, readerSess := loginUser(t, writer.Name), loginUser(t, writer2.Name), loginUser(t, reader.Name)
		adminSess, siteAdminSess := loginUser(t, repoAdmin.Name), loginUser(t, "user1")
		anon := emptyTestSession(t)
		rows := func() []*actions_model.ActionScheduledDispatch {
			var l []*actions_model.ActionScheduledDispatch
			require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ?", repo.ID).Asc("id").Find(&l))
			return l
		}
		reset := func() {
			_, err := db.GetEngine(t.Context()).Where("repo_id = ? OR repo_id = ?", repo.ID, other.ID).Delete(new(actions_model.ActionScheduledDispatch))
			require.NoError(t, err)
		}
		post := func(s *TestSession, path string, v map[string]string, status int) string {
			s.SetCookie(&http.Cookie{Name: "gitea_flash", Value: "", MaxAge: -1})
			s.MakeRequest(t, NewRequestWithValues(t, "POST", path, v), status)
			return bwFlash(s)
		}
		at := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }
		schedule := func(s *TestSession, v map[string]string, status int) string {
			form := map[string]string{"ref": repo.DefaultBranch, "workflow": "dispatch.yml", "inputs[who]": "SECRETVALUE", "run_mode": "later"}
			maps.Copy(form, v)
			return post(s, base+"/manual", form, status)
		}
		countRuns := func() int {
			return unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID, TriggerEvent: "workflow_dispatch"})
		}

		t.Run("dialog", func(t *testing.T) {
			defer reset()
			page := writerSess.MakeRequest(t, NewRequest(t, "GET", base+"?workflow=dispatch.yml"), http.StatusOK).Body.String()
			assert.Contains(t, page, `name="run_mode"`)
			func() {
				defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 0)()
				page := writerSess.MakeRequest(t, NewRequest(t, "GET", base+"?workflow=dispatch.yml"), http.StatusOK).Body.String()
				assert.NotContains(t, page, `name="run_mode"`)
			}()

			assert.Contains(t, schedule(writerSess, map[string]string{"run_at": at(time.Hour)}, http.StatusSeeOther), "scheduled")
			l := rows()
			require.Len(t, l, 1)
			assert.Equal(t, writer.ID, l[0].DoerID)
			assert.Equal(t, "dispatch.yml", l[0].WorkflowID)
			assert.Equal(t, "refs/heads/"+repo.DefaultBranch, l[0].Ref)
			assert.JSONEq(t, `{"who":"SECRETVALUE","extra":"x"}`, l[0].Inputs)
			assert.Zero(t, countRuns())

			reset()
			for name, tc := range map[string]struct {
				v    map[string]string
				want string
			}{
				"missing":   {map[string]string{}, "Choose a time"},
				"invalid":   {map[string]string{"run_at": "tomorrow"}, "not valid"},
				"local":     {map[string]string{"run_at": "2030-01-01T10:00"}, "not valid"}, // no zone, no ParseInLocation
				"past":      {map[string]string{"run_at": at(-time.Hour)}, "in the future"},
				"too far":   {map[string]string{"run_at": at(31 * 24 * time.Hour)}, "30 days"},
				"required":  {map[string]string{"run_at": at(time.Hour), "inputs[who]": ""}, `who`},
				"too large": {map[string]string{"run_at": at(time.Hour), "inputs[extra]": strings.Repeat("a", 70<<10)}, "too large"},
			} {
				assert.Contains(t, schedule(writerSess, tc.v, http.StatusSeeOther), tc.want, name)
				assert.Empty(t, rows(), name)
			}
			func() {
				defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 0)()
				assert.Contains(t, schedule(writerSess, map[string]string{"run_at": at(time.Hour)}, http.StatusSeeOther), "turned off")
			}()
			// no run_mode: runs now as before
			assert.Contains(t, schedule(writerSess, map[string]string{"run_mode": "", "run_at": ""}, http.StatusSeeOther), "successfully requested")
			assert.Equal(t, 1, countRuns())
			assert.Empty(t, rows())
			// a reader cannot schedule
			schedule(readerSess, map[string]string{"run_at": at(time.Hour)}, http.StatusNotFound)
			assert.Empty(t, rows())
		})

		t.Run("limit", func(t *testing.T) {
			defer reset()
			for range 100 {
				require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), &actions_model.ActionScheduledDispatch{
					RepoID: repo.ID, WorkflowID: "dispatch.yml", Ref: repo.DefaultBranch, Inputs: "{}", DoerID: writer.ID, RunAt: timeutil.TimeStamp(time.Now().Add(time.Hour).Unix()),
				}))
			}
			assert.Contains(t, schedule(writerSess, map[string]string{"run_at": at(time.Hour)}, http.StatusSeeOther), "Too many")
			assert.Len(t, rows(), 100)
		})

		newRow := func(doer *user_model.User, runAt time.Time) *actions_model.ActionScheduledDispatch {
			sd := &actions_model.ActionScheduledDispatch{RepoID: repo.ID, WorkflowID: "dispatch.yml", Ref: repo.DefaultBranch, Inputs: `{"who":"SECRETVALUE"}`, DoerID: doer.ID, RunAt: timeutil.TimeStamp(runAt.Unix())}
			require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), sd))
			return sd
		}

		t.Run("list", func(t *testing.T) {
			defer reset()
			pending := newRow(writer, time.Now().Add(time.Hour))
			gone := newRow(writer, time.Now().Add(2*time.Hour))
			require.NoError(t, actions_model.CancelClaimedScheduledDispatch(t.Context(), gone.ID, "x")) // no-op: not claimed
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_scheduled_dispatch SET status = ?, cancel_reason = ?, inputs = '' WHERE id = ?", actions_model.ScheduledDispatchCancelled, "no_permission", gone.ID)
			require.NoError(t, err)
			claimed := newRow(writer, time.Now().Add(3*time.Hour))
			_, err = db.GetEngine(t.Context()).Exec("UPDATE action_scheduled_dispatch SET status = ? WHERE id = ?", actions_model.ScheduledDispatchClaimed, claimed.ID)
			require.NoError(t, err)
			foreign := &actions_model.ActionScheduledDispatch{RepoID: other.ID, WorkflowID: "foreign-wf.yml", Ref: "x", Inputs: "{}", DoerID: writer.ID, RunAt: timeutil.TimeStamp(time.Now().Add(time.Hour).Unix())}
			require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), foreign))

			for _, path := range []string{base, base + "?list_inner=true", base + "?workflow=dispatch.yml&list_inner=true"} {
				page := writerSess.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String()
				assert.Contains(t, page, "scheduled-runs", path)
				assert.Contains(t, page, fmt.Sprintf("/actions/scheduled/%d/cancel", pending.ID), path)
				assert.Contains(t, page, "may not run workflows", path) // reason of no_permission, rendered through the locale
				assert.NotContains(t, page, "no_permission", path)
				assert.NotContains(t, page, "SECRETVALUE", path)
				assert.NotContains(t, page, fmt.Sprintf("scheduled/%d/", claimed.ID), path)
				assert.NotContains(t, page, "foreign-wf.yml", path)
				for _, s := range []*TestSession{readerSess, anon} {
					page := s.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String()
					assert.NotContains(t, page, "scheduled-runs", path)
					assert.NotContains(t, page, "/actions/scheduled/", path)
				}
			}
			// only the scheduler, a repo admin and a site admin get the buttons
			page := writer2Sess.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, page, "scheduled-runs")
			assert.NotContains(t, page, "/actions/scheduled/")
			page = adminSess.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, page, fmt.Sprintf("/actions/scheduled/%d/cancel", pending.ID))
		})

		t.Run("reasons", func(t *testing.T) {
			defer reset()
			for _, code := range actions_model.ScheduledDispatchCancelReasons {
				sd := newRow(writer, time.Now().Add(time.Hour))
				_, err := db.GetEngine(t.Context()).Exec("UPDATE action_scheduled_dispatch SET status = ?, cancel_reason = ?, inputs = '' WHERE id = ?", actions_model.ScheduledDispatchCancelled, code, sd.ID)
				require.NoError(t, err)
			}
			page := writerSess.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
			assert.Contains(t, page, "scheduled-runs")
			for _, code := range actions_model.ScheduledDispatchCancelReasons {
				assert.NotContains(t, page, ">"+code+"<")
			}
			assert.NotContains(t, page, "actions.scheduled.reason")
		})

		t.Run("cancel", func(t *testing.T) {
			defer reset()
			mine, theirs := newRow(writer, time.Now().Add(time.Hour)), newRow(writer, time.Now().Add(time.Hour))
			cancel := func(s *TestSession, id int64, status int) {
				post(s, fmt.Sprintf("%s/scheduled/%d/cancel", base, id), nil, status)
			}
			cancel(readerSess, mine.ID, http.StatusNotFound)
			cancel(anon, mine.ID, http.StatusNotFound)
			cancel(writer2Sess, mine.ID, http.StatusForbidden)
			cancel(writerSess, 987654, http.StatusNotFound)
			cancel(writerSess, 0, http.StatusNotFound)
			cancel(writer2Sess, mine.ID+1000000, http.StatusNotFound)
			assert.Len(t, rows(), 2)
			// an id of another repository is 404 even for an admin
			f := &actions_model.ActionScheduledDispatch{RepoID: other.ID, WorkflowID: "dispatch.yml", Ref: "x", Inputs: "{}", DoerID: writer.ID, RunAt: timeutil.TimeStamp(time.Now().Add(time.Hour).Unix())}
			require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), f))
			cancel(siteAdminSess, f.ID, http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: f.ID})

			cancel(writerSess, mine.ID, http.StatusSeeOther)
			cancel(adminSess, theirs.ID, http.StatusSeeOther)
			assert.Empty(t, rows())

			s3 := newRow(writer, time.Now().Add(time.Hour))
			cancel(siteAdminSess, s3.ID, http.StatusSeeOther)
			assert.Empty(t, rows())
			cancel(writerSess, s3.ID, http.StatusNotFound) // already gone

			claimed := newRow(writer, time.Now().Add(time.Hour))
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_scheduled_dispatch SET status = ? WHERE id = ?", actions_model.ScheduledDispatchClaimed, claimed.ID)
			require.NoError(t, err)
			cancel(writerSess, claimed.ID, http.StatusNotFound)
			assert.Len(t, rows(), 1)
		})

		t.Run("time", func(t *testing.T) {
			defer reset()
			first := time.Now().Add(time.Hour)
			sd := newRow(writer, first)
			change := func(s *TestSession, id int64, runAt string, status int) string {
				return post(s, fmt.Sprintf("%s/scheduled/%d/time", base, id), map[string]string{"run_at": runAt}, status)
			}
			runAt := func() int64 {
				return int64(unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: sd.ID}).RunAt)
			}
			want := runAt()

			change(readerSess, sd.ID, at(2*time.Hour), http.StatusNotFound)
			change(writer2Sess, sd.ID, at(2*time.Hour), http.StatusForbidden)
			change(writerSess, 987654, at(2*time.Hour), http.StatusNotFound)
			assert.Contains(t, change(writerSess, sd.ID, "", http.StatusSeeOther), "Choose a time")
			assert.Contains(t, change(writerSess, sd.ID, "2030-01-01T10:00", http.StatusSeeOther), "not valid")
			assert.Contains(t, change(writerSess, sd.ID, at(-time.Hour), http.StatusSeeOther), "in the future")
			assert.Contains(t, change(writerSess, sd.ID, at(31*24*time.Hour), http.StatusSeeOther), "30 days")
			assert.Equal(t, want, runAt())

			newTime := time.Now().Add(5 * time.Hour)
			assert.Contains(t, change(adminSess, sd.ID, newTime.UTC().Format(time.RFC3339), http.StatusSeeOther), "changed")
			assert.Equal(t, newTime.Unix(), runAt())
			after := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: sd.ID})
			assert.Equal(t, writer.ID, after.DoerID)
			assert.Equal(t, sd.Inputs, after.Inputs)
			assert.Equal(t, sd.Ref, after.Ref)
			assert.Equal(t, sd.CommitID, after.CommitID)
			assert.Contains(t, change(siteAdminSess, sd.ID, at(6*time.Hour), http.StatusSeeOther), "changed")
			assert.Contains(t, change(writerSess, sd.ID, at(7*time.Hour), http.StatusSeeOther), "changed")

			// a cancelled row stays as it is
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_scheduled_dispatch SET status = ?, cancel_reason = 'missed' WHERE id = ?", actions_model.ScheduledDispatchCancelled, sd.ID)
			require.NoError(t, err)
			want = runAt()
			assert.Contains(t, change(writerSess, sd.ID, at(8*time.Hour), http.StatusSeeOther), "no longer waiting")
			assert.Equal(t, want, runAt())
			// a claimed row is not found
			_, err = db.GetEngine(t.Context()).Exec("UPDATE action_scheduled_dispatch SET status = ? WHERE id = ?", actions_model.ScheduledDispatchClaimed, sd.ID)
			require.NoError(t, err)
			change(writerSess, sd.ID, at(8*time.Hour), http.StatusNotFound)
			assert.Equal(t, want, runAt())
		})

		t.Run("archived", func(t *testing.T) {
			defer reset()
			sd := newRow(writer, time.Now().Add(time.Hour))
			repo.IsArchived = true
			_, err := db.GetEngine(t.Context()).ID(repo.ID).Cols("is_archived").Update(repo)
			require.NoError(t, err)
			defer func() {
				repo.IsArchived = false
				_, err := db.GetEngine(t.Context()).ID(repo.ID).Cols("is_archived").Update(repo)
				require.NoError(t, err)
			}()
			post(writerSess, fmt.Sprintf("%s/scheduled/%d/cancel", base, sd.ID), nil, http.StatusNotFound)
			post(writerSess, fmt.Sprintf("%s/scheduled/%d/time", base, sd.ID), map[string]string{"run_at": at(2 * time.Hour)}, http.StatusNotFound)
			schedule(writerSess, map[string]string{"run_at": at(time.Hour)}, http.StatusNotFound)
			assert.Len(t, rows(), 1)
		})
	})
}
