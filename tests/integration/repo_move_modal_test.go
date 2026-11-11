// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/migration"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	mirror_service "forgejo.org/services/mirror"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The move modal of the settings page posts the full name of the repository as confirmation. It is compared without
// case and surrounding blanks, a mismatch names the expected name, and a pull mirror is movable into a project and
// back and keeps syncing on its new path.
func TestRepoMoveModalFields(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
		defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
		ctx := db.DefaultContext
		f := prepareRepoGroupWeb(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user2.AllowImportLocal = true
		require.NoError(t, user_model.UpdateUserCols(ctx, user2, "allow_import_local"))
		defer func() {
			user2.AllowImportLocal = false
			require.NoError(t, user_model.UpdateUserCols(ctx, user2, "allow_import_local"))
		}()
		// the sync checks the local path against the owner of the mirror, here the organization
		f.org.AllowImportLocal = true
		require.NoError(t, user_model.UpdateUserCols(ctx, f.org, "allow_import_local"))
		defer func() {
			f.org.AllowImportLocal = false
			require.NoError(t, user_model.UpdateUserCols(ctx, f.org, "allow_import_local"))
		}()
		owner := loginUser(t, "user2")
		proj, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "proj")
		require.NoError(t, err)
		source, err := repo_service.CreateRepository(ctx, user2, f.org, repo_service.CreateRepoOptions{
			Name: "modal-source", Readme: "Default", AutoInit: true, DefaultBranch: "main",
		})
		require.NoError(t, err)

		newRepo := func(t *testing.T, name string, mirror bool) *repo_model.Repository {
			t.Helper()
			if !mirror {
				repo, err := repo_service.CreateRepository(ctx, user2, f.org, repo_service.CreateRepoOptions{
					Name: name, Readme: "Default", AutoInit: true, DefaultBranch: "main",
				})
				require.NoError(t, err)
				return repo
			}
			repo, err := repo_service.CreateRepositoryDirectly(ctx, user2, f.org, repo_service.CreateRepoOptions{
				Name: name, IsMirror: true, Status: repo_model.RepositoryBeingMigrated,
			})
			require.NoError(t, err)
			repo, err = repo_service.MigrateRepositoryGitData(ctx, user2, repo, migration.MigrateOptions{
				RepoName: name, Mirror: true, CloneAddr: source.RepoPath(),
			}, nil)
			require.NoError(t, err)
			repo.Status = repo_model.RepositoryReady // as the migration task does when it is done
			require.NoError(t, repo_model.UpdateRepositoryCols(ctx, repo, "status"))
			return repo
		}
		reload := func(id int64) *repo_model.Repository {
			return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
		}
		move := func(t *testing.T, repo *repo_model.Repository, confirm string, groupID int64, status int) string {
			t.Helper()
			return owner.MakeRequest(t, NewRequestWithValues(t, "POST", repo.Link()+"/settings", map[string]string{
				"action": "move", "repo_name": confirm, "group_id": strconv.FormatInt(groupID, 10),
			}), status).Body.String()
		}
		tags := 0
		// a new tag in the source, synced into the mirror, is visible on the mirror's current path
		syncAndCheck := func(t *testing.T, mirror *repo_model.Repository) {
			t.Helper()
			tags++
			tag := "v0." + strconv.Itoa(tags)
			require.NoError(t, exec.Command("git", "-C", source.RepoPath(), "tag", tag).Run())
			require.True(t, mirror_service.SyncPullMirror(ctx, mirror.ID))
			out, err := exec.Command("git", "-C", reload(mirror.ID).RepoPath(), "tag", "-l", tag).Output()
			require.NoError(t, err)
			assert.Equal(t, tag+"\n", string(out))
		}

		for _, mirror := range []bool{false, true} {
			name := map[bool]string{false: "modal-plain", true: "modal-mirror"}[mirror]
			t.Run(name, func(t *testing.T) {
				repo := newRepo(t, name, mirror)
				if mirror {
					syncAndCheck(t, repo)
				}

				body := move(t, repo, "org3/other", proj.ID, http.StatusOK)
				assert.Contains(t, body, "Enter the full name of the repository: org3/"+name)
				assert.Contains(t, body, `field error`, "the move field is red")
				assert.EqualValues(t, 0, reload(repo.ID).GroupID)

				// padded and differently cased
				move(t, repo, "  ORG3/"+name+" ", proj.ID, http.StatusSeeOther)
				moved := reload(repo.ID)
				assert.Equal(t, proj.ID, moved.GroupID)
				if mirror {
					syncAndCheck(t, moved)
				}

				move(t, moved, moved.FullName(), 0, http.StatusSeeOther)
				assert.EqualValues(t, 0, reload(repo.ID).GroupID)
				if mirror {
					syncAndCheck(t, repo)
				}
			})
		}

		// what a keyboard or a copied label adds, and a real mismatch
		t.Run("confirmation forms", func(t *testing.T) {
			repo := newRepo(t, "modal-forms", false)
			for _, confirm := range []string{"org3/modal-forms\n", "org3/modal-forms ", "org3/modal-forms\u00a0", "\u200borg3/modal-forms", "\ufeffORG3/Modal-Forms\u2060"} {
				move(t, repo, confirm, proj.ID, http.StatusSeeOther)
				assert.Equal(t, proj.ID, reload(repo.ID).GroupID, "%q", confirm)
				move(t, reload(repo.ID), reload(repo.ID).FullName(), 0, http.StatusSeeOther)
			}
			move(t, repo, "org3/modal-form", proj.ID, http.StatusOK)
			assert.EqualValues(t, 0, reload(repo.ID).GroupID)
		})

		t.Run("delete with a padded confirmation", func(t *testing.T) {
			repo := newRepo(t, "modal-delete", false)
			post := func(confirm string, status int) {
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", repo.Link()+"/settings", map[string]string{
					"action": "delete", "repo_name": confirm,
				}), status)
			}
			post("org3/modal-delet", http.StatusOK)
			_, err := repo_model.GetRepositoryByID(ctx, repo.ID)
			require.NoError(t, err)
			post(" Org3/modal-delete\n", http.StatusSeeOther)
			_, err = repo_model.GetRepositoryByID(ctx, repo.ID)
			assert.True(t, repo_model.IsErrRepoNotExist(err), "deleted")
		})

		t.Run("messages", func(t *testing.T) {
			repo := newRepo(t, "modal-errors", false)

			assert.Contains(t, move(t, repo, repo.FullName(), 0, http.StatusOK), "The repository is already there.")

			_, err := repo_service.CreateRepository(ctx, user2, f.org, repo_service.CreateRepoOptions{
				Name: "modal-errors", GroupID: proj.ID,
			})
			require.NoError(t, err)
			assert.Contains(t, move(t, repo, repo.FullName(), proj.ID, http.StatusOK), "is already used there")

			other, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17}), "elsewhere-modal", "")
			require.NoError(t, err)
			move(t, repo, repo.FullName(), other.ID, http.StatusNotFound)

			_, err = db.GetEngine(ctx).Exec("UPDATE `repository` SET status = ? WHERE id = ?", repo_model.RepositoryBeingMigrated, repo.ID)
			require.NoError(t, err)
			assert.Contains(t, move(t, repo, repo.FullName(), proj.ID, http.StatusOK), "still being migrated")
			_, err = db.GetEngine(ctx).Exec("UPDATE `repository` SET status = ? WHERE id = ?", repo_model.RepositoryReady, repo.ID)
			require.NoError(t, err)

			require.NoError(t, repo_service.StartRepositoryTransfer(audit_model.WithSystem(ctx, "test"), user2, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}), reload(repo.ID), nil))
			assert.Contains(t, move(t, repo, repo.FullName(), proj.ID, http.StatusOK), "transfer")
			assert.EqualValues(t, 0, reload(repo.ID).GroupID)
		})
	})
}
