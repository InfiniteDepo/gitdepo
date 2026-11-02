// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	repo_service "forgejo.org/services/repository"
	wiki_service "forgejo.org/services/wiki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretToken is a GitHub-shaped token for a seed, built from parts so that no source line holds one.
func secretToken(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "ghp" + "_" + hex.EncodeToString(sum[:])[:36]
}

func secretAlerts(t *testing.T, repoID int64) []*secretscan_model.Alert {
	t.Helper()
	var alerts []*secretscan_model.Alert
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ?", repoID).OrderBy("`index`").Find(&alerts))
	return alerts
}

func secretLocations(t *testing.T, alertID int64) []*secretscan_model.Location {
	t.Helper()
	var locs []*secretscan_model.Location
	require.NoError(t, db.GetEngine(t.Context()).Where("alert_id = ?", alertID).OrderBy("kind, path, start_line").Find(&locs))
	return locs
}

// secretAlertWith finds the alert of the token's secret with at least places stored places, or returns nil. It runs
// inside Eventually: no require, no t.Context().
func secretAlertWith(repoID int64, tok string, places int64) *secretscan_model.Alert {
	var alerts []*secretscan_model.Alert
	if err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND rule_id = ? AND fingerprint = ?", repoID, "github-token", secretFingerprint(tok)).Find(&alerts); err != nil {
		return nil
	}
	for _, a := range alerts {
		if n, err := db.GetEngine(db.DefaultContext).Where("alert_id = ?", a.ID).Count(new(secretscan_model.Location)); err == nil && n >= places {
			return a
		}
	}
	return nil
}

// secretAlertPlaces waits for the scan the push queued to store the alert of the token's secret with its places.
func secretAlertPlaces(t *testing.T, repoID int64, tok string, places int64) *secretscan_model.Alert {
	t.Helper()
	var found *secretscan_model.Alert
	require.Eventually(t, func() bool {
		found = secretAlertWith(repoID, tok, places)
		return found != nil
	}, 20*time.Second, 50*time.Millisecond)
	return found
}

func secretAlertOf(t *testing.T, repoID int64, tok string) *secretscan_model.Alert {
	t.Helper()
	return secretAlertPlaces(t, repoID, tok, 1)
}

func secretFingerprint(tok string) string {
	return secretdetection.Fingerprint([]byte(tok))
}

// wikiPush commits the files to the wiki repository over HTTP.
func wikiPush(t *testing.T, u *url.URL, repo *repo_model.Repository, files map[string]string) {
	t.Helper()
	dst := t.TempDir()
	c := *u
	c.Path = "/" + repo.FullName() + ".wiki.git"
	c.User = url.UserPassword(repo.OwnerName, userPassword)
	require.NoError(t, git.Clone(t.Context(), c.String(), dst, git.CloneRepoOptions{}))
	doGitSetRemoteURL(dst, "origin", &c)(t) // the clone keeps no credentials in the remote
	run := func(args ...string) {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dst
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	for p, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dst, p), []byte(content), 0o644))
	}
	run("add", "-A")
	run("commit", "-m", "page")
	run("push", "origin", "HEAD")
}

func TestSecretScanning(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		repo := depNewRepo(t, user2, user2, "secret-push", false, 0)
		first := secretToken("first")

		t.Run("a pushed key opens one alert with one place", func(t *testing.T) {
			sha := depPush(t, u, token, repo, "refs/heads/main", map[string]string{"deploy/env": "A=1\nB=2\nTOKEN=" + first + "\n"})
			a := secretAlertOf(t, repo.ID, first)
			locs := secretLocations(t, a.ID)
			require.Len(t, locs, 1)
			assert.Equal(t, "deploy/env", locs[0].Path)
			assert.Equal(t, 3, locs[0].StartLine)
			assert.Equal(t, sha, locs[0].CommitID)
			assert.Equal(t, "t", locs[0].AuthorName)
			assert.Equal(t, "t@example.com", locs[0].AuthorEmail)
			assert.Equal(t, secretscan_model.KindRepo, locs[0].Kind)
			assert.Len(t, secretAlerts(t, repo.ID), 1)
			s, err := secretscan_model.GetScan(t.Context(), repo.ID, secretscan_model.KindRepo)
			require.NoError(t, err)
			require.NotNil(t, s)
			assert.Equal(t, secretscan_model.StatusOK, s.Status)
		})

		t.Run("the same key in another file is a place, not an alert; the second scan reads only what is new", func(t *testing.T) {
			depPush(t, u, token, repo, "refs/heads/main", map[string]string{"scripts/run.sh": "export T=" + first + "\n"})
			secretAlertPlaces(t, repo.ID, first, 2)
			assert.Len(t, secretAlerts(t, repo.ID), 1)
			s, err := secretscan_model.GetScan(t.Context(), repo.ID, secretscan_model.KindRepo)
			require.NoError(t, err)
			assert.EqualValues(t, 1, s.Blobs, "one new file")
		})

		t.Run("a key in a tag, in an AGit push and in a removed commit", func(t *testing.T) {
			inTag, inAgit, removed := secretToken("tag"), secretToken("agit"), secretToken("removed")
			depPush(t, u, token, repo, "refs/tags/v1", map[string]string{"tag.txt": "x " + inTag + "\n"})
			require.NotNil(t, secretAlertOf(t, repo.ID, inTag))
			depPush(t, u, token, repo, "refs/for/main", map[string]string{"agit.txt": "x " + inAgit + "\n"})
			agit := secretAlertOf(t, repo.ID, inAgit)
			assert.True(t, agit.ViaPull)
			assert.Equal(t, secretscan_model.KindPull, secretLocations(t, agit.ID)[0].Kind)
			depPush(t, u, token, repo, "refs/heads/main", map[string]string{"gone.txt": removed + "\n"})
			depPush(t, u, token, repo, "refs/heads/main", nil, "gone.txt")
			require.NotNil(t, secretAlertOf(t, repo.ID, removed))
		})

		t.Run("a key pushed to the wiki", func(t *testing.T) {
			inWiki := secretToken("wiki")
			require.NoError(t, repo_service.UpdateRepositoryUnits(t.Context(), repo, []repo_model.RepoUnit{{RepoID: repo.ID, Type: unit_model.TypeWiki, Config: new(repo_model.UnitConfig)}}, nil))
			require.NoError(t, wiki_service.InitWiki(t.Context(), repo))
			wikiPush(t, u, repo, map[string]string{"Home.md": "# Home\n\nkey " + inWiki + "\n"})
			a := secretAlertOf(t, repo.ID, inWiki)
			locs := secretLocations(t, a.ID)
			require.Len(t, locs, 1)
			assert.Equal(t, secretscan_model.KindWiki, locs[0].Kind)
			assert.Equal(t, "Home.md", locs[0].Path)
			assert.Equal(t, 3, locs[0].StartLine)
		})

		t.Run("a fork starts from its parent's state", func(t *testing.T) {
			token4 := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/secret-push/forks", &api.CreateForkOption{}).AddTokenAuth(token4)
			var fork api.Repository
			DecodeJSON(t, MakeRequest(t, req, http.StatusAccepted), &fork)
			require.Eventually(t, func() bool {
				s, err := secretscan_model.GetScan(db.DefaultContext, fork.ID, secretscan_model.KindRepo)
				return err == nil && s != nil
			}, 20*time.Second, 50*time.Millisecond)
			s, err := secretscan_model.GetScan(t.Context(), fork.ID, secretscan_model.KindRepo)
			require.NoError(t, err)
			assert.Equal(t, secretscan_model.StatusOK, s.Status)
			assert.Zero(t, s.Blobs, "nothing of the shared history was read again")
			assert.Empty(t, secretAlerts(t, fork.ID))
			assert.NotEmpty(t, secretAlerts(t, repo.ID))
		})

		t.Run("canary: the secret is in no row and no log line", func(t *testing.T) {
			canary := secretToken("canary")
			body := strings.TrimPrefix(canary, "ghp"+"_")
			lc, cancel := test.NewLogChecker(log.DEFAULT, log.TRACE)
			defer cancel()
			lc.Filter(canary, body).StopMark("secret-canary-stop")
			depPush(t, u, token, repo, "refs/heads/main", map[string]string{"canary.env": "T=" + canary + "\n"})
			alert := secretAlertOf(t, repo.ID, canary)

			// the API answers (list, get, close with a comment, reopen) and its audit rows never hold the secret
			base := "/api/v1/repos/user2/secret-push/secret-scanning/alerts"
			one := fmt.Sprintf("%s/%d", base, alert.Index)
			bodies := []string{
				MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(token), http.StatusOK).Body.String(),
				MakeRequest(t, NewRequest(t, "GET", one).AddTokenAuth(token), http.StatusOK).Body.String(),
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "resolved", "resolution": "revoked", "resolution_comment": "rotated"}).AddTokenAuth(token), http.StatusOK).Body.String(),
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "open"}).AddTokenAuth(token), http.StatusOK).Body.String(),
			}
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", one, map[string]string{"state": "resolved", "resolution": "revoked", "resolution_comment": "leaked " + canary}).AddTokenAuth(token), http.StatusUnprocessableEntity)
			for _, b := range bodies {
				assert.NotContains(t, b, canary)
				assert.NotContains(t, b, body)
			}
			assert.Contains(t, bodies[1], secretFingerprint(canary), "the fingerprint is shown to the writer")
			audited, err := db.GetEngine(t.Context()).Where("action LIKE ?", "repo.secret_alert.%").Count(new(audit_model.Entry))
			require.NoError(t, err)
			assert.EqualValues(t, 2, audited)

			for _, table := range []string{"secret_scan", "secret_scanning_alert", "secret_scanning_location", "secret_scanning_alert_index", "audit_event"} {
				rows, err := db.GetEngine(t.Context()).Query("SELECT * FROM " + table)
				require.NoError(t, err)
				for _, row := range rows {
					for col, v := range row {
						assert.NotContains(t, string(v), canary, "%s.%s", table, col)
						assert.NotContains(t, string(v), body, "%s.%s", table, col)
					}
				}
			}
			log.Info("secret-canary-stop")
			seen, stopped := lc.Check(5 * time.Second)
			require.True(t, stopped)
			assert.Equal(t, []bool{false, false}, seen)
		})

		t.Run("off keeps the alerts and stops the scans", func(t *testing.T) {
			before := len(secretAlerts(t, repo.ID))
			repo.SecretScanningDisabled = true
			require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "secret_scanning_disabled"))
			late := secretToken("late")
			depPush(t, u, token, repo, "refs/heads/main", map[string]string{"late.txt": late + "\n"})
			// a scan the push queued has run when the queues are flushed
			require.NoError(t, queue.GetManager().FlushAll(t.Context(), 10*time.Second))
			assert.Len(t, secretAlerts(t, repo.ID), before)

			repo.SecretScanningDisabled = false
			require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "secret_scanning_disabled"))
			depPush(t, u, token, repo, "refs/heads/main", map[string]string{"later.txt": "no secret\n"})
			require.NotNil(t, secretAlertOf(t, repo.ID, late), "scanned from the stored state once it is on again")
		})
	})
}
