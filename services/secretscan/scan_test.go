// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/process"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	repo_service "forgejo.org/services/repository"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// token is a GitHub-shaped token for a seed, built from parts so that no source line holds one.
func token(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "ghp" + "_" + hex.EncodeToString(sum[:])[:36]
}

// enable turns secret scanning on with generous budgets and returns user2/repo1, a repository with a history.
func enable(t *testing.T) *repo_model.Repository {
	t.Helper()
	unittest.PrepareTestEnv(t) // the database and the git repositories: a test never sees what another one left
	bumpRevision(t)            // a site switch an earlier test stored is cached by revision
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.GenericRules, false))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxConcurrentScans, 1))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.ScanTimeout, time.Minute))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxBlobSize, 1<<20))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxScanBytes, 1<<30))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxScanBlobs, 100000))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, 1000))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxLocationsPerAlert, 100))
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
}

// work is a clone of a repository to commit in and push from; every commit is a minute after the one before.
type work struct {
	t     *testing.T
	repo  *repo_model.Repository
	dir   string
	clock time.Time
}

func newWork(t *testing.T, repo *repo_model.Repository) *work {
	t.Helper()
	w := &work{t: t, repo: repo, dir: t.TempDir(), clock: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	w.git("clone", "-q", "-b", repo.DefaultBranch, repo.RepoPath(), ".")
	return w
}

func (w *work) git(args ...string) string {
	w.t.Helper()
	return w.gitEnv(nil, args...)
}

func (w *work) gitEnv(env []string, args ...string) string {
	w.t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=Dev One", "-c", "user.email=dev@example.com", "-c", "commit.gpgsign=false", "-c", "core.quotepath=off"}, args...)...)
	cmd.Dir = w.dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	require.NoError(w.t, err, string(out))
	return strings.TrimSpace(string(out))
}

// commit writes the files and commits them with the author; an empty content removes the file.
func (w *work) commit(files map[string]string, author ...string) string {
	w.t.Helper()
	for p, c := range files {
		full := filepath.Join(w.dir, p)
		if c == "" {
			require.NoError(w.t, os.RemoveAll(full))
			continue
		}
		require.NoError(w.t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(w.t, os.WriteFile(full, []byte(c), 0o644))
	}
	w.clock = w.clock.Add(time.Minute)
	date := w.clock.Format(time.RFC3339)
	env := []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}
	if len(author) == 2 {
		env = append(env, "GIT_AUTHOR_NAME="+author[0], "GIT_AUTHOR_EMAIL="+author[1])
	}
	w.git("add", "-A")
	w.gitEnv(env, "commit", "-q", "--allow-empty", "-m", "change")
	return w.git("rev-parse", "HEAD")
}

// push pushes HEAD to the ref of the repository (a bare directory, so no hook runs).
func (w *work) push(ref string) {
	w.t.Helper()
	w.git("push", "-q", "--force", w.repo.RepoPath(), "HEAD:"+ref)
}

func (w *work) pushDefault() { w.push("refs/heads/" + w.repo.DefaultBranch) }

// currentTips are the commits the refs of the repository other than refs/pull/* point to, sorted.
func currentTips(t *testing.T, repo *repo_model.Repository) []string {
	t.Helper()
	tips, err := refTips(t.Context(), repo.RepoPath(), false)
	require.NoError(t, err)
	return tips
}

func scanOf(t *testing.T, repoID int64, kind string) *secretscan_model.Scan {
	t.Helper()
	s, err := secretscan_model.GetScan(t.Context(), repoID, kind)
	require.NoError(t, err)
	return s
}

func alertsOf(t *testing.T, repoID int64) []*secretscan_model.Alert {
	t.Helper()
	var alerts []*secretscan_model.Alert
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ?", repoID).OrderBy("`index`").Find(&alerts))
	return alerts
}

func locationsOf(t *testing.T, alertID int64) []*secretscan_model.Location {
	t.Helper()
	var locs []*secretscan_model.Location
	require.NoError(t, db.GetEngine(t.Context()).Where("alert_id = ?", alertID).OrderBy("path, start_line").Find(&locs))
	return locs
}

// alertFor is the alert of a token's secret, which has the fingerprint of the token's secret part.
func alertFor(t *testing.T, repoID int64, tok string) *secretscan_model.Alert {
	t.Helper()
	for _, a := range alertsOf(t, repoID) {
		if a.RuleID == "github-token" && a.Fingerprint == secretdetection.Fingerprint([]byte(tok)) {
			return a
		}
	}
	return nil
}

func TestScanPushedKey(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	tok := token("pushed")

	// the first scan reads the whole history of the repository
	require.NoError(t, Scan(t.Context(), repo.ID))
	first := scanOf(t, repo.ID, secretscan_model.KindRepo)
	require.NotNil(t, first)
	assert.Equal(t, secretscan_model.StatusOK, first.Status)
	assert.Positive(t, first.Blobs)
	assert.Empty(t, alertsOf(t, repo.ID))

	c1 := w.commit(map[string]string{"deploy/env": "# env\nA=1\nGITHUB_TOKEN=" + tok + "\n"}, "Alice Dev", "alice@example.com")
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))

	// incremental: only the new file is read
	second := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.EqualValues(t, 1, second.Blobs)
	assert.Equal(t, int64(len("# env\nA=1\nGITHUB_TOKEN="+tok+"\n")), second.Bytes)
	assert.Greater(t, second.Version, first.Version)
	alert := alertFor(t, repo.ID, tok)
	require.NotNil(t, alert)
	assert.Equal(t, int64(1), alert.Index)
	assert.Equal(t, "github", alert.SecretType)
	assert.Equal(t, secretscan_model.StateOpen, alert.State)
	assert.Equal(t, secretscan_model.CurrentKeyVersion, alert.KeyVersion)
	assert.Len(t, alert.Fingerprint, 64)
	assert.Equal(t, 1, alert.LocationCount)
	locs := locationsOf(t, alert.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, secretscan_model.KindRepo, locs[0].Kind)
	assert.Equal(t, "deploy/env", locs[0].Path)
	assert.Equal(t, 3, locs[0].StartLine)
	assert.Equal(t, c1, locs[0].CommitID)
	assert.Equal(t, "Alice Dev", locs[0].AuthorName)
	assert.Equal(t, "alice@example.com", locs[0].AuthorEmail)
	assert.Equal(t, time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC).Unix(), locs[0].CommitUnix)
	assert.Len(t, locs[0].BlobID, 40)

	// the same key in another file is another place of the same alert
	w.commit(map[string]string{"scripts/run.sh": "#!/bin/sh\n\n\nexport T=" + tok + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Len(t, alertsOf(t, repo.ID), 1)
	alert = alertFor(t, repo.ID, tok)
	locs = locationsOf(t, alert.ID)
	require.Len(t, locs, 2)
	assert.Equal(t, "deploy/env", locs[0].Path)
	assert.Equal(t, "scripts/run.sh", locs[1].Path)
	assert.Equal(t, 4, locs[1].StartLine)
	assert.Equal(t, 2, alert.LocationCount)

	// the same key at the same line of the same file in a new commit adds nothing
	w.commit(map[string]string{"deploy/env": "# env changed\nA=2\nGITHUB_TOKEN=" + tok + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Len(t, alertsOf(t, repo.ID), 1)
	alert = alertFor(t, repo.ID, tok)
	assert.Len(t, locationsOf(t, alert.ID), 2)
	assert.Equal(t, 2, alert.LocationCount)
	assert.EqualValues(t, 1, scanOf(t, repo.ID, secretscan_model.KindRepo).Blobs, "only the changed file was read")

	// a scan with nothing new writes nothing
	before := scanOf(t, repo.ID, secretscan_model.KindRepo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Equal(t, before.Version, scanOf(t, repo.ID, secretscan_model.KindRepo).Version)
}

func TestScanFullHistory(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	old, inTag, inPull, inBranch := token("old"), token("tag"), token("pull"), token("branch")

	// added in an old commit and removed in the next one
	c1 := w.commit(map[string]string{"old.txt": "key " + old + "\n"})
	w.commit(map[string]string{"old.txt": ""})
	w.pushDefault()
	// a file that only a tag reaches, and one that only a pull request ref reaches
	w.git("checkout", "-q", "-b", "side")
	c3 := w.commit(map[string]string{"in-pull.txt": "x " + inPull + "\n"})
	w.push("refs/pull/9/head")
	w.git("checkout", "-q", "-b", "other", repo.DefaultBranch)
	w.commit(map[string]string{"in-branch.txt": "x " + inBranch + "\n"})
	w.push("refs/heads/other")
	cmd := exec.Command("git", "hash-object", "-w", "--stdin")
	cmd.Dir = repo.RepoPath()
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
	cmd.Stdin = strings.NewReader("tag " + inTag + "\n")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	tagBlob := strings.TrimSpace(string(out))
	tagCmd := exec.Command("git", "update-ref", "refs/tags/just-a-file", tagBlob)
	tagCmd.Dir = repo.RepoPath()
	tagCmd.Env = cmd.Env
	out, err = tagCmd.CombinedOutput()
	require.NoError(t, err, string(out))

	require.NoError(t, Scan(t.Context(), repo.ID))
	require.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)

	a := alertFor(t, repo.ID, old)
	require.NotNil(t, a, "a key removed in the next commit is still in the history")
	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, "old.txt", locs[0].Path)
	assert.Equal(t, c1, locs[0].CommitID)

	a = alertFor(t, repo.ID, inPull)
	require.NotNil(t, a, "a key only in refs/pull/N/head")
	locs = locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, c3, locs[0].CommitID)
	assert.Equal(t, "in-pull.txt", locs[0].Path)

	require.NotNil(t, alertFor(t, repo.ID, inBranch))

	assert.Nil(t, alertFor(t, repo.ID, inTag), "what only a ref to a file reaches is not scanned (documented)")
}

func TestScanPathWithNewline(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	other, hostile := token("other"), token("hostile")

	w.commit(map[string]string{"other.txt": other + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	otherBlob := w.git("rev-parse", "HEAD:other.txt")
	a := alertFor(t, repo.ID, other)
	require.NotNil(t, a)
	base := len(alertsOf(t, repo.ID)) // the fixture's history has findings of its own

	// a file named so that a line of rev-list output could pass for the line of the blob above
	name := "a\n" + otherBlob + " b.txt"
	w.commit(map[string]string{name: hostile + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))

	assert.Len(t, alertsOf(t, repo.ID), base+1)
	a2 := alertFor(t, repo.ID, other)
	assert.Equal(t, a.ID, a2.ID)
	assert.Len(t, locationsOf(t, a2.ID), 1, "the other blob gained no place")
	assert.EqualValues(t, 1, scanOf(t, repo.ID, secretscan_model.KindRepo).Blobs, "and was not read again")
	h := alertFor(t, repo.ID, hostile)
	require.NotNil(t, h)
	locs := locationsOf(t, h.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, "a?"+otherBlob+" b.txt", locs[0].Path, "the whole path, the newline stripped for display")
	assert.Equal(t, secretscan_model.PathHash(name), locs[0].PathHash)
}

func TestScanAuthorTextIsNoRecord(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	tok := token("author")
	zero := strings.Repeat("0", 40)

	// an author name that looks like the raw line of a commit
	w.commit(map[string]string{"real.txt": tok + "\n"}, ":100644 100644 "+zero+" "+strings.Repeat("a", 40)+" A", "x@example.com")
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, "real.txt", locs[0].Path)
	assert.Equal(t, "100644 100644 "+zero+" "+strings.Repeat("a", 40)+" A", locs[0].AuthorName, "git itself drops the leading colon of a name")
}

// later moves the clock forward until the end of the test: the backoff of a failed scan is counted from it.
func later(t *testing.T, d time.Duration) {
	t.Helper()
	timeutil.MockSet(timeutil.TimeStampNow().AsTime().Add(d))
	t.Cleanup(timeutil.MockUnset)
}

// openAlerts counts the open alerts of the repository.
func openAlerts(t *testing.T, repoID int64) (total, viaPull int64) {
	t.Helper()
	total, viaPull, _, err := secretscan_model.CountOpenAlerts(t.Context(), repoID)
	require.NoError(t, err)
	return total, viaPull
}

func dueRepos(t *testing.T, now timeutil.TimeStamp) []int64 {
	t.Helper()
	ids, err := secretscan_model.UnscannedRepoIDs(t.Context(), now, 1000)
	require.NoError(t, err)
	return ids
}

func TestScanBudgets(t *testing.T) {
	// every subtest has its own repository: holes stay on a row
	fresh := func(t *testing.T) (*repo_model.Repository, *work) {
		repo := enable(t)
		require.NoError(t, Scan(t.Context(), repo.ID)) // the history the fixture has
		return repo, newWork(t, repo)
	}

	t.Run("a file over MAX_BLOB_SIZE is skipped without being read", func(t *testing.T) {
		repo, w := fresh(t)
		defer test.MockVariableValue(&setting.SecretScanning.MaxBlobSize, 100)()
		big := token("big") + "\n" + strings.Repeat("x", 200)
		w.commit(map[string]string{"big.txt": big, "small.txt": token("small") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
		s := scanOf(t, repo.ID, secretscan_model.KindRepo)
		assert.Equal(t, secretscan_model.StatusOK, s.Status, "the status stays ok")
		assert.EqualValues(t, 1, s.Blobs)
		assert.EqualValues(t, 1, s.SkippedLarge, "and the file is counted")
		assert.EqualValues(t, len(token("small"))+1, s.Bytes, "the big file's bytes were not read")
		assert.NotNil(t, alertFor(t, repo.ID, token("small")))
		assert.Nil(t, alertFor(t, repo.ID, token("big")))

		w.commit(map[string]string{"next.txt": "nothing\n"})
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
		s = scanOf(t, repo.ID, secretscan_model.KindRepo)
		assert.EqualValues(t, 1, s.Blobs, "the next scan read one file")
		assert.EqualValues(t, 1, s.SkippedLarge, "and the large file is still counted: it was never read")
	})

	// a commit that alone is over a limit is scanned as far as it fits, the rest is a hole, and the scan goes on
	for name, c := range map[string]struct {
		limit *int64
		value int64
	}{
		"MAX_SCAN_BLOBS": {&setting.SecretScanning.MaxScanBlobs, 1},
		"MAX_SCAN_BYTES": {&setting.SecretScanning.MaxScanBytes, int64(len(token("c1")) + 10)},
	} {
		t.Run(name+": one commit over the limit is a hole, not a block", func(t *testing.T) {
			repo, w := fresh(t)
			restore := test.MockVariableValue(c.limit, c.value)
			defer restore()
			w.commit(map[string]string{"c1.txt": token("c1"+name) + "\n", "c2.txt": token("c2"+name) + "\n"})
			head := w.git("rev-parse", "HEAD")
			after := token("after" + name)
			w.commit(map[string]string{"after.txt": after + "\n"})
			w.pushDefault()
			require.NoError(t, Scan(t.Context(), repo.ID))
			s := scanOf(t, repo.ID, secretscan_model.KindRepo)
			assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
			assert.Equal(t, stopHole, s.Error)
			assert.Zero(t, s.FailCount, "progress is no failure")
			assert.EqualValues(t, 1, s.Holes)
			assert.NotNil(t, alertFor(t, repo.ID, token("c1"+name)), "what fits is scanned")
			assert.Nil(t, alertFor(t, repo.ID, token("c2"+name)), "the rest is the hole")
			var tips []string
			require.NoError(t, json.Unmarshal([]byte(s.ScannedTips), &tips))
			assert.Contains(t, tips, head, "the commit is done")

			// the next slice goes on after it; the hole stays on the row
			require.NoError(t, Scan(t.Context(), repo.ID))
			assert.NotNil(t, alertFor(t, repo.ID, after))
			s = scanOf(t, repo.ID, secretscan_model.KindRepo)
			assert.Equal(t, secretscan_model.StatusIncomplete, s.Status, "a hole stays")
			assert.Equal(t, stopHole, s.Error)
			assert.EqualValues(t, 1, s.Holes)
			require.NoError(t, Scan(t.Context(), repo.ID))
			assert.Equal(t, s.Version, scanOf(t, repo.ID, secretscan_model.KindRepo).Version, "a trigger with nothing new writes nothing")
		})
	}

	t.Run("MAX_LOCATIONS_PER_ALERT: places over the cap are counted, not stored", func(t *testing.T) {
		repo, w := fresh(t)
		defer test.MockVariableValue(&setting.SecretScanning.MaxLocationsPerAlert, 2)()
		same := token("same")
		w.commit(map[string]string{"s1.txt": same + "\n", "s2.txt": same + "\n", "s3.txt": same + "\n", "s4.txt": same + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
		assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
		a := alertFor(t, repo.ID, same)
		require.NotNil(t, a)
		assert.Len(t, locationsOf(t, a.ID), 2)
		assert.Equal(t, 4, a.LocationCount, "every place seen is counted")

		w.commit(map[string]string{"s5.txt": same + " again\n"}) // another blob: git lists only new ones
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
		a = alertFor(t, repo.ID, same)
		assert.Len(t, locationsOf(t, a.ID), 2, "a later place has no row either")
		assert.Equal(t, 5, a.LocationCount)
	})

	t.Run("MAX_ALERTS_PER_REPO counts open alerts only, and what it leaves out is a hole", func(t *testing.T) {
		repo, w := fresh(t)
		open, _ := openAlerts(t, repo.ID)
		defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, open+1)()
		all := len(alertsOf(t, repo.ID))
		w.commit(map[string]string{"n1.txt": token("n1") + "\n", "n2.txt": token("n2") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
		s := scanOf(t, repo.ID, secretscan_model.KindRepo)
		assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
		assert.Equal(t, stopAlerts, s.Error)
		assert.EqualValues(t, 1, s.Holes, "the secret that found no place")
		assert.Zero(t, s.RetryUnix, "a full alert list is not retried")
		assert.Len(t, alertsOf(t, repo.ID), all+1, "one of the two found a place")

		// closing an alert makes room: closed alerts don't count
		_, err := db.Exec(t.Context(), "UPDATE secret_scanning_alert SET state = ? WHERE id = ?", secretscan_model.StateRevoked, alertsOf(t, repo.ID)[0].ID)
		require.NoError(t, err)
		w.commit(map[string]string{"n3.txt": token("n3") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
		assert.NotNil(t, alertFor(t, repo.ID, token("n3")))
		assert.Equal(t, stopAlerts, scanOf(t, repo.ID, secretscan_model.KindRepo).Error, "the hole is still there")
	})
}

func TestFingerprintUninitialisedKeyingFailsScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	good := scanOf(t, repo.ID, secretscan_model.KindRepo)
	before := len(alertsOf(t, repo.ID))

	// the real Fingerprint panics with this value before the keying is set up
	defer test.MockVariableValue(&scanContent, func(*secretdetection.Detector, []byte) ([]secretdetection.Finding, bool) {
		panic("keying: not initialized")
	})()
	w.commit(map[string]string{"k.txt": token("k") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID), "the panic is recovered")

	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusFailed, s.Status)
	assert.Equal(t, errPanic, s.Error)
	assert.Equal(t, good.ScannedTips, s.ScannedTips, "the earlier tips stay, the file is scanned again")
	assert.Len(t, alertsOf(t, repo.ID), before)
}

func TestScanPartlyScannedBlobIsIncomplete(t *testing.T) {
	repo := enable(t)
	require.NoError(t, Scan(t.Context(), repo.ID))
	w := newWork(t, repo)
	w.commit(map[string]string{"p.txt": token("partial") + "\n"})
	w.pushDefault()
	defer test.MockVariableValue(&scanContent, func(d *secretdetection.Detector, c []byte) ([]secretdetection.Finding, bool) {
		r, _ := d.Scan(c)
		return r, false
	})()
	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopPartial, s.Error)
	assert.EqualValues(t, 1, s.Holes)
	assert.NotNil(t, alertFor(t, repo.ID, token("partial")), "what was found is kept")

	// a trigger with nothing new, and a later clean scan, leave the hole on the row
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Equal(t, s.Version, scanOf(t, repo.ID, secretscan_model.KindRepo).Version)
	scanContent = func(d *secretdetection.Detector, c []byte) ([]secretdetection.Finding, bool) { return d.Scan(c) }
	w.commit(map[string]string{"q.txt": "nothing\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	s = scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopPartial, s.Error)
	assert.EqualValues(t, 1, s.Holes)
}

func TestScanWiki(t *testing.T) {
	repo := enable(t)
	tok := token("wiki")
	require.True(t, repo.HasWiki(), "the fixture has a wiki")
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-c", "user.name=w", "-c", "user.email=w@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	run("clone", "-q", repo.WikiPath(), ".")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Secrets.md"), []byte("# Page\n\ntoken "+tok+"\n"), 0o644))
	run("add", "-A")
	run("commit", "-q", "-m", "page")
	run("push", "-q", "origin", "HEAD")

	require.NoError(t, Scan(t.Context(), repo.ID))
	require.NotNil(t, scanOf(t, repo.ID, secretscan_model.KindWiki))
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, secretscan_model.KindWiki, locs[0].Kind)
	assert.Equal(t, "Secrets.md", locs[0].Path)
	assert.Equal(t, 3, locs[0].StartLine)
	assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
}

// holdScan makes the next scan wait after it read the tips; hold returns when it is waiting, and release lets it go on.
func holdScan(t *testing.T) (hold, release func()) {
	t.Helper()
	started, gate := make(chan struct{}), make(chan struct{})
	done := false
	t.Cleanup(test.MockVariableValue(&afterTips, func(_ int64, kind string) {
		if kind == secretscan_model.KindRepo && !done {
			done = true
			close(started)
			<-gate
		}
	}))
	once := false
	release = func() {
		if !once {
			once = true
			close(gate)
		}
	}
	t.Cleanup(release)
	return func() {
		select {
		case <-started:
		case <-time.After(30 * time.Second):
			require.Fail(t, "the scan never reached the hold")
		}
	}, release
}

func scanInBackground(t *testing.T, repoID int64) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Scan(t.Context(), repoID) }()
	return done
}

func TestScanPushDuringScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	first, second := token("first"), token("second")
	w.commit(map[string]string{"1.txt": first + "\n"})
	w.pushDefault()
	startTips := currentTips(t, repo)

	hold, release := holdScan(t)
	done := scanInBackground(t, repo.ID)
	hold()
	w.commit(map[string]string{"2.txt": second + "\n"})
	w.pushDefault() // after the scan read the tips
	release()
	require.NoError(t, <-done)

	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	var tips []string
	require.NoError(t, json.Unmarshal([]byte(s.ScannedTips), &tips))
	assert.Equal(t, startTips, tips, "the state is the tips the scan read, not the push")
	assert.NotNil(t, alertFor(t, repo.ID, first))
	assert.Nil(t, alertFor(t, repo.ID, second))

	// the scan the push queued reads what is new
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, second))
	assert.EqualValues(t, 1, scanOf(t, repo.ID, secretscan_model.KindRepo).Blobs)
	require.NoError(t, json.Unmarshal([]byte(scanOf(t, repo.ID, secretscan_model.KindRepo).ScannedTips), &tips))
	assert.Equal(t, currentTips(t, repo), tips)
}

func TestScanSwitchOffDuringScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	w.commit(map[string]string{"1.txt": token("off") + "\n"})
	w.pushDefault()

	hold, release := holdScan(t)
	done := scanInBackground(t, repo.ID)
	hold()
	storeSiteSwitch(t, "off")
	release()
	require.NoError(t, <-done)

	assert.Nil(t, scanOf(t, repo.ID, secretscan_model.KindRepo), "nothing was written")
	assert.Empty(t, alertsOf(t, repo.ID))
}

func TestScanTrashDuringScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	w.commit(map[string]string{"1.txt": token("trash") + "\n"})
	w.pushDefault()

	hold, release := holdScan(t)
	done := scanInBackground(t, repo.ID)
	hold()
	_, err := db.Exec(t.Context(), "UPDATE repository SET trashed_unix = 1 WHERE id = ?", repo.ID)
	require.NoError(t, err)
	release()
	require.NoError(t, <-done)

	assert.Nil(t, scanOf(t, repo.ID, secretscan_model.KindRepo))
	assert.Empty(t, alertsOf(t, repo.ID))
}

func TestScanTransferDuringScan(t *testing.T) {
	repo := enable(t)
	q := mockQueue(t)
	w := newWork(t, repo)
	w.commit(map[string]string{"1.txt": token("transfer") + "\n"})
	w.pushDefault()

	hold, release := holdScan(t)
	done := scanInBackground(t, repo.ID)
	hold()
	_, err := db.Exec(t.Context(), "UPDATE repository SET owner_id = 3 WHERE id = ?", repo.ID)
	require.NoError(t, err)
	release()
	require.NoError(t, <-done)

	assert.Nil(t, scanOf(t, repo.ID, secretscan_model.KindRepo), "the scan read the rules and the switch of the old owner: discarded")
	assert.Empty(t, alertsOf(t, repo.ID))
	has, err := q.Has(repo.ID)
	require.NoError(t, err)
	assert.True(t, has, "and queued again")
}

func TestScanLostWriteRequeues(t *testing.T) {
	repo := enable(t)
	q := mockQueue(t)
	w := newWork(t, repo)
	w.commit(map[string]string{"1.txt": token("lost") + "\n"})
	w.pushDefault()

	// another process stores a state row while this scan reads
	hold, release := holdScan(t)
	done := scanInBackground(t, repo.ID)
	hold()
	require.NoError(t, secretscan_model.Save(t.Context(), nil, &secretscan_model.Scan{RepoID: repo.ID, Kind: secretscan_model.KindRepo, Status: secretscan_model.StatusOK, ScannedTips: "[]"}))
	release()
	require.NoError(t, <-done)

	st := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, "[]", st.ScannedTips, "the other process's row stays")
	var repoLocations int64
	repoLocations, err := db.GetEngine(t.Context()).Where("repo_id = ? AND kind = ?", repo.ID, secretscan_model.KindRepo).Count(new(secretscan_model.Location))
	require.NoError(t, err)
	assert.Zero(t, repoLocations, "the write was rolled back")
	has, err := q.Has(repo.ID)
	require.NoError(t, err)
	assert.True(t, has)
}

// mockQueue replaces the scan queue with one that holds the items.
func mockQueue(t *testing.T) *queue.WorkerPoolQueue[int64] {
	t.Helper()
	cfg, err := setting.NewConfigProviderFromData("[queue.secret_scanning]\nTYPE = channel\n")
	require.NoError(t, err)
	t.Cleanup(test.MockVariableValue(&setting.CfgProvider, cfg))
	q := queue.CreateUniqueQueue(t.Context(), "secret_scanning", func(items ...int64) []int64 { return nil })
	require.NotNil(t, q)
	t.Cleanup(test.MockVariableValue(&scanQueue, q))
	return q
}

var lastRevision int

// storeSiteSwitch stores the site switch as the admin page will and moves the settings revision past the cached
// one: fixtures reset it, and a value is cached by revision.
func storeSiteSwitch(t *testing.T, mode string) {
	t.Helper()
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().SecretScanning.DynKey(): `{"mode":"` + mode + `"}`}))
	bumpRevision(t)
}

func bumpRevision(t *testing.T) {
	t.Helper()
	lastRevision = max(lastRevision, system_model.GetRevision(db.DefaultContext)) + 1
	_, err := db.Exec(db.DefaultContext, "UPDATE system_setting SET version=? WHERE setting_key='revision'", lastRevision)
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
}

func TestSwitches(t *testing.T) {
	repo := enable(t)
	org := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // owned by org3
	setOrg := func(on, locked bool) {
		t.Helper()
		_, err := db.Exec(t.Context(), "DELETE FROM user_setting WHERE user_id = 3 AND setting_key LIKE 'secret_scanning.%'")
		require.NoError(t, err)
		if !on {
			_, err = db.Exec(t.Context(), "INSERT INTO user_setting (user_id, setting_key, setting_value) VALUES (3, ?, 'false')", secretscan_model.OrgKey)
			require.NoError(t, err)
		}
		if locked {
			_, err = db.Exec(t.Context(), "INSERT INTO user_setting (user_id, setting_key, setting_value) VALUES (3, ?, 'true')", secretscan_model.OrgLockedKey)
			require.NoError(t, err)
		}
	}
	reload := func(r *repo_model.Repository) *repo_model.Repository {
		return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: r.ID})
	}
	optOut := func(r *repo_model.Repository, out bool) {
		t.Helper()
		_, err := db.Exec(t.Context(), "UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", out, r.ID)
		require.NoError(t, err)
	}

	assert.True(t, Enabled(t.Context(), reload(repo)))
	assert.True(t, Enabled(t.Context(), reload(org)))

	t.Run("repository opt-out", func(t *testing.T) {
		optOut(repo, true)
		assert.False(t, Enabled(t.Context(), reload(repo)))
		optOut(repo, false)
	})
	t.Run("organization off", func(t *testing.T) {
		setOrg(false, false)
		assert.False(t, Enabled(t.Context(), reload(org)))
		assert.True(t, Enabled(t.Context(), reload(repo)), "a personal repository has no organization")
	})
	t.Run("a lock overrides the opt-out of a repository", func(t *testing.T) {
		optOut(org, true)
		setOrg(true, false)
		assert.False(t, Enabled(t.Context(), reload(org)))
		setOrg(true, true)
		assert.True(t, Enabled(t.Context(), reload(org)))
		setOrg(false, true)
		assert.False(t, Enabled(t.Context(), reload(org)), "an organization that is off is off for every repository")
		optOut(org, false)
		setOrg(true, false)
	})
	t.Run("settings of a personal owner never count", func(t *testing.T) {
		_, err := db.Exec(t.Context(), "INSERT INTO user_setting (user_id, setting_key, setting_value) VALUES (?, ?, 'false')", repo.OwnerID, secretscan_model.OrgKey)
		require.NoError(t, err)
		assert.True(t, Enabled(t.Context(), reload(repo)))
		var off []int64
		require.NoError(t, db.GetEngine(t.Context()).Table("repository").Select("id").Where("id = ?", repo.ID).And(secretscan_model.OffCond()).Find(&off))
		assert.Empty(t, off, "the SQL form agrees")
	})
	t.Run("site off", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
		assert.False(t, Enabled(t.Context(), reload(repo)))
		storeSiteSwitch(t, "on")
		assert.True(t, Enabled(t.Context(), reload(repo)), "the stored switch wins over app.ini")
		storeSiteSwitch(t, "off")
		assert.False(t, Enabled(t.Context(), reload(repo)))
		storeSiteSwitch(t, "") // app.ini again
	})
	t.Run("the SQL form agrees", func(t *testing.T) {
		for _, c := range []struct{ on, locked, optOut bool }{{true, false, false}, {true, false, true}, {true, true, true}, {false, false, false}, {false, true, true}} {
			setOrg(c.on, c.locked)
			optOut(org, c.optOut)
			var off []int64
			require.NoError(t, db.GetEngine(t.Context()).Table("repository").Select("id").Where("id = ?", org.ID).And(secretscan_model.OffCond()).Find(&off))
			assert.Equal(t, !Enabled(t.Context(), reload(org)), len(off) == 1, "%+v", c)
		}
	})
}

func TestScanSwitchesAndKeptRows(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	a, b := token("kept-a"), token("kept-b")
	w.commit(map[string]string{"a.txt": a + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	require.NotNil(t, alertFor(t, repo.ID, a))
	state := scanOf(t, repo.ID, secretscan_model.KindRepo)

	// off: no scan, and the rows stay
	_, err := db.Exec(t.Context(), "UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", true, repo.ID)
	require.NoError(t, err)
	w.commit(map[string]string{"b.txt": b + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Nil(t, alertFor(t, repo.ID, b))
	assert.NotNil(t, alertFor(t, repo.ID, a), "off keeps the alerts")
	assert.Equal(t, state.Version, scanOf(t, repo.ID, secretscan_model.KindRepo).Version)

	// site off
	_, err = db.Exec(t.Context(), "UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", false, repo.ID)
	require.NoError(t, err)
	storeSiteSwitch(t, "off")
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Nil(t, alertFor(t, repo.ID, b))
	assert.NotNil(t, alertFor(t, repo.ID, a))

	// on again: a scan from the stored state reads only what is new
	storeSiteSwitch(t, "on")
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, b))
	assert.EqualValues(t, 1, scanOf(t, repo.ID, secretscan_model.KindRepo).Blobs)
}

func TestForkStartsFromParentState(t *testing.T) {
	parent := enable(t)
	fork := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	n := &notifier{}
	q := mockQueue(t)
	queued := func(id int64) bool {
		has, err := q.Has(id)
		require.NoError(t, err)
		return has
	}

	// the parent was never scanned: the fork scans everything
	n.ForkRepository(t.Context(), nil, parent, fork)
	assert.Nil(t, scanOf(t, fork.ID, secretscan_model.KindRepo))
	assert.True(t, queued(fork.ID))
	require.NoError(t, q.RemoveAllItems(t.Context()))

	// the parent's scan is incomplete: the same
	require.NoError(t, secretscan_model.Save(t.Context(), nil, &secretscan_model.Scan{RepoID: parent.ID, Kind: secretscan_model.KindRepo, Status: secretscan_model.StatusIncomplete, ScannedTips: `["a"]`}))
	n.ForkRepository(t.Context(), nil, parent, fork)
	assert.Nil(t, scanOf(t, fork.ID, secretscan_model.KindRepo))

	// complete: the fork starts from its tips
	cur := scanOf(t, parent.ID, secretscan_model.KindRepo)
	cur.Status, cur.ScannedTips = secretscan_model.StatusOK, `["abc","def"]`
	require.NoError(t, secretscan_model.Save(t.Context(), cur, cur))
	n.ForkRepository(t.Context(), nil, parent, fork)
	s := scanOf(t, fork.ID, secretscan_model.KindRepo)
	require.NotNil(t, s)
	assert.Equal(t, `["abc","def"]`, s.ScannedTips)
	assert.Equal(t, secretscan_model.StatusOK, s.Status)
	assert.True(t, queued(fork.ID))
	assert.Empty(t, alertsOf(t, fork.ID), "the alerts stay with the parent")
}

func TestNotifierEnqueues(t *testing.T) {
	repo := enable(t)
	q := mockQueue(t)
	n := &notifier{}
	queued := func() bool {
		has, err := q.Has(repo.ID)
		require.NoError(t, err)
		if has {
			require.NoError(t, q.RemoveAllItems(t.Context()))
		}
		return has
	}
	events := map[string]func(){
		"push":      func() { n.PushCommits(t.Context(), nil, repo, nil, nil) },
		"mirror":    func() { n.SyncPushCommits(t.Context(), nil, repo, nil, nil) },
		"migrate":   func() { n.MigrateRepository(t.Context(), nil, nil, repo) },
		"transfer":  func() { n.TransferRepository(t.Context(), nil, repo, "old") },
		"wiki new":  func() { n.NewWikiPage(t.Context(), nil, repo, "p", "") },
		"wiki edit": func() { n.EditWikiPage(t.Context(), nil, repo, "p", "") },
	}
	for name, fire := range events {
		fire()
		assert.True(t, queued(), name)
	}
	// the queue holds a repository once
	Enqueue(repo.ID)
	require.ErrorIs(t, q.Push(repo.ID), queue.ErrAlreadyInQueue)
	require.NoError(t, q.RemoveAllItems(t.Context()))

	defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
	for name, fire := range events {
		fire()
		assert.False(t, queued(), "off: "+name)
	}
}

func TestEnqueueUnscanned(t *testing.T) {
	enable(t)
	q := mockQueue(t)
	ids := func() map[int64]bool {
		m := map[int64]bool{}
		for id := int64(1); id < 2000; id++ {
			if has, err := q.Has(id); err == nil && has {
				m[id] = true
			}
		}
		require.NoError(t, q.RemoveAllItems(t.Context()))
		return m
	}
	ready := func() []int64 {
		var all []int64
		require.NoError(t, db.GetEngine(t.Context()).Table("repository").Select("id").Where("status = ? AND trashed_unix = 0", repo_model.RepositoryReady).Find(&all))
		return all
	}
	require.NoError(t, EnqueueUnscanned(t.Context()))
	got := ids()
	assert.NotEmpty(t, got)
	for _, id := range ready() { // empty repositories too: their wiki may hold a secret
		assert.True(t, got[id], id)
	}
	var empty []int64
	require.NoError(t, db.GetEngine(t.Context()).Table("repository").Select("id").Where("is_empty = ? AND status = ? AND trashed_unix = 0", true, repo_model.RepositoryReady).Find(&empty))
	require.NotEmpty(t, empty, "the fixtures have an empty repository")
	assert.True(t, got[empty[0]], "an empty repository is queued")

	now := timeutil.TimeStampNow()
	save := func(id int64, kind, status string, retry timeutil.TimeStamp) {
		require.NoError(t, secretscan_model.Save(t.Context(), nil, &secretscan_model.Scan{RepoID: id, Kind: kind, Status: status, ScannedTips: "[]", RetryUnix: retry, FailCount: 1}))
	}
	repoKind, wikiKind := secretscan_model.KindRepo, secretscan_model.KindWiki
	save(1, repoKind, secretscan_model.StatusOK, 0)
	save(2, repoKind, secretscan_model.StatusIncomplete, now.Add(3600)) // under way or backing off
	save(3, repoKind, secretscan_model.StatusFailed, now.Add(3600))
	save(4, repoKind, secretscan_model.StatusFailed, now.Add(-1))     // the backoff is over
	save(6, repoKind, secretscan_model.StatusIncomplete, now.Add(-1)) // a limit stopped it: it goes on
	save(7, repoKind, secretscan_model.StatusOK, 0)                   // the repository is done...
	save(7, wikiKind, secretscan_model.StatusFailed, now.Add(-1))     // ...its wiki failed, and is due
	_, err := db.Exec(t.Context(), "UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", true, 5)
	require.NoError(t, err)
	require.NoError(t, EnqueueUnscanned(t.Context()))
	got = ids()
	assert.False(t, got[1], "scanned")
	assert.False(t, got[2], "incomplete, backing off")
	assert.False(t, got[3], "failed, backing off")
	assert.True(t, got[4], "failed, backoff over")
	assert.False(t, got[5], "turned off by its admin")
	assert.True(t, got[6], "a stopped scan goes on")
	assert.True(t, got[7], "a failed wiki scan is retried")

	defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
	require.NoError(t, EnqueueUnscanned(t.Context()))
	assert.Empty(t, ids(), "the site switch is off")
}

func TestScanCanary(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	canary := token("canary")
	body := strings.TrimPrefix(canary, "ghp"+"_")
	lc, cancel := test.NewLogChecker(log.DEFAULT, log.TRACE)
	defer cancel()
	lc.Filter(canary, body, body[:12]).StopMark("canary-stop-mark")

	w.commit(map[string]string{"c.env": "export T=" + canary + "\n"}, "Dev", "dev@example.com")
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	require.NotNil(t, alertFor(t, repo.ID, canary))
	// a scan that panics with the secret in the panic value
	defer test.MockVariableValue(&scanContent, func(*secretdetection.Detector, []byte) ([]secretdetection.Finding, bool) { panic("boom " + canary) })()
	w.commit(map[string]string{"d.env": "export T=" + token("canary2") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Equal(t, secretscan_model.StatusFailed, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)

	for _, table := range []string{"secret_scan", "secret_scanning_alert", "secret_scanning_location", "secret_scanning_alert_index", "audit_event"} {
		rows, err := db.GetEngine(t.Context()).Query("SELECT * FROM " + table)
		require.NoError(t, err)
		for _, row := range rows {
			for col, v := range row {
				for _, needle := range []string{canary, body, body[:12]} {
					assert.NotContains(t, string(v), needle, "%s.%s", table, col)
				}
			}
		}
	}
	log.Info("canary-stop-mark")
	seen, stopped := lc.Check(5 * time.Second)
	require.True(t, stopped)
	assert.Equal(t, []bool{false, false, false}, seen, "the secret is in no log line")
}

type sqlCounter struct {
	on atomic.Bool
	n  atomic.Int64
}

func (c *sqlCounter) BeforeProcess(ctx *contexts.ContextHook) (context.Context, error) {
	if c.on.Load() {
		c.n.Add(1)
	}
	return db.TracingHook{}.BeforeProcess(ctx)
}

func (c *sqlCounter) AfterProcess(ctx *contexts.ContextHook) error {
	return db.TracingHook{}.AfterProcess(ctx)
}

var (
	queryCounter     = &sqlCounter{}
	queryCounterOnce sync.Once
)

// countQueries runs fn and returns the number of statements it ran.
func countQueries(t *testing.T, fn func()) int64 {
	t.Helper()
	queryCounterOnce.Do(func() {
		x, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
		require.NoError(t, err)
		x.AddHook(queryCounter)
	})
	queryCounter.n.Store(0)
	queryCounter.on.Store(true)
	defer queryCounter.on.Store(false)
	fn()
	return queryCounter.n.Load()
}

// commitsWithKeys adds n commits, each with one file holding its own key, and returns the keys.
func commitsWithKeys(w *work, prefix string, n int) []string {
	var toks []string
	for i := range n {
		tok := token(fmt.Sprintf("%s-%d", prefix, i))
		toks = append(toks, tok)
		w.commit(map[string]string{fmt.Sprintf("%s%d.txt", prefix, i): tok + "\n"})
	}
	return toks
}

// cancelScan ends the scan of the repository the way its time running out would.
func cancelScan(repoID int64) {
	ps, _ := process.GetManager().Processes(true, true)
	for _, p := range ps {
		if p.Description == fmt.Sprintf("secret scan of repository %d", repoID) {
			process.GetManager().Cancel(p.PID)
		}
	}
}

func TestScanPullRefsAreTheirOwnScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID)) // the history the fixture has
	def, pull := token("p-def"), token("p-pull")

	w.git("checkout", "-q", "-b", "pr")
	w.commit(map[string]string{"pull.txt": pull + "\n"})
	w.push("refs/pull/4/head")
	w.git("checkout", "-q", repo.DefaultBranch)
	w.commit(map[string]string{"def.txt": def + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))

	repoRow, pullRow := scanOf(t, repo.ID, secretscan_model.KindRepo), scanOf(t, repo.ID, secretscan_model.KindPull)
	require.NotNil(t, pullRow, "refs/pull/* have a row of their own")
	pullTips, err := refTips(t.Context(), repo.RepoPath(), true)
	require.NoError(t, err)
	var tips []string
	require.NoError(t, json.Unmarshal([]byte(pullRow.ScannedTips), &tips))
	assert.Equal(t, pullTips, tips)
	assert.NotContains(t, repoRow.ScannedTips, pullTips[0], "and the other row doesn't hold the pull tips")
	assert.True(t, alertFor(t, repo.ID, pull).ViaPull)
	assert.False(t, alertFor(t, repo.ID, def).ViaPull)
	assert.Equal(t, secretscan_model.KindPull, locationsOf(t, alertFor(t, repo.ID, pull).ID)[0].Kind, "the place says a pull ref reaches it")

	// merged: a branch reaches the place too, and it is listed once per kind
	w.git("checkout", "-q", "pr")
	w.push("refs/heads/pr")
	require.NoError(t, Scan(t.Context(), repo.ID))
	locs := locationsOf(t, alertFor(t, repo.ID, pull).ID)
	require.Len(t, locs, 2)
	assert.ElementsMatch(t, []string{secretscan_model.KindPull, secretscan_model.KindRepo}, []string{locs[0].Kind, locs[1].Kind})
	assert.Equal(t, locs[0].Path, locs[1].Path)
	assert.False(t, alertFor(t, repo.ID, pull).ViaPull)
}

func TestScanContinuesWithinATip(t *testing.T) {
	repo := enable(t)
	q := mockQueue(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID)) // the history the fixture has
	base := len(alertsOf(t, repo.ID))
	toks := commitsWithKeys(w, "m", 6)
	w.commit(map[string]string{"big.bin": strings.Repeat("x", 500)})
	w.pushDefault()
	defer test.MockVariableValue(&setting.SecretScanning.MaxBlobSize, 100)()
	size := int64(len(toks[0]) + 1)
	restore := test.MockVariableValue(&setting.SecretScanning.MaxScanBytes, 2*size)
	defer restore()

	// one tip alone is bigger than a slice: each slice stores a prefix of its commits and queues the next one
	var last int64
	slices := 0
	for ; slices < 20; slices++ {
		require.NoError(t, Scan(t.Context(), repo.ID))
		s := scanOf(t, repo.ID, secretscan_model.KindRepo)
		if s.Status == secretscan_model.StatusOK {
			break
		}
		assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
		assert.Equal(t, stopBytes, s.Error)
		assert.Zero(t, s.FailCount, "progress is no failure")
		assert.Greater(t, s.Blobs, last, "every slice makes progress")
		assert.LessOrEqual(t, s.Blobs-last, int64(2), "and reads at most the limit")
		last = s.Blobs
		has, err := q.Has(repo.ID)
		require.NoError(t, err)
		assert.True(t, has, "the next slice is queued behind the others")
		require.NoError(t, q.RemoveAllItems(t.Context()))
		var tips []string
		require.NoError(t, json.Unmarshal([]byte(s.ScannedTips), &tips))
		assert.NotEqual(t, currentTips(t, repo), tips, "a commit inside the tip stands for what is done")
	}
	assert.Equal(t, 2, slices, "two slices stop at the limit, the third finishes")
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusOK, s.Status)
	assert.EqualValues(t, 6, s.Blobs, "every file once")
	assert.EqualValues(t, 1, s.SkippedLarge, "the large file is counted once over the slices")
	assert.Len(t, alertsOf(t, repo.ID), base+6)
	assert.Equal(t, secretscan_model.CurrentKeyVersion, alertFor(t, repo.ID, toks[5]).KeyVersion)
	var tips []string
	require.NoError(t, json.Unmarshal([]byte(s.ScannedTips), &tips))
	assert.Equal(t, currentTips(t, repo), tips, "the commits that stood in for the tip are gone")
}

func TestScanRaisedLimitFinishes(t *testing.T) {
	repo := enable(t)
	mockQueue(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	base := len(alertsOf(t, repo.ID))
	toks := commitsWithKeys(w, "r", 5)
	w.pushDefault()
	restore := test.MockVariableValue(&setting.SecretScanning.MaxScanBlobs, 2)
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Equal(t, secretscan_model.StatusIncomplete, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
	assert.Less(t, len(alertsOf(t, repo.ID)), base+5)
	restore()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
	for _, tok := range toks {
		assert.NotNil(t, alertFor(t, repo.ID, tok))
	}
}

func TestScanPullRefsHaveTheirOwnShare(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	open, _ := openAlerts(t, repo.ID)
	limit := 2*open + 8
	defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, limit)()

	// a reader's pull ref holds more junk keys than the repository may have alerts
	junk := func(round string) {
		w.git("checkout", "-q", "-b", "junk"+round, repo.DefaultBranch)
		files := map[string]string{}
		for i := range limit + 3 {
			files[fmt.Sprintf("j%d.txt", i)] = token(fmt.Sprintf("junk%s-%d", round, i)) + "\n"
		}
		w.commit(files)
		w.push("refs/pull/" + round + "/head")
	}
	junk("1")
	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopAlerts, s.Error)
	assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status, "the branches are not affected")
	_, pulls := openAlerts(t, repo.ID)
	assert.Equal(t, limit/2, pulls, "half of the cap at most")

	// the real key on the default branch still gets its alert
	w.git("checkout", "-q", repo.DefaultBranch)
	real := token("real-key")
	w.commit(map[string]string{"real.txt": real + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	a := alertFor(t, repo.ID, real)
	require.NotNil(t, a)
	assert.False(t, a.ViaPull)

	// closed alerts don't count against the share
	_, err := db.Exec(t.Context(), "UPDATE secret_scanning_alert SET state = ? WHERE via_pull = ? AND repo_id = ?", secretscan_model.StateRevoked, true, repo.ID)
	require.NoError(t, err)
	junk("2")
	require.NoError(t, Scan(t.Context(), repo.ID))
	_, pulls = openAlerts(t, repo.ID)
	assert.Equal(t, limit/2, pulls, "the real key is the branches' and takes no place of the share")
}

// a fork PR's key is found as a pull ref, and again when the PR is merged: the alert is no longer a pull-ref one, and
// one that the pull share left out is created with the branch share
func TestScanPullThenMerge(t *testing.T) {
	for _, ff := range []bool{true, false} {
		t.Run(fmt.Sprintf("fast-forward=%v", ff), func(t *testing.T) {
			repo := enable(t)
			w := newWork(t, repo)
			require.NoError(t, Scan(t.Context(), repo.ID))
			open, _ := openAlerts(t, repo.ID)
			limit := 2*open + 8
			defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, limit)()

			// junk fills the pull share, then a contributor's fork PR brings a real key
			w.git("checkout", "-q", "-b", "junk", repo.DefaultBranch)
			files := map[string]string{}
			for i := range limit {
				files[fmt.Sprintf("j%d.txt", i)] = token(fmt.Sprintf("j-%d", i)) + "\n"
			}
			w.commit(files)
			w.push("refs/pull/91/head")
			w.git("checkout", "-q", "-b", "fork", repo.DefaultBranch)
			merged, onlyPull := token("merged-key"), token("pull-only-key")
			w.commit(map[string]string{"m.txt": merged + "\n", "pp.txt": onlyPull + "\n"})
			w.push("refs/pull/92/head")
			require.NoError(t, Scan(t.Context(), repo.ID))
			_, pulls := openAlerts(t, repo.ID)
			assert.Equal(t, limit/2, pulls)
			pullAlert := alertFor(t, repo.ID, merged)
			assert.True(t, pullAlert == nil || pullAlert.ViaPull)

			// the maintainer merges it
			w.git("checkout", "-q", repo.DefaultBranch)
			if ff {
				w.git("merge", "-q", "--ff-only", "fork")
			} else {
				w.gitEnv(nil, "merge", "-q", "--no-ff", "-m", "merge", "fork")
			}
			w.pushDefault()
			require.NoError(t, Scan(t.Context(), repo.ID))
			a := alertFor(t, repo.ID, merged)
			require.NotNil(t, a, "the merged key has an alert")
			assert.False(t, a.ViaPull, "and it is a branch one now")
			require.NotNil(t, alertFor(t, repo.ID, onlyPull))
			assert.False(t, alertFor(t, repo.ID, onlyPull).ViaPull)
		})
	}
}

func TestScanManyPlacesIsBounded(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	tok := token("many")
	files := map[string]string{}
	for b := range 50 { // 50 blobs, each at 400 paths, with the key on 99 lines
		content := fmt.Sprintf("# version %d\n", b) + strings.Repeat("KEY="+tok+"\n", 99)
		for p := range 400 {
			files[fmt.Sprintf("d%d/f%03d.txt", b, p)] = content
		}
	}
	w.commit(files)
	w.pushDefault()

	queries := countQueries(t, func() { require.NoError(t, Scan(t.Context(), repo.ID)) })
	assert.Less(t, queries, int64(40), "no query per place")
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusOK, s.Status, "it fits the slice limits")
	assert.EqualValues(t, 50, s.Blobs, "each blob is read once, whatever the number of paths")
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	assert.Len(t, locationsOf(t, a.ID), 100, "capped")
	assert.Greater(t, a.LocationCount, 100, "the others are counted")
}

func TestScanHostilePathDoesNotStopTheScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	hostile, real := token("hostile-name"), token("real-after")

	// a file name of 1.5 MiB in one ref (git's tree objects allow it)
	blobCmd := exec.Command("git", "hash-object", "-w", "--stdin")
	blobCmd.Dir = w.dir
	blobCmd.Stdin = strings.NewReader("k=" + hostile + "\n")
	out, err := blobCmd.CombinedOutput()
	require.NoError(t, err, string(out))
	name := strings.Repeat("a", 3<<19) + ".txt"
	treeCmd := exec.Command("git", "mktree")
	treeCmd.Dir = w.dir
	treeCmd.Stdin = strings.NewReader("100644 blob " + strings.TrimSpace(string(out)) + "\t" + name + "\n")
	out, err = treeCmd.CombinedOutput()
	require.NoError(t, err, string(out))
	commit := w.git("commit-tree", strings.TrimSpace(string(out)), "-p", "HEAD", "-m", "long")
	w.git("push", "-q", "--force", repo.RepoPath(), commit+":refs/heads/longname")
	w.commit(map[string]string{"real.txt": real + "\n"})
	w.pushDefault()

	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusOK, s.Status)
	assert.NotNil(t, alertFor(t, repo.ID, real), "the scan went on")
	a := alertFor(t, repo.ID, hostile)
	require.NotNil(t, a)
	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.LessOrEqual(t, len(locs[0].Path), 4096)
	assert.True(t, strings.HasPrefix(locs[0].Path, "aaaa"))
}

func TestScanBackoffDoesNotDelayTheBranches(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	pullTips := scanOf(t, repo.ID, secretscan_model.KindPull).ScannedTips
	now := time.Now().Truncate(time.Second)
	timeutil.MockSet(now)
	defer timeutil.MockUnset()
	good, junk := token("bo-good"), token("bo-junk")
	boom := true
	defer test.MockVariableValue(&scanContent, func(d *secretdetection.Detector, c []byte) ([]secretdetection.Finding, bool) {
		if boom && strings.Contains(string(c), "BOOM") {
			panic("boom")
		}
		return d.Scan(c)
	})()

	// a pull ref fails its scan: only the pull row waits
	w.git("checkout", "-q", "-b", "pr")
	w.commit(map[string]string{"p.txt": "BOOM " + junk + "\n"})
	w.push("refs/pull/3/head")
	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, secretscan_model.StatusFailed, s.Status)
	assert.Equal(t, errPanic, s.Error)
	assert.Equal(t, 1, s.FailCount)
	assert.EqualValues(t, now.Unix()+600, s.RetryUnix)
	assert.Equal(t, pullTips, s.ScannedTips, "no tips of a failed scan")
	assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)

	// a key pushed to the default branch is found at once
	w.git("checkout", "-q", repo.DefaultBranch)
	w.commit(map[string]string{"g.txt": good + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, good))
	cur := scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, s.Version, cur.Version, "the pull row waits for its backoff")
	assert.Nil(t, alertFor(t, repo.ID, junk))
	assert.NotContains(t, dueRepos(t, timeutil.TimeStamp(now.Unix())), repo.ID)

	// each failure in a row doubles the delay, up to a day
	later(t, 11*time.Minute)
	assert.Contains(t, dueRepos(t, timeutil.TimeStampNow()), repo.ID)
	require.NoError(t, Scan(t.Context(), repo.ID))
	cur = scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, 2, cur.FailCount)
	assert.Equal(t, timeutil.TimeStampNow().Add(1200), cur.RetryUnix)
	_, err := db.Exec(t.Context(), "UPDATE secret_scan SET fail_count = 20 WHERE repo_id = ? AND kind = 'pull'", repo.ID)
	require.NoError(t, err)
	later(t, 25*time.Hour)
	require.NoError(t, Scan(t.Context(), repo.ID))
	cur = scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, timeutil.TimeStampNow().Add(86400), cur.RetryUnix, "at most a day")

	// the cause goes away: the pull scan finishes after the backoff
	boom = false
	later(t, 25*time.Hour)
	require.NoError(t, Scan(t.Context(), repo.ID))
	cur = scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, secretscan_model.StatusOK, cur.Status)
	assert.Zero(t, cur.FailCount)
	assert.Zero(t, cur.RetryUnix)
	a := alertFor(t, repo.ID, junk)
	require.NotNil(t, a)
	assert.True(t, a.ViaPull)
}

func TestScanTimeoutStoresNoFakePlaces(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	tok := token("slow")
	commit := w.commit(map[string]string{"slow.txt": tok + "\n"})
	w.pushDefault()
	slow := true
	defer test.MockVariableValue(&scanContent, func(d *secretdetection.Detector, c []byte) ([]secretdetection.Finding, bool) {
		if slow {
			cancelScan(repo.ID) // the time runs out while the blob is scanned
		}
		return d.Scan(c)
	})()

	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopTimeout, s.Error)
	assert.Equal(t, 1, s.FailCount)
	assert.Nil(t, alertFor(t, repo.ID, tok), "the blob was found, but its commit was not handled: it is read again")
	n, err := db.GetEngine(t.Context()).Where("repo_id = ?", repo.ID).Count(new(secretscan_model.Location))
	require.NoError(t, err)
	assert.Zero(t, n)

	slow = false
	later(t, 11*time.Minute)
	require.NoError(t, Scan(t.Context(), repo.ID))
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.Equal(t, commit, locs[0].CommitID)
	assert.Equal(t, "slow.txt", locs[0].Path)
}

func TestScanStoreFailureIsStored(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	// an alert that already has the number the next one gets: the write fails on the unique key
	conflict := &secretscan_model.Alert{RepoID: repo.ID, Index: 1, RuleID: "x", Fingerprint: "y", State: secretscan_model.StateOpen}
	_, err := db.GetEngine(t.Context()).Insert(conflict)
	require.NoError(t, err)
	tok := token("store-fail")
	w.commit(map[string]string{"k.txt": tok + "\n"})
	head := w.git("rev-parse", "HEAD")
	w.pushDefault()
	now := time.Now().Truncate(time.Second)
	timeutil.MockSet(now)
	defer timeutil.MockUnset()
	err = Scan(t.Context(), repo.ID)
	require.ErrorContains(t, err, errStore)
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	require.NotNil(t, s)
	assert.Equal(t, secretscan_model.StatusFailed, s.Status)
	assert.Equal(t, errStore, s.Error)
	assert.Equal(t, 1, s.FailCount)
	assert.EqualValues(t, now.Unix()+600, s.RetryUnix)
	assert.NotContains(t, s.ScannedTips, head, "the tips of the write that failed are not stored")

	// the cause goes away: after the backoff the scan finds the alert
	_, err = db.GetEngine(t.Context()).ID(conflict.ID).Delete(new(secretscan_model.Alert))
	require.NoError(t, err)
	later(t, 11*time.Minute)
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, tok))
	assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
}

func TestScanRepoDeletedDuringScan(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	w.commit(map[string]string{"1.txt": token("deleted") + "\n"})
	w.pushDefault()

	hold, release := holdScan(t)
	done := scanInBackground(t, repo.ID)
	hold()
	require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID, repo_service.DeleteRepositoryOpts{}))
	release()
	require.NoError(t, <-done)

	for _, table := range []string{"secret_scan", "secret_scanning_alert", "secret_scanning_location"} {
		n, err := db.GetEngine(t.Context()).Table(table).Where("repo_id = ?", repo.ID).Count()
		require.NoError(t, err)
		assert.Zero(t, n, table)
	}
}

func TestScansOfOneRepositoryDoNotOverlap(t *testing.T) {
	repo := enable(t)
	hold, release := holdScan(t)
	first := scanInBackground(t, repo.ID)
	hold()
	locked, unlock := repoScans.TryLock(strconv.FormatInt(repo.ID, 10))
	unlock()
	assert.False(t, locked, "the repository is held while its scan runs")
	release()
	require.NoError(t, <-first)
	locked, unlock = repoScans.TryLock(strconv.FormatInt(repo.ID, 10))
	unlock()
	assert.True(t, locked, "and free afterwards")
}

// the pull scan leaves the branch history to the branch scan: its range excludes the branch row's done tips, and the
// secrets of the branches don't use up its share
func TestScanPullScanExcludesBranchHistory(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	open, _ := openAlerts(t, repo.ID)
	defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, open+8)()
	mains := commitsWithKeys(w, "m", 6)
	w.pushDefault()
	w.git("checkout", "-q", "-b", "pr")
	pull := token("only-in-the-pr")
	w.commit(map[string]string{"pr.txt": pull + "\n"})
	w.push("refs/pull/7/head")

	require.NoError(t, Scan(t.Context(), repo.ID))
	for _, tok := range mains {
		assert.NotNil(t, alertFor(t, repo.ID, tok))
	}
	a := alertFor(t, repo.ID, pull)
	require.NotNil(t, a, "the share of the pull refs holds the secret of the PR")
	assert.True(t, a.ViaPull)
	s := scanOf(t, repo.ID, secretscan_model.KindPull)
	assert.Equal(t, secretscan_model.StatusOK, s.Status)
	assert.EqualValues(t, 1, s.Blobs, "the history of the branches is not read again")
}

// progress is never dropped: PR refs that don't fit one slice are all done after a bounded number of slices, and every
// blob is read once
func TestScanManyPullRefsFinish(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	defer test.MockVariableValue(&setting.SecretScanning.MaxScanBlobs, 4)()
	var toks []string
	for i := range 12 {
		w.git("checkout", "-q", "-B", "pr", repo.DefaultBranch)
		tok := token(fmt.Sprintf("many-%d", i))
		toks = append(toks, tok)
		w.commit(map[string]string{fmt.Sprintf("p%d.txt", i): tok + "\n"})
		w.push(fmt.Sprintf("refs/pull/%d/head", i+1))
	}
	slices := 0
	for ; slices < 12; slices++ {
		require.NoError(t, Scan(t.Context(), repo.ID))
		if scanOf(t, repo.ID, secretscan_model.KindPull).Status == secretscan_model.StatusOK {
			break
		}
	}
	assert.LessOrEqual(t, slices, 3, "12 files, 4 per slice")
	assert.EqualValues(t, 12, scanOf(t, repo.ID, secretscan_model.KindPull).Blobs, "every blob once")
	for _, tok := range toks {
		assert.NotNil(t, alertFor(t, repo.ID, tok))
	}
}

// a commit that can't be handled within the time is tried once more, then it is a hole and the scan goes on
func TestScanTimeoutCommitBecomesAHole(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	slow := token("slow-commit")
	w.commit(map[string]string{"slow.txt": "SLOW " + slow + "\n"})
	w.pushDefault()
	defer test.MockVariableValue(&scanContent, func(d *secretdetection.Detector, c []byte) ([]secretdetection.Finding, bool) {
		if strings.Contains(string(c), "SLOW") {
			cancelScan(repo.ID)
		}
		return d.Scan(c)
	})()

	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, 1, s.FailCount, "the first time it is a failure with a backoff")
	later(t, 11*time.Minute)
	require.NoError(t, Scan(t.Context(), repo.ID))
	s = scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopHole, s.Error)
	assert.Zero(t, s.FailCount)
	assert.EqualValues(t, 1, s.Holes)
	assert.Contains(t, s.ScannedTips, w.git("rev-parse", "HEAD"), "the commit is done")

	afterSlow := token("after-the-slow-commit")
	w.commit(map[string]string{"later.txt": afterSlow + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, afterSlow), "the next commit is scanned")
	assert.Equal(t, secretscan_model.StatusIncomplete, scanOf(t, repo.ID, secretscan_model.KindRepo).Status, "the hole stays")
}

// entries that are no blobs (submodules) count against MAX_SCAN_BLOBS too, so a commit of them is cut by the limit
func TestScanEntriesOtherThanBlobsAreLimited(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	defer test.MockVariableValue(&setting.SecretScanning.MaxScanBlobs, 5)()
	var tree strings.Builder
	for i := range 20 {
		fmt.Fprintf(&tree, "160000 commit %040x\tsub%d\n", i+1, i)
	}
	treeCmd := exec.Command("git", "mktree", "--missing")
	treeCmd.Dir = w.dir
	treeCmd.Stdin = strings.NewReader(tree.String())
	out, err := treeCmd.CombinedOutput()
	require.NoError(t, err, string(out))
	commit := w.git("commit-tree", strings.TrimSpace(string(out)), "-p", "HEAD", "-m", "gitlinks")
	w.git("push", "-q", "--force", repo.RepoPath(), commit+":refs/heads/"+repo.DefaultBranch)
	w.git("reset", "-q", "--hard", commit)
	tok := token("after-gitlinks")
	w.commit(map[string]string{"k.txt": tok + "\n"})
	w.pushDefault()

	require.NoError(t, Scan(t.Context(), repo.ID))
	s := scanOf(t, repo.ID, secretscan_model.KindRepo)
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopHole, s.Error)
	assert.Positive(t, s.Holes, "the commit of entries is a hole, not a wait for the time")
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, tok))
}

// a tag of a tag reaches its commit
func TestScanNestedTagIsPeeled(t *testing.T) {
	repo := enable(t)
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	w.git("checkout", "-q", "-b", "hidden")
	tok := token("nested-tag")
	w.commit(map[string]string{"n.txt": tok + "\n"})
	w.git("tag", "-a", "-m", "one", "inner")
	w.git("tag", "-a", "-m", "two", "outer", "inner")
	w.git("push", "-q", "--force", repo.RepoPath(), "refs/tags/outer:refs/tags/outer")

	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, tok))
}

// time running out while the refs are read is a timeout, not a git error
func TestScanTimeoutReadingTipsIsATimeout(t *testing.T) {
	repo := enable(t)
	require.NoError(t, Scan(t.Context(), repo.ID))
	defer test.MockVariableValue(&afterTips, func(id int64, _ string) { cancelScan(id) })()
	w := newWork(t, repo)
	w.commit(map[string]string{"y.txt": "y\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Equal(t, stopTimeout, scanOf(t, repo.ID, secretscan_model.KindRepo).Error)
}
