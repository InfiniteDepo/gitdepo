// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	vulnerability_model "forgejo.org/models/vulnerability"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/git"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const goMod = "module example.com/m\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/net v0.10.0 // indirect\n)\n"

const lockV3 = `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"^1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","license":"WTFPL"}}}`

// commitFiles replaces the default branch of the repository with one commit holding the files (and symlinks, path
// to target) and returns its SHA. The repository is a bare directory of the fixtures, so git is run from a clone.
func commitFiles(t *testing.T, repo *repo_model.Repository, files, symlinks map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "core.quotepath=off"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", repo.DefaultBranch)
	for p, c := range files {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644))
	}
	for p, target := range symlinks {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755))
		require.NoError(t, os.Symlink(target, filepath.Join(dir, p)))
	}
	run("add", "-A")
	run("commit", "-q", "--allow-empty", "-m", "files")
	run("push", "-q", "--force", repo.RepoPath(), "HEAD:refs/heads/"+repo.DefaultBranch)
	return run("rev-parse", "HEAD")
}

func enable(t *testing.T) *repo_model.Repository {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.Enabled, true))
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.MaxManifestSize, 20<<20))
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.MaxManifests, 500))
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.MaxDependencies, 50000))
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.MaxTreeEntries, 200000))
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.ScanTimeout, time.Minute))
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
}

func rowsOf(t *testing.T, repoID int64) map[string]*repo_model.Dependency {
	t.Helper()
	var rows []*repo_model.Dependency
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ?", repoID).Find(&rows))
	m := map[string]*repo_model.Dependency{}
	for _, r := range rows {
		m[r.Ecosystem+"|"+r.Name+"@"+r.Version+"|"+r.ManifestPath] = r
	}
	return m
}

func TestScan(t *testing.T) {
	repo := enable(t)
	sha := commitFiles(t, repo, map[string]string{
		"go.mod":                             goMod,
		"web/package-lock.json":              lockV3,
		"web/package.json":                   `{"dependencies":{"left-pad":"^1.3.0"}}`,
		"vendor/go.mod":                      goMod, // vendored
		"a/node_modules/x/package-lock.json": lockV3,
		"vendored/go.mod":                    "module v\n\nrequire example.com/vend v1.0.0\n",
		"testdata/go.mod":                    goMod,
		"req/requirements.txt":               "django==4.2\n-r ../../../../etc/passwd\n--index-url http://169.254.169.254\n",
		"bad/pom.xml":                        `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><project><artifactId>&e;</artifactId></project>`,
		"we\nird/go.mod":                     goMod,
		"link/package-lock.json.txt":         "not a manifest",
		"README.md":                          "hi",
	}, map[string]string{
		"link/go.mod":     "/etc/passwd",
		"link2/go.mod":    "../../other-repo/go.mod",
		"link3/yarn.lock": "../web/package-lock.json",
	})

	require.NoError(t, Scan(t.Context(), repo.ID))

	rows := rowsOf(t, repo.ID)
	require.Len(t, rows, 5, "%v", keys(rows))
	assert.True(t, rows["Go|github.com/gin-gonic/gin@v1.9.1|go.mod"].Direct)
	assert.False(t, rows["Go|golang.org/x/net@v0.10.0|go.mod"].Direct)
	assert.Contains(t, rows, "Go|example.com/vend@v1.0.0|vendored/go.mod")
	left := rows["npm|left-pad@1.3.0|web/package-lock.json"]
	require.NotNil(t, left)
	assert.True(t, left.Direct)
	assert.Equal(t, "WTFPL", left.License)
	assert.Contains(t, rows, "PyPI|django@4.2|req/requirements.txt")

	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Equal(t, sha, scan.CommitSHA)
	assert.Equal(t, repo_model.DependencyScanOK, scan.Status)
	assert.Empty(t, scan.Error)
	assert.Equal(t, 4, scan.ManifestCount, "go.mod, the lock file, vendored/go.mod, requirements.txt")
	assert.Equal(t, 5, scan.DependencyCount)
	assert.ElementsMatch(t, []repo_model.SkippedManifest{
		{Path: "bad/pom.xml", Code: "parse_error"},
		{Path: "weird/go.mod", Code: "invalid_path"},
	}, scan.SkippedManifests(), "the path of the second one is stored without its newline")
	assert.NotZero(t, scan.ScannedUnix)

	// a second scan of the same commit reads nothing
	var parses atomic.Int32
	defer test.MockVariableValue(&parseManifest, func(context.Context, *dependency.Format, []byte, dependency.Finder, int) (*dependency.Result, error) {
		parses.Add(1)
		return nil, nil
	})()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Zero(t, parses.Load())

	// a push that removes the manifests drops their rows
	sha2 := commitFiles(t, repo, map[string]string{"README.md": "hi"}, nil)
	parseManifest = func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		return f.ParseFull(ctx, data, find, maxRows)
	}
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Empty(t, rowsOf(t, repo.ID))
	scan, _ = repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, sha2, scan.CommitSHA)
	assert.Zero(t, scan.ManifestCount)
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestScanCaps(t *testing.T) {
	repo := enable(t)
	files := map[string]string{
		"go.mod":                goMod,
		"a/go.mod":              goMod,
		"web/package-lock.json": lockV3,
	}
	commitFiles(t, repo, files, nil)

	t.Run("manifest size", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.MaxManifestSize, int64(len(lockV3)-1))()
		require.NoError(t, Scan(t.Context(), repo.ID))
		scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
		assert.Equal(t, []repo_model.SkippedManifest{{Path: "web/package-lock.json", Code: "manifest_too_large"}}, scan.SkippedManifests())
		assert.Equal(t, 2, scan.ManifestCount)
		assert.Len(t, rowsOf(t, repo.ID), 4, "the other manifests were read")
	})

	t.Run("too many manifests", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.MaxManifests, 1)()
		require.NoError(t, db.TruncateBeans(t.Context(), &repo_model.DependencyScan{}))
		require.NoError(t, Scan(t.Context(), repo.ID))
		scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
		assert.Equal(t, 1, scan.ManifestCount)
		assert.Len(t, scan.SkippedManifests(), 2)
		for _, s := range scan.SkippedManifests() {
			assert.Equal(t, "too_many_manifests", s.Code)
		}
		assert.Len(t, rowsOf(t, repo.ID), 2)
	})

	t.Run("too many dependencies", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.MaxDependencies, 2)()
		require.NoError(t, db.TruncateBeans(t.Context(), &repo_model.DependencyScan{}))
		require.NoError(t, Scan(t.Context(), repo.ID))
		scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
		assert.Equal(t, 2, scan.DependencyCount, "a manifest that would pass the cap is skipped whole")
		assert.Equal(t, 1, scan.ManifestCount)
		assert.Len(t, scan.SkippedManifests(), 2)
		assert.Equal(t, "too_many_dependencies", scan.SkippedManifests()[0].Code)
		assert.Len(t, rowsOf(t, repo.ID), 2)
	})

	t.Run("tree too large keeps the old rows", func(t *testing.T) {
		require.NoError(t, db.TruncateBeans(t.Context(), &repo_model.DependencyScan{}))
		require.NoError(t, Scan(t.Context(), repo.ID))
		before := len(rowsOf(t, repo.ID))
		require.Positive(t, before)
		old, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)

		many := map[string]string{"go.mod": goMod}
		for i := range 10 {
			many["d/f"+strconv.Itoa(i)] = "x"
		}
		commitFiles(t, repo, many, nil)
		defer test.MockVariableValue(&setting.DependencyGraph.MaxTreeEntries, 5)()
		require.NoError(t, Scan(t.Context(), repo.ID))
		scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
		assert.Equal(t, repo_model.DependencyScanFailed, scan.Status)
		assert.Equal(t, "tree_too_large", scan.Error)
		assert.Equal(t, old.CommitSHA, scan.CommitSHA, "the rows still belong to the old commit")
		assert.Len(t, rowsOf(t, repo.ID), before)
	})
}

func TestScanTimeoutKeepsOldRows(t *testing.T) {
	repo := enable(t)
	sha := commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	require.NoError(t, Scan(t.Context(), repo.ID))
	require.Len(t, rowsOf(t, repo.ID), 2)

	commitFiles(t, repo, map[string]string{"go.mod": "module m\n\nrequire example.com/new v1.0.0\n"}, nil)
	defer test.MockVariableValue(&setting.DependencyGraph.ScanTimeout, 100*time.Millisecond)()
	defer test.MockVariableValue(&parseManifest, func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		<-ctx.Done() // a parser that takes too long
		return f.ParseFull(ctx, data, find, maxRows)
	})()
	require.NoError(t, Scan(t.Context(), repo.ID))

	scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, "timeout", scan.Error)
	assert.Equal(t, repo_model.DependencyScanFailed, scan.Status)
	assert.Equal(t, sha, scan.CommitSHA)
	rows := rowsOf(t, repo.ID)
	assert.Len(t, rows, 2)
	assert.Contains(t, rows, "Go|github.com/gin-gonic/gin@v1.9.1|go.mod")
}

func TestScanSkips(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)

	t.Run("deleted repository", func(t *testing.T) {
		require.NoError(t, Scan(t.Context(), 999999))
		assert.Empty(t, rowsOf(t, 999999))
	})
	t.Run("trashed repository", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = ? WHERE id = ?", timeutil.TimeStampNow(), repo.ID)
		require.NoError(t, err)
		defer func() {
			_, _ = db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", repo.ID)
		}()
		require.NoError(t, Scan(t.Context(), repo.ID))
		assert.Empty(t, rowsOf(t, repo.ID))
	})
	t.Run("disabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
		require.NoError(t, Scan(t.Context(), repo.ID))
		assert.Empty(t, rowsOf(t, repo.ID))
		scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
		assert.Nil(t, scan)
	})
	t.Run("empty and migrating", func(t *testing.T) {
		for _, set := range []string{"is_empty = ?", "status = ?"} {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET "+set+" WHERE id = ?", map[string]any{"is_empty = ?": true, "status = ?": int(repo_model.RepositoryBeingMigrated)}[set], repo.ID)
			require.NoError(t, err)
			require.NoError(t, Scan(t.Context(), repo.ID))
			assert.Empty(t, rowsOf(t, repo.ID))
		}
		require.NoError(t, unittest.PrepareTestDatabase())
	})
}

func TestEnqueueUnscanned(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	ids, err := repo_model.UnscannedDependencyRepoIDs(t.Context(), 0, nil, 1000)
	require.NoError(t, err)
	assert.Contains(t, ids, repo.ID, "never scanned")

	require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), &repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: "old", Status: "ok"}, []*repo_model.Dependency{}))
	ids, _ = repo_model.UnscannedDependencyRepoIDs(t.Context(), 0, nil, 1000)
	assert.Contains(t, ids, repo.ID, "scanned at another commit than the head of the branch table")

	var head string
	_, err = db.GetEngine(t.Context()).SQL("SELECT commit_id FROM branch WHERE repo_id = ? AND name = ?", repo.ID, repo.DefaultBranch).Get(&head)
	require.NoError(t, err)
	require.NotEmpty(t, head)
	require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), &repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: head, Status: "ok"}, []*repo_model.Dependency{}))
	ids, _ = repo_model.UnscannedDependencyRepoIDs(t.Context(), 0, nil, 1000)
	assert.NotContains(t, ids, repo.ID, "up to date")

	// a failed scan of a new head waits for the retry time
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repo_dependency_scan SET commit_sha = 'old', error = 'timeout', scanned_unix = ? WHERE repo_id = ?", timeutil.TimeStampNow(), repo.ID)
	require.NoError(t, err)
	ids, _ = repo_model.UnscannedDependencyRepoIDs(t.Context(), timeutil.TimeStampNow().Add(-3600), nil, 1000)
	assert.NotContains(t, ids, repo.ID)
	ids, _ = repo_model.UnscannedDependencyRepoIDs(t.Context(), timeutil.TimeStampNow().Add(3600), nil, 1000)
	assert.Contains(t, ids, repo.ID)

	// the batch is limited
	ids, _ = repo_model.UnscannedDependencyRepoIDs(t.Context(), timeutil.TimeStampNow().Add(3600), nil, 1)
	assert.Len(t, ids, 1)

	// disabled: the cron task does nothing
	defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
	require.NoError(t, EnqueueUnscanned(t.Context()))
}

// TestQueueDedup: 20 pushes of one repository are one queued item, with the queue not running (nothing is
// timing-dependent), and pushes while a scan runs leave at most one waiting.
func TestQueueDedup(t *testing.T) {
	enable(t)
	cfg, err := setting.NewConfigProviderFromData("[queue.dependency_graph]\nTYPE = channel\nMAX_WORKERS = 1\nBATCH_LENGTH = 1\n")
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.CfgProvider, cfg)()
	release := make(chan struct{})
	var started, handled atomic.Int32
	q := queue.CreateUniqueQueue(t.Context(), "dependency_graph", func(items ...int64) []int64 {
		started.Add(1)
		<-release
		handled.Add(int32(len(items)))
		return nil
	})
	require.NotNil(t, q)
	defer test.MockVariableValue(&scanQueue, q)()

	// checked before the queue runs: once it ran, a worker can still hold a popped item and start it late
	t.Run("disabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
		Enqueue(1)
		assert.Equal(t, 0, q.GetQueueItemNumber())
	})

	for range 20 {
		Enqueue(1)
	}
	assert.Equal(t, 1, q.GetQueueItemNumber(), "twenty pushes of one repository are one item")
	go q.Run()
	require.Eventually(t, func() bool { return started.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	for range 20 {
		Enqueue(1)
	}
	assert.LessOrEqual(t, q.GetQueueItemNumber(), 1, "one scan runs, at most one waits")
	close(release)
	require.Eventually(t, func() bool { return handled.Load() >= 2 && q.GetQueueItemNumber() == 0 }, 5*time.Second, 10*time.Millisecond)
}

// TestNotifier: only the default branch of the repository queues a scan; tags, other branches and the refs of AGit
// and pull requests never do. Mirror syncs and a changed default branch do.
func TestNotifier(t *testing.T) {
	repo := enable(t)
	cfg, err := setting.NewConfigProviderFromData("[queue.dependency_graph]\nTYPE = channel\n")
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.CfgProvider, cfg)()
	q := queue.CreateUniqueQueue(t.Context(), "dependency_graph", func(items ...int64) []int64 { return nil })
	require.NotNil(t, q)
	defer test.MockVariableValue(&scanQueue, q)()
	n := &notifier{}
	queued := func() bool {
		has, err := q.Has(repo.ID)
		require.NoError(t, err)
		if has {
			require.NoError(t, q.RemoveAllItems(t.Context()))
		}
		return has
	}
	push := func(ref string) *repository.PushUpdateOptions {
		return &repository.PushUpdateOptions{RefFullName: git.RefName(ref)}
	}

	for _, ref := range []string{"refs/heads/feature", "refs/tags/master", "refs/for/master", "refs/for/master/topic", "refs/pull/1/head", "refs/heads/master/sub"} {
		n.PushCommits(t.Context(), nil, repo, push(ref), nil)
		n.SyncPushCommits(t.Context(), nil, repo, push(ref), nil)
		assert.False(t, queued(), ref)
	}
	n.PushCommits(t.Context(), nil, repo, push("refs/heads/master"), nil)
	assert.True(t, queued(), "push to the default branch")
	n.SyncPushCommits(t.Context(), nil, repo, push("refs/heads/master"), nil)
	assert.True(t, queued(), "mirror sync of the default branch")
	n.ChangeDefaultBranch(t.Context(), repo)
	assert.True(t, queued(), "a new default branch")

	defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
	n.PushCommits(t.Context(), nil, repo, push("refs/heads/master"), nil)
	n.ChangeDefaultBranch(t.Context(), repo)
	assert.False(t, queued(), "the feature is off")
}

// commitOnTop adds a commit with the files on top of the default branch and returns its SHA.
func commitOnTop(t *testing.T, repo *repo_model.Repository, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	run("clone", "-q", "-b", repo.DefaultBranch, repo.RepoPath(), ".")
	for p, c := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644))
	}
	run("add", "-A")
	run("commit", "-q", "-m", "on top")
	run("push", "-q", repo.RepoPath(), "HEAD:refs/heads/"+repo.DefaultBranch)
	return run("rev-parse", "HEAD")
}

// blockFirstParse makes the first parse wait until release is closed; started is closed when it is waiting.
func blockFirstParse(t *testing.T) (started <-chan struct{}, release func()) {
	t.Helper()
	st, rel := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(test.MockVariableValue(&parseManifest, func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		once.Do(func() {
			close(st)
			<-rel
		})
		return f.ParseFull(ctx, data, find, maxRows)
	}))
	var relOnce sync.Once
	release = func() { relOnce.Do(func() { close(rel) }) }
	t.Cleanup(release)
	return st, release
}

func TestScansOfOneRepositoryAreSerialized(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	started, release := blockFirstParse(t)

	first := make(chan error, 1)
	go func() { first <- Scan(t.Context(), repo.ID) }()
	<-started
	// the branch moves while the first scan reads its commit
	sha2 := commitFiles(t, repo, map[string]string{"go.mod": "module m\n\nrequire example.com/new v1.0.0\n"}, nil)
	second := make(chan error, 1)
	go func() { second <- Scan(t.Context(), repo.ID) }()

	select {
	case <-second:
		t.Fatal("the second scan ran while the first one held the repository")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	require.NoError(t, <-first)
	require.NoError(t, <-second)

	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Equal(t, sha2, scan.CommitSHA)
	rows := rowsOf(t, repo.ID)
	assert.Len(t, rows, 1)
	assert.Contains(t, rows, "Go|example.com/new@v1.0.0|go.mod")
}

func TestScanNeverReplacesNewerRows(t *testing.T) {
	repo := enable(t)
	sha1 := commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	started, release := blockFirstParse(t)

	done := make(chan error, 1)
	go func() { done <- Scan(t.Context(), repo.ID) }()
	<-started

	// another process scans a later commit of the branch and stores it while this scan is still reading
	sha2 := commitOnTop(t, repo, map[string]string{"go.mod": "module m\n\nrequire example.com/newer v1.0.0\n"})
	require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(),
		&repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: sha2, Status: repo_model.DependencyScanOK, ManifestCount: 1, DependencyCount: 1, ScannedUnix: timeutil.TimeStampNow()},
		[]*repo_model.Dependency{{RepoID: repo.ID, Ecosystem: "Go", Name: "example.com/newer", Version: "v1.0.0", ManifestPath: "go.mod", Direct: true}}))
	release()
	require.NoError(t, <-done)

	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Equal(t, sha2, scan.CommitSHA, "the older result (%s) must not replace it", sha1)
	rows := rowsOf(t, repo.ID)
	assert.Len(t, rows, 1)
	assert.Contains(t, rows, "Go|example.com/newer@v1.0.0|go.mod")
}

func TestScanWithoutDefaultBranchIsRecorded(t *testing.T) {
	repo := enable(t)
	_, err := db.GetEngine(t.Context()).ID(repo.ID).Cols("default_branch").Update(&repo_model.Repository{DefaultBranch: ""})
	require.NoError(t, err)
	require.NoError(t, Scan(t.Context(), repo.ID))
	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.NoError(t, err)
	require.NotNil(t, scan, "a row, or the cron offers the repository on every run")
	assert.Equal(t, repo_model.DependencyScanFailed, scan.Status)
}

// A force push back to an older commit must be scanned and stored: only the same commit is skipped.
func TestScanAfterForcePushBackToOlderCommit(t *testing.T) {
	repo := enable(t)
	shaA := commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	require.NoError(t, Scan(t.Context(), repo.ID))
	shaB := commitOnTop(t, repo, map[string]string{"go.mod": "module m\n\nrequire example.com/newer v1.0.0\n"})
	require.NoError(t, Scan(t.Context(), repo.ID))
	scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.Equal(t, shaB, scan.CommitSHA)

	_, _, err := git.NewCommand(t.Context(), "update-ref").AddDynamicArguments("refs/heads/"+repo.DefaultBranch, shaA).RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
	require.NoError(t, err)
	require.NoError(t, Scan(t.Context(), repo.ID))

	scan, _ = repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, shaA, scan.CommitSHA)
	rows := rowsOf(t, repo.ID)
	assert.Len(t, rows, 2)
	assert.Contains(t, rows, "Go|github.com/gin-gonic/gin@v1.9.1|go.mod")
}

// A scan that times out on a row another process replaced meanwhile doesn't overwrite it.
func TestFailedScanKeepsNewerRow(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	defer test.MockVariableValue(&setting.DependencyGraph.ScanTimeout, 300*time.Millisecond)()
	defer test.MockVariableValue(&parseManifest, func(ctx context.Context, _ *dependency.Format, _ []byte, _ dependency.Finder, _ int) (*dependency.Result, error) {
		other := &repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: "other", Status: repo_model.DependencyScanOK, ScannedUnix: timeutil.TimeStampNow()}
		require.NoError(t, repo_model.ReplaceRepoDependencies(context.Background(), other, []*repo_model.Dependency{}))
		<-ctx.Done()
		return nil, ctx.Err()
	})()
	require.NoError(t, Scan(t.Context(), repo.ID))
	scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, "other", scan.CommitSHA)
	assert.Equal(t, repo_model.DependencyScanOK, scan.Status)
	assert.Empty(t, scan.Error)
}

// Only the stored rows reaching the cap end the scan: a manifest with more rows than are left is skipped on its
// own, and once the cap is reached the manifest that finds no room and every later one are skipped unread.
func TestScanStopsAtDependencyCap(t *testing.T) {
	repo := enable(t)
	defer test.MockVariableValue(&setting.DependencyGraph.MaxDependencies, 3)()
	commitFiles(t, repo, map[string]string{
		"a/go.mod": "module a\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n",
		"b/go.mod": "module b\n\nrequire (\n\texample.com/c v1.0.0\n\texample.com/d v1.0.0\n)\n",
		"c/go.mod": "module c\n\nrequire example.com/e v1.0.0\n",
		"d/go.mod": "module d\n\nrequire example.com/f v1.0.0\n",
		"e/go.mod": "module e\n\nrequire example.com/g v1.0.0\n",
	}, nil)
	var parses atomic.Int32
	orig := parseManifest
	defer test.MockVariableValue(&parseManifest, func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		parses.Add(1)
		return orig(ctx, f, data, find, maxRows)
	})()
	require.NoError(t, Scan(t.Context(), repo.ID))
	scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, 2, scan.ManifestCount)
	assert.Equal(t, 3, scan.DependencyCount)
	assert.ElementsMatch(t, []repo_model.SkippedManifest{
		{Path: "b/go.mod", Code: "too_many_dependencies"},
		{Path: "d/go.mod", Code: "too_many_dependencies"},
		{Path: "e/go.mod", Code: "too_many_dependencies"},
	}, scan.SkippedManifests())
	assert.EqualValues(t, 4, parses.Load(), "the manifest after the one that found no room is not parsed")
}

// 400 directories with the same 1 MiB package.json keep one copy of it, not 400.
func TestHelperCacheKeepsOneCopyPerBlob(t *testing.T) {
	repo := enable(t)
	pkg := `{"dependencies":{"left-pad":"^1.3.0"},"x":"` + strings.Repeat("a", 1<<20-200) + `"}`
	files := map[string]string{}
	for i := range 400 {
		d := "d" + strconv.Itoa(i)
		files[d+"/package-lock.json"] = lockV3
		files[d+"/package.json"] = pkg
	}
	commitFiles(t, repo, files, nil)
	defer test.MockVariableValue(&setting.DependencyGraph.MaxManifests, 1000)()
	defer test.MockVariableValue(&setting.DependencyGraph.MaxDependencies, 100000)()

	var reads atomic.Int32
	orig := parseManifest
	defer test.MockVariableValue(&parseManifest, func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		if b := find("package.json", false); b != nil {
			reads.Add(1)
		}
		return orig(ctx, f, data, find, maxRows)
	})()
	defer debug.SetGCPercent(debug.SetGCPercent(20))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	require.NoError(t, Scan(t.Context(), repo.ID))
	close(stop)
	assert.EqualValues(t, 400, reads.Load())
	assert.Less(t, int64(peak.Load())-int64(base.HeapInuse), int64(48<<20), "400 copies would be 400 MiB")
	assert.Len(t, rowsOf(t, repo.ID), 400)
}

// A manifest that is over the entry budget is given up on its own: the manifests after it are still read, and only
// the scan-wide row cap ends the scan.
func TestScanEntryBudgetSkipsOnlyThatManifest(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{
		"a/go.mod": "module a\n\nrequire example.com/huge v1.0.0\n",
		"b/go.mod": "module b\n\nrequire example.com/small v1.0.0\n",
	}, nil)
	orig := parseManifest
	defer test.MockVariableValue(&parseManifest, func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		if strings.Contains(string(data), "huge") {
			return nil, dependency.ErrTooManyEntries
		}
		return orig(ctx, f, data, find, maxRows)
	})()
	require.NoError(t, Scan(t.Context(), repo.ID))
	scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, repo_model.DependencyScanOK, scan.Status)
	assert.Equal(t, []repo_model.SkippedManifest{{Path: "a/go.mod", Code: "too_many_entries"}}, scan.SkippedManifests())
	rows := rowsOf(t, repo.ID)
	assert.Len(t, rows, 1)
	assert.Contains(t, rows, "Go|example.com/small@v1.0.0|b/go.mod")
}

// The write that loses to another process asks for a new scan when what that process stored isn't the head.
func TestLostWriteRequeuesWhenHeadMoved(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	started, release := blockFirstParse(t)
	done := make(chan struct {
		requeue bool
		err     error
	}, 1)
	go func() {
		r, err := scan(t.Context(), repo.ID, new(bool))
		done <- struct {
			requeue bool
			err     error
		}{r, err}
	}()
	<-started
	// another process stores an older result; the head this scan read is a different commit
	require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), &repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: "other", Status: repo_model.DependencyScanOK, ScannedUnix: timeutil.TimeStampNow()}, []*repo_model.Dependency{}))
	release()
	res := <-done
	require.NoError(t, res.err)
	assert.True(t, res.requeue)
	scan, _ := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	assert.Equal(t, "other", scan.CommitSHA)
}

// When the head can't be read after the write, the scan asks for another one rather than leave a moved branch to
// the cron.
func TestScanRequeuesWhenHeadUnreadable(t *testing.T) {
	repo := enable(t)
	commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
	orig := parseManifest
	defer test.MockVariableValue(&parseManifest, func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		out, err := exec.Command("git", "-C", repo.RepoPath(), "update-ref", "-d", "refs/heads/"+repo.DefaultBranch).CombinedOutput()
		require.NoError(t, err, string(out))
		return orig(ctx, f, data, find, maxRows)
	})()
	requeue, err := scan(t.Context(), repo.ID, new(bool))
	require.NoError(t, err)
	assert.True(t, requeue)
	assert.Len(t, rowsOf(t, repo.ID), 2, "the scan of the commit read at the start is stored")
}

// keyHeavyPackageJSON is the package.json of the security review: about 1 MiB of 100 000 short keys, ten times what
// a helper may contribute. n makes one key differ, so each n gives another blob.
func keyHeavyPackageJSON(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"dependencies":{"pkg-1":"^1.0.0","n` + strconv.Itoa(n) + `":""`)
	for i := range 100000 {
		fmt.Fprintf(&sb, `,"%05x":""`, i)
	}
	sb.WriteString(`}}`)
	return sb.String()
}

// Lock files that share one package.json: it is read and parsed once. A key-heavy one (over the helper key
// limit) counts as absent, so its packages are not direct, and neither 400 lock files sharing it nor 100 that each
// have their own cost more than a few seconds: the scan parses a bounded number of helper bytes.
func TestScanParsesSharedHelperOnce(t *testing.T) {
	repo := enable(t)
	defer test.MockVariableValue(&setting.DependencyGraph.MaxManifests, 1000)()
	var sb strings.Builder
	sb.WriteString(`{"dependencies":{`)
	for i := range 5000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`"pkg-` + strconv.Itoa(i) + `":"^1.0.0"`)
	}
	sb.WriteString(`}}`)
	const lock = "# yarn lockfile v1\n\npkg-1@^1.0.0:\n  version \"1.0.0\"\n"
	for _, tc := range []struct {
		name   string
		dirs   int
		pkg    func(i int) string
		direct bool
	}{
		{"shared", 400, func(int) string { return sb.String() }, true},
		{"shared key-heavy", 400, func(int) string { return keyHeavyPackageJSON(0) }, false},
		{"distinct key-heavy", 100, keyHeavyPackageJSON, false}, // 100 MiB of helpers, 8 MiB may be parsed
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			for i := range tc.dirs {
				files["d"+strconv.Itoa(i)+"/package.json"] = tc.pkg(i)
				files["d"+strconv.Itoa(i)+"/yarn.lock"] = lock
			}
			commitFiles(t, repo, files, nil)
			start := time.Now()
			require.NoError(t, Scan(t.Context(), repo.ID))
			took := time.Since(start)
			t.Logf("scan: %v", took)
			assert.Less(t, took, 5*time.Second)
			rows := rowsOf(t, repo.ID)
			assert.Len(t, rows, tc.dirs)
			for _, r := range rows {
				assert.Equal(t, tc.direct, r.Direct)
			}
		})
	}
}

// A manifest without a lock file is read for its direct dependencies and their ranges. Only a lock file the scan
// read, with rows, covers a manifest: the one next to it, and for npm and Cargo the root and the workspace members
// the lock names. Anything else is read on its own, never left out silently.
func TestScanFallbackManifests(t *testing.T) {
	repo := enable(t)
	rootLock := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"^1.3.0"}},"packages/a":{"name":"a"},` +
		`"node_modules/left-pad":{"version":"1.3.0"},"node_modules/express":{"version":"4.18.0"}}}`
	cargoLock := "version = 3\n\n[[package]]\nname = \"member\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"rand\"\nversion = \"0.8.5\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
	commitFiles(t, repo, map[string]string{
		// a monorepo: the root lock covers the root and its workspace member, not another project below it
		"package-lock.json":              rootLock,
		"package.json":                   `{"dependencies":{"left-pad":"^1.3.0"}}`,
		"packages/a/package.json":        `{"dependencies":{"express":"^4.18.0"}}`,
		"docs/package.json":              `{"devDependencies":{"lodash":"~4.17.20"}}`,
		"crates/x/Cargo.toml":            "[dependencies]\nserde = \"1\"\n",
		"rust/Cargo.lock":                cargoLock,
		"rust/Cargo.toml":                "[workspace]\nmembers = [\"member\", \"tools/*\"]\nexclude = [\"tools/app\"]\n",
		"rust/tools/app/Cargo.toml":      "[package]\nname = \"member\"\n[dependencies]\nevil = \"1\"\n",
		"rust/member/Cargo.toml":         "[package]\nname = \"member\"\n[dependencies]\nrand = \"0.8\"\n",
		"rust/fuzz/Cargo.toml":           "[package]\nname = \"member\"\n[workspace]\n[dependencies]\nlibfuzzer-sys = \"0.4\"\n",
		"bad/Cargo.lock":                 "not a lock file", // no rows
		"bad/Cargo.toml":                 "[dependencies]\nanyhow = \"1\"\n",
		"bad/package-lock.json":          "{",
		"bad/package.json":               `{"dependencies":{"chalk":"^5"}}`,
		"ruby/Gemfile":                   "gem \"rails\", \"~> 7.1\"\ngem(\"odd\")\n",
		"ruby/sub/Gemfile.lock":          "GEM\n  specs:\n",
		"empty/Gemfile":                  "gem \"rack\"\n",
		"empty/Gemfile.lock":             "",
		"py/pyproject.toml":              "[project]\ndependencies = [\"requests>=2\"]\n",
		"py-uv/pyproject.toml":           "[project]\ndependencies = [\"httpx\"]\n",
		"py-uv/uv.lock":                  "version = 1\n",
		"php/composer.json":              `{"require":{"monolog/monolog":"^3"}}`,
		"vendor/lib/package.json":        `{"dependencies":{"vendored":"1"}}`,
		"node_modules/package-lock.json": lockV3, // excluded: covers nothing
	}, nil)
	require.NoError(t, Scan(t.Context(), repo.ID))
	rows := rowsOf(t, repo.ID)
	assert.ElementsMatch(t, []string{
		"npm|left-pad@1.3.0|package-lock.json",
		"npm|express@4.18.0|package-lock.json",
		"npm|lodash@|docs/package.json",                 // no workspace member of the root lock
		"crates.io|serde@|crates/x/Cargo.toml",          // no lock above
		"crates.io|rand@0.8.5|rust/Cargo.lock",          // the member is covered
		"crates.io|libfuzzer-sys@|rust/fuzz/Cargo.toml", // a workspace of its own
		"crates.io|evil@|rust/tools/app/Cargo.toml",     // excluded from the workspace, though a member has its name
		"crates.io|anyhow@|bad/Cargo.toml",              // the lock next to it has no rows
		"npm|chalk@|bad/package.json",                   // the lock next to it can't be read
		"RubyGems|rails@|ruby/Gemfile",
		"RubyGems|rack@|empty/Gemfile", // an empty lock covers nothing
		"PyPI|requests@|py/pyproject.toml",
		"PyPI|httpx@|py-uv/pyproject.toml", // uv.lock has no reader
		"Packagist|monolog/monolog@|php/composer.json",
	}, keys(rows))
	assert.Equal(t, "1", rows["crates.io|serde@|crates/x/Cargo.toml"].Requirement)
	assert.Equal(t, "~> 7.1", rows["RubyGems|rails@|ruby/Gemfile"].Requirement)
	assert.Equal(t, ">=2", rows["PyPI|requests@|py/pyproject.toml"].Requirement)
	assert.True(t, rows["Packagist|monolog/monolog@|php/composer.json"].Direct)
	assert.Empty(t, rows["npm|left-pad@1.3.0|package-lock.json"].Requirement)
	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.NoError(t, err)
	// the unread lock stays in the list, and so does a Gemfile read in part
	assert.Equal(t, []repo_model.SkippedManifest{
		{Path: "bad/package-lock.json", Code: repo_model.DependencySkipParse},
		{Path: "ruby/Gemfile", Code: repo_model.DependencySkipPartial, Lines: 1},
	}, scan.SkippedManifests())

	// without the root lock, every package.json is read
	commitFiles(t, repo, map[string]string{
		"package.json":            `{"dependencies":{"left-pad":"^1.3.0"}}`,
		"packages/a/package.json": `{"dependencies":{"express":"^4.18.0"}}`,
	}, nil)
	require.NoError(t, Scan(t.Context(), repo.ID))
	rows = rowsOf(t, repo.ID)
	assert.ElementsMatch(t, []string{"npm|left-pad@|package.json", "npm|express@|packages/a/package.json"}, keys(rows))
	assert.Equal(t, "^4.18.0", rows["npm|express@|packages/a/package.json"].Requirement)
}

// Lock files are read before the manifests without one, so those never push a lock file out of MaxManifests or the
// list of skipped manifests (security re-review 4, L6).
func TestScanLockFilesFirst(t *testing.T) {
	repo := enable(t)
	defer test.MockVariableValue(&setting.DependencyGraph.MaxManifests, 3)()
	files := map[string]string{"z/package-lock.json": lockV3}
	for i := range 120 {
		files[fmt.Sprintf("a%03d/package.json", i)] = `{"dependencies":{"x":"1"}}`
	}
	commitFiles(t, repo, files, nil)
	require.NoError(t, Scan(t.Context(), repo.ID))
	rows := rowsOf(t, repo.ID)
	assert.Contains(t, rows, "npm|left-pad@1.3.0|z/package-lock.json")
	assert.Len(t, rows, 3) // the lock and two package.json files
	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repo.ID)
	require.NoError(t, err)
	skipped := scan.SkippedManifests()
	require.Len(t, skipped, 100)
	assert.Equal(t, "a002/package.json", skipped[0].Path)
}

// A refresh that fails or asks for a requeue after a scan queues a rematch, and with an immediate queue (the handler
// runs inside Push) one scan slot is enough: the scan has released its lock and slot by then.
func TestFailedRefreshRequeuesWithoutDeadlock(t *testing.T) {
	for name, result := range map[string]struct {
		stats vulnerability_model.ApplyStats
		err   error
	}{
		"failed":   {err: errors.New("refresh failed")},
		"requeue":  {stats: vulnerability_model.ApplyStats{Requeue: true}},
		"all done": {},
	} {
		t.Run(name, func(t *testing.T) {
			repo := enable(t)
			commitFiles(t, repo, map[string]string{"go.mod": goMod}, nil)
			defer test.MockVariableValue(&setting.DependencyGraph.MaxConcurrentScans, 1)()
			defer test.MockVariableValue(&refreshAlerts, func(context.Context, int64, func(context.Context) (bool, error)) (vulnerability_model.ApplyStats, error) {
				return result.stats, result.err
			})()
			var rematched atomic.Int32
			defer test.MockVariableValue(&RematchAlerts, func(id int64) {
				// what Rematch does, run synchronously as an immediate queue does
				unlock := LockRepoScan(id)
				defer unlock()
				release, err := AcquireSlot(t.Context())
				if err == nil {
					release()
					rematched.Add(1)
				}
			})()
			done := make(chan error, 1)
			go func() { done <- Scan(t.Context(), repo.ID) }()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(15 * time.Second):
				t.Fatal("the scan waits for a slot it holds itself")
			}
			if name == "all done" {
				assert.Zero(t, rematched.Load())
			} else {
				assert.EqualValues(t, 1, rematched.Load())
			}
		})
	}
}

func TestAcquireSlotLiveLimit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	setLimit := func(n int) {
		require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().DependencyGraphConfig.DynKey(): fmt.Sprintf(`{"limits":{"max_concurrent_scans":%d}}`, n)}))
		bumpRevision(t)
	}
	t.Cleanup(func() {
		require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().DependencyGraphConfig.DynKey(): ""}))
		bumpRevision(t)
	})
	setLimit(2)
	a, err := AcquireSlot(t.Context())
	require.NoError(t, err)
	b, err := AcquireSlot(t.Context())
	require.NoError(t, err)

	// the limit is lowered: the two running scans keep their slots, a third waits
	setLimit(1)
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	_, err = AcquireSlot(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	a()
	a() // a second call gives nothing back
	ctx2, cancel2 := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel2()
	_, err = AcquireSlot(ctx2)
	require.ErrorIs(t, err, context.DeadlineExceeded, "one runs, the limit is one")

	// a raised limit admits a waiting scan without a release
	got := make(chan func(), 1)
	go func() {
		release, err := AcquireSlot(t.Context())
		if err == nil {
			got <- release
		}
	}()
	time.Sleep(100 * time.Millisecond)
	setLimit(3)
	select {
	case release := <-got:
		release()
	case <-time.After(5 * time.Second):
		t.Fatal("the raised limit was not seen")
	}
	b()
	scanSlots.Lock()
	assert.Zero(t, scanSlots.running)
	scanSlots.Unlock()
}
