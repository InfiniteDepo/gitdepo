// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	repo_model "forgejo.org/models/repo"
	vulnerability_model "forgejo.org/models/vulnerability"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/process"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
)

var (
	errTreeTooLarge = errors.New("tree too large")

	// helperCacheBudget is the total size of the helper files (package.json, ...) one scan keeps in memory, with
	// what is parsed from them
	helperCacheBudget int64 = 8 << 20

	// helperParseBudget is the total size of the helper files one scan parses (a file kept in the cache is parsed
	// once); past it, a helper counts as absent (see dependency.HelperCache)
	helperParseBudget int64 = 8 << 20

	// excludedSegments are directory names whose content is never scanned (vendored or generated copies)
	excludedSegments = map[string]bool{"vendor": true, "node_modules": true, "testdata": true}

	// auxNames are the files a parser may ask for next to a manifest (see dependency.Finder)
	auxNames = map[string]bool{"package.json": true, "composer.json": true, "pyproject.toml": true, "Cargo.toml": true, "Directory.Packages.props": true, "pom.xml": true}

	// parseManifest parses one manifest; tests replace it
	parseManifest = func(ctx context.Context, f *dependency.Format, data []byte, find dependency.Finder, maxRows int) (*dependency.Result, error) {
		return f.ParseFull(ctx, data, find, maxRows)
	}
)

type treeEntry struct {
	path string
	id   string
	size int64
}

// walkTree runs `git ls-tree -r -z --long` on the commit and calls fn for every regular file (symlinks, submodules
// and trees are left out), counting entries so a huge tree ends the walk with errTreeTooLarge.
func walkTree(ctx context.Context, gitRepo *git.Repository, sha string, limit int, fn func(treeEntry)) error {
	w := &lsTreeWriter{limit: limit, fn: fn}
	cmd := git.NewCommand(ctx, "ls-tree", "-r", "-z", "--long").AddDynamicArguments(sha)
	err := cmd.Run(&git.RunOpts{Dir: gitRepo.Path, Stdout: w, Stderr: io.Discard, UseContextTimeout: true})
	if errors.Is(w.err, errTreeTooLarge) {
		return errTreeTooLarge
	}
	if err != nil {
		return err
	}
	return w.err
}

// lsTreeWriter parses the NUL-terminated records `<mode> <type> <id> <size>\t<path>` as git writes them; a record
// is never held longer than a path can be.
type lsTreeWriter struct {
	limit int
	n     int
	buf   []byte
	fn    func(treeEntry)
	err   error
}

func (w *lsTreeWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, 0)
		if i < 0 {
			break
		}
		rec := w.buf[:i]
		w.buf = w.buf[i+1:]
		if w.n++; w.n > w.limit {
			w.err = errTreeTooLarge
			return 0, w.err
		}
		w.record(rec)
	}
	if len(w.buf) > 64<<10 {
		w.err = errTreeTooLarge // a path longer than any filesystem allows
		return 0, w.err
	}
	return len(p), nil
}

func (w *lsTreeWriter) record(rec []byte) {
	meta, name, ok := bytes.Cut(rec, []byte{'\t'})
	f := strings.Fields(string(meta))
	if !ok || len(f) != 4 || f[0] == "120000" || f[1] != "blob" {
		return // a symlink, a submodule or something odd
	}
	size, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil {
		return
	}
	w.fn(treeEntry{path: string(name), id: f[2], size: size})
}

func hasExcludedSegment(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if excludedSegments[seg] {
			return true
		}
	}
	return false
}

// AcquireSlot waits for one of the slots (the scans at once in force) that scans and alert rematches share in this
// process; release gives it back. The limit is read at every attempt: a lower one lets the running scans finish, a
// higher one admits a waiting scan within a second.
func AcquireSlot(ctx context.Context) (release func(), err error) {
	for {
		limit := setting.DependencyGraphSettings(ctx).MaxConcurrentScans // outside the lock: it may query the database
		scanSlots.Lock()
		if scanSlots.running < max(limit, 1) {
			scanSlots.running++
			scanSlots.Unlock()
			var once sync.Once
			return func() { once.Do(releaseSlot) }, nil
		}
		if scanSlots.freed == nil {
			scanSlots.freed = make(chan struct{})
		}
		freed := scanSlots.freed
		scanSlots.Unlock()
		timer := time.NewTimer(time.Second)
		select {
		case <-freed:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
		timer.Stop()
	}
}

func releaseSlot() {
	scanSlots.Lock()
	defer scanSlots.Unlock()
	scanSlots.running--
	if scanSlots.freed != nil {
		close(scanSlots.freed)
		scanSlots.freed = nil
	}
}

// refreshAlerts is the alert refresh after a scan (tests replace it).
var refreshAlerts = vulnerability_model.RefreshAlerts

// RematchAlerts queues a repository for a rematch of its vulnerability alerts; services/vulnerability sets it.
var RematchAlerts = func(repoID int64) {}

// Scan reads the manifests of the repository's default branch, at the head as it is when the scan starts, and
// replaces the stored dependencies. A scan that fails keeps the old dependencies and records an error code.
func Scan(ctx context.Context, repoID int64) error {
	var rematch bool
	requeue, err := scan(ctx, repoID, &rematch)
	// after the scan's lock and slot are released: with immediate queues these run at once, and a rematch waits for both
	if rematch {
		RematchAlerts(repoID)
	}
	if requeue {
		Enqueue(repoID)
	}
	return err
}

// scan is Scan; requeue is true when the branch moved while it ran, and *rematch is set when the alerts must be
// matched again (the refresh failed or was overtaken by newer advisory data).
func scan(ctx context.Context, repoID int64, rematch *bool) (requeue bool, err error) {
	if !SiteEnabled(ctx) {
		return false, nil
	}
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if repo_model.IsErrRepoNotExist(err) {
		return false, nil // deleted or trashed since it was queued
	}
	if err != nil {
		return false, err
	}
	if !Enabled(ctx, repo) {
		return false, nil
	}
	if repo.IsEmpty || repo.Status != repo_model.RepositoryReady {
		return false, nil
	}
	// one scan of a repository at a time, and at most MAX_CONCURRENT_SCANS of all, counted only while one runs
	unlock := LockRepoScan(repo.ID)
	defer unlock()
	release, err := AcquireSlot(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	old, err := repo_model.GetRepoDependencyScan(ctx, repo.ID)
	if err != nil {
		return false, err
	}
	if repo.DefaultBranch == "" {
		// store the outcome, or the cron would offer this repository again on every run
		return false, fail(ctx, repo, old, repo_model.DependencyErrGit, errors.New("no default branch"))
	}

	cfg := setting.DependencyGraphSettings(ctx)
	scanCtx, cancel, finished := process.GetManager().AddContextTimeout(ctx, cfg.ScanTimeout, fmt.Sprintf("dependency scan of repository %d", repo.ID))
	defer finished()
	defer cancel()

	gitRepo, err := gitrepo.OpenRepository(scanCtx, repo)
	if err != nil {
		return false, fail(ctx, repo, old, repo_model.DependencyErrGit, err)
	}
	defer gitRepo.Close()
	sha, err := gitRepo.GetBranchCommitID(repo.DefaultBranch)
	if err != nil {
		return false, fail(ctx, repo, old, repo_model.DependencyErrGit, err)
	}
	if old != nil && old.CommitSHA == sha && old.Error == "" {
		return false, nil // nothing changed, e.g. a mirror sync of other branches
	}

	result, deps, code, err := scanCommit(scanCtx, &cfg, repo, gitRepo, sha)
	if err != nil {
		return false, fail(ctx, repo, old, code, err)
	}
	// The stored rows belong to sha; the database write is not bound to the scan's time budget. It happens only if
	// the row is still the one read at the start, so a scan another process finished meanwhile is kept (the head
	// read at the start is the one to store, even if it is an older commit than the stored one after a force push).
	if !stillEnabled(ctx, repo.ID) {
		return false, nil // turned off while the scan ran
	}
	written, err := repo_model.ReplaceRepoDependenciesIf(ctx, result, deps, old, stillOn(repo.ID))
	if err != nil {
		return false, err
	}
	if written {
		// the alerts follow the rows, under the same check of the switches; if this fails, the rows are right and the
		// repository is queued for a rematch
		st, err := refreshAlerts(ctx, repo.ID, stillOn(repo.ID))
		if err != nil {
			log.Error("vulnerability alerts: refresh repository %d: %v", repo.ID, err)
		}
		*rematch = err != nil || st.Requeue
	}
	// turned off between the check and the write: the switch's purge may have run before the write, so delete here
	if !stillEnabled(ctx, repo.ID) {
		return false, DeleteRepoRows(ctx, repo.ID)
	}
	// the head now, read with the outer context (the scan's time budget may be spent); if it can't be read, the
	// next scan decides (the unique queue makes a needless one cheap)
	head, headErr := headCommit(ctx, repo)
	if headErr != nil {
		return true, nil
	}
	if !written {
		// another process stored its result first: if that isn't the head, the next scan is still due
		cur, err := repo_model.GetRepoDependencyScan(ctx, repo.ID)
		return err == nil && (cur == nil || cur.CommitSHA != head), nil
	}
	// the branch moved while the scan ran: the next scan is the one that ends on the head
	return head != sha, nil
}

// stillEnabled reads the switches again with the repository as it is stored now.
func stillEnabled(ctx context.Context, repoID int64) bool {
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	return err == nil && Enabled(ctx, repo)
}

// stillOn is the check of the switches inside the transaction that stores a scan (see enabledStored).
func stillOn(repoID int64) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) { return enabledStored(ctx, repoID) }
}

// StillOn is the check of the switches inside a transaction that writes something that depends on them (see
// enabledStored).
func StillOn(repoID int64) func(context.Context) (bool, error) { return stillOn(repoID) }

// headCommit reads the commit the default branch points at now.
func headCommit(ctx context.Context, repo *repo_model.Repository) (string, error) {
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return "", err
	}
	defer gitRepo.Close()
	return gitRepo.GetBranchCommitID(repo.DefaultBranch)
}

// fail records the error code of a scan and keeps the old rows (and the commit they belong to); it does not
// overwrite a row another process wrote meanwhile.
func fail(ctx context.Context, repo *repo_model.Repository, old *repo_model.DependencyScan, code string, cause error) error {
	if ctx.Err() != nil {
		return ctx.Err() // shutting down: not a failure of the repository
	}
	if !stillEnabled(ctx, repo.ID) {
		return nil // turned off while the scan ran: nothing is stored
	}
	log.Warn("dependency graph: scan of repository %d failed (%s): %v", repo.ID, code, cause)
	s := &repo_model.DependencyScan{RepoID: repo.ID, ScannedUnix: timeutil.TimeStampNow(), Status: repo_model.DependencyScanFailed, Error: code}
	if old != nil {
		s.CommitSHA = old.CommitSHA // the condition of the write; the stored commit and counts stay
	}
	_, err := repo_model.ReplaceRepoDependenciesIf(ctx, s, nil, old, stillOn(repo.ID))
	return err
}

func scanCommit(ctx context.Context, cfg *setting.DependencyGraphOptions, repo *repo_model.Repository, gitRepo *git.Repository, sha string) (*repo_model.DependencyScan, []*repo_model.Dependency, string, error) {
	var manifests, unpinned []treeEntry
	aux := map[string]treeEntry{}
	err := walkTree(ctx, gitRepo, sha, cfg.MaxTreeEntries, func(e treeEntry) {
		if hasExcludedSegment(e.path) {
			return
		}
		if auxNames[path.Base(e.path)] {
			aux[e.path] = e
		}
		if f := dependency.FormatForPath(e.path); f != nil && f.Unpinned {
			unpinned = append(unpinned, e)
		} else if f != nil {
			manifests = append(manifests, e)
		}
	})
	// the manifests without a lock file come last: they are read only when no lock file read before covers them, and
	// they never push a lock file out of MaxManifests or the list of skipped manifests
	manifests = append(manifests, unpinned...)
	switch {
	case errors.Is(err, errTreeTooLarge):
		return nil, nil, repo_model.DependencyErrTreeTooLarge, err
	case ctx.Err() != nil:
		return nil, nil, repo_model.DependencyErrTimeout, ctx.Err()
	case err != nil:
		return nil, nil, repo_model.DependencyErrGit, err
	}

	readBlob := func(e treeEntry, limit int64) ([]byte, error) {
		if e.size > limit {
			return nil, io.ErrShortBuffer
		}
		blob, err := gitRepo.GetBlob(e.id)
		if err != nil {
			return nil, err
		}
		r, _, err := blob.NewReader(limit)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(io.LimitReader(r, limit+1))
	}
	// helper files by blob ID: the same blob is kept once however many directories hold it, and what doesn't fit
	// the budget is read again on each use
	cache := map[string][]byte{}
	helpers := dependency.NewHelperCache(helperCacheBudget, helperParseBudget) // the files above and what is parsed from them
	ctx = dependency.WithHelperCache(ctx, helpers)
	find := func(manifestPath string) dependency.Finder {
		return func(name string, up bool) []byte {
			for dir := path.Dir(manifestPath); ; dir = path.Dir(dir) {
				p := path.Join(dir, name)
				if e, ok := aux[p]; ok {
					if b, seen := cache[e.id]; seen {
						return b
					}
					if !helpers.CanParse(e.size) {
						return nil // the scan's helper budget is spent: the helper counts as absent
					}
					b, err := readBlob(e, dependency.MaxSmallManifestSize)
					if err != nil {
						b = nil
					}
					if helpers.Keep(b) {
						cache[e.id] = b
					}
					return b
				}
				if !up || dir == "." {
					return nil
				}
			}
		}
	}

	scan := &repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: sha, ScannedUnix: timeutil.TimeStampNow(), Status: repo_model.DependencyScanOK}
	deps := []*repo_model.Dependency{}
	var skipped []repo_model.SkippedManifest
	skip := func(p, code string) {
		skipped = appendSkipped(skipped, repo_model.SkippedManifest{Path: p, Code: code})
	}
	locks := map[string]*dependency.Info{} // the lock files read, with rows: what they cover (see Format.Covered)
	read := 0                              // the manifests counted against MaxManifests
	for i, m := range manifests {
		if ctx.Err() != nil {
			return nil, nil, repo_model.DependencyErrTimeout, ctx.Err()
		}
		format := dependency.FormatForPath(m.path)
		if format.Unpinned && format.Covered(m.path, locks, nil) {
			continue
		}
		if read++; read > cfg.MaxManifests {
			skip(m.path, repo_model.DependencySkipTooMany)
			continue
		}
		if !dependency.ValidPath(m.path) {
			skip(m.path, repo_model.DependencySkipInvalidPath)
			continue
		}
		limit := cfg.MaxManifestSize
		if format.Small {
			limit = min(limit, dependency.MaxSmallManifestSize)
		}
		if m.size > limit {
			skip(m.path, repo_model.DependencySkipTooLarge)
			continue
		}
		data, err := readBlob(m, limit)
		if err != nil {
			skip(m.path, repo_model.DependencySkipRead)
			continue
		}
		res, err := parseManifest(ctx, format, data, find(m.path), cfg.MaxDependencies-len(deps))
		if ctx.Err() != nil {
			return nil, nil, repo_model.DependencyErrTimeout, ctx.Err()
		}
		if errors.Is(err, dependency.ErrTooManyEntries) {
			skip(m.path, repo_model.DependencySkipTooManyEntries) // this file only: the next one is read
			continue
		}
		if errors.Is(err, dependency.ErrTooManyDependencies) {
			skip(m.path, repo_model.DependencySkipTooManyDeps)
			if len(deps) < cfg.MaxDependencies {
				continue // this file alone has more rows than are left: the next one may fit
			}
			// the stored rows reached the cap: every later manifest stays unread
			for _, rest := range manifests[i+1:] {
				if f := dependency.FormatForPath(rest.path); !f.Unpinned || !f.Covered(rest.path, locks, nil) {
					skip(rest.path, repo_model.DependencySkipTooManyDeps)
				}
			}
			break
		}
		if err != nil {
			skip(m.path, repo_model.DependencySkipParse)
			continue
		}
		if res == nil {
			res = &dependency.Result{}
		}
		if format.Unpinned && format.Covered(m.path, locks, &res.Info) {
			continue // a workspace member, which the root's Cargo.lock covers
		}
		if dependency.IsLockName(path.Base(m.path)) && len(res.Deps) > 0 {
			locks[m.path] = &res.Info // an empty lock covers nothing: its manifests are read on their own
		}
		if res.Info.Unread > 0 {
			skipped = appendSkipped(skipped, repo_model.SkippedManifest{Path: m.path, Code: repo_model.DependencySkipPartial, Lines: res.Info.Unread})
		}
		scan.ManifestCount++
		for _, d := range res.Deps {
			deps = append(deps, &repo_model.Dependency{
				RepoID: repo.ID, Ecosystem: d.Ecosystem, Name: d.Name, Version: d.Version, Requirement: d.Requirement,
				ManifestPath: m.path, Direct: d.Direct, License: d.License,
			})
		}
	}
	scan.DependencyCount = len(deps)
	scan.SetSkippedManifests(skipped)
	return scan, deps, "", nil
}

// appendSkipped adds a manifest to the list of skipped ones, which keeps the first 100.
func appendSkipped(skipped []repo_model.SkippedManifest, m repo_model.SkippedManifest) []repo_model.SkippedManifest {
	if len(skipped) >= 100 {
		return skipped
	}
	m.Path = dependency.SafeText(m.Path)
	if len(m.Path) > dependency.MaxPathLen {
		m.Path = strings.ToValidUTF8(m.Path[:dependency.MaxPathLen], "") // cut on a rune boundary
	}
	return append(skipped, m)
}
