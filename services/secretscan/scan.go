// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/process"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	sync_module "forgejo.org/modules/sync"
	"forgejo.org/modules/timeutil"
)

// Codes stored in secret_scan.error: the failures, and the limits that end a slice of a scan or leave a hole. Never
// text from git.
const (
	errGit        = "git_error"
	errPanic      = "scan_panic"
	errTooManyRef = "too_many_refs"
	errStore      = "store_failed"

	stopTimeout  = "timeout"
	stopBlobs    = "max_scan_blobs"
	stopBytes    = "max_scan_bytes"
	stopCommits  = "max_scan_commits"
	stopFindings = "too_many_findings"
	stopAlerts   = "max_alerts"     // a hole: secrets left out for the cap
	stopPartial  = "partly_scanned" // a hole: a file the detector could not scan whole
	stopHole     = "over_limit"     // a hole: a commit that alone is over the limits
)

const (
	maxTips         = 100_000   // refs (distinct tips) of a repository a scan reads; the tips are stored as one text
	maxFindingBlobs = 100_000   // files with findings one slice keeps in memory
	maxSliceCommits = 200_000   // commits one slice handles (commits without files cost no budget otherwise)
	maxSeen         = 1_000_000 // blob IDs one slice remembers as read; more are read again
	maxLocBytes     = 32 << 20  // path text one slice keeps for the places of its findings; more places are counted
	alertBatch      = 200       // alerts looked up and written together

	// A scan that fails is tried again (by the next trigger, the cron task) only after retryBase, doubling per
	// failure in a row up to retryMax. While a scan is under way the row's retry time is retryBase ahead, so the
	// cron task picks it up if the queue lost it.
	retryBase = 10 * time.Minute
	retryMax  = 24 * time.Hour
)

var (
	errDisabled   = errors.New("secret scanning is off")
	errOwnerMoved = errors.New("the repository changed owner while it was scanned")
	errAborted    = errors.New("scan aborted")
	errStopped    = errors.New("stopped")
	errStoreFail  = errors.New(errStore)

	// repoScans holds the repositories being scanned in this process: the unique queue forgets an ID once it is
	// popped, so a push during a scan queues the repository again, and the second scan must wait for the first.
	repoScans sync_module.MutexMap

	// scanContent runs the detector and says whether it scanned all of the content (false: cut at the detector's size
	// limit, or a rule ran out of its budget). It computes the keyed fingerprints, so it panics before the keying is
	// set up. A test replaces it.
	scanContent = func(d *secretdetection.Detector, content []byte) ([]secretdetection.Finding, bool) {
		return d.Scan(content)
	}

	// afterTips runs when the tips of a scan are read, before any object is (tests hold a scan here)
	afterTips = func(repoID int64, kind string) {}
)

// acquireSlot waits for one of the slots (MAX_CONCURRENT_SCANS scans at once in this process); release gives it
// back. The limit is read at every attempt: a lower one lets the running scans finish, a higher one admits a
// waiting scan within a second.
func acquireSlot(ctx context.Context) (release func(), err error) {
	for {
		limit := setting.SecretScanningSettings(ctx).MaxConcurrentScans // outside the lock: it may query the database
		scanSlots.Lock()
		if int64(scanSlots.running) < max(limit, 1) {
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

// Scan reads the commits of the repository (its refs other than refs/pull/*, its wiki, and then refs/pull/*) that the
// stored scan states don't cover and stores the alerts and the new states. One call is one slice: at most
// MAX_SCAN_BYTES and MAX_SCAN_BLOBS of files within SCAN_TIMEOUT. A repository with more is continued by the next
// slice, queued behind the other repositories. A scan that fails backs off; one that is overtaken is queued again.
func Scan(ctx context.Context, repoID int64) error {
	requeue, err := scan(ctx, repoID)
	// after the scan's lock and slot are released: with immediate queues this runs at once
	if requeue {
		Enqueue(repoID)
	}
	return err
}

func scan(ctx context.Context, repoID int64) (requeue bool, err error) {
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
	if !Enabled(ctx, repo) || repo.Status != repo_model.RepositoryReady {
		return false, nil
	}
	// one scan of a repository at a time, and at most MAX_CONCURRENT_SCANS of all, counted only while one runs
	unlock := repoScans.Lock(strconv.FormatInt(repo.ID, 10))
	defer unlock()
	// read once per scan (a disable or a delete counts from the next scan on), and before the slot: loading and
	// checking them is not scan work
	custom, err := customRules(ctx, repo)
	if err != nil {
		return false, err
	}
	release, err := acquireSlot(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	cfg := setting.SecretScanningSettings(ctx)
	rules := []secretdetection.Rule{}
	for _, r := range secretdetection.BuiltinRules() {
		if !r.DefaultOff || cfg.GenericRules {
			rules = append(rules, r)
		}
	}
	detector, err := secretdetection.NewDetector(append(rules, custom...))
	if err != nil {
		return false, err
	}
	detector.MaxContentSize = int(cfg.MaxBlobSize)

	scanCtx, cancel, finished := process.GetManager().AddContextTimeout(ctx, cfg.ScanTimeout, fmt.Sprintf("secret scan of repository %d", repo.ID))
	defer finished()
	defer cancel()

	s := &scanner{ctx: ctx, scanCtx: scanCtx, repo: repo, cfg: cfg, detector: detector}
	forgetStuck(ctx, repo.ID)
	mark := readMark(ctx, repo.ID) // before any ref is read: a push after this keeps its own mark for the next scan
	kinds := []string{secretscan_model.KindRepo}
	if repo.HasWiki() {
		kinds = append(kinds, secretscan_model.KindWiki)
	}
	states := map[string]kindState{}
	for _, kind := range append(kinds, secretscan_model.KindPull) { // what a reader can write comes last
		rq, kerr := s.scanKind(kind)
		requeue = requeue || rq
		err = errors.Join(err, kerr)
		if kind != secretscan_model.KindPull && !rq && kerr == nil { // the digest never waits for the pull refs
			states[kind] = readKindState(ctx, repo.ID, kind)
		}
	}
	if !requeue && ctx.Err() == nil {
		// the text there is already is read after the code, a slice at a time; it doesn't depend on the code's tips, so
		// a code scan that failed (and backs off) doesn't hold it up
		rq, terr := s.scanText()
		requeue = requeue || rq
		err = errors.Join(err, terr)
	}
	finishDigest(ctx, repo, mark, states) // waits for the kinds the push touched, never for the pull refs
	if mark == nil && states[secretscan_model.KindRepo].current {
		// nothing is owed for the alerts up to now: a later push's digest starts after them
		if err := secretscan_model.AdvanceNotifyFloor(ctx, repo.ID); err != nil {
			log.Error("secret scanning: advance the digest floor of repository %d: %v", repo.ID, err)
		}
	}
	return requeue, err
}

// scanner is the state of one slice of a scan of a repository, for each of its git repositories in turn.
type scanner struct {
	ctx, scanCtx context.Context
	repo         *repo_model.Repository
	cfg          setting.SecretScanningOptions
	detector     *secretdetection.Detector
	// the files read in this slice, over all kinds: the limits are for the slice
	blobs, bytes int64
	entries      int64 // entries git was asked about
	progress     bool  // a kind handled a commit
	full         bool  // a kind stopped at a limit: the rest waits for the next slice
}

// blobFinding is a finding with its fingerprint: the secret itself is gone.
type blobFinding struct {
	ruleID, fingerprint string
	start, end          int
}

// place is a file path of a blob, in the commit that brought it first in this slice.
type place struct {
	path, hash string
	commit     *commitInfo
}

// foundBlob is a file with findings and the places git says it is at.
type foundBlob struct {
	findings []blobFinding
	places   []place // the oldest first, at most MAX_LOCATIONS_PER_ALERT
	extra    int     // places over the cap, counted
}

// candidate is an alert to store: a secret and the places it was found at in this scan.
type candidate struct {
	ruleID, fingerprint string
	locs                map[string]*secretscan_model.Location // by path hash and line
	extra               int
	poster              int64 // of a secret in text: who wrote the first place found (0: nobody known)
}

// run is the scan of one git repository (the repository, its wiki or its pull refs) in one slice.
type run struct {
	*scanner
	kind    string
	gitRepo *git.Repository
	old     *secretscan_model.Scan // the row as stored last, nil when there is none
	done    []string               // commits whose history is scanned, as stored
	keyCap  int64                  // distinct secrets of built-in rules; custom patterns have half as many of their own (customCap)
	// the totals of the scan under way (over its slices), as stored in the row
	totBlobs, totBytes, totSkipped int64
	// what this slice has seen
	cur                  *commitInfo
	handled              []*commitInfo // complete commits, parents first
	stop                 string        // the limit that ended the slice
	hole                 bool          // the first commit of the slice is over the limits: its files are counted
	holes, partial, left int64         // files not scanned, files scanned in part, secrets left out for the key cap
	found                map[string]*foundBlob
	seen                 map[string]struct{} // blobs read (or too large)
	keys                 map[string]struct{} // distinct (rule, fingerprint)
	customKeys           int64               // of keys, those of custom patterns
	locBytes             int
	exclude              []string // commits the log leaves out besides done: the branches' tips, for the pull refs
	buf                  []byte
}

// abort is an error that ends the slice quietly: the scan was overtaken or switched off.
type abort struct{ requeue bool }

func (*abort) Error() string { return "scan aborted" }

func (s *scanner) scanKind(kind string) (requeue bool, err error) {
	if s.full {
		return false, nil // a kind before stopped at a limit and queues the next slice
	}
	if s.scanCtx.Err() != nil {
		return s.progress, nil // the slice's time is up: this one is next (not a failure of its git repository)
	}
	old, err := secretscan_model.GetScan(s.ctx, s.repo.ID, kind)
	if err != nil {
		return false, err
	}
	r := &run{scanner: s, kind: kind, old: old, keyCap: s.cfg.MaxAlertsPerRepo, found: map[string]*foundBlob{}, seen: map[string]struct{}{}, keys: map[string]struct{}{}}
	if kind == secretscan_model.KindPull {
		r.keyCap = max(r.keyCap/2, 1) // as many secrets as the alert share of the pull refs
	}
	open := gitrepo.OpenRepository
	if kind == secretscan_model.KindWiki {
		open = gitrepo.OpenWikiRepository
	}
	if r.gitRepo, err = open(s.scanCtx, s.repo); err != nil {
		return r.fail(secretscan_model.StatusFailed, errGit)
	}
	defer r.gitRepo.Close()

	tips, err := refTips(s.scanCtx, r.gitRepo.Path, kind == secretscan_model.KindPull)
	if err != nil {
		return r.gitFailed()
	}
	if len(tips) > maxTips {
		return r.fail(secretscan_model.StatusFailed, errTooManyRef)
	}
	var stored []string
	if old != nil {
		_ = json.Unmarshal([]byte(old.ScannedTips), &stored) // a state that can't be read scans everything again
		if old.FailCount > 0 && timeutil.TimeStampNow() < old.RetryUnix {
			return false, nil // a failure waits out its backoff
		}
		if old.RetryUnix == 0 && len(missing(tips, stored)) == 0 {
			if kind == secretscan_model.KindRepo && old.Requeue > 0 { // the scan took the row and has nothing to write
				return false, secretscan_model.ClearRequeue(s.ctx, s.repo.ID, old.Requeue)
			}
			return false, nil // nothing new; the status stays as it is
		}
		if old.RetryUnix > 0 { // a scan under way or after a failure: its totals go on
			r.totBlobs, r.totBytes = old.Blobs, old.Bytes
		}
		r.totSkipped = old.SkippedLarge // a file that was never read stays counted until a rescan from the beginning
	}
	afterTips(s.repo.ID, kind)
	if r.done, err = existingTips(s.scanCtx, r.gitRepo, stored); err != nil {
		return r.gitFailed()
	}
	if kind == secretscan_model.KindPull { // what the branches have scanned is theirs: the pull scan reads only the rest
		if b, _ := secretscan_model.GetScan(s.ctx, s.repo.ID, secretscan_model.KindRepo); b != nil {
			var bt []string
			_ = json.Unmarshal([]byte(b.ScannedTips), &bt)
			if r.exclude, err = existingTips(s.scanCtx, r.gitRepo, bt); err != nil {
				return r.gitFailed()
			}
		}
	}
	pending := missing(tips, r.done)
	complete := true
	if len(pending) > 0 {
		if complete, err = r.walk(pending); err != nil {
			if errors.Is(err, errAborted) && s.ctx.Err() == nil {
				return r.fail(secretscan_model.StatusFailed, errPanic)
			}
			return r.gitFailed()
		}
	}
	return r.finish(tips, complete)
}

// gitFailed fails a scan whose git call failed: a timeout of the slice is a timeout, a shut down is no failure.
func (r *run) gitFailed() (requeue bool, err error) {
	switch {
	case r.ctx.Err() != nil:
		return false, r.ctx.Err()
	case r.scanCtx.Err() != nil:
		return r.fail(secretscan_model.StatusIncomplete, stopTimeout)
	}
	return r.fail(secretscan_model.StatusFailed, errGit)
}

// missing are the tips that are not in done.
func missing(tips, done []string) []string {
	have := make(map[string]struct{}, len(done))
	for _, id := range done {
		have[id] = struct{}{}
	}
	return slices.DeleteFunc(slices.Clone(tips), func(id string) bool { _, ok := have[id]; return ok })
}

// heads are the commits that no other commit of the list has as a parent: they stand for all of them.
func heads(commits []*commitInfo) []string {
	isParent := map[string]struct{}{}
	for _, c := range commits {
		for _, p := range c.Parents {
			isParent[p] = struct{}{}
		}
	}
	var out []string
	for _, c := range commits {
		if _, ok := isParent[c.ID]; !ok {
			out = append(out, c.ID)
		}
	}
	slices.Sort(out)
	return out
}

// walk reads the commits of the range in one pass, oldest first: the commits handled so far are closed under
// ancestors, so their heads can stand as done tips. A limit ends it at a commit boundary (complete is false). The
// first commit of the slice is never cut off: what fits is scanned, the rest is counted as holes, and it is handled.
func (r *run) walk(pending []string) (complete bool, err error) {
	err = r.gitRepo.WithCatFileBatchCheck(r.scanCtx, func(cw io.Writer, cr *bufio.Reader) error {
		return r.gitRepo.WithCatFileBatch(r.scanCtx, func(bw io.Writer, br *bufio.Reader) error {
			return logCommits(r.scanCtx, r.gitRepo.Path, rangeInput(pending, slices.Concat(r.done, r.exclude)), r.startCommit,
				func(c change) error { return r.file(cw, cr, bw, br, c) })
		})
	})
	switch {
	case r.scanCtx.Err() != nil && r.ctx.Err() == nil:
		r.stop = stopTimeout // the commit that was read when the time ran out is not handled...
		if o := r.old; r.cur != nil && len(r.handled) == 0 && !r.progress && o != nil && o.FailCount > 0 && o.Error == stopTimeout {
			r.handled = append(r.handled, r.cur) // ...unless it ran out in a try before too: what was read stands, the rest is a hole
			r.holes++
			r.stop = stopHole
		}
		return false, nil
	case err == nil:
		if r.cur != nil {
			r.handled = append(r.handled, r.cur)
		}
		return true, nil
	case errors.Is(err, errStopped):
		return false, nil
	}
	return false, err
}

// startCommit is called when the log starts a commit, which completes the one before.
func (r *run) startCommit(c commitInfo) error {
	if r.cur != nil {
		r.handled = append(r.handled, r.cur)
	}
	switch {
	case r.stop != "":
		return errStopped
	case len(r.handled) >= maxSliceCommits:
		r.stop = stopCommits
		return errStopped
	case len(r.found) >= maxFindingBlobs:
		r.stop = stopFindings
		return errStopped
	}
	r.cur = &c
	return nil
}

// limit records that a limit ended the slice. In the first commit of the slice, it only counts what is left.
func (r *run) limit(code string) error {
	r.stop = code
	if len(r.handled) == 0 && !r.progress {
		r.hole = true
		r.holes++
		return nil
	}
	return errStopped
}

// file reads and scans the blob a commit brought, unless the slice has seen it, and remembers its place.
func (r *run) file(cw io.Writer, cr *bufio.Reader, bw io.Writer, br *bufio.Reader, c change) error {
	if r.hole {
		r.holes++
		return nil
	}
	if fb := r.found[c.NewID]; fb != nil {
		r.addPlace(fb, c.Path)
		return nil
	}
	if _, ok := r.seen[c.NewID]; ok {
		return nil
	}
	if r.entries++; r.entries > r.cfg.MaxScanBlobs { // every entry git is asked about counts, not only the files read
		return r.limit(stopBlobs)
	}
	if _, err := io.WriteString(cw, c.NewID+"\n"); err != nil {
		return err
	}
	_, typ, size, err := git.ReadBatchLine(cr)
	if git.IsErrNotExist(err) {
		return nil // a submodule's commit
	}
	if err != nil {
		return err
	}
	if typ != "blob" {
		return nil
	}
	if len(r.seen) < maxSeen {
		r.seen[c.NewID] = struct{}{}
	}
	if size > r.cfg.MaxBlobSize {
		r.totSkipped++
		return nil // never read
	}
	if r.bytes+size > r.cfg.MaxScanBytes {
		return r.limit(stopBytes)
	}
	if _, err := io.WriteString(bw, c.NewID+"\n"); err != nil {
		return err
	}
	if _, typ, size, err = git.ReadBatchLine(br); err != nil {
		return err
	}
	if cap(r.buf) < int(size) {
		r.buf = make([]byte, size)
	}
	buf := r.buf[:size]
	if _, err := io.ReadFull(br, buf); err != nil {
		return err
	}
	if _, err := br.Discard(1); err != nil { // the newline after the content
		return err
	}
	r.blobs++
	r.bytes += size
	r.totBlobs++
	r.totBytes += size
	if typ != "blob" {
		return nil
	}
	return r.scanBlob(c, buf)
}

// addPlace keeps a path of the blob (up to MAX_LOCATIONS_PER_ALERT, and a text budget per slice), else counts it.
func (r *run) addPlace(fb *foundBlob, path string) {
	if int64(len(fb.places)) >= r.cfg.MaxLocationsPerAlert || r.locBytes > maxLocBytes {
		fb.extra++
		return
	}
	r.locBytes += len(path) + 128
	fb.places = append(fb.places, place{path: path, hash: secretscan_model.PathHash(path), commit: r.cur})
}

// scanBlob runs the detector over one blob. A panic is recovered and fails the scan: skipping the blob would leave
// a hole in what the stored state calls scanned.
func (r *run) scanBlob(c change, content []byte) (err error) {
	defer func() {
		if p := recover(); p != nil {
			log.Error("secret scanning: panic (%T) scanning blob %s of repository %d", p, c.NewID, r.repo.ID)
			err = errAborted
		}
	}()
	findings, complete := scanContent(r.detector, content)
	if !complete {
		r.partial++
	}
	fb := &foundBlob{}
	for _, f := range findings {
		key := f.RuleID + "|" + f.Fingerprint
		if _, seen := r.keys[key]; !seen {
			// custom patterns count apart, so they can't push a built-in rule's secrets out
			_, custom := secretscan_model.ParseCustomRuleID(f.RuleID)
			if !custom && int64(len(r.keys))-r.customKeys >= r.keyCap || custom && r.customKeys >= customCap(r.keyCap) {
				r.left++ // more distinct secrets than alerts are kept: this one is left out (a hole)
				continue
			}
			r.keys[key] = struct{}{}
			if custom {
				r.customKeys++
			}
		}
		fb.findings = append(fb.findings, blobFinding{ruleID: f.RuleID, fingerprint: f.Fingerprint, start: f.StartLine, end: f.EndLine})
	}
	if len(fb.findings) > 0 {
		r.found[c.NewID] = fb
		r.addPlace(fb, c.Path)
	}
	return nil
}

// candidates turns the findings of the blobs into alerts with their places (at most MAX_LOCATIONS_PER_ALERT each).
func (r *run) candidates() []*candidate {
	byKey := map[string]*candidate{}
	for _, id := range slices.Sorted(maps.Keys(r.found)) {
		if r.ctx.Err() != nil {
			break
		}
		fb := r.found[id]
		counted := map[*candidate]bool{}
		for _, f := range fb.findings {
			c := byKey[f.ruleID+"|"+f.fingerprint]
			if c == nil {
				c = &candidate{ruleID: f.ruleID, fingerprint: f.fingerprint, locs: map[string]*secretscan_model.Location{}}
				byKey[f.ruleID+"|"+f.fingerprint] = c
			}
			if !counted[c] {
				counted[c] = true
				c.extra += fb.extra
			}
			if int64(len(c.locs)) >= r.cfg.MaxLocationsPerAlert {
				c.extra += len(fb.places)
				continue
			}
			for _, p := range fb.places {
				key := p.hash + ":" + strconv.Itoa(f.start)
				switch {
				case c.locs[key] != nil: // the first place seen is the oldest
				case int64(len(c.locs)) >= r.cfg.MaxLocationsPerAlert:
					c.extra++
				default:
					c.locs[key] = secretscan_model.NewLocation(r.repo.ID, r.kind, id, p.path, f.start, f.end, p.commit.ID, p.commit.AuthorName, p.commit.AuthorEmail, p.commit.Unix)
				}
			}
		}
	}
	return slices.SortedFunc(maps.Values(byKey), func(a, b *candidate) int {
		return cmp.Or(cmp.Compare(a.ruleID, b.ruleID), cmp.Compare(a.fingerprint, b.fingerprint))
	})
}

// finish stores what the slice did in one transaction: the alerts and the row, with the new done tips (the ref tips
// when the whole range was read, else the heads of the commits handled and the done tips before). They move only here,
// after the commit.
func (r *run) finish(tips []string, complete bool) (requeue bool, err error) {
	if !complete && len(r.handled) == 0 {
		if r.progress { // a kind before used the slice
			r.full = true
			return true, nil
		}
		return r.fail(secretscan_model.StatusIncomplete, r.stop) // not even the first commit: the time ran out
	}
	done := tips
	if !complete {
		done = slices.Compact(slices.Sorted(slices.Values(slices.Concat(heads(r.handled), r.done)))) // every head: dropping one would read its history again
	}
	tipsJSON, _ := json.Marshal(done) // a list of strings
	st := &secretscan_model.Scan{
		RepoID: r.repo.ID, Kind: r.kind, ScannedTips: string(tipsJSON), Status: secretscan_model.StatusOK,
		Blobs: r.totBlobs, Bytes: r.totBytes, SkippedLarge: r.totSkipped,
	}
	reason := ""
	switch {
	case r.left > 0:
		reason = stopAlerts
	case r.holes > 0:
		reason = stopHole
	case r.partial > 0:
		reason = stopPartial
	}
	if o := r.old; o != nil { // holes stay until a scan finds none: a scan with nothing new doesn't clear them
		st.Holes = o.Holes
		if reason == "" && o.Holes > 0 && slices.Contains([]string{stopAlerts, stopPartial, stopHole}, o.Error) {
			reason = o.Error
		}
	}
	st.Holes += r.holes + r.partial + r.left
	switch {
	case !complete:
		st.Status, st.Error = secretscan_model.StatusIncomplete, cmp.Or(reason, r.stop) // a hole is the better answer
		st.RetryUnix = timeutil.TimeStampNow().Add(int64(retryBase / time.Second))      // under way: a safety net for the cron task
	case st.Holes > 0:
		st.Status, st.Error = secretscan_model.StatusIncomplete, cmp.Or(reason, stopPartial)
	}
	if err := r.write(st, r.candidates()); err != nil {
		if ab, ok := errors.AsType[*abort](err); ok {
			return ab.requeue, nil
		}
		return false, err
	}
	r.done = done
	r.progress = r.progress || len(r.handled) > 0
	r.full = !complete
	return !complete, nil
}

// fail stores a slice that handled nothing: the earlier row with the backoff, never new tips.
func (r *run) fail(status, code string) (requeue bool, err error) {
	log.Warn("secret scanning: scan of repository %d (%s) failed: %s", r.repo.ID, r.kind, code)
	st := &secretscan_model.Scan{RepoID: r.repo.ID, Kind: r.kind, ScannedTips: "[]", Status: status, Error: code, FailCount: 1}
	if o := r.old; o != nil {
		st.ScannedTips, st.Blobs, st.Bytes, st.SkippedLarge, st.Holes, st.FailCount = o.ScannedTips, o.Blobs, o.Bytes, o.SkippedLarge, o.Holes, o.FailCount+1
	}
	st.RetryUnix = timeutil.TimeStampNow().Add(int64(min(retryBase<<min(st.FailCount-1, 12), retryMax) / time.Second))
	if err := r.write(st, nil); err != nil {
		if ab, ok := errors.AsType[*abort](err); ok {
			return ab.requeue, nil
		}
		return false, err
	}
	return false, nil
}

// write stores the alerts and the state row in one transaction, after the last check of the switches. It is discarded
// when scanning was turned off, and the slice is dropped (queued again) when the owner changed or another process wrote
// the state first. Secrets left out for the alert cap are added to the row's holes.
func (r *run) write(st *secretscan_model.Scan, cands []*candidate) error {
	cfg := setting.SecretScanningSettings(r.ctx) // before the transaction: it may query the database
	err := db.WithTx(r.ctx, func(ctx context.Context) error {
		enabled, owner, err := enabledStored(ctx, r.repo.ID)
		if err != nil {
			return err
		}
		if !enabled {
			return errDisabled
		}
		if owner != r.repo.OwnerID {
			return errOwnerMoved
		}
		left, err := writeAlerts(ctx, cfg, r.repo.ID, r.kind, r.kind == secretscan_model.KindPull, cands, nil)
		if err != nil {
			return err
		}
		if left > 0 {
			st.Holes += left
			if st.RetryUnix == 0 { // the scan is complete: it is incomplete with a hole
				st.Status, st.Error = secretscan_model.StatusIncomplete, stopAlerts
			}
		}
		if err := secretscan_model.Save(ctx, r.old, st); err != nil {
			return err
		}
		// the scan takes the requeue mark with the state it writes: a slice that failed or was cut short by a kill
		// leaves the mark, so the repository is queued again
		if r.kind == secretscan_model.KindRepo && st.FailCount == 0 && r.old != nil && r.old.Requeue > 0 {
			return secretscan_model.ClearRequeue(ctx, r.repo.ID, r.old.Requeue)
		}
		return nil
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errDisabled):
		return &abort{}
	case errors.Is(err, errOwnerMoved), errors.Is(err, secretscan_model.ErrScanMoved):
		return &abort{requeue: true}
	}
	// a write that lost a race on a unique key looks like any error: if the state row moved, the scan is overtaken
	if cur, rerr := secretscan_model.GetScan(r.ctx, r.repo.ID, r.kind); rerr == nil && ((cur == nil) != (r.old == nil) || cur != nil && r.old != nil && cur.Version != r.old.Version) {
		return &abort{requeue: true}
	}
	log.Error("secret scanning: store the scan of repository %d (%s): %v", r.repo.ID, r.kind, err)
	if st.Error != errStore { // say so in the row too, with the backoff, so the cron task tries again later
		_, _ = r.fail(secretscan_model.StatusFailed, errStore)
	}
	return errStoreFail
}

// customCap is the share of an alert cap that custom patterns have on top of the built-in rules' cap.
func customCap(limit int64) int64 { return max(limit/2, 1) }

// writeAlerts stores the alerts and their places, relying on the unique keys: an alert or a place that is already
// there is not stored again. It reads and writes in batches (a few queries per batch of alerts, none per place).
// Places over MAX_LOCATIONS_PER_ALERT are only counted. A new alert is left out (counted in left, a hole) when the repository has
// MAX_ALERTS_PER_REPO open alerts of built-in rules, or, for a secret only refs/pull/* reach (which any reader can write),
// when half of that many open alerts are of that kind: the branches and tags always have room. Custom patterns have
// half as many of their own on top (customCap), so they never take a built-in rule's room, and their pull-only alerts
// a quarter of that share.
// byPoster, for text (nil for code), counts the open alerts of each poster (CountOpenTextAlertsByPoster): one poster
// opens at most a quarter of the pull refs' share, so a reader posting tokens can't take all of it.
func writeAlerts(ctx context.Context, cfg setting.SecretScanningOptions, repoID int64, kind string, viaPull bool, cands []*candidate, byPoster map[int64]int64) (left int64, err error) {
	if len(cands) == 0 {
		return 0, nil
	}
	n, err := secretscan_model.CountOpenAlertsByCap(ctx, repoID)
	if err != nil {
		return 0, err
	}
	// counts and caps of the built-in rules, and of the custom patterns
	counts := func(custom bool) (total, pulls *int64, limit, pullLimit int64) {
		if custom {
			c := customCap(cfg.MaxAlertsPerRepo)
			return &n.Custom, &n.CustomViaPull, c, max(c/4, 1)
		}
		return &n.Total, &n.ViaPull, cfg.MaxAlertsPerRepo, max(cfg.MaxAlertsPerRepo/2, 1)
	}
	posterCap := max(max(cfg.MaxAlertsPerRepo/2, 1)/4, 1)
	for batch := range slices.Chunk(cands, alertBatch) {
		fingerprints := make([]string, len(batch))
		for i, c := range batch {
			fingerprints[i] = c.fingerprint
		}
		existing, err := secretscan_model.GetAlertsByFingerprints(ctx, repoID, fingerprints)
		if err != nil {
			return 0, err
		}
		byKey := map[string]*secretscan_model.Alert{}
		for _, a := range existing {
			byKey[a.RuleID+"|"+a.Fingerprint] = a
		}
		var alerts []*secretscan_model.Alert // by candidate; nil for one that was left out
		var ids, reached []int64
		for _, c := range batch {
			a := byKey[c.ruleID+"|"+c.fingerprint]
			switch {
			case a == nil:
				rule, _ := secretdetection.RuleByID(c.ruleID)
				_, custom := secretscan_model.ParseCustomRuleID(c.ruleID)
				total, pulls, limit, pullLimit := counts(custom)
				byThem := byPoster != nil && c.poster != 0
				if *total >= limit || viaPull && *pulls >= pullLimit || byThem && byPoster[c.poster] >= posterCap {
					left++
					break
				}
				if byThem {
					byPoster[c.poster]++
				}
				if custom {
					rule.Type = "custom"
				}
				a = &secretscan_model.Alert{RepoID: repoID, RuleID: c.ruleID, SecretType: rule.Type, Fingerprint: c.fingerprint, ViaPull: viaPull}
				if err := secretscan_model.InsertAlert(ctx, a); err != nil {
					return 0, err
				}
				*total++
				if viaPull {
					*pulls++
				}
			case a.ViaPull && !viaPull:
				reached = append(reached, a.ID) // a branch or tag reaches it too
				if a.State == secretscan_model.StateOpen {
					_, pulls, _, _ := counts(a.SecretType == "custom")
					*pulls--
				}
			}
			alerts = append(alerts, a)
			if a != nil {
				ids = append(ids, a.ID)
			}
		}
		if err := secretscan_model.ClearViaPull(ctx, reached); err != nil {
			return 0, err
		}
		places, err := secretscan_model.StoredPlaces(ctx, ids)
		if err != nil {
			return 0, err
		}
		var rows []*secretscan_model.Location
		for i, c := range batch {
			a := alerts[i]
			if a == nil {
				continue
			}
			stored, seen := int64(len(places[a.ID])), c.extra
			for _, key := range slices.Sorted(maps.Keys(c.locs)) {
				loc := c.locs[key]
				if places[a.ID][secretscan_model.PlaceKey{Kind: kind, PathHash: loc.PathHash, StartLine: loc.StartLine}] {
					continue
				}
				seen++
				if stored >= cfg.MaxLocationsPerAlert {
					continue
				}
				loc.AlertID = a.ID
				rows = append(rows, loc)
				stored++
			}
			if seen > 0 {
				if err := secretscan_model.AddLocationCount(ctx, a.ID, seen); err != nil {
					return 0, err
				}
			}
		}
		if err := secretscan_model.InsertLocations(ctx, rows); err != nil {
			return 0, err
		}
	}
	return left, nil
}
