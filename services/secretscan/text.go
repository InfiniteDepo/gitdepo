// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/mailer"

	"xorm.io/builder"
)

// The text of issues, pull requests and comments is scanned from a second unique queue of items: "i:<issue ID>" (title
// and body), "c:<comment ID>" and "x:<kind>:<repository ID>:<ID>" (the text is gone). The notifier only queues; the
// handler reads the text as it is then, so a burst of edits is one scan and a deleted text is skipped. The text that
// is there already is read by the scan of the repository (scanText), after its code. A secret found in text is an
// alert like any other, with a place of kind issue or comment (never the text, only the number, field and line);
// an alert that only text reaches shares the alert cap of the pull refs (ViaPull), since anyone who can read the
// repository can write text.
var (
	textQueue     *queue.WorkerPoolQueue[string]
	pushTextQueue = func(item string) error { return textQueue.Push(item) }
)

const (
	maxTextSliceBytes = 32 << 20 // bytes of text one slice reads
	textBatch         = 100      // issues or comments loaded together

	stopText = "max_text" // the slice read what it may; the rest follows
)

// maxTextItems is the issues and comments one slice of the backfill reads (a variable for the tests).
var maxTextItems = 2000

// A text item whose scan failed (a store error, a lost connection) is queued again after a backoff, at most
// maxTextRetries times; one whose repository is being scanned (repoScans held by a code slice, which can take
// SCAN_TIMEOUT) is queued again after textBusyDelay without waiting in a worker, and after maxTextBusy such tries it
// waits for the lock.
const (
	maxTextRetries = 5
	maxTextBusy    = 20
)

// textRetryDelay is the backoff of a failed item's try n (from 1), textBusyDelay that of a busy repository's.
var (
	textRetryDelay = func(n int) time.Duration { return time.Second << n }
	textBusyDelay  = func(n int) time.Duration { return min(5*time.Second<<min(n-1, 3), 30*time.Second) }
)

// pushTextLater queues an item again after the delay (the queue's own re-push of an unhandled item has none). An
// item waiting in the timer when the process stops or crashes is lost without a log line (known limit): the next
// edit of its text or a Rescan reads it again.
var pushTextLater = func(item string, delay time.Duration) {
	time.AfterFunc(delay, func() {
		if err := pushTextQueue(item); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
			log.Error("secret scanning: queue text %q again: %v", item, err)
		}
	})
}

// errTextBusy is a text item that found its repository locked.
var errTextBusy = errors.New("the repository is being scanned")

// textCommentTypes are the comment types that carry text a person wrote (a dismissed review's message too).
var textCommentTypes = []issues_model.CommentType{issues_model.CommentTypeComment, issues_model.CommentTypeCode, issues_model.CommentTypeReview, issues_model.CommentTypeDismissReview}

// dataURI is the payload of a data: URI, which would only feed the entropy rules and the cost; the rest of the line
// stays. The payload is the base64 alphabet only, so a token glued to its end (after a "_" or "-") is still scanned.
var dataURI = regexp.MustCompile(`(?i)(data:[a-z0-9.+/-]{0,64};base64,)[a-z0-9+/=]{1000,}`)

func stripDataURIs(s string) string {
	if !strings.Contains(s, "base64,") {
		return s
	}
	return dataURI.ReplaceAllString(s, "$1")
}

func enqueueText(ctx context.Context, item string) {
	if textQueue == nil || !SiteEnabled(ctx) {
		return
	}
	if err := pushTextQueue(item); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
		log.Error("secret scanning: queue text %q: %v", item, err)
	}
}

// enqueueIssueText queues an issue's title and body; doer made the change.
func enqueueIssueText(ctx context.Context, issueID, doerID int64) {
	enqueueText(ctx, fmt.Sprintf("i:%d:%d", issueID, max(doerID, 0)))
}

func enqueueCommentText(ctx context.Context, c *issues_model.Comment, doerID int64) {
	if c != nil && slices.Contains(textCommentTypes, c.Type) {
		enqueueText(ctx, fmt.Sprintf("c:%d:%d", c.ID, max(doerID, 0)))
	}
}

func enqueueTextGone(ctx context.Context, kind string, repoID, id int64) {
	enqueueText(ctx, fmt.Sprintf("x:%s:%d:%d", kind, repoID, id))
}

// textHandler runs the items; a failed or busy one is queued again later with its tries counted (nextTextItem).
func textHandler(items ...string) (unhandled []string) {
	ctx := graceful.GetManager().ShutdownContext()
	for _, item := range items {
		err := handleText(ctx, item)
		switch {
		case err == nil:
		case ctx.Err() != nil:
			unhandled = append(unhandled, item)
		default:
			busy := errors.Is(err, errTextBusy)
			if !busy {
				log.Error("secret scanning: scan of text %q: %v", item, err)
			}
			if next, delay, ok := nextTextItem(item, busy); ok {
				pushTextLater(next, delay)
			}
		}
	}
	return unhandled
}

// textTries reads the tries an item has had: "<item>#<failed>.<busy>".
func textTries(item string) (base string, failed, busy int) {
	base, tries, _ := strings.Cut(item, "#")
	f, b, _ := strings.Cut(tries, ".")
	failed, _ = strconv.Atoi(f)
	busy, _ = strconv.Atoi(b)
	// clamped, so that a bad item can't make a negative or huge shift in the delays
	return base, min(max(failed, 0), maxTextRetries), min(max(busy, 0), maxTextBusy)
}

// nextTextItem is the item to queue again after a failure (or a busy repository) with the delay, or false once it
// failed maxTextRetries times.
func nextTextItem(item string, busy bool) (string, time.Duration, bool) {
	base, failed, b := textTries(item)
	var delay time.Duration
	if busy {
		b = min(b+1, maxTextBusy)
		delay = textBusyDelay(b)
	} else {
		if failed >= maxTextRetries {
			return "", 0, false
		}
		failed++
		delay = textRetryDelay(failed)
	}
	return fmt.Sprintf("%s#%d.%d", base, failed, b), delay, true
}

// textJob is one text item being handled: the repository it locked, and whether it waits for the lock.
type textJob struct {
	repoID int64
	wait   bool
	doer   int64 // who made the change the item is about (0: unknown)
}

// lock holds the repository against its scan and the other text items (repoScans) from before its text is read until
// the store, so that a pass never stores what an older read of the text found. A repository that is locked is
// errTextBusy unless the job waits.
func (j *textJob) lock(repoID int64) (func(), error) {
	key := strconv.FormatInt(repoID, 10)
	if j.wait {
		return repoScans.Lock(key), nil
	}
	ok, unlock := repoScans.TryLock(key)
	if !ok {
		unlock()
		return nil, errTextBusy
	}
	return unlock, nil
}

// handleText runs one queue item. A panic (the keying is not set up, a detector bug) is logged and drops the item.
func handleText(ctx context.Context, item string) (err error) {
	base, _, busy := textTries(item)
	job := &textJob{wait: busy >= maxTextBusy}
	defer func() {
		if p := recover(); p != nil {
			log.Error("secret scanning: panic (%T) scanning text %q of repository %d", p, item, job.repoID)
			err = nil
		}
	}()
	parts := strings.Split(base, ":")
	nums := make([]int64, 0, 3)
	for _, p := range parts[1:] {
		if n, perr := strconv.ParseInt(p, 10, 64); perr == nil {
			nums = append(nums, n)
		}
	}
	switch {
	case parts[0] == "i" && len(nums) == 2:
		job.doer = nums[1]
		return scanIssueText(ctx, nums[0], job)
	case parts[0] == "c" && len(nums) == 2:
		job.doer = nums[1]
		return scanCommentText(ctx, nums[0], job)
	case parts[0] == "x" && len(parts) == 4 && len(nums) == 2:
		job.repoID = nums[0]
		unlock, err := job.lock(nums[0])
		if err != nil {
			return err
		}
		defer unlock()
		return secretscan_model.MarkTextGone(ctx, nums[0], parts[1], nums[1])
	}
	return nil
}

// textUnit is the unit an issue's text belongs to.
func textUnit(isPull bool) unit.Type {
	if isPull {
		return unit.TypePullRequests
	}
	return unit.TypeIssues
}

// textRepo returns the repository when the text of an issue (a pull request with isPull) is to be scanned: scanning
// is on for it, text is part of it and the unit is on (the unit policy and the organization's units included). Text
// in a unit that is off or hidden is not scanned: no alert tells of it.
func textRepo(ctx context.Context, repoID int64, isPull bool) (*repo_model.Repository, setting.SecretScanningOptions, bool) {
	cfg := setting.SecretScanningSettings(ctx)
	if !cfg.ScanText || !SiteEnabled(ctx) {
		return nil, cfg, false
	}
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		if !repo_model.IsErrRepoNotExist(err) {
			log.Error("secret scanning: load repository %d for its text: %v", repoID, err)
		}
		return nil, cfg, false
	}
	return repo, cfg, Enabled(ctx, repo) && repo.Status == repo_model.RepositoryReady && repo.UnitEnabled(ctx, textUnit(isPull))
}

// TextStatusVisible tells whether a viewer may see the state of the repository's text scan (its holes and status):
// it covers the Issues and Pull requests units that are on, so the viewer must be able to read each of them.
func TextStatusVisible(ctx context.Context, repo *repo_model.Repository, canRead func(unit.Type) bool) bool {
	for _, u := range []unit.Type{unit.TypeIssues, unit.TypePullRequests} {
		if repo.UnitEnabled(ctx, u) && !canRead(u) {
			return false
		}
	}
	return true
}

func scanIssueText(ctx context.Context, id int64, job *textJob) error {
	issue, err := issues_model.GetIssueByID(ctx, id)
	if err != nil {
		if issues_model.IsErrIssueNotExist(err) {
			return nil
		}
		return err
	}
	job.repoID = issue.RepoID
	repo, cfg, ok := textRepo(ctx, issue.RepoID, issue.IsPull)
	if !ok {
		return nil
	}
	unlock, err := job.lock(repo.ID)
	if err != nil {
		return err
	}
	defer unlock()
	if issue, err = issues_model.GetIssueByID(ctx, id); err != nil { // as it is now, under the lock
		if issues_model.IsErrIssueNotExist(err) {
			return nil
		}
		return err
	}
	t, err := newTextScan(ctx, repo, cfg)
	if err != nil {
		return err
	}
	t.addIssue(issue)
	t.doer = job.doer
	return t.flushLive()
}

func scanCommentText(ctx context.Context, id int64, job *textJob) error {
	c, err := issues_model.GetCommentByID(ctx, id)
	if err != nil {
		if issues_model.IsErrCommentNotExist(err) {
			return nil
		}
		return err
	}
	issue, err := issues_model.GetIssueByID(ctx, c.IssueID)
	if err != nil {
		if issues_model.IsErrIssueNotExist(err) {
			return nil
		}
		return err
	}
	job.repoID = issue.RepoID
	repo, cfg, ok := textRepo(ctx, issue.RepoID, issue.IsPull)
	if !ok || !slices.Contains(textCommentTypes, c.Type) {
		return nil
	}
	unlock, err := job.lock(repo.ID)
	if err != nil {
		return err
	}
	defer unlock()
	if c, err = issues_model.GetCommentByID(ctx, id); err != nil { // as it is now, under the lock
		if issues_model.IsErrCommentNotExist(err) {
			return nil
		}
		return err
	}
	if pending, err := pendingReviews(ctx, []*issues_model.Comment{c}); err != nil || pending[c.ReviewID] {
		return err // a draft is not published: it is scanned when the review is submitted
	}
	t, err := newTextScan(ctx, repo, cfg)
	if err != nil {
		return err
	}
	t.addComment(c)
	t.doer = job.doer
	return t.flushLive()
}

// pendingReviews tells which of the reviews the comments belong to are drafts.
func pendingReviews(ctx context.Context, comments []*issues_model.Comment) (map[int64]bool, error) {
	var ids []int64
	for _, c := range comments {
		if c.ReviewID > 0 {
			ids = append(ids, c.ReviewID)
		}
	}
	out := map[int64]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []*issues_model.Review
	if err := db.GetEngine(ctx).In("id", ids).And("type = ?", issues_model.ReviewTypePending).Cols("id").Find(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = true
	}
	return out, nil
}

// detectors caches the compiled detectors by what they were built from, so that a text is not scanned by a detector
// compiled for it: one per set of custom patterns, the generic rule and the size limit. A pattern that changes is
// another entry; the cache is dropped when it grows.
var detectors = struct {
	sync.Mutex
	m map[[sha256.Size]byte]*secretdetection.Detector
}{m: map[[sha256.Size]byte]*secretdetection.Detector{}}

func textDetector(ctx context.Context, repo *repo_model.Repository, cfg setting.SecretScanningOptions) (*secretdetection.Detector, error) {
	custom, err := customRules(ctx, repo)
	if err != nil {
		return nil, err
	}
	var key strings.Builder
	fmt.Fprintf(&key, "%t|%d", cfg.GenericRules, cfg.MaxTextBytes)
	for _, r := range custom {
		fmt.Fprintf(&key, "|%s\x00%s\x00%d\x00%s", r.ID, r.Regex, r.SecretGroup, strings.Join(r.Keywords, "\x01"))
	}
	k := sha256.Sum256([]byte(key.String()))
	detectors.Lock()
	defer detectors.Unlock()
	if d := detectors.m[k]; d != nil {
		return d, nil
	}
	rules := []secretdetection.Rule{}
	for _, r := range secretdetection.BuiltinRules() {
		if !r.DefaultOff || cfg.GenericRules {
			rules = append(rules, r)
		}
	}
	d, err := secretdetection.NewDetector(append(rules, custom...))
	if err != nil {
		return nil, err
	}
	d.MaxContentSize = int(cfg.MaxTextBytes)
	if len(detectors.m) >= 64 {
		clear(detectors.m)
	}
	detectors.m[k] = d
	return d, nil
}

// textScan collects what the texts of one pass hold; flush stores it in one transaction.
type textScan struct {
	ctx      context.Context
	repo     *repo_model.Repository
	cfg      setting.SecretScanningOptions
	detector *secretdetection.Detector
	cands    map[string]map[string]*candidate // by place kind, then rule and fingerprint
	found    map[secretscan_model.TextSource]map[secretscan_model.PlaceKey]bool
	holes    int64
	read     int64 // bytes of text added
	meta     map[secretscan_model.TextSource]textMeta
	doer     int64 // who wrote the text as it is now (0: unknown); only that person is told by mail
}

// textMeta is what the notice to a poster needs of a text.
type textMeta struct{ issueID, posterID int64 }

func newTextScan(ctx context.Context, repo *repo_model.Repository, cfg setting.SecretScanningOptions) (*textScan, error) {
	d, err := textDetector(ctx, repo, cfg)
	if err != nil {
		return nil, err
	}
	return &textScan{
		ctx: ctx, repo: repo, cfg: cfg, detector: d,
		cands: map[string]map[string]*candidate{}, found: map[secretscan_model.TextSource]map[secretscan_model.PlaceKey]bool{},
		meta: map[secretscan_model.TextSource]textMeta{},
	}, nil
}

func poster(id, originalAuthorID int64) int64 {
	if originalAuthorID != 0 || id <= 0 {
		return 0 // imported text has no gitdepo author; the Actions user and token identities write no text
	}
	return id
}

func (t *textScan) addIssue(issue *issues_model.Issue) {
	by := poster(issue.PosterID, issue.OriginalAuthorID)
	t.add(secretscan_model.TextSource{Kind: secretscan_model.KindIssue, ID: issue.ID, Field: "title"}, issue.ID, by, issue.Title)
	t.add(secretscan_model.TextSource{Kind: secretscan_model.KindIssue, ID: issue.ID, Field: "body"}, issue.ID, by, issue.Content)
}

func (t *textScan) addComment(c *issues_model.Comment) {
	t.add(secretscan_model.TextSource{Kind: secretscan_model.KindComment, ID: c.ID}, c.IssueID, poster(c.PosterID, c.OriginalAuthorID), c.Content)
}

// add scans one text. Its data: URI payloads are dropped first; a text still over MAX_TEXT_BYTES is cut (a hole), as
// is one the detector could not scan whole. Only a text read to its end tells which of its places are gone.
func (t *textScan) add(src secretscan_model.TextSource, issueID, posterID int64, text string) {
	places := map[secretscan_model.PlaceKey]bool{}
	t.meta[src] = textMeta{issueID, posterID}
	t.read += int64(len(text))
	text = stripDataURIs(text)
	whole := true
	if int64(len(text)) > t.cfg.MaxTextBytes {
		text = strings.ToValidUTF8(text[:t.cfg.MaxTextBytes], "")
		t.holes++
		whole = false
	}
	defer func() {
		if whole {
			t.found[src] = places
		}
	}()
	if text == "" {
		return
	}
	findings, complete := scanContent(t.detector, []byte(text))
	if !complete {
		t.holes++
		whole = false
	}
	byKey := t.cands[src.Kind]
	if byKey == nil {
		byKey = map[string]*candidate{}
		t.cands[src.Kind] = byKey
	}
	for _, f := range findings {
		loc := secretscan_model.NewTextLocation(t.repo.ID, src.Kind, src.ID, issueID, src.Field, f.StartLine, f.EndLine, posterID)
		places[secretscan_model.PlaceKey{Kind: src.Kind, PathHash: loc.PathHash, StartLine: loc.StartLine}] = true
		key := f.RuleID + "|" + f.Fingerprint
		c := byKey[key]
		if c == nil {
			if int64(len(byKey)) >= t.cfg.MaxAlertsPerRepo { // more distinct secrets than the repository may have alerts
				t.holes++
				continue
			}
			c = &candidate{ruleID: f.RuleID, fingerprint: f.Fingerprint, locs: map[string]*secretscan_model.Location{}, poster: posterID}
			byKey[key] = c
		}
		lk := loc.PathHash + ":" + strconv.Itoa(loc.StartLine)
		switch {
		case c.locs[lk] != nil:
		case int64(len(c.locs)) >= t.cfg.MaxLocationsPerAlert:
			c.extra++
		default:
			c.locs[lk] = loc
		}
	}
}

// flush stores the alerts and their places, marks the places that are gone, counts the holes and runs more (the
// backfill's state row), in one transaction after the last check of the switches. Alerts left out for the cap are
// holes too; left tells how many.
func (t *textScan) flush(more func(ctx context.Context, left int64) error) error {
	err := db.WithTx(t.ctx, func(ctx context.Context) error {
		enabled, owner, err := enabledStored(ctx, t.repo.ID)
		if err != nil {
			return err
		}
		if !enabled {
			return errDisabled
		}
		if owner != t.repo.OwnerID {
			return errOwnerMoved
		}
		var posters []int64
		for _, byKey := range t.cands {
			for _, c := range byKey {
				if c.poster != 0 && !slices.Contains(posters, c.poster) {
					posters = append(posters, c.poster)
				}
			}
		}
		byPoster, err := secretscan_model.CountOpenTextAlertsByPoster(ctx, t.repo.ID, posters)
		if err != nil {
			return err
		}
		var left int64
		for _, kind := range slices.Sorted(maps.Keys(t.cands)) {
			cands := slices.SortedFunc(maps.Values(t.cands[kind]), func(a, b *candidate) int {
				return cmp.Or(cmp.Compare(a.ruleID, b.ruleID), cmp.Compare(a.fingerprint, b.fingerprint))
			})
			l, err := writeAlerts(ctx, t.cfg, t.repo.ID, kind, true, cands, byPoster)
			if err != nil {
				return err
			}
			left += l
		}
		if err := secretscan_model.SyncTextPlaces(ctx, t.repo.ID, t.found); err != nil {
			return err
		}
		if more != nil {
			return more(ctx, left)
		}
		return secretscan_model.AddTextHoles(ctx, t.repo.ID, t.holes+left)
	})
	if errors.Is(err, errDisabled) {
		return nil // switched off meanwhile: nothing is stored
	}
	return err
}

// sendPosterNotice is a variable so that tests can see it.
var sendPosterNotice = mailer.SendSecretPosterNotice

// flushLive is flush for the scan of one text that was just written or changed: besides storing it, it marks the
// repository for a digest when the scan opened an alert, and tells the person who wrote the text about each place that
// is new (the text may be an edit: a place that was stored already and is still there is not new). Neither runs in the
// transaction, and a scan that stored nothing (scanning was switched off meanwhile) notifies nobody.
func (t *textScan) flushLive() error {
	var before, stored map[secretscan_model.TextSource]map[secretscan_model.PlaceKey]bool
	var maxBefore int64
	hasFound := false
	for _, places := range t.found {
		hasFound = hasFound || len(places) > 0
	}
	if hasFound {
		var err error
		if before, err = secretscan_model.StoredTextPlaces(t.ctx, t.repo.ID, t.found); err != nil {
			return err
		}
		if maxBefore, err = secretscan_model.MaxAlertID(t.ctx, t.repo.ID); err != nil {
			return err
		}
	}
	if err := t.flush(nil); err != nil || !hasFound {
		return err
	}
	stored, err := secretscan_model.StoredTextPlaces(t.ctx, t.repo.ID, t.found)
	if err != nil {
		return err
	}
	var notices []mailer.SecretPosterNotice
	fresh := false
	for src, places := range stored {
		m := t.meta[src]
		for key := range places {
			if before[src][key] {
				continue
			}
			fresh = true
			if m.posterID != 0 && m.posterID == t.doer { // not for text that somebody else edited the secret into
				n := mailer.SecretPosterNotice{PosterID: m.posterID, IssueID: m.issueID, Field: src.Field}
				if src.Kind == secretscan_model.KindComment {
					n.CommentID, n.Field = src.ID, ""
				}
				if !slices.Contains(notices, n) {
					notices = append(notices, n) // one mail per text, whatever the number of places
				}
			}
		}
	}
	if !fresh {
		return nil
	}
	if maxAfter, err := secretscan_model.MaxAlertID(t.ctx, t.repo.ID); err == nil && maxAfter > maxBefore {
		markText(t.ctx, t.repo, maxBefore)
	}
	for _, n := range notices {
		if err := sendPosterNotice(t.ctx, t.repo, n); err != nil {
			log.Error("secret scanning: notice to poster %d in repository %d: %v", n.PosterID, t.repo.ID, err)
		}
	}
	return nil
}

// textCursor is where the scan of a repository's text is: issues up to Issue are done; Batch, when set, is the last
// issue of the batch under way (issues after Issue up to it: their titles and bodies are done), whose comments are
// done up to comment Comment of issue CIssue (in issue, then comment order).
type textCursor struct {
	Issue   int64 `json:"i"`
	Batch   int64 `json:"b,omitempty"`
	CIssue  int64 `json:"p,omitempty"`
	Comment int64 `json:"c,omitempty"`
}

// scanText reads the text of the repository that is there already, one slice per call, after its code. It goes on
// from the cursor kept in the state row of kind issue and is done once that row has a status and no retry time (a row
// that Rescan or turning the text scan on reset has none: it starts again). Issues are read a batch at a time, and
// the comments of a batch with one query per page; only the issues and pull requests whose unit is on.
func (s *scanner) scanText() (requeue bool, err error) {
	if !s.cfg.ScanText {
		return false, nil
	}
	var isPull []bool
	for _, pull := range []bool{false, true} {
		if s.repo.UnitEnabled(s.ctx, textUnit(pull)) {
			isPull = append(isPull, pull)
		}
	}
	if len(isPull) == 0 {
		return false, nil // no text to read: a unit turned on later reads it then
	}
	old, err := secretscan_model.GetScan(s.ctx, s.repo.ID, secretscan_model.KindIssue)
	if err != nil {
		return false, err
	}
	var cur textCursor
	if old != nil {
		if old.Status != "" && (old.RetryUnix == 0 || old.FailCount > 0 && timeutil.TimeStampNow() < old.RetryUnix) {
			return false, nil // done, or a failure waiting out its backoff
		}
		_ = json.Unmarshal([]byte(old.ScannedTips), &cur) // a state that can't be read (a reset row) reads everything again
	}
	t, err := newTextScan(s.ctx, s.repo, s.cfg)
	if err != nil {
		return false, err
	}
	items := 0
	done := false
	more := func() bool { return items < maxTextItems && t.read < maxTextSliceBytes && s.scanCtx.Err() == nil }
	issueCond := builder.Eq{"repo_id": s.repo.ID}.And(builder.In("is_pull", isPull))
	for more() && !done {
		var issues []*issues_model.Issue
		if cur.Batch == 0 { // a new batch: its titles and bodies
			if err := db.GetEngine(s.ctx).Where(issueCond.And(builder.Gt{"id": cur.Issue})).OrderBy("id").Limit(textBatch).Find(&issues); err != nil {
				return false, err
			}
			if len(issues) == 0 {
				done = true
				break
			}
			for i, issue := range issues { // the budget is checked per issue: the batch ends where it runs out
				if i > 0 && !more() {
					issues = issues[:i]
					break
				}
				t.addIssue(issue)
				items++
			}
			cur.Batch = issues[len(issues)-1].ID
		} else if err := db.GetEngine(s.ctx).Cols("id").Where(issueCond.And(builder.Gt{"id": cur.Issue}, builder.Lte{"id": cur.Batch})).Find(&issues); err != nil {
			return false, err // the batch a slice ended in: its issues again, for their comments
		}
		ids := make([]int64, 0, len(issues))
		for _, issue := range issues {
			ids = append(ids, issue.ID)
		}
		for more() && cur.Batch != 0 { // its comments, a page at a time
			var comments []*issues_model.Comment
			if len(ids) > 0 {
				if err := db.GetEngine(s.ctx).Where(builder.In("issue_id", ids).And(builder.In("type", textCommentTypes),
					builder.Or(builder.Gt{"issue_id": cur.CIssue}, builder.Eq{"issue_id": cur.CIssue}.And(builder.Gt{"id": cur.Comment})))).
					OrderBy("issue_id, id").Limit(textBatch).Find(&comments); err != nil {
					return false, err
				}
			}
			pending, err := pendingReviews(s.ctx, comments)
			if err != nil {
				return false, err
			}
			read := 0
			for _, c := range comments {
				cur.CIssue, cur.Comment = c.IssueID, c.ID
				read++
				items++
				if pending[c.ReviewID] {
					t.read += int64(len(c.Content)) // a draft is skipped, but it was read; its review's submission scans it
				} else {
					t.addComment(c)
				}
				if !more() {
					break
				}
			}
			if read == len(comments) && len(comments) < textBatch { // the batch is done
				cur = textCursor{Issue: cur.Batch}
			}
		}
	}
	return s.saveText(old, cur, t, done)
}

// saveText stores a slice of the text scan: the alerts and the state row in one transaction.
func (s *scanner) saveText(old *secretscan_model.Scan, cur textCursor, t *textScan, done bool) (requeue bool, err error) {
	tips, _ := json.Marshal(cur)
	st := &secretscan_model.Scan{RepoID: s.repo.ID, Kind: secretscan_model.KindIssue, ScannedTips: string(tips), Status: secretscan_model.StatusOK}
	if old != nil {
		st.Holes = old.Holes
	}
	err = t.flush(func(ctx context.Context, left int64) error {
		if done { // the texts deleted without a notifier (a purged user's comments) were not read
			if err := secretscan_model.MarkOrphanTextGone(ctx, s.repo.ID); err != nil {
				return err
			}
		}
		st.Holes += t.holes + left
		switch {
		case !done:
			st.Status, st.Error = secretscan_model.StatusIncomplete, stopText
			st.RetryUnix = timeutil.TimeStampNow().Add(int64(retryBase / time.Second)) // under way: a safety net for the cron task
		case st.Holes > 0:
			st.Status, st.Error = secretscan_model.StatusIncomplete, stopPartial
			if left > 0 || old != nil && old.Holes > 0 && old.Error == stopAlerts {
				st.Error = stopAlerts
			}
		}
		return secretscan_model.Save(ctx, old, st)
	})
	switch {
	case err == nil:
		return !done, nil
	case errors.Is(err, secretscan_model.ErrScanMoved), errors.Is(err, errOwnerMoved):
		return true, nil // overtaken: read again
	}
	log.Error("secret scanning: store the text scan of repository %d: %v", s.repo.ID, err)
	fail := &secretscan_model.Scan{RepoID: s.repo.ID, Kind: secretscan_model.KindIssue, ScannedTips: "{}", Status: secretscan_model.StatusFailed, Error: errStore, FailCount: 1}
	if old != nil {
		fail.ScannedTips, fail.Holes, fail.FailCount = old.ScannedTips, old.Holes, old.FailCount+1
	}
	fail.RetryUnix = timeutil.TimeStampNow().Add(int64(min(retryBase<<min(fail.FailCount-1, 12), retryMax) / time.Second))
	_ = secretscan_model.Save(s.ctx, old, fail)
	return false, errStoreFail
}

func doerID(u *user_model.User) int64 {
	if u == nil {
		return 0
	}
	return u.ID
}

// textNotifier methods: a text that is written or changed is queued; the handler reads it as it is then.
func (*notifier) NewIssue(ctx context.Context, issue *issues_model.Issue, _ []*user_model.User) {
	enqueueIssueText(ctx, issue.ID, issue.PosterID)
}

func (*notifier) IssueChangeContent(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, _ string) {
	enqueueIssueText(ctx, issue.ID, doerID(doer))
}

func (*notifier) IssueChangeTitle(ctx context.Context, doer *user_model.User, issue *issues_model.Issue, _ string) {
	enqueueIssueText(ctx, issue.ID, doerID(doer))
}

func (*notifier) DeleteIssue(ctx context.Context, _ *user_model.User, issue *issues_model.Issue) {
	enqueueTextGone(ctx, secretscan_model.KindIssue, issue.RepoID, issue.ID)
}

func (*notifier) CreateIssueComment(ctx context.Context, doer *user_model.User, _ *repo_model.Repository, _ *issues_model.Issue, c *issues_model.Comment, _ []*user_model.User) {
	enqueueCommentText(ctx, c, doerID(doer))
}

func (*notifier) UpdateComment(ctx context.Context, doer *user_model.User, c *issues_model.Comment, _ string) {
	enqueueCommentText(ctx, c, doerID(doer))
}

func (*notifier) DeleteComment(ctx context.Context, _ *user_model.User, c *issues_model.Comment) {
	if c.Issue == nil {
		if err := c.LoadIssue(ctx); err != nil {
			return
		}
	}
	enqueueTextGone(ctx, secretscan_model.KindComment, c.Issue.RepoID, c.ID)
}

// PullRequestReview and PullRequestCodeComment come when a review is submitted, so a draft is not scanned before.
func (*notifier) PullRequestReview(ctx context.Context, _ *issues_model.PullRequest, _ *issues_model.Review, c *issues_model.Comment, _ []*user_model.User) {
	enqueueCommentText(ctx, c, c.PosterID)
}

func (*notifier) PullRequestCodeComment(ctx context.Context, _ *issues_model.PullRequest, c *issues_model.Comment, _ []*user_model.User) {
	enqueueCommentText(ctx, c, c.PosterID)
}
