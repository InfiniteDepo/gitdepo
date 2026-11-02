// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enableText is enable with the text scan on and a small text limit.
func enableText(t *testing.T) *repo_model.Repository {
	t.Helper()
	repo := enable(t)
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.ScanText, true))
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 4096))
	return repo
}

var nextIndex = int64(1000)

func newIssue(t *testing.T, repo *repo_model.Repository, title, body string) *issues_model.Issue {
	t.Helper()
	nextIndex++
	issue := &issues_model.Issue{RepoID: repo.ID, Index: nextIndex, PosterID: 2, Title: title, Content: body}
	require.NoError(t, db.Insert(t.Context(), issue))
	return issue
}

func newComment(t *testing.T, issue *issues_model.Issue, body string) *issues_model.Comment {
	t.Helper()
	c := &issues_model.Comment{Type: issues_model.CommentTypeComment, IssueID: issue.ID, PosterID: 3, Content: body}
	require.NoError(t, db.Insert(t.Context(), c))
	return c
}

func setText(t *testing.T, table string, id int64, col, text string) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Table(table).Where("id = ?", id).Update(map[string]any{col: text})
	require.NoError(t, err)
}

func textPlaces(t *testing.T, repoID int64) []*secretscan_model.Location {
	t.Helper()
	var locs []*secretscan_model.Location
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ? AND kind IN (?, ?)", repoID, secretscan_model.KindIssue, secretscan_model.KindComment).OrderBy("id").Find(&locs))
	return locs
}

func TestScanTextIssueAndComment(t *testing.T) {
	repo := enableText(t)
	tok := token("text-body")
	titleTok := token("text-title")
	issue := newIssue(t, repo, "leaked "+titleTok, "first line\nsecond: "+tok+"\n")
	c := newComment(t, issue, "also here\n\n"+tok)

	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("c:%d:0", c.ID)))

	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	assert.True(t, a.ViaPull, "an alert that only text reaches shares the cap of the pull refs")
	assert.Equal(t, secretscan_model.StateOpen, a.State)
	assert.NotNil(t, alertFor(t, repo.ID, titleTok))

	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 2)
	byKind := map[string]*secretscan_model.Location{}
	for _, l := range locs {
		byKind[l.Kind] = l
		assert.Empty(t, l.CommitID)
		assert.Zero(t, l.RemovedUnix)
	}
	assert.Equal(t, secretscan_model.KindIssue, byKind["issue"].Kind)
	assert.Equal(t, "body", byKind["issue"].Field)
	assert.Equal(t, 2, byKind["issue"].StartLine)
	assert.Equal(t, issue.ID, byKind["issue"].SourceID)
	assert.Equal(t, issue.ID, byKind["issue"].IssueID)
	assert.EqualValues(t, 2, byKind["issue"].PosterID)
	assert.Equal(t, 3, byKind["comment"].StartLine)
	assert.Equal(t, c.ID, byKind["comment"].SourceID)
	assert.Equal(t, issue.ID, byKind["comment"].IssueID)
	assert.EqualValues(t, 3, byKind["comment"].PosterID)
	assert.Equal(t, 1, locationsOfTitle(t, alertFor(t, repo.ID, titleTok).ID).StartLine)

	t.Run("the readers of places return the places in text, and a code reader counts the alert as code", func(t *testing.T) {
		first, err := secretscan_model.FirstLocations(t.Context(), repo.ID, []int64{a.ID}, true)
		require.NoError(t, err)
		require.Contains(t, first, a.ID)
		assert.True(t, first[a.ID].IsText())
		counts, err := secretscan_model.CountLocations(t.Context(), repo.ID, []int64{a.ID}, true)
		require.NoError(t, err)
		assert.Equal(t, 2, counts[a.ID])
		found, err := secretscan_model.FindLocations(t.Context(), repo.ID, a.ID, 10)
		require.NoError(t, err)
		assert.Len(t, found, 2)
		has, err := secretscan_model.HasCodeLocation(t.Context(), repo.ID, a.ID)
		require.NoError(t, err)
		assert.True(t, has, "only the wiki is a place a viewer without Wiki read can't have")
		got, err := secretscan_model.GetVisibleAlert(t.Context(), repo.ID, a.Index, false)
		require.NoError(t, err)
		assert.Equal(t, a.ID, got.ID, "the alert is listed for viewers without Wiki read, so it can be opened by them too")
	})

	t.Run("the same text again stores nothing new", func(t *testing.T) {
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		assert.Len(t, locationsOf(t, a.ID), 2)
		assert.Len(t, alertsOf(t, repo.ID), 2)
	})

	t.Run("an edit that removes the secret keeps the alert and marks the place", func(t *testing.T) {
		setText(t, "issue", issue.ID, "content", "nothing here")
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		for _, l := range locationsOf(t, a.ID) {
			if l.Kind == secretscan_model.KindIssue {
				assert.NotZero(t, l.RemovedUnix)
			} else {
				assert.Zero(t, l.RemovedUnix, "the comment still holds it")
			}
		}
		assert.Equal(t, secretscan_model.StateOpen, alertFor(t, repo.ID, tok).State)
		// pasted again: the place is back
		setText(t, "issue", issue.ID, "content", "again\nsecond: "+tok)
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		for _, l := range locationsOf(t, a.ID) {
			assert.Zero(t, l.RemovedUnix)
		}
	})

	t.Run("a deleted comment and a deleted issue mark their places", func(t *testing.T) {
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("x:comment:%d:%d", repo.ID, c.ID)))
		for _, l := range locationsOf(t, a.ID) {
			assert.Equal(t, l.Kind == secretscan_model.KindComment, l.RemovedUnix != 0, l.Kind)
		}
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("x:issue:%d:%d", repo.ID, issue.ID)))
		for _, l := range textPlaces(t, repo.ID) {
			assert.NotZero(t, l.RemovedUnix, l.Kind)
		}
		assert.Equal(t, secretscan_model.StateOpen, alertFor(t, repo.ID, tok).State, "the secret was exposed: the alert stays")
	})
}

func locationsOfTitle(t *testing.T, alertID int64) *secretscan_model.Location {
	t.Helper()
	for _, l := range locationsOf(t, alertID) {
		if l.Field == "title" {
			return l
		}
	}
	require.FailNow(t, "no place in the title")
	return nil
}

func TestScanTextSwitches(t *testing.T) {
	repo := enableText(t)
	issue := newIssue(t, repo, "t", "key "+token("switch"))
	scan := func() { require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID))) }

	t.Run("the text switch", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.ScanText, false)()
		scan()
		assert.Empty(t, alertsOf(t, repo.ID))
	})
	t.Run("the site switch", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
		scan()
		assert.Empty(t, alertsOf(t, repo.ID))
	})
	t.Run("the repository switch", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Table("repository").Where("id = ?", repo.ID).Update(map[string]any{"secret_scanning_disabled": true})
		require.NoError(t, err)
		scan()
		assert.Empty(t, alertsOf(t, repo.ID))
		_, err = db.GetEngine(t.Context()).Table("repository").Where("id = ?", repo.ID).Update(map[string]any{"secret_scanning_disabled": false})
		require.NoError(t, err)
	})
	t.Run("on", func(t *testing.T) {
		scan()
		assert.Len(t, alertsOf(t, repo.ID), 1)
	})
	t.Run("a deleted text and a bad item are no failure", func(t *testing.T) {
		require.NoError(t, handleText(t.Context(), "i:999999:0"))
		require.NoError(t, handleText(t.Context(), "c:999999:0"))
		require.NoError(t, handleText(t.Context(), "nonsense"))
		require.NoError(t, handleText(t.Context(), "i:abc"))
	})
}

func TestScanTextPendingReview(t *testing.T) {
	repo := enableText(t)
	issue := newIssue(t, repo, "pr", "")
	review := &issues_model.Review{Type: issues_model.ReviewTypePending, IssueID: issue.ID, ReviewerID: 3}
	require.NoError(t, db.Insert(t.Context(), review))
	c := &issues_model.Comment{Type: issues_model.CommentTypeCode, IssueID: issue.ID, PosterID: 3, ReviewID: review.ID, Content: "draft " + token("draft"), TreePath: "a.go", Line: 1}
	require.NoError(t, db.Insert(t.Context(), c))

	require.NoError(t, handleText(t.Context(), fmt.Sprintf("c:%d:0", c.ID)))
	assert.Empty(t, alertsOf(t, repo.ID), "a draft is not scanned: it is not published")

	// the backfill skips it too, then the submission scans it
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Empty(t, alertsOf(t, repo.ID))

	_, err := db.GetEngine(t.Context()).Table("review").Where("id = ?", review.ID).Update(map[string]any{"type": issues_model.ReviewTypeComment})
	require.NoError(t, err)
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("c:%d:0", c.ID)))
	require.Len(t, alertsOf(t, repo.ID), 1)
	assert.Equal(t, secretscan_model.KindComment, textPlaces(t, repo.ID)[0].Kind)
}

func TestScanTextLimits(t *testing.T) {
	repo := enableText(t)
	tok := token("limits")

	t.Run("text over the limit is cut", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 200)()
		issue := newIssue(t, repo, "t", strings.Repeat("x", 300)+"\n"+tok)
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		assert.Nil(t, alertFor(t, repo.ID, tok), "the part past the limit is not scanned")
	})
	t.Run("a data URI payload is skipped, the rest of the text is not", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<20)()
		payload := strings.Repeat("QUJD", 400) + tok + strings.Repeat("QUJD", 400)
		issue := newIssue(t, repo, "t", "![x](data:image/png;base64,"+payload+")\nreal: "+tok)
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		a := alertFor(t, repo.ID, tok)
		require.NotNil(t, a)
		locs := locationsOf(t, a.ID)
		require.Len(t, locs, 1)
		assert.Equal(t, 2, locs[0].StartLine)
	})
	t.Run("places per alert are capped", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.MaxLocationsPerAlert, 2)()
		other := token("many")
		for range 4 {
			issue := newIssue(t, repo, "t", other)
			require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		}
		a := alertFor(t, repo.ID, other)
		require.NotNil(t, a)
		assert.Len(t, locationsOf(t, a.ID), 2)
		assert.Equal(t, 4, a.LocationCount)
	})
	t.Run("alerts are capped like the pull refs' share", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, 4)()
		before := len(alertsOf(t, repo.ID))
		var body []string
		for i := range 10 {
			body = append(body, token(fmt.Sprintf("cap-%d", i)))
		}
		issue := newIssue(t, repo, "t", strings.Join(body, "\n"))
		require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
		assert.LessOrEqual(t, len(alertsOf(t, repo.ID))-before, 4)
	})
}

func TestScanTextBackfill(t *testing.T) {
	repo := enableText(t)
	var toks []string
	for i := range 3 {
		tok := token(fmt.Sprintf("back-%d", i))
		toks = append(toks, tok)
		issue := newIssue(t, repo, "t", "x")
		newComment(t, issue, "plain")
		newComment(t, issue, "secret "+tok)
	}
	// text of another repository is not read
	otherRepo := unittestRepo(t, 2)
	newIssue(t, otherRepo, "t", token("elsewhere"))

	defer test.MockVariableValue(&maxTextItems, 2)()
	slices := 0
	for {
		requeue, err := scan(t.Context(), repo.ID)
		require.NoError(t, err)
		slices++
		s := scanOf(t, repo.ID, secretscan_model.KindIssue)
		require.NotNil(t, s)
		if !requeue {
			break
		}
		assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
		assert.NotZero(t, s.RetryUnix)
		require.Less(t, slices, 40)
	}
	assert.Greater(t, slices, 2, "the budget cuts the backfill into slices")
	for _, tok := range toks {
		require.NotNil(t, alertFor(t, repo.ID, tok), tok)
	}
	assert.Nil(t, alertFor(t, repo.ID, token("elsewhere")))
	assert.Len(t, textPlaces(t, repo.ID), 3)
	s := scanOf(t, repo.ID, secretscan_model.KindIssue)
	assert.Zero(t, s.RetryUnix)
	assert.Equal(t, secretscan_model.StatusOK, s.Status)
	assert.True(t, s.Completed)

	t.Run("a finished backfill is not run again", func(t *testing.T) {
		newIssue(t, repo, "t", token("later"))
		requeue, err := scan(t.Context(), repo.ID)
		require.NoError(t, err)
		assert.False(t, requeue)
		assert.Nil(t, alertFor(t, repo.ID, token("later")), "new text comes through the notifier")
	})
}

func unittestRepo(t *testing.T, id int64) *repo_model.Repository {
	t.Helper()
	repo, err := repo_model.GetRepositoryByID(t.Context(), id)
	require.NoError(t, err)
	return repo
}

func TestScanTextBackfillHoles(t *testing.T) {
	repo := enableText(t)
	defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<10)()
	newIssue(t, repo, "t", strings.Repeat("y", 3000))
	_, err := scan(t.Context(), repo.ID)
	require.NoError(t, err)
	s := scanOf(t, repo.ID, secretscan_model.KindIssue)
	require.NotNil(t, s)
	assert.EqualValues(t, 1, s.Holes, "the text over the limit is a hole")
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.Equal(t, stopPartial, s.Error)
	assert.Zero(t, s.RetryUnix)
}

func TestScanTextNotifierQueuesItems(t *testing.T) {
	repo := enableText(t)
	var items []string
	t.Cleanup(test.MockVariableValue(&textQueue, &queue.WorkerPoolQueue[string]{}))
	t.Cleanup(test.MockVariableValue(&pushTextQueue, func(item string) error { items = append(items, item); return nil }))
	issue := newIssue(t, repo, "t", "b")
	c := newComment(t, issue, "c")
	n := &notifier{}
	ctx := t.Context()

	n.NewIssue(ctx, issue, nil)
	n.IssueChangeTitle(ctx, nil, issue, "old")
	n.IssueChangeContent(ctx, nil, issue, "old")
	n.CreateIssueComment(ctx, nil, repo, issue, c, nil)
	n.UpdateComment(ctx, nil, c, "old")
	n.PullRequestReview(ctx, nil, nil, c, nil)
	n.PullRequestCodeComment(ctx, nil, c, nil)
	n.DeleteComment(ctx, nil, c)
	n.DeleteIssue(ctx, nil, issue)
	i, cs := fmt.Sprintf("i:%d:0", issue.ID), fmt.Sprintf("c:%d:0", c.ID)
	ip, cp := fmt.Sprintf("i:%d:%d", issue.ID, issue.PosterID), fmt.Sprintf("c:%d:%d", c.ID, c.PosterID)
	assert.Equal(t, []string{
		ip, i, i, cs, cs, cp, cp,
		fmt.Sprintf("x:comment:%d:%d", repo.ID, c.ID), fmt.Sprintf("x:issue:%d:%d", repo.ID, issue.ID),
	}, items)

	t.Run("a comment that carries no text, and a site switched off, queue nothing", func(t *testing.T) {
		items = nil
		n.CreateIssueComment(ctx, nil, repo, issue, &issues_model.Comment{ID: 5, Type: issues_model.CommentTypeClose}, nil)
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
		n.NewIssue(ctx, issue, nil)
		assert.Empty(t, items)
	})
}

func TestStripDataURIs(t *testing.T) {
	long := strings.Repeat("A", 1200)
	assert.Equal(t, "see data:image/png;base64, here", stripDataURIs("see data:image/png;base64,"+long+" here"))
	assert.Equal(t, "data:image/png;base64,_x-y", stripDataURIs("data:image/png;base64,"+long+"_x-y"), "only the base64 alphabet is the payload")
	short := "data:image/png;base64," + strings.Repeat("A", 100)
	assert.Equal(t, short, stripDataURIs(short), "a short payload is kept")
	assert.Equal(t, "no uri "+long, stripDataURIs("no uri "+long))
}

// A text, a second text and the code holding the same new secret, handled at once: every pass stores, one alert.
func TestScanTextConcurrentWithCode(t *testing.T) {
	repo := enableText(t)
	tok := token("concurrent")
	w := newWork(t, repo)
	w.commit(map[string]string{"conf.txt": tok + "\n"})
	w.pushDefault()
	issue := newIssue(t, repo, "t", tok)
	c := newComment(t, issue, tok)

	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i, run := range []func() error{
		func() error { return Scan(t.Context(), repo.ID) },
		func() error { return untilFree(t, fmt.Sprintf("i:%d:0", issue.ID)) },
		func() error { return untilFree(t, fmt.Sprintf("c:%d:0", c.ID)) },
	} {
		wg.Go(func() { errs[i] = run() })
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	assert.Len(t, alertsOf(t, repo.ID), 1)
	kinds := map[string]bool{}
	for _, l := range locationsOf(t, a.ID) {
		kinds[l.Kind] = true
	}
	assert.Equal(t, map[string]bool{secretscan_model.KindRepo: true, secretscan_model.KindIssue: true, secretscan_model.KindComment: true}, kinds)
	assert.False(t, a.ViaPull, "the code reaches it")
}

// untilFree runs a text item until the repository is not busy (the queue would bring it back later).
func untilFree(t *testing.T, item string) error {
	for {
		err := handleText(t.Context(), item)
		if !errors.Is(err, errTextBusy) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNextTextItem(t *testing.T) {
	next, delay, ok := nextTextItem("i:5", false)
	assert.True(t, ok)
	assert.Equal(t, "i:5#1.0", next)
	assert.Equal(t, 2*time.Second, delay)
	next, delay, ok = nextTextItem(next, false)
	assert.True(t, ok)
	assert.Equal(t, "i:5#2.0", next)
	assert.Equal(t, 4*time.Second, delay, "a backoff")
	_, _, ok = nextTextItem(fmt.Sprintf("i:5#%d.0", maxTextRetries), false)
	assert.False(t, ok, "bounded")
	next, delay, ok = nextTextItem("i:5#1.0", true)
	assert.True(t, ok)
	assert.Equal(t, "i:5#1.1", next, "busy is counted apart")
	assert.Equal(t, 5*time.Second, delay)
	next, _, _ = nextTextItem(fmt.Sprintf("i:5#0.%d", maxTextBusy), true)
	assert.Equal(t, fmt.Sprintf("i:5#0.%d", maxTextBusy), next)

	repo := enableText(t)
	issue := newIssue(t, repo, "t", token("retried"))
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0#3.2", issue.ID)))
	assert.NotNil(t, alertFor(t, repo.ID, token("retried")), "a retried item is the item")
}

// A text item whose repository is being scanned doesn't wait in the worker: it is queued again later, and after
// maxTextBusy tries it waits for the lock.
func TestScanTextBusyRepository(t *testing.T) {
	repo := enableText(t)
	issue := newIssue(t, repo, "t", token("busy"))
	var later []string
	defer test.MockVariableValue(&pushTextLater, func(item string, delay time.Duration) {
		later = append(later, fmt.Sprintf("%s %s", item, delay))
	})()
	unlock := repoScans.Lock(strconv.FormatInt(repo.ID, 10))
	item := fmt.Sprintf("i:%d:0", issue.ID)
	require.ErrorIs(t, handleText(t.Context(), item), errTextBusy)
	assert.Empty(t, textHandler(item))
	assert.Equal(t, []string{item + "#0.1 5s"}, later)
	assert.Nil(t, alertFor(t, repo.ID, token("busy")))

	go func() {
		time.Sleep(100 * time.Millisecond)
		unlock()
	}()
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("%s#0.%d", item, maxTextBusy)), "waits for the lock")
	assert.NotNil(t, alertFor(t, repo.ID, token("busy")))
}

// The backfill checks its budget per issue, not per batch: the first slice's batch ends at the second issue.
func TestScanTextBackfillBudgetPerIssue(t *testing.T) {
	repo := enableText(t)
	for i := range 5 {
		newIssue(t, repo, "t", token(fmt.Sprintf("per-issue-%d", i)))
	}
	var ids []int64
	require.NoError(t, db.GetEngine(t.Context()).Table("issue").Where("repo_id = ?", repo.ID).OrderBy("id").Limit(2).Cols("id").Find(&ids))
	defer test.MockVariableValue(&maxTextItems, 2)()
	requeue := true
	var err error
	for scanOf(t, repo.ID, secretscan_model.KindIssue) == nil { // the code's slices first
		requeue, err = scan(t.Context(), repo.ID)
		require.NoError(t, err)
	}
	assert.True(t, requeue)
	var cur textCursor
	require.NoError(t, json.Unmarshal([]byte(scanOf(t, repo.ID, secretscan_model.KindIssue).ScannedTips), &cur))
	assert.Equal(t, ids[1], cur.Batch, "two issues in the first slice")
	for requeue {
		requeue, err = scan(t.Context(), repo.ID)
		require.NoError(t, err)
	}
	for i := range 5 {
		assert.NotNil(t, alertFor(t, repo.ID, token(fmt.Sprintf("per-issue-%d", i))))
	}
}

// Rescan resets the text row too: the text is read again and its holes are counted again.
func TestScanTextRescan(t *testing.T) {
	repo := enableText(t)
	defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<10)()
	newIssue(t, repo, "t", strings.Repeat("y", 3000))
	_, err := scan(t.Context(), repo.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, scanOf(t, repo.ID, secretscan_model.KindIssue).Holes)
	later := token("before-rescan")
	newIssue(t, repo, "t", later) // written without a notifier

	_, err = secretscan_model.ResetScans(t.Context(), repo.ID)
	require.NoError(t, err)
	_, err = scan(t.Context(), repo.ID)
	require.NoError(t, err)
	s := scanOf(t, repo.ID, secretscan_model.KindIssue)
	assert.EqualValues(t, 1, s.Holes, "counted again, not forgotten")
	assert.Equal(t, secretscan_model.StatusIncomplete, s.Status)
	assert.NotNil(t, alertFor(t, repo.ID, later), "read again")
}

// Turning the text scan on (again) resets the text rows and marks the scanned repositories, in the save.
func TestScanTextSwitchOnRequeues(t *testing.T) {
	repo := enableText(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	_, err := scan(ctx, repo.ID)
	require.NoError(t, err)
	require.NoError(t, secretscan_model.ClearRequeue(ctx, repo.ID, scanOf(t, repo.ID, secretscan_model.KindRepo).Requeue))
	require.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindIssue).Status)
	asked := 0
	defer test.MockVariableValue(&requeue, func() { asked++ })()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	_, err = SaveSwitches(ctx, doer, true, false, false)
	require.NoError(t, err)
	bumpRevision(t)
	assert.Zero(t, asked, "turning it off queues nothing")
	assert.Equal(t, secretscan_model.StatusOK, scanOf(t, repo.ID, secretscan_model.KindIssue).Status)

	_, err = SaveSwitches(ctx, doer, true, false, true)
	require.NoError(t, err)
	bumpRevision(t)
	assert.Equal(t, 1, asked)
	assert.Empty(t, scanOf(t, repo.ID, secretscan_model.KindIssue).Status, "reset: the next scan reads the text again")
	assert.Positive(t, scanOf(t, repo.ID, secretscan_model.KindRepo).Requeue)

	written := token("while-off")
	newIssue(t, repo, "t", written)
	_, err = scan(ctx, repo.ID)
	require.NoError(t, err)
	assert.NotNil(t, alertFor(t, repo.ID, written))
}

// The backfill reads issues a batch at a time and their comments with one query per page, not one per issue.
func TestScanTextBackfillQueries(t *testing.T) {
	repo := enableText(t)
	_, err := scan(t.Context(), repo.ID) // the code first
	require.NoError(t, err)
	backfill := func() int64 {
		_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND kind = ?", repo.ID, secretscan_model.KindIssue).Delete(new(secretscan_model.Scan))
		require.NoError(t, err)
		s := &scanner{ctx: t.Context(), scanCtx: t.Context(), repo: repo, cfg: setting.SecretScanningSettings(t.Context())}
		return countQueries(t, func() {
			requeue, err := s.scanText()
			require.NoError(t, err)
			require.False(t, requeue)
		})
	}
	for range 5 {
		newComment(t, newIssue(t, repo, "t", "x"), "y")
	}
	few := backfill()
	for range 40 {
		issue := newIssue(t, repo, "t", "x")
		newComment(t, issue, "y")
		newComment(t, issue, "z")
	}
	many := backfill()
	assert.LessOrEqual(t, many, few+2, "no query per issue (%d issues: %d queries, 45: %d)", 5, few, many)
}

// Data URIs are dropped before the cut, so a big inline image doesn't use up the limit; a token glued to the end of
// a payload is still scanned.
func TestScanTextDataURIBeforeCut(t *testing.T) {
	repo := enableText(t)
	defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<10)()
	after, glued := token("after-image"), token("glued")
	issue := newIssue(t, repo, "t", "![x](data:image/png;base64,"+strings.Repeat("QUJD", 2000)+")\n"+after+"\n![y](data:image/png;base64,"+strings.Repeat("QUJD", 300)+"_"+glued+")")
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
	assert.NotNil(t, alertFor(t, repo.ID, after), "the image didn't use up the limit")
	assert.NotNil(t, alertFor(t, repo.ID, glued))
}

// Text in an Issues or Pull requests unit that is off is not scanned, and its state is for readers of those units.
func TestScanTextUnitOff(t *testing.T) {
	repo := enableText(t)
	tok, prTok := token("unit-off"), token("unit-off-pr")
	issue := newIssue(t, repo, "t", tok)
	pr := newIssue(t, repo, "t", prTok)
	_, err := db.GetEngine(t.Context()).Table("issue").Where("id = ?", pr.ID).Update(map[string]any{"is_pull": true})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repo.ID, unit.TypePullRequests).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	repo = unittestRepo(t, repo.ID)

	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", pr.ID)))
	assert.Nil(t, alertFor(t, repo.ID, prTok), "the pull requests unit is off")
	_, err = scan(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Nil(t, alertFor(t, repo.ID, prTok), "the backfill skips it too")
	assert.NotNil(t, alertFor(t, repo.ID, tok), "the issues unit is on")
	_ = issue

	readsAll := func(unit.Type) bool { return true }
	readsIssues := func(u unit.Type) bool { return u == unit.TypeIssues }
	assert.True(t, TextStatusVisible(t.Context(), repo, readsAll))
	assert.True(t, TextStatusVisible(t.Context(), repo, readsIssues), "the pull requests unit is off: its text isn't scanned")
	assert.False(t, TextStatusVisible(t.Context(), repo, func(unit.Type) bool { return false }))
}

// A text that was cut or not scanned whole never marks the places past what was read as gone.
func TestScanTextCutKeepsPlaces(t *testing.T) {
	repo := enableText(t)
	tok := token("past-the-cut")
	issue := newIssue(t, repo, "t", strings.Repeat("x", 3000)+"\n"+tok)
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<10)()
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
	for _, l := range locationsOf(t, a.ID) {
		assert.Zero(t, l.RemovedUnix, "not read: not known to be gone")
	}
}

// Comments deleted without a notifier (a purged user's) are marked gone by the next backfill.
func TestScanTextOrphanPlaces(t *testing.T) {
	repo := enableText(t)
	tok := token("orphan")
	c := newComment(t, newIssue(t, repo, "t", "x"), tok)
	_, err := scan(t.Context(), repo.ID)
	require.NoError(t, err)
	a := alertFor(t, repo.ID, tok)
	require.NotNil(t, a)
	_, err = db.GetEngine(t.Context()).ID(c.ID).Delete(new(issues_model.Comment))
	require.NoError(t, err)
	_, err = secretscan_model.ResetScans(t.Context(), repo.ID)
	require.NoError(t, err)
	_, err = scan(t.Context(), repo.ID)
	require.NoError(t, err)
	locs := locationsOf(t, a.ID)
	require.Len(t, locs, 1)
	assert.NotZero(t, locs[0].RemovedUnix)
}

// The text backfill runs when the code scan fails.
func TestScanTextAfterCodeFailure(t *testing.T) {
	repo := enableText(t)
	tok := token("code-failed")
	newIssue(t, repo, "t", tok)
	path := repo.RepoPath()
	require.NoError(t, os.Rename(path, path+".away"))
	defer func() { require.NoError(t, os.Rename(path+".away", path)) }()
	_, _ = scan(t.Context(), repo.ID)
	assert.Equal(t, secretscan_model.StatusFailed, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
	assert.NotNil(t, alertFor(t, repo.ID, tok))
}

// One poster opens at most a quarter of the share of alerts text and pull refs have.
func TestScanTextPosterShare(t *testing.T) {
	repo := enableText(t)
	defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, 8)() // share 4, a poster 1
	var mine, theirs []string
	for i := range 3 {
		mine = append(mine, token(fmt.Sprintf("poster-a-%d", i)))
		theirs = append(theirs, token(fmt.Sprintf("poster-b-%d", i)))
	}
	issue := newIssue(t, repo, "t", strings.Join(mine, "\n")) // poster 2
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("i:%d:0", issue.ID)))
	assert.Len(t, alertsOf(t, repo.ID), 1)
	c := newComment(t, issue, strings.Join(theirs, "\n")) // poster 3
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("c:%d:0", c.ID)))
	assert.Len(t, alertsOf(t, repo.ID), 2, "another poster still has their share")
}

// A dismissed review's message is text a person wrote.
func TestScanTextDismissReview(t *testing.T) {
	repo := enableText(t)
	tok := token("dismissed")
	c := &issues_model.Comment{Type: issues_model.CommentTypeDismissReview, IssueID: newIssue(t, repo, "t", "x").ID, PosterID: 2, Content: tok}
	require.NoError(t, db.Insert(t.Context(), c))
	require.NoError(t, handleText(t.Context(), fmt.Sprintf("c:%d:0", c.ID)))
	assert.NotNil(t, alertFor(t, repo.ID, tok))
}

// Resetting one repository's text scan leaves the other repositories' rows alone.
func TestResetTextScansOneRepository(t *testing.T) {
	enableText(t)
	for _, id := range []int64{1, 2} {
		require.NoError(t, secretscan_model.Save(t.Context(), nil, &secretscan_model.Scan{RepoID: id, Kind: secretscan_model.KindIssue, ScannedTips: `{"i":5}`, Status: secretscan_model.StatusOK}))
	}
	other := scanOf(t, 2, secretscan_model.KindIssue)
	require.NoError(t, secretscan_model.ResetTextScans(t.Context(), 1))
	assert.Empty(t, scanOf(t, 1, secretscan_model.KindIssue).Status)
	after := scanOf(t, 2, secretscan_model.KindIssue)
	assert.Equal(t, secretscan_model.StatusOK, after.Status)
	assert.Equal(t, other.Version, after.Version)
	assert.JSONEq(t, `{"i":5}`, after.ScannedTips)
}
