// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func overviewDoc(t *testing.T, session *TestSession) *HTMLDoc {
	t.Helper()
	return NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions/overview"), http.StatusOK).Body)
}

func overviewRows(doc *HTMLDoc, section, attr string) []string {
	var rows []string
	doc.Find(section + " tbody tr").Each(func(_ int, s *goquery.Selection) {
		rows = append(rows, s.AttrOr("data-repo", "")+" "+s.AttrOr(attr, ""))
	})
	return rows
}

func TestOrgActionsOverviewPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	runs := prepareOrgRuns(t)
	ctx := db.DefaultContext
	_, err := db.GetEngine(ctx).Exec("UPDATE repository SET default_branch = 'main' WHERE id IN (3, 5, 32)")
	require.NoError(t, err)
	// repo3's main is broken; one queued job each on repo3 (a runner exists) and repo5 (none matches)
	bad := &actions_model.ActionRun{
		Title: "bad", RepoID: 3, OwnerID: 3, WorkflowID: "bad.yaml", Index: 500, TriggerUserID: 2, Ref: "refs/heads/main",
		Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusFailure,
	}
	require.NoError(t, db.Insert(ctx, bad))
	for _, job := range []*actions_model.ActionRunJob{
		{RunID: runs[3].ID, RepoID: 3, OwnerID: 3, Name: "with-runner", RunsOn: []string{"linux"}},
		{RunID: runs[5].ID, RepoID: 5, OwnerID: 3, Name: "no-runner", RunsOn: []string{"gpu"}},
	} {
		job.Handle, job.JobID, job.Status = "overview-"+job.Name, actions_model.JobIdentifier(job.Name), actions_model.StatusWaiting
		require.NoError(t, db.Insert(ctx, job))
	}
	require.NoError(t, db.Insert(ctx, &actions_model.ActionRunner{
		UUID: "00000000-0000-0000-0000-000000000064", Name: "r", TokenHash: "overviewhash", AgentLabels: []string{"linux"}, LastOnline: timeutil.TimeStampNow(),
	}))

	t.Run("owner", func(t *testing.T) {
		doc := overviewDoc(t, loginUser(t, "user2"))
		card := func(name string) string { return doc.Find(`[data-card="` + name + `"] .value`).Text() }
		assert.Equal(t, "4", card("runs-24h"))
		assert.Equal(t, "4", card("runs-7d"))
		assert.Equal(t, "50%", card("failure-rate")) // repo5 and bad.yaml failed, repo3 and repo21 succeeded
		assert.Equal(t, "2", card("queued"))
		assert.Equal(t, "n/a", card("avg-queue"))
		// the cards are ui segments: Fomantic's statistic module isn't built
		assert.Zero(t, doc.Find(".ui.statistics, .statistic").Length())
		assert.Equal(t, 6, doc.Find(".org-overview-cards > .ui.segment[data-card]").Length())
		assert.Equal(t, []string{"org3/repo3 " + fmt.Sprint(bad.ID)}, overviewRows(doc, ".org-failing-now", "data-run"))
		queue := doc.Find(".org-queue tbody tr")
		assert.Equal(t, 2, queue.Length())
		assert.Equal(t, "yes", queue.Filter(`[data-repo="org3/repo3"]`).AttrOr("data-runner", ""))
		assert.Equal(t, "no", queue.Filter(`[data-repo="org3/repo5"]`).AttrOr("data-runner", ""))
		assert.Contains(t, queue.Filter(`[data-repo="org3/repo5"]`).Text(), "gpu")
	})

	t.Run("a member sees only what they can read, in the cards too", func(t *testing.T) {
		// user4 reads repo3 and the public repo21, not repo5
		doc := overviewDoc(t, loginUser(t, "user4"))
		assert.Equal(t, "3", doc.Find(`[data-card="runs-7d"] .value`).Text())
		assert.Equal(t, "1", doc.Find(`[data-card="queued"] .value`).Text())
		assert.Equal(t, []string{"org3/repo3 yes"}, overviewRows(doc, ".org-queue", "data-runner"))
	})

	t.Run("who may open it", func(t *testing.T) {
		loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions/overview"), http.StatusNotFound) // not a member
		MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions/overview"), http.StatusSeeOther)
		assert.Equal(t, "2", overviewDoc(t, loginUser(t, "user1")).Find(`[data-card="queued"] .value`).Text())
	})

	t.Run("the org menu shows the tab to a site admin who is not a member", func(t *testing.T) {
		resp := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK)
		assert.Equal(t, 1, NewHTMLParser(t, resp.Body).Find(`.organization .menu a.item[href$="/org3/actions"]`).Length(), "owner")
		resp = loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK)
		assert.Equal(t, 1, NewHTMLParser(t, resp.Body).Find(`.organization .menu a.item[href$="/org3/actions"]`).Length())
		resp = loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK)
		assert.Zero(t, NewHTMLParser(t, resp.Body).Find(`.organization .menu a.item[href$="/org3/actions"]`).Length())
	})
}

// The number of queries doesn't depend on the runs, jobs or actors shown.
func TestOrgActionsOverviewQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	runs := prepareOrgRuns(t)
	ctx := db.DefaultContext
	_, err := db.GetEngine(ctx).Exec("UPDATE repository SET default_branch = 'main' WHERE id IN (3, 5, 32)")
	require.NoError(t, err)
	session := loginUser(t, "user2")
	count := func() int64 {
		return stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions/overview"), http.StatusOK) })
	}
	add := func(i int) {
		repoID := []int64{3, 5, 32}[i%3]
		require.NoError(t, db.Insert(ctx, &actions_model.ActionRun{
			Title: "more", RepoID: repoID, OwnerID: 3, WorkflowID: fmt.Sprintf("more%d.yaml", i), Index: int64(1000 + i), TriggerUserID: int64(1 + i%4),
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusFailure,
		}))
		require.NoError(t, db.Insert(ctx, &actions_model.ActionRunJob{
			RunID: runs[repoID].ID, RepoID: repoID, OwnerID: 3, Name: "j", Handle: fmt.Sprintf("qc-%d", i), JobID: "j", RunsOn: []string{fmt.Sprintf("l%d", i)}, Status: actions_model.StatusWaiting,
		}))
	}
	add(0)  // an empty list skips its queries
	count() // once, as ToUser saves a generated avatar the first time it renders a user
	one := count()
	for i := 1; i < 20; i++ {
		add(i)
	}
	count() // new actors
	assert.Equal(t, one, count())
}
