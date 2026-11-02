// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrgStorageOverview(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	// org3 owns repo3 and repo5 (both private) and repo21
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 3, 3<<20, 1<<20, 0))
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 5, 1<<20, 4<<20, 0))
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 32, 2<<20, 0, 0))
	defer test.MockVariableValue(&setting.UI.User.RepoPagingNum, 50)()
	const url = "/org/org3/settings/storage_overview"

	rows := func(t *testing.T, session *TestSession, url string) [][]string {
		t.Helper()
		resp := session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK)
		var rows [][]string
		NewHTMLParser(t, resp.Body).Find(".org-setting-content table tbody tr").Each(func(_ int, tr *goquery.Selection) {
			rows = append(rows, tr.Find("td").Map(func(_ int, td *goquery.Selection) string { return td.Text() }))
		})
		return rows
	}

	t.Run("Owner", func(t *testing.T) {
		owner := loginUser(t, "user2")
		got := rows(t, owner, url)
		assert.Len(t, got, unittest.GetCount(t, &repo_model.Repository{OwnerID: 3}))
		assert.Equal(t, []string{"repo5", "1 MiB", "4 MiB", "5 MiB", "45.5%"}, got[0])
		assert.Equal(t, []string{"repo3", "3 MiB", "1 MiB", "4 MiB", "36.4%"}, got[1])
		assert.Equal(t, []string{"repo21", "2 MiB", "0 B", "2 MiB", "18.2%"}, got[2])

		got = rows(t, owner, url+"?sort=reversegitsize")
		assert.Equal(t, "repo3", got[0][0])
		got = rows(t, owner, url+"?sort=alphabetically")
		assert.Equal(t, "repo5", got[0][0], "only size keys sort")

		defer test.MockVariableValue(&setting.UI.User.RepoPagingNum, 1)()
		got = rows(t, owner, url+"?page=2")
		assert.Equal(t, [][]string{{"repo3", "3 MiB", "1 MiB", "4 MiB", "36.4%"}}, got)
	})

	t.Run("TotalsMatchSiteReport", func(t *testing.T) {
		totals, err := repo_model.GetOwnerStorageTotals(db.DefaultContext, 3)
		require.NoError(t, err)
		owners, _, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{})
		require.NoError(t, err)
		for _, o := range owners {
			if o.OwnerID == 3 {
				assert.Equal(t, o.StorageStats, totals)
				return
			}
		}
		t.Fatal("org3 is missing from the site report")
	})

	t.Run("Quota", func(t *testing.T) {
		owner := loginUser(t, "user2")
		resp := owner.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK)
		htmlDoc := NewHTMLParser(t, resp.Body)
		assert.Zero(t, htmlDoc.Find(".org-setting-content details.stats").Length(), "no quota block without quotas")
		assert.Equal(t, 1, htmlDoc.Find(".org-setting-content a[href='/org3/repo3']").Length())
		assert.Equal(t, 1, htmlDoc.Find(".menu a.active[href$='/settings/storage_overview']").Length())

		defer test.MockVariableValue(&setting.Quota.Enabled, true)()
		resp = owner.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK)
		htmlDoc = NewHTMLParser(t, resp.Body)
		assert.Positive(t, htmlDoc.Find(".org-setting-content details.stats").Length())
		assert.Equal(t, 1, htmlDoc.Find(".org-setting-content a[href='/org3/repo3']").Length())
	})

	t.Run("Admin", func(t *testing.T) {
		assert.Len(t, rows(t, loginUser(t, "user1"), url), 3)
	})

	t.Run("Refused", func(t *testing.T) {
		loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", url), http.StatusNotFound) // org3 member, not owner
		loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", url), http.StatusNotFound) // member of other orgs only
		MakeRequest(t, NewRequest(t, "GET", url), http.StatusSeeOther)                       // signed out
	})

	t.Run("UserPageStillNeedsQuota", func(t *testing.T) {
		loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user/settings/storage_overview"), http.StatusNotFound)
	})
}
