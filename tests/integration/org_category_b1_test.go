// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exploreRepos returns the "owner/name" of the repositories on an Explore page, and the page.
func exploreRepos(t *testing.T, s *TestSession, query string, status int) ([]string, *goquery.Document) {
	t.Helper()
	req := NewRequest(t, "GET", "/explore/repos"+query)
	if status != http.StatusOK {
		req.SetHeader("Accept", "text/html")
	}
	var doc *goquery.Document
	if s == nil {
		doc = NewHTMLParser(t, MakeRequest(t, req, status).Body).doc
	} else {
		doc = NewHTMLParser(t, s.MakeRequest(t, req, status).Body).doc
	}
	var repos []string
	doc.Find(".page-content .flex-list .flex-item .flex-item-title a.name:last-of-type").Each(func(_ int, sel *goquery.Selection) {
		repos = append(repos, strings.TrimPrefix(sel.AttrOr("href", ""), "/"))
	})
	return repos, doc
}

// AC1-AC6: the Explore repositories category filter.
func TestOrgCategoryExploreRepos(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.UI.ExplorePagingNum, 1000)()
	admin := loginUser(t, "user1")

	// AC1: without categories nothing changes
	plain, doc := exploreRepos(t, nil, "", http.StatusOK)
	assert.Zero(t, doc.Find("#repo-search-category").Length())
	ignored, _ := exploreRepos(t, nil, "?category=whatever", http.StatusOK)
	assert.Equal(t, plain, ignored)
	// the relevancy note renders its link without the category data
	_, doc = exploreRepos(t, nil, "?only_show_relevant=1", http.StatusOK)
	assert.Equal(t, 1, doc.Find(".explore-relevancy-note a").Length())
	assert.Equal(t, 1, doc.Find("footer").Length(), "the page is rendered to its end")

	a := createOrgCategory(t, "Alpha", 2)
	b := createOrgCategory(t, "Beta", 1)
	setOrgCategory(t, 3, a.ID)
	setOrgCategory(t, 19, b.ID)

	// AC2, AC4: a category lists only its organizations' repositories, within the usual visibility
	repos, _ := exploreRepos(t, nil, fmt.Sprintf("?category=%d", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org3/repo21"}, repos)
	// for a signed-in user: exactly their own list, narrowed to the category
	user4 := loginUser(t, "user4")
	all, _ := exploreRepos(t, user4, "", http.StatusOK)
	repos, _ = exploreRepos(t, user4, fmt.Sprintf("?category=%d", a.ID), http.StatusOK)
	assert.Equal(t, slices.DeleteFunc(all, func(r string) bool { return !strings.HasPrefix(r, "org3/") }), repos)
	assert.NotContains(t, repos, "org3/repo5")
	repos, _ = exploreRepos(t, admin, fmt.Sprintf("?category=%d&sort=alphabetically", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org3/repo21", "org3/repo3", "org3/repo5"}, repos)
	repos, _ = exploreRepos(t, nil, fmt.Sprintf("?category=%d", b.ID), http.StatusOK)
	assert.Equal(t, []string{"org19/big_test_public_mirror_6"}, repos)
	other, _ := exploreRepos(t, nil, "?category=other", http.StatusOK)
	assert.Len(t, other, len(plain)-2)
	assert.Contains(t, other, "user2/repo1")
	assert.NotContains(t, other, "org3/repo21")
	exploreRepos(t, nil, "?category=9999", http.StatusNotFound)
	exploreRepos(t, nil, "?category=abc", http.StatusNotFound)

	// AC3: combines with the topic filter
	for _, id := range []int64{1, 32, 27} {
		require.NoError(t, repo_model.SaveTopics(db.DefaultContext, id, "shared-topic"))
	}
	repos, _ = exploreRepos(t, nil, "?q=shared-topic&topic=1", http.StatusOK)
	assert.Len(t, repos, 3)
	repos, doc = exploreRepos(t, nil, fmt.Sprintf("?q=shared-topic&topic=1&category=%d", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org3/repo21"}, repos)
	repos, _ = exploreRepos(t, nil, "?q=shared-topic&topic=1&category=other", http.StatusOK)
	assert.Equal(t, []string{"user2/repo1"}, repos)

	// AC5: the form, the topic links and the opener keep and name the category
	assert.Equal(t, "true", doc.Find(`#repo-search-form input[name="topic"]`).AttrOr("value", ""))
	checked := doc.Find(`#repo-search-category input[name="category"][checked]`)
	assert.Equal(t, fmt.Sprint(a.ID), checked.AttrOr("value", ""))
	assert.True(t, checked.Parent().HasClass("active"))
	assert.Equal(t, "Category: Alpha", strings.TrimSpace(doc.Find("#repo-search-category > .text").Text()))
	assert.Equal(t, fmt.Sprintf("/explore/repos?q=shared-topic&topic=1&category=%d", a.ID), doc.Find(".repo-topics a").AttrOr("href", ""))
	// the "show all repositories" link of the relevancy note keeps it too; Sort and Filter are radios of the same form
	_, doc = exploreRepos(t, nil, fmt.Sprintf("?only_show_relevant=1&category=%d", a.ID), http.StatusOK)
	assert.Contains(t, doc.Find(".explore-relevancy-note a").AttrOr("href", ""), fmt.Sprintf("&category=%d", a.ID))
	assert.Equal(t, 1, doc.Find(`#repo-search-form input[name="category"][checked]`).Length())
	assert.Positive(t, doc.Find(`#repo-search-form input[name="sort"]`).Length())
	_, doc = exploreRepos(t, nil, "?category=other", http.StatusOK)
	assert.Equal(t, "Category: Other", strings.TrimSpace(doc.Find("#repo-search-category > .text").Text()))
	_, doc = exploreRepos(t, nil, "", http.StatusOK)
	assert.Equal(t, "Category", strings.TrimSpace(doc.Find("#repo-search-category > .text").Text()))
	assert.Empty(t, doc.Find(`#repo-search-category input[name="category"][checked]`).AttrOr("value", "none"))

	defer test.MockVariableValue(&setting.UI.ExplorePagingNum, 2)()
	_, doc = exploreRepos(t, nil, "?category=other", http.StatusOK)
	pager := doc.Find(".pagination a.item[href]")
	require.Positive(t, pager.Length())
	pager.Each(func(_ int, sel *goquery.Selection) {
		assert.Contains(t, sel.AttrOr("href", ""), "category=other")
	})

	// AC6: other pages with the repository search are unchanged
	resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?category=9999"), http.StatusOK)
	assert.Zero(t, NewHTMLParser(t, resp.Body).Find("#repo-search-category").Length())
	resp = MakeRequest(t, NewRequest(t, "GET", "/user2?category=9999"), http.StatusOK)
	assert.Zero(t, NewHTMLParser(t, resp.Body).Find("#repo-search-category").Length())
}

// dashboardSwitcher returns the dashboard context switcher's organizations, with "#<header>" entries,
// the page, the first entry (the personal account, "*" appended when marked active) and the names of the active organizations.
func dashboardSwitcher(t *testing.T, s *TestSession) (items []string, body, personal string, active []string) {
	t.Helper()
	return dashboardSwitcherAt(t, s, "/")
}

func dashboardSwitcherAt(t *testing.T, s *TestSession, path string) (items []string, body, personal string, active []string) {
	t.Helper()
	resp := s.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK)
	body = resp.Body.String()
	NewHTMLParser(t, bytes.NewBufferString(body)).Find(".context.user.overflow.menu .scrolling.menu.items").First().Children().Each(func(i int, sel *goquery.Selection) {
		switch {
		case i == 0:
			personal = strings.TrimSpace(sel.Find(".truncated-item-name").Text())
			if sel.HasClass("active") {
				personal += "*"
			}
		case sel.Is(".header"):
			items = append(items, "#"+strings.TrimSpace(sel.Text()))
		case sel.Is("a.item[title]"):
			items = append(items, sel.AttrOr("title", ""))
			if sel.HasClass("active") {
				active = append(active, sel.AttrOr("title", ""))
			}
		}
	})
	return items, body, personal, active
}

// AC7-AC9: the dashboard switcher and "My organizations" tab are grouped by category.
func TestOrgCategoryDashboard(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	session := loginUser(t, "user5")

	// AC9: without categories, no headers and the name order
	plain, body, personal, _ := dashboardSwitcher(t, session)
	require.Greater(t, len(plain), 3)
	assert.True(t, slices.IsSorted(plain))
	assert.Equal(t, "user5*", personal)
	assert.NotContains(t, body, "'category':")

	orgs, err := organization.GetUserOrgsList(db.DefaultContext, user5)
	require.NoError(t, err)
	a := createOrgCategory(t, "Alpha", 2)
	b := createOrgCategory(t, "Beta", 1)
	setOrgCategory(t, orgs[0].ID, a.ID)
	setOrgCategory(t, orgs[1].ID, b.ID)
	setOrgCategory(t, orgs[2].ID, a.ID)

	// AC7: categories by position, "Other" last, names in order within each group
	items, body, personal, _ := dashboardSwitcher(t, session)
	want := []string{"#Beta", orgs[1].Name, "#Alpha", orgs[0].Name, orgs[2].Name, "#Other"}
	assert.Equal(t, want, items[:6])
	assert.Equal(t, "user5*", personal, "the personal entry stays first, active on the own dashboard")
	assert.Equal(t, plain[3:], items[6:])

	// AC8: the "My organizations" tab gets the same order and the category of each organization
	last := -1
	for _, name := range []string{orgs[1].Name, orgs[0].Name, orgs[2].Name, plain[3]} {
		i := strings.Index(body, fmt.Sprintf("{'name': %q", name))
		require.Greater(t, i, last, name)
		last = i
	}
	assert.Contains(t, body, fmt.Sprintf("{'name': %q, ", orgs[1].Name))
	assert.Contains(t, body, `'category': {'name': "Beta", 'color': "#1e90ff"}`)
	assert.Contains(t, body, `'category': {'name': "Other", 'color': ''}`)

	// archived organizations stay hidden from the switcher
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", true, orgs[1].ID)
	require.NoError(t, err)
	items, _, _, _ = dashboardSwitcher(t, session)
	assert.Equal(t, []string{"#Alpha", orgs[0].Name, orgs[2].Name, "#Other"}, items[:4])

	// the active mark stays on an organization's own dashboard, the personal entry is first and unmarked
	items, _, personal, active := dashboardSwitcherAt(t, session, "/org/"+orgs[0].Name+"/dashboard")
	assert.Equal(t, "user5", personal)
	assert.Equal(t, []string{orgs[0].Name}, active)
	assert.Contains(t, items, "#Alpha")
}

// stableQueryCount reads the queries of f until two readings in a row agree:
// countQueries counts the queries of every goroutine.
func stableQueryCount(t *testing.T, f func()) int64 {
	t.Helper()
	var readings []int64
	for len(readings) < 6 {
		readings = append(readings, countQueries(t, f))
		if n := len(readings); n > 1 && readings[n-1] == readings[n-2] {
			return readings[n-1]
		}
	}
	require.FailNow(t, "query count doesn't settle", "%v", readings)
	return 0
}

// AC11: the dashboard and Explore repositories query counts don't grow with organizations, repositories or categories.
func TestOrgCategoryB1Queries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	session := loginUser(t, "user2")
	c := createOrgCategory(t, "Counted", 0)
	stable := func(f func()) int64 { return stableQueryCount(t, f) }

	count := func(n int) []int64 {
		for i := range n {
			org := &organization.Organization{Name: fmt.Sprintf("b1-org-%d-%d", n, i)}
			require.NoError(t, organization.CreateOrganization(ctx, org, owner))
			setOrgCategory(t, org.ID, createOrgCategory(t, fmt.Sprintf("b1-cat-%d-%d", n, i), i+1).ID)
			repoOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
			_, err := repo_service.CreateRepositoryDirectly(ctx, owner, repoOwner, repo_service.CreateRepoOptions{Name: fmt.Sprintf("b1-repo-%d-%d", n, i)})
			require.NoError(t, err)
		}
		setOrgCategory(t, 3, c.ID)
		var counts []int64
		for _, l := range []string{"/", fmt.Sprintf("/explore/repos?category=%d", c.ID), "/explore/repos?category=other"} {
			session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) // generated avatars are saved once
			counts = append(counts, stable(func() { session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) }))
		}
		return counts
	}
	assert.Equal(t, count(2), count(4))
}

// adminOrgs returns the organization names of an admin organizations page, and the page.
func adminOrgs(t *testing.T, s *TestSession, query string, status int) ([]string, *goquery.Document) {
	t.Helper()
	doc := NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", "/admin/orgs"+query), status).Body).doc
	var names []string
	doc.Find(".admin-setting-content table tbody tr td:nth-child(2) > a").Each(func(_ int, sel *goquery.Selection) {
		names = append(names, sel.Text())
	})
	return names, doc
}

// AC10: the admin organizations list has a category filter.
func TestOrgCategoryAdminOrgs(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.UI.Admin.OrgPagingNum, 1000)()
	admin := loginUser(t, "user1")

	plain, doc := adminOrgs(t, admin, "?category=whatever", http.StatusOK)
	assert.Zero(t, doc.Find("#search-category-dropdown").Length())

	a := createOrgCategory(t, "Alpha", 1)
	setOrgCategory(t, 3, a.ID)
	setOrgCategory(t, 6, a.ID)

	names, doc := adminOrgs(t, admin, fmt.Sprintf("?category=%d&sort=alphabetically", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org3", "org6"}, names)
	assert.Equal(t, "Category: Alpha", strings.TrimSpace(doc.Find(`[commandfor="search-category-dropdown"]`).Text()))
	assert.Equal(t, "Alpha", strings.TrimSpace(doc.Find("#search-category-dropdown a.active").Text()))
	assert.Equal(t, fmt.Sprint(a.ID), doc.Find(`form input[name="category"]`).AttrOr("value", ""))
	doc.Find(".admin-setting-content .ui.dropdown .menu a.item").Each(func(_ int, sel *goquery.Selection) {
		assert.Contains(t, sel.AttrOr("href", ""), fmt.Sprintf("&category=%d", a.ID))
	})
	names, _ = adminOrgs(t, admin, fmt.Sprintf("?category=%d&q=org6", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org6"}, names)
	other, _ := adminOrgs(t, admin, "?category=other", http.StatusOK)
	assert.Len(t, other, len(plain)-2)
	assert.NotContains(t, other, "org3")
	adminOrgs(t, admin, "?category=9999", http.StatusNotFound)

	defer test.MockVariableValue(&setting.UI.Admin.OrgPagingNum, 1)()
	_, doc = adminOrgs(t, admin, fmt.Sprintf("?category=%d", a.ID), http.StatusOK)
	pager := doc.Find(".pagination a.item[href]")
	require.Positive(t, pager.Length())
	pager.Each(func(_ int, sel *goquery.Selection) {
		assert.Contains(t, sel.AttrOr("href", ""), fmt.Sprintf("category=%d", a.ID))
	})

	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/admin/orgs?category=%d", a.ID)), http.StatusForbidden)
}

// AC4: a category only narrows what the viewer may see already; nothing leaks through it.
func TestOrgCategoryExploreNoLeak(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.UI.ExplorePagingNum, 1000)()
	cat := createOrgCategory(t, "Leaky", 1)
	for _, id := range []int64{3, 22, 23} {
		setOrgCategory(t, id, cat.ID)
	}
	query := fmt.Sprintf("?category=%d", cat.ID)
	owners := []string{"org3/", "limited_org/", "privated_org/"}
	inCategory := func(repos []string) []string {
		return slices.DeleteFunc(slices.Clone(repos), func(r string) bool {
			return !slices.ContainsFunc(owners, func(o string) bool { return strings.HasPrefix(r, o) })
		})
	}
	// the category list is exactly the viewer's own list, narrowed to the category
	same := func(s *TestSession) []string {
		t.Helper()
		all, _ := exploreRepos(t, s, "", http.StatusOK)
		got, _ := exploreRepos(t, s, query, http.StatusOK)
		assert.ElementsMatch(t, inCategory(all), got)
		return got
	}

	// anonymous: no private or limited organization, no private repository
	anon := same(nil)
	assert.Equal(t, []string{"org3/repo21"}, anon)

	// a signed-in outsider sees the limited organization's public repository, not the private organization's
	user10 := loginUser(t, "user10")
	got := same(user10)
	assert.Contains(t, got, "limited_org/public_repo_on_limited_org")
	assert.NotContains(t, got, "limited_org/private_repo_on_limited_org")
	assert.NotContains(t, got, "privated_org/public_repo_on_private_org")
	assert.NotContains(t, got, "privated_org/private_repo_on_private_org")

	// a restricted user sees none of them without access
	assert.Empty(t, same(loginUser(t, "user29")))

	// a member of an organization that requires two-factor, without it, sees what an outsider sees
	member := loginUser(t, "user4") // a team member
	before, _ := exploreRepos(t, member, query, http.StatusOK)
	require.Contains(t, before, "org3/repo3")
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
	require.NoError(t, err)
	_, err = db.GetEngine(db.DefaultContext).Exec("DELETE FROM two_factor WHERE uid = 4")
	require.NoError(t, err)
	_, err = db.GetEngine(db.DefaultContext).Exec("DELETE FROM webauthn_credential WHERE user_id = 4")
	require.NoError(t, err)
	blocked := same(member)
	assert.NotContains(t, blocked, "org3/repo3")
	assert.NotContains(t, blocked, "org3/repo5")

	// a trashed repository is gone
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 32")
	require.NoError(t, err)
	for _, s := range []*TestSession{nil, user10, loginUser(t, "user1")} {
		got, _ := exploreRepos(t, s, query, http.StatusOK)
		assert.NotContains(t, got, "org3/repo21")
	}
}

// AC11: the admin organizations list costs at most one query more than without categories, however many organizations have one.
func TestOrgCategoryAdminOrgsQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.UI.Admin.OrgPagingNum, 1000)()
	ctx := db.DefaultContext
	admin := loginUser(t, "user1")
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	count := func(url string) int64 {
		admin.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK) // generated avatars are saved once
		return stableQueryCount(t, func() { admin.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK) })
	}
	baseline := count("/admin/orgs")

	categorised := func(n int) (int64, int64) {
		t.Helper()
		for i := range n {
			org := &organization.Organization{Name: fmt.Sprintf("ac11-org-%d-%d", n, i)}
			require.NoError(t, organization.CreateOrganization(ctx, org, owner))
			setOrgCategory(t, org.ID, createOrgCategory(t, fmt.Sprintf("ac11-cat-%d-%d", n, i), i).ID)
		}
		c := createOrgCategory(t, fmt.Sprintf("ac11-filter-%d", n), 0)
		setOrgCategory(t, 3, c.ID)
		return count("/admin/orgs"), count(fmt.Sprintf("/admin/orgs?category=%d", c.ID))
	}
	list2, filtered2 := categorised(2)
	list4, filtered4 := categorised(4)
	assert.Equal(t, list2, list4)
	assert.Equal(t, filtered2, filtered4)
	assert.LessOrEqual(t, filtered4, baseline+1)
	assert.LessOrEqual(t, list4, baseline+1)
}
