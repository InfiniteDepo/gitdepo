// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createOrgCategory(t *testing.T, name string, position int) *organization.OrgCategory {
	t.Helper()
	c := &organization.OrgCategory{Name: name, Color: "#1e90ff", Position: position}
	require.NoError(t, organization.CreateOrgCategory(db.DefaultContext, c))
	return c
}

func setOrgCategory(t *testing.T, orgID, categoryID int64) {
	t.Helper()
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET category_id = ? WHERE id = ?", categoryID, orgID)
	require.NoError(t, err)
}

func orgCategoryOf(t *testing.T, orgID int64) int64 {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: orgID}).CategoryID
}

// AC2-AC5: admin CRUD, permissions, validation and delete.
func TestOrgCategoryAdmin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")
	user := loginUser(t, "user2")

	existing := createOrgCategory(t, "Existing", 5)
	for _, r := range []struct{ method, path string }{
		{"GET", ""},
		{"GET", "/new"},
		{"POST", "/new"},
		{"POST", "/settings"},
		{"GET", fmt.Sprintf("/%d", existing.ID)},
		{"POST", fmt.Sprintf("/%d", existing.ID)},
		{"POST", fmt.Sprintf("/%d/delete", existing.ID)},
	} {
		user.MakeRequest(t, NewRequestWithValues(t, r.method, "/admin/org-categories"+r.path, map[string]string{"name": "nope", "color": "#000000"}), http.StatusForbidden)
	}
	unittest.AssertNotExistsBean(t, &organization.OrgCategory{Name: "nope"})
	unittest.AssertExistsAndLoadBean(t, &organization.OrgCategory{ID: existing.ID})

	resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/org-categories/new", map[string]string{
		"name": "Payments", "description": "Money <b>matters</b>", "color": "#1E90FF", "position": "1",
	}), http.StatusSeeOther)
	assert.Equal(t, "/admin/org-categories", test.RedirectURL(resp))
	payments := unittest.AssertExistsAndLoadBean(t, &organization.OrgCategory{Name: "Payments"})
	assert.Equal(t, "#1e90ff", payments.Color)

	// invalid input re-renders with an error and stores nothing
	for _, values := range []map[string]string{
		{"name": "Payments", "color": "#000000"},               // name taken
		{"name": "Bad colour", "color": "red"},                 // not hex
		{"name": strings.Repeat("x", 101), "color": "#000000"}, // too long
		{"name": "Long", "color": "#000000", "description": strings.Repeat("x", 256)},
		{"name": "Far", "color": "#000000", "position": "1000001"},
	} {
		resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/org-categories/new", values), http.StatusOK)
		assert.NotEmpty(t, NewHTMLParser(t, resp.Body).Find(".ui.negative.message, .flash-error").Text(), "%v", values)
	}
	assert.Equal(t, 2, unittest.GetCount(t, &organization.OrgCategory{}))

	// list in (position, id) order, user text escaped
	resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/org-categories"), http.StatusOK)
	assert.NotContains(t, resp.Body.String(), "<b>matters</b>")
	var names []string
	NewHTMLParser(t, resp.Body).Find(".admin-setting-content table tbody tr td:nth-child(2)").Each(func(_ int, s *goquery.Selection) {
		names = append(names, strings.TrimSpace(s.Text()))
	})
	assert.Equal(t, []string{"Payments", "Existing"}, names)

	// edit
	link := fmt.Sprintf("/admin/org-categories/%d", payments.ID)
	admin.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
	admin.MakeRequest(t, NewRequest(t, "GET", "/admin/org-categories/9999"), http.StatusNotFound)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"name": "Existing", "color": "#000000"}), http.StatusOK)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", link, map[string]string{"name": "Payments", "color": "abc", "position": "9"}), http.StatusSeeOther)
	payments = unittest.AssertExistsAndLoadBean(t, &organization.OrgCategory{ID: payments.ID})
	assert.Equal(t, "#aabbcc", payments.Color)
	assert.Equal(t, 9, payments.Position)

	// deleting moves its organizations to "Other" and leaves the others alone
	setOrgCategory(t, 3, payments.ID)
	setOrgCategory(t, 6, payments.ID)
	setOrgCategory(t, 7, existing.ID)
	admin.MakeRequest(t, NewRequest(t, "POST", link+"/delete"), http.StatusOK)
	unittest.AssertNotExistsBean(t, &organization.OrgCategory{ID: payments.ID})
	assert.EqualValues(t, 0, orgCategoryOf(t, 3))
	assert.EqualValues(t, 0, orgCategoryOf(t, 6))
	assert.Equal(t, existing.ID, orgCategoryOf(t, 7))
}

// AC6-AC9: the category picker in the organization settings.
func TestOrgCategoryPicker(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")
	owner := loginUser(t, "user2") // owner of org3

	hasPicker := func(s *TestSession) bool {
		t.Helper()
		resp := s.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusOK)
		return NewHTMLParser(t, resp.Body).Find("#category_box").Length() > 0
	}
	post := func(s *TestSession, values map[string]string, status int) {
		t.Helper()
		values["name"] = "org3"
		values["visibility"] = "0"
		s.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", values), status)
	}

	// no categories: no picker, not even for a site admin
	assert.False(t, hasPicker(admin))

	cat := createOrgCategory(t, "Platform", 1)
	cat2 := createOrgCategory(t, "Data", 2)
	idStr := fmt.Sprint(cat.ID)

	// a site admin can always set and clear it
	assert.True(t, hasPicker(admin))
	post(admin, map[string]string{"category_shown": "true", "category_id": idStr}, http.StatusSeeOther)
	assert.Equal(t, cat.ID, orgCategoryOf(t, 3))
	post(admin, map[string]string{"category_shown": "true", "category_id": "9999"}, http.StatusBadRequest)
	assert.Equal(t, cat.ID, orgCategoryOf(t, 3))
	post(admin, map[string]string{"full_name": "kept"}, http.StatusSeeOther) // a post without the picker keeps it
	assert.Equal(t, cat.ID, orgCategoryOf(t, 3))

	// an owner can't while the setting is off, even with a crafted post
	assert.False(t, hasPicker(owner))
	post(owner, map[string]string{"category_shown": "true", "category_id": fmt.Sprint(cat2.ID)}, http.StatusSeeOther)
	assert.Equal(t, cat.ID, orgCategoryOf(t, 3))

	// the setting takes effect without a restart
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/org-categories/settings", map[string]string{"owners_can_assign": "on"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	defer func() {
		admin.MakeRequest(t, NewRequest(t, "POST", "/admin/org-categories/settings"), http.StatusSeeOther)
		bumpSettingsRevision(t)
	}()
	assert.True(t, hasPicker(owner))
	post(owner, map[string]string{"category_shown": "true", "category_id": fmt.Sprint(cat2.ID)}, http.StatusSeeOther)
	assert.Equal(t, cat2.ID, orgCategoryOf(t, 3))
	post(owner, map[string]string{"category_shown": "true", "category_id": "0"}, http.StatusSeeOther)
	assert.EqualValues(t, 0, orgCategoryOf(t, 3))
}

// exploreOrgs returns the organizations of an Explore page in order, with "#<header>" entries for the category
// headers, and the pager links.
func exploreOrgs(t *testing.T, s *TestSession, query string, status int) (items, pager []string) {
	t.Helper()
	req := NewRequest(t, "GET", "/explore/organizations"+query)
	if status != http.StatusOK {
		req.SetHeader("Accept", "text/html")
	}
	var body *goquery.Document
	if s == nil {
		body = NewHTMLParser(t, MakeRequest(t, req, status).Body).doc
	} else {
		body = NewHTMLParser(t, s.MakeRequest(t, req, status).Body).doc
	}
	body.Find(".page-content .flex-list").First().Children().Each(func(_ int, sel *goquery.Selection) {
		if sel.Is("h3.org-category-header") {
			items = append(items, "#"+strings.TrimSpace(sel.Text()))
		} else if href, ok := sel.Find(".flex-item-title a").Attr("href"); ok {
			items = append(items, strings.TrimPrefix(href, "/"))
		}
	})
	body.Find(".pagination a.item[href]").Each(func(_ int, sel *goquery.Selection) {
		pager = append(pager, sel.AttrOr("href", ""))
	})
	return items, pager
}

// AC10-AC14: Explore groups and filters.
func TestOrgCategoryExplore(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.UI.ExploreDefaultSort, "alphabetically")()
	admin := loginUser(t, "user1")

	// AC14: without categories nothing changes
	plain, _ := exploreOrgs(t, nil, "?category=whatever", http.StatusOK)
	for _, item := range plain {
		assert.False(t, strings.HasPrefix(item, "#"))
	}

	a := createOrgCategory(t, "Alpha", 2)
	b := createOrgCategory(t, "Beta", 1)
	setOrgCategory(t, 3, a.ID)
	setOrgCategory(t, 6, b.ID)
	setOrgCategory(t, 19, b.ID)
	setOrgCategory(t, 23, b.ID) // private
	setOrgCategory(t, 7, a.ID)
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = 7", true)
	require.NoError(t, err)
	setOrgCategory(t, 17, a.ID)
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET trashed_unix = 1 WHERE id = 17")
	require.NoError(t, err)

	// grouped: categories by position, "Other" last, the sort within each group
	items, _ := exploreOrgs(t, nil, "", http.StatusOK)
	require.Greater(t, len(items), 6)
	assert.Equal(t, []string{"#Beta", "org19", "org6", "#Alpha", "org3", "#Other"}, items[:6])
	assert.Len(t, items, len(plain)+3-2, "three headers, minus the archived and the trashed org")
	for _, hidden := range []string{"org7", "org17", "privated_org", "limited_org"} {
		assert.NotContains(t, items, hidden)
	}
	items, _ = exploreOrgs(t, admin, "?sort=reversealphabetically", http.StatusOK)
	assert.Equal(t, []string{"#Beta", "privated_org", "org6", "org19", "#Alpha", "org3", "#Other"}, items[:7])

	// filters
	items, _ = exploreOrgs(t, nil, fmt.Sprintf("?category=%d", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org3"}, items)
	items, _ = exploreOrgs(t, admin, fmt.Sprintf("?category=%d&archived=true", a.ID), http.StatusOK)
	assert.Equal(t, []string{"org3", "org7"}, items)
	items, _ = exploreOrgs(t, nil, fmt.Sprintf("?category=%d", b.ID), http.StatusOK)
	assert.Equal(t, []string{"org19", "org6"}, items)
	items, _ = exploreOrgs(t, nil, "?category=other", http.StatusOK)
	assert.Len(t, items, len(plain)-5)
	assert.NotContains(t, items, "org3")
	exploreOrgs(t, nil, "?category=9999", http.StatusNotFound)
	exploreOrgs(t, nil, "?category=abc", http.StatusNotFound)

	// sort, search and archived links keep the filter
	resp := MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/explore/organizations?category=%d", a.ID)), http.StatusOK)
	doc := NewHTMLParser(t, resp.Body)
	sortHref, _ := doc.Find(`#search-sort-dropdown a.active`).Attr("href")
	assert.Equal(t, fmt.Sprintf("?sort=alphabetically&q=&category=%d", a.ID), sortHref)
	assert.Equal(t, fmt.Sprint(a.ID), doc.Find(`form.list-header-search input[name="category"]`).AttrOr("value", ""))
	archivedHref, _ := doc.Find(`a[href^="?archived="]`).Attr("href")
	assert.Equal(t, fmt.Sprintf("?archived=true&category=%d", a.ID), archivedHref)

	// the opener names the current filter, and the current item is active and focused on open
	for _, c := range []struct{ query, label, active string }{
		{"", "Category", "All"},
		{fmt.Sprintf("?category=%d", a.ID), "Category: Alpha", "Alpha"},
		{"?category=other", "Category: Other", "Other"},
	} {
		doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/explore/organizations"+c.query), http.StatusOK).Body)
		assert.Equal(t, c.label, strings.TrimSpace(doc.Find(`[commandfor="search-category-dropdown"]`).Text()), c.query)
		assert.Equal(t, c.active, strings.TrimSpace(doc.Find(`#search-category-dropdown a.active[autofocus]`).Text()), c.query)
		assert.Equal(t, 1, doc.Find(`#search-category-dropdown a[autofocus]`).Length(), c.query)
	}

	// paging: a group continued on the next page repeats its header, and the pages join up to the full list
	full, _ := exploreOrgs(t, admin, "", http.StatusOK)
	defer test.MockVariableValue(&setting.UI.ExplorePagingNum, 2)()
	var joined []string
	header := ""
	for page := 1; page < 20; page++ {
		items, _ := exploreOrgs(t, admin, fmt.Sprintf("?page=%d", page), http.StatusOK)
		if len(items) == 0 {
			break
		}
		require.True(t, strings.HasPrefix(items[0], "#"), "page %d starts with a header: %v", page, items)
		if page == 2 {
			assert.Equal(t, []string{"#Beta", "privated_org", "#Alpha", "org3"}, items)
		}
		for _, item := range items {
			if strings.HasPrefix(item, "#") {
				if item == header {
					continue
				}
				header = item
			}
			joined = append(joined, item)
		}
	}
	assert.Equal(t, full, joined)

	_, pager := exploreOrgs(t, admin, "?category=other&archived=true", http.StatusOK)
	require.NotEmpty(t, pager)
	for _, href := range pager {
		assert.Contains(t, href, "category=other")
		assert.Contains(t, href, "archived=true")
	}
}

// AC15: the Explore query count doesn't grow with organizations or categories.
func TestOrgCategoryExploreQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	count := func(n int) []int64 {
		for i := range n {
			org := &organization.Organization{Name: fmt.Sprintf("cat-org-%d-%d", n, i)}
			require.NoError(t, organization.CreateOrganization(ctx, org, owner))
			c := createOrgCategory(t, fmt.Sprintf("cat-%d-%d", n, i), i)
			setOrgCategory(t, org.ID, c.ID)
		}
		var counts []int64
		for _, l := range []string{"/explore/organizations", "/explore/organizations?category=other"} {
			MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) // generated avatars are saved once
			counts = append(counts, stableQueryCount(t, func() { MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) }))
		}
		return counts
	}
	assert.Equal(t, count(2), count(4))
}
