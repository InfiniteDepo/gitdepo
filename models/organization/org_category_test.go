// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization_test

import (
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrgCategoryCRUD(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	c := &organization.OrgCategory{Name: "  Payments ", Description: " money ", Color: "ABC", Position: 2}
	require.NoError(t, organization.CreateOrgCategory(ctx, c))
	assert.Equal(t, "Payments", c.Name)
	assert.Equal(t, "money", c.Description)
	assert.Equal(t, "#aabbcc", c.Color)

	for _, bad := range []*organization.OrgCategory{
		{Name: " ", Color: "#000000"},
		{Name: strings.Repeat("é", 101), Color: "#000000"},
		{Name: "x", Description: strings.Repeat("é", 256), Color: "#000000"},
		{Name: "x", Color: "red"},
		{Name: "x", Color: "#12345g"},
	} {
		require.ErrorIs(t, organization.CreateOrgCategory(ctx, bad), util.ErrInvalidArgument, "%+v", bad)
	}
	require.ErrorIs(t, organization.CreateOrgCategory(ctx, &organization.OrgCategory{Name: "Payments", Color: "#000000"}), util.ErrAlreadyExist)

	d := &organization.OrgCategory{Name: "Data", Color: "#000000", Position: 1}
	require.NoError(t, organization.CreateOrgCategory(ctx, d))
	cats, err := organization.FindOrgCategories(ctx)
	require.NoError(t, err)
	if assert.Len(t, cats, 2) {
		assert.Equal(t, []int64{d.ID, c.ID}, []int64{cats[0].ID, cats[1].ID})
	}

	d.Name = "Payments"
	require.ErrorIs(t, organization.UpdateOrgCategory(ctx, d), util.ErrAlreadyExist)
	c.Name, c.Color = "Payments", "#FFFFFF" // its own name is fine
	require.NoError(t, organization.UpdateOrgCategory(ctx, c))
	got, err := organization.GetOrgCategoryByID(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "#ffffff", got.Color)

	_, err = organization.GetOrgCategoryByID(ctx, 9999)
	assert.True(t, db.IsErrNotExist(err))
}

func TestOrgCategorySearchAndDelete(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	a := &organization.OrgCategory{Name: "A", Color: "#000000", Position: 2}
	b := &organization.OrgCategory{Name: "B", Color: "#000000", Position: 1}
	require.NoError(t, organization.CreateOrgCategory(ctx, a))
	require.NoError(t, organization.CreateOrgCategory(ctx, b))
	for org, cat := range map[int64]int64{3: a.ID, 7: a.ID, 6: b.ID} {
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET category_id = ? WHERE id = ?", cat, org)
		require.NoError(t, err)
	}

	search := func(opts user_model.SearchUserOptions) []int64 {
		t.Helper()
		opts.Type = user_model.UserTypeOrganization
		opts.OrderBy = "id ASC"
		users, _, err := user_model.SearchUsers(ctx, &opts)
		require.NoError(t, err)
		ids := make([]int64, len(users))
		for i, u := range users {
			ids[i] = u.ID
		}
		return ids
	}

	all := search(user_model.SearchUserOptions{})
	grouped := search(user_model.SearchUserOptions{GroupByCategory: true})
	require.Len(t, grouped, len(all))
	assert.Equal(t, []int64{6, 3, 7}, grouped[:3], "B (position 1), then A, each by the chosen sort")
	assert.ElementsMatch(t, all, grouped)

	var paged []int64
	for page := 1; len(paged) < len(grouped); page++ {
		ids := search(user_model.SearchUserOptions{GroupByCategory: true, ListOptions: db.ListOptions{Page: page, PageSize: 2}})
		require.NotEmpty(t, ids)
		paged = append(paged, ids...)
	}
	assert.Equal(t, grouped, paged, "pages join up to the full grouped list")

	assert.Equal(t, []int64{3, 7}, search(user_model.SearchUserOptions{CategoryID: optional.Some(a.ID)}))
	other := search(user_model.SearchUserOptions{CategoryID: optional.Some[int64](0)})
	assert.Len(t, other, len(all)-3)
	assert.NotContains(t, other, int64(3))

	require.NoError(t, organization.DeleteOrgCategory(ctx, a.ID))
	assert.Empty(t, search(user_model.SearchUserOptions{CategoryID: optional.Some(a.ID)}))
	assert.Equal(t, []int64{6}, search(user_model.SearchUserOptions{CategoryID: optional.Some(b.ID)}))
	assert.Len(t, search(user_model.SearchUserOptions{CategoryID: optional.Some[int64](0)}), len(all)-1)
	unittest.AssertNotExistsBean(t, &organization.OrgCategory{ID: a.ID})
}

func TestSortOrgsByCategory(t *testing.T) {
	cats := []*organization.OrgCategory{{ID: 7}, {ID: 2}}
	orgs := []*organization.Organization{
		{Name: "a"}, {Name: "b", CategoryID: 2}, {Name: "c", CategoryID: 7}, {Name: "d", CategoryID: 99}, {Name: "e", CategoryID: 2}, {Name: "f", CategoryID: 7},
	}
	organization.SortOrgsByCategory(orgs, cats)
	names := make([]string, 0, len(orgs))
	for _, o := range orgs {
		names = append(names, o.Name)
	}
	// category order, unknown and none last, existing order kept within a group
	assert.Equal(t, []string{"c", "f", "b", "e", "a", "d"}, names)
}
