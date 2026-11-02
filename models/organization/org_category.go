// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/label"
	"forgejo.org/modules/util"
)

// OrgCategory is a category site admins group organizations in (user.category_id; 0 = none, shown as "Other").
type OrgCategory struct {
	ID          int64  `xorm:"pk autoincr"`
	Name        string `xorm:"VARCHAR(100) UNIQUE NOT NULL"`
	Description string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	Color       string `xorm:"VARCHAR(7) NOT NULL DEFAULT ''"` // lower-case #rrggbb
	Position    int    `xorm:"NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(OrgCategory))
}

// FindOrgCategories returns every category in display order.
func FindOrgCategories(ctx context.Context) ([]*OrgCategory, error) {
	cats := make([]*OrgCategory, 0, 8)
	return cats, db.GetEngine(ctx).Asc("position", "id").Find(&cats)
}

// GetOrgCategoryByID returns a category or a db.ErrNotExist.
func GetOrgCategoryByID(ctx context.Context, id int64) (*OrgCategory, error) {
	c := new(OrgCategory)
	if has, err := db.GetEngine(ctx).ID(id).Get(c); err != nil {
		return nil, err
	} else if !has {
		return nil, db.ErrNotExist{Resource: "org_category", ID: id}
	}
	return c, nil
}

// normalize trims and validates the fields and checks that no other category has the name.
func (c *OrgCategory) normalize(ctx context.Context) error {
	c.Name = strings.TrimSpace(c.Name)
	c.Description = strings.TrimSpace(c.Description)
	if n := utf8.RuneCountInString(c.Name); n < 1 || n > 100 {
		return util.NewInvalidArgumentErrorf("category name must be 1 to 100 characters")
	}
	if utf8.RuneCountInString(c.Description) > 255 {
		return util.NewInvalidArgumentErrorf("category description must be at most 255 characters")
	}
	color, err := label.NormalizeColor(c.Color)
	if err != nil {
		return util.NewInvalidArgumentErrorf("invalid category color")
	}
	c.Color = color
	if taken, err := db.GetEngine(ctx).Where("name = ? AND id <> ?", c.Name, c.ID).Exist(new(OrgCategory)); err != nil {
		return err
	} else if taken {
		return util.NewAlreadyExistErrorf("category name %q is already used", c.Name)
	}
	return nil
}

// CreateOrgCategory validates and inserts a category.
func CreateOrgCategory(ctx context.Context, c *OrgCategory) error {
	if err := c.normalize(ctx); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).Insert(c)
	return err
}

// UpdateOrgCategory validates and saves a category.
func UpdateOrgCategory(ctx context.Context, c *OrgCategory) error {
	if err := c.normalize(ctx); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).ID(c.ID).Cols("name", "description", "color", "position").Update(c)
	return err
}

// DeleteOrgCategory deletes a category and moves its organizations to "Other".
func DeleteOrgCategory(ctx context.Context, id int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).Table(new(user_model.User)).Where("category_id = ?", id).Update(map[string]any{"category_id": 0}); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).ID(id).Delete(new(OrgCategory))
		return err
	})
}

// SortOrgsByCategory orders orgs by the position of their category in cats (as returned by FindOrgCategories),
// organizations without a known category last, keeping the existing order within each group.
func SortOrgsByCategory(orgs []*Organization, cats []*OrgCategory) {
	rank := make(map[int64]int, len(cats))
	for i, c := range cats {
		rank[c.ID] = i
	}
	rankOf := func(o *Organization) int {
		if r, ok := rank[o.CategoryID]; ok {
			return r
		}
		return len(cats)
	}
	slices.SortStableFunc(orgs, func(a, b *Organization) int { return rankOf(a) - rankOf(b) })
}

// CategoriesByID maps the categories by ID, for the category headers.
func CategoriesByID(cats []*OrgCategory) map[int64]*OrgCategory {
	byID := make(map[int64]*OrgCategory, len(cats))
	for _, c := range cats {
		byID[c.ID] = c
	}
	return byID
}
