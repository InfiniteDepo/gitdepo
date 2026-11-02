// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"
	"slices"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// OrgUnit is a repository unit an organization owner turned off (or back on) for every repository of the organization.
// No row means on.
type OrgUnit struct {
	ID          int64              `xorm:"pk autoincr"`
	OrgID       int64              `xorm:"UNIQUE(s) NOT NULL"`
	Type        unit.Type          `xorm:"UNIQUE(s) NOT NULL"`
	Disabled    bool               `xorm:"NOT NULL DEFAULT false"`
	UpdatedBy   int64              `xorm:"NOT NULL DEFAULT 0"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(OrgUnit))
}

// OrgUnits returns the rows of the organization.
func OrgUnits(ctx context.Context, orgID int64) ([]*OrgUnit, error) {
	var rows []*OrgUnit
	return rows, db.GetEngine(ctx).Where("org_id = ?", orgID).Find(&rows)
}

// orgDisabledUnits returns the units the organization turned off, read once per request.
func orgDisabledUnits(ctx context.Context, orgID int64) ([]unit.Type, error) {
	return cache.GetWithContextCache(ctx, "org_disabled_units", orgID, func() ([]unit.Type, error) {
		types := []unit.Type{}
		return types, db.GetEngine(ctx).Table("org_unit").Where("org_id = ? AND disabled = ?", orgID, true).Cols("type").Find(&types)
	})
}

// anyOrgUnitOff reports whether some organization turned a unit off, read once per request, so the org_unit
// condition costs nothing until an owner uses it. An error reads as true (fail closed).
func anyOrgUnitOff(ctx context.Context) bool {
	has, err := cache.GetWithContextCache(ctx, "org_unit_any_off", 0, func() (bool, error) {
		return db.GetEngine(ctx).Table("org_unit").Where("disabled = ?", true).Exist()
	})
	if err != nil {
		log.Error("anyOrgUnitOff: %v", err)
		return true
	}
	return has
}

// SetOrgUnits stores the organization owner's choice for the units in on (true = on). A unit the site policy hides,
// app.ini disables, or Code is refused.
func SetOrgUnits(ctx context.Context, org *user_model.User, doerID int64, on map[unit.Type]bool) error {
	p := setting.Config().RepoUnitPolicy.Value(ctx)
	for t := range on {
		if !slices.Contains(PolicyUnitTypes(), t) || t.UnitGlobalDisabled() || !p.OrgAllowed(unit.Units[t].NameKey, org.ID) {
			return util.NewInvalidArgumentErrorf("unit %d can't be changed for this organization", t)
		}
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		var before, after []string
		for t, v := range on {
			row := &OrgUnit{OrgID: org.ID, Type: t}
			has, err := db.GetEngine(ctx).Get(row)
			if err != nil {
				return err
			}
			if row.Disabled == !v { // unchanged, or on without a row
				continue
			}
			row.Disabled, row.UpdatedBy = !v, doerID
			if has {
				_, err = db.GetEngine(ctx).ID(row.ID).Cols("disabled", "updated_by", "updated_unix").Update(row)
			} else {
				_, err = db.GetEngine(ctx).Insert(row)
			}
			if err != nil {
				return err
			}
			name := strings.TrimPrefix(unit.Units[t].NameKey, "repo.")
			before, after = append(before, name+":"+onOff(!v)), append(after, name+":"+onOff(v))
		}
		if len(after) > 0 {
			slices.Sort(before)
			slices.Sort(after)
			if err := user_model.RecordOrg(ctx, "org.units.changed", org, map[string]any{
				"before": map[string]any{"units": before}, "after": map[string]any{"units": after},
			}); err != nil {
				return err
			}
		}
		cache.RemoveContextData(ctx, "org_disabled_units", org.ID)
		cache.RemoveContextData(ctx, "org_unit_any_off", 0)
		return nil
	})
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// PolicyUnitTypes are the units the site policy decides on: every unit but Code.
func PolicyUnitTypes() []unit.Type {
	return slices.DeleteFunc(slices.Clone(unit.AllRepoUnitTypes), func(t unit.Type) bool { return t == unit.TypeCode })
}

// HiddenUnits returns the units the site policy or the organization owner hides in repositories of owner, which must
// be loaded from the database (a nil owner hides everything). The repo_unit rows are kept, so a unit comes back when it is allowed again.
// App.ini DISABLED_REPO_UNITS is checked separately (UnitGlobalDisabled).
func HiddenUnits(ctx context.Context, owner *user_model.User) container.Set[unit.Type] {
	hidden := container.Set[unit.Type]{}
	if owner != nil && !owner.IsOrganization() {
		return hidden
	}
	p := setting.Config().RepoUnitPolicy.Value(ctx)
	for _, t := range PolicyUnitTypes() {
		if owner == nil || !p.OrgAllowed(unit.Units[t].NameKey, owner.ID) {
			hidden.Add(t)
		}
	}
	if owner != nil && anyOrgUnitOff(ctx) {
		off, err := orgDisabledUnits(ctx, owner.ID)
		if err != nil {
			log.Error("orgDisabledUnits(%d): %v", owner.ID, err)
			hidden.AddMultiple(PolicyUnitTypes()...) // fail closed
		}
		hidden.AddMultiple(off...)
	}
	return hidden
}

// ActionsAvailable reports whether Actions is on for the site and, when owner is an organization, not hidden for it
// (the org Actions pages, their menu entries and MustEnableActions all follow this one rule).
func ActionsAvailable(ctx context.Context, owner *user_model.User) bool {
	return setting.Actions.Enabled && !unit.TypeActions.UnitGlobalDisabled() &&
		(owner == nil || !HiddenUnits(ctx, owner).Contains(unit.TypeActions))
}

// HiddenUnitCond is HiddenUnits in SQL: it matches the rows whose unit (the typeCol column) is hidden in
// repositories owned by ownerCol.
func HiddenUnitCond(ctx context.Context, ownerCol, typeCol string) builder.Cond {
	return hiddenUnitCond(ctx, ownerCol, PolicyUnitTypes(), func(t unit.Type) builder.Cond { return builder.Eq{typeCol: t} }).
		Or(orgUnitOffCond(ctx, ownerCol, builder.Expr("`org_unit`.type = "+typeCol)))
}

// orgUnitOffCond matches the owners (ownerCol) that turned off the unit typeCond selects in org_unit, or is empty
// when no organization turned a unit off.
func orgUnitOffCond(ctx context.Context, ownerCol string, typeCond builder.Cond) builder.Cond {
	if !anyOrgUnitOff(ctx) {
		return builder.NewCond()
	}
	return builder.Exists(builder.Select("1").From("org_unit").
		Where(builder.Expr("`org_unit`.org_id = " + ownerCol)).And(builder.Eq{"`org_unit`.disabled": true}).And(typeCond))
}

// HiddenUnitTypeCond matches the owners (ownerCol) in whose repositories the site policy or the organization owner
// hides the unit t.
func HiddenUnitTypeCond(ctx context.Context, ownerCol string, t unit.Type) builder.Cond {
	return hiddenUnitCond(ctx, ownerCol, []unit.Type{t}, func(unit.Type) builder.Cond { return builder.NewCond() }).
		Or(orgUnitOffCond(ctx, ownerCol, builder.Eq{"`org_unit`.type": t}))
}

func hiddenUnitCond(ctx context.Context, ownerCol string, types []unit.Type, typeCond func(unit.Type) builder.Cond) builder.Cond {
	p := setting.Config().RepoUnitPolicy.Value(ctx)
	cond := builder.NewCond()
	for _, t := range types {
		key := unit.Units[t].NameKey
		flipped := p.OrgOverrides[key]
		switch {
		case t == unit.TypeCode:
		case p.Invalid || slices.Contains(p.NotAllowed, key):
			c := typeCond(t).And(builder.In(ownerCol, builder.Select("id").From("`user`").Where(builder.Eq{"type": user_model.UserTypeOrganization})))
			if len(flipped) > 0 && !p.Invalid {
				c = c.And(builder.NotIn(ownerCol, flipped))
			}
			cond = cond.Or(c)
		case len(flipped) > 0:
			// only organization IDs are stored, and IDs are never reused
			cond = cond.Or(typeCond(t).And(builder.In(ownerCol, flipped)))
		}
	}
	return cond
}

// AvailableUnitCond is the negation of HiddenUnitCond, or an empty condition when nothing is hidden.
func AvailableUnitCond(ctx context.Context, ownerCol, typeCol string) builder.Cond {
	return notCond(HiddenUnitCond(ctx, ownerCol, typeCol))
}

// AvailableUnitTypeCond is the negation of HiddenUnitTypeCond, or an empty condition when nothing is hidden.
func AvailableUnitTypeCond(ctx context.Context, ownerCol string, t unit.Type) builder.Cond {
	return notCond(HiddenUnitTypeCond(ctx, ownerCol, t))
}

func notCond(c builder.Cond) builder.Cond {
	if c.IsValid() {
		return builder.Not{c}
	}
	return builder.NewCond()
}
