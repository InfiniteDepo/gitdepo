// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"
	"strings"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
)

const tplSettingsUnits base.TplName = "org/settings/units"

type orgUnitRow struct {
	Unit       unit.Unit
	On         bool
	Locked     string // why the owner can't change it: "app_ini" or "site"
	UpdatedBy  string
	UpdatedRow *repo_model.OrgUnit
}

// Units shows the repository units of the organization: which the owner turned off, and which the site decides
func Units(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("org.settings.units")
	ctx.Data["PageIsSettingsUnits"] = true

	org := ctx.Org.Organization
	rows, err := repo_model.OrgUnits(ctx, org.ID)
	if err != nil {
		ctx.ServerError("OrgUnits", err)
		return
	}
	byType := map[unit.Type]*repo_model.OrgUnit{}
	for _, r := range rows {
		byType[r.Type] = r
	}
	p := setting.Config().RepoUnitPolicy.Value(ctx)
	var units []orgUnitRow
	for _, t := range repo_model.PolicyUnitTypes() {
		r := orgUnitRow{Unit: unit.Units[t], On: byType[t] == nil || !byType[t].Disabled, UpdatedRow: byType[t]}
		switch {
		case t.UnitGlobalDisabled():
			r.Locked = "app_ini"
		case !p.OrgAllowed(unit.Units[t].NameKey, org.ID):
			r.Locked = "site"
		}
		if r.UpdatedRow != nil {
			r.UpdatedBy = "-"
			if u, err := user_model.GetPossibleUserByID(ctx, r.UpdatedRow.UpdatedBy); err == nil {
				r.UpdatedBy = u.Name
			}
		}
		units = append(units, r)
	}
	ctx.Data["Units"] = units
	ctx.HTML(http.StatusOK, tplSettingsUnits)
}

// UnitsPost stores which units are on for every repository of the organization. A field of a unit the owner can't
// change is refused.
func UnitsPost(ctx *context.Context) {
	if err := ctx.Req.ParseForm(); err != nil {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	org := ctx.Org.Organization
	p := setting.Config().RepoUnitPolicy.Value(ctx)
	on := map[unit.Type]bool{}
	known := map[string]bool{}
	for _, t := range repo_model.PolicyUnitTypes() {
		known["on_"+unit.Units[t].NameKey] = true
	}
	for key := range ctx.Req.Form {
		if strings.HasPrefix(key, "on_") && !known[key] {
			ctx.Error(http.StatusBadRequest, key+" is not a unit")
			return
		}
	}
	for _, t := range repo_model.PolicyUnitTypes() {
		key := "on_" + unit.Units[t].NameKey
		if t.UnitGlobalDisabled() || !p.OrgAllowed(unit.Units[t].NameKey, org.ID) {
			if ctx.Req.Form.Has(key) {
				ctx.Error(http.StatusBadRequest, unit.Units[t].NameKey+" can't be changed for this organization")
				return
			}
			continue
		}
		on[t] = ctx.FormBool(key)
	}
	err := repo_model.SetOrgUnits(ctx, org.AsUser(), ctx.Doer.ID, on)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		ctx.ServerError("SetOrgUnits", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("org.settings.units.saved"))
	ctx.Redirect(ctx.Org.OrgLink + "/settings/units")
}
