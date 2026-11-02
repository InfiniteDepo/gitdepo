// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	repo_service "forgejo.org/services/repository"
)

const tplRepoUnits base.TplName = "admin/repo_units"

type repoUnitRow struct {
	Unit         unit.Unit
	Allowed      bool
	OrgNames     string
	OnDefault    bool
	CanBeDefault bool
	Locked       bool
}

// RepoUnits shows which repository units organizations may use and which are on for new repositories
func RepoUnits(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.repo_units")
	ctx.Data["PageIsAdminRepoUnits"] = true

	p := setting.Config().RepoUnitPolicy.Value(ctx)
	var defaults []unit.Type
	if p.DefaultUnits == nil || repo_service.DefaultUnitsLocked() {
		defaults = unit.DefaultRepoUnits
	} else {
		defaults, _ = unit.FindUnitTypes(p.DefaultUnits...)
	}
	var rows []repoUnitRow
	for _, t := range repo_model.PolicyUnitTypes() {
		key := unit.Units[t].NameKey
		// stale IDs of deleted organizations are skipped
		orgs, err := user_model.GetUsersByIDs(ctx, p.OrgOverrides[key])
		if err != nil {
			ctx.ServerError("GetUsersByIDs", err)
			return
		}
		names := make([]string, 0, len(orgs))
		for _, o := range orgs {
			names = append(names, o.Name)
		}
		rows = append(rows, repoUnitRow{
			Unit:         unit.Units[t],
			Allowed:      !slices.Contains(p.NotAllowed, key),
			OrgNames:     strings.Join(names, "\n"),
			OnDefault:    slices.Contains(defaults, t),
			CanBeDefault: t.CanBeDefault(),
			Locked:       repo_service.UnitPolicyLocked(t),
		})
	}
	ctx.Data["Units"] = rows
	ctx.Data["PolicyInvalid"] = p.Invalid
	ctx.Data["DefaultsLocked"] = repo_service.DefaultUnitsLocked()
	if p.UpdatedUnix > 0 {
		ctx.Data["UpdatedUnix"] = timeutil.TimeStamp(p.UpdatedUnix)
		ctx.Data["UpdatedBy"] = "-"
		if u, err := user_model.GetPossibleUserByID(ctx, p.UpdatedBy); err == nil {
			ctx.Data["UpdatedBy"] = u.Name
		}
	}
	ctx.HTML(http.StatusOK, tplRepoUnits)
}

// RepoUnitsPost stores the policy. A field of a unit app.ini locks is refused.
func RepoUnitsPost(ctx *context.Context) {
	if err := ctx.Req.ParseForm(); err != nil {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	changes := map[unit.Type]repo_service.UnitPolicyChange{}
	for _, t := range repo_model.PolicyUnitTypes() {
		key := unit.Units[t].NameKey
		if repo_service.UnitPolicyLocked(t) {
			for _, f := range []string{"allowed_", "orgs_", "default_"} {
				if ctx.Req.Form.Has(f + key) {
					ctx.Error(http.StatusBadRequest, key+" is disabled in app.ini")
					return
				}
			}
			continue
		}
		changes[t] = repo_service.UnitPolicyChange{
			Allowed:   ctx.FormBool("allowed_" + key),
			OrgNames:  splitList(ctx.FormString("orgs_" + key)),
			OnDefault: ctx.FormBool("default_" + key),
		}
	}
	err := repo_service.SetUnitPolicy(ctx, ctx.Doer, changes)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		ctx.ServerError("SetUnitPolicy", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.repo_units.saved"))
	ctx.Redirect(setting.AppSubURL + "/admin/repo-units")
}
