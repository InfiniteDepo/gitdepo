// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"time"

	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	maintenance_service "forgejo.org/services/maintenance"
)

func toAPIMaintenance(s setting.MaintenanceState) *api.Maintenance {
	m := &api.Maintenance{Mode: s.Mode, Message: s.Message, SetBy: s.SetByName, FromConfig: s.FromConfig}
	if m.Mode == "" {
		m.Mode = setting.MaintenanceOff
	}
	if s.Until > 0 {
		t := time.Unix(s.Until, 0)
		m.Until = &t
	}
	return m
}

// GetMaintenance gets the maintenance mode
func GetMaintenance(ctx *context.APIContext) {
	// swagger:operation GET /admin/maintenance admin adminGetMaintenance
	// ---
	// summary: Get the read-only or maintenance mode
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/Maintenance"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	ctx.JSON(http.StatusOK, toAPIMaintenance(setting.GetMaintenance(ctx)))
}

// EditMaintenance changes the maintenance mode
func EditMaintenance(ctx *context.APIContext) {
	// swagger:operation PUT /admin/maintenance admin adminEditMaintenance
	// ---
	// summary: Turn the read-only or maintenance mode on or off
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditMaintenanceOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/Maintenance"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.EditMaintenanceOption)
	var until time.Time
	if form.Until != nil {
		until = *form.Until
	}
	err := maintenance_service.Set(ctx, ctx.Doer(), form.Mode, form.Message, until)
	switch {
	case errors.Is(err, maintenance_service.ErrSetByConfig):
		ctx.Error(http.StatusConflict, "", err)
		return
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
		return
	case err != nil:
		ctx.Error(http.StatusInternalServerError, "Set", err)
		return
	}
	ctx.JSON(http.StatusOK, toAPIMaintenance(setting.GetMaintenance(ctx)))
}
