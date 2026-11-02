// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"net/netip"

	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	ipallowlist_service "forgejo.org/services/ipallowlist"
)

func toAPIIPAllowlist(ctx *context.APIContext, s setting.IPAllowlistState) *api.IPAllowlist {
	a := &api.IPAllowlist{
		Enabled:       s.Enabled,
		Surfaces:      api.IPAllowlistSurfaces{Web: s.Web, API: s.API, Git: s.Git, SSH: s.SSH, Packages: s.Packages},
		ExemptAdmins:  s.ExemptAdmins,
		Entries:       []*api.IPAllowlistEntry{},
		ExemptUserIDs: append([]int64{}, s.ExemptUserIDs...),
		ExemptTokens:  []*api.IPAllowlistToken{},
		YourIP:        common.ClientIP(ctx.Req).String(),
		FromConfig:    s.FromConfig,
	}
	for _, e := range s.Entries {
		a.Entries = append(a.Entries, &api.IPAllowlistEntry{CIDR: e.CIDR.String(), Description: e.Description})
	}
	for _, t := range s.ExemptTokens {
		a.ExemptTokens = append(a.ExemptTokens, &api.IPAllowlistToken{ID: t.ID, UserID: t.UID})
	}
	return a
}

// GetIPAllowlist gets the instance IP allowlist
func GetIPAllowlist(ctx *context.APIContext) {
	// swagger:operation GET /admin/ip-allowlist admin adminGetIPAllowlist
	// ---
	// summary: Get the instance IP allowlist
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/IPAllowlist"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	ctx.JSON(http.StatusOK, toAPIIPAllowlist(ctx, setting.GetIPAllowlist(ctx)))
}

// EditIPAllowlist replaces the instance IP allowlist
func EditIPAllowlist(ctx *context.APIContext) {
	// swagger:operation PUT /admin/ip-allowlist admin adminEditIPAllowlist
	// ---
	// summary: Replace the instance IP allowlist
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: force
	//   in: query
	//   description: save even if the new list blocks the address of this request
	//   type: boolean
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditIPAllowlistOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/IPAllowlist"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.EditIPAllowlistOption)
	s := setting.IPAllowlistState{
		Enabled: form.Enabled, Web: form.Surfaces.Web, API: form.Surfaces.API, Git: form.Surfaces.Git,
		SSH: form.Surfaces.SSH, Packages: form.Surfaces.Packages,
		ExemptAdmins: form.ExemptAdmins == nil || *form.ExemptAdmins, ExemptUserIDs: form.ExemptUserIDs,
	}
	for _, e := range form.Entries {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			ctx.Error(http.StatusUnprocessableEntity, "", err)
			return
		}
		s.Entries = append(s.Entries, setting.IPAllowlistEntry{CIDR: p, Description: e.Description})
	}
	for _, id := range form.ExemptTokenIDs {
		s.ExemptTokens = append(s.ExemptTokens, setting.IPAllowlistToken{ID: id})
	}
	if ip := common.ClientIP(ctx.Req); s.WouldBlock(ip) && !ctx.FormBool("force") {
		ctx.Error(http.StatusConflict, "", "the new IP allowlist blocks your address "+ip.String()+"; set force=true to save it anyway")
		return
	}

	err := ipallowlist_service.Set(ctx, ctx.Doer(), s)
	switch {
	case errors.Is(err, ipallowlist_service.ErrSetByConfig), errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
		return
	case err != nil:
		ctx.Error(http.StatusInternalServerError, "Set", err)
		return
	}
	ctx.JSON(http.StatusOK, toAPIIPAllowlist(ctx, setting.GetIPAllowlist(ctx)))
}
