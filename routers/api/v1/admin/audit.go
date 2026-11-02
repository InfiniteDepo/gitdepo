// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"maps"
	"net/http"
	"strconv"

	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/routers/common"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/services/auth"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// ReqAuditReader lets a usable site admin or auditor through. A site admin needs a token that allows the admin
// override, an auditor a credential they hold (no OAuth2 grant, no authorized integration); both need a token that
// is limited neither to public resources nor to specific repositories.
func ReqAuditReader(ctx *context.APIContext) {
	doer := ctx.Doer()
	ok := common.UsableAuditReader(doer) &&
		(doer.IsAdmin && ctx.Reducer().AllowAdminOverride() || doer.IsAuditor && auth.IsHeldByUser(ctx.Authentication())) &&
		utils.IsOrgWideToken(ctx)
	if !ok {
		ctx.Error(http.StatusForbidden, "ReqAuditReader", "the audit log needs a site admin or auditor and a token for all resources")
	}
}

// ListAuditEvents lists or exports the audit log
func ListAuditEvents(ctx *context.APIContext) {
	// swagger:operation GET /admin/audit admin adminListAuditEvents
	// ---
	// summary: List the audit log, newest first, or export it
	// description: Paged by ID (before_id, after_id) with a Link header and no total count. With format=csv or
	//   format=json every matching entry is exported, oldest first, with the X-Audit-* manifest headers.
	// produces:
	// - application/json
	// - text/csv
	// parameters:
	// - name: category
	//   in: query
	//   description: changes (default), signins, activity, all, or a comma-separated list of categories
	//   type: string
	// - name: org
	//   in: query
	//   description: organization name or ID
	//   type: string
	// - name: project
	//   in: query
	//   description: project ID
	//   type: integer
	// - name: repo
	//   in: query
	//   description: repository full name (owner/[project/]name) or ID
	//   type: string
	// - name: user
	//   in: query
	//   description: user name or ID (the acting user, the admin behind a sudo, or the account the entry concerns)
	//   type: string
	// - name: credential_type
	//   in: query
	//   description: comma-separated credential types
	//   type: string
	// - name: credential
	//   in: query
	//   description: one credential, as type and ID separated by a colon
	//   type: string
	// - name: credential_owner
	//   in: query
	//   description: user or organization name or ID owning the credential
	//   type: string
	// - name: action
	//   in: query
	//   description: catalog key, or a prefix ending in .*
	//   type: string
	// - name: result
	//   in: query
	//   description: success, failure or refused
	//   type: string
	// - name: ip
	//   in: query
	//   description: client IP address
	//   type: string
	// - name: request_id
	//   in: query
	//   description: request ID
	//   type: string
	// - name: since
	//   in: query
	//   description: RFC 3339 time, inclusive
	//   type: string
	// - name: before
	//   in: query
	//   description: RFC 3339 time, exclusive
	//   type: string
	// - name: target_type
	//   in: query
	//   description: target type
	//   type: string
	// - name: target_id
	//   in: query
	//   description: target ID
	//   type: integer
	// - name: before_id
	//   in: query
	//   description: return entries older than this ID
	//   type: integer
	// - name: after_id
	//   in: query
	//   description: return entries newer than this ID
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size, at most 100 (default 50)
	//   type: integer
	// - name: format
	//   in: query
	//   description: csv or json to export every matching entry (at most 100000) instead of a page
	//   type: string
	// responses:
	//   "200":
	//     "$ref": "#/responses/AuditEventList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"

	f, err := audit_service.ParseFilter(ctx, ctx.FormString)
	if err != nil {
		if filterErr, ok := errors.AsType[*audit_service.FilterError](err); ok {
			ctx.Error(http.StatusUnprocessableEntity, "", filterErr.Error())
		} else {
			ctx.Error(http.StatusInternalServerError, "ParseFilter", err)
		}
		return
	}
	link := setting.AppURL + "api/v1/admin/audit"
	if format := ctx.FormString("format"); format == "csv" || format == "json" {
		if common.ChargeHeavyAPI(ctx) {
			common.ExportAudit(ctx.Base, f, format, link)
		}
		return
	} else if format != "" {
		ctx.Error(http.StatusUnprocessableEntity, "", "format must be csv or json")
		return
	}

	limit := ctx.FormInt("limit")
	if limit <= 0 {
		limit = 50
	}
	entries, newer, older, err := audit_service.Page(ctx, f, min(limit, 100))
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "Page", err)
		return
	}
	events := make([]*api.AuditEvent, 0, len(entries))
	for _, e := range entries {
		events = append(events, convert.ToAuditEvent(e))
	}
	page := func(key string, id int64, rel string) string {
		q := maps.Clone(f.Values)
		q.Del("before_id")
		q.Del("after_id")
		q.Set(key, strconv.FormatInt(id, 10))
		if limit != 50 {
			q.Set("limit", strconv.Itoa(min(limit, 100)))
		}
		return "<" + link + "?" + q.Encode() + ">; rel=\"" + rel + "\""
	}
	var links []string
	if len(entries) > 0 {
		if older {
			links = append(links, page("before_id", entries[len(entries)-1].ID, "next"))
		}
		if newer {
			links = append(links, page("after_id", entries[0].ID, "prev"))
		}
	}
	for _, l := range links {
		ctx.Resp.Header().Add("Link", l)
	}
	ctx.AppendAccessControlExposeHeaders("Link")
	ctx.JSON(http.StatusOK, events)
}
