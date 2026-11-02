// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"net/http"

	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/container"
	"forgejo.org/modules/setting"
	"forgejo.org/routers/api/v1/permissions"
	"forgejo.org/services/context"

	"github.com/go-chi/chi/v5"
)

const tplStatus503 base.TplName = "status/503"

// MaintenanceSignInRoutes stay open to everyone in read-only and full maintenance mode, so that admins can sign in.
var MaintenanceSignInRoutes = container.SetOf(
	"GET /user/login",
	"POST /user/login",
	"GET /user/login/openid",
	"POST /user/login/openid",
	"GET /user/two_factor",
	"POST /user/two_factor",
	"GET /user/two_factor/scratch",
	"POST /user/two_factor/scratch",
	"GET /user/webauthn",
	"GET /user/webauthn/assertion",
	"POST /user/webauthn/assertion",
	"GET /user/oauth2/{provider}",
	"GET /user/oauth2/{provider}/callback",
	"POST /user/logout",
	"GET /user/saml/{source}/login",
	"POST /user/saml/{source}/acs",
	"GET /user/saml/{source}/slo",
)

// MaintenanceReadRoutes are POST routes that only read, open to everyone who may read in read-only mode.
var MaintenanceReadRoutes = container.SetOf(
	"POST /login/oauth/access_token",
	"POST /{username}/{reponame}/markup",
	"POST /{username}/{reponame}/archive/*",
	"POST /{username}/{groupname}/{reponame}/archive/*",
	"POST /{username}/{groupname}/{reponame}/-/archive/*",
	"POST /org/{org}/security/vulnerabilities/export",
	"POST /org/{org}/security/dependencies/export",
	"POST /org/{org}/security/secrets/export",
	"POST /admin/security/secrets/export",
	"POST /org/{org}/settings/code_security/patterns/test",
	"POST /admin/security/patterns/test",
	"POST /admin/config/dependency-graph/vulnerabilities/export",
	"POST /admin/config/dependency-graph/dependencies/export",
	"POST /api/v1/markup",
	"POST /api/v1/markdown",
	"POST /api/v1/markdown/raw",
	"POST /api/v1/repos/{username}/{reponame}/markup",
	"POST /api/v1/repos/{username}/{reponame}/markdown",
	"POST /api/v1/repos/{username}/{reponame}/markdown/raw",
	"POST /api/v1/repos/{username}/{groupname}/{reponame}/-/markup",
	"POST /api/v1/repos/{username}/{groupname}/{reponame}/-/markdown",
	"POST /api/v1/repos/{username}/{groupname}/{reponame}/-/markdown/raw",
	"POST /api/v1/repositories/{repo_id}/markup",
	"POST /api/v1/repositories/{repo_id}/markdown",
	"POST /api/v1/repositories/{repo_id}/markdown/raw",
)

// MaintenanceRevokeRoutes are the routes that revoke credentials, open to everyone who may revoke in read-only mode.
var MaintenanceRevokeRoutes = container.SetOf(permissions.CredentialRevokeRoutes...)

// MaintenanceAdminRoutes are the admin settings a site admin can still change in read-only mode.
var MaintenanceAdminRoutes = container.SetOf(
	"POST /admin/maintenance",
	"POST /admin/ip-allowlist",
	"POST /admin/log-shipping/destinations/{id}/test",
	"POST /admin/config/dependency-graph/test-connection",
	"POST /admin/webhook-types",
	"POST /admin/repo-units",
	"POST /admin/applications/policy",
	"POST /admin/config",
	"POST /admin/config/test_mail",
	"POST /admin/config/test_cache",
	"POST /admin/announcements/new",
	"POST /admin/announcements/markup",
	"POST /admin/announcements/{id}",
	"POST /admin/announcements/{id}/delete",
	"POST /admin/monitor/stacktrace/cancel/{pid}",
	"PUT /api/v1/admin/maintenance",
	"PUT /api/v1/admin/ip-allowlist",
	"POST /api/v1/admin/log-shipping/destinations/{id}/test",
	"POST /api/v1/admin/announcements",
	"PATCH /api/v1/admin/announcements/{id}",
	"DELETE /api/v1/admin/announcements/{id}",
)

// IsMaintenanceAdmin reports whether the user is a site admin who can still use the instance in full maintenance mode.
func IsMaintenanceAdmin(u *user_model.User) bool {
	return u != nil && u.IsAdmin && u.IsActive && !u.ProhibitLogin
}

func maintenanceRoute(req *http.Request) string {
	return req.Method + " " + chi.RouteContext(req.Context()).RoutePattern()
}

func isMaintenanceWriteAllowed(req *http.Request, doer *user_model.User) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	route := maintenanceRoute(req)
	return MaintenanceSignInRoutes.Contains(route) || MaintenanceReadRoutes.Contains(route) || MaintenanceRevokeRoutes.Contains(route) ||
		IsMaintenanceAdmin(doer) && MaintenanceAdminRoutes.Contains(route)
}

func setRetryAfter(w http.ResponseWriter, s setting.MaintenanceState) {
	if v := s.RetryAfter(); v != "" {
		w.Header().Set("Retry-After", v)
	}
}

// MaintenanceWeb refuses web writes in read-only mode with a flash message, and shows non-admins the maintenance
// page in full maintenance mode.
func MaintenanceWeb(ctx *context.Context) {
	s := setting.GetMaintenance(ctx)
	if !s.ReadOnly() {
		return
	}
	if s.Full() && !IsMaintenanceAdmin(ctx.Doer) && !MaintenanceSignInRoutes.Contains(maintenanceRoute(ctx.Req)) {
		setRetryAfter(ctx.Resp, s)
		ctx.Data["Maintenance"] = s
		ctx.Data["Title"] = ctx.Tr("maintenance.full")
		ctx.HTML(http.StatusServiceUnavailable, tplStatus503)
		return
	}
	if isMaintenanceWriteAllowed(ctx.Req, ctx.Doer) {
		return
	}
	// a path in a project is decided on its second pass, which has the route of the repository
	if ctx.ResolveRepoGroupPath() {
		return
	}
	msg := ctx.Locale.TrString("maintenance.read_only")
	if s.Message != "" {
		msg += ": " + s.Message
	}
	ctx.Flash.Error(msg)
	ctx.RedirectToFirst(ctx.Req.Referer())
}

// MaintenanceGit refuses non-admins git, LFS and packages over HTTP in full maintenance mode. Writes in read-only mode
// are refused by the git, LFS and package handlers, because some of their POST requests are reads.
func MaintenanceGit(ctx *context.Context) {
	if s := setting.GetMaintenance(ctx); s.Full() && !IsMaintenanceAdmin(ctx.Doer) {
		setRetryAfter(ctx.Resp, s)
		ctx.PlainText(http.StatusServiceUnavailable, s.Refusal())
	}
}

// MaintenanceAPI refuses API writes in read-only mode, and every API request by a non-admin in full maintenance mode.
func MaintenanceAPI(ctx *context.APIContext) {
	s := setting.GetMaintenance(ctx)
	if !s.ReadOnly() {
		return
	}
	if s.Full() && !IsMaintenanceAdmin(ctx.Doer()) {
		setRetryAfter(ctx.Resp, s)
		ctx.JSON(http.StatusServiceUnavailable, map[string]string{"message": "maintenance mode", "detail": s.Message})
		return
	}
	if isMaintenanceWriteAllowed(ctx.Req, ctx.Doer()) {
		return
	}
	setRetryAfter(ctx.Resp, s)
	ctx.JSON(http.StatusServiceUnavailable, map[string]string{"message": "read-only mode", "detail": s.Message})
}
