// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strconv"

	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/services/auth"
	auth_method "forgejo.org/services/auth/method"
	app_context "forgejo.org/services/context"
)

const tplIPBlocked base.TplName = "status/ip_blocked"

// IPAllowlistRefusal is the English message shown when the IP allowlist refuses a client, e.g. by git as "remote: ...".
func IPAllowlistRefusal(ip string) string {
	return "access from " + ip + " is not allowed by the IP allowlist"
}

// IPAllowlistExempt reports whether the user or the personal access token is exempt from the IP allowlist.
func IPAllowlistExempt(s setting.IPAllowlistState, doer *user_model.User, ar auth.AuthenticationResult) bool {
	if doer == nil || !doer.IsActive || doer.ProhibitLogin {
		return false
	}
	if slices.Contains(s.ExemptUserIDs, doer.ID) {
		return true
	}
	if ar != nil {
		if id := ar.AccessTokenID(); id != 0 && slices.Contains(s.ExemptTokens, setting.IPAllowlistToken{ID: id, UID: doer.ID}) {
			return true
		}
	}
	return s.ExemptAdmins && IsMaintenanceAdmin(doer)
}

// IPAllowlistRefused checks the client against the IP allowlist of the surface. It returns the address to show, and
// whether the client is refused: neither in the list nor exempt. An address that can't be parsed is refused.
func IPAllowlistRefused(ctx context.Context, ip netip.Addr, surface string, doer *user_model.User, ar auth.AuthenticationResult) (string, bool) {
	s := setting.GetIPAllowlist(ctx)
	if !s.Enforced(surface) {
		return "", false
	}
	if s.Allows(ip) || IPAllowlistExempt(s, doer, ar) {
		return "", false
	}
	shown := "unknown"
	if ip.IsValid() {
		shown = ip.String()
	}
	var uid int64
	if doer != nil {
		uid = doer.ID
	}
	auth.RecordRefusal(ctx, "ip_allowlist", 0, uid, auth.ActorIPKey(ctx, 48)+"|"+strconv.FormatInt(uid, 10), map[string]any{"class": surface})
	return shown, true
}

// IPAllowlistWeb shows the "approved networks" page to refused clients of the web UI. The sign-in pages stay reachable,
// so that exempt users can sign in.
func IPAllowlistWeb(ctx *app_context.Context) {
	if MaintenanceSignInRoutes.Contains(maintenanceRoute(ctx.Req)) {
		return
	}
	if ip, refused := IPAllowlistRefused(ctx, ClientIP(ctx.Req), setting.IPAllowlistSurfaceWeb, ctx.Doer, ctx.Authentication); refused {
		ctx.Data["Title"] = ctx.Tr("ip_allowlist.title")
		ctx.Data["ClientIP"] = ip
		ctx.HTML(http.StatusForbidden, tplIPBlocked)
	}
}

// IPAllowlistAPI refuses API requests from refused clients. It runs before sudo, so the check is on the credential's
// own user.
func IPAllowlistAPI(ctx *app_context.APIContext) {
	if ip, refused := IPAllowlistRefused(ctx, ClientIP(ctx.Req), setting.IPAllowlistSurfaceAPI, ctx.Doer(), ctx.Authentication()); refused {
		ctx.JSON(http.StatusForbidden, map[string]string{"message": "IP address not allowed", "ip": ip})
	}
}

// IPAllowlistPlain refuses refused clients with a plain text message, for git over HTTP, LFS and packages.
func IPAllowlistPlain(surface string) func(*app_context.Context) {
	return func(ctx *app_context.Context) {
		if ip, refused := IPAllowlistRefused(ctx, ClientIP(ctx.Req), surface, ctx.Doer, ctx.Authentication); refused {
			ctx.PlainText(http.StatusForbidden, IPAllowlistRefusal(ip))
		}
	}
}

// IPAllowlistMixed is for routes that take both a web session and API credentials: a session (or no credential) is
// checked as the web UI, anything else as the API.
func IPAllowlistMixed(ctx *app_context.Context) {
	if ctx.Doer == nil || auth_method.IsSession(ctx.Authentication) || ctx.Authentication.IsReverseProxyAuthentication() {
		IPAllowlistWeb(ctx)
		return
	}
	if ip, refused := IPAllowlistRefused(ctx, ClientIP(ctx.Req), setting.IPAllowlistSurfaceAPI, ctx.Doer, ctx.Authentication); refused {
		ctx.JSON(http.StatusForbidden, map[string]string{"message": "IP address not allowed", "ip": ip})
	}
}
