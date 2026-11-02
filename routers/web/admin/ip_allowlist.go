// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	ipallowlist_service "forgejo.org/services/ipallowlist"
)

const tplIPAllowlist base.TplName = "admin/ip_allowlist"

func renderIPAllowlist(ctx *context.Context, s setting.IPAllowlistState, entries, users, tokens string) {
	ctx.Data["Title"] = ctx.Tr("admin.ip_allowlist")
	ctx.Data["PageIsAdminIPAllowlist"] = true
	ctx.Data["State"] = s
	ctx.Data["ClientIP"] = common.ClientIP(ctx.Req).String()
	ctx.Data["Entries"] = entries
	ctx.Data["ExemptUsers"] = users
	ctx.Data["ExemptTokens"] = tokens
	ctx.HTML(http.StatusOK, tplIPAllowlist)
}

// IPAllowlist shows the instance IP allowlist
func IPAllowlist(ctx *context.Context) {
	s := setting.GetIPAllowlist(ctx)
	var entries, users, tokens []string
	for _, e := range s.Entries {
		entries = append(entries, strings.TrimSpace(e.CIDR.String()+" "+e.Description))
	}
	exempt, err := user_model.GetUsersByIDs(ctx, s.ExemptUserIDs)
	if err != nil {
		ctx.ServerError("GetUsersByIDs", err)
		return
	}
	for _, u := range exempt {
		users = append(users, u.Name)
	}
	for _, t := range s.ExemptTokens {
		tokens = append(tokens, strconv.FormatInt(t.ID, 10))
	}
	renderIPAllowlist(ctx, s, strings.Join(entries, "\n"), strings.Join(users, ", "), strings.Join(tokens, ", "))
}

// splitList splits a comma or whitespace separated list
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

func parseIPAllowlistForm(ctx *context.Context) (setting.IPAllowlistState, error) {
	s := setting.IPAllowlistState{
		Enabled: ctx.FormBool("enabled"), Web: ctx.FormBool("web"), API: ctx.FormBool("api"), Git: ctx.FormBool("git"),
		SSH: ctx.FormBool("ssh"), Packages: ctx.FormBool("packages"), ExemptAdmins: ctx.FormBool("exempt_admins"),
	}
	for line := range strings.SplitSeq(ctx.FormString("entries"), "\n") {
		cidr, desc, _ := strings.Cut(strings.TrimSpace(line), " ")
		if cidr == "" {
			continue
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return s, util.NewInvalidArgumentErrorf("%s: %v", cidr, err)
		}
		s.Entries = append(s.Entries, setting.IPAllowlistEntry{CIDR: p, Description: strings.TrimSpace(desc)})
	}
	for _, name := range splitList(ctx.FormString("exempt_users")) {
		u, err := user_model.GetUserByName(ctx, name)
		if err != nil {
			return s, util.NewInvalidArgumentErrorf("%s: %v", name, err)
		}
		s.ExemptUserIDs = append(s.ExemptUserIDs, u.ID)
	}
	for _, id := range splitList(ctx.FormString("exempt_tokens")) {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return s, util.NewInvalidArgumentErrorf("invalid token ID %q", id)
		}
		s.ExemptTokens = append(s.ExemptTokens, setting.IPAllowlistToken{ID: n})
	}
	return s, nil
}

// IPAllowlistPost saves the instance IP allowlist, after a warning if it would block the admin's own address
func IPAllowlistPost(ctx *context.Context) {
	link := setting.AppSubURL + "/admin/ip-allowlist"
	s, err := parseIPAllowlistForm(ctx)
	if err == nil && s.WouldBlock(common.ClientIP(ctx.Req)) && !ctx.FormBool("force") {
		ctx.Data["LockoutWarning"] = true
		renderIPAllowlist(ctx, s, ctx.FormString("entries"), ctx.FormString("exempt_users"), ctx.FormString("exempt_tokens"))
		return
	}
	if err == nil {
		err = ipallowlist_service.Set(ctx, ctx.Doer, s)
	}
	switch {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("admin.ip_allowlist.saved"))
	case errors.Is(err, ipallowlist_service.ErrSetByConfig):
		ctx.Flash.Error(ctx.Tr("admin.ip_allowlist.from_config"))
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Flash.Error(err.Error())
	default:
		ctx.ServerError("Set", err)
		return
	}
	ctx.Redirect(link)
}
