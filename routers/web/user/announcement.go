// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	goctx "context"
	"errors"
	"net/http"
	"strings"

	system_model "forgejo.org/models/system"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/web/middleware"
	announcement_service "forgejo.org/services/announcement"
	"forgejo.org/services/context"
)

// GetAnnouncements is the middleware that makes the active announcements available to the page templates
func GetAnnouncements(ctx *context.Context) {
	if strings.HasPrefix(ctx.Req.URL.Path, "/api") {
		return
	}

	var anonDismissed map[int64]string
	if ctx.Doer == nil {
		anonDismissed = announcement_service.ParseDismissCookie(middleware.GetSiteCookie(ctx.Req, announcement_service.DismissCookie))
	}
	ctx.Data["Maintenance"] = setting.GetMaintenance(ctx)
	ctx.Data["SiteAnnouncements"] = func() []*announcement_service.Banner {
		banners, err := announcement_service.ActiveForUser(ctx, ctx.Doer, anonDismissed)
		if err != nil {
			if !errors.Is(err, goctx.Canceled) {
				log.Error("Unable to load announcements: %v", err)
			}
			return nil
		}
		return banners
	}
}

// DismissAnnouncement hides an announcement for the signed-in user (or, with a cookie, the anonymous visitor) until its message changes
func DismissAnnouncement(ctx *context.Context) {
	a, err := system_model.GetAnnouncementByID(ctx, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetAnnouncementByID", system_model.IsErrAnnouncementNotExist, err)
		return
	}
	if !a.CanBeDismissed() {
		ctx.Error(http.StatusUnprocessableEntity, "announcement cannot be dismissed")
		return
	}
	if ctx.Doer == nil {
		value := announcement_service.AddToDismissCookie(middleware.GetSiteCookie(ctx.Req, announcement_service.DismissCookie), a.ID, announcement_service.CookieHash(a))
		middleware.SetSiteCookie(ctx.Resp, announcement_service.DismissCookie, value, 365*24*60*60)
	} else if err := system_model.DismissAnnouncement(ctx, a, ctx.Doer.ID); err != nil {
		ctx.ServerError("DismissAnnouncement", err)
		return
	}
	ctx.RedirectToFirst(ctx.FormString("redirect_to"))
}
