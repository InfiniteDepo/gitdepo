// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package misc

import (
	"net/http"

	system_model "forgejo.org/models/system"
	announcement_service "forgejo.org/services/announcement"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// ListActiveAnnouncements lists the announcements currently shown to the user
func ListActiveAnnouncements(ctx *context.APIContext) {
	// swagger:operation GET /announcements miscellaneous listActiveAnnouncements
	// ---
	// summary: List the announcements currently shown to the authenticated user, or to anonymous visitors
	// description: Announcements the user dismissed are left out. The most severe ones come first.
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/AnnouncementList"

	banners, err := announcement_service.ActiveForUser(ctx, ctx.Doer(), nil)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ActiveForUser", err)
		return
	}
	list := make([]*system_model.Announcement, 0, len(banners))
	for _, b := range banners {
		list = append(list, b.Announcement)
	}
	ctx.JSON(http.StatusOK, convert.ToAnnouncements(list))
}
