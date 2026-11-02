// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"fmt"
	"net/http"
	"time"

	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/web"
	announcement_service "forgejo.org/services/announcement"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

const (
	tplAnnouncements    base.TplName = "admin/announcement/list"
	tplAnnouncementEdit base.TplName = "admin/announcement/edit"

	announcementTimeLayout = "2006-01-02T15:04"
)

func announcementLink(a *system_model.Announcement) string {
	return fmt.Sprintf("%s/admin/announcements/%d", setting.AppSubURL, a.ID)
}

// Announcements shows all announcements
func Announcements(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.announcements")
	ctx.Data["PageIsAdminAnnouncements"] = true

	page := max(ctx.FormInt("page"), 1)
	opts := db.ListOptions{Page: page, PageSize: setting.UI.Admin.NoticePagingNum}
	list, count, err := system_model.FindAnnouncements(ctx, opts)
	if err != nil {
		ctx.ServerError("FindAnnouncements", err)
		return
	}

	ctx.Data["Announcements"] = list
	ctx.Data["Total"] = count
	ctx.Data["Now"] = timeutil.TimeStampNow()

	pager := context.NewPagination(int(count), opts.PageSize, opts.Page, 5)
	ctx.Data["Page"] = pager

	ctx.HTML(http.StatusOK, tplAnnouncements)
}

func prepareAnnouncementForm(ctx *context.Context) {
	ctx.Data["PageIsAdminAnnouncements"] = true
	ctx.Data["AnnouncementTypes"] = system_model.AnnouncementTypes
	ctx.Data["AnnouncementAudiences"] = system_model.AnnouncementAudiences
	ctx.Data["TimeZone"] = time.Now().In(setting.DefaultUILocation).Format("MST, UTC-07:00")
}

func formatAnnouncementTime(ts timeutil.TimeStamp) string {
	if ts == 0 {
		return ""
	}
	return ts.AsTimeInLocation(setting.DefaultUILocation).Format(announcementTimeLayout)
}

func parseAnnouncementTime(value string) (timeutil.TimeStamp, error) {
	if value == "" {
		return 0, nil
	}
	t, err := time.ParseInLocation(announcementTimeLayout, value, setting.DefaultUILocation)
	if err != nil {
		return 0, err
	}
	return timeutil.TimeStamp(t.Unix()), nil
}

// NewAnnouncement renders the page to create an announcement
func NewAnnouncement(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.announcements.new")
	prepareAnnouncementForm(ctx)
	ctx.Data["type"] = string(system_model.AnnouncementInfo)
	ctx.Data["audience"] = string(system_model.AnnouncementAudienceEveryone)
	ctx.Data["dismissible"] = true
	ctx.HTML(http.StatusOK, tplAnnouncementEdit)
}

// applyAnnouncementForm copies the form into the announcement, rendering the
// form with an error and returning false if it is invalid
func applyAnnouncementForm(ctx *context.Context, a *system_model.Announcement) bool {
	form := web.GetForm(ctx).(*forms.AnnouncementForm)
	ctx.Data["dismissible"] = form.Dismissible
	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplAnnouncementEdit)
		return false
	}

	start, err := parseAnnouncementTime(form.StartTime)
	if err != nil {
		ctx.Data["Err_StartTime"] = true
		ctx.RenderWithErr(ctx.Tr("admin.announcements.invalid_time"), tplAnnouncementEdit, form)
		return false
	}
	end, err := parseAnnouncementTime(form.EndTime)
	if err != nil {
		ctx.Data["Err_EndTime"] = true
		ctx.RenderWithErr(ctx.Tr("admin.announcements.invalid_time"), tplAnnouncementEdit, form)
		return false
	}
	if start != 0 && end != 0 && end <= start {
		ctx.Data["Err_EndTime"] = true
		ctx.RenderWithErr(ctx.Tr("admin.announcements.end_before_start"), tplAnnouncementEdit, form)
		return false
	}

	a.Message = form.Message
	a.Type = system_model.AnnouncementType(form.Type)
	a.Audience = system_model.AnnouncementAudience(form.Audience)
	a.Dismissible = form.Dismissible
	a.StartUnix = start
	a.EndUnix = end
	return true
}

// NewAnnouncementPost creates an announcement
func NewAnnouncementPost(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.announcements.new")
	prepareAnnouncementForm(ctx)

	a := &system_model.Announcement{CreatedByID: ctx.Doer.ID}
	if !applyAnnouncementForm(ctx, a) {
		return
	}
	if err := announcement_service.Create(ctx, a); err != nil {
		ctx.ServerError("CreateAnnouncement", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("admin.announcements.created"))
	ctx.Redirect(setting.AppSubURL + "/admin/announcements")
}

func getAnnouncement(ctx *context.Context) *system_model.Announcement {
	a, err := system_model.GetAnnouncementByID(ctx, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetAnnouncementByID", system_model.IsErrAnnouncementNotExist, err)
		return nil
	}
	return a
}

func prepareAnnouncementEdit(ctx *context.Context, a *system_model.Announcement) {
	ctx.Data["Title"] = ctx.Tr("admin.announcements.edit")
	prepareAnnouncementForm(ctx)
	ctx.Data["Announcement"] = a
	ctx.Data["AnnouncementLink"] = announcementLink(a)
}

// EditAnnouncement renders the page to edit an announcement
func EditAnnouncement(ctx *context.Context) {
	a := getAnnouncement(ctx)
	if ctx.Written() {
		return
	}
	prepareAnnouncementEdit(ctx, a)
	ctx.Data["message"] = a.Message
	ctx.Data["type"] = string(a.Type)
	ctx.Data["audience"] = string(a.Audience)
	ctx.Data["dismissible"] = a.Dismissible
	ctx.Data["start_time"] = formatAnnouncementTime(a.StartUnix)
	ctx.Data["end_time"] = formatAnnouncementTime(a.EndUnix)
	ctx.HTML(http.StatusOK, tplAnnouncementEdit)
}

// EditAnnouncementPost updates an announcement
func EditAnnouncementPost(ctx *context.Context) {
	a := getAnnouncement(ctx)
	if ctx.Written() {
		return
	}
	prepareAnnouncementEdit(ctx, a)

	if !applyAnnouncementForm(ctx, a) {
		return
	}
	if err := announcement_service.Update(ctx, a); err != nil {
		ctx.ServerError("UpdateAnnouncement", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("admin.announcements.updated"))
	ctx.Redirect(setting.AppSubURL + "/admin/announcements")
}

// DeleteAnnouncement deletes an announcement
func DeleteAnnouncement(ctx *context.Context) {
	a := getAnnouncement(ctx)
	if ctx.Written() {
		return
	}
	if err := announcement_service.Delete(ctx, a.ID); err != nil {
		ctx.ServerError("DeleteAnnouncement", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("admin.announcements.deleted"))
	ctx.JSONRedirect(setting.AppSubURL + "/admin/announcements")
}
