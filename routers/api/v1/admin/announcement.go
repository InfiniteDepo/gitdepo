// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"time"

	system_model "forgejo.org/models/system"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	announcement_service "forgejo.org/services/announcement"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

func getAnnouncementFromParams(ctx *context.APIContext) *system_model.Announcement {
	a, err := system_model.GetAnnouncementByID(ctx, ctx.ParamsInt64(":id"))
	if err != nil {
		if system_model.IsErrAnnouncementNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetAnnouncementByID", err)
		}
		return nil
	}
	return a
}

func announcementTimeStamp(t *time.Time) timeutil.TimeStamp {
	if t == nil || t.IsZero() || t.Unix() <= 0 {
		return 0
	}
	return timeutil.TimeStamp(t.Unix())
}

// validateAnnouncement writes a 422 response and returns false if the announcement is not valid
func validateAnnouncement(ctx *context.APIContext, a *system_model.Announcement) bool {
	var err error
	switch {
	case a.Message == "":
		err = errors.New("message cannot be empty")
	case !a.Type.IsValid():
		err = errors.New("invalid type")
	case !a.Audience.IsValid():
		err = errors.New("invalid audience")
	case a.StartUnix != 0 && a.EndUnix != 0 && a.EndUnix <= a.StartUnix:
		err = errors.New("end_at must be after start_at")
	}
	if err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "", err)
		return false
	}
	return true
}

// ListAnnouncements lists all announcements
func ListAnnouncements(ctx *context.APIContext) {
	// swagger:operation GET /admin/announcements admin adminListAnnouncements
	// ---
	// summary: List all announcements, including inactive ones
	// produces:
	// - application/json
	// parameters:
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/AnnouncementList"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	listOptions := utils.GetListOptions(ctx)
	listOptions.SetDefaultValues()
	list, count, err := system_model.FindAnnouncements(ctx, listOptions)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindAnnouncements", err)
		return
	}

	ctx.SetLinkHeader(int(count), listOptions.PageSize)
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, convert.ToAnnouncements(list))
}

// CreateAnnouncement creates an announcement
func CreateAnnouncement(ctx *context.APIContext) {
	// swagger:operation POST /admin/announcements admin adminCreateAnnouncement
	// ---
	// summary: Create an announcement
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateAnnouncementOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/Announcement"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.CreateAnnouncementOption)
	a := &system_model.Announcement{
		Message:     form.Message,
		Type:        system_model.AnnouncementType(form.Type),
		Audience:    system_model.AnnouncementAudience(form.Audience),
		Dismissible: form.Dismissible,
		StartUnix:   announcementTimeStamp(form.StartAt),
		EndUnix:     announcementTimeStamp(form.EndAt),
		CreatedByID: ctx.Doer().ID,
	}
	if !validateAnnouncement(ctx, a) {
		return
	}
	if err := announcement_service.Create(ctx, a); err != nil {
		ctx.Error(http.StatusInternalServerError, "CreateAnnouncement", err)
		return
	}
	ctx.JSON(http.StatusCreated, convert.ToAnnouncement(a))
}

// GetAnnouncement gets an announcement
func GetAnnouncement(ctx *context.APIContext) {
	// swagger:operation GET /admin/announcements/{id} admin adminGetAnnouncement
	// ---
	// summary: Get an announcement
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the announcement
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/Announcement"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	a := getAnnouncementFromParams(ctx)
	if ctx.Written() {
		return
	}
	ctx.JSON(http.StatusOK, convert.ToAnnouncement(a))
}

// EditAnnouncement edits an announcement
func EditAnnouncement(ctx *context.APIContext) {
	// swagger:operation PATCH /admin/announcements/{id} admin adminEditAnnouncement
	// ---
	// summary: Edit an announcement
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the announcement
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditAnnouncementOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/Announcement"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	a := getAnnouncementFromParams(ctx)
	if ctx.Written() {
		return
	}
	form := web.GetForm(ctx).(*api.EditAnnouncementOption)
	if form.Message != nil {
		a.Message = *form.Message
	}
	if form.Type != nil {
		a.Type = system_model.AnnouncementType(*form.Type)
	}
	if form.Audience != nil {
		a.Audience = system_model.AnnouncementAudience(*form.Audience)
	}
	if form.Dismissible != nil {
		a.Dismissible = *form.Dismissible
	}
	if form.StartAt != nil {
		a.StartUnix = announcementTimeStamp(form.StartAt)
	}
	if form.EndAt != nil {
		a.EndUnix = announcementTimeStamp(form.EndAt)
	}
	if !validateAnnouncement(ctx, a) {
		return
	}
	if err := announcement_service.Update(ctx, a); err != nil {
		ctx.Error(http.StatusInternalServerError, "UpdateAnnouncement", err)
		return
	}
	ctx.JSON(http.StatusOK, convert.ToAnnouncement(a))
}

// DeleteAnnouncement deletes an announcement
func DeleteAnnouncement(ctx *context.APIContext) {
	// swagger:operation DELETE /admin/announcements/{id} admin adminDeleteAnnouncement
	// ---
	// summary: Delete an announcement
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the announcement
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	a := getAnnouncementFromParams(ctx)
	if ctx.Written() {
		return
	}
	if err := announcement_service.Delete(ctx, a.ID); err != nil {
		ctx.Error(http.StatusInternalServerError, "DeleteAnnouncement", err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
