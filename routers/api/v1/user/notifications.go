// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"net/http"

	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	user_service "forgejo.org/services/user"
)

func notificationSettings(ctx *context.APIContext) {
	all, err := user_model.LoadNotificationSettings(ctx, []int64{ctx.Doer().ID}, 0)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	res := api.NotificationSettings{Preset: ctx.Doer().EmailNotificationsPreference, Events: make(map[string]bool, len(user_model.AllNotifyEvents))}
	for _, e := range user_model.AllNotifyEvents {
		res.Events[string(e)] = all[ctx.Doer().ID].Enabled(e)
	}
	ctx.JSON(http.StatusOK, res)
}

// GetNotificationSettings returns the doer's email notification preset and event map
func GetNotificationSettings(ctx *context.APIContext) {
	// swagger:operation GET /user/settings/notifications user getNotificationSettings
	// ---
	// summary: Get the email notification settings of the current user
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/NotificationSettings"
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	notificationSettings(ctx)
}

// PutNotificationSettings updates the doer's email notification preset and event map
func PutNotificationSettings(ctx *context.APIContext) {
	// swagger:operation PUT /user/settings/notifications user putNotificationSettings
	// ---
	// summary: Update the email notification settings of the current user
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/NotificationSettings"
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/NotificationSettings"
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"
	doer := ctx.Doer()
	if doer.ID <= 0 || doer.IsActions() {
		ctx.Error(http.StatusForbidden, "", "this user has no settings")
		return
	}
	form := web.GetForm(ctx).(*api.NotificationSettings)
	if !user_model.IsValidEmailNotificationsPreference(form.Preset) {
		ctx.Error(http.StatusUnprocessableEntity, "", "invalid preset")
		return
	}
	for k := range form.Events {
		if !user_model.NotifyEvent(k).IsValid() {
			ctx.Error(http.StatusUnprocessableEntity, "", "unknown event "+k)
			return
		}
	}
	all, err := user_model.LoadNotificationSettings(ctx, []int64{doer.ID}, 0)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	// Rows come from the known events, never from the submitted keys; events missing from the body keep their value.
	events := make(map[user_model.NotifyEvent]bool, len(user_model.AllNotifyEvents))
	for _, e := range user_model.AllNotifyEvents {
		v, ok := form.Events[string(e)]
		events[e] = v
		if !ok {
			events[e] = all[doer.ID].Enabled(e)
		}
	}
	if err := user_model.SaveNotificationSettings(ctx, doer.ID, 0, events); err != nil {
		ctx.InternalServerError(err)
		return
	}
	if err := user_service.UpdateUser(ctx, doer, &user_service.UpdateOptions{EmailNotificationsPreference: optional.Some(form.Preset)}); err != nil {
		ctx.InternalServerError(err)
		return
	}
	notificationSettings(ctx)
}
