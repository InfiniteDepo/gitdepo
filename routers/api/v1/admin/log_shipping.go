// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"

	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	logshipping_service "forgejo.org/services/logshipping"
)

func toAPILogShippingDestination(d logshipping_service.Destination) *api.LogShippingDestination {
	a := &api.LogShippingDestination{
		ID: d.ID, Name: d.Name, Type: d.Type, Endpoint: d.Endpoint, HasKey: d.HasKey, Headers: []*api.LogShippingHeader{},
		NDJSON: d.NDJSON, Enabled: d.Enabled, LogTypes: d.LogTypes, Level: d.Level, Expression: d.Expression, Exclusion: d.Exclusion,
		Status: api.LogShippingStatus{Sent: d.Status.Sent, Dropped: d.Status.Dropped, Errors: d.Status.Errors, LastSuccess: d.Status.LastSuccess, LastError: d.Status.LastError},
	}
	for _, h := range d.Headers {
		a.Headers = append(a.Headers, &api.LogShippingHeader{Name: h.Name, HasValue: h.HasValue})
	}
	return a
}

// logShippingAdmin refuses everyone but an active site admin, whatever the token: this configures where logs are sent
func logShippingAdmin(ctx *context.APIContext) bool {
	if !common.IsMaintenanceAdmin(ctx.Doer()) || !ctx.Reducer().AllowAdminOverride() {
		ctx.Error(http.StatusForbidden, "", "site administrators only")
		return false
	}
	return true
}

func logShippingError(ctx *context.APIContext, err error) {
	switch {
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound()
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
	case errors.Is(err, logshipping_service.ErrRateLimited):
		ctx.Error(http.StatusTooManyRequests, "", err)
	default:
		ctx.Error(http.StatusInternalServerError, "LogShipping", err)
	}
}

func headerInputs(in []*api.LogShippingHeaderOption) *[]logshipping_service.HeaderInput {
	out := make([]logshipping_service.HeaderInput, 0, len(in))
	for _, h := range in {
		if h != nil {
			out = append(out, logshipping_service.HeaderInput{Name: h.Name, Value: h.Value})
		}
	}
	return &out
}

// ListLogShippingDestinations lists the log destinations
func ListLogShippingDestinations(ctx *context.APIContext) {
	// swagger:operation GET /admin/log-shipping/destinations admin adminListLogShippingDestinations
	// ---
	// summary: List the log destinations
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/LogShippingDestinationList"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	if !logShippingAdmin(ctx) {
		return
	}
	list, err := logshipping_service.List(ctx)
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	out := make([]*api.LogShippingDestination, 0, len(list))
	for _, d := range list {
		out = append(out, toAPILogShippingDestination(d))
	}
	ctx.JSON(http.StatusOK, out)
}

// GetLogShippingDestination gets a log destination
func GetLogShippingDestination(ctx *context.APIContext) {
	// swagger:operation GET /admin/log-shipping/destinations/{id} admin adminGetLogShippingDestination
	// ---
	// summary: Get a log destination
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the destination
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/LogShippingDestination"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !logShippingAdmin(ctx) {
		return
	}
	d, err := logshipping_service.Get(ctx, ctx.Params("id"))
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, toAPILogShippingDestination(d))
}

// CreateLogShippingDestination creates a log destination
func CreateLogShippingDestination(ctx *context.APIContext) {
	// swagger:operation POST /admin/log-shipping/destinations admin adminCreateLogShippingDestination
	// ---
	// summary: Create a log destination
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateLogShippingDestinationOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/LogShippingDestination"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !logShippingAdmin(ctx) {
		return
	}
	form := web.GetForm(ctx).(*api.CreateLogShippingDestinationOption)
	in := logshipping_service.Input{
		Name: &form.Name, Type: &form.Type, Endpoint: &form.Endpoint, Key: &form.Key, Level: &form.Level,
		Expression: &form.Expression, Exclusion: &form.Exclusion, LogTypes: &form.LogTypes, NDJSON: &form.NDJSON,
		Enabled: form.Enabled, Headers: headerInputs(form.Headers),
	}
	if form.Level == "" {
		in.Level = nil // the default
	}
	d, err := logshipping_service.Save(ctx, ctx.Doer(), "", in)
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	v, err := logshipping_service.Get(ctx, d.ID)
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.JSON(http.StatusCreated, toAPILogShippingDestination(v))
}

// EditLogShippingDestination changes a log destination
func EditLogShippingDestination(ctx *context.APIContext) {
	// swagger:operation PATCH /admin/log-shipping/destinations/{id} admin adminEditLogShippingDestination
	// ---
	// summary: Change a log destination
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the destination
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditLogShippingDestinationOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/LogShippingDestination"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !logShippingAdmin(ctx) {
		return
	}
	form := web.GetForm(ctx).(*api.EditLogShippingDestinationOption)
	in := logshipping_service.Input{
		Name: form.Name, Endpoint: form.Endpoint, Key: form.Key, Level: form.Level, Expression: form.Expression,
		Exclusion: form.Exclusion, LogTypes: form.LogTypes, NDJSON: form.NDJSON, Enabled: form.Enabled,
	}
	if form.Headers != nil {
		in.Headers = headerInputs(*form.Headers)
	}
	d, err := logshipping_service.Save(ctx, ctx.Doer(), ctx.Params("id"), in)
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	v, err := logshipping_service.Get(ctx, d.ID)
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, toAPILogShippingDestination(v))
}

// DeleteLogShippingDestination deletes a log destination
func DeleteLogShippingDestination(ctx *context.APIContext) {
	// swagger:operation DELETE /admin/log-shipping/destinations/{id} admin adminDeleteLogShippingDestination
	// ---
	// summary: Delete a log destination
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the destination
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !logShippingAdmin(ctx) {
		return
	}
	if err := logshipping_service.Remove(ctx, ctx.Doer(), ctx.Params("id")); err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// TestLogShippingDestination sends a test event to a saved log destination
func TestLogShippingDestination(ctx *context.APIContext) {
	// swagger:operation POST /admin/log-shipping/destinations/{id}/test admin adminTestLogShippingDestination
	// ---
	// summary: Send a test event to a log destination
	// description: Sends one event with logtype "test" to the saved destination and reports the status and a class of failure. At most one per destination every 5 seconds.
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the destination
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/LogShippingTestResult"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "429":
	//     "$ref": "#/responses/error"

	if !logShippingAdmin(ctx) {
		return
	}
	ctx.Req.Body = http.MaxBytesReader(ctx.Resp, ctx.Req.Body, 1024) // the test takes no input
	res, err := logshipping_service.Test(ctx, ctx.Params("id"))
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, &api.LogShippingTestResult{Status: res.Status, Error: res.Error})
}
