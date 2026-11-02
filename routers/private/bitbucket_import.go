// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package private

import (
	"errors"
	"net/http"
	"strings"

	"forgejo.org/modules/json"
	"forgejo.org/modules/private"
	"forgejo.org/modules/util"
	app_context "forgejo.org/services/context"
	"forgejo.org/services/migrations"
)

// BitbucketImport runs a Bitbucket import for `forgejo admin bitbucket-import`. The body holds the Bitbucket token:
// it is never logged and only kept for the run.
func BitbucketImport(ctx *app_context.PrivateContext) {
	var params private.BitbucketImportParams
	if err := json.NewDecoder(ctx.Req.Body).Decode(&params); err != nil {
		ctx.JSON(http.StatusBadRequest, private.Response{UserMsg: "invalid request"})
		return
	}
	opts := migrations.BitbucketImportOptions{
		Server:       params.Server,
		Username:     params.Username,
		Token:        params.Token,
		Projects:     params.Projects,
		DryRun:       params.DryRun,
		PullRequests: params.PullRequests,
		KeyExpiry:    params.KeyExpiry,
		SkipUnmapped: params.SkipUnmapped,
	}
	token := params.Token
	params.Token = ""
	report, err := migrations.ImportBitbucket(ctx, params.Doer, params.Org, opts)
	opts.Token = ""
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, util.ErrPermissionDenied):
			status = http.StatusForbidden
		case errors.Is(err, util.ErrNotExist):
			status = http.StatusNotFound
		case errors.Is(err, util.ErrInvalidArgument), errors.Is(err, util.ErrAlreadyExist):
			status = http.StatusBadRequest
		}
		msg := util.SanitizeCredentialURLs(err.Error())
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "***")
		}
		msg = util.StripControl(msg)
		ctx.JSON(status, private.Response{Err: msg, UserMsg: msg})
		return
	}
	ctx.JSON(http.StatusOK, report)
}
