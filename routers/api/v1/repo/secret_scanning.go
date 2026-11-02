// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"
	"slices"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	secretscan_service "forgejo.org/services/secretscan"
	wiki_service "forgejo.org/services/wiki"
)

// MustSeeSecretAlerts is the gate of the secret alert routes (see mustSeeAlerts); scanning off is a 404 too.
var MustSeeSecretAlerts = mustSeeAlerts("secret", secretscan_service.Enabled)

// ListSecretScanningAlerts lists the secret alerts of a repository
func ListSecretScanningAlerts(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/secret-scanning/alerts repository repoListSecretScanningAlerts
	// ---
	// summary: List the secret alerts of a repository
	// description: Secrets found in the code and wiki of the repository, newest first. The alerts never hold the
	//   secret. Only people who can write to the code, and auditors, see them; everyone else gets 404, as does a
	//   repository secret scanning is turned off for. Someone who can't read the wiki (with the Wiki unit off, nobody
	//   can) doesn't see an alert that is only in the wiki, nor its places in the wiki.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: state
	//   in: query
	//   description: only alerts in this state
	//   type: string
	//   enum: [open, resolved]
	// - name: resolution
	//   in: query
	//   description: only alerts resolved with one of these resolutions, comma separated
	//   type: string
	// - name: secret_type
	//   in: query
	//   description: only alerts of these secret types (rule IDs), comma separated
	//   type: string
	// - name: sort
	//   in: query
	//   description: what to sort by, newest first unless direction is asc
	//   type: string
	//   enum: [created, updated]
	// - name: direction
	//   in: query
	//   description: the order
	//   type: string
	//   enum: [asc, desc]
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
	//     "$ref": "#/responses/SecretScanningAlertList"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	repo := ctx.Repo().Repository
	opts := &secretscan_model.AlertSearchOptions{ListOptions: utils.GetListOptions(ctx), RepoID: repo.ID}
	opts.CodeOnly = !ctx.Permission().CanRead(unit.TypeWiki) // an alert that is only in the wiki is not for them
	if err := opts.ParseFilters(ctx.FormString("state"), ctx.FormString("resolution"), ctx.FormString("secret_type"), ctx.FormString("sort"), ctx.FormString("direction")); err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	opts.SetDefaultValues()
	alerts, total, err := db.FindAndCount[secretscan_model.Alert](ctx, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindAndCount", err)
		return
	}
	list, err := convert.ToSecretScanningAlerts(ctx, ctx.Doer(), repo, alerts, ctx.Permission().CanRead(unit.TypeWiki))
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToSecretScanningAlerts", err)
		return
	}
	ctx.SetLinkHeader(int(total), opts.PageSize)
	ctx.SetTotalCountHeader(total)
	ctx.JSON(http.StatusOK, list)
}

// GetSecretScanningStatus sums up the scan of a repository
func GetSecretScanningStatus(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/secret-scanning/status repository repoGetSecretScanningStatus
	// ---
	// summary: How far the secret scan of a repository has come
	// description: One summary for the code, the wiki and the pull refs. Visible to the same people as the alerts.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/SecretScanningStatus"
	//   "404":
	//     "$ref": "#/responses/notFound"

	scans, err := secretscan_model.FindScans(ctx, ctx.Repo().Repository.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindScans", err)
		return
	}
	// the wiki's state is for those who can read it, the text's for those who can read its units
	canReadWiki := ctx.Permission().CanRead(unit.TypeWiki)
	canReadText := secretscan_service.TextStatusVisible(ctx, ctx.Repo().Repository, ctx.Permission().CanRead)
	scans = slices.DeleteFunc(scans, func(s *secretscan_model.Scan) bool {
		return s.Kind == secretscan_model.KindWiki && !canReadWiki || s.Kind == secretscan_model.KindIssue && !canReadText
	})
	ctx.JSON(http.StatusOK, convert.ToSecretScanningStatus(scans))
}

// GetSecretScanningAlert gets a secret alert with its places
func GetSecretScanningAlert(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/secret-scanning/alerts/{index} repository repoGetSecretScanningAlert
	// ---
	// summary: Get a secret alert
	// description: The alert; its places are at locations_url.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: number of the alert
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/SecretScanningAlert"
	//   "404":
	//     "$ref": "#/responses/notFound"

	alert := loadSecretScanningAlert(ctx)
	if alert == nil {
		return
	}
	respondSecretScanningAlert(ctx, alert)
}

// EditSecretScanningAlert closes or reopens a secret alert
func EditSecretScanningAlert(ctx *context.APIContext) {
	// swagger:operation PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{index} repository repoEditSecretScanningAlert
	// ---
	// summary: Close or reopen a secret alert
	// description: State resolved needs a resolution (false_positive, wont_fix, revoked or used_in_tests) and takes an
	//   optional resolution_comment of at most 1000 bytes that must not look like a secret or hold the secret of the
	//   alert. State open reopens a resolved alert. An alert that is not open can't be resolved again, and one that
	//   is not resolved can't be reopened by two requests at once (409).
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: number of the alert
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditSecretScanningAlertOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/SecretScanningAlert"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/conflict"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	form := web.GetForm(ctx).(*api.EditSecretScanningAlertOption)
	alert := loadSecretScanningAlert(ctx)
	if alert == nil {
		return
	}
	var err error
	switch form.State {
	case secretscan_model.StateOpen:
		if form.Resolution != "" || form.ResolutionComment != "" {
			ctx.Error(http.StatusUnprocessableEntity, "", "a resolution and a comment are only for resolving")
			return
		}
		alert, err = secretscan_service.Reopen(ctx, ctx.Repo().Repository, alert.Index)
	case "resolved":
		alert, err = secretscan_service.Close(ctx, ctx.Repo().Repository, ctx.Doer(), alert.Index, form.Resolution, form.ResolutionComment, ctx.Permission().CanRead(unit.TypeWiki))
	default:
		ctx.Error(http.StatusUnprocessableEntity, "", "state must be open or resolved")
		return
	}
	switch {
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound()
	case errors.Is(err, secretscan_service.ErrConflict):
		ctx.Error(http.StatusConflict, "", "the alert changed, reload it")
	case errors.Is(err, secretscan_service.ErrArchived):
		ctx.Error(http.StatusLocked, "", "the repository is archived")
	case err != nil:
		ctx.Error(http.StatusInternalServerError, "secretscan_service", err)
	default:
		respondSecretScanningAlert(ctx, alert)
	}
}

// loadSecretScanningAlert finds the alert of the route in this repository only; a number that is not positive, is
// unknown or belongs to another repository is the same 404.
func loadSecretScanningAlert(ctx *context.APIContext) *secretscan_model.Alert {
	index := ctx.ParamsInt64("index")
	if index <= 0 {
		ctx.NotFound()
		return nil
	}
	alert, err := secretscan_model.GetVisibleAlert(ctx, ctx.Repo().Repository.ID, index, ctx.Permission().CanRead(unit.TypeWiki))
	if errors.Is(err, util.ErrNotExist) {
		ctx.NotFound()
		return nil
	}
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetAlert", err)
		return nil
	}
	return alert
}

func respondSecretScanningAlert(ctx *context.APIContext, alert *secretscan_model.Alert) {
	list, err := convert.ToSecretScanningAlerts(ctx, ctx.Doer(), ctx.Repo().Repository, []*secretscan_model.Alert{alert}, ctx.Permission().CanRead(unit.TypeWiki))
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToSecretScanningAlerts", err)
		return
	}
	ctx.JSON(http.StatusOK, list[0])
}

// ListSecretScanningAlertLocations lists the places of a secret alert
func ListSecretScanningAlertLocations(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/secret-scanning/alerts/{index}/locations repository repoListSecretScanningAlertLocations
	// ---
	// summary: List the places of a secret alert
	// description: In the order they were found. Places in the wiki are left out for people who can't read the wiki.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: number of the alert
	//   type: integer
	//   format: int64
	//   required: true
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
	//     "$ref": "#/responses/SecretScanningLocationList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	alert := loadSecretScanningAlert(ctx)
	if alert == nil {
		return
	}
	repo := ctx.Repo().Repository
	opts := &secretscan_model.LocationSearchOptions{ListOptions: utils.GetListOptions(ctx), RepoID: repo.ID, AlertID: alert.ID, NoWiki: !ctx.Permission().CanRead(unit.TypeWiki)}
	opts.SetDefaultValues()
	locs, total, err := db.FindAndCount[secretscan_model.Location](ctx, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindAndCount", err)
		return
	}
	ctx.SetLinkHeader(int(total), opts.PageSize)
	ctx.SetTotalCountHeader(total)
	// a place in text is data of the issue tracker: a token with scopes needs read:issue for it, as for /issues
	access := secretscan_model.TextAccess{Issues: ctx.Permission().CanRead(unit.TypeIssues), Pulls: ctx.Permission().CanRead(unit.TypePullRequests)}
	if has, scope := ctx.Authentication().Scope().Get(); has {
		if ok, err := scope.HasScope(auth_model.AccessTokenScopeReadIssue); err != nil || !ok {
			access = secretscan_model.TextAccess{}
		}
	}
	texts, err := secretscan_model.LoadTextPlaces(ctx, repo.ID, locs, access)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadTextPlaces", err)
		return
	}
	ctx.JSON(http.StatusOK, convert.ToSecretScanningLocations(repo, locs, texts, func(path string) string { return wiki_service.PageHTMLURL(repo, path) }))
}

// RedactSecretScanningText removes the secret of an alert from one text of an issue or pull request
func RedactSecretScanningText(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/secret-scanning/alerts/{index}/redact repository repoRedactSecretScanningText
	// ---
	// summary: Remove the secret of an alert from the text of an issue, pull request or comment
	// description: For people who may resolve the alert and read the issue or pull request (a token with scopes also
	//   needs write:issue). The secret is found again in the text as it is now and every copy of it is replaced with
	//   "[secret removed]"; the versions in the text's edit history are emptied (for a title, the secret is removed from
	//   the title changes of the timeline), the alert's places in the text are marked removed and the change is
	//   audited. When the secret is already gone from the text, only the history versions that hold it are emptied
	//   and the rest is done (204 too). Nobody is notified. It can't be undone, and the secret must still be revoked.
	//   A text the alert has no place in, or that the caller can't read, is 404; a text the detector can't read whole,
	//   an alert whose pattern is no longer used and a text with nothing left to remove are 422, a text that changed
	//   while it was redacted 409.
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: number of the alert
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/RedactSecretScanningTextOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/conflict"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	// the text is data of the issue tracker: a token with scopes needs write:issue, asked before anything is looked up
	if has, scope := ctx.Authentication().Scope().Get(); has {
		if ok, err := scope.HasScope(auth_model.AccessTokenScopeWriteIssue); err != nil || !ok {
			ctx.Error(http.StatusForbidden, "", "the token needs the write:issue scope")
			return
		}
	}
	form := web.GetForm(ctx).(*api.RedactSecretScanningTextOption)
	alert := loadSecretScanningAlert(ctx)
	if alert == nil {
		return
	}
	perm := ctx.Permission()
	target := secretscan_service.RedactTarget{Issue: form.IssueNumber, Field: form.Field, Comment: form.CommentID}
	access := secretscan_model.TextAccess{Issues: perm.CanRead(unit.TypeIssues), Pulls: perm.CanRead(unit.TypePullRequests)}
	switch _, err := secretscan_service.RedactText(ctx, ctx.Repo().Repository, ctx.Doer(), alert.Index, target, access, perm.CanRead(unit.TypeWiki)); {
	case err == nil:
		ctx.Status(http.StatusNoContent)
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound()
	case errors.Is(err, secretscan_service.ErrRedactChanged):
		ctx.Error(http.StatusConflict, "", "the text changed meanwhile, try again")
	case errors.Is(err, secretscan_service.ErrArchived):
		ctx.Error(http.StatusLocked, "", "the repository is archived")
	default:
		ctx.Error(http.StatusInternalServerError, "RedactText", err)
	}
}
