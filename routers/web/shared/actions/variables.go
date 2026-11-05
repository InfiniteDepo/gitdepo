// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"errors"
	"net/http"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

// SetVariablesContext lists the variables of a level as shared/secrets.SetSecretsContext names it.
func SetVariablesContext(ctx *context.Context, ownerID, groupID, repoID, environmentID int64) {
	variables, err := db.Find[actions_model.ActionVariable](ctx, actions_model.FindVariablesOpts{
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
	})
	if err != nil {
		ctx.ServerError("FindVariables", err)
		return
	}
	ctx.Data["Variables"] = variables
}

func CreateVariable(ctx *context.Context, ownerID, groupID, repoID, environmentID int64, redirectURL string) {
	form := web.GetForm(ctx).(*forms.EditVariableForm)

	v, err := actions_service.CreateVariable(ctx, ownerID, groupID, repoID, environmentID, form.Name, form.Data)
	if err != nil {
		failed(ctx, "CreateVariable", err, true, ctx.Tr("actions.variables.creation.failed"))
		return
	}

	ctx.Flash.Success(ctx.Tr("actions.variables.creation.success", v.Name))
	ctx.JSONRedirect(redirectURL)
}

func UpdateVariable(ctx *context.Context, ownerID, groupID, repoID, environmentID int64, redirectURL string) {
	id := ctx.ParamsInt64(":variable_id")
	form := web.GetForm(ctx).(*forms.EditVariableForm)

	if ok, err := actions_service.UpdateVariable(ctx, id, ownerID, groupID, repoID, environmentID, form.Name, form.Data); err != nil || !ok {
		failed(ctx, "UpdateVariable", err, ok, ctx.Tr("actions.variables.update.failed"))
		return
	}
	ctx.Flash.Success(ctx.Tr("actions.variables.update.success"))
	ctx.JSONRedirect(redirectURL)
}

func DeleteVariable(ctx *context.Context, ownerID, groupID, repoID, environmentID int64, redirectURL string) {
	id := ctx.ParamsInt64(":variable_id")

	if ok, err := actions_service.DeleteVariableByID(ctx, id, ownerID, groupID, repoID, environmentID); err != nil || !ok {
		failed(ctx, "DeleteVariableByID", err, ok, ctx.Tr("actions.variables.deletion.failed"))
		return
	}
	ctx.Flash.Success(ctx.Tr("actions.variables.deletion.success"))
	ctx.JSONRedirect(redirectURL)
}

// failed answers a change of a variable that didn't happen (found false: no variable of that ID in the level): 404
// for a variable that is not of the level (one answer for edit and delete), 403 for a change that is not the doer's
// own act (a refusal, logged at Info), otherwise the message, with the error logged.
func failed(ctx *context.Context, what string, err error, found bool, msg any) {
	switch {
	case errors.Is(err, util.ErrPermissionDenied):
		log.Info("%s refused: %v", what, err)
		ctx.Error(http.StatusForbidden)
	case errors.Is(err, util.ErrNotExist), err == nil && !found:
		ctx.NotFound(what, err)
	case errors.Is(err, secret_model.ErrValueTooLarge):
		ctx.JSONError(ctx.Tr("actions.variables.value_too_large", secret_model.MaxValueSize>>10))
	case errors.Is(err, secret_model.ErrEnvironmentFull):
		ctx.JSONError(ctx.Tr("actions.environments.full", secret_model.MaxPerEnvironment, secret_model.MaxPerEnvironment))
	default:
		log.Error("%s failed: %v", what, err)
		ctx.JSONError(msg)
	}
}
