// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	shared_secrets "forgejo.org/routers/web/shared/secrets"
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
		shared_secrets.Failed(ctx, "CreateVariable", err, ctx.Tr("actions.variables.creation.failed"), tooLarge(ctx))
		return
	}

	ctx.Flash.Success(ctx.Tr("actions.variables.creation.success", v.Name))
	ctx.JSONRedirect(redirectURL)
}

func UpdateVariable(ctx *context.Context, ownerID, groupID, repoID, environmentID int64, redirectURL string) {
	id := ctx.ParamsInt64(":variable_id")
	form := web.GetForm(ctx).(*forms.EditVariableForm)

	if ok, err := actions_service.UpdateVariable(ctx, id, ownerID, groupID, repoID, environmentID, form.Name, form.Data); err != nil || !ok {
		shared_secrets.Failed(ctx, "UpdateVariable", notFound(ok, err), ctx.Tr("actions.variables.update.failed"), tooLarge(ctx))
		return
	}
	ctx.Flash.Success(ctx.Tr("actions.variables.update.success"))
	ctx.JSONRedirect(redirectURL)
}

func DeleteVariable(ctx *context.Context, ownerID, groupID, repoID, environmentID int64, redirectURL string) {
	id := ctx.ParamsInt64(":variable_id")

	if ok, err := actions_service.DeleteVariableByID(ctx, id, ownerID, groupID, repoID, environmentID); err != nil || !ok {
		shared_secrets.Failed(ctx, "DeleteVariableByID", notFound(ok, err), ctx.Tr("actions.variables.deletion.failed"), nil)
		return
	}
	ctx.Flash.Success(ctx.Tr("actions.variables.deletion.success"))
	ctx.JSONRedirect(redirectURL)
}

// notFound is the error of a change that found no variable of that ID in the level (ok false without an error).
func notFound(ok bool, err error) error {
	if err == nil && !ok {
		return util.ErrNotExist
	}
	return err
}

func tooLarge(ctx *context.Context) any {
	return ctx.Tr("actions.variables.value_too_large", secret_model.MaxValueSize>>10)
}
