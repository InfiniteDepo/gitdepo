// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"errors"
	"net/http"

	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	secrets_service "forgejo.org/services/secrets"
)

// SetSecretsContext lists the secrets of a level: an owner, a project of an owner, a repository, or (environmentID not
// 0) an environment of the repository. The handlers below take the same level.
func SetSecretsContext(ctx *context.Context, ownerID, groupID, repoID, environmentID int64) {
	secrets, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{OwnerID: ownerID, GroupID: groupID, RepoID: repoID, EnvironmentID: environmentID})
	if err != nil {
		ctx.ServerError("FindSecrets", err)
		return
	}

	ctx.Data["Secrets"] = secrets
}

func CreateSecretPost(ctx *context.Context, ownerID, groupID, repoID, environmentID int64, redirectURL string) {
	form := web.GetForm(ctx).(*forms.CreateSecretForm)

	secret, err := secrets_service.CreateSecret(ctx, ownerID, groupID, repoID, environmentID, form.Name, form.Data)
	if err != nil {
		Failed(ctx, "CreateSecret", err, ctx.Tr("secrets.creation.failed"), ctx.Tr("actions.secrets.value_too_large", secret_model.MaxValueSize>>10))
		return
	}

	ctx.Flash.Success(ctx.Tr("secrets.creation.success", secret.Name))
	ctx.JSONRedirect(redirectURL)
}

func EditSecretPost(ctx *context.Context, ownerID, groupID, repoID, environmentID, id int64, redirectURL string) {
	form := web.GetForm(ctx).(*forms.EditSecretForm)

	secret, err := secrets_service.EditSecret(ctx, ownerID, groupID, repoID, environmentID, id, form.Name, form.Data)
	if err != nil {
		Failed(ctx, "EditSecret", err, ctx.Tr("actions.secrets.mutation.failure_message", form.Name), ctx.Tr("actions.secrets.value_too_large", secret_model.MaxValueSize>>10))
		return
	}

	ctx.Flash.Success(ctx.Tr("actions.secrets.mutation.success_message", secret.Name))
	ctx.JSONRedirect(redirectURL)
}

func DeleteSecretPost(ctx *context.Context, ownerID, groupID, repoID, environmentID, id int64, redirectURL string) {
	err := secrets_service.DeleteSecretByID(ctx, ownerID, groupID, repoID, environmentID, id)
	if err != nil {
		Failed(ctx, "DeleteSecretByID", err, ctx.Tr("secrets.deletion.failed"), nil)
		return
	}

	ctx.Flash.Success(ctx.Tr("secrets.deletion.success"))
	ctx.JSONRedirect(redirectURL)
}

// Failed answers a change of a secret or variable that didn't happen: 404 for one that is not of the level (one answer
// for edit and delete), 403 for a change that is not the doer's own act (a refusal, logged at Info), tooLarge for a
// value over secret_model.MaxValueSize, otherwise msg, with the error logged.
func Failed(ctx *context.Context, what string, err error, msg, tooLarge any) {
	switch {
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound(what, err)
	case errors.Is(err, util.ErrPermissionDenied):
		log.Info("%s refused: %v", what, err)
		ctx.Error(http.StatusForbidden)
	case errors.Is(err, secret_model.ErrValueTooLarge):
		ctx.JSONError(tooLarge)
	case errors.Is(err, secret_model.ErrEnvironmentFull):
		ctx.JSONError(ctx.Tr("actions.environments.full", secret_model.MaxPerEnvironment, secret_model.MaxPerEnvironment))
	default:
		log.Error("%s failed: %v", what, err)
		ctx.JSONError(msg)
	}
}
