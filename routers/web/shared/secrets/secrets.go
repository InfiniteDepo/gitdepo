// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"errors"

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

	normalizedData := util.ReserveLineBreakForTextarea(form.Data)
	secret, err := secrets_service.CreateSecret(ctx, ownerID, groupID, repoID, environmentID, form.Name, normalizedData)
	if err != nil {
		log.Error("InsertEncryptedSecret failed: %v", err)
		ctx.JSONError(ctx.Tr("secrets.creation.failed"))
		return
	}

	ctx.Flash.Success(ctx.Tr("secrets.creation.success", secret.Name))
	ctx.JSONRedirect(redirectURL)
}

func EditSecretPost(ctx *context.Context, ownerID, groupID, repoID, environmentID, id int64, redirectURL string) {
	form := web.GetForm(ctx).(*forms.EditSecretForm)

	secret, err := secrets_service.EditSecret(ctx, ownerID, groupID, repoID, environmentID, id, form.Name, util.ReserveLineBreakForTextarea(form.Data))
	if errors.Is(err, util.ErrNotExist) {
		ctx.NotFound("GetSecretByID", err)
		return
	}
	if err != nil {
		log.Error("UpdateSecret failed: %v", err)
		ctx.JSONError(ctx.Tr("actions.secrets.mutation.failure_message", form.Name))
		return
	}

	ctx.Flash.Success(ctx.Tr("actions.secrets.mutation.success_message", secret.Name))
	ctx.JSONRedirect(redirectURL)
}

func DeleteSecretPost(ctx *context.Context, ownerID, groupID, repoID, environmentID, id int64, redirectURL string) {
	err := secrets_service.DeleteSecretByID(ctx, ownerID, groupID, repoID, environmentID, id)
	if err != nil {
		log.Error("DeleteSecretByID(%d) failed: %v", id, err)
		ctx.JSONError(ctx.Tr("secrets.deletion.failed"))
		return
	}

	ctx.Flash.Success(ctx.Tr("secrets.deletion.success"))
	ctx.JSONRedirect(redirectURL)
}
