// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/modules/base"
	shared_actions "forgejo.org/routers/web/shared/actions"
	shared_secrets "forgejo.org/routers/web/shared/secrets"
	"forgejo.org/services/context"
)

const tplRepoGroupActions base.TplName = "org/repo_group/actions"

// repoGroupActionsPage renders the secrets (kind "secrets") or variables list of a project,
// `/org/{org}/groups/{id}/settings/secrets`; the shared lists post to {{.Link}}.
func repoGroupActionsPage(ctx *context.Context, kind string) {
	org := ctx.Org.Organization
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if !prepareRepoGroupForm(ctx, "repo_group."+kind) {
		return
	}
	ctx.Data["RepoGroupLink"] = group.Link(org.Name)
	ctx.Data["Link"] = group.Link(org.Name) + "/-/settings/" + kind
	ctx.Data["PageType"] = kind
	// names also defined at the organization level, which this project overrides
	overrides := map[string]bool{}
	if kind == "secrets" {
		ctx.Data["Description"] = ctx.Tr("repo_group.secrets_desc")
		shared_secrets.SetSecretsContext(ctx, org.ID, group.ID, 0)
		orgSecrets, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{OwnerID: org.ID})
		if err != nil {
			ctx.ServerError("FindSecrets", err)
			return
		}
		for _, s := range orgSecrets {
			overrides[s.Name] = true
		}
	} else {
		ctx.Data["Description"] = ctx.Tr("repo_group.variables_desc")
		shared_actions.SetVariablesContext(ctx, org.ID, group.ID, 0)
		orgVars, err := db.Find[actions_model.ActionVariable](ctx, actions_model.FindVariablesOpts{OwnerID: org.ID})
		if err != nil {
			ctx.ServerError("FindVariables", err)
			return
		}
		for _, v := range orgVars {
			overrides[v.Name] = true
		}
	}
	ctx.Data["OverridesOrg"] = overrides
	if !ctx.Written() {
		ctx.HTML(http.StatusOK, tplRepoGroupActions)
	}
}

// RepoGroupSecrets lists the secrets of the project.
func RepoGroupSecrets(ctx *context.Context) { repoGroupActionsPage(ctx, "secrets") }

// RepoGroupVariables lists the variables of the project.
func RepoGroupVariables(ctx *context.Context) { repoGroupActionsPage(ctx, "variables") }

func repoGroupLinks(ctx *context.Context, kind string) (orgID, groupID int64, redirect string) {
	org := ctx.Org.Organization
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	return org.ID, group.ID, group.Link(org.Name) + "/-/settings/" + kind
}

// RepoGroupSecretCreate creates a project secret of the project.
func RepoGroupSecretCreate(ctx *context.Context) {
	orgID, groupID, redirect := repoGroupLinks(ctx, "secrets")
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_secrets.CreateSecretPost(ctx, orgID, groupID, 0, redirect)
}

// RepoGroupSecretEdit edits a project secret of the project.
func RepoGroupSecretEdit(ctx *context.Context) {
	orgID, groupID, redirect := repoGroupLinks(ctx, "secrets")
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_secrets.EditSecretPost(ctx, orgID, groupID, 0, ctx.ParamsInt64(":secret_id"), redirect)
}

// RepoGroupSecretDelete deletes a project secret of the project.
func RepoGroupSecretDelete(ctx *context.Context) {
	orgID, groupID, redirect := repoGroupLinks(ctx, "secrets")
	shared_secrets.DeleteSecretPost(ctx, orgID, groupID, 0, ctx.ParamsInt64(":secret_id"), redirect)
}

// RepoGroupVariableCreate creates a project variable of the project.
func RepoGroupVariableCreate(ctx *context.Context) {
	orgID, groupID, redirect := repoGroupLinks(ctx, "variables")
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_actions.CreateVariable(ctx, orgID, groupID, 0, redirect)
}

// RepoGroupVariableUpdate edits a project variable of the project.
func RepoGroupVariableUpdate(ctx *context.Context) {
	orgID, groupID, redirect := repoGroupLinks(ctx, "variables")
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_actions.UpdateVariable(ctx, orgID, groupID, 0, redirect)
}

// RepoGroupVariableDelete deletes a project variable of the project.
func RepoGroupVariableDelete(ctx *context.Context) {
	orgID, groupID, redirect := repoGroupLinks(ctx, "variables")
	shared_actions.DeleteVariable(ctx, orgID, groupID, 0, redirect)
}
