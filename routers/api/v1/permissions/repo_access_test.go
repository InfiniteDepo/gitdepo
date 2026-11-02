// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package permissions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/services/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

type taskAuthentication struct {
	*auth.BaseAuthenticationResult
	taskID int64
}

func (r *taskAuthentication) Credential() audit_model.Credential {
	return audit_model.Credential{Type: audit_model.CredentialActionsTask, ID: r.taskID}
}

func (r *taskAuthentication) User() *user_model.User {
	return user_model.NewActionsUser()
}

func (r *taskAuthentication) ActionsTaskID() optional.Option[int64] {
	return optional.Some(r.taskID)
}

func TestRepoAccessTokenPermissionsWrite(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	task.TokenPermissions = actions_model.TokenPermissions{unit.TypeCode: perm.AccessModeWrite, unit.TypeIssues: perm.AccessModeRead}.Encode()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "token_permissions"))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: task.RepoID})
	require.NoError(t, repo.LoadOwner(t.Context()))

	ctx := &Permissions{}
	ctx.SetContext(t.Context())
	ctx.SetDoer(user_model.NewActionsUser())
	ctx.SetRepository(repo)
	ctx.SetAuthentication(&taskAuthentication{BaseAuthenticationResult: &auth.BaseAuthenticationResult{}, taskID: task.ID})
	RepoAccess(ctx) // a request that writes

	require.Zero(t, ctx.status, ctx.message)
	permission := ctx.Permission()
	assert.True(t, permission.CanWrite(unit.TypeCode))
	assert.False(t, permission.CanRead(unit.TypeIssues))
	for _, u := range permission.Units {
		assert.NotEqual(t, unit.TypeIssues, u.Type, "a read-only unit must not stay in Units, e.g. for IsGloballyWriteable")
	}
}
