// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The review routes of a repository in a project (org3/repo3), through the project and the ID mounts.
func TestAPIActionDeploymentsInProject(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := audit_model.WithSystem(t.Context(), "test")
	group := createProjectForKeys(t, 3, "revproj")
	moveRepoForKeys(t, 3, group.ID)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{}})

	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	stranger := getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)

	env := &actions_model.ActionEnvironment{RepoID: repo.ID, Name: "proj-env"}
	require.NoError(t, actions_model.CreateEnvironment(ctx, env))
	_, err := db.GetEngine(ctx).Insert(&actions_model.ActionEnvironmentReviewer{EnvironmentID: env.ID, UserID: 2})
	require.NoError(t, err)

	run := &actions_model.ActionRun{RepoID: repo.ID, OwnerID: 3, WorkflowID: "x.yml", Index: 9001, Title: "x", TriggerUserID: 1, Ref: "refs/heads/master", CommitSHA: "abc", Status: actions_model.StatusBlocked}
	_, err = db.GetEngine(ctx).Insert(run)
	require.NoError(t, err)
	job := &actions_model.ActionRunJob{RunID: run.ID, RepoID: repo.ID, OwnerID: 3, Name: "deploy", JobID: "deploy", Status: actions_model.StatusBlocked, Handle: "proj-rv-1", Attempt: 1}
	_, err = db.GetEngine(ctx).Insert(job)
	require.NoError(t, err)
	dep := &actions_model.ActionDeployment{RepoID: repo.ID, EnvironmentID: env.ID, RunID: run.ID, JobID: job.ID, Attempt: 1, Status: actions_model.DeploymentWaitingReview}
	_, err = db.GetEngine(ctx).Insert(dep)
	require.NoError(t, err)

	for _, base := range []string{
		fmt.Sprintf("/api/v1/repos/org3/%s/repo3/-/actions/runs/%d/deployments", group.Name, run.ID),
		fmt.Sprintf("/api/v1/repositories/%d/actions/runs/%d/deployments", repo.ID, run.ID),
	} {
		resp := MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(owner), http.StatusOK)
		var out []*api.ActionDeployment
		DecodeJSON(t, resp, &out)
		require.Len(t, out, 1)
		assert.Equal(t, "proj-env", out[0].Environment)
		assert.Equal(t, "waiting_review", out[0].Status)

		// a user without access to the private repository gets 404, and the deployment stays waiting
		MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/review", api.ReviewDeploymentsOption{State: "approved", JobIDs: []int64{job.ID}}).AddTokenAuth(stranger), http.StatusNotFound)
		assert.Equal(t, actions_model.DeploymentWaitingReview, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionDeployment{ID: dep.ID}).Status)
	}

	base := fmt.Sprintf("/api/v1/repos/org3/%s/repo3/-/actions/runs/%d/deployments", group.Name, run.ID)
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/review", api.ReviewDeploymentsOption{State: "rejected", JobIDs: []int64{job.ID}}).AddTokenAuth(owner), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/review", api.ReviewDeploymentsOption{State: "rejected", Comment: "no", JobIDs: []int64{job.ID}}).AddTokenAuth(owner), http.StatusOK)
	assert.Equal(t, actions_model.DeploymentRejected, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionDeployment{ID: dep.ID}).Status)
}
