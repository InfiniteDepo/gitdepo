// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Attacks on organization environments, from the security review: each subtest asserts the secure behaviour.
func TestActionsOrgEnvironmentsAttacks(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		sys := audit_model.WithSystem(ctx, "test")
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		scopes := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteUser}
		ownerToken := getUserToken(t, user2.Name, scopes...)
		owner := loginUser(t, user2.Name)
		apiBase := "/api/v1/orgs/org3/actions/environments"

		newOrgRepo := func(name string) *repo_model.Repository {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{
				Name: name, Private: true, AutoInit: true, Readme: "Default", DefaultBranch: "main",
			}).AddTokenAuth(ownerToken), http.StatusCreated)
			repo, err := repo_model.GetRepositoryByOwnerAndName(ctx, "org3", name)
			require.NoError(t, err)
			return repo
		}
		runnerFor := func(repo *repo_model.Repository, label string) *mockRunner {
			runner := newMockRunner()
			tok, err := actions_model.NewRunnerToken(sys, optional.None[int64](), optional.Some(repo.ID))
			require.NoError(t, err)
			runner.doRegister(t, "oenva-"+label, tok.Token, []string{label})
			return runner
		}
		waitDeployment := func(repo *repo_model.Repository, sha string) (*actions_model.ActionRunJob, *actions_model.ActionDeployment) {
			run := new(actions_model.ActionRun)
			require.Eventually(t, func() bool {
				has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repo.ID, sha).Get(run)
				return err == nil && has
			}, 10*time.Second, 100*time.Millisecond)
			jobs, err := actions_model.GetRunJobsByRunID(ctx, run.ID)
			require.NoError(t, err)
			require.Len(t, jobs, 1)
			var d *actions_model.ActionDeployment
			require.Eventually(t, func() bool {
				d, err = actions_model.GetDeployment(db.DefaultContext, jobs[0].ID, 1)
				return err == nil && d != nil && d.Status != 0
			}, 10*time.Second, 100*time.Millisecond)
			return jobs[0], d
		}

		// A repository in a project is named by its path in the organization, so a GET -> PUT round trip (as any
		// declarative client does) keeps it, never moving the selection to a root repository of the same leaf name,
		// which any member who may create repositories can make. The web picker labels it the same way.
		t.Run("API round trip of a project repository keeps it, never a root twin", func(t *testing.T) {
			org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
			group, err := repo_model.CreateRepoGroup(sys, org3, "oenvaproj", "")
			require.NoError(t, err)
			projRepo, err := repo_service.CreateRepositoryDirectly(sys, user2, org3, repo_service.CreateRepoOptions{Name: "oenvaapi", GroupID: group.ID})
			require.NoError(t, err)
			rootTwin := newOrgRepo("oenvaapi")
			selection := func(id int64) []int64 {
				ids, err := actions_model.EnvironmentRepoIDs(ctx, []int64{id})
				require.NoError(t, err)
				return ids[id]
			}
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/oenva-round", envRules(api.CreateOrUpdateEnvironmentOption{Repositories: []string{"OENVAPROJ/oenvaapi"}})).
				AddTokenAuth(ownerToken), http.StatusCreated)
			env, err := actions_model.GetEnvironmentByName(ctx, 3, 0, "oenva-round")
			require.NoError(t, err)
			require.Equal(t, []int64{projRepo.ID}, selection(env.ID))

			var got api.ActionEnvironment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", apiBase+"/oenva-round").AddTokenAuth(ownerToken), http.StatusOK), &got)
			assert.Equal(t, []string{"oenvaproj/oenvaapi"}, got.Repositories)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/oenva-round", envRules(api.CreateOrUpdateEnvironmentOption{
				RepositorySelection: got.RepositorySelection, Repositories: got.Repositories,
			})).AddTokenAuth(ownerToken), http.StatusOK)
			assert.Equal(t, []int64{projRepo.ID}, selection(env.ID))
			_, err = actions_model.ResolveEnvironment(ctx, rootTwin.ID, "oenva-round")
			require.ErrorIs(t, err, actions_model.ErrEnvironmentNotFound)

			// malformed, foreign and unknown paths are one plain 422 and change nothing
			for _, names := range [][]string{{"oenvaproj/"}, {"/oenvaapi"}, {"a/b/c"}, {"user2/repo1"}, {"repo1"}, {"nope/oenvaapi"}} {
				resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/oenva-round", envRules(api.CreateOrUpdateEnvironmentOption{Repositories: names})).
					AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
				assert.Contains(t, resp.Body.String(), "a repository is not found in the organization", names)
			}
			assert.Equal(t, []int64{projRepo.ID}, selection(env.ID))

			// the picker tells the two apart
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org/org3/settings/actions/environments/%d", env.ID)), http.StatusOK).Body)
			assert.Equal(t, "oenvaproj/oenvaapi", doc.Find(fmt.Sprintf(`#environment-repos .item[data-value="%d"]`, projRepo.ID)).Text())
			assert.Equal(t, "oenvaapi", doc.Find(fmt.Sprintf(`#environment-repos .item[data-value="%d"]`, rootTwin.ID)).Text())
		})

		// An organization environment restricted to protected branches, without reviewers: the organization's owner
		// relies on branch protection. A repository administrator who is no owner of the organization adds a
		// catch-all protection rule to the repository and deploys from any branch, getting the organization's secret.
		t.Run("repo admin satisfies protected_branches with a repo-level rule", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/bp-prod", envRules(api.CreateOrUpdateEnvironmentOption{RefPolicy: "protected_branches"})).
				AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/bp-prod/secrets/BP_KEY", api.CreateOrUpdateSecretOption{Data: "bp-org-secret"}).
				AddTokenAuth(ownerToken), http.StatusCreated)
			repo := newOrgRepo("oenva-bp")
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/bp-prod", envRules(api.CreateOrUpdateEnvironmentOption{RefPolicy: "protected_branches", Repositories: []string{"oenva-bp"}})).
				AddTokenAuth(ownerToken), http.StatusOK)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/oenva-bp/collaborators/user8", &api.AddCollaboratorOption{Permission: new("admin")}).
				AddTokenAuth(ownerToken), http.StatusNoContent)
			runner := runnerFor(repo, "oenvabp")

			adminToken := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/oenva-bp/branch_protections", &api.CreateBranchProtectionOption{
				RuleName: "*", EnablePush: true,
			}).AddTokenAuth(adminToken), http.StatusCreated)

			user8 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
			path := ".gitea/workflows/steal.yml"
			content := "on:\n  push:\n    paths:\n      - '" + path + "'\njobs:\n  steal:\n    runs-on: oenvabp\n    environment: bp-prod\n    steps:\n      - run: echo ${{ secrets.BP_KEY }}\n"
			opts := getWorkflowCreateFileOptions(user8, "main", "steal", content)
			opts.NewBranchName = "attacker-branch"
			fileResp := createWorkflowFile(t, adminToken, "org3", repo.Name, path, opts)
			_, d := waitDeployment(repo, fileResp.Commit.SHA)
			assert.NotEqual(t, actions_model.DeploymentReleased, d.Status,
				"a ref rule of an organization environment is satisfied by a protection rule the repository administrator wrote")
			if task := runner.maybeFetchTask(t); task != nil {
				assert.Empty(t, task.Secrets["BP_KEY"], "the organization environment's secret reached a branch the org owner never protected")
			}
		})

		// An organization environment restricted to the branch pattern "main", without reviewers. A member who may only
		// create repositories in the organization creates one, whose main branch they own, and deploys from it.
		t.Run("repo creator satisfies a branch pattern in a new repository", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/pat-prod", envRules(api.CreateOrUpdateEnvironmentOption{
				RefPolicy: "patterns", RefPatterns: []*api.ActionEnvironmentRefPattern{{Type: "branch", Pattern: "main"}},
			})).AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/pat-prod/secrets/PAT_KEY", api.CreateOrUpdateSecretOption{Data: "pat-org-secret"}).
				AddTokenAuth(ownerToken), http.StatusCreated)
			creators := &organization.Team{OrgID: 3, Name: "oenva-creators", AccessMode: perm.AccessModeRead, CanCreateOrgRepo: true, Units: []*organization.TeamUnit{
				{OrgID: 3, Type: unit.TypeCode, AccessMode: perm.AccessModeRead},
			}}
			require.NoError(t, models.NewTeam(ctx, creators))
			require.NoError(t, models.AddTeamMemberByCooptation(ctx, creators, 4, 2))
			memberToken := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{
				Name: "oenva-pat", Private: true, AutoInit: true, Readme: "Default", DefaultBranch: "main",
			}).AddTokenAuth(memberToken), http.StatusCreated)
			repo, err := repo_model.GetRepositoryByOwnerAndName(ctx, "org3", "oenva-pat")
			require.NoError(t, err)
			runner := runnerFor(repo, "oenvapat")
			user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			path := ".gitea/workflows/steal.yml"
			content := "on:\n  push:\n    paths:\n      - '" + path + "'\njobs:\n  steal:\n    runs-on: oenvapat\n    environment: pat-prod\n    steps:\n      - run: echo ${{ secrets.PAT_KEY }}\n"
			fileResp := createWorkflowFile(t, memberToken, "org3", repo.Name, path, getWorkflowCreateFileOptions(user4, "main", "steal", content))
			_, d := waitDeployment(repo, fileResp.Commit.SHA)
			assert.NotEqual(t, actions_model.DeploymentReleased, d.Status, "a new environment applies to no repository until one is selected")
			assert.Equal(t, actions_model.DeploymentReasonNotAvailable, d.Reason)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repo.ID})
			if task := runner.maybeFetchTask(t); task != nil {
				assert.Empty(t, task.Secrets["PAT_KEY"], "a member who can only create repositories got the organization environment's secret")
			}
		})

		// A job released by an organization environment but not picked yet, of a repository transferred out of the
		// organization: it gets none of the environment's secrets.
		t.Run("released job transferred out before the pick gets no secret", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/tr-prod", envRules(api.CreateOrUpdateEnvironmentOption{})).
				AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/tr-prod/secrets/TR_KEY", api.CreateOrUpdateSecretOption{Data: "tr-org-secret"}).
				AddTokenAuth(ownerToken), http.StatusCreated)
			repo := newOrgRepo("oenva-tr")
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/tr-prod", envRules(api.CreateOrUpdateEnvironmentOption{Repositories: []string{"oenva-tr"}})).
				AddTokenAuth(ownerToken), http.StatusOK)
			runner := runnerFor(repo, "oenvatr")
			path := ".gitea/workflows/deploy.yml"
			content := "on:\n  push:\n    paths:\n      - '" + path + "'\njobs:\n  deploy:\n    runs-on: oenvatr\n    environment: tr-prod\n    steps:\n      - run: echo ${{ secrets.TR_KEY }}\n"
			fileResp := createWorkflowFile(t, ownerToken, "org3", repo.Name, path, getWorkflowCreateFileOptions(user2, "main", "deploy", content))
			_, d := waitDeployment(repo, fileResp.Commit.SHA)
			require.Equal(t, actions_model.DeploymentReleased, d.Status)

			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/oenva-tr/transfer", &api.TransferRepoOption{NewOwner: "user2"}).
				AddTokenAuth(ownerToken), http.StatusAccepted)
			if task := runner.maybeFetchTask(t); task != nil {
				assert.Empty(t, task.Secrets["TR_KEY"])
			}
		})

		// A repository of another organization never resolves org3's environment: it auto-creates its own.
		t.Run("another owner's repository never resolves the environment", func(t *testing.T) {
			other := &organization.Organization{Name: "oenva-other"}
			require.NoError(t, organization.CreateOrganization(ctx, other, user2))
			repo, err := repo_service.CreateRepositoryDirectly(sys, user2, other.AsUser(), repo_service.CreateRepoOptions{Name: "r"})
			require.NoError(t, err)
			env, err := actions_model.GetOrCreateRepoEnvironment(sys, repo.ID, "tr-prod")
			require.NoError(t, err)
			assert.Equal(t, repo.ID, env.RepoID)
			assert.Zero(t, env.OwnerID)

			// by ID across scopes: org3's page doesn't reach oenva-other's environments, nor a repository's
			otherEnv := &actions_model.ActionEnvironment{OwnerID: other.ID, Name: "foreign"}
			require.NoError(t, actions_model.CreateEnvironment(sys, otherEnv, nil))
			for _, id := range []int64{otherEnv.ID, env.ID} {
				link := fmt.Sprintf("/org/org3/settings/actions/environments/%d", id)
				owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
				owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/delete", url.Values{"confirm_name": {"foreign"}}), http.StatusNotFound)
				owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/secrets", url.Values{"name": {"X"}, "data": {"y"}}), http.StatusNotFound)
			}
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: otherEnv.ID})
			// the repository API of org3 doesn't list oenva-other's environment as inherited
			var list []*api.ActionEnvironment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/oenva-bp/actions/environments").AddTokenAuth(ownerToken), http.StatusOK), &list)
			for _, e := range list {
				assert.NotEqual(t, "foreign", e.Name)
			}
		})

		// Accepting a pending transfer of a repository whose environment twins an organization environment is
		// refused with a clear answer, never a 500.
		t.Run("accepting a pending transfer with a twin", func(t *testing.T) {
			user5Token := getUserToken(t, "user5", scopes...)
			repo := createActionsTestRepo(t, user5Token, "oenva-twin", false)
			require.NoError(t, actions_model.CreateEnvironment(sys, &actions_model.ActionEnvironment{RepoID: repo.ID, Name: "TR-PROD"}, nil))
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/oenva-twin/transfer", &api.TransferRepoOption{NewOwner: "org3"}).
				AddTokenAuth(user5Token), NoExpectedStatus)
			assert.Equal(t, http.StatusUnprocessableEntity, resp.Code, "refused before a pending transfer exists")
			if resp.Code != http.StatusCreated {
				return // no pending transfer to accept
			}
			resp = MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user5/oenva-twin/transfer/accept").AddTokenAuth(ownerToken), NoExpectedStatus)
			assert.NotEqual(t, http.StatusInternalServerError, resp.Code, resp.Body.String())
			assert.EqualValues(t, 5, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID}).OwnerID)
			// and the web accept
			resp = owner.MakeRequest(t, NewRequest(t, "POST", "/user5/oenva-twin/action/accept_transfer"), NoExpectedStatus)
			assert.NotEqual(t, http.StatusInternalServerError, resp.Code)
			assert.EqualValues(t, 5, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID}).OwnerID)
		})
	})
}
