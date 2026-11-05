// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"testing/fstest"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests/forgery"

	"code.forgejo.org/xorm/xorm/convert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Org owners manage the Actions secrets and variables of a project on its settings pages; they stay in the project.
func TestRepoGroupActionsSecretsVariables(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		f := prepareRepoGroupWeb(t)
		owner := loginUser(t, "user2")
		proj, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "proj")
		require.NoError(t, err)
		other, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "secret")
		require.NoError(t, err)
		secretsLink, varsLink := "/org3/proj/-/settings/secrets", "/org3/proj/-/settings/variables"
		const (
			value  = "s3cr3t-value-for-the-project-7f2c"
			value2 = "s3cr3t-second-value-8e1d"
		)
		// every response of this test is checked for the values
		noLeak := func(t *testing.T, resp string) {
			t.Helper()
			assert.NotContains(t, resp, value)
			assert.NotContains(t, resp, value2)
		}

		t.Run("owner creates, edits and deletes a secret", func(t *testing.T) {
			noLeak(t, owner.MakeRequest(t, NewRequest(t, "GET", secretsLink), http.StatusOK).Body.String())
			resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", secretsLink, map[string]string{"name": "deploy_token", "data": value}), http.StatusOK)
			noLeak(t, resp.Body.String())
			secret := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: f.org.ID, GroupID: proj.ID, RepoID: 0, Name: "DEPLOY_TOKEN"})
			plain, err := secret.GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, value, plain)
			page := owner.MakeRequest(t, NewRequest(t, "GET", secretsLink), http.StatusOK).Body.String()
			assert.Contains(t, page, "DEPLOY_TOKEN")
			noLeak(t, page)

			// a blank value keeps the stored one, a new one replaces it
			noLeak(t, owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", secretsLink, secret.ID), map[string]string{"name": "deploy_token2", "data": ""}), http.StatusOK).Body.String())
			secret = unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: secret.ID})
			assert.Equal(t, "DEPLOY_TOKEN2", secret.Name)
			plain, err = secret.GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, value, plain, "blank value keeps the secret")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", secretsLink, secret.ID), map[string]string{"name": "deploy_token2", "data": value2}), http.StatusOK)
			secret = unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: secret.ID})
			plain, err = secret.GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, value2, plain)
			assert.Equal(t, proj.ID, secret.GroupID)
			assert.Equal(t, f.org.ID, secret.OwnerID)

			owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", secretsLink, secret.ID)), http.StatusOK)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{ID: secret.ID})
		})

		t.Run("owner creates, edits and deletes a variable", func(t *testing.T) {
			owner.MakeRequest(t, NewRequest(t, "GET", varsLink), http.StatusOK)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", varsLink+"/new", map[string]string{"name": "build_mode", "data": "fast"}), http.StatusOK)
			v := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: f.org.ID, GroupID: proj.ID, RepoID: 0, Name: "BUILD_MODE"})
			assert.Equal(t, "fast", v.Data)
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", varsLink), http.StatusOK).Body.String(), "BUILD_MODE")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", varsLink, v.ID), map[string]string{"name": "build_mode", "data": "slow"}), http.StatusOK)
			assert.Equal(t, "slow", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{ID: v.ID}).Data)
			owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", varsLink, v.ID)), http.StatusOK)
			unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{ID: v.ID})
		})

		forgery.EnableRepoUnit(t, f.pub, unit_model.TypeActions, nil)
		orgSecret, err := secret_model.InsertEncryptedSecret(ctx, f.org.ID, 0, 0, "ORG_LEVEL", value)
		require.NoError(t, err)
		orgVar, err := actions_model.InsertVariable(ctx, f.org.ID, 0, 0, "ORG_VAR", "org")
		require.NoError(t, err)
		repoSecret, err := secret_model.InsertEncryptedSecret(ctx, 0, 0, f.pub.ID, "REPO_LEVEL", value)
		require.NoError(t, err)
		otherSecret, err := secret_model.InsertEncryptedSecret(ctx, f.org.ID, other.ID, 0, "OTHER_PROJECT", value)
		require.NoError(t, err)
		otherVar, err := actions_model.InsertVariable(ctx, f.org.ID, other.ID, 0, "OTHER_VAR", "other")
		require.NoError(t, err)
		projSecret, err := secret_model.InsertEncryptedSecret(ctx, f.org.ID, proj.ID, 0, "PROJECT_LEVEL", value)
		require.NoError(t, err)
		projVar, err := actions_model.InsertVariable(ctx, f.org.ID, proj.ID, 0, "PROJECT_VAR", "proj")
		require.NoError(t, err)

		t.Run("a row of another level or project is not found and stays untouched", func(t *testing.T) {
			for _, s := range []*secret_model.Secret{orgSecret, repoSecret, otherSecret} {
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", secretsLink, s.ID), map[string]string{"name": "hijacked", "data": value2}), http.StatusNotFound)
				owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", secretsLink, s.ID)), http.StatusNotFound)
				stored := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: s.ID})
				assert.Equal(t, s.Name, stored.Name)
				assert.Equal(t, s.GroupID, stored.GroupID)
				plain, err := stored.GetDecryptedData()
				require.NoError(t, err)
				assert.Equal(t, value, plain)
			}
			for _, v := range []*actions_model.ActionVariable{orgVar, otherVar} {
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", varsLink, v.ID), map[string]string{"name": "HIJACKED", "data": "x"}), http.StatusNotFound)
				owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", varsLink, v.ID)), http.StatusNotFound)
				assert.Equal(t, v.Name, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{ID: v.ID}).Name)
			}
			// the project of another organization's ID in the path, or a missing one
			owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups/99999/settings/secrets"), http.StatusNotFound)
		})

		t.Run("project rows appear only on the project pages and lists", func(t *testing.T) {
			projPage := owner.MakeRequest(t, NewRequest(t, "GET", secretsLink), http.StatusOK).Body.String()
			assert.Contains(t, projPage, "PROJECT_LEVEL")
			for _, absent := range []string{"OTHER_PROJECT", "REPO_LEVEL"} {
				assert.NotContains(t, projPage, absent)
			}
			varsPage := owner.MakeRequest(t, NewRequest(t, "GET", varsLink), http.StatusOK).Body.String()
			assert.Contains(t, varsPage, "PROJECT_VAR")
			assert.NotContains(t, varsPage, "OTHER_VAR")

			orgSecrets := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/actions/secrets"), http.StatusOK).Body.String()
			assert.Contains(t, orgSecrets, "ORG_LEVEL")
			assert.NotContains(t, orgSecrets, "PROJECT_LEVEL")
			assert.NotContains(t, orgSecrets, "OTHER_PROJECT")
			orgVars := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/actions/variables"), http.StatusOK).Body.String()
			assert.Contains(t, orgVars, "ORG_VAR")
			assert.NotContains(t, orgVars, "PROJECT_VAR")
			assert.NotContains(t, orgVars, "OTHER_VAR")
			repoSecrets := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/pub/settings/actions/secrets"), http.StatusOK).Body.String()
			assert.NotContains(t, repoSecrets, "PROJECT_LEVEL")

			// the API of the organization and of the repository list their own level only
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
			for path, absent := range map[string][]string{
				"/api/v1/orgs/org3/actions/secrets":                              {"PROJECT_LEVEL", "OTHER_PROJECT"},
				"/api/v1/orgs/org3/actions/variables":                            {"PROJECT_VAR", "OTHER_VAR"},
				fmt.Sprintf("/api/v1/repositories/%d/actions/secrets", f.pub.ID): {"PROJECT_LEVEL"},
			} {
				body := owner.MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK).Body.String()
				for _, a := range absent {
					assert.NotContains(t, body, a, path)
				}
				noLeak(t, body)
			}
			// the project row can't be addressed through the organization endpoints
			owner.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/actions/secrets/PROJECT_LEVEL", map[string]string{"data": value2}).AddTokenAuth(token), http.StatusCreated)
			unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: f.org.ID, GroupID: 0, Name: "PROJECT_LEVEL"})
			plain, err := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: projSecret.ID}).GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, value, plain, "the API wrote a new organization secret, the project one is untouched")
			owner.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3/actions/secrets/PROJECT_LEVEL").AddTokenAuth(token), http.StatusNoContent)
			unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: projSecret.ID})
			owner.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3/actions/variables/PROJECT_VAR").AddTokenAuth(token), http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{ID: projVar.ID})
		})

		t.Run("nobody below an owner reaches it, no value leaks", func(t *testing.T) {
			for _, session := range []*TestSession{loginUser(t, "user4"), loginUser(t, "user28"), loginUser(t, "user5"), emptyTestSession(t)} {
				for _, req := range []*RequestWrapper{
					NewRequest(t, "GET", secretsLink),
					NewRequest(t, "GET", varsLink),
					NewRequestWithValues(t, "POST", secretsLink, map[string]string{"name": "intruder", "data": value2}),
					NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", secretsLink, projSecret.ID), map[string]string{"name": "intruder", "data": value2}),
					NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", secretsLink, projSecret.ID)),
					NewRequestWithValues(t, "POST", varsLink+"/new", map[string]string{"name": "intruder", "data": "x"}),
					NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/edit", varsLink, projVar.ID), map[string]string{"name": "INTRUDER", "data": "x"}),
					NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", varsLink, projVar.ID)),
				} {
					resp := session.MakeRequest(t, req, NoExpectedStatus)
					assert.NotEqual(t, http.StatusOK, resp.Code, "%s %s", req.Method, req.URL)
					body := resp.Body.String()
					noLeak(t, body)
					assert.NotContains(t, body, "PROJECT_LEVEL")
					assert.NotContains(t, body, "PROJECT_VAR")
				}
			}
			stored := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: projSecret.ID})
			assert.Equal(t, "PROJECT_LEVEL", stored.Name)
			assert.Equal(t, "proj", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{ID: projVar.ID}).Data)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{Name: "INTRUDER"})
		})

		t.Run("Actions off for the instance: the routes do not exist", func(t *testing.T) {
			defer test.MockVariableValue(&setting.Actions.Enabled, false)()
			for _, link := range []string{secretsLink, varsLink} {
				owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
			}
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", secretsLink, map[string]string{"name": "late", "data": value2}), http.StatusNotFound)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{Name: "LATE"})
		})

		t.Run("Actions hidden for the organization: the routes do not exist", func(t *testing.T) {
			_, err := db.GetEngine(ctx).Insert(&repo_model.OrgUnit{OrgID: f.org.ID, Type: unit_model.TypeActions, Disabled: true})
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(ctx).Delete(&repo_model.OrgUnit{OrgID: f.org.ID, Type: unit_model.TypeActions})
				require.NoError(t, err)
			}()
			for _, link := range []string{secretsLink, varsLink} {
				owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
			}
			assert.NotContains(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/-/settings"), http.StatusOK).Body.String(), "/-/settings/secrets")
		})

		t.Run("the project badge marks an overridden organization name", func(t *testing.T) {
			_, err := secret_model.InsertEncryptedSecret(ctx, f.org.ID, proj.ID, 0, "ORG_LEVEL", value2)
			require.NoError(t, err)
			page := owner.MakeRequest(t, NewRequest(t, "GET", secretsLink), http.StatusOK).Body.String()
			assert.Contains(t, page, "Overrides the organization")
			noLeak(t, page)
		})
	})
}

// Deleting the organization deletes its project secrets and variables, and so does deleting an empty project.
func TestRepoGroupActionsDelete(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		org := &organization.Organization{Name: "actions-del-org", Visibility: 2}
		require.NoError(t, organization.CreateOrganization(ctx, org, admin))
		orgUser := org.AsUser()
		group, err := repo_model.CreateRepoGroup(ctx, orgUser, "pa", "")
		require.NoError(t, err)
		for _, g := range []int64{0, group.ID} {
			_, err = secret_model.InsertEncryptedSecret(ctx, org.ID, g, 0, "TOKEN", "x")
			require.NoError(t, err)
			_, err = actions_model.InsertVariable(ctx, org.ID, g, 0, "TOKEN", "x")
			require.NoError(t, err)
		}
		require.NoError(t, organization.DeleteOrganization(ctx, org))
		unittest.AssertNotExistsBean(t, &secret_model.Secret{OwnerID: org.ID})
		unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{OwnerID: org.ID})
	})
}

// A job gets the secrets and variables of the project its repository is in when the job is fetched: a move starts the
// new project's and stops the old one's.
func TestRepoGroupActionsFetchTask(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip() // mock repo runner only supported on SQLite testing
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		a, err := repo_model.CreateRepoGroup(ctx, org3, "fa", "")
		require.NoError(t, err)
		b, err := repo_model.CreateRepoGroup(ctx, org3, "fb", "")
		require.NoError(t, err)
		for _, s := range []struct {
			group       int64
			name, value string
		}{{0, "SHARED", "org"}, {a.ID, "SHARED", "a"}, {a.ID, "ONLY_A", "a"}, {b.ID, "SHARED", "b"}, {b.ID, "ONLY_B", "b"}} {
			_, err := secret_model.InsertEncryptedSecret(ctx, org3.ID, s.group, 0, s.name, s.value)
			require.NoError(t, err)
			_, err = actions_model.InsertVariable(ctx, org3.ID, s.group, 0, s.name, s.value)
			require.NoError(t, err)
		}

		repo := forgery.CreateRepository(t, org3, &forgery.CreateRepositoryOptions{
			LatestSha: new(string),
			Files: forgery.MapFS{".forgejo/workflows/matrix.yml": &fstest.MapFile{Data: []byte(`
on:
  push:
jobs:
  job1:
    strategy:
      matrix:
        n: [1, 2, 3]
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ matrix.n }}
`)}},
		})
		var unitConfig convert.Conversion
		forgery.EnableRepoUnit(t, repo, unit_model.TypeActions, unitConfig)

		runner := newMockRunner()
		session := loginUser(t, user2.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		resp := MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/actions/runners/registration-token", org3.Name, repo.Name)).AddTokenAuth(token), http.StatusOK)
		var registration struct {
			Token string `json:"token"`
		}
		DecodeJSON(t, resp, &registration)
		runner.doRegister(t, "mock-runner", registration.Token, []string{"ubuntu-latest"})

		fetch := func() (map[string]string, map[string]string) {
			runner.lastTasksVersion = 0
			task := runner.fetchTask(t)
			require.NotNil(t, task)
			secrets := map[string]string{}
			for k, v := range task.Secrets {
				if k != "FORGEJO_TOKEN" && k != "GITEA_TOKEN" && k != "GITHUB_TOKEN" {
					secrets[k] = v
				}
			}
			return secrets, task.Vars
		}

		runner.setRequestKey("11111111-2222-4333-8444-555555555551")
		secrets, vars := fetch()
		assert.Equal(t, map[string]string{"SHARED": "org"}, secrets, "root repository: the organization's")
		assert.Equal(t, map[string]string{"SHARED": "org"}, vars)

		require.NoError(t, repo_service.MoveRepository(ctx, user2, repo, a.ID))
		runner.setRequestKey("11111111-2222-4333-8444-555555555552")
		secretsA, varsA := fetch()
		assert.Equal(t, map[string]string{"SHARED": "a", "ONLY_A": "a"}, secretsA, "moved into A")
		assert.Equal(t, map[string]string{"SHARED": "a", "ONLY_A": "a"}, varsA)

		repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		require.NoError(t, repo_service.MoveRepository(ctx, user2, repo, b.ID))
		runner.setRequestKey("11111111-2222-4333-8444-555555555553")
		secrets, vars = fetch()
		assert.Equal(t, map[string]string{"SHARED": "b", "ONLY_B": "b"}, secrets, "moved on to B")
		assert.Equal(t, map[string]string{"SHARED": "b", "ONLY_B": "b"}, vars)
		// what the task of A was given is not touched by the move: the server doesn't hand it out again to a running task
		assert.Equal(t, map[string]string{"SHARED": "a", "ONLY_A": "a"}, secretsA)
		assert.Equal(t, map[string]string{"SHARED": "a", "ONLY_A": "a"}, varsA)

		// only a retry of the same fetch request (a lost response) is answered with the values of the project it is in now
		runner.setRequestKey("11111111-2222-4333-8444-555555555552")
		secrets, vars = fetch()
		assert.Equal(t, map[string]string{"SHARED": "b", "ONLY_B": "b"}, secrets, "retry after the move")
		assert.Equal(t, map[string]string{"SHARED": "b", "ONLY_B": "b"}, vars)
	})
}
