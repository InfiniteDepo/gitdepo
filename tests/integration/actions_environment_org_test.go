// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	actions_web "forgejo.org/routers/web/repo/actions"
	"forgejo.org/services/mailer"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Environments of an organization (org3, owned by user2) that its repositories inherit: the web pages, the API, the
// review of a run, the secrets a job gets, transfers and the threat model, through real requests.
func TestActionsOrgEnvironments(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		mails := &deploymentMails{}
		defer test.MockVariableValue(&mailer.SendAsync, func(msgs ...*mailer.Message) {
			mails.mu.Lock()
			defer mails.mu.Unlock()
			mails.sent = append(mails.sent, msgs...)
		})()
		ctx := db.DefaultContext
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		scopes := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteUser}
		ownerToken := getUserToken(t, user2.Name, scopes...)
		owner := loginUser(t, user2.Name)

		newOrgRepo := func(name string, private bool) *repo_model.Repository {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{
				Name: name, Private: private, AutoInit: true, Readme: "Default", DefaultBranch: "main",
			}).AddTokenAuth(ownerToken), http.StatusCreated)
			repo, err := repo_model.GetRepositoryByOwnerAndName(ctx, "org3", name)
			require.NoError(t, err)
			return repo
		}
		repoA := newOrgRepo("oenv-a", true)
		repoB := newOrgRepo("oenv-b", false)
		// user4 reads the Actions of both repositories through a team; oenv-member is a member with no repository
		deployers := &organization.Team{OrgID: 3, Name: "oenv-deployers", AccessMode: perm.AccessModeRead, Units: []*organization.TeamUnit{
			{OrgID: 3, Type: unit.TypeCode, AccessMode: perm.AccessModeRead}, {OrgID: 3, Type: unit.TypeActions, AccessMode: perm.AccessModeRead},
		}}
		require.NoError(t, models.NewTeam(ctx, deployers))
		require.NoError(t, models.AddTeamMemberByCooptation(ctx, deployers, 4, 2))
		require.NoError(t, org_service.TeamAddRepository(ctx, deployers, repoA))
		require.NoError(t, org_service.TeamAddRepository(ctx, deployers, repoB))
		member := &user_model.User{Name: "oenv-member", Email: "oenv-member@example.com", Passwd: userPassword, IsActive: true}
		require.NoError(t, user_model.CreateUser(ctx, member))
		empty := &organization.Team{OrgID: 3, Name: "oenv-empty", AccessMode: perm.AccessModeRead, Units: []*organization.TeamUnit{{OrgID: 3, Type: unit.TypeCode, AccessMode: perm.AccessModeRead}}}
		require.NoError(t, models.NewTeam(ctx, empty))
		require.NoError(t, models.AddTeamMemberByCooptation(ctx, empty, member.ID, 2))
		// user8 administers oenv-a as a collaborator without being an owner of the organization
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/oenv-a/collaborators/user8", &api.AddCollaboratorOption{Permission: new("admin")}).AddTokenAuth(ownerToken), http.StatusNoContent)

		orgBase := "/org/org3/settings/actions/environments"
		repoBase := "/org3/oenv-a/settings/actions/environments"
		apiBase := "/api/v1/orgs/org3/actions/environments"
		auditNow := func() int64 {
			var id int64
			_, err := db.GetEngine(ctx).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
			require.NoError(t, err)
			return id
		}
		auditActions := func(since int64, prefix string) []string {
			var entries []*audit_model.Entry
			require.NoError(t, db.GetEngine(ctx).Where("id > ?", since).OrderBy("id").Find(&entries))
			var actions []string
			for _, e := range entries {
				if strings.HasPrefix(e.Action, prefix) {
					actions = append(actions, e.Action)
					assert.EqualValues(t, 3, e.OwnerID, e.Action)
				}
			}
			return actions
		}
		post := func(s *TestSession, link string, values url.Values, status int) string {
			t.Helper()
			return s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link, values), status).Body.String()
		}
		orgEnv := func(name string) *actions_model.ActionEnvironment {
			env, err := actions_model.GetEnvironmentByName(ctx, 3, 0, name)
			require.NoError(t, err)
			return env
		}

		var production *actions_model.ActionEnvironment
		t.Run("web: create, edit, secrets and variables at the organization", func(t *testing.T) {
			body := owner.MakeRequest(t, NewRequest(t, "GET", orgBase), http.StatusOK).Body.String()
			assert.Contains(t, body, "Organization environments are never created by workflows.")
			assert.Contains(t, body, orgBase+"/new")
			assert.Contains(t, body, `href="`+orgBase+`"`, "the settings menu links the page")

			since := auditNow()
			form := url.Values{"name": {"Production"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "reviewers": {fmt.Sprintf("user:4,user:%d", member.ID)}, "scope": {"all"}}
			resp := owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", orgBase+"/new", form), http.StatusSeeOther)
			production = orgEnv("production")
			assert.Equal(t, fmt.Sprintf("%s/%d", orgBase, production.ID), resp.Header().Get("Location"))
			assert.Zero(t, production.RepoID)
			assert.True(t, production.ReviewsRequired)
			unittest.AssertCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: production.ID}, 2)

			// a non-member and a team of another organization are refused
			link := fmt.Sprintf("%s/%d", orgBase, production.ID)
			post(owner, link, url.Values{"name": {"Production"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "reviewers": {"user:4,user:5"}}, http.StatusOK)
			post(owner, link, url.Values{"name": {"Production"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "reviewers": {"user:4,team:3"}}, http.StatusOK)
			unittest.AssertCount(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: production.ID}, 2)

			// the picker offers the organization's members and teams only
			body = owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.Contains(t, body, fmt.Sprintf(`value="user:4,user:%d"`, member.ID))
			assert.Contains(t, body, `data-value="user:28"`)
			assert.Contains(t, body, fmt.Sprintf(`data-value="team:%d"`, deployers.ID))
			assert.NotContains(t, body, `data-value="user:5"`)
			assert.NotContains(t, body, `data-value="team:3"`)

			post(owner, link, url.Values{"name": {"Production"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "prevent_self_review": {"on"}, "reviewers": {fmt.Sprintf("user:4,user:%d", member.ID)}, "scope": {"all"}}, http.StatusSeeOther)
			post(owner, link+"/secrets", url.Values{"name": {"ORG_ENV_KEY"}, "data": {"org-env-value"}}, http.StatusOK)
			post(owner, link+"/variables/new", url.Values{"name": {"ORG_ENV_VAR"}, "data": {"org-env-var"}}, http.StatusOK)
			s := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{EnvironmentID: production.ID, Name: "ORG_ENV_KEY"})
			assert.EqualValues(t, 3, s.OwnerID)
			assert.Zero(t, s.RepoID)
			v := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{EnvironmentID: production.ID, Name: "ORG_ENV_VAR"})
			assert.EqualValues(t, 3, v.OwnerID)
			assert.Equal(t, []string{
				"org.actions_env.created", "org.actions_env.updated", "org.actions_env_secret.created", "org.actions_env_variable.created",
			}, auditActions(since, "org.actions_env"))
			assert.Empty(t, auditActions(since, "repo.actions_env"))
		})

		t.Run("web: the repository shows it read-only and refuses a twin", func(t *testing.T) {
			body := owner.MakeRequest(t, NewRequest(t, "GET", repoBase), http.StatusOK).Body.String()
			assert.Contains(t, body, `id="environment-inherited-list"`)
			assert.Contains(t, body, "From organization org3")
			assert.Contains(t, body, "Edit in org3")
			assert.Contains(t, body, orgBase)

			body = post(owner, repoBase+"/new", url.Values{"name": {"PRODUCTION"}, "ref_policy": {"0"}, "wait_timer": {"0"}}, http.StatusOK)
			assert.Contains(t, body, "This name is taken by an environment of the organization org3")
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repoA.ID, LowerName: "production"})

			// the repository's pages never reach it
			link := fmt.Sprintf("%s/%d", repoBase, production.ID)
			owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
			owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/delete", url.Values{"confirm": {"Production"}}), http.StatusNotFound)
			owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/secrets", url.Values{"name": {"X"}, "data": {"y"}}), http.StatusNotFound)
			orgEnv("production")

			// a name repositories already use can't become an organization environment
			post(owner, repoBase+"/new", url.Values{"name": {"staging"}, "ref_policy": {"0"}, "wait_timer": {"0"}}, http.StatusSeeOther)
			body = post(owner, orgBase+"/new", url.Values{"name": {"Staging"}, "ref_policy": {"0"}, "wait_timer": {"0"}}, http.StatusOK)
			assert.Contains(t, body, "1 repository of org3 already has an environment named like this (oenv-a).")
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{OwnerID: 3, LowerName: "staging"})
			since := auditNow()
			resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/STAGING", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			assert.Contains(t, resp.Body.String(), "environments of 1 repository of the organization (oenv-a)")
			assert.Empty(t, auditActions(since, "org.actions_env"))
		})

		t.Run("web: the last reviewer of an organization environment is named to a site administrator", func(t *testing.T) {
			doc := NewHTMLParser(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/users/4/edit"), http.StatusOK).Body)
			// decided for each repository it applies to: user4 is the only one who can approve in both
			assert.Contains(t, text(doc, ".last-approver-warnings"), "Environment Production of org3, for its repository org3/oenv-a (Deployment environment)")
			assert.Contains(t, text(doc, ".last-approver-warnings"), "Environment Production of org3, for its repository org3/oenv-b (Deployment environment)")
			assert.Equal(t, 2, doc.Find(fmt.Sprintf(`.last-approver-warnings a[href="%s/%d"]`, orgBase, production.ID)).Length())
		})

		t.Run("web: only acting owners of the organization", func(t *testing.T) {
			for user, status := range map[string]int{"user1": http.StatusOK, "user28": http.StatusNotFound, "user4": http.StatusNotFound, "user8": http.StatusNotFound, "user5": http.StatusNotFound} {
				s := loginUser(t, user)
				resp := s.MakeRequest(t, NewRequest(t, "GET", orgBase), NoExpectedStatus)
				if status == http.StatusOK {
					assert.Equal(t, http.StatusOK, resp.Code, user)
					continue
				}
				assert.NotEqual(t, http.StatusOK, resp.Code, user)
				s.MakeRequest(t, NewRequestWithURLValues(t, "POST", orgBase+"/new", url.Values{"name": {"intruder"}, "ref_policy": {"0"}, "wait_timer": {"0"}}), NoExpectedStatus)
				s.MakeRequest(t, NewRequestWithURLValues(t, "POST", fmt.Sprintf("%s/%d/delete", orgBase, production.ID), url.Values{"confirm": {"Production"}}), NoExpectedStatus)
			}
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{OwnerID: 3, LowerName: "intruder"})
			orgEnv("production")
			// the repository administrator doesn't reach the repository's environments either
			loginUser(t, "user8").MakeRequest(t, NewRequest(t, "GET", repoBase), http.StatusNotFound)

			// an owner without 2FA in an organization that requires it is no owner there
			_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
			require.NoError(t, err)
			resp := owner.MakeRequest(t, NewRequest(t, "GET", orgBase), NoExpectedStatus)
			assert.NotEqual(t, http.StatusOK, resp.Code)
			_, err = db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		})

		t.Run("web: read-only maintenance refuses writes", func(t *testing.T) {
			defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
			req := NewRequestWithURLValues(t, "POST", orgBase+"/new", url.Values{"name": {"frozen"}, "ref_policy": {"0"}, "wait_timer": {"0"}})
			req.Header.Set("Referer", setting.AppURL+"org3")
			owner.MakeRequest(t, req, http.StatusSeeOther)
			assertMaintenanceFlash(t, owner)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{OwnerID: 3, LowerName: "frozen"})
		})

		t.Run("API: the organization's routes", func(t *testing.T) {
			since := auditNow()
			resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/Canary", envRules(api.CreateOrUpdateEnvironmentOption{
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "team", ID: deployers.ID}}, Repositories: []string{"OENV-A", "oenv-a"},
			})).AddTokenAuth(ownerToken), http.StatusCreated)
			var canary api.ActionEnvironment
			DecodeJSON(t, resp, &canary)
			assert.Equal(t, "Canary", canary.Name)
			assert.False(t, canary.Inherited)
			assert.Equal(t, "selected", canary.RepositorySelection)
			assert.Equal(t, []string{"oenv-a"}, canary.Repositories)
			assert.Equal(t, "oenv-deployers", canary.Reviewers[0].Name)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/canary", envRules(api.CreateOrUpdateEnvironmentOption{
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "user", ID: 5}},
			})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/staging", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)

			var list []*api.ActionEnvironment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", apiBase).AddTokenAuth(ownerToken), http.StatusOK), &list)
			require.Len(t, list, 2)
			assert.Equal(t, "Canary", list[0].Name)
			assert.Equal(t, "Production", list[1].Name)
			assert.EqualValues(t, 1, list[1].SecretsCount)
			assert.EqualValues(t, 1, list[1].VariablesCount)

			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/canary/secrets/KEY", api.CreateOrUpdateSecretOption{Data: "api-value"}).AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/canary/secrets/KEY", api.CreateOrUpdateSecretOption{Data: "api-value-2"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			var secrets []*api.Secret
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", apiBase+"/canary/secrets").AddTokenAuth(ownerToken), http.StatusOK), &secrets)
			require.Len(t, secrets, 1)
			MakeRequest(t, NewRequest(t, "DELETE", apiBase+"/canary/secrets/KEY").AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequestWithJSON(t, "POST", apiBase+"/canary/variables/TARGET", api.CreateVariableOption{Value: "prod"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/canary/variables/TARGET", api.UpdateVariableOption{Value: "eu"}).AddTokenAuth(ownerToken), http.StatusNoContent)
			var variable api.ActionVariable
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", apiBase+"/canary/variables/TARGET").AddTokenAuth(ownerToken), http.StatusOK), &variable)
			assert.Equal(t, "eu", variable.Data)
			assert.EqualValues(t, 3, variable.OwnerID)
			var vars []*api.ActionVariable
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", apiBase+"/canary/variables").AddTokenAuth(ownerToken), http.StatusOK), &vars)
			require.Len(t, vars, 1)
			MakeRequest(t, NewRequest(t, "DELETE", apiBase+"/canary/variables/TARGET").AddTokenAuth(ownerToken), http.StatusNoContent)

			// the repository lists it as inherited and never changes it
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/oenv-a/actions/environments").AddTokenAuth(ownerToken), http.StatusOK), &list)
			names := map[string]bool{}
			for _, e := range list {
				names[e.Name] = e.Inherited
			}
			assert.Equal(t, map[string]bool{"Canary": true, "Production": true, "staging": false}, names)
			repoAPI := "/api/v1/repos/org3/oenv-a/actions/environments"
			MakeRequest(t, NewRequestWithJSON(t, "PUT", repoAPI+"/canary", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequest(t, "DELETE", repoAPI+"/canary").AddTokenAuth(ownerToken), http.StatusNotFound)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", repoAPI+"/canary/secrets/X", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(ownerToken), http.StatusNotFound)
			MakeRequest(t, NewRequestWithJSON(t, "POST", repoAPI+"/canary/variables/X", api.CreateVariableOption{Value: "x"}).AddTokenAuth(ownerToken), http.StatusNotFound)

			MakeRequest(t, NewRequest(t, "DELETE", apiBase+"/canary").AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequest(t, "GET", apiBase+"/canary").AddTokenAuth(ownerToken), http.StatusNotFound)
			assert.Equal(t, []string{
				"org.actions_env.created",
				"org.actions_env_secret.created", "org.actions_env_secret.updated", "org.actions_env_secret.deleted",
				"org.actions_env_variable.created", "org.actions_env_variable.updated", "org.actions_env_variable.deleted",
				"org.actions_env.deleted",
			}, auditActions(since, "org.actions_env"))
		})

		t.Run("API: who and which credentials", func(t *testing.T) {
			requests := func() map[string]*RequestWrapper {
				return map[string]*RequestWrapper{
					"list":   NewRequest(t, "GET", apiBase),
					"put":    NewRequestWithJSON(t, "PUT", apiBase+"/intruder", envRules(api.CreateOrUpdateEnvironmentOption{})),
					"delete": NewRequest(t, "DELETE", apiBase+"/production"),
					"secret": NewRequestWithJSON(t, "PUT", apiBase+"/production/secrets/ORG_ENV_KEY", api.CreateOrUpdateSecretOption{Data: "stolen"}),
				}
			}
			check := func(who string, auth func(*RequestWrapper) *RequestWrapper, status int) {
				t.Helper()
				for name, req := range requests() {
					assert.Equal(t, status, MakeRequest(t, auth(req), NoExpectedStatus).Code, "%s %s", who, name)
				}
			}
			token := func(tok string) func(*RequestWrapper) *RequestWrapper {
				return func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(tok) }
			}
			for _, user := range []string{"user4", "user5", "user8", "user28"} {
				check(user, token(getUserToken(t, user, scopes...)), http.StatusForbidden)
			}
			check("anonymous", func(r *RequestWrapper) *RequestWrapper { return r }, http.StatusUnauthorized)
			check("public-only token", token(getUserToken(t, "user2", append(scopes, auth_model.AccessTokenScopePublicOnly)...)), http.StatusForbidden)
			check("repo-restricted token", token(createFineGrainedRepoAccessToken(t, "user2", scopes, []int64{repoA.ID})), http.StatusForbidden)
			check("OAuth2 grant", token(createOAuth2Token(t, owner, scopes)), http.StatusForbidden)
			ait := newAITester(t)
			defer ait.close()
			check("authorized integration", token(ait.signedJWT()), http.StatusForbidden)
			read := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization)
			MakeRequest(t, NewRequest(t, "GET", apiBase).AddTokenAuth(read), http.StatusOK)
			MakeRequest(t, NewRequest(t, "DELETE", apiBase+"/production").AddTokenAuth(read), http.StatusForbidden)
			// the repository administrator can't escape with a twin on the repository either
			MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/oenv-a/actions/environments/production", envRules(api.CreateOrUpdateEnvironmentOption{})).
				AddTokenAuth(getUserToken(t, "user8", scopes...)), http.StatusForbidden)

			env := orgEnv("production")
			assert.True(t, env.PreventSelfReview)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{LowerName: "intruder"})
			value, err := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{EnvironmentID: env.ID, Name: "ORG_ENV_KEY"}).GetDecryptedData()
			require.NoError(t, err)
			assert.Equal(t, "org-env-value", value)
		})

		t.Run("a run waits for its review, which only an eligible member gives", func(t *testing.T) {
			runner := newMockRunner()
			runnerToken, err := actions_model.NewRunnerToken(audit_model.WithSystem(ctx, "test"), optional.None[int64](), optional.Some(repoB.ID))
			require.NoError(t, err)
			runner.doRegister(t, "oenv-runner", runnerToken.Token, []string{"oenv"})
			path := ".gitea/workflows/deploy.yml"
			content := "on:\n  push:\n    paths:\n      - '" + path + "'\njobs:\n  deploy:\n    runs-on: oenv\n    environment: PRODUCTION\n    steps:\n      - run: echo ${{ secrets.ORG_ENV_KEY }} ${{ vars.ORG_ENV_VAR }}\n"
			fileResp := createWorkflowFile(t, ownerToken, "org3", repoB.Name, path, getWorkflowCreateFileOptions(user2, repoB.DefaultBranch, "deploy", content))
			run := new(actions_model.ActionRun)
			require.Eventually(t, func() bool {
				has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repoB.ID, fileResp.Commit.SHA).Get(run)
				return err == nil && has
			}, 10*time.Second, 100*time.Millisecond)
			jobs, err := actions_model.GetRunJobsByRunID(ctx, run.ID)
			require.NoError(t, err)
			require.Len(t, jobs, 1)
			job := jobs[0]
			require.Eventually(t, func() bool {
				d, err := actions_model.GetDeployment(db.DefaultContext, job.ID, 1)
				return err == nil && d != nil && d.Status == actions_model.DeploymentWaitingReview
			}, 10*time.Second, 100*time.Millisecond)
			d, err := actions_model.GetDeployment(ctx, job.ID, 1)
			require.NoError(t, err)
			assert.Equal(t, production.ID, d.EnvironmentID, "inherited, never auto-created")
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repoB.ID})

			// only user4 can approve in this repository: the other listed member has no access to its Actions
			require.Eventually(t, func() bool { return len(mails.to("waiting for your review")) == 1 }, 10*time.Second, 50*time.Millisecond)
			assert.Equal(t, []string{unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).EmailTo()}, mails.to("waiting for your review"))

			runLink := fmt.Sprintf("/org3/%s/actions/runs/%d", repoB.Name, run.Index)
			panel := func(s *TestSession) *actions_web.ViewDeployments {
				resp := s.MakeRequest(t, NewRequestWithJSON(t, "POST", runLink+"/jobs/0/attempt/1", map[string]any{"logCursors": []any{}}), http.StatusOK)
				var out actions_web.ViewResponse
				DecodeJSON(t, resp, &out)
				return out.State.Run.Deployments
			}
			reviewer, outsider := loginUser(t, "user4"), loginUser(t, member.Name)
			assert.True(t, panel(reviewer).CanReview)
			assert.Equal(t, "Production", panel(reviewer).Items[0].Environment)
			assert.False(t, panel(outsider).CanReview)
			webReview := func(s *TestSession, status int) {
				req := NewRequestWithBody(t, "POST", runLink+"/deployments/review", strings.NewReader(url.Values{"state": {"approved"}, "job_ids": {strconv.FormatInt(job.ID, 10)}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				s.MakeRequest(t, req, status)
			}
			apiReview := func(tok string, status int) {
				MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/%s/actions/runs/%d/deployments/review", repoB.Name, run.ID),
					api.ReviewDeploymentsOption{State: "approved", JobIDs: []int64{job.ID}}).AddTokenAuth(tok), status)
			}
			webReview(outsider, http.StatusForbidden)
			apiReview(getUserToken(t, member.Name, auth_model.AccessTokenScopeWriteRepository), http.StatusForbidden)
			// a reviewer blocked by the organization's 2FA requirement is refused
			_, err = db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
			require.NoError(t, err)
			apiReview(getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository), http.StatusForbidden)
			_, err = db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
			assert.Equal(t, actions_model.DeploymentWaitingReview, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionDeployment{ID: d.ID}).Status)

			since := auditNow()
			webReview(reviewer, http.StatusSeeOther)
			assert.Equal(t, actions_model.DeploymentReleased, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionDeployment{ID: d.ID}).Status)
			var reviewed []*audit_model.Entry
			require.NoError(t, db.GetEngine(ctx).Where("id > ? AND action LIKE ?", since, "repo.actions_deployment.%").Find(&reviewed))
			require.NotEmpty(t, reviewed)
			assert.Equal(t, repoB.ID, reviewed[0].RepoID)

			// the released job gets the organization environment's secret and variable
			task := runner.maybeFetchTask(t)
			require.NotNil(t, task)
			assert.Equal(t, "org-env-value", task.Secrets["ORG_ENV_KEY"])
			assert.Equal(t, "org-env-var", task.Vars["ORG_ENV_VAR"])

			// the deployments view shows it like any other environment
			body := owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/actions/deployments?environment=production", repoB.Name)), http.StatusOK).Body.String()
			assert.Contains(t, body, "Production")
			assert.Contains(t, body, runLink)
			var apiDeployments []*api.ActionDeployment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/org3/%s/actions/runs/%d/deployments", repoB.Name, run.ID)).AddTokenAuth(ownerToken), http.StatusOK), &apiDeployments)
			require.NotEmpty(t, apiDeployments)
			assert.Equal(t, "Production", apiDeployments[0].Environment, "the name of an organization environment is shown")
			apiDeployments = nil
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/org3/%s/actions/deployments", repoB.Name)).AddTokenAuth(ownerToken), http.StatusOK), &apiDeployments)
			require.NotEmpty(t, apiDeployments)
			assert.Equal(t, "Production", apiDeployments[0].Environment)

			// the organization's delete dialog says what the deletion does and shows that last deployment
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", orgBase, production.ID)), http.StatusOK).Body)
			modal := text(doc, "#delete-environment-modal")
			assert.Contains(t, modal, "In every repository of org3, the next job that names Production runs without approval")
			assert.Equal(t, 1, doc.Find(`#delete-environment-modal a[href="`+runLink+`"]`).Length())
		})

		t.Run("transfers: in is refused with a twin, out no longer inherits", func(t *testing.T) {
			userRepo := createActionsTestRepo(t, ownerToken, "oenv-mine", false)
			require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(ctx, "test"), &actions_model.ActionEnvironment{RepoID: userRepo.ID, Name: "production"}, nil))
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/oenv-mine/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			assert.Equal(t, user2.ID, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: userRepo.ID}).OwnerID)

			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/oenv-b/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(ownerToken), http.StatusAccepted)
			_, err := actions_model.ResolveEnvironment(ctx, repoB.ID, "production")
			require.ErrorIs(t, err, actions_model.ErrEnvironmentNotFound)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/oenv-b/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(ownerToken), http.StatusAccepted)
			env, err := actions_model.ResolveEnvironment(ctx, repoB.ID, "production")
			require.NoError(t, err)
			assert.Equal(t, production.ID, env.ID)
		})

		t.Run("repository selection: only selected repositories inherit, and all of them only with reviewers", func(t *testing.T) {
			repoC := newOrgRepo("oenv-c", true)
			since := auditNow()
			post(owner, orgBase+"/new", url.Values{"name": {"limited"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "scope": {"selected"}, "repo_ids": {strconv.FormatInt(repoC.ID, 10)}}, http.StatusSeeOther)
			limited := orgEnv("limited")
			link := fmt.Sprintf("%s/%d", orgBase, limited.ID)
			post(owner, link+"/secrets", url.Values{"name": {"LIMITED_KEY"}, "data": {"limited-value"}}, http.StatusOK)
			// a selection of another owner's repository is refused
			body := post(owner, link, url.Values{"name": {"limited"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "scope": {"selected"}, "repo_ids": {"1"}}, http.StatusOK)
			assert.Contains(t, body, "Select at most 1000 repositories, each of the organization.")
			// all repositories without reviewers: refused through the web and the API, with or without secrets
			body = post(owner, link, url.Values{"name": {"limited"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "scope": {"all"}}, http.StatusOK)
			assert.Contains(t, body, "An environment of all repositories needs required reviewers")
			post(owner, orgBase+"/new", url.Values{"name": {"allnone"}, "ref_policy": {"0"}, "wait_timer": {"0"}, "scope": {"all"}}, http.StatusOK)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{OwnerID: 3, LowerName: "allnone"})
			resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/limited", envRules(api.CreateOrUpdateEnvironmentOption{RepositorySelection: "all"})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			assert.Contains(t, resp.Body.String(), "needs required reviewers")
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/limited", envRules(api.CreateOrUpdateEnvironmentOption{Repositories: []string{"oenv-c", "repo1"}})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/limited", envRules(api.CreateOrUpdateEnvironmentOption{RepositorySelection: "some"})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/open", envRules(api.CreateOrUpdateEnvironmentOption{RepositorySelection: "all"})).AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: limited.ID}).ReviewsRequired)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: limited.ID}).AllRepos)
			assert.Equal(t, []string{"org.actions_env.created", "org.actions_env_secret.created"}, auditActions(since, "org.actions_env"))

			// the organization's list says which repositories it applies to; the form selects them
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", orgBase), http.StatusOK).Body)
			assert.Contains(t, text(doc, "#environment-list"), "1 selected repository · used by 0 repositories")
			assert.Contains(t, text(doc, "#environment-list"), "All repositories · used by 1 repository")
			doc = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
			assert.Equal(t, strconv.FormatInt(repoC.ID, 10), doc.Find(`#environment-repos input[name="repo_ids"]`).AttrOr("value", ""))
			assert.Equal(t, 1, doc.Find(fmt.Sprintf(`#environment-repos .item[data-value="%d"]`, repoA.ID)).Length())
			assert.Contains(t, text(doc, "#environment-repos-all-desc"), "can deploy to it and get ID tokens with its environment claim. It needs at least one required reviewer.")

			// a repository it doesn't apply to doesn't list it, can't read it, and a run there is refused
			body = owner.MakeRequest(t, NewRequest(t, "GET", repoBase), http.StatusOK).Body.String()
			assert.NotContains(t, body, ">limited<")
			assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/oenv-c/settings/actions/environments"), http.StatusOK).Body.String(), ">limited<")
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/oenv-a/actions/environments/limited").AddTokenAuth(ownerToken), http.StatusNotFound)
			var inherited api.ActionEnvironment
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/oenv-c/actions/environments/LIMITED").AddTokenAuth(ownerToken), http.StatusOK), &inherited)
			assert.True(t, inherited.Inherited, "read on the repository route like in its list")
			assert.EqualValues(t, 1, inherited.SecretsCount)
			path := ".gitea/workflows/limited.yml"
			content := "on:\n  push:\n    paths:\n      - '" + path + "'\njobs:\n  deploy:\n    runs-on: oenv\n    environment: limited\n    steps:\n      - run: echo ${{ secrets.LIMITED_KEY }}\n"
			fileResp := createWorkflowFile(t, ownerToken, "org3", repoA.Name, path, getWorkflowCreateFileOptions(user2, repoA.DefaultBranch, "limited", content))
			run := new(actions_model.ActionRun)
			require.Eventually(t, func() bool {
				has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repoA.ID, fileResp.Commit.SHA).Get(run)
				return err == nil && has
			}, 10*time.Second, 100*time.Millisecond)
			var d *actions_model.ActionDeployment
			require.Eventually(t, func() bool {
				var err error
				d, err = actions_model.GetDeployment(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{RunID: run.ID}).ID, 1)
				return err == nil && d != nil && d.Status != 0
			}, 10*time.Second, 100*time.Millisecond)
			assert.Equal(t, actions_model.DeploymentReasonNotAvailable, d.Reason)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{RepoID: repoA.ID, LowerName: "limited"})
			var view actions_web.ViewResponse
			DecodeJSON(t, owner.MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/org3/oenv-a/actions/runs/%d/jobs/0/attempt/1", run.Index), map[string]any{"logCursors": []any{}}), http.StatusOK), &view)
			assert.Contains(t, view.State.Run.Deployments.Items[0].Text, "isn't available to this repository")

			// a transfer out drops the repository's selection
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/oenv-c/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(ownerToken), http.StatusAccepted)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironmentRepo{RepoID: repoC.ID})
		})

		t.Run("accepting a pending transfer that would twin is refused, never a 500", func(t *testing.T) {
			user5Token := getUserToken(t, "user5", scopes...)
			repo := createActionsTestRepo(t, user5Token, "oenv-pending", false)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/oenv-pending/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(user5Token), http.StatusCreated)
			// the twin appears after the transfer was started
			require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(ctx, "test"), &actions_model.ActionEnvironment{RepoID: repo.ID, Name: "late"}, nil))
			MakeRequest(t, NewRequestWithJSON(t, "PUT", apiBase+"/late", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(ownerToken), http.StatusCreated)
			resp := MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user5/oenv-pending/transfer/accept").AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
			assert.Contains(t, resp.Body.String(), "environment named like one of the new owner")
			owner.MakeRequest(t, NewRequest(t, "POST", "/user5/oenv-pending/action/accept_transfer"), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "The repository has an environment named like an environment of the new owner")
			assert.EqualValues(t, 5, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID}).OwnerID)
			// a new transfer is refused up front
			MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user5/oenv-pending/transfer/reject").AddTokenAuth(ownerToken), http.StatusOK)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/oenv-pending/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(user5Token), http.StatusUnprocessableEntity)
		})

		t.Run("names are escaped in every view", func(t *testing.T) {
			require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(ctx, "test"), &actions_model.ActionEnvironment{OwnerID: 3, Name: "<i>x", AllRepos: true}, []actions_model.ActionEnvironmentReviewer{{UserID: 4}}))
			for _, link := range []string{orgBase, repoBase} {
				body := owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
				assert.Contains(t, body, "&lt;i&gt;x", link)
				assert.NotContains(t, body, "<i>x", link)
			}
		})

		t.Run("archive and deletion of the organization", func(t *testing.T) {
			org := &organization.Organization{Name: "oenv-gone"}
			require.NoError(t, organization.CreateOrganization(ctx, org, user2))
			// the organization's own empty state and limit
			gone := "/org/oenv-gone/settings/actions/environments"
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", gone), http.StatusOK).Body)
			assert.Contains(t, text(doc, ".org-setting-content"), "No organization environments")
			for i := range actions_model.MaxEnvironments {
				require.NoError(t, actions_model.CreateEnvironment(audit_model.WithSystem(ctx, "test"), &actions_model.ActionEnvironment{OwnerID: org.ID, Name: fmt.Sprint("cap-", i)}, nil))
			}
			body := post(owner, gone+"/new", url.Values{"name": {"one-more"}, "ref_policy": {"0"}, "wait_timer": {"0"}}, http.StatusOK)
			assert.Contains(t, body, "The organization already has 100 environments, the most it can have.")
			_, err := db.GetEngine(ctx).Where("owner_id = ? AND repo_id = 0", org.ID).Delete(new(actions_model.ActionEnvironment))
			require.NoError(t, err)
			team, err := org.GetOwnerTeam(ctx)
			require.NoError(t, err)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/oenv-gone/actions/environments/prod", envRules(api.CreateOrUpdateEnvironmentOption{
				Reviewers: []*api.ActionEnvironmentReviewer{{Type: "team", ID: team.ID}},
			})).AddTokenAuth(ownerToken), http.StatusCreated)
			env, err := actions_model.GetEnvironmentByName(ctx, org.ID, 0, "prod")
			require.NoError(t, err)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/oenv-gone/actions/environments/prod/secrets/S", api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(ownerToken), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/oenv-gone/actions/environments/prod/variables/V", api.CreateVariableOption{Value: "x"}).AddTokenAuth(ownerToken), http.StatusNoContent)

			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/oenv-gone/archive", &api.ArchiveOrgOption{}).AddTokenAuth(ownerToken), NoExpectedStatus)
			if unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: org.ID}).IsArchived {
				assert.NotEqual(t, http.StatusOK, MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/oenv-gone/actions/environments/prod", envRules(api.CreateOrUpdateEnvironmentOption{})).AddTokenAuth(ownerToken), NoExpectedStatus).Code)
				post(owner, "/org/oenv-gone/settings/actions/environments/new", url.Values{"name": {"frozen"}, "ref_policy": {"0"}, "wait_timer": {"0"}}, NoExpectedStatus)
				unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{OwnerID: org.ID, LowerName: "frozen"})
				assert.True(t, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{ID: env.ID}).ReviewsRequired)
				MakeRequest(t, NewRequest(t, "POST", "/api/v1/orgs/oenv-gone/unarchive").AddTokenAuth(ownerToken), NoExpectedStatus)
			}

			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/oenv-gone").AddTokenAuth(ownerToken), http.StatusNoContent)
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{ID: env.ID})
			unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironmentReviewer{EnvironmentID: env.ID})
			unittest.AssertNotExistsBean(t, &secret_model.Secret{EnvironmentID: env.ID})
			unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{EnvironmentID: env.ID})
		})
	})
}

// The repository's list with its inherited block and the deployments view of inherited environments take a fixed
// number of queries, whatever the number of environments, reviewers and deployments.
func TestActionsOrgEnvironmentsQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := audit_model.WithSystem(db.DefaultContext, "test")
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	session := loginUser(t, "user2")

	count := func(n int) []int64 {
		org := &organization.Organization{Name: fmt.Sprintf("oenv-q-%d", n)}
		require.NoError(t, organization.CreateOrganization(ctx, org, owner))
		repo, err := repo_service.CreateRepositoryDirectly(ctx, owner, org.AsUser(), repo_service.CreateRepoOptions{Name: "deploy"})
		require.NoError(t, err)
		team := &organization.Team{OrgID: org.ID, Name: "deployers", AccessMode: perm.AccessModeRead, Units: []*organization.TeamUnit{
			{OrgID: org.ID, Type: unit.TypeActions, AccessMode: perm.AccessModeRead},
		}}
		require.NoError(t, models.NewTeam(ctx, team))
		require.NoError(t, org_service.TeamAddRepository(ctx, team, repo))
		var first *actions_model.ActionEnvironment
		var members []int64
		for i := range n {
			u := &user_model.User{Name: fmt.Sprintf("oenv-q-%d-%d", n, i), Email: fmt.Sprintf("oenv-q-%d-%d@example.com", n, i), IsActive: true}
			require.NoError(t, user_model.CreateUser(ctx, u))
			require.NoError(t, models.AddTeamMemberByCooptation(ctx, team, u.ID, owner.ID))
			members = append(members, u.ID)
			e := &actions_model.ActionEnvironment{OwnerID: org.ID, Name: fmt.Sprintf("env-%d", i), AllRepos: true}
			require.NoError(t, actions_model.CreateEnvironment(ctx, e, []actions_model.ActionEnvironmentReviewer{{TeamID: team.ID}, {UserID: u.ID}}))
			_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, org.ID, 0, e.ID, "S", "x")
			require.NoError(t, err)
			if first == nil {
				first = e
			}
			run := &actions_model.ActionRun{RepoID: repo.ID, OwnerID: org.ID, Index: int64(i + 1), Title: "run", TriggerUserID: u.ID, Status: actions_model.StatusSuccess}
			require.NoError(t, db.Insert(ctx, run))
			job := &actions_model.ActionRunJob{RunID: run.ID, RepoID: repo.ID, OwnerID: org.ID, Name: "deploy", Attempt: 1, Status: actions_model.StatusSuccess, Handle: fmt.Sprintf("oenv-q-%d-%d", n, i)}
			require.NoError(t, db.Insert(ctx, job))
			require.NoError(t, db.Insert(ctx, &actions_model.ActionDeployment{
				RepoID: repo.ID, RunID: run.ID, JobID: job.ID, Attempt: 1, EnvironmentID: e.ID, Status: actions_model.DeploymentRejected,
				Ref: "refs/heads/main", TriggerUserID: u.ID, ReviewedBy: u.ID, ReviewComment: "no",
			}))
		}
		// adding a team member adds its watches in a goroutine, whose queries would be counted
		require.Eventually(t, func() bool {
			n, err := db.GetEngine(db.DefaultContext).In("user_id", members).And("repo_id = ?", repo.ID).Count(new(repo_model.Watch))
			return err == nil && int(n) == len(members)
		}, 10*time.Second, 50*time.Millisecond)
		var counts []int64
		for _, l := range []string{
			fmt.Sprintf("/%s/deploy/settings/actions/environments", org.Name),
			fmt.Sprintf("/%s/deploy/actions/deployments", org.Name),
			fmt.Sprintf("/%s/deploy/actions/deployments?environment=%s", org.Name, first.Name),
			fmt.Sprintf("/org/%s/settings/actions/environments", org.Name),
		} {
			session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) // generated avatars are saved once
			counts = append(counts, stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) }))
		}
		return counts
	}
	assert.Equal(t, count(1), count(20))
}
