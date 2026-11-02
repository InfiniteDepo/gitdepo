// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/lfs"
	api "forgejo.org/modules/structs"
	auth_service "forgejo.org/services/auth"
	repo_service "forgejo.org/services/repository"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repositories in a project can be selected for access tokens and authorized integrations by their full name, and a
// selection reaches exactly the selected repository (#492).
func TestAccessTokenRepoGroup(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, _ := prepareRepoGroupGit(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		create := func(name string, groupID int64) *repo_model.Repository {
			repo, err := repo_service.CreateRepository(db.DefaultContext, user2, f.org, repo_service.CreateRepoOptions{
				Name: name, IsPrivate: true, Readme: "Default", AutoInit: true, DefaultBranch: "main", GroupID: groupID,
			})
			require.NoError(t, err)
			return repo
		}
		sibling := create("priv2", f.priv.GroupID)
		rootPriv := create("priv", 0) // the same leaf name as org3/proj/priv
		session := loginUser(t, "user2")

		postToken := func(t *testing.T, session *TestSession, status int, selected ...string) string {
			t.Helper()
			name := fmt.Sprintf("repo-group-token-%d", tokenCounter.Add(1))
			values := url.Values{"name": {name}, "resource": {"repo-specific"}, "scope": {"write:repository"}, "selected_repo": selected}
			resp := session.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user/settings/keys/tokens/new", values), status)
			if status != http.StatusSeeOther {
				return resp.Body.String()
			}
			return assertAccessToken(t, session)
		}
		apiStatus := func(t *testing.T, token string, repo *repo_model.Repository) int {
			t.Helper()
			path := "/api/v1/repos/" + repo.FullName()
			if repo.GroupID != 0 {
				path += "/-"
			}
			return MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), NoExpectedStatus).Code
		}
		lfsStatus := func(t *testing.T, token string, repo *repo_model.Repository) int {
			t.Helper()
			req := NewRequestWithJSON(t, "POST", "/"+repo.FullName()+".git/info/lfs/objects/batch", &lfs.BatchRequest{
				Operation: "download",
				Objects:   []lfs.Pointer{{Oid: "83de2e488b89a0aa1c97496b888120a28b0c1e15463a4adb8405578c540f36d4", Size: 6}},
			}).SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType)
			req.Request.SetBasicAuth("user2", token)
			return MakeRequest(t, req, NoExpectedStatus).Code
		}
		gitURL := func(token string, repo *repo_model.Repository) *url.URL {
			c := *u
			c.Path = "/" + repo.FullName() + ".git"
			c.User = url.UserPassword("user2", token)
			return &c
		}

		t.Run("web token for a repository in a project", func(t *testing.T) {
			token := postToken(t, session, http.StatusSeeOther, "org3/proj/priv")
			at := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, TokenLastEight: token[len(token)-8:]})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AccessTokenResourceRepo{TokenID: at.ID, RepoID: f.priv.ID})
			unittest.AssertCount(t, &auth_model.AccessTokenResourceRepo{TokenID: at.ID}, 1)

			assert.Equal(t, http.StatusOK, apiStatus(t, token, f.priv))
			assert.Equal(t, http.StatusOK, lfsStatus(t, token, f.priv))
			require.NoError(t, git.Clone(t.Context(), gitURL(token, f.priv).String(), t.TempDir(), git.CloneRepoOptions{}))
			for _, other := range []*repo_model.Repository{sibling, rootPriv} {
				assert.Equal(t, http.StatusNotFound, apiStatus(t, token, other), other.FullName())
				assert.NotEqual(t, http.StatusOK, lfsStatus(t, token, other), other.FullName())
				doGitCloneFail(gitURL(token, other))(t)
			}
		})

		t.Run("web token for a root repository", func(t *testing.T) {
			token := postToken(t, session, http.StatusSeeOther, "org3/priv")
			assert.Equal(t, http.StatusOK, apiStatus(t, token, rootPriv))
			require.NoError(t, git.Clone(t.Context(), gitURL(token, rootPriv).String(), t.TempDir(), git.CloneRepoOptions{}))
			assert.Equal(t, http.StatusNotFound, apiStatus(t, token, f.priv))
		})

		t.Run("hidden is missing", func(t *testing.T) {
			user5 := loginUser(t, "user5")
			missing := postToken(t, user5, http.StatusBadRequest, "org3/proj/nosuch")
			assert.Equal(t, "getSelectedRepos\n", missing)
			for _, selected := range []string{"org3/proj/priv", "org3/secret/hid", "org3/priv", "org3/proj/priv/"} {
				assert.Equal(t, missing, postToken(t, user5, http.StatusBadRequest, selected), selected)
			}
		})

		t.Run("API", func(t *testing.T) {
			post := func(t *testing.T, path, user string, status int, target *api.RepoTargetOption) string {
				t.Helper()
				req := NewRequestWithJSON(t, "POST", path, &api.CreateAccessTokenOption{
					Name:         fmt.Sprintf("repo-group-api-token-%d", tokenCounter.Add(1)),
					Scopes:       []string{"read:repository"},
					Repositories: []*api.RepoTargetOption{target},
				})
				if strings.HasPrefix(path, "/api/v1/admin/") {
					req.AddTokenAuth(getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin))
				} else {
					req.AddBasicAuth(user)
				}
				return MakeRequest(t, req, status).Body.String()
			}
			for _, path := range []string{"/api/v1/users/user2/tokens", "/api/v1/admin/users/user2/tokens"} {
				var token api.AccessToken
				require.NoError(t, json.Unmarshal([]byte(post(t, path, "user2", http.StatusCreated, &api.RepoTargetOption{Owner: "org3", Project: "proj", Name: "priv"})), &token))
				require.Len(t, token.Repositories, 1)
				assert.Equal(t, f.priv.ID, token.Repositories[0].ID)
				assert.Equal(t, "org3/proj/priv", token.Repositories[0].FullName)
				assert.Equal(t, http.StatusOK, apiStatus(t, token.Token, f.priv))
				assert.Equal(t, http.StatusNotFound, apiStatus(t, token.Token, rootPriv))

				missing := post(t, path, "user2", http.StatusBadRequest, &api.RepoTargetOption{Owner: "org3", Project: "proj", Name: "nosuch"})
				assert.Contains(t, missing, "repository org3/proj/nosuch does not exist")
			}

			path := "/api/v1/users/user5/tokens"
			missing := post(t, path, "user5", http.StatusBadRequest, &api.RepoTargetOption{Owner: "org3", Project: "proj", Name: "nosuch"})
			hidden := post(t, path, "user5", http.StatusBadRequest, &api.RepoTargetOption{Owner: "org3", Project: "proj", Name: "priv"})
			assert.Equal(t, missing, strings.ReplaceAll(hidden, "org3/proj/priv", "org3/proj/nosuch"))
			assert.Contains(t, post(t, path, "user5", http.StatusBadRequest, &api.RepoTargetOption{Owner: "org3", Name: "proj/priv"}),
				"repository org3/proj/priv does not exist")
		})

		t.Run("authorized integration", func(t *testing.T) {
			values := url.Values{
				"name": {"project integration"}, "source_repo": {"org3/proj/pub"},
				"resource": {"repo-specific"}, "scope": {"read:repository"}, "selected_repo": {"org3/proj/pub", "org3/pub"},
			}
			resp := session.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user/settings/authorized-integrations/forgejo-actions-local/new", values), http.StatusSeeOther)
			ai := unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "project integration"})
			editPath := fmt.Sprintf("/user/settings/authorized-integrations/forgejo-actions-local/%d", ai.ID)
			assert.Equal(t, editPath, resp.Header().Get("Location"))
			rootPub, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "org3", "pub")
			require.NoError(t, err)
			repoIDs := func() []int64 {
				var ids []int64
				require.NoError(t, db.GetEngine(db.DefaultContext).Table("authorized_integ_resource_repo").Where("integ_id = ?", ai.ID).OrderBy("repo_id").Cols("repo_id").Find(&ids))
				return ids
			}
			assert.Equal(t, []int64{f.pub.ID, rootPub.ID}, repoIDs())
			sourceRule := auth_model.ClaimRule{Claim: "repository_id", Comparison: auth_model.ClaimEqual, Value: fmt.Sprint(f.pub.ID)}
			assert.Contains(t, ai.ClaimRules.Rules, sourceRule)

			// the edit page shows the project repositories, and saving what it shows keeps them
			doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", editPath), http.StatusOK).Body)
			edit := url.Values{}
			doc.Find(`form input[type="hidden"][name="selected_repo"], form input[type="hidden"][name="source_repo"]`).Each(func(_ int, s *goquery.Selection) {
				edit.Add(s.AttrOr("name", ""), s.AttrOr("value", ""))
			})
			assert.Equal(t, []string{"org3/proj/pub", "org3/pub"}, edit["selected_repo"])
			assert.Equal(t, []string{"org3/proj/pub"}, edit["source_repo"])
			edit.Set("name", "project integration")
			edit.Set("resource", "repo-specific")
			edit.Set("scope", "read:repository")
			session.MakeRequest(t, NewRequestWithURLValues(t, "POST", editPath, edit), http.StatusSeeOther)
			assert.Equal(t, []int64{f.pub.ID, rootPub.ID}, repoIDs())
			ai = unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{ID: ai.ID})
			assert.Contains(t, ai.ClaimRules.Rules, sourceRule)

			// missing and hidden repositories give the same 400, in both UIs, on new and edit
			user5 := loginUser(t, "user5")
			issuer := "urn:forgejo:authorized-integrations:actions"
			paths := map[string][]string{}
			for _, ui := range []auth_model.AuthorizedIntegrationUI{auth_model.AuthorizedIntegrationUIGeneric, auth_model.AuthorizedIntegrationUIForgejoActionsLocal} {
				existing := &auth_model.AuthorizedIntegration{
					UserID: 5, Name: "user5 " + string(ui), UI: ui, Issuer: issuer, Scope: "read:repository", ResourceAllRepos: true,
					ClaimRules: &auth_model.ClaimRules{Rules: []auth_model.ClaimRule{
						{Claim: "repository_id", Comparison: auth_model.ClaimEqual, Value: "4"},
						{Claim: "repository_owner_id", Comparison: auth_model.ClaimEqual, Value: "5"},
					}},
				}
				require.NoError(t, auth_service.InsertAuthorizedIntegration(db.DefaultContext, existing, nil))
				base := fmt.Sprintf("/user/settings/authorized-integrations/%s/", ui)
				paths[string(ui)] = []string{base + "new", fmt.Sprintf("%s%d", base, existing.ID)}
			}
			post := func(t *testing.T, path, field, value string) string {
				t.Helper()
				v := url.Values{
					"name": {"x"}, "resource": {"repo-specific"}, "scope": {"read:repository"}, "selected_repo": {"user5/repo4"},
					"source_repo": {"user5/repo4"}, "issuer": {issuer}, "claim_rules": {`{"rules":[]}`},
				}
				v.Set(field, value)
				return user5.MakeRequest(t, NewRequestWithURLValues(t, "POST", path, v), http.StatusBadRequest).Body.String()
			}
			for ui, uiPaths := range paths {
				fields := []string{"selected_repo"}
				if ui == string(auth_model.AuthorizedIntegrationUIForgejoActionsLocal) {
					fields = append(fields, "source_repo")
				}
				for _, path := range uiPaths {
					for _, field := range fields {
						missing := post(t, path, field, "org3/proj/nosuch")
						assert.Equal(t, "getSelectedRepos\n", missing, "%s %s", path, field)
						for _, hidden := range []string{"org3/proj/priv", "org3/secret/hid", "org3/priv"} {
							assert.Equal(t, missing, post(t, path, field, hidden), "%s %s %s", path, field, hidden)
						}
					}
				}
			}
		})

		t.Run("CLI authorized integration", func(t *testing.T) {
			create := func(name, repo string) error {
				_, err := runMainApp("admin", "user", "create-authorized-integration", "--username", "user2", "--name", name,
					"--issuer", "urn:forgejo:authorized-integrations:actions", "--scope", "read:repository", "--repo", repo)
				return err
			}
			require.NoError(t, create("cli project", "org3/proj/priv"))
			ai := unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli project"})
			unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegResourceRepo{IntegID: ai.ID, RepoID: f.priv.ID})
			unittest.AssertCount(t, &auth_model.AuthorizedIntegResourceRepo{IntegID: ai.ID}, 1)
			for _, repo := range []string{"org3/proj/nosuch", "org3//priv", "org3/proj/priv/", "/proj/priv", "org3", "org3/proj/priv/x"} {
				require.Error(t, create("cli "+repo, repo), repo)
				unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli " + repo})
			}
		})
	})
}
