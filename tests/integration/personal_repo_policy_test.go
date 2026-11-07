// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var personalRepoModes = []string{setting.PersonalReposAllowed, setting.PersonalReposPrivateOnly, setting.PersonalReposDisabled}

// setPersonalRepoMode stores the policy; the returned function removes it again (the app.ini default, allowed).
func setPersonalRepoMode(t *testing.T, mode string) func() {
	t.Helper()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.NoError(t, repo_service.SetPersonalRepoPolicy(db.DefaultContext, admin, mode, 0))
	bumpSettingsRevision(t)
	return func() { resetPersonalRepoMode(t) }
}

func resetPersonalRepoMode(t *testing.T) {
	t.Helper()
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().PersonalRepos.DynKey(): ""}))
	bumpSettingsRevision(t)
}

// personalRepoAllowed is what the policy decides for a repository of an individual non-admin user.
func personalRepoAllowed(mode string, private bool) bool {
	return mode == setting.PersonalReposAllowed || mode == setting.PersonalReposPrivateOnly && private
}

func personalRepoMessage(mode string) string {
	return repo_module.ErrPersonalRepoPolicy{Mode: mode}.Error()
}

// assertPersonalRepoAPI expects ok, or a 403 with the policy message.
func assertPersonalRepoAPI(t *testing.T, req *RequestWrapper, ok int, mode string, allowed bool) {
	t.Helper()
	if allowed {
		MakeRequest(t, req, ok)
		return
	}
	var apiErr api.APIError
	DecodeJSON(t, MakeRequest(t, req, http.StatusForbidden), &apiErr)
	assert.Contains(t, apiErr.Message, personalRepoMessage(mode))
}

// assertPersonalRepoWeb expects a redirect, or the page again with the translated policy message.
func assertPersonalRepoWeb(t *testing.T, session *TestSession, req *RequestWrapper, mode string, allowed bool) {
	t.Helper()
	if allowed {
		session.MakeRequest(t, req, http.StatusSeeOther)
		return
	}
	resp := session.MakeRequest(t, req, http.StatusOK)
	assert.Contains(t, NewHTMLParser(t, resp.Body).Find(".flash-error").Text(), "Personal repositories")
}

func repoExists(t *testing.T, owner, name string) bool {
	t.Helper()
	return unittest.GetCount(t, &repo_model.Repository{OwnerName: owner, LowerName: strings.ToLower(name)}) == 1
}

func TestPersonalRepoPolicyCreate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user4 := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, user4, auth_model.AccessTokenScopeAll)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)
	orgToken := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)

	for _, mode := range personalRepoModes {
		t.Run(mode, func(t *testing.T) {
			defer setPersonalRepoMode(t, mode)()
			for _, private := range []bool{true, false} {
				name := fmt.Sprintf("pc-%s-%t", mode, private)
				allowed := personalRepoAllowed(mode, private)

				assertPersonalRepoAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name, Private: private}).AddTokenAuth(token), http.StatusCreated, mode, allowed)
				assert.Equal(t, allowed, repoExists(t, "user4", name))

				values := map[string]string{"uid": "4", "repo_name": "web-" + name}
				if private {
					values["private"] = "on"
				}
				assertPersonalRepoWeb(t, user4, NewRequestWithValues(t, "POST", "/repo/create", values), mode, allowed)
				assert.Equal(t, allowed, repoExists(t, "user4", "web-"+name))

				// a site admin creating for the user, an admin's own repositories and organizations are not restricted
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user4/repos", &api.CreateRepoOption{Name: "admin-" + name, Private: private}).AddTokenAuth(adminToken), http.StatusCreated)
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name, Private: private}).AddTokenAuth(adminToken), http.StatusCreated)
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: name, Private: private}).AddTokenAuth(orgToken), http.StatusCreated)
			}
		})
	}
}

func TestPersonalRepoPolicyTemplate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user4 := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, user4, auth_model.AccessTokenScopeAll)

	for _, mode := range personalRepoModes {
		t.Run(mode, func(t *testing.T) {
			defer setPersonalRepoMode(t, mode)()
			for _, private := range []bool{true, false} {
				name := fmt.Sprintf("tpl-%s-%t", mode, private)
				allowed := personalRepoAllowed(mode, private)

				assertPersonalRepoAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user27/template1/generate", &api.GenerateRepoOption{Owner: "user4", Name: name, Private: private, GitContent: true}).AddTokenAuth(token), http.StatusCreated, mode, allowed)
				assert.Equal(t, allowed, repoExists(t, "user4", name))

				values := map[string]string{"uid": "4", "repo_name": "web-" + name, "repo_template": "44", "git_content": "on"}
				if private {
					values["private"] = "on"
				}
				assertPersonalRepoWeb(t, user4, NewRequestWithValues(t, "POST", "/repo/create", values), mode, allowed)
				assert.Equal(t, allowed, repoExists(t, "user4", "web-"+name))
			}
		})
	}
}

func TestPersonalRepoPolicyFork(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user4 := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, user4, auth_model.AccessTokenScopeAll)
	owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)

	for _, mode := range personalRepoModes {
		t.Run(mode, func(t *testing.T) {
			// a user forks a repository once, so each mode has its own sources; user4 can read the private one
			src := func(name string, private bool) string {
				name = name + "-" + mode
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name, Private: private, AutoInit: true}).AddTokenAuth(owner), http.StatusCreated)
				MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/"+name+"/collaborators/user4", &api.AddCollaboratorOption{}).AddTokenAuth(owner), http.StatusNoContent)
				return name
			}
			public, private, web := src("fork-src-pub", false), src("fork-src-priv", true), src("fork-src-web", false)

			defer setPersonalRepoMode(t, mode)()
			// a fork keeps the visibility of its source
			for src, isPrivate := range map[string]bool{public: false, private: true} {
				name := "fork-of-" + src
				allowed := personalRepoAllowed(mode, isPrivate)
				assertPersonalRepoAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+src+"/forks", &api.CreateForkOption{Name: &name}).AddTokenAuth(token), http.StatusAccepted, mode, allowed)
				assert.Equal(t, allowed, repoExists(t, "user4", name))
			}
			allowed := personalRepoAllowed(mode, false)
			req := NewRequestWithValues(t, "POST", "/user2/"+web+"/fork", map[string]string{"uid": "4", "repo_name": "fork-of-" + web})
			assertPersonalRepoWeb(t, user4, req, mode, allowed)
			assert.Equal(t, allowed, repoExists(t, "user4", "fork-of-"+web))

			// into an organization: never restricted
			org, name := "org3", "org-fork-"+mode
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+public+"/forks", &api.CreateForkOption{Organization: &org, Name: &name}).AddTokenAuth(owner), http.StatusAccepted)
		})
	}
}

// S4: making the source public doesn't make a personal fork public where the policy refuses public personal repositories.
func TestPersonalRepoPolicyForkVisibility(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
	user4 := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeAll)
	no := false

	for mode, wantPublic := range map[string]bool{setting.PersonalReposAllowed: true, setting.PersonalReposPrivateOnly: false} {
		t.Run(mode, func(t *testing.T) {
			src, fork := "cascade-"+mode, "cascade-fork-"+mode
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: src, Private: true, AutoInit: true}).AddTokenAuth(owner), http.StatusCreated)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+src+"/collaborators/user4", &api.AddCollaboratorOption{}).AddTokenAuth(owner), http.StatusNoContent)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+src+"/forks", &api.CreateForkOption{Name: &fork}).AddTokenAuth(user4), http.StatusAccepted)

			defer setPersonalRepoMode(t, mode)()
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+src, &api.EditRepoOption{Private: &no}).AddTokenAuth(owner), http.StatusOK)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: src}).IsPrivate)
			assert.Equal(t, wantPublic, !unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user4", LowerName: fork}).IsPrivate)
		})
	}
}

func TestPersonalRepoPolicyMigrate(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
		defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
		require.NoError(t, migrations_allowlist.Init())
		user4 := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, user4, auth_model.AccessTokenScopeAll)
		cloneURL := *u
		cloneURL.Path = "/user2/repo1.git"

		for _, mode := range personalRepoModes {
			t.Run(mode, func(t *testing.T) {
				defer setPersonalRepoMode(t, mode)()
				for _, private := range []bool{true, false} {
					name := fmt.Sprintf("mig-%s-%t", mode, private)
					allowed := personalRepoAllowed(mode, private)
					assertPersonalRepoAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: cloneURL.String(), RepoOwner: "user4", RepoName: name, Private: private}).AddTokenAuth(token), http.StatusCreated, mode, allowed)
					assert.Equal(t, allowed, repoExists(t, "user4", name))
				}
				if mode != setting.PersonalReposAllowed {
					values := map[string]string{"clone_addr": cloneURL.String(), "uid": "4", "repo_name": "web-mig-" + mode, "service": strconv.Itoa(int(api.PlainGitService))}
					assertPersonalRepoWeb(t, user4, NewRequestWithValues(t, "POST", "/repo/migrate", values), mode, false)
					assert.False(t, repoExists(t, "user4", "web-mig-"+mode))
				}
			})
		}
	})
}

func TestPersonalRepoPolicyPushCreate(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateUser, true)()
		for _, mode := range personalRepoModes {
			for _, private := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s-%t", mode, private), func(t *testing.T) {
					defer setPersonalRepoMode(t, mode)()
					defer test.MockVariableValue(&setting.Repository.DefaultPushCreatePrivate, private)()
					name := fmt.Sprintf("push-%s-%t", mode, private)
					dir := t.TempDir()
					pushURL := *u
					pushURL.Path = "/user4/" + name + ".git"
					pushURL.User = url.UserPassword("user4", userPassword)
					t.Run("Init", doGitInitTestRepository(dir, git.Sha1ObjectFormat))
					t.Run("AddRemote", doGitAddRemote(dir, "origin", &pushURL))
					if personalRepoAllowed(mode, private) {
						t.Run("Push", doGitPushTestRepository(dir, "origin", "master"))
						assert.True(t, repoExists(t, "user4", name))
						return
					}
					assert.Contains(t, doGitPushTestRepositoryFail(t, dir, "origin", "master"), personalRepoMessage(mode))
					assert.False(t, repoExists(t, "user4", name))
				})
			}
		}
	})
}

func TestPersonalRepoPolicyAdopt(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Repository.AllowAdoptionOfUnadoptedRepositories, true)()
	user4 := loginUser(t, "user4")
	for _, mode := range personalRepoModes {
		t.Run(mode, func(t *testing.T) {
			defer setPersonalRepoMode(t, mode)()
			name := "adopt-" + mode
			require.NoError(t, git.InitRepository(t.Context(), repo_model.RepoPath("user4", name), true, git.Sha1ObjectFormat.Name()))
			// an adopted repository is private
			user4.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/repos/unadopted", map[string]string{"id": name, "action": "adopt"}), http.StatusSeeOther)
			allowed := personalRepoAllowed(mode, true)
			assert.Equal(t, allowed, repoExists(t, "user4", name))
			if !allowed {
				doc := NewHTMLParser(t, user4.MakeRequest(t, NewRequest(t, "GET", "/user/settings/repos"), http.StatusOK).Body)
				assert.Contains(t, doc.Find(".flash-error").Text(), "Personal repositories are disabled")
			}
		})
	}
}

func TestPersonalRepoPolicyTransfer(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
	user4 := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeAll)
	admin := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)

	for _, mode := range personalRepoModes {
		t.Run(mode, func(t *testing.T) {
			for _, private := range []bool{true, false} {
				allowed := personalRepoAllowed(mode, private)
				start, accept := fmt.Sprintf("tr-start-%s-%t", mode, private), fmt.Sprintf("tr-accept-%s-%t", mode, private)
				for _, name := range []string{start, accept} {
					MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name, Private: private}).AddTokenAuth(owner), http.StatusCreated)
				}
				// a pending transfer started while it was allowed
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+accept+"/transfer", &api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(owner), http.StatusCreated)

				reset := setPersonalRepoMode(t, mode)
				assertPersonalRepoAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+start+"/transfer", &api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(owner), http.StatusCreated, mode, allowed)
				assertPersonalRepoAPI(t, NewRequest(t, "POST", "/api/v1/repos/user2/"+accept+"/transfer/accept").AddTokenAuth(user4), http.StatusAccepted, mode, allowed)
				assert.Equal(t, allowed, repoExists(t, "user4", accept))
				assert.Equal(t, !allowed, repoExists(t, "user2", accept))

				// a site admin moves it directly (user4 blocks user1 in the fixtures); organizations are not restricted
				adminName := "tr-admin-" + start
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: adminName, Private: private}).AddTokenAuth(admin), http.StatusCreated)
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user1/"+adminName+"/transfer", &api.TransferRepoOption{NewOwner: "user5"}).AddTokenAuth(admin), http.StatusAccepted)
				assert.True(t, repoExists(t, "user5", adminName))
				if !allowed {
					MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+start+"/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(owner), http.StatusAccepted)
				}
				reset()
			}
		})
	}
}

// Restoring a repository from the trash to another owner is checked for that owner; the same owner is allowed.
func TestPersonalRepoPolicyTrashRestore(t *testing.T) {
	defer prepareTrash(t)()
	owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "trash-move"}).AddTokenAuth(owner), http.StatusCreated)
	id := repoIDByName(t, "user2", "trash-move")
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/trash-move").AddTokenAuth(owner), http.StatusNoContent)
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(db.DefaultContext, id)
	require.NoError(t, err)
	require.NotZero(t, repo.TrashedUnix)

	defer setPersonalRepoMode(t, setting.PersonalReposDisabled)()
	err = repo_service.MoveTrashedRepository(audit_model.WithSystem(db.DefaultContext, "test"), user2, user4, repo, "")
	require.ErrorAs(t, err, &repo_module.ErrPersonalRepoPolicy{})
	// the same owner: allowed (the call above changed repo in memory, so load it again)
	repo, err = repo_model.GetRepositoryByIDIncludingTrashed(db.DefaultContext, id)
	require.NoError(t, err)
	require.NoError(t, repo_service.MoveTrashedRepository(db.DefaultContext, user2, nil, repo, "trash-renamed"))
}

func TestPersonalRepoPolicyVisibility(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		session := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
		admin := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)
		orgOwner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
		no, yes := false, true

		for _, mode := range personalRepoModes {
			t.Run(mode, func(t *testing.T) {
				name := "vis-" + mode
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name, Private: true, AutoInit: true}).AddTokenAuth(token), http.StatusCreated)
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: name, Private: true}).AddTokenAuth(orgOwner), http.StatusCreated)
				defer setPersonalRepoMode(t, mode)()
				allowed := personalRepoAllowed(mode, false)
				isPrivate := func() bool {
					return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user4", LowerName: name}).IsPrivate
				}

				// the repo.private push option, at the hook and through a real push
				res := private.HookPreReceive(t.Context(), repoIDByName(t, "user4", name), private.HookOptions{UserID: 4, GitPushOptions: map[string]string{"repo.private": "false"}})
				if allowed {
					require.NoError(t, res.Error)
				} else {
					assert.Equal(t, http.StatusForbidden, res.StatusCode)
					assert.Contains(t, res.UserMsg, personalRepoMessage(mode))
					dir := t.TempDir()
					cloneURL := *u
					cloneURL.Path = "/user4/" + name + ".git"
					cloneURL.User = url.UserPassword("user4", userPassword)
					doGitClone(dir, &cloneURL)(t)
					doGitCreateBranch(dir, "push-option")(t)
					_, stderr, err := git.NewCommand(git.DefaultContext, "push", "-o", "repo.private=false", "origin", "push-option").RunStdString(&git.RunOpts{Dir: dir})
					require.Error(t, err)
					assert.Contains(t, stderr, personalRepoMessage(mode))
				}

				assertPersonalRepoWeb(t, session, NewRequestWithValues(t, "POST", "/user4/"+name+"/settings", map[string]string{"action": "update", "repo_name": name}), mode, allowed)
				assert.Equal(t, !allowed, isPrivate())
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user4/"+name, &api.EditRepoOption{Private: &yes}).AddTokenAuth(token), http.StatusOK)
				assertPersonalRepoAPI(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user4/"+name, &api.EditRepoOption{Private: &no}).AddTokenAuth(token), http.StatusOK, mode, allowed)
				assert.Equal(t, !allowed, isPrivate())

				// making it private is always allowed; a site admin and organizations are not restricted
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user4/"+name, &api.EditRepoOption{Private: &yes}).AddTokenAuth(token), http.StatusOK)
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user4/"+name, &api.EditRepoOption{Private: &no}).AddTokenAuth(admin), http.StatusOK)
				assert.False(t, isPrivate())
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+name, &api.EditRepoOption{Private: &no}).AddTokenAuth(orgOwner), http.StatusOK)
			})
		}
	})
}

func TestPersonalRepoPolicyAdminPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")

	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/personal-repos"), http.StatusOK).Body)
	assert.Equal(t, 1, doc.Find("#mode-allowed[checked]").Length())
	assert.Equal(t, 0, doc.Find("#personal-repo-violators").Length())

	logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.INFO)
	logChecker.Filter("Personal repository policy changed from allowed to private_only by user1")
	defer cleanup()
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": "private_only"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	defer resetPersonalRepoMode(t)
	filtered, _ := logChecker.Check(5 * time.Second)
	assert.Equal(t, []bool{true}, filtered)

	doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/personal-repos"), http.StatusOK).Body)
	assert.Equal(t, 1, doc.Find("#mode-private_only[checked]").Length())
	// user2 owns public repositories, org3 is an organization
	violators := doc.Find("#personal-repo-violators").Text()
	assert.Contains(t, violators, "user2")
	assert.NotContains(t, violators, "org3")

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": "public"}), http.StatusBadRequest)
	user2 := loginUser(t, "user2")
	user2.MakeRequest(t, NewRequest(t, "GET", "/admin/personal-repos"), http.StatusForbidden)
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/personal-repos", map[string]string{"mode": "allowed"}), http.StatusForbidden)
	assert.Equal(t, setting.PersonalReposPrivateOnly, setting.Config().PersonalRepos.Value(db.DefaultContext).EffectiveMode())
}

// Refusals are logged with the owner and the doer.
func TestPersonalRepoPolicyRefusalLogged(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer setPersonalRepoMode(t, setting.PersonalReposDisabled)()
	logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
	logChecker.Filter("Personal repository policy disabled refused a repository of user4 (doer user4")
	defer cleanup()
	token := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "logged", Private: true}).AddTokenAuth(token), http.StatusForbidden)
	filtered, _ := logChecker.Check(5 * time.Second)
	assert.Equal(t, []bool{true}, filtered)
}

// Push-to-create into another user's namespace is never refused by the policy before the namespace check, so the
// answer doesn't tell which users are site admins, and nothing is logged.
func TestPersonalRepoPolicyPushCreateProbe(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Repository.EnablePushCreateUser, true)()
	defer setPersonalRepoMode(t, setting.PersonalReposDisabled)()
	logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
	logChecker.Filter("Personal repository policy")
	defer cleanup()

	probe := func(owner string) *httptest.ResponseRecorder {
		return MakeRequest(t, NewRequest(t, "GET", "/"+owner+"/probe.git/info/refs?service=git-receive-pack").AddBasicAuth("user4"), NoExpectedStatus)
	}
	admin, ordinary := probe("user1"), probe("user5")
	assert.Equal(t, admin.Code, ordinary.Code)
	assert.Equal(t, admin.Body.String(), ordinary.Body.String())
	filtered, _ := logChecker.Check(time.Second)
	assert.Equal(t, []bool{false}, filtered)

	// in the doer's own namespace the refusal shows
	assert.Contains(t, probe("user4").Body.String(), "ERR "+personalRepoMessage(setting.PersonalReposDisabled))
}

// The web transfer and accept pages show the policy refusal.
func TestPersonalRepoPolicyWebTransfer(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := loginUser(t, "user2")
	owner := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeAll)
	for _, name := range []string{"web-tr-start", "web-tr-accept"} {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name}).AddTokenAuth(owner), http.StatusCreated)
	}
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/web-tr-accept/transfer", &api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(owner), http.StatusCreated)
	defer setPersonalRepoMode(t, setting.PersonalReposPrivateOnly)()

	resp := user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/web-tr-start/settings", map[string]string{"action": "transfer", "repo_name": "user2/web-tr-start", "new_owner_name": "user4"}), http.StatusOK)
	assert.Contains(t, NewHTMLParser(t, resp.Body).Find(".flash-error").Text(), "Personal repositories must be private")
	assert.True(t, repoExists(t, "user2", "web-tr-start"))

	user4 := loginUser(t, "user4")
	user4.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/web-tr-accept/action/accept_transfer", nil), http.StatusSeeOther)
	doc := NewHTMLParser(t, user4.MakeRequest(t, NewRequest(t, "GET", "/user2/web-tr-accept"), http.StatusOK).Body)
	assert.Contains(t, doc.Find(".flash-error").Text(), "Personal repositories must be private")
	assert.True(t, repoExists(t, "user2", "web-tr-accept"))
}
