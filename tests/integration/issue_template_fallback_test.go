// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	files_service "forgejo.org/services/repository/files"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const orgBugForm = `name: Org bug
about: Org bug form
body:
  - type: input
    id: what
    attributes:
      label: What happened
`

func mdTemplate(name, body string) *fstest.MapFile {
	return forgery.MapFile("---\nname: " + name + "\nabout: " + name + "\n---\n" + body)
}

func TestIssueTemplateFallback(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1, IsAdmin: true})
		orgOwner := forgery.CreateUser(t, nil)
		org := forgery.CreateOrganisation(t, orgOwner)
		outsider := forgery.CreateUser(t, nil)
		session := loginUser(t, outsider.Name)

		// A private <org>/.forgejo that outsider can't read.
		dotForgejo := forgery.CreateRepository(t, org.AsUser(), &forgery.CreateRepositoryOptions{
			Name:      ".forgejo",
			IsPrivate: true,
			Files: forgery.MapFS{
				".forgejo/ISSUE_TEMPLATE/bug.yaml":   forgery.MapFile(orgBugForm),
				".forgejo/ISSUE_TEMPLATE/config.yml": forgery.MapFile("contact_links:\n  - name: Org help\n    url: https://example.com\n    about: Ask here\n"),
				".forgejo/PULL_REQUEST_TEMPLATE.md":  forgery.MapFile("Org PR checklist"),
				"secret.md":                          mdTemplate("Secret", "TOP SECRET"),
			},
		})
		plain := forgery.CreateRepository(t, org.AsUser(), &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{"README.md": forgery.MapFile("plain")},
		})

		apiTemplates := func(t *testing.T, repo *repo_model.Repository) []*api.IssueTemplate {
			t.Helper()
			resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+repo.FullName()+"/issue_templates"), http.StatusOK)
			var templates []*api.IssueTemplate
			DecodeJSON(t, resp, &templates)
			return templates
		}
		templateNames := func(t *testing.T, repo *repo_model.Repository) []string {
			t.Helper()
			var names []string
			for _, it := range apiTemplates(t, repo) {
				names = append(names, it.Name)
			}
			return names
		}
		newIssueBody := func(t *testing.T, repo *repo_model.Repository, template string) string {
			t.Helper()
			resp := session.MakeRequest(t, NewRequest(t, "GET", repo.Link()+"/issues/new?template="+url.QueryEscape(template)), http.StatusOK)
			return resp.Body.String()
		}

		t.Run("Org templates without access to .forgejo", func(t *testing.T) {
			resp := session.MakeRequest(t, NewRequest(t, "GET", plain.Link()+"/issues/new/choose"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Org help")
			htmlDoc := NewHTMLParser(t, resp.Body)
			htmlDoc.AssertElement(t, "a[href$='/issues/new?template=.forgejo%2fISSUE_TEMPLATE%2fbug.yaml']", true)

			htmlDoc = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", plain.Link()+"/issues/new?template=.forgejo%2fISSUE_TEMPLATE%2fbug.yaml"), http.StatusOK).Body)
			htmlDoc.AssertElement(t, "#new-issue input[name='form-field-what']", true)

			assert.Equal(t, []string{"Org bug"}, templateNames(t, plain))
			resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+plain.FullName()+"/issue_config"), http.StatusOK)
			var config api.IssueConfig
			DecodeJSON(t, resp, &config)
			require.Len(t, config.ContactLinks, 1)
			assert.Equal(t, "Org help", config.ContactLinks[0].Name)
		})

		t.Run("Fallback form submits its body", func(t *testing.T) {
			req := NewRequestWithValues(t, "POST", plain.Link()+"/issues/new", map[string]string{
				"title":           "fallback form",
				"template-file":   ".forgejo/ISSUE_TEMPLATE/bug.yaml",
				"form-field-what": "it broke",
				"content":         "ignored",
			})
			session.MakeRequest(t, req, http.StatusOK)
			issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: plain.ID, Title: "fallback form"})
			assert.Contains(t, issue.Content, "it broke")
			assert.Contains(t, issue.Content, "What happened")

			// A template-file outside the template directories is never read.
			req = NewRequestWithValues(t, "POST", plain.Link()+"/issues/new", map[string]string{
				"title":         "secret form",
				"template-file": "secret.md",
				"content":       "mine",
			})
			session.MakeRequest(t, req, http.StatusOK)
			issue = unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: plain.ID, Title: "secret form"})
			assert.Equal(t, "mine", issue.Content)
		})

		t.Run("?template= is limited to template directories", func(t *testing.T) {
			for _, tpl := range []string{"secret.md", ".forgejo/ISSUE_TEMPLATE/../../secret.md"} {
				assert.NotContains(t, newIssueBody(t, plain, tpl), "TOP SECRET", tpl)
			}

			// Also on the repo itself.
			own := forgery.CreateRepository(t, outsider, &forgery.CreateRepositoryOptions{
				Files: forgery.MapFS{
					".forgejo/ISSUE_TEMPLATE/own.md": mdTemplate("Own", "own body"),
					"notes.md":                       mdTemplate("Notes", "NOTES BODY"),
				},
			})
			assert.NotContains(t, newIssueBody(t, own, "notes.md"), "NOTES BODY")
			assert.NotContains(t, newIssueBody(t, own, ".forgejo/ISSUE_TEMPLATE/../../notes.md"), "NOTES BODY")
			assert.Contains(t, newIssueBody(t, own, ".forgejo/ISSUE_TEMPLATE/own.md"), "own body")
		})

		t.Run("Repo templates win per kind", func(t *testing.T) {
			ownPR := forgery.CreateRepository(t, org.AsUser(), &forgery.CreateRepositoryOptions{
				Files: forgery.MapFS{".forgejo/PULL_REQUEST_TEMPLATE.md": forgery.MapFile("Repo PR checklist")},
			})
			assert.Equal(t, []string{"Org bug"}, templateNames(t, ownPR))
			assert.Equal(t, "Repo PR checklist", comparePRTemplate(t, session, ownPR, ""))

			ownIssue := forgery.CreateRepository(t, org.AsUser(), &forgery.CreateRepositoryOptions{
				Files: forgery.MapFS{".forgejo/ISSUE_TEMPLATE/own.md": mdTemplate("Own", "own body")},
			})
			assert.Equal(t, []string{"Own"}, templateNames(t, ownIssue))
		})

		t.Run("PR template from the org", func(t *testing.T) {
			assert.Equal(t, "Org PR checklist", comparePRTemplate(t, session, plain, ""))
			// ?template= is never read from a fallback source.
			assert.NotContains(t, comparePRTemplate(t, session, plain, "secret.md"), "TOP SECRET")
			assert.NotContains(t, comparePRTemplate(t, session, plain, ".forgejo/PULL_REQUEST_TEMPLATE.md"), "Org PR checklist")
		})

		t.Run("A push to .forgejo is used immediately", func(t *testing.T) {
			require.NoError(t, createOrReplaceFileInBranch(orgOwner, dotForgejo, ".forgejo/ISSUE_TEMPLATE/bug.yaml", "main",
				strings.Replace(orgBugForm, "Org bug", "Org bug v2", 1)))
			assert.Equal(t, []string{"Org bug v2"}, templateNames(t, plain))
		})

		t.Run("The .forgejo repo itself", func(t *testing.T) {
			ownerToken := getTokenForLoggedInUser(t, loginUser(t, orgOwner.Name), auth_model.AccessTokenScopeReadRepository)
			resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+dotForgejo.FullName()+"/issue_templates").AddTokenAuth(ownerToken), http.StatusOK)
			var templates []*api.IssueTemplate
			DecodeJSON(t, resp, &templates)
			require.Len(t, templates, 1)
			assert.Equal(t, "Org bug v2", templates[0].Name)
		})

		t.Run("User-owned .forgejo", func(t *testing.T) {
			forgery.CreateRepository(t, outsider, &forgery.CreateRepositoryOptions{
				Name:  ".forgejo",
				Files: forgery.MapFS{".gitea/issue_template/mine.md": mdTemplate("Mine", "mine")},
			})
			repo := forgery.CreateRepository(t, outsider, &forgery.CreateRepositoryOptions{
				Files: forgery.MapFS{"README.md": forgery.MapFile("x")},
			})
			assert.Equal(t, []string{"Mine"}, templateNames(t, repo))
		})

		t.Run("Instance fallback", func(t *testing.T) {
			loner := forgery.CreateUser(t, nil)
			repo := forgery.CreateRepository(t, loner, &forgery.CreateRepositoryOptions{
				Files: forgery.MapFS{"README.md": forgery.MapFile("x")},
			})
			assert.Empty(t, templateNames(t, repo))

			instanceFiles := forgery.MapFS{".forgejo/ISSUE_TEMPLATE/inst.md": mdTemplate("Instance", "inst")}
			adminRepo := forgery.CreateRepository(t, admin, &forgery.CreateRepositoryOptions{Files: instanceFiles})
			defer test.MockVariableValue(&setting.Repository.DefaultTemplatesRepo, adminRepo.FullName())()
			assert.Equal(t, []string{"Instance"}, templateNames(t, repo))
			// The org's .forgejo still wins over the instance repo.
			assert.Equal(t, []string{"Org bug v2"}, templateNames(t, plain))

			// Repos not owned by a site admin user are ignored, even an org with a site admin among its owners.
			adminOrg := forgery.CreateOrganisation(t, admin)
			adminOrgRepo := forgery.CreateRepository(t, adminOrg.AsUser(), &forgery.CreateRepositoryOptions{Files: instanceFiles})
			defer test.MockVariableValue(&setting.Repository.DefaultTemplatesRepo, adminOrgRepo.FullName())()
			assert.Empty(t, templateNames(t, repo))
			userRepo := forgery.CreateRepository(t, outsider, &forgery.CreateRepositoryOptions{Files: instanceFiles})
			defer test.MockVariableValue(&setting.Repository.DefaultTemplatesRepo, userRepo.FullName())()
			assert.Empty(t, templateNames(t, repo))
			defer test.MockVariableValue(&setting.Repository.DefaultTemplatesRepo, dotForgejo.FullName())()
			assert.Empty(t, templateNames(t, repo))
			defer test.MockVariableValue(&setting.Repository.DefaultTemplatesRepo, "nobody/nothing")()
			assert.Empty(t, templateNames(t, repo))
		})

		t.Run("API requires issue access", func(t *testing.T) {
			codeOnly := forgery.CreateUser(t, nil)
			team := forgery.CreateTeam(t, org, &forgery.CreateTeamOptions{Mode: perm.AccessModeRead, Members: []*user_model.User{codeOnly}})
			_, err := db.GetEngine(t.Context()).Where("team_id = ? AND `type` = ?", team.ID, unit_model.TypeIssues).
				Cols("access_mode").Update(&org_model.TeamUnit{AccessMode: perm.AccessModeNone})
			require.NoError(t, err)
			private := forgery.CreateRepository(t, org.AsUser(), &forgery.CreateRepositoryOptions{
				IsPrivate: true,
				Files:     forgery.MapFS{"README.md": forgery.MapFile("x")},
			})

			token := getTokenForLoggedInUser(t, loginUser(t, codeOnly.Name), auth_model.AccessTokenScopeReadRepository)
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+private.FullName()).AddTokenAuth(token), http.StatusOK)
			for _, endpoint := range []string{"issue_templates", "issue_config", "issue_config/validate"} {
				MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+private.FullName()+"/"+endpoint).AddTokenAuth(token), http.StatusForbidden)
			}
		})
	})
}

// comparePRTemplate returns the pre-filled body of a new pull request from a new branch of repo.
func comparePRTemplate(t *testing.T, session *TestSession, repo *repo_model.Repository, template string) string {
	t.Helper()
	branch := "feature-" + strings.ReplaceAll(template, "/", "-")
	_, err := files_service.ChangeRepoFiles(git.DefaultContext, repo, repo.Owner, &files_service.ChangeRepoFilesOptions{
		Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: branch + ".txt", ContentReader: strings.NewReader("change")}},
		OldBranch: repo.DefaultBranch,
		NewBranch: branch,
		Message:   "change",
	})
	require.NoError(t, err)
	link := repo.Link() + "/compare/" + repo.DefaultBranch + "..." + url.PathEscape(branch) + "?expand=1"
	if template != "" {
		link += "&template=" + url.QueryEscape(template)
	}
	resp := session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
	return NewHTMLParser(t, resp.Body).Find("#new-issue textarea[name='content']").Text()
}
