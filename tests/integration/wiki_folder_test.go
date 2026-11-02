// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPLv3-or-later

package integration

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/lfs"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests/forgery"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWikiFolder(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		lfsContent := "large file content"
		lfsPointer, err := lfs.GeneratePointer(strings.NewReader(lfsContent))
		require.NoError(t, err)
		require.NoError(t, lfs.NewContentStore().Put(lfsPointer, strings.NewReader(lfsContent)))

		owner := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, owner, &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{
				"docs/README.md":        forgery.MapFile("# Welcome\n\nSee [install](guide/install.md) and ![logo](img/a.png)\n"),
				"docs/index.md":         forgery.MapFile("# Index\n"),
				"docs/guide/install.md": forgery.MapFile("# Install guide\n\n[back](../README.md) ![logo](../img/a.png)\n"),
				"docs/img/a.png":        forgery.MapFile("PNGDATA"),
				"docs/_Sidebar.md":      forgery.MapFile("Sidebar text\n"),
				"docs/b.markdown":       forgery.MapFile("no heading\n"),
				"docs/notes.txt":        forgery.MapFile("not a page\n"),
				"docs/link.md":          forgery.MapSymlink("../secret.md"),
				"docs/lfs.bin":          forgery.MapFile(lfsPointer.StringContent()),
				"docs/lfspage.md":       forgery.MapFile(lfsPointer.StringContent()),
				"secret.md":             forgery.MapFile("top secret\n"),
			},
		})
		_, err = git_model.NewLFSMetaObject(t.Context(), repo.ID, lfsPointer)
		require.NoError(t, err)
		forgery.InitWiki(t, repo, "main")

		link := repo.Link()
		setConfig := func(t *testing.T, cfg *repo_model.WikiConfig) {
			forgery.EnableRepoUnit(t, repo, unit.TypeWiki, cfg)
		}
		wikiConfig := func(t *testing.T) *repo_model.WikiConfig {
			r, err := repo_model.GetRepositoryByID(t.Context(), repo.ID)
			require.NoError(t, err)
			return r.MustGetUnit(t.Context(), unit.TypeWiki).WikiConfig()
		}
		folderMode := &repo_model.WikiConfig{Source: repo_model.WikiSourceFolder, Folder: "docs"}
		setConfig(t, folderMode)
		session := loginUser(t, owner.Name)

		hrefs := func(doc *HTMLDoc, selector string) []string {
			return doc.Find(selector).Map(func(_ int, s *goquery.Selection) string {
				return s.AttrOr("href", s.AttrOr("src", ""))
			})
		}

		t.Run("Home", func(t *testing.T) {
			doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+"/wiki"), http.StatusOK).Body)
			assert.Contains(t, doc.Find(".wiki-content-main").Text(), "Welcome")
			assert.Contains(t, hrefs(doc, ".wiki-content-main a"), link+"/src/branch/main/docs/guide/install.md")
			assert.Contains(t, hrefs(doc, ".wiki-content-main img"), link+"/media/branch/main/docs/img/a.png")
			assert.Contains(t, doc.Find(".wiki-content-sidebar").Text(), "Sidebar text")
			assert.Equal(t, []string{
				link + "/wiki/README.md",
				link + "/wiki/b.markdown",
				link + "/wiki/guide/install.md",
				link + "/wiki/index.md",
				link + "/wiki/lfspage.md",
			}, hrefs(doc, ".wiki-folder-pages a"))
			// directories are labelled once, only when they hold pages
			assert.Equal(t, []string{"guide"}, doc.Find(".wiki-folder-pages li.grey").Map(func(_ int, s *goquery.Selection) string { return strings.TrimSpace(s.Text()) }))
			// anonymous users see no edit link
			doc.AssertElement(t, "a.wiki-folder-edit", false)
			assert.Equal(t, []string{link + "/commits/branch/main/docs/README.md"}, hrefs(doc, "a.wiki-folder-history"))

			doc = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link+"/wiki/"), http.StatusOK).Body)
			assert.Equal(t, []string{link + "/_edit/main/docs/README.md"}, hrefs(doc, "a.wiki-folder-edit"))
		})

		t.Run("NestedPage", func(t *testing.T) {
			for _, p := range []string{"/wiki/guide/install", "/wiki/guide/install.md", "/wiki/guide/../guide/install.md", "/wiki/guide%2Finstall.md"} {
				doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+p), http.StatusOK).Body)
				assert.Contains(t, doc.Find(".wiki-content-main").Text(), "Install guide", p)
				assert.Contains(t, hrefs(doc, ".wiki-content-main a"), link+"/src/branch/main/docs/README.md", p)
				assert.Contains(t, hrefs(doc, ".wiki-content-main img"), link+"/media/branch/main/docs/img/a.png", p)
			}
			MakeRequest(t, NewRequest(t, "GET", link+"/wiki/nope"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", link+"/wiki/notes.txt"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", link+"/wiki/link.md"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", link+"/wiki/guide"), http.StatusNotFound)
		})

		t.Run("Pages", func(t *testing.T) {
			doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+"/wiki/?action=_pages"), http.StatusOK).Body)
			titles := doc.Find(".wiki-folder-pages a").Map(func(_ int, s *goquery.Selection) string { return strings.TrimSpace(s.Text()) })
			assert.Equal(t, []string{"Welcome", "b", "Install guide", "Index", "lfspage"}, titles)
		})

		t.Run("Raw", func(t *testing.T) {
			resp := MakeRequest(t, NewRequest(t, "GET", link+"/wiki/raw/img/a.png"), http.StatusOK)
			assert.Equal(t, "PNGDATA", resp.Body.String())
			resp = MakeRequest(t, NewRequest(t, "GET", link+"/wiki/raw/lfs.bin"), http.StatusOK)
			assert.Equal(t, lfsContent, resp.Body.String())
			for _, p := range []string{"../secret.md", "%2e%2e/secret.md", "..%2Fsecret.md", "link.md", "guide", "nope.png"} {
				MakeRequest(t, NewRequest(t, "GET", link+"/wiki/raw/"+p), http.StatusNotFound)
			}
		})

		t.Run("LFSPage", func(t *testing.T) {
			doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+"/wiki/lfspage"), http.StatusOK).Body)
			assert.Contains(t, doc.Find(".wiki-content-main").Text(), "Stored with Git LFS")
		})

		t.Run("Missing", func(t *testing.T) {
			for _, cfg := range []*repo_model.WikiConfig{
				{Source: repo_model.WikiSourceFolder, Folder: "nope"},
				{Source: repo_model.WikiSourceFolder, Folder: "docs", Branch: "gone"},
				{Source: repo_model.WikiSourceFolder, Folder: "../docs"},
				{Source: repo_model.WikiSourceFolder, Folder: "docs/README.md"},
			} {
				setConfig(t, cfg)
				for _, p := range []string{"/wiki", "/wiki/?action=_pages"} {
					doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+p), http.StatusOK).Body)
					doc.AssertElement(t, ".wiki-folder-missing", true)
				}
				MakeRequest(t, NewRequest(t, "GET", link+"/wiki/raw/img/a.png"), http.StatusNotFound)
			}
			setConfig(t, folderMode)
		})

		t.Run("Branch", func(t *testing.T) {
			gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
			require.NoError(t, err)
			defer gitRepo.Close()
			require.NoError(t, repo_service.CreateNewBranch(t.Context(), owner, repo, gitRepo, "main", "docs#1"))

			setConfig(t, &repo_model.WikiConfig{Source: repo_model.WikiSourceFolder, Folder: "docs", Branch: "docs#1"})
			defer setConfig(t, folderMode)
			doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link+"/wiki"), http.StatusOK).Body)
			assert.Contains(t, hrefs(doc, ".wiki-content-main a"), link+"/src/branch/docs%231/docs/guide/install.md")
			assert.Contains(t, hrefs(doc, ".wiki-content-main img"), link+"/media/branch/docs%231/docs/img/a.png")
			assert.Equal(t, []string{link + "/_edit/docs%231/docs/README.md"}, hrefs(doc, "a.wiki-folder-edit"))
			assert.Equal(t, []string{link + "/commits/branch/docs%231/docs/README.md"}, hrefs(doc, "a.wiki-folder-history"))
		})

		t.Run("Archived", func(t *testing.T) {
			repo.IsArchived = true
			require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "is_archived"))
			defer func() {
				repo.IsArchived = false
				require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "is_archived"))
			}()
			doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link+"/wiki"), http.StatusOK).Body)
			doc.AssertElement(t, "a.wiki-folder-edit", false)
		})

		t.Run("WriteRoutes", func(t *testing.T) {
			wikiRepo, err := gitrepo.OpenWikiRepository(t.Context(), repo)
			require.NoError(t, err)
			wikiCommit, err := wikiRepo.GetBranchCommit("main")
			wikiRepo.Close()
			require.NoError(t, err)

			check := func(t *testing.T, status int) {
				for _, p := range []string{"/wiki/?action=_new", "/wiki/Home?action=_edit", "/wiki/Home?action=_revision", "/wiki/search?q=wiki", "/wiki/commit/" + wikiCommit.ID.String()} {
					session.MakeRequest(t, NewRequest(t, "GET", link+p), status)
				}
			}
			check(t, http.StatusNotFound)
			for _, p := range []string{"/wiki/?action=_new", "/wiki/Home?action=_delete", "/wiki/Home"} {
				session.MakeRequest(t, NewRequestWithValues(t, "POST", link+p, map[string]string{"title": "Home", "content": "changed"}), http.StatusNotFound)
			}

			setConfig(t, &repo_model.WikiConfig{})
			defer setConfig(t, folderMode)
			check(t, http.StatusOK)
			doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+"/wiki"), http.StatusOK).Body)
			assert.Contains(t, doc.Find(".wiki-content-main").Text(), "Welcome to the wiki!")
		})

		t.Run("Settings", func(t *testing.T) {
			defer setConfig(t, folderMode)
			post := func(t *testing.T, values map[string]string) {
				form := map[string]string{"enable_code": "on", "enable_wiki": "on", "enable_external_wiki": "false"}
				maps.Copy(form, values)
				session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/settings/units", form), http.StatusSeeOther)
			}

			setConfig(t, &repo_model.WikiConfig{})
			post(t, map[string]string{"wiki_source": "folder", "wiki_folder": "docs/"})
			assert.Equal(t, &repo_model.WikiConfig{Source: repo_model.WikiSourceFolder, Folder: "docs"}, wikiConfig(t))
			post(t, map[string]string{"wiki_source": "folder", "wiki_folder": "docs", "wiki_branch": "main"})
			saved := &repo_model.WikiConfig{Source: repo_model.WikiSourceFolder, Folder: "docs", Branch: "main"}
			assert.Equal(t, saved, wikiConfig(t))

			for _, bad := range []map[string]string{
				{"wiki_source": "folder", "wiki_folder": "../x"},
				{"wiki_source": "folder", "wiki_folder": "/docs"},
				{"wiki_source": "folder", "wiki_folder": ""},
				{"wiki_source": "folder", "wiki_folder": "."},
				{"wiki_source": "folder", "wiki_folder": "docs", "wiki_branch": "unknown"},
			} {
				post(t, bad)
				assert.Equal(t, saved, wikiConfig(t), bad)
			}

			// a form without the wiki source (e.g. an older page) keeps the config
			post(t, nil)
			assert.Equal(t, saved, wikiConfig(t))

			// the settings page shows the saved config
			doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link+"/settings/units"), http.StatusOK).Body)
			doc.AssertElement(t, "input[name=wiki_source][value=folder][checked]", true)
			assert.Equal(t, "docs", doc.Find("input[name=wiki_folder]").AttrOr("value", ""))
			assert.Equal(t, "main", doc.Find("input[name=wiki_branch]").AttrOr("value", ""))

			// API changes of the wiki unit keep the config
			token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
			yes := true
			for _, opts := range []*api.EditRepoOption{{HasWiki: &yes}, {GloballyEditableWiki: &yes}} {
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/"+repo.FullName(), opts).AddTokenAuth(token), http.StatusOK)
				assert.Equal(t, saved, wikiConfig(t))
			}

			// switching back
			post(t, map[string]string{"wiki_source": "separate", "wiki_folder": "docs"})
			assert.False(t, wikiConfig(t).FromFolder())
			doc = NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", link+"/wiki"), http.StatusOK).Body)
			assert.Contains(t, doc.Find(".wiki-content-main").Text(), "Welcome to the wiki!")
		})
	})
}

func TestWikiFolderPermissions(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		// teams first: a repository joins the teams that include all repositories when it is created
		org := forgery.CreateOrganisation(t, nil)
		wikiReader := forgery.CreateUser(t, nil)
		team := forgery.CreateTeam(t, org, &forgery.CreateTeamOptions{Mode: perm.AccessModeRead, Members: []*user_model.User{wikiReader}})
		_, err := db.DeleteByBean(t.Context(), &org_model.TeamUnit{TeamID: team.ID, Type: unit.TypeCode})
		require.NoError(t, err)
		codeReader := forgery.CreateUser(t, nil)
		forgery.CreateTeam(t, org, &forgery.CreateTeamOptions{Name: fmt.Sprintf("readers-%d", team.ID), Mode: perm.AccessModeRead, Members: []*user_model.User{codeReader}})
		repo := forgery.CreateRepository(t, org.AsUser(), &forgery.CreateRepositoryOptions{
			IsPrivate: true,
			Files: forgery.MapFS{
				"docs/README.md": forgery.MapFile("# Welcome\n"),
				"docs/a.png":     forgery.MapFile("PNGDATA"),
			},
		})
		forgery.InitWiki(t, repo, "main")
		session := loginUser(t, wikiReader.Name)
		link := repo.Link()

		// separate wiki: wiki read is enough
		session.MakeRequest(t, NewRequest(t, "GET", link+"/wiki"), http.StatusOK)

		forgery.EnableRepoUnit(t, repo, unit.TypeWiki, &repo_model.WikiConfig{Source: repo_model.WikiSourceFolder, Folder: "docs"})
		for _, p := range []string{"/wiki", "/wiki/README", "/wiki/?action=_pages", "/wiki/raw/a.png"} {
			t.Run(p, func(t *testing.T) {
				session.MakeRequest(t, NewRequest(t, "GET", link+p), http.StatusNotFound)
				MakeRequest(t, NewRequest(t, "GET", link+p), http.StatusNotFound)
			})
		}

		// a member with code read can read it
		loginUser(t, codeReader.Name).MakeRequest(t, NewRequest(t, "GET", link+"/wiki/raw/a.png"), http.StatusOK)
	})
}
