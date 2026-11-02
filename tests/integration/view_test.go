// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	unit_model "forgejo.org/models/unit"
	"forgejo.org/modules/markup"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderFileSVGIsInImgTag(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	session := loginUser(t, "user2")

	req := NewRequest(t, "GET", "/user2/repo2/src/branch/master/line.svg")
	resp := session.MakeRequest(t, req, http.StatusOK)

	doc := NewHTMLParser(t, resp.Body)
	src, exists := doc.doc.Find(".file-view img").Attr("src")
	assert.True(t, exists, "The SVG image should be in an <img> tag so that scripts in the SVG are not run")
	assert.Equal(t, "/user2/repo2/raw/branch/master/line.svg", src)
}

func TestRenderDrawio(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		const diagram = `<mxfile><diagram name="Page-1"><mxGraphModel><root><mxCell id="0"/></root></mxGraphModel></diagram></mxfile>`
		user := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, user, &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{
				"docs/a.drawio": forgery.MapFile(diagram),
				"b.drawio.xml":  forgery.MapFile(diagram),
				"c.drawio.svg":  forgery.MapFile(`<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`),
			},
		})
		srcLink := repo.Link() + "/src/branch/" + repo.DefaultBranch + "/"
		renderLink := repo.Link() + "/render/branch/" + repo.DefaultBranch + "/"

		checkViewer := func(t *testing.T, treePath string) {
			resp := MakeRequest(t, NewRequest(t, "GET", srcLink+treePath), http.StatusOK)
			src, ok := NewHTMLParser(t, resp.Body).Find(".file-view iframe.external-render").Attr("src")
			require.True(t, ok)
			assert.Equal(t, renderLink+url.PathEscape(treePath), src)

			resp = MakeRequest(t, NewRequest(t, "GET", src), http.StatusOK)
			assert.Contains(t, resp.Body.String(), `<div class="mxgraph" data-mxgraph=`)
			assert.Contains(t, resp.Body.String(), "/assets/vendor/drawio/viewer-static-32.0.2.min.js")
			assert.Contains(t, resp.Header().Values("Content-Security-Policy"), "frame-src 'self'; sandbox allow-scripts")
			assert.Contains(t, strings.Join(resp.Header().Values("Content-Security-Policy"), "\n"), "default-src 'none'; script-src 'self' 'unsafe-inline';")
		}

		t.Run("Drawio", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			checkViewer(t, "docs/a.drawio")
		})

		t.Run("DrawioXML", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			checkViewer(t, "b.drawio.xml")
		})

		t.Run("Source", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			resp := MakeRequest(t, NewRequest(t, "GET", srcLink+"docs/a.drawio?display=source"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			assert.Equal(t, 0, doc.Find("iframe.external-render").Length())
			assert.Equal(t, 1, doc.Find(".file-view.code-view").Length())
		})

		t.Run("SVGIsImage", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			resp := MakeRequest(t, NewRequest(t, "GET", srcLink+"c.drawio.svg"), http.StatusOK)
			src, ok := NewHTMLParser(t, resp.Body).Find(".file-view img").Attr("src")
			require.True(t, ok)
			assert.Equal(t, repo.Link()+"/raw/branch/"+repo.DefaultBranch+"/c.drawio.svg", src)
		})

		t.Run("Disabled", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			defer markup.Init(nil)
			defer test.MockVariableValue(&setting.DrawioEnabled, false)()
			markup.Init(nil)

			resp := MakeRequest(t, NewRequest(t, "GET", srcLink+"docs/a.drawio"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			assert.Equal(t, 0, doc.Find("iframe.external-render").Length())
			assert.Equal(t, 1, doc.Find(".file-view.code-view").Length())
		})

		t.Run("ProfileReadme", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			forgery.CreateRepository(t, user, &forgery.CreateRepositoryOptions{
				Name:  ".profile",
				Files: forgery.MapFS{"README.drawio": forgery.MapFile(diagram)},
			})

			resp := MakeRequest(t, NewRequest(t, "GET", "/"+user.Name), http.StatusOK)
			assert.NotContains(t, resp.Body.String(), "viewer-static")
			assert.NotContains(t, resp.Body.String(), "mxgraph")
		})
	})
}

func TestAmbiguousCharacterDetection(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user := forgery.CreateUser(t, nil)
		session := loginUser(t, user.Name)

		// Prepare the environments. File view, commit view (diff), wiki page.
		var commitID string
		repo := forgery.CreateRepository(t, user, &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{
				"test.sh": forgery.MapFile("Hello there!\nline western"),
			},
			LatestSha: &commitID,
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeWiki)

		req := NewRequestWithValues(t, "POST", repo.Link()+"/wiki?action=new", map[string]string{
			"title":   "Normal",
			"content": "Hello – Hello",
		})
		session.MakeRequest(t, req, http.StatusSeeOther)

		assertCase := func(t *testing.T, fileContext, commitContext, wikiContext bool) {
			t.Helper()

			t.Run("File context", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				req := NewRequest(t, "GET", repo.Link()+"/src/branch/main/test.sh")
				resp := session.MakeRequest(t, req, http.StatusOK)

				htmlDoc := NewHTMLParser(t, resp.Body)
				htmlDoc.AssertElement(t, ".unicode-escape-prompt", fileContext)
			})
			t.Run("Commit context", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				req := NewRequest(t, "GET", repo.Link()+"/commit/"+commitID)
				resp := session.MakeRequest(t, req, http.StatusOK)

				htmlDoc := NewHTMLParser(t, resp.Body)
				htmlDoc.AssertElement(t, ".lines-escape .toggle-escape-button", commitContext)
			})
			t.Run("Wiki context", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				req := NewRequest(t, "GET", repo.Link()+"/wiki/Normal")
				resp := session.MakeRequest(t, req, http.StatusOK)

				htmlDoc := NewHTMLParser(t, resp.Body)
				htmlDoc.AssertElement(t, ".unicode-escape-prompt", wikiContext)
			})
		}

		t.Run("Enabled all context", func(t *testing.T) {
			defer test.MockVariableValue(&setting.UI.SkipEscapeContexts, []string{})()

			assertCase(t, true, true, true)
		})

		t.Run("Enabled file context", func(t *testing.T) {
			defer test.MockVariableValue(&setting.UI.SkipEscapeContexts, []string{"diff", "wiki"})()

			assertCase(t, true, false, false)
		})

		t.Run("Enabled commit context", func(t *testing.T) {
			defer test.MockVariableValue(&setting.UI.SkipEscapeContexts, []string{"file-view", "wiki"})()

			assertCase(t, false, true, false)
		})

		t.Run("Enabled wiki context", func(t *testing.T) {
			defer test.MockVariableValue(&setting.UI.SkipEscapeContexts, []string{"file-view", "diff"})()

			assertCase(t, false, false, true)
		})

		t.Run("No context", func(t *testing.T) {
			defer test.MockVariableValue(&setting.UI.SkipEscapeContexts, []string{"file-view", "wiki", "diff"})()

			assertCase(t, false, false, false)
		})

		t.Run("Disabled detection", func(t *testing.T) {
			defer test.MockVariableValue(&setting.UI.SkipEscapeContexts, []string{})()
			defer test.MockVariableValue(&setting.UI.AmbiguousUnicodeDetection, false)()

			assertCase(t, false, false, false)
		})
	})
}

func TestCommitListActions(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user := forgery.CreateUser(t, nil)
		session := loginUser(t, user.Name)
		var commitID string
		repo := forgery.CreateRepository(t, user, &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{
				"test/test.sh": forgery.MapFile("Hello there!"),
			},
			LatestSha: &commitID,
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeWiki)

		req := NewRequestWithValues(t, "POST", repo.Link()+"/wiki?action=new", map[string]string{
			"title":   "Normal",
			"content": "Hello world!",
		})
		session.MakeRequest(t, req, http.StatusSeeOther)

		t.Run("Wiki revision", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()

			req := NewRequest(t, "GET", repo.Link()+"/wiki/Normal?action=_revision")
			resp := session.MakeRequest(t, req, http.StatusOK)
			htmlDoc := NewHTMLParser(t, resp.Body)

			htmlDoc.AssertElement(t, fmt.Sprintf(".commit-list a[href^='/%s/src/commit/']", repo.FullName()), false)
		})

		fileDiffSelector := fmt.Sprintf(".commit-list a[href='/%s/commit/%s?files=test/test.sh']", repo.FullName(), commitID)
		t.Run("Commit list", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()

			req := NewRequest(t, "GET", repo.Link()+"/commits/branch/main")
			resp := session.MakeRequest(t, req, http.StatusOK)
			htmlDoc := NewHTMLParser(t, resp.Body)

			htmlDoc.AssertElement(t, fmt.Sprintf(".commit-list a[href='/%s/src/commit/%s']", repo.FullName(), commitID), true)
			htmlDoc.AssertElement(t, fileDiffSelector, false)
		})

		t.Run("File history", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()

			req := NewRequest(t, "GET", repo.Link()+"/commits/branch/main/test/test.sh")
			resp := session.MakeRequest(t, req, http.StatusOK)
			htmlDoc := NewHTMLParser(t, resp.Body)

			htmlDoc.AssertElement(t, fmt.Sprintf(".commit-list a[href='/%s/src/commit/%s/test/test.sh']", repo.FullName(), commitID), true)
			htmlDoc.AssertElement(t, fileDiffSelector, true)

			htmlDoc.AssertElement(t, ".repo-path", true)
			htmlDoc.AssertElement(t, fmt.Sprintf(".repo-path a[href='/%s/src/branch/main'][title='%s']", repo.FullName(), repo.Name), true)
			assert.Equal(t, 2, htmlDoc.Find(".repo-path .breadcrumb-divider").Length())
			htmlDoc.AssertElement(t, fmt.Sprintf(".repo-path .section a[href='/%s/src/branch/main/test'][title='test']", repo.FullName()), true)
			htmlDoc.AssertElement(t, ".repo-path .active[title='test.sh']", true)
			htmlDoc.AssertElement(t, ".repo-path button[data-clipboard-text='test/test.sh']", true)
		})
	})
}

func TestTitleDisplayName(t *testing.T) {
	session := emptyTestSession(t)
	title := GetHTMLTitle(t, session, "/")
	assert.Equal(t, "gitdepo: Beyond coding. We Forge.", title)
}

func TestHomeDisplayName(t *testing.T) {
	session := emptyTestSession(t)
	req := NewRequest(t, "GET", "/")
	resp := session.MakeRequest(t, req, http.StatusOK)
	htmlDoc := NewHTMLParser(t, resp.Body)
	assert.Equal(t, "gitdepo: Beyond coding. We Forge.", strings.TrimSpace(htmlDoc.Find("h1.title").Text()))
}

func TestOpenGraphDisplayName(t *testing.T) {
	session := emptyTestSession(t)
	req := NewRequest(t, "GET", "/")
	resp := session.MakeRequest(t, req, http.StatusOK)
	htmlDoc := NewHTMLParser(t, resp.Body)
	ogTitle, _ := htmlDoc.Find("meta[property='og:title']").Attr("content")
	assert.Equal(t, "gitdepo: Beyond coding. We Forge.", ogTitle)
	ogSiteName, _ := htmlDoc.Find("meta[property='og:site_name']").Attr("content")
	assert.Equal(t, "gitdepo: Beyond coding. We Forge.", ogSiteName)
}
