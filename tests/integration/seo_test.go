// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"strings"
	"testing"

	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type seoHead struct {
	canonical   string
	description string
	twitterCard string
	jsonLD      map[string]any
}

func readSEOHead(t *testing.T, session *TestSession, url string) seoHead {
	t.Helper()
	req := NewRequest(t, "GET", url)
	var doc *HTMLDoc
	if session != nil {
		doc = NewHTMLParser(t, session.MakeRequest(t, req, http.StatusOK).Body)
	} else {
		doc = NewHTMLParser(t, MakeRequest(t, req, http.StatusOK).Body)
	}

	var h seoHead
	assert.Equal(t, 1, doc.Find(`head link[rel="canonical"]`).Length(), "one canonical link")
	h.canonical, _ = doc.Find(`head link[rel="canonical"]`).Attr("href")
	h.description, _ = doc.Find(`head meta[name="description"]`).Attr("content")
	h.twitterCard, _ = doc.Find(`head meta[name="twitter:card"]`).Attr("content")
	if ld := doc.Find(`head script[type="application/ld+json"]`); ld.Length() > 0 {
		require.Equal(t, 1, ld.Length())
		require.NoError(t, json.Unmarshal([]byte(ld.Text()), &h.jsonLD), ld.Text())
		assert.Equal(t, "https://schema.org", h.jsonLD["@context"])
	}
	return h
}

func TestSEOHead(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	t.Run("home", func(t *testing.T) {
		h := readSEOHead(t, nil, "/")
		assert.Equal(t, setting.AppURL, h.canonical)
		assert.Equal(t, "summary", h.twitterCard)
		assert.Equal(t, "WebSite", h.jsonLD["@type"])
		assert.Equal(t, setting.AppURL, h.jsonLD["url"])
		action := h.jsonLD["potentialAction"].(map[string]any)
		assert.Equal(t, setting.AppURL+"explore/repos?q={search_term_string}", action["target"])
	})

	t.Run("list page keeps only the page number", func(t *testing.T) {
		h := readSEOHead(t, nil, "/explore/repos?sort=newest&q=repo&page=2")
		assert.Equal(t, setting.AppURL+"explore/repos?page=2", h.canonical)
		assert.Nil(t, h.jsonLD)
	})

	t.Run("public repository home", func(t *testing.T) {
		h := readSEOHead(t, nil, "/User2/Repo1")
		assert.Equal(t, setting.AppURL+"user2/repo1", h.canonical, "differently cased paths share one canonical URL")
		assert.Equal(t, "summary_large_image", h.twitterCard)
		assert.Equal(t, "SoftwareSourceCode", h.jsonLD["@type"])
		assert.Equal(t, "repo1", h.jsonLD["name"])
		assert.Equal(t, setting.AppURL+"user2/repo1", h.jsonLD["url"])
		assert.Equal(t, setting.AppURL+"user2/repo1.git", h.jsonLD["codeRepository"])
		author := h.jsonLD["author"].(map[string]any)
		assert.Equal(t, "Person", author["@type"])
		assert.Equal(t, "user2", author["alternateName"])
		assert.Equal(t, setting.AppURL+"user2", author["url"])
	})

	t.Run("repository subpage", func(t *testing.T) {
		h := readSEOHead(t, nil, "/user2/repo1/src/branch/master/README.md")
		assert.Equal(t, setting.AppURL+"user2/repo1/src/branch/master/README.md", h.canonical)
		assert.Nil(t, h.jsonLD)
	})

	t.Run("private repository has no structured data", func(t *testing.T) {
		h := readSEOHead(t, loginUser(t, "user2"), "/user2/repo2")
		assert.Equal(t, setting.AppURL+"user2/repo2", h.canonical)
		assert.Nil(t, h.jsonLD)
	})

	t.Run("user profile", func(t *testing.T) {
		h := readSEOHead(t, nil, "/the_34-user.with.all.allowedchars")
		assert.Equal(t, setting.AppURL+"the_34-user.with.all.allowedChars", h.canonical)
		assert.Equal(t, "some [commonmark](https://commonmark.org/)!", h.description)
		assert.Equal(t, "ProfilePage", h.jsonLD["@type"])
		person := h.jsonLD["mainEntity"].(map[string]any)
		assert.Equal(t, "Person", person["@type"])
		assert.Equal(t, "the_1-user.with.all.allowedChars", person["name"])
		assert.Equal(t, "some [commonmark](https://commonmark.org/)!", person["description"])
		assert.NotContains(t, person, "email")
	})

	t.Run("organization profile", func(t *testing.T) {
		h := readSEOHead(t, nil, "/org3")
		assert.Equal(t, setting.AppURL+"org3", h.canonical)
		assert.Equal(t, "ProfilePage", h.jsonLD["@type"])
		assert.Equal(t, "Organization", h.jsonLD["mainEntity"].(map[string]any)["@type"])
	})

	t.Run("limited organization has no structured data", func(t *testing.T) {
		h := readSEOHead(t, loginUser(t, "user2"), "/limited_org")
		assert.Nil(t, h.jsonLD)
	})
}

func TestSEOCrawlerFiles(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	t.Run("robots.txt names the sitemap", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/robots.txt"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "\nSitemap: "+setting.AppURL+"sitemap.xml\n")
	})

	t.Run("llms.txt", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/llms.txt"), http.StatusOK)
		assert.Equal(t, "text/markdown; charset=utf-8", resp.Header().Get("Content-Type"))
		body := resp.Body.String()
		assert.True(t, strings.HasPrefix(body, "# "+setting.AppDisplayName+"\n"), body)
		assert.Contains(t, body, "("+setting.AppURL+"explore/repos)")
		assert.Contains(t, body, "("+setting.AppURL+"sitemap.xml)")
	})

	t.Run("sitemap lists public organizations", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/sitemap.xml"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), setting.AppURL+"explore/organizations/sitemap-1.xml")

		resp = MakeRequest(t, NewRequest(t, "GET", "/explore/organizations/sitemap-1.xml"), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "<loc>"+setting.AppURL+"org3</loc>")
		assert.NotContains(t, body, "limited_org", "only public organizations")
		assert.NotContains(t, body, "privated_org", "only public organizations")
		assert.NotContains(t, body, "<loc>"+setting.AppURL+"user2</loc>", "no individual users")
	})

	t.Run("sign-in required hides the sitemap", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Service.RequireSignInView, true)()
		resp := MakeRequest(t, NewRequest(t, "GET", "/robots.txt"), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), "Sitemap:")
		resp = MakeRequest(t, NewRequest(t, "GET", "/llms.txt"), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), "explore/")
	})
}
