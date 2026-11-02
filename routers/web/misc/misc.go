// Copyright 2023 The Gitea Authors. All rights reserved.
// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package misc

import (
	"net/http"
	"path"
	"strings"
	"sync"

	"forgejo.org/modules/httpcache"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
)

func SSHInfo(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("content-type", "text/json;charset=UTF-8")
	_, err := rw.Write([]byte(`{"type":"agit","version":1}`))
	if err != nil {
		log.Error("fail to write result: err: %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func DummyOK(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func ManifestJSON(w http.ResponseWriter, req *http.Request) {
	httpcache.SetCacheControlInHeader(w.Header(), setting.StaticCacheTime)
	w.Header().Add("content-type", "application/manifest+json;charset=UTF-8")

	manifestJSON := util.FilePathJoinAbs(setting.CustomPath, "public/manifest.json")
	if ok, _ := util.IsExist(manifestJSON); ok {
		http.ServeFile(w, req, manifestJSON)
		return
	}

	bytes, err := setting.GetManifestJSON()
	if err != nil {
		log.Error("unable to marshal manifest JSON. Error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(bytes); err != nil {
		log.Error("unable to write manifest JSON. Error: %v", err)
		return
	}
}

func StaticRedirect(target string) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, path.Join(setting.StaticURLPrefix, target), http.StatusMovedPermanently)
	}
}

var defaultRobotsTxt = sync.OnceValue(func() []byte {
	return []byte(`# The default gitdepo robots.txt
# For more information: ` + setting.AppDocsURL("admin/advanced/search-engines/") + `

User-agent: *
Disallow: /api/
Disallow: /avatars/
Disallow: /user/
Disallow: /swagger.*.json
Disallow: /explore/*?*

Disallow: /repo/create
Disallow: /repo/migrate
Disallow: /org/create
Disallow: /*/*/fork

Disallow: /*/*/watchers
Disallow: /*/*/stargazers
Disallow: /*/*/forks

Disallow: /*/*/src/
Disallow: /*/*/blame/
Disallow: /*/*/commit/
Disallow: /*/*/commits/
Disallow: /*/*/raw/
Disallow: /*/*/media/
Disallow: /*/*/tags
Disallow: /*/*/graph
Disallow: /*/*/branches
Disallow: /*/*/compare
Disallow: /*/*/lastcommit/
Disallow: /*/*/rss/branch/
Disallow: /*/*/atom/branch/

Disallow: /*/*/activity
Disallow: /*/*/activity_author_data

Disallow: /*/*/actions
Disallow: /*/*/projects
Disallow: /*/*/labels
Disallow: /*/*/milestones

Disallow: /*/*/find/
Disallow: /*/*/tree-list/
Disallow: /*/*/search/
Disallow: /*/-/code

Disallow: /*/*/issues/new
Disallow: /*/*/pulls/*/files
Disallow: /*/*/pulls/*/commits

Disallow: /attachments/
Disallow: /*/*/attachments/
Disallow: /*/*/issues/*/attachments/
Disallow: /*/*/pulls/*/attachments/
Disallow: /*/*/releases/attachments
Disallow: /*/*/releases/download

Disallow: /*/*/archive/
Disallow: /*.bundle$
Disallow: /*.patch$
Disallow: /*.diff$
Disallow: /*.atom$
Disallow: /*.rss$

Disallow: /*lang=*
Disallow: /*redirect_to=*
Disallow: /*tab=*
Disallow: /*q=*
Disallow: /*sort=*
Disallow: /*repo-search-archived=*
`)
})

func RobotsTxt(w http.ResponseWriter, req *http.Request) {
	httpcache.SetCacheControlInHeader(w.Header(), setting.StaticCacheTime)
	w.Header().Set("Content-Type", "text/plain")

	robotsTxt := util.FilePathJoinAbs(setting.CustomPath, "public/robots.txt")
	if ok, _ := util.IsExist(robotsTxt); ok {
		http.ServeFile(w, req, robotsTxt)
		return
	}

	robots := defaultRobotsTxt()
	if sitemapPublic() {
		robots = append(append([]byte{}, robots...), "\nSitemap: "+setting.AppURL+"sitemap.xml\n"...)
	}
	_, err := w.Write(robots)
	if err != nil {
		log.Error("failed to write robots.txt: %v", err)
	}
}

// sitemapPublic tells whether anonymous visitors (crawlers) can read /sitemap.xml.
func sitemapPublic() bool {
	return setting.Other.EnableSitemap && !setting.Service.RequireSignInView && !setting.Service.Explore.RequireSigninView
}

// LlmsTxt serves /llms.txt (https://llmstxt.org): a Markdown overview of the site for AI
// assistants and answer engines. custom/public/llms.txt replaces it, like robots.txt.
func LlmsTxt(w http.ResponseWriter, req *http.Request) {
	httpcache.SetCacheControlInHeader(w.Header(), setting.StaticCacheTime)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")

	llmsTxt := util.FilePathJoinAbs(setting.CustomPath, "public/llms.txt")
	if ok, _ := util.IsExist(llmsTxt); ok {
		http.ServeFile(w, req, llmsTxt)
		return
	}

	if _, err := w.Write([]byte(defaultLlmsTxt())); err != nil {
		log.Error("failed to write llms.txt: %v", err)
	}
}

func defaultLlmsTxt() string {
	oneLine := strings.NewReplacer("\r", " ", "\n", " ")
	var b strings.Builder
	b.WriteString("# " + oneLine.Replace(setting.AppDisplayName) + "\n\n")
	if setting.UI.Meta.Description != "" {
		b.WriteString("> " + oneLine.Replace(setting.UI.Meta.Description) + "\n\n")
	}
	b.WriteString("This site runs gitdepo, a self-hosted software forge: Git repositories, issues, pull requests, code review, packages and CI.\n")
	if setting.Service.RequireSignInView {
		b.WriteString("\nSign-in is required to view content on this site.\n")
		return b.String()
	}

	if !setting.Service.Explore.RequireSigninView {
		b.WriteString("\n## Explore\n\n")
		b.WriteString("- [Repositories](" + setting.AppURL + "explore/repos): public repositories, searchable with `?q=`\n")
		if !setting.Service.Explore.DisableUsersPage {
			b.WriteString("- [Users](" + setting.AppURL + "explore/users): public user profiles\n")
		}
		if !setting.Service.Explore.DisableOrganizationsPage {
			b.WriteString("- [Organizations](" + setting.AppURL + "explore/organizations): public organizations\n")
		}
	}

	b.WriteString("\n## API\n\n")
	b.WriteString("- REST API: " + setting.AppURL + "api/v1\n")
	if setting.API.EnableSwagger {
		b.WriteString("- [API reference](" + setting.AppURL + "api/swagger): OpenAPI documentation of the REST API\n")
	}

	if sitemapPublic() {
		b.WriteString("\n## Optional\n\n")
		b.WriteString("- [Sitemap](" + setting.AppURL + "sitemap.xml): public repositories, users and organizations\n")
	}
	return b.String()
}
