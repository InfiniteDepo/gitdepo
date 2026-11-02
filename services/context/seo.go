// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"html/template"
	"strconv"
	"time"

	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
)

// SetCanonicalURL sets the page's canonical URL (base/head) to the absolute URL u, keeping only a
// page number above 1 from the query, so sort, tab and filter variants of a page share one URL.
// Every page starts with the requested path; a page with an entity URL (profile, repository
// home) sets that one, so differently cased paths share it too.
func (ctx *Context) SetCanonicalURL(u string) {
	if page, err := strconv.Atoi(ctx.Req.URL.Query().Get("page")); err == nil && page > 1 {
		u += "?page=" + strconv.Itoa(page)
	}
	ctx.Data["CanonicalURL"] = u
}

// SetStructuredData renders v as the page's schema.org JSON-LD (base/head_opengraph). The JSON
// encoder escapes <, > and &, so user text can't close the script element.
func (ctx *Context) SetStructuredData(v map[string]any) {
	v["@context"] = "https://schema.org"
	b, err := json.Marshal(v)
	if err != nil {
		log.Error("SetStructuredData: %v", err)
		return
	}
	ctx.Data["StructuredData"] = template.JS(b)
}

// OwnerStructuredData describes a user or organization as a schema.org Person or Organization.
func OwnerStructuredData(ctx *Context, u *user_model.User) map[string]any {
	v := map[string]any{
		"@type":         "Person",
		"name":          u.DisplayName(),
		"alternateName": u.Name,
		"url":           u.HTMLURL(),
		"image":         u.AvatarLink(ctx),
	}
	if u.IsOrganization() {
		v["@type"] = "Organization"
	}
	if u.Description != "" {
		v["description"] = u.Description
	}
	return v
}

// SetProfileStructuredData marks a public user or organization profile as a schema.org ProfilePage.
func (ctx *Context) SetProfileStructuredData(u *user_model.User) {
	ctx.SetCanonicalURL(u.HTMLURL())
	if !u.Visibility.IsPublic() {
		return
	}
	ctx.SetStructuredData(map[string]any{
		"@type":      "ProfilePage",
		"mainEntity": OwnerStructuredData(ctx, u),
	})
}

// SetRepoStructuredData describes a public repository as schema.org SoftwareSourceCode.
func (ctx *Context) SetRepoStructuredData(repo *repo_model.Repository, owner *user_model.User) {
	if repo.IsPrivate || owner == nil || !owner.Visibility.IsPublic() {
		return
	}
	v := map[string]any{
		"@type":          "SoftwareSourceCode",
		"name":           repo.Name,
		"url":            repo.HTMLURL(),
		"codeRepository": repo.CloneLink().HTTPS,
		"dateCreated":    repo.CreatedUnix.AsTime().UTC().Format(time.RFC3339),
		"dateModified":   repo.UpdatedUnix.AsTime().UTC().Format(time.RFC3339),
		"author":         OwnerStructuredData(ctx, owner),
	}
	if repo.Description != "" {
		v["description"] = repo.Description
	}
	if len(repo.Topics) > 0 {
		v["keywords"] = repo.Topics
	}
	ctx.SetStructuredData(v)
}
