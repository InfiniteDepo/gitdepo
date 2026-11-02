// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"html/template"
	"net/http/httptest"
	"testing"

	"forgejo.org/modules/json"
	"forgejo.org/modules/web/middleware"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seoTestContext(target string) *Context {
	return &Context{Base: &Base{Req: httptest.NewRequest("GET", target, nil), Data: middleware.ContextData{}}}
}

func TestSetCanonicalURL(t *testing.T) {
	for target, want := range map[string]string{
		"/explore/repos":                   "https://example.com/explore/repos",
		"/explore/repos?sort=newest&q=x":   "https://example.com/explore/repos",
		"/explore/repos?page=1":            "https://example.com/explore/repos",
		"/explore/repos?page=3&sort=x":     "https://example.com/explore/repos?page=3",
		"/explore/repos?page=%3Cscript%3E": "https://example.com/explore/repos",
		"/explore/repos?page=-2":           "https://example.com/explore/repos",
	} {
		ctx := seoTestContext(target)
		ctx.SetCanonicalURL("https://example.com/explore/repos")
		assert.Equal(t, want, ctx.Data["CanonicalURL"], target)
	}
}

func TestSetStructuredDataEscapes(t *testing.T) {
	ctx := seoTestContext("/")
	ctx.SetStructuredData(map[string]any{"@type": "WebSite", "name": `</script><script>alert(1)</script> & "x"`})

	out := string(ctx.Data["StructuredData"].(template.JS))
	assert.NotContains(t, out, "<")
	assert.NotContains(t, out, ">")
	assert.NotContains(t, out, "&")

	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &v))
	assert.Equal(t, "https://schema.org", v["@context"])
	assert.Equal(t, `</script><script>alert(1)</script> & "x"`, v["name"])
}
