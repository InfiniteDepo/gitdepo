// Copyright 2025 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

// `/-/demo/error/{errcode}` provides a convenient way of testing various
// error pages sometimes which can be hard to reach otherwise.
// This file is a test of various attributes on those pages.

func enableDemoPages() func() {
	resetIsProd := test.MockVariableValue(&setting.IsProd, false)
	resetRoutes := test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())
	return func() {
		resetIsProd()
		resetRoutes()
	}
}

func TestDemoErrorPages(t *testing.T) {
	defer enableDemoPages()()

	t.Run("Server error", func(t *testing.T) {
		// `/-/demo/error/x` returns 500 for any x by default.
		// `/500` is simply for good look here
		req := NewRequest(t, "GET", "/-/demo/error/500")
		resp := MakeRequest(t, req, http.StatusInternalServerError)
		doc := NewHTMLParser(t, resp.Body)
		assert.Equal(t, "500", doc.Find(".error-code").Text())
		assert.Contains(t, doc.Find("head title").Text(), "Internal server error")
	})

	t.Run("Server error reports to the issue tracker", func(t *testing.T) {
		defer tests.PrepareTestEnv(t)()
		defer test.MockVariableValue(&setting.IssueTrackerURL, "https://example.com/tracker")()

		req := NewRequest(t, "GET", "/-/demo/error/500")
		resp := loginUser(t, "user1").MakeRequest(t, req, http.StatusInternalServerError)
		body := resp.Body.String()
		doc := NewHTMLParser(t, resp.Body)
		href, _ := doc.Find(".status-page-500 p a[target=_blank]").Attr("href")
		assert.Equal(t, "https://example.com/tracker", href)
		assert.NotContains(t, body, "codeberg.org")
	})

	t.Run("Server error reports to the gitdepo issues by default", func(t *testing.T) {
		defer tests.PrepareTestEnv(t)()

		req := NewRequest(t, "GET", "/-/demo/error/500")
		resp := loginUser(t, "user1").MakeRequest(t, req, http.StatusInternalServerError)
		href, _ := NewHTMLParser(t, resp.Body).Find(".status-page-500 p a[target=_blank]").Attr("href")
		assert.Equal(t, "https://github.com/InfiniteSpoved/spoved/issues", href)
	})

	t.Run("Page not found",
		func(t *testing.T) {
			req := NewRequest(t, "GET", "/-/demo/error/404").
				// Without this header `notFoundInternal` returns plaintext error message
				SetHeader("Accept", "text/html")
			resp := MakeRequest(t, req, http.StatusNotFound)
			doc := NewHTMLParser(t, resp.Body)
			assert.Equal(t, "404", doc.Find(".error-code").Text())
			assert.Contains(t, doc.Find("head title").Text(), "Page not found")
		})

	t.Run("Quota exhaustion",
		func(t *testing.T) {
			req := NewRequest(t, "GET", "/-/demo/error/413")
			resp := MakeRequest(t, req, http.StatusRequestEntityTooLarge)
			doc := NewHTMLParser(t, resp.Body)
			assert.Equal(t, "413", doc.Find(".error-code").Text())
		})
}
