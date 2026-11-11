// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo.org/modules/web/middleware"

	"github.com/stretchr/testify/assert"
)

func TestBaseFormRefusesUnparsableForm(t *testing.T) {
	read := func(body string) (*httptest.ResponseRecorder, bool) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(middleware.WithFormState(req.Context()))
		rec := httptest.NewRecorder()
		b := &Base{Req: req, Resp: WrapResponseWriter(rec)}
		refused := false
		func() {
			defer func() { _, refused = recover().(middleware.FormRefused) }()
			assert.Equal(t, "1", b.FormString("a"))
		}()
		return rec, refused
	}
	rec, refused := read("a=1")
	assert.False(t, refused)
	assert.Equal(t, http.StatusOK, rec.Code)
	for _, body := range []string{"a=%zz", "a=1" + strings.Repeat("&f=1", 10000)} {
		rec, refused = read(body)
		assert.True(t, refused)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}
}
