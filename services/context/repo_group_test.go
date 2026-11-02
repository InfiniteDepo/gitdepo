// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefusedPath(t *testing.T) {
	for _, path := range []string{
		"org/proj%2Frepo", "org/proj%2frepo", "org/proj/repo%2F..", "org/proj/repo%252F", "org/proj%5Crepo",
		"org/proj%5crepo", "org/proj/%2E%2E", "org/proj/%2e", "org%2Fproj/repo", "org%2E/proj", "org%5C/proj",
		"org%25/proj", "org/@1", "org/%401", "org/proj/@1", "org/proj/re@po", "org/proj\\repo", "org/../x",
		"org/proj/..", "./proj", "../proj", "org/proj/%E2%80%AE",
	} {
		assert.True(t, refusedPath(strings.Split(path, "/")), path)
	}
	for _, path := range []string{
		"org/repo", "org/repo.git", "org/repo/src/branch/main/%2E%2E", "org/proj/repo/-/raw/branch/main/a%2Fb",
		"org/-/packages/npm/@scope%2Fname", "org/repo/-/a@b", "@user@example.com/-/x", "%CE%BFrg/repo",
		"org/proj/re-po_1.x", "org/repo/-",
	} {
		assert.False(t, refusedPath(strings.Split(path, "/")), path)
	}
}

func TestRepoGroupWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	st := &repoGroupState{}
	w := &repoGroupWriter{ResponseWriter: rec, st: st}
	assert.Equal(t, http.ResponseWriter(rec), w.Unwrap())

	st.target = "/org/@1"
	w.WriteHeader(http.StatusNotFound)
	n, err := w.Write([]byte("dropped"))
	require.NoError(t, err)
	assert.Equal(t, 7, n)
	w.Flush()
	assert.False(t, rec.Flushed)
	assert.Empty(t, rec.Body.String())

	rec = httptest.NewRecorder()
	w = &repoGroupWriter{ResponseWriter: rec, st: &repoGroupState{}}
	w.WriteHeader(http.StatusTeapot)
	_, _ = w.Write([]byte("kept"))
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "kept", rec.Body.String())
}
