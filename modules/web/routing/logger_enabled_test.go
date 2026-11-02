// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package routing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo.org/modules/log"

	"github.com/stretchr/testify/assert"
)

func TestLoggerHandlerFollowsTheWriters(t *testing.T) {
	logger := log.GetManager().GetLogger("router")
	logger.ReplaceAllWriters()
	defer logger.ReplaceAllWriters()
	var seenRecord []bool
	handler := NewLoggerHandler()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, ok := req.Context().Value(contextKey).(*requestRecord)
		seenRecord = append(seenRecord, ok)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/a", nil))
	w := log.NewEventWriterBuffer("router-late", log.WriterMode{Level: log.INFO, Format: "json"}).(log.EventWriterBuffer)
	logger.AddWriters(w)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/b", nil))
	logger.ReplaceAllWriters()

	assert.Equal(t, []bool{false, true}, seenRecord, "no request record is made while the logger has no writer")
	assert.Contains(t, w.GetString(), "/b")
	assert.NotContains(t, w.GetString(), "/a")
}
