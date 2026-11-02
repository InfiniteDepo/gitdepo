// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogShippingNewRelicAccessLog(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const key = "NRAK-INTEGRATIONKEY0123456789"
	var (
		mu      sync.Mutex
		events  []map[string]any
		headers []http.Header
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if assert.NoError(t, err) {
			b, _ := io.ReadAll(zr)
			var batch []map[string]any
			assert.NoError(t, json.Unmarshal(b, &batch))
			mu.Lock()
			events = append(events, batch...)
			headers = append(headers, r.Header.Clone())
			mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	defer test.MockVariableValue(&log.NewRelicTransport, srv.Client().Transport)()

	// the access logger writes "file" and "newrelic"; its middleware is only added to routes built afterwards
	logSec := setting.CfgProvider.Section("log")
	_, _ = logSec.NewKey("LOGGER_ACCESS_MODE", "file, newrelic")
	logSec.Key("LOGGER_ACCESS_MODE").SetValue("file, newrelic")
	nrSec := setting.CfgProvider.Section("log.newrelic")
	nrSec.Key("ENDPOINT").SetValue(srv.URL + "/log/v1")
	nrSec.Key("KEY").SetValue(key)
	setting.InitLoggersForTest()
	defer log.GetManager().GetLogger("access").ReplaceAllWriters()
	routes := routers.NormalRoutes()

	req := NewRequest(t, "GET", "/api/v1/version?access_token=SECRETTOKEN0123456789&page=2")
	req.Request.RemoteAddr = "203.0.113.7:4711"
	req.Header.Set("User-Agent", "nr-integration-agent")
	recorder := httptest.NewRecorder()
	routes.ServeHTTP(recorder, req.Request)

	accessEvents := func() (out []map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range events {
			if e["logtype"] == "access" {
				out = append(out, e)
			}
		}
		return out
	}
	require.Eventually(t, func() bool { return len(accessEvents()) > 0 }, 15*time.Second, 50*time.Millisecond) // flushed every 5 s
	require.Len(t, accessEvents(), 1)
	e := accessEvents()[0]
	mu.Lock()
	assert.Equal(t, key, headers[0].Get("Api-Key"))
	mu.Unlock()
	assert.Equal(t, "access", e["logger"])
	assert.Equal(t, "gitdepo", e["service"])
	assert.Equal(t, "203.0.113.7", e["ip"])
	assert.Equal(t, "GET", e["method"])
	assert.Equal(t, "nr-integration-agent", e["user_agent"])
	assert.InDelta(t, recorder.Code, e["status"], 0)
	assert.InDelta(t, recorder.Body.Len(), e["bytes"], 0)
	assert.Contains(t, e, "duration_ms")
	assert.Contains(t, e, "timestamp")
	assert.NotEmpty(t, e["hostname"])
	assert.Equal(t, "/api/v1/version?access_token=[REDACTED]&page=2", e["path"])
	body, _ := json.Marshal(e)
	assert.NotContains(t, string(body), "SECRETTOKEN0123456789")
	assert.NotContains(t, string(body), key)

	// the file log still gets the line, in the unchanged text format
	logFile := filepath.Join(setting.Log.RootPath, "access.log")
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(logFile)
		return err == nil && strings.Contains(string(b), `"GET /api/v1/version?access_token=`)
	}, 5*time.Second, 20*time.Millisecond)

	// the key is not on the administration configuration page
	session := loginUser(t, "user1")
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/config"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "newrelic.access")
	assert.NotContains(t, resp.Body.String(), key)
}
