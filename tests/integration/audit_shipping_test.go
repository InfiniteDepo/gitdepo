// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #17 PR 4c: a loki destination with the audit type receives the rows the sealer commits; the audit page shows
// the count to admins and auditors, never the destination.
func TestAuditShippingToLoki(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer cleanLogShipping(t)

	var mu sync.Mutex
	var lines []string
	var path string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var push struct {
			Streams []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"streams"`
		}
		_ = json.Unmarshal(b, &push)
		mu.Lock()
		defer mu.Unlock()
		path = r.URL.Path
		for _, s := range push.Streams {
			if s.Stream["logtype"] == "audit" && s.Stream["service"] == "gitdepo" {
				for _, v := range s.Values {
					lines = append(lines, v[1])
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Cleanup(test.MockVariableValue(&log.ShipTransport, srv.Client().Transport))
	t.Cleanup(test.MockVariableValue(&setting.Webhook.AllowedHostList, "loopback"))
	t.Cleanup(test.MockVariableValue(&audit_service.SealInterval, time.Hour))

	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	create := func(o *api.CreateLogShippingDestinationOption, status int) {
		apiShip(t, "POST", "", token, o, status)
	}
	// loki takes no key, and "all" doesn't stream audit
	create(&api.CreateLogShippingDestinationOption{Name: "bad", Type: "loki", Endpoint: srv.URL, Key: "abcdefgh12345", LogTypes: []string{"audit"}}, http.StatusUnprocessableEntity)
	create(&api.CreateLogShippingDestinationOption{Name: "all", Type: "http", Endpoint: srv.URL, LogTypes: []string{"all"}}, http.StatusCreated)
	assert.Empty(t, shipWritersOn("audit"))
	create(&api.CreateLogShippingDestinationOption{
		Name: "loki", Type: "loki", Endpoint: srv.URL + "/loki/api/v1/push", LogTypes: []string{"audit"}, Level: "error",
		Headers: []*api.LogShippingHeaderOption{{Name: "Authorization", Value: shipHeader}},
	}, http.StatusCreated)
	require.Len(t, shipWritersOn("audit"), 1)

	getUserToken(t, "user2", auth_model.AccessTokenScopeReadUser) // creating a token is an audit entry
	require.NoError(t, audit_service.SealAll(t.Context()))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, l := range lines {
			if strings.Contains(l, `"action":"credential.access_token.created"`) {
				return true
			}
		}
		return false
	}, 30*time.Second, 200*time.Millisecond)
	mu.Lock()
	assert.Equal(t, "/loki/api/v1/push", path)
	for _, l := range lines {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &m))
		assert.NotNil(t, m["seq"])
		assert.Len(t, m["hash"], 64)
		assert.Equal(t, m["action"], m["message"])
	}
	mu.Unlock()

	// the page: a count for admin and auditor, no destination
	setUserFlag(t, 2, "is_auditor", true)
	for _, name := range []string{"user1", "user2"} {
		body := loginUser(t, name).MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
		_, status, _ := strings.Cut(body, `audit-status`)
		status, _, _ = strings.Cut(status, "</p>") // the rows may name the destination the admin created; the header must not
		assert.Contains(t, status, "Streaming: 1 destination", name)
		assert.NotContains(t, status, "destinations", name)
		assert.NotContains(t, status, "127.0.0.1", name)
		assert.NotContains(t, status, "loki", name)
	}

	// shipping endpoints stay admin-only
	for _, name := range []string{"user2"} {
		tok := getUserToken(t, name, auth_model.AccessTokenScopeReadAdmin)
		apiShip(t, "GET", "", tok, nil, http.StatusForbidden)
	}
}

// The audit checkbox and its hint render on the destination form.
func TestAuditShippingForm(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	body := loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/log-shipping"), http.StatusOK).Body.String()
	assert.Contains(t, body, `id="log-type-audit"`)
	assert.Contains(t, body, `<span class="help">Contains IP addresses and user agents`)
	assert.Contains(t, body, `<option value="loki"`)
}
