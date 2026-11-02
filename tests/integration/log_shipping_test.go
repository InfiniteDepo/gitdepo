// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	app_context "forgejo.org/services/context"
	logshipping_service "forgejo.org/services/logshipping"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	shipKey    = "NRAK-SHIPINTEGRATIONKEY0123456789"
	shipHeader = "Bearer ship-integration-header-value"
)

type shipSink struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	events []map[string]any
	auth   []string
}

// newShipSink starts a TLS endpoint that collects JSON events (array or NDJSON) and lets loopback be a log destination.
func newShipSink(t *testing.T, status int) *shipSink {
	t.Helper()
	s := &shipSink{status: status}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		_ = json.Unmarshal(b, &batch)
		s.mu.Lock()
		s.events = append(s.events, batch...)
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		code := s.status
		s.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(s.Close)
	t.Cleanup(test.MockVariableValue(&log.ShipTransport, s.Client().Transport))
	t.Cleanup(test.MockVariableValue(&setting.Webhook.AllowedHostList, "loopback"))
	return s
}

func (s *shipSink) find(f func(map[string]any) bool) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if f(e) {
			return e
		}
	}
	return nil
}

func (s *shipSink) has(f func(map[string]any) bool) func() bool {
	return func() bool { return s.find(f) != nil }
}

func cleanLogShipping(t *testing.T) {
	t.Helper()
	require.NoError(t, logshipping_service.Apply(db.DefaultContext, setting.LogShippingState{}))
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().LogShipping.DynKey(): ""}))
	bumpSettingsRevision(t)
}

func shipWritersOn(logger string) (names []string) {
	if l, ok := log.GetManager().DumpLoggers()[logger].(map[string]any); ok {
		if w, ok := l["EventWriters"].(map[string]any); ok {
			for k := range w {
				if strings.HasPrefix(k, "ship-") {
					names = append(names, k)
				}
			}
		}
	}
	return names
}

func apiShip(t *testing.T, method, path, token string, body any, status int) *httptest.ResponseRecorder {
	t.Helper()
	var req *RequestWrapper
	if body != nil {
		req = NewRequestWithJSON(t, method, "/api/v1/admin/log-shipping/destinations"+path, body)
	} else {
		req = NewRequest(t, method, "/api/v1/admin/log-shipping/destinations"+path)
	}
	return MakeRequest(t, req.AddTokenAuth(token), status)
}

// AC2, AC3: a destination created through the API ships the selected log types as JSON, and changes apply without a restart
func TestLogShippingDestinationLifecycle(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer cleanLogShipping(t)
	bumpSettingsRevision(t) // fixtures reset the revision: a Save could reuse one an earlier test cached
	sink := newShipSink(t, http.StatusOK)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)

	var d api.LogShippingDestination
	resp := apiShip(t, "POST", "", token, &api.CreateLogShippingDestinationOption{
		Name: "sink", Type: "http", Endpoint: sink.URL, LogTypes: []string{"access"},
		Headers: []*api.LogShippingHeaderOption{{Name: "Authorization", Value: shipHeader}},
	}, http.StatusCreated)
	DecodeJSON(t, resp, &d)
	writer := "ship-" + d.ID
	assert.Equal(t, []string{writer}, shipWritersOn("access"))
	assert.Empty(t, shipWritersOn("default"))

	MakeRequest(t, NewRequest(t, "GET", "/api/v1/version?marker=ship-access-1"), http.StatusOK)
	log.Warn("ship-app-marker-1")
	isMarker := func(e map[string]any) bool {
		s, _ := e["path"].(string)
		return strings.Contains(s, "marker=ship-access-1")
	}
	require.Eventually(t, sink.has(isMarker), 20*time.Second, 100*time.Millisecond) // flushed every 5 s
	e := sink.find(isMarker)
	assert.Equal(t, "access", e["logtype"])
	assert.Equal(t, "gitdepo", e["service"])
	assert.Equal(t, "GET", e["method"])
	assert.Nil(t, sink.find(func(e map[string]any) bool { return e["logtype"] == "application" }), "application events are not selected")
	assert.Equal(t, shipHeader, sink.auth[0])

	// the selection changes at once: the access writer is gone, application events go out
	apiShip(t, "PATCH", "/"+d.ID, token, map[string]any{"log_types": []string{"application"}}, http.StatusOK)
	assert.Empty(t, shipWritersOn("access"))
	assert.Equal(t, []string{writer}, shipWritersOn("default"))
	log.Warn("ship-app-marker-2")
	require.Eventually(t, sink.has(func(e map[string]any) bool {
		m, _ := e["message"].(string)
		return e["logtype"] == "application" && strings.Contains(m, "ship-app-marker-2")
	}), 20*time.Second, 100*time.Millisecond)

	// disabled and deleted ones stop at once
	apiShip(t, "PATCH", "/"+d.ID, token, map[string]any{"enabled": false}, http.StatusOK)
	assert.Empty(t, shipWritersOn("default"))
	assert.Nil(t, log.GetManager().GetSharedWriter(writer))
	apiShip(t, "PATCH", "/"+d.ID, token, map[string]any{"enabled": true}, http.StatusOK)
	assert.Equal(t, []string{writer}, shipWritersOn("default"))
	apiShip(t, "DELETE", "/"+d.ID, token, nil, http.StatusNoContent)
	assert.Empty(t, shipWritersOn("default"))
	apiShip(t, "GET", "/"+d.ID, token, nil, http.StatusNotFound)
	apiShip(t, "DELETE", "/"+d.ID, token, nil, http.StatusNotFound)
}

// AC4, AC5: validation, secrets never come back, are stored encrypted, a new endpoint needs them again
func TestLogShippingSecrets(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer cleanLogShipping(t)
	bumpSettingsRevision(t)
	newShipSink(t, http.StatusOK)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	admin := loginUser(t, "user1")

	var nr, gen api.LogShippingDestination
	DecodeJSON(t, apiShip(t, "POST", "", token, &api.CreateLogShippingDestinationOption{
		Name: "nr", Type: "newrelic", Endpoint: "https://127.0.0.1:9/log/v1", Key: shipKey, LogTypes: []string{"all"},
	}, http.StatusCreated), &nr)
	DecodeJSON(t, apiShip(t, "POST", "", token, &api.CreateLogShippingDestinationOption{
		Name: "gen", Type: "http", Endpoint: "https://127.0.0.1:9/in", LogTypes: []string{"router"},
		Headers: []*api.LogShippingHeaderOption{{Name: "Authorization", Value: shipHeader}, {Name: "X-Team", Value: "team-ops-secret-value"}},
	}, http.StatusCreated), &gen)
	assert.True(t, nr.HasKey)
	assert.False(t, gen.HasKey)
	require.Len(t, gen.Headers, 2)
	assert.True(t, gen.Headers[0].HasValue)

	noSecrets := func(where, body string) {
		t.Helper()
		assert.NotContains(t, body, shipKey, where)
		assert.NotContains(t, body, shipHeader, where)
		assert.NotContains(t, body, "team-ops-secret-value", where)
	}
	noSecrets("list", apiShip(t, "GET", "", token, nil, http.StatusOK).Body.String())
	noSecrets("get", apiShip(t, "GET", "/"+nr.ID, token, nil, http.StatusOK).Body.String())
	noSecrets("page", admin.MakeRequest(t, NewRequest(t, "GET", "/admin/log-shipping"), http.StatusOK).Body.String())
	page := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/log-shipping/destinations/"+gen.ID), http.StatusOK).Body.String()
	noSecrets("edit page", page)
	assert.Contains(t, page, "Authorization:")
	noSecrets("config page", admin.MakeRequest(t, NewRequest(t, "GET", "/admin/config"), http.StatusOK).Body.String())
	assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/config"), http.StatusOK).Body.String(), "ship-"+gen.ID)

	// stored encrypted
	row := unittest.AssertExistsAndLoadBean(t, &system_model.Setting{SettingKey: setting.Config().LogShipping.DynKey()})
	noSecrets("stored setting", row.SettingValue)
	assert.Contains(t, row.SettingValue, "Authorization")

	// a new endpoint without the key, or without every header value, is refused
	apiShip(t, "PATCH", "/"+nr.ID, token, map[string]any{"endpoint": "https://127.0.0.1:9/other"}, http.StatusUnprocessableEntity)
	apiShip(t, "PATCH", "/"+gen.ID, token, map[string]any{"endpoint": "https://127.0.0.1:9/other"}, http.StatusUnprocessableEntity)
	apiShip(t, "PATCH", "/"+gen.ID, token, map[string]any{"endpoint": "https://127.0.0.1:9/other", "headers": []map[string]string{{"name": "Authorization", "value": shipHeader}, {"name": "X-Team"}}}, http.StatusUnprocessableEntity)
	var got api.LogShippingDestination
	DecodeJSON(t, apiShip(t, "GET", "/"+nr.ID, token, nil, http.StatusOK), &got)
	assert.Equal(t, "https://127.0.0.1:9/log/v1", got.Endpoint)
	// with the secrets it works; with the endpoint unchanged they are kept
	apiShip(t, "PATCH", "/"+nr.ID, token, map[string]any{"endpoint": "https://127.0.0.1:9/other", "key": shipKey + "2"}, http.StatusOK)
	DecodeJSON(t, apiShip(t, "PATCH", "/"+gen.ID, token, map[string]any{"level": "warn", "headers": []map[string]string{{"name": "Authorization"}}}, http.StatusOK), &got)
	assert.Equal(t, "warn", got.Level)
	require.Len(t, got.Headers, 1)
	assert.True(t, got.Headers[0].HasValue)

	// validation: userinfo, query, plain http, private address, bad names, forbidden headers
	for name, o := range map[string]api.CreateLogShippingDestinationOption{
		"userinfo": {Name: "a", Type: "http", Endpoint: "https://u:p@127.0.0.1:9/x", LogTypes: []string{"git"}},
		"query":    {Name: "a", Type: "http", Endpoint: "https://127.0.0.1:9/x?k=v", LogTypes: []string{"git"}},
		"http":     {Name: "a", Type: "http", Endpoint: "http://example.org/x", LogTypes: []string{"git"}},
		"private":  {Name: "a", Type: "http", Endpoint: "https://10.1.2.3/x", LogTypes: []string{"git"}},
		"mapped":   {Name: "a", Type: "http", Endpoint: "https://[::ffff:10.1.2.3]/x", LogTypes: []string{"git"}},
		"name":     {Name: "Bad Name", Type: "http", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"git"}},
		"dupe":     {Name: "gen", Type: "http", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"git"}},
		"header":   {Name: "a", Type: "http", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"git"}, Headers: []*api.LogShippingHeaderOption{{Name: "Host", Value: "x"}}},
		"no key":   {Name: "a", Type: "newrelic", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"git"}},
		"log type": {Name: "a", Type: "http", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"nope"}},
		"database": {Name: "a", Type: "http", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"database"}},
		"self":     {Name: "a", Type: "http", Endpoint: setting.AppURL + "api/v1/version", LogTypes: []string{"access"}},
		"crlf":     {Name: "a", Type: "http", Endpoint: "https://127.0.0.1:9/x", LogTypes: []string{"git"}, Headers: []*api.LogShippingHeaderOption{{Name: "X-A", Value: "v\r\nX-B: w"}}},
	} {
		resp := apiShip(t, "POST", "", token, &o, http.StatusUnprocessableEntity)
		assert.NotContains(t, resp.Body.String(), "u:p", name)
	}

	// the web form: create, and an edit that leaves the key empty keeps it
	form := url.Values{"name": {"web"}, "type": {"newrelic"}, "endpoint": {"https://127.0.0.1:9/web"}, "key": {shipKey}, "level": {"info"}, "enabled": {"on"}, "log_types": {"access", "git"}}
	resp := admin.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/admin/log-shipping/destinations", form), http.StatusSeeOther)
	loc := resp.Header().Get("Location")
	assert.Contains(t, loc, "/admin/log-shipping/destinations/")
	form.Del("key")
	form.Set("level", "error")
	admin.MakeRequest(t, NewRequestWithURLValues(t, "POST", loc, form), http.StatusSeeOther)
	list := apiShip(t, "GET", "", token, nil, http.StatusOK)
	noSecrets("list after web", list.Body.String())
	var all []api.LogShippingDestination
	DecodeJSON(t, list, &all)
	var web *api.LogShippingDestination
	for i := range all {
		if all[i].Name == "web" {
			web = &all[i]
		}
	}
	require.NotNil(t, web)
	assert.True(t, web.HasKey)
	assert.Equal(t, "error", web.Level)
	assert.Equal(t, []string{"access", "git"}, web.LogTypes)
}

// AC6: the test event goes to the saved destination only, errors are classes, one per 5 seconds
func TestLogShippingTestEvent(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer cleanLogShipping(t)
	bumpSettingsRevision(t)
	ok := newShipSink(t, http.StatusOK)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	admin := loginUser(t, "user1")

	create := func(name, endpoint string) (d api.LogShippingDestination) {
		DecodeJSON(t, apiShip(t, "POST", "", token, &api.CreateLogShippingDestinationOption{
			Name: name, Type: "http", Endpoint: endpoint, LogTypes: []string{"git"},
			Headers: []*api.LogShippingHeaderOption{{Name: "Authorization", Value: shipHeader}},
		}, http.StatusCreated), &d)
		return d
	}
	good := create("good", ok.URL)
	var res api.LogShippingTestResult
	DecodeJSON(t, apiShip(t, "POST", "/"+good.ID+"/test", token, nil, http.StatusOK), &res)
	assert.Equal(t, api.LogShippingTestResult{Status: 200}, res)
	e := ok.find(func(e map[string]any) bool { return e["logtype"] == "test" })
	require.NotNil(t, e)
	assert.Equal(t, shipHeader, ok.auth[0])
	apiShip(t, "POST", "/"+good.ID+"/test", token, nil, http.StatusTooManyRequests)
	apiShip(t, "POST", "/zzzzzzzz/test", token, nil, http.StatusNotFound)

	ok.mu.Lock()
	ok.status = http.StatusServiceUnavailable
	ok.mu.Unlock()
	failing := create("failing", ok.URL)
	DecodeJSON(t, apiShip(t, "POST", "/"+failing.ID+"/test", token, nil, http.StatusOK), &res)
	assert.Equal(t, api.LogShippingTestResult{Status: 503, Error: "status 5xx"}, res)

	// a closed port: the same fixed answer, no address, no error text
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	endpoint := dead.URL
	dead.Close()
	gone := create("gone", endpoint)
	resp := apiShip(t, "POST", "/"+gone.ID+"/test", token, nil, http.StatusOK)
	text := resp.Body.String()
	DecodeJSON(t, resp, &res)
	assert.Zero(t, res.Status)
	assert.Contains(t, []string{"connection failed", "timeout"}, res.Error)
	assert.NotContains(t, text, "127.0.0.1")

	// the web button flashes the result
	web := create("web", ok.URL)
	r := admin.MakeRequest(t, NewRequest(t, "POST", "/admin/log-shipping/destinations/"+web.ID+"/test"), http.StatusSeeOther)
	assert.Equal(t, setting.AppSubURL+"/admin/log-shipping/destinations/"+web.ID, r.Header().Get("Location"))
	assert.NotNil(t, admin.GetCookie(app_context.CookieNameFlash))
}

// AC7: admins only on the page and the API; maintenance mode keeps saves out and the test event in
func TestLogShippingAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer cleanLogShipping(t)
	bumpSettingsRevision(t)
	sink := newShipSink(t, http.StatusOK)
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	var d api.LogShippingDestination
	DecodeJSON(t, apiShip(t, "POST", "", adminToken, &api.CreateLogShippingDestinationOption{Name: "sink", Type: "http", Endpoint: sink.URL, LogTypes: []string{"git"}}, http.StatusCreated), &d)

	user2 := loginUser(t, "user2")
	user2Token := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeWriteAdmin)
	readOnly := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)
	publicOnly := getUserToken(t, "user1", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteAdmin)
	specific := createFineGrainedRepoAccessToken(t, "user1", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteAdmin}, []int64{3})

	body := &api.CreateLogShippingDestinationOption{Name: "x", Type: "http", Endpoint: sink.URL, LogTypes: []string{"git"}}
	for name, token := range map[string]string{"non-admin": user2Token, "public only": publicOnly, "specific repos": specific} {
		for _, c := range []struct {
			method, path string
			body         any
		}{{"GET", "", nil}, {"POST", "", body}, {"GET", "/" + d.ID, nil}, {"PATCH", "/" + d.ID, map[string]any{"enabled": false}}, {"DELETE", "/" + d.ID, nil}, {"POST", "/" + d.ID + "/test", nil}} {
			resp := apiShip(t, c.method, c.path, token, c.body, http.StatusForbidden)
			assert.NotContains(t, resp.Body.String(), d.ID, name)
		}
	}
	// the user of a running job (Actions token) is no admin
	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	task.GenerateToken()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "token", "token_salt", "token_hash", "token_last_eight"))
	apiShip(t, "GET", "", task.Token, nil, http.StatusForbidden)
	apiShip(t, "POST", "/"+d.ID+"/test", task.Token, nil, http.StatusForbidden)

	// a read-only token can read but not write
	apiShip(t, "GET", "", readOnly, nil, http.StatusOK)
	apiShip(t, "POST", "", readOnly, body, http.StatusForbidden)
	apiShip(t, "DELETE", "/"+d.ID, readOnly, nil, http.StatusForbidden)

	// the page: non-admins, anonymous
	for _, p := range []string{"/admin/log-shipping", "/admin/log-shipping/destinations/" + d.ID} {
		user2.MakeRequest(t, NewRequest(t, "GET", p), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", p), http.StatusSeeOther)
	}
	for _, p := range []string{"/admin/log-shipping/destinations", "/admin/log-shipping/destinations/" + d.ID, "/admin/log-shipping/destinations/" + d.ID + "/delete", "/admin/log-shipping/destinations/" + d.ID + "/test"} {
		user2.MakeRequest(t, NewRequestWithValues(t, "POST", p, map[string]string{"name": "x"}), http.StatusForbidden)
	}
	assert.Len(t, shipWritersOn("ssh"), 1, "nothing of the above changed the destination")

	// an admin who may not log in
	session := loginUser(t, "user1")
	user1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	user1.ProhibitLogin = true
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "prohibit_login"))
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/log-shipping"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "suspended")
	assert.NotContains(t, resp.Body.String(), d.ID)
	apiShip(t, "GET", "", adminToken, nil, http.StatusForbidden)
	user1.ProhibitLogin = false
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "prohibit_login"))

	// read-only maintenance: saves and deletes are refused, the test event still works
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
	apiShip(t, "POST", "", adminToken, body, http.StatusServiceUnavailable)
	apiShip(t, "PATCH", "/"+d.ID, adminToken, map[string]any{"enabled": false}, http.StatusServiceUnavailable)
	apiShip(t, "DELETE", "/"+d.ID, adminToken, nil, http.StatusServiceUnavailable)
	apiShip(t, "POST", "/"+d.ID+"/test", adminToken, nil, http.StatusOK)
	r := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/log-shipping/destinations/"+d.ID+"/delete", nil), http.StatusSeeOther)
	assert.NotContains(t, r.Header().Get("Location"), "log-shipping")
	assert.Len(t, shipWritersOn("ssh"), 1)
	maintenanceOff(t)
	apiShip(t, "GET", "/"+d.ID, adminToken, nil, http.StatusOK)
}

// AC9: a change is logged at Warn with who and what, never a secret
func TestLogShippingChangesAreLogged(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer cleanLogShipping(t)
	bumpSettingsRevision(t)
	newShipSink(t, http.StatusOK)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	checker, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
	defer cleanup()
	checker.Filter("log shipping: user1 created destination", shipKey).StopMark("changed:")

	apiShip(t, "POST", "", token, &api.CreateLogShippingDestinationOption{Name: "nr", Type: "newrelic", Endpoint: "https://127.0.0.1:9/x", Key: shipKey, LogTypes: []string{"access"}}, http.StatusCreated)
	filtered, stopped := checker.Check(5 * time.Second)
	assert.True(t, stopped)
	assert.True(t, filtered[0], "who and what")
	assert.False(t, filtered[1], "the key must not appear")
}
