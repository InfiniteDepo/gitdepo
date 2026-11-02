// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package logshipping

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/test"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKey    = "NRAK-UNITTESTKEY0123456789"
	testHeader = "Bearer unit-test-header-value"
)

// reset removes every destination, also from the loggers, and the saved state.
// lastRevision is the highest settings revision a test has used: the fixtures reset the revision, so without a new
// one a cached value of an earlier test would be served.
var lastRevision int

func reset(t *testing.T) {
	t.Helper()
	unittest.PrepareTestEnv(t)
	require.NoError(t, Apply(t.Context(), setting.LogShippingState{}))
	require.NoError(t, system_model.SetSettings(t.Context(), map[string]string{setting.Config().LogShipping.DynKey(): ""}))
	lastRevision = max(lastRevision, system_model.GetRevision(t.Context())) + 1
	_, err := db.Exec(t.Context(), "UPDATE system_setting SET version=? WHERE setting_key='revision'", lastRevision)
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
}

func allowLoopback(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.Webhook.AllowedHostList, "loopback"))
}

func writersOf(logger string) []string {
	var names []string
	m := log.GetManager().DumpLoggers()
	if l, ok := m[logger].(map[string]any); ok {
		if w, ok := l["EventWriters"].(map[string]any); ok {
			for k := range w {
				names = append(names, k)
			}
		}
	}
	slices.Sort(names)
	return names
}

func admin(t *testing.T) *user_model.User {
	return &user_model.User{ID: 1, Name: "user1", IsAdmin: true}
}

func newRelic(endpoint string, logTypes ...string) Input {
	return Input{Name: new("nr"), Type: new("newrelic"), Endpoint: &endpoint, Key: new(testKey), LogTypes: &logTypes}
}

func TestEndpointHostPolicy(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"https://logs.example.org/in":    true, // names are checked when dialled
		"https://8.8.8.8/in":             true,
		"https://10.0.0.1/in":            false,
		"https://192.168.1.5:8443/in":    false,
		"https://[::ffff:10.0.0.1]/in":   false, // IPv4-mapped IPv6
		"https://[fd00::1]/in":           false,
		"https://100.64.0.1/in":          false,
		"http://127.0.0.1:3000/in":       false,
		"https://[::1]/in":               false,
		"https://[::ffff:127.0.0.1]/in":  false,
		"https://169.254.169.254/latest": false,
	} {
		err := CheckEndpoint(endpoint)
		assert.Equal(t, ok, err == nil, endpoint)
	}
	allowLoopback(t)
	assert.NoError(t, CheckEndpoint("http://127.0.0.1:3000/in"))
	assert.NoError(t, CheckEndpoint("https://[::ffff:127.0.0.1]/in"))
	assert.Error(t, CheckEndpoint("https://10.0.0.1/in"))
}

func TestDialContextChecksTheResolvedAddress(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// "localhost" is a name the save-time check lets through; the dial resolves it to a loopback address
	addr := strings.Replace(l.Addr().String(), "127.0.0.1", "localhost", 1)

	_, err = DialContext()(t.Context(), "tcp", addr)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testKey)

	allowLoopback(t)
	c, err := DialContext()(t.Context(), "tcp", addr)
	require.NoError(t, err)
	c.Close()
}

func TestSaveStoresEncryptedAndNeverReturnsSecrets(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)

	d, err := Save(t.Context(), admin(t), "", Input{
		Name: new("generic"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/in"),
		Headers:  &[]HeaderInput{{Name: "Authorization", Value: testHeader}},
		LogTypes: &[]string{"access"},
	})
	require.NoError(t, err)
	assert.Len(t, d.ID, 8)

	row := unittest.AssertExistsAndLoadBean(t, &system_model.Setting{SettingKey: setting.Config().LogShipping.DynKey()})
	assert.NotContains(t, row.SettingValue, testHeader)
	assert.Contains(t, row.SettingValue, "Authorization")

	_, err = Save(t.Context(), admin(t), "", newRelic("https://127.0.0.1:9/nr", "all"))
	require.NoError(t, err)
	row = unittest.AssertExistsAndLoadBean(t, &system_model.Setting{SettingKey: setting.Config().LogShipping.DynKey()})
	assert.NotContains(t, row.SettingValue, testKey)

	list, err := List(t.Context())
	require.NoError(t, err)
	b, err := json.Marshal(list)
	require.NoError(t, err)
	assert.NotContains(t, string(b), testKey)
	assert.NotContains(t, string(b), testHeader)
	assert.Contains(t, string(b), `"has_key":true`)
	assert.Contains(t, string(b), "Authorization")
}

func TestSaveValidationAndNames(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)

	_, err := Save(t.Context(), u, "", newRelic("https://127.0.0.1:9/nr", "access"))
	require.NoError(t, err)

	for name, in := range map[string]Input{
		"duplicate name": newRelic("https://127.0.0.1:9/other", "access"),
		"bad name":       {Name: new("Bad Name"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}},
		"private host":   {Name: new("p"), Type: new("http"), Endpoint: new("https://10.0.0.1/x"), LogTypes: &[]string{"access"}},
		"userinfo":       {Name: new("u"), Type: new("http"), Endpoint: new("https://a:b@127.0.0.1:9/x"), LogTypes: &[]string{"access"}},
		"no key":         {Name: new("k"), Type: new("newrelic"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}},
		"long header":    {Name: new("h"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}, Headers: &[]HeaderInput{{Name: "X-A", Value: strings.Repeat("a", 1025)}}},
		"bad type":       {Name: new("t"), Type: new("splunk"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}},
	} {
		_, err := Save(t.Context(), u, "", in)
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
		assert.NotContains(t, err.Error(), "a:b", name)
	}
	list, err := List(t.Context())
	require.NoError(t, err)
	assert.Len(t, list, 1)

	_, err = Save(t.Context(), u, "zzzzzzzz", Input{})
	require.ErrorIs(t, err, util.ErrNotExist)
}

func TestPatchEndpointChangeNeedsEverySecret(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)

	nr, err := Save(t.Context(), u, "", newRelic("https://127.0.0.1:9/nr", "access"))
	require.NoError(t, err)
	gen, err := Save(t.Context(), u, "", Input{
		Name: new("gen"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/gen"), LogTypes: &[]string{"access"},
		Headers: &[]HeaderInput{{Name: "Authorization", Value: testHeader}, {Name: "X-Team", Value: "team-ops-secret-value"}},
	})
	require.NoError(t, err)

	// a new endpoint without a new key, or without every header value, is refused and changes nothing
	_, err = Save(t.Context(), u, nr.ID, Input{Endpoint: new("https://127.0.0.1:9/elsewhere")})
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = Save(t.Context(), u, gen.ID, Input{Endpoint: new("https://127.0.0.1:9/elsewhere")})
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = Save(t.Context(), u, gen.ID, Input{Endpoint: new("https://127.0.0.1:9/elsewhere"), Headers: &[]HeaderInput{{Name: "Authorization", Value: testHeader}, {Name: "X-Team"}}})
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	cur, _ := get(t.Context(), nr.ID)
	assert.Equal(t, "https://127.0.0.1:9/nr", cur.Endpoint)

	// with all secrets given it works
	_, err = Save(t.Context(), u, nr.ID, Input{Endpoint: new("https://127.0.0.1:9/elsewhere"), Key: new("NRAK-NEW-KEY")})
	require.NoError(t, err)
	_, err = Save(t.Context(), u, gen.ID, Input{Endpoint: new("https://127.0.0.1:9/elsewhere"), Headers: &[]HeaderInput{{Name: "Authorization", Value: "Bearer new-value"}, {Name: "X-Team", Value: "team-sre-secret-value"}}})
	require.NoError(t, err)

	// with the endpoint unchanged the key and the header values stay, also when a header is sent without a value
	_, err = Save(t.Context(), u, nr.ID, Input{Enabled: new(false)})
	require.NoError(t, err)
	_, err = Save(t.Context(), u, gen.ID, Input{Headers: &[]HeaderInput{{Name: "authorization"}}})
	require.NoError(t, err)
	st := setting.Config().LogShipping.Value(t.Context())
	for _, d := range st.Destinations {
		switch d.ID {
		case nr.ID:
			k, err := decrypt(d.KeyEnc)
			require.NoError(t, err)
			assert.Equal(t, "NRAK-NEW-KEY", k)
			assert.False(t, d.Enabled)
		case gen.ID:
			require.Len(t, d.Headers, 1)
			v, err := decrypt(d.Headers[0].ValueEnc)
			require.NoError(t, err)
			assert.Equal(t, "Bearer new-value", v)
		}
	}
}

func TestApplyAttachesAndKeepsWriters(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)

	d, err := Save(t.Context(), u, "", newRelic("https://127.0.0.1:9/nr", "access", "application"))
	require.NoError(t, err)
	name := "ship-" + d.ID
	assert.Contains(t, writersOf("access"), name)
	assert.Contains(t, writersOf("default"), name)
	assert.NotContains(t, writersOf("router"), name)
	w := log.GetManager().GetSharedWriter(name)
	require.NotNil(t, w)

	// an unrelated change elsewhere keeps this destination's writer (and its buffer)
	_, err = Save(t.Context(), u, "", Input{Name: new("other"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/o"), LogTypes: &[]string{"router"}})
	require.NoError(t, err)
	assert.Same(t, w, log.GetManager().GetSharedWriter(name))

	// a changed destination gets a new writer on the new loggers only
	_, err = Save(t.Context(), u, d.ID, Input{LogTypes: &[]string{"router"}})
	require.NoError(t, err)
	assert.NotSame(t, w, log.GetManager().GetSharedWriter(name))
	assert.NotContains(t, writersOf("access"), name)
	assert.Contains(t, writersOf("router"), name)

	// disabled and deleted ones are gone from the loggers and the manager
	_, err = Save(t.Context(), u, d.ID, Input{Enabled: new(false)})
	require.NoError(t, err)
	assert.Nil(t, log.GetManager().GetSharedWriter(name))
	assert.NotContains(t, writersOf("router"), name)
	_, err = Save(t.Context(), u, d.ID, Input{Enabled: new(true)})
	require.NoError(t, err)
	require.NotNil(t, log.GetManager().GetSharedWriter(name))
	require.NoError(t, Remove(t.Context(), u, d.ID))
	assert.Nil(t, log.GetManager().GetSharedWriter(name))
	assert.NotContains(t, writersOf("router"), name)
	require.ErrorIs(t, Remove(t.Context(), u, d.ID), util.ErrNotExist)
}

func TestSaveRejectsDatabaseLogsLoopsAndBadHeaders(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	t.Cleanup(test.MockVariableValue(&setting.AppURL, "https://git.example.org/"))
	t.Cleanup(test.MockVariableValue(&setting.Domain, "ssh.example.org"))
	u := admin(t)
	base := func(f func(in *Input)) Input {
		in := Input{Name: new("x"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}}
		f(&in)
		return in
	}
	hdr := func(name, value string) func(in *Input) {
		return func(in *Input) { in.Headers = &[]HeaderInput{{Name: name, Value: value}} }
	}
	for name, in := range map[string]Input{
		"database log":       base(func(in *Input) { in.LogTypes = &[]string{"database"} }),
		"app url host":       base(func(in *Input) { in.Endpoint = new("https://git.example.org/api") }),
		"app url host case":  base(func(in *Input) { in.Endpoint = new("https://GIT.example.org.:443/api") }),
		"domain":             base(func(in *Input) { in.Endpoint = new("https://ssh.example.org/api") }),
		"header crlf name":   base(hdr("X-A\r\nX-B", "value-123")),
		"header crlf value":  base(hdr("X-A", "value-123\r\nX-B: w")),
		"header short value": base(hdr("X-A", "short")),
		"header nul value":   base(hdr("X-A", "value-123\x00")),
		"header proxy":       base(hdr("Proxy-Authorization", "value-123")),
		"header upgrade":     base(hdr("upgrade", "value-123")),
		"header te":          base(hdr("TE", "value-123")),
		"header host":        base(hdr("host", "value-123")),
		"key short":          {Name: new("k"), Type: new("newrelic"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}, Key: new("short")},
		"key crlf":           {Name: new("k"), Type: new("newrelic"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"}, Key: new("a\nb")},
		"duplicate by case": base(func(in *Input) {
			in.Headers = &[]HeaderInput{{Name: "x-a", Value: "value-001"}, {Name: "X-A", Value: "value-002"}}
		}),
		"too many": base(func(in *Input) {
			h := make([]HeaderInput, 11)
			for i := range h {
				h[i] = HeaderInput{Name: "X-" + strings.Repeat("a", i+1), Value: "value-123"}
			}
			in.Headers = &h
		}),
	} {
		_, err := Save(t.Context(), u, "", in)
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
		assert.NotContains(t, err.Error(), "X-B: w", name)
	}

	// a local agent on another port of the loopback address is fine; the public names are this instance on any port
	_, err := Save(t.Context(), u, "", base(func(in *Input) { in.Endpoint = new("https://git.example.org:8443/api") }))
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	for i, e := range []string{"http://localhost:4318/in", "http://127.0.0.1:4318/in"} {
		_, err := Save(t.Context(), u, "", base(func(in *Input) { in.Name, in.Endpoint = new(fmt.Sprint("agent-", i)), new(e) }))
		require.NoError(t, err, e)
	}
	func() {
		defer test.MockVariableValue(&setting.HTTPAddr, "0.0.0.0")()
		defer test.MockVariableValue(&setting.HTTPPort, "3000")()
		defer test.MockVariableValue(&setting.LocalURL, "http://localhost:3000/")()
		for _, e := range []string{"http://127.0.0.1:3000/in", "http://[::1]:3000/in", "http://[::ffff:127.0.0.1]:3000/in", "http://localhost:3000/in"} {
			_, err := Save(t.Context(), u, "", base(func(in *Input) { in.Endpoint = new(e) }))
			require.ErrorIs(t, err, util.ErrInvalidArgument, e)
		}
	}()

	// names are stored in canonical form
	d, err := Save(t.Context(), u, "", base(hdr("x-team", "team-ops-secret-value")))
	require.NoError(t, err)
	assert.Equal(t, "X-Team", d.Headers[0].Name)
}

func TestEndpointChangeIsComparedAsText(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)
	nr, err := Save(t.Context(), u, "", newRelic("https://127.0.0.1:9/nr", "access"))
	require.NoError(t, err)
	// any other text is a new endpoint: trailing slash, case of the host, an explicit default port, a dot
	for _, e := range []string{"https://127.0.0.1:9/nr/", "https://127.0.0.1:9/NR", "https://127.0.0.1:09/nr", "https://127.0.0.1.:9/nr", "https://127.0.0.1:9/nr?"} {
		_, err := Save(t.Context(), u, nr.ID, Input{Endpoint: &e})
		require.ErrorIs(t, err, util.ErrInvalidArgument, e)
	}
	// the same text is not
	_, err = Save(t.Context(), u, nr.ID, Input{Endpoint: new("https://127.0.0.1:9/nr"), Level: new("warn")})
	require.NoError(t, err)

	// a renamed secret header that keeps the old value is a new secret
	gen, err := Save(t.Context(), u, "", Input{Name: new("gen"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/g"), LogTypes: &[]string{"access"}, Headers: &[]HeaderInput{{Name: "Authorization", Value: testHeader}}})
	require.NoError(t, err)
	_, err = Save(t.Context(), u, gen.ID, Input{Headers: &[]HeaderInput{{Name: "X-Token"}}})
	require.ErrorIs(t, err, util.ErrInvalidArgument)
}

func TestReloadOnlyWhenTheRevisionChanges(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)

	d, err := Save(t.Context(), u, "", newRelic("https://127.0.0.1:9/nr", "access"))
	require.NoError(t, err)
	name := "ship-" + d.ID
	require.NoError(t, Reload(t.Context())) // first call applies
	require.NoError(t, Reload(t.Context()))
	w := log.GetManager().GetSharedWriter(name)
	require.NotNil(t, w)

	// someone else (another pod) changes the setting: only the revision moves, Reload applies it
	st := setting.Config().LogShipping.Value(t.Context())
	st.Destinations[0].Enabled = false
	b, _ := json.Marshal(st)
	require.NoError(t, system_model.SetSettings(t.Context(), map[string]string{setting.Config().LogShipping.DynKey(): string(b)}))
	require.NoError(t, Reload(t.Context()))
	assert.Nil(t, log.GetManager().GetSharedWriter(name))

	// no change of revision: nothing is rebuilt, even if the loggers were touched by hand
	st.Destinations[0].Enabled = true
	require.NoError(t, Apply(t.Context(), st))
	require.NotNil(t, log.GetManager().GetSharedWriter(name))
	require.NoError(t, Apply(t.Context(), setting.LogShippingState{}))
	require.NoError(t, Reload(t.Context()))
	assert.Nil(t, log.GetManager().GetSharedWriter(name), "same revision: Reload must not apply again")
}

func TestTestEventUsesSavedDestinationAndGenericErrors(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)

	var mu sync.Mutex
	status := 200
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.Header.Get("Authorization")+" "+string(b))
		w.WriteHeader(status)
		_, _ = w.Write([]byte("the remote says: " + testKey))
	}))
	defer srv.Close()
	t.Cleanup(test.MockVariableValue(&log.ShipTransport, srv.Client().Transport))
	t.Cleanup(test.MockVariableValue(&testInterval, 0*time.Second))

	d, err := Save(t.Context(), admin(t), "", Input{
		Name: new("gen"), Type: new("http"), Endpoint: new(srv.URL), LogTypes: &[]string{"access"},
		Headers: &[]HeaderInput{{Name: "Authorization", Value: testHeader}},
	})
	require.NoError(t, err)

	res, err := Test(t.Context(), d.ID)
	require.NoError(t, err)
	assert.Equal(t, TestResult{Status: 200}, res)
	require.Len(t, got, 1)
	assert.Contains(t, got[0], testHeader)
	assert.Contains(t, got[0], `"logtype":"test"`)

	// a 4xx and a 5xx give their class; a closed port gives a class too, never the address or the error text
	for code, class := range map[int]string{400: "status 4xx", 503: "status 5xx"} {
		mu.Lock()
		status = code
		mu.Unlock()
		testLast = map[string]time.Time{}
		res, err = Test(t.Context(), d.ID)
		require.NoError(t, err)
		assert.Equal(t, TestResult{Status: code, Error: class}, res)
	}
	_, err = Test(t.Context(), "zzzzzzzz")
	require.ErrorIs(t, err, util.ErrNotExist)

	srv.Close()
	testLast = map[string]time.Time{}
	res, err = Test(t.Context(), d.ID)
	require.NoError(t, err)
	assert.Zero(t, res.Status)
	assert.Contains(t, []string{"connection failed", "timeout"}, res.Error)
}

func TestTestEventIsRateLimited(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	t.Cleanup(test.MockVariableValue(&log.ShipTransport, srv.Client().Transport))

	d, err := Save(t.Context(), admin(t), "", Input{Name: new("gen"), Type: new("http"), Endpoint: new(srv.URL), LogTypes: &[]string{"access"}})
	require.NoError(t, err)
	_, err = Test(t.Context(), d.ID)
	require.NoError(t, err)
	_, err = Test(t.Context(), d.ID)
	require.ErrorIs(t, err, ErrRateLimited)
}

func TestSecretsAreRegisteredForRedaction(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	_, err := Save(t.Context(), admin(t), "", Input{
		Name: new("gen"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/x"), LogTypes: &[]string{"access"},
		Headers: &[]HeaderInput{{Name: "Authorization", Value: testHeader}},
	})
	require.NoError(t, err)
	assert.NotContains(t, log.Redact("sending "+testHeader), testHeader)
	_, err = Save(t.Context(), admin(t), "", newRelic("https://127.0.0.1:9/nr2", "router"))
	require.NoError(t, err)
	assert.NotContains(t, log.Redact("sending "+testKey), testKey)
	b, err := json.Marshal(log.GetManager().DumpLoggers())
	require.NoError(t, err)
	assert.NotContains(t, string(b), testHeader)
	assert.NotContains(t, string(b), testKey)
}

func TestFailedDecryptDisablesOnlyThatDestination(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)
	good, err := Save(t.Context(), u, "", newRelic("https://127.0.0.1:9/good", "access"))
	require.NoError(t, err)

	// the second one is encrypted with another secret key, as after SECRET_KEY changed
	restore := test.MockVariableValue(&setting.SecretKey, "another-secret-key-for-this-test")
	bad, err := Save(t.Context(), u, "", Input{Name: new("bad"), Type: new("newrelic"), Endpoint: new("https://127.0.0.1:9/bad"), Key: new("NRAK-OTHER-KEY"), LogTypes: &[]string{"router"}})
	restore()
	require.NoError(t, err)

	checker, cleanup := test.NewLogChecker(log.DEFAULT, log.ERROR)
	defer cleanup()
	checker.Filter(`destination "bad" is not started`, "NRAK", "can't be decrypted").StopMark("decrypted")
	require.NoError(t, Apply(t.Context(), load(t.Context())))
	filtered, _ := checker.Check(5 * time.Second)
	assert.True(t, filtered[0], "the name is logged")
	assert.False(t, filtered[1], "never a key or ciphertext")

	assert.Contains(t, writersOf("access"), "ship-"+good.ID)
	assert.NotContains(t, writersOf("router"), "ship-"+bad.ID)
	assert.Nil(t, log.GetManager().GetSharedWriter("ship-"+bad.ID))
}

// TestSaveConcurrent saves destinations at once: each save reads and writes the stored list in one transaction, so
// none undoes another.
func TestSaveConcurrent(t *testing.T) {
	reset(t)
	defer reset(t)
	ctx := audit_model.WithCLI(t.Context())
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := range 6 {
		wg.Go(func() {
			_, err := Save(ctx, admin(t), "", Input{
				Name: new(fmt.Sprintf("d%d", i)), Type: new("http"), Endpoint: new("https://logs.example.com/x"), LogTypes: &[]string{"access"},
			})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Len(t, load(ctx).Destinations, 6)
}

func TestApplyAuditWriter(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)
	u := admin(t)

	// "all" alone never streams audit
	d, err := Save(t.Context(), u, "", Input{Name: new("all"), Type: new("http"), Endpoint: new("https://127.0.0.1:9/a"), LogTypes: &[]string{"all"}})
	require.NoError(t, err)
	assert.Empty(t, writersOf("audit"))
	assert.Equal(t, 0, StreamingCount())

	// audit has a writer of its own, so the destination's level (and filters) can't drop audit rows (M3)
	_, err = Save(t.Context(), u, d.ID, Input{LogTypes: &[]string{"all", "audit"}, Level: new("error"), Expression: new("nothing-matches")})
	require.NoError(t, err)
	assert.Equal(t, []string{"ship-" + d.ID + "-audit"}, writersOf("audit"))
	assert.Contains(t, writersOf("access"), "ship-"+d.ID)
	assert.Equal(t, log.TRACE, log.GetManager().GetSharedWriter("ship-"+d.ID+"-audit").GetLevel())
	assert.Equal(t, log.ERROR, log.GetManager().GetSharedWriter("ship-"+d.ID).GetLevel())
	assert.Equal(t, 1, StreamingCount())

	// only audit: no writer on the other loggers
	_, err = Save(t.Context(), u, d.ID, Input{LogTypes: &[]string{"audit"}})
	require.NoError(t, err)
	assert.Nil(t, log.GetManager().GetSharedWriter("ship-"+d.ID))
	assert.NotContains(t, writersOf("access"), "ship-"+d.ID)

	_, err = Save(t.Context(), u, d.ID, Input{Enabled: new(false)})
	require.NoError(t, err)
	assert.Empty(t, writersOf("audit"))
	assert.Equal(t, 0, StreamingCount())
}

// A destination with Level=error and only the audit type still receives an info row, as Loki lines.
func TestAuditRowsIgnoreDestinationLevel(t *testing.T) {
	reset(t)
	defer reset(t)
	allowLoopback(t)

	var mu sync.Mutex
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+string(b))
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer srv.Close()
	t.Cleanup(test.MockVariableValue(&log.ShipTransport, srv.Client().Transport))

	u := admin(t)
	d, err := Save(t.Context(), u, "", Input{
		Name: new("loki"), Type: new("loki"), Endpoint: new(srv.URL + "/loki/api/v1/push"), LogTypes: &[]string{"audit"}, Level: new("error"),
	})
	require.NoError(t, err)
	log.GetManager().GetLogger("audit").LogWithFields(0, log.INFO, map[string]any{"seq": 7, "data": "{}"}, "%s", "auth.signin")
	require.NoError(t, Remove(t.Context(), u, d.ID)) // flushes the writer

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, got, 1)
	assert.True(t, strings.HasPrefix(got[0], "/loki/api/v1/push "), got[0])
	assert.Contains(t, got[0], `"logtype":"audit"`)
	assert.Contains(t, got[0], `\"message\":\"auth.signin\"`)
}
