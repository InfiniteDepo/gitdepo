// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package logshipping turns the instance's log destinations (a dynamic setting) into running log writers.
package logshipping

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/hostmatcher"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/secret"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
)

// MaxDestinations is the most destinations the instance holds.
const MaxDestinations = 20

// ErrRateLimited is returned when a test event was sent to the destination a moment ago.
var ErrRateLimited = errors.New("a test event was sent a moment ago, try again in a few seconds")

var (
	testInterval = 5 * time.Second // per destination, per instance

	mu         sync.Mutex // guards the fields below; never held across a database query
	active     = map[string]running{}
	appliedRev = -1

	testMu   sync.Mutex
	testLast = map[string]time.Time{}
)

// running is a destination's writers: name -> loggers. Audit has a writer of its own (writerName(id)+"-audit"), at
// TRACE and without filters, so a destination's level or expression can never drop an audit row.
type running struct {
	hash    string
	writers map[string][]string
}

func writerName(id string) string { return "ship-" + id }

func auditWriterName(id string) string { return writerName(id) + "-audit" }

// StreamingCount is the number of destinations of this instance that are running with the audit type.
func StreamingCount() (n int) {
	mu.Lock()
	defer mu.Unlock()
	for id, r := range active {
		if _, ok := r.writers[auditWriterName(id)]; ok {
			n++
		}
	}
	return n
}

// hostList is the webhook host policy: the same rule decides where an admin may send logs.
func hostList() *hostmatcher.HostMatchList {
	v := setting.Webhook.AllowedHostList
	if v == "" {
		v = hostmatcher.MatchBuiltinExternal
	}
	return hostmatcher.ParseHostMatchList("webhook.ALLOWED_HOST_LIST", v)
}

// DialContext makes the connections of the shippers; it checks the resolved address, so a name that points to an
// internal address (DNS rebinding) is refused at the time of the connection.
func DialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return hostmatcher.NewDialContext("log_shipping", hostList(), nil, nil)
}

// CheckEndpoint refuses an address literal the host policy doesn't allow. Names are checked when dialled.
func CheckEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return util.NewInvalidArgumentErrorf("invalid endpoint")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !hostList().MatchIPAddr(ip) {
		return util.NewInvalidArgumentErrorf("the endpoint address is not allowed (see ALLOWED_HOST_LIST in the [webhook] section)")
	}
	return nil
}

// checkLoop refuses the instance itself as a destination: shipping its own access log to itself would make every
// delivery log another request, forever. Host and port are compared, so an agent on another port of this machine is
// fine. A proxy, an alias or a DNS name of this machine (other than the configured ones) is not detected.
func checkLoop(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return util.NewInvalidArgumentErrorf("invalid endpoint")
	}
	if setting.IsInstanceHost(u.Hostname(), setting.URLPort(u)) {
		return util.NewInvalidArgumentErrorf("the endpoint is this instance, which would ship its logs to itself")
	}
	return nil
}

func encrypt(v string) (string, error) { return secret.EncryptSecret(setting.SecretKey, v) }
func decrypt(v string) (string, error) { return secret.DecryptSecret(setting.SecretKey, v) }

// option decrypts the secrets of the destination into the options of its writer.
func option(d setting.LogShippingDestination) (log.HTTPShipOption, error) {
	opt := log.HTTPShipOption{Format: d.Type, Endpoint: d.Endpoint, NDJSON: d.NDJSON, DialContext: DialContext()}
	var err error
	if d.KeyEnc != "" {
		if opt.Key, err = decrypt(d.KeyEnc); err != nil {
			return opt, errors.New("the key can't be decrypted")
		}
	}
	if len(d.Headers) > 0 {
		opt.Headers = make(map[string]string, len(d.Headers))
	}
	for _, h := range d.Headers {
		if opt.Headers[h.Name], err = decrypt(h.ValueEnc); err != nil {
			return opt, errors.New("a header value can't be decrypted")
		}
	}
	return opt, nil
}

// validSecret accepts a key or header value of 8 bytes to 1 KiB without CR, LF or NUL. Every one is registered for
// redaction, and a short one would mask itself all over the logs.
func validSecret(v string) bool {
	return len(v) >= 8 && len(v) <= setting.LogShippingMaxHeaderValue && !strings.ContainsAny(v, "\r\n\x00")
}

func hashOf(d setting.LogShippingDestination) string {
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Apply makes the running writers match the state: a new or changed destination gets a new writer on its loggers,
// a changed, disabled or removed one loses its writer (flushed with the usual final timeout), an unchanged one keeps
// its writer and buffer.
func Apply(ctx context.Context, state setting.LogShippingState) error {
	type desired struct {
		d    setting.LogShippingDestination
		mode log.WriterMode
		hash string
	}
	wantAudit := map[string]log.WriterMode{}
	want := map[string]desired{}
	for _, d := range state.Destinations {
		if !d.Enabled {
			continue
		}
		opt, err := option(d)
		if err == nil {
			err = opt.Validate()
		}
		if err != nil {
			log.Error("log shipping: destination %q is not started: %v", d.Name, err)
			continue
		}
		want[d.ID] = desired{d, log.WriterMode{
			BufferLen: max(setting.Log.BufferLen, 1000), Level: log.LevelFromString(d.Level), Format: "json",
			Expression: d.Expression, Exclusion: d.Exclusion, StacktraceLevel: log.NONE, WriterOption: opt,
		}, hashOf(d)}
		if d.StreamsAudit() {
			wantAudit[d.ID] = log.WriterMode{BufferLen: max(setting.Log.BufferLen, 1000), Level: log.TRACE, Format: "json", StacktraceLevel: log.NONE, WriterOption: opt}
		}
	}

	mu.Lock()
	for id, r := range active {
		if w, ok := want[id]; !ok || w.hash != r.hash {
			stop(r)
			delete(active, id)
		}
	}
	for id, w := range want {
		if _, ok := active[id]; ok {
			continue
		}
		r := running{hash: w.hash, writers: map[string][]string{}}
		type spec struct {
			name    string
			mode    log.WriterMode
			loggers []string
		}
		var others []string
		for _, l := range w.d.Loggers() {
			if l != "audit" {
				others = append(others, l)
			}
		}
		specs := []spec{{writerName(id), w.mode, others}}
		if m, ok := wantAudit[id]; ok {
			specs = append(specs, spec{auditWriterName(id), m, []string{"audit"}})
		}
		for _, sp := range specs {
			if len(sp.loggers) == 0 {
				continue
			}
			wr, err := log.GetManager().NewSharedWriter(sp.name, "http", sp.mode)
			if err != nil {
				log.Error("log shipping: destination %q is not started: %v", w.d.Name, err)
				continue
			}
			for _, l := range sp.loggers {
				log.GetManager().GetLogger(l).AddWriters(wr)
			}
			r.writers[sp.name] = sp.loggers
		}
		active[id] = r
	}
	mu.Unlock()
	return nil
}

func stop(r running) {
	for name, loggers := range r.writers {
		for _, l := range loggers {
			_ = log.GetManager().GetLogger(l).RemoveWriter(name)
		}
		log.GetManager().RemoveSharedWriter(name)
		log.ForgetShipping(name)
	}
}

// Reload applies the stored destinations when the settings revision differs from the one applied last. It runs
// from cron on every pod; the revision is read before the lock is taken.
func Reload(ctx context.Context) error {
	rev := system_model.GetRevision(ctx)
	mu.Lock()
	same := rev == appliedRev
	mu.Unlock()
	if same {
		return nil
	}
	if err := Apply(ctx, load(ctx)); err != nil {
		return err
	}
	mu.Lock()
	appliedRev = rev
	mu.Unlock()
	return nil
}

// load reads the stored state past the cache.
func load(ctx context.Context) setting.LogShippingState {
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return setting.Config().LogShipping.Value(ctx)
}

// HeaderInput is a custom header; an empty Value on an existing header keeps the stored value.
type HeaderInput struct{ Name, Value string }

// Input holds the fields to set; nil fields are kept on an edit and defaulted on a create.
type Input struct {
	Name, Type, Endpoint, Key, Level, Expression, Exclusion *string
	Headers                                                 *[]HeaderInput // the complete list: a header left out is removed
	LogTypes                                                *[]string
	NDJSON, Enabled                                         *bool
}

// Save creates (id == "") or edits a destination and applies it. It reads the stored list with its row locked,
// changes one destination and writes the list back in one transaction, so two saves at once can't undo each other.
func Save(ctx context.Context, doer *user_model.User, id string, in Input) (d setting.LogShippingDestination, err error) {
	var state setting.LogShippingState
	var changed []string
	if err = db.WithTx(ctx, func(ctx context.Context) error {
		changed, err = save(ctx, &state, &d, id, in)
		return err
	}); err != nil {
		return d, err
	}
	if err := apply(ctx, state); err != nil {
		return d, err
	}
	action := "edited"
	if id == "" {
		action = "created"
	}
	warnChange(doer, action, d, changed)
	return d, nil
}

func save(ctx context.Context, state *setting.LogShippingState, out *setting.LogShippingDestination, id string, in Input) (changed []string, err error) {
	stored, err := lockedState(ctx)
	if err != nil {
		return nil, err
	}
	dests := stored.Destinations
	var d setting.LogShippingDestination
	idx := slices.IndexFunc(dests, func(x setting.LogShippingDestination) bool { return x.ID == id })
	if id == "" {
		if len(dests) >= MaxDestinations {
			return nil, util.NewInvalidArgumentErrorf("at most %d destinations", MaxDestinations)
		}
		var b [4]byte
		_, _ = rand.Read(b[:])
		d = setting.LogShippingDestination{ID: hex.EncodeToString(b[:]), Enabled: true, Level: "info"}
		dests = append(dests, d)
		idx = len(dests) - 1
	} else if idx < 0 {
		return nil, util.ErrNotExist
	}
	d = dests[idx]
	d.Headers = slices.Clone(d.Headers)
	old := d

	set := func(field string, dst, v *string) {
		if v != nil && *v != *dst {
			*dst = *v
			changed = append(changed, field)
		}
	}
	if id == "" {
		set("type", &d.Type, in.Type)
	}
	set("name", &d.Name, in.Name)
	set("endpoint", &d.Endpoint, in.Endpoint)
	set("level", &d.Level, in.Level)
	set("expression", &d.Expression, in.Expression)
	set("exclusion", &d.Exclusion, in.Exclusion)
	if in.NDJSON != nil && *in.NDJSON != d.NDJSON {
		d.NDJSON = *in.NDJSON
		changed = append(changed, "ndjson")
	}
	if in.Enabled != nil && *in.Enabled != d.Enabled {
		d.Enabled = *in.Enabled
		changed = append(changed, "enabled")
	}
	if in.LogTypes != nil {
		d.LogTypes = slices.Clone(*in.LogTypes)
		changed = append(changed, "log_types")
	}

	// a key or header value must not be sent to an address the admin didn't give it to: a new endpoint needs them all again
	endpointChanged := id != "" && d.Endpoint != old.Endpoint
	if in.Key != nil && *in.Key != "" {
		if !validSecret(*in.Key) {
			return nil, util.NewInvalidArgumentErrorf("the key must be 8 to 1024 characters without control characters")
		}
		if d.KeyEnc, err = encrypt(*in.Key); err != nil {
			return nil, err
		}
		changed = append(changed, "key")
	} else if endpointChanged && d.Type == setting.LogShippingNewRelic {
		return nil, util.NewInvalidArgumentErrorf("a new endpoint needs the key again")
	}
	if in.Headers != nil {
		headers := make([]setting.LogShippingHeader, 0, len(*in.Headers))
		for _, h := range *in.Headers {
			if h.Value != "" && !validSecret(h.Value) {
				return nil, util.NewInvalidArgumentErrorf("a header value must be 8 to 1024 characters without control characters")
			}
			h.Name = http.CanonicalHeaderKey(h.Name)
			var enc string
			if h.Value != "" {
				if enc, err = encrypt(h.Value); err != nil {
					return nil, err
				}
			} else if j := slices.IndexFunc(old.Headers, func(o setting.LogShippingHeader) bool { return strings.EqualFold(o.Name, h.Name) }); j >= 0 && !endpointChanged {
				enc = old.Headers[j].ValueEnc
			} else {
				return nil, util.NewInvalidArgumentErrorf("the header %q needs a value", h.Name)
			}
			headers = append(headers, setting.LogShippingHeader{Name: h.Name, ValueEnc: enc})
		}
		d.Headers = headers
		changed = append(changed, "headers")
	} else if endpointChanged && len(d.Headers) > 0 {
		return nil, util.NewInvalidArgumentErrorf("a new endpoint needs the header values again")
	}

	if err := d.Validate(); err != nil {
		return nil, util.NewInvalidArgumentErrorf("%v", err)
	}
	if err := CheckEndpoint(d.Endpoint); err != nil {
		return nil, err
	}
	if err := checkLoop(d.Endpoint); err != nil {
		return nil, err
	}
	for i, o := range dests {
		if i != idx && o.Name == d.Name {
			return nil, util.NewInvalidArgumentErrorf("the name is taken")
		}
	}
	dests[idx] = d
	*out, *state = d, setting.LogShippingState{Destinations: dests}
	if err := write(ctx, *state); err != nil {
		return nil, err
	}
	if id == "" {
		return changed, recordDestination(ctx, "admin.log_shipping.created", d, nil)
	}
	if data := destinationChanges(old, d); data != nil {
		return changed, recordDestination(ctx, "admin.log_shipping.updated", d, data)
	}
	return changed, nil
}

// Remove deletes a destination and stops its writer.
func Remove(ctx context.Context, doer *user_model.User, id string) error {
	var state setting.LogShippingState
	var d setting.LogShippingDestination
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if state, err = lockedState(ctx); err != nil {
			return err
		}
		idx := slices.IndexFunc(state.Destinations, func(x setting.LogShippingDestination) bool { return x.ID == id })
		if idx < 0 {
			return util.ErrNotExist
		}
		d = state.Destinations[idx]
		state.Destinations = slices.Delete(state.Destinations, idx, idx+1)
		if err := write(ctx, state); err != nil {
			return err
		}
		return recordDestination(ctx, "admin.log_shipping.deleted", d, nil)
	}); err != nil {
		return err
	}
	if err := apply(ctx, state); err != nil {
		return err
	}
	testMu.Lock()
	delete(testLast, id)
	testMu.Unlock()
	warnChange(doer, "deleted", d, nil)
	return nil
}

// lockedState reads the stored destinations and locks their row until the transaction ends.
func lockedState(ctx context.Context) (state setting.LogShippingState, err error) {
	v, has, err := system_model.GetSettingForUpdate(ctx, setting.Config().LogShipping.DynKey())
	if err != nil || !has || v == "" {
		return state, err
	}
	return state, json.Unmarshal([]byte(v), &state)
}

func write(ctx context.Context, state setting.LogShippingState) error {
	v, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return system_model.SetSettings(ctx, map[string]string{setting.Config().LogShipping.DynKey(): string(v)})
}

// apply starts using state once it is stored.
func apply(ctx context.Context, state setting.LogShippingState) error {
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return Apply(ctx, state)
}

// warnChange records who changed what; never a key, a header value or the endpoint's query.
func warnChange(doer *user_model.User, action string, d setting.LogShippingDestination, fields []string) {
	who := "-"
	if doer != nil {
		who = doer.Name
	}
	log.Warn("log shipping: %s %s destination %q (%s, id %s), changed: %s", who, action, d.Name, d.Type, d.ID, strings.Join(fields, ","))
}

func get(ctx context.Context, id string) (setting.LogShippingDestination, error) {
	for _, d := range load(ctx).Destinations {
		if d.ID == id {
			return d, nil
		}
	}
	return setting.LogShippingDestination{}, util.ErrNotExist
}

// Header is a custom header as shown: its name, and that a value is stored.
type Header struct {
	Name     string `json:"name"`
	HasValue bool   `json:"has_value"`
}

// Status is what this instance's writer of the destination did so far.
type Status struct {
	Sent        uint64     `json:"sent"`
	Dropped     uint64     `json:"dropped"`
	Errors      uint64     `json:"errors"`
	LastSuccess *time.Time `json:"last_success"`
	LastError   string     `json:"last_error"`
}

// Destination is a destination as shown: no key and no header value.
type Destination struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Endpoint   string   `json:"endpoint"`
	HasKey     bool     `json:"has_key"`
	Headers    []Header `json:"headers"`
	NDJSON     bool     `json:"ndjson"`
	Enabled    bool     `json:"enabled"`
	LogTypes   []string `json:"log_types"`
	Level      string   `json:"level"`
	Expression string   `json:"expression"`
	Exclusion  string   `json:"exclusion"`
	Status     Status   `json:"status"`
}

// View turns a stored destination into its public form with the status of this instance.
func View(d setting.LogShippingDestination) Destination {
	v := Destination{
		ID: d.ID, Name: d.Name, Type: d.Type, Endpoint: d.Endpoint, HasKey: d.KeyEnc != "", Headers: []Header{},
		NDJSON: d.NDJSON, Enabled: d.Enabled, LogTypes: slices.Clone(d.LogTypes), Level: d.Level,
		Expression: d.Expression, Exclusion: d.Exclusion,
	}
	for _, h := range d.Headers {
		v.Headers = append(v.Headers, Header{Name: h.Name, HasValue: h.ValueEnc != ""})
	}
	for _, st := range log.ShippingStatsSnapshot() {
		if st.Writer == writerName(d.ID) || st.Writer == auditWriterName(d.ID) {
			v.Status.Sent, v.Status.Dropped, v.Status.Errors = v.Status.Sent+st.Sent, v.Status.Dropped+st.Dropped, v.Status.Errors+st.Errors
		}
	}
	t, e := log.ShippingStatus(writerName(d.ID))
	if !t.IsZero() {
		v.Status.LastSuccess = &t
	}
	v.Status.LastError = e
	return v
}

// List returns the destinations as shown.
func List(ctx context.Context) ([]Destination, error) {
	state := load(ctx)
	out := make([]Destination, 0, len(state.Destinations))
	for _, d := range state.Destinations {
		out = append(out, View(d))
	}
	return out, nil
}

// Get returns one destination as shown.
func Get(ctx context.Context, id string) (Destination, error) {
	d, err := get(ctx, id)
	if err != nil {
		return Destination{}, err
	}
	return View(d), nil
}

// TestResult is the outcome of a test event: the status code (0 if the destination wasn't reached) and a class of
// failure ("status 4xx", "status 5xx", "connection failed", "timeout"), never what the network or the remote said.
type TestResult struct {
	Status int    `json:"status"`
	Error  string `json:"error"`
}

// Test sends one "test" event to a saved destination, with the same options and dial check as its writer.
func Test(ctx context.Context, id string) (TestResult, error) {
	d, err := get(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	testMu.Lock()
	if time.Since(testLast[id]) < testInterval {
		testMu.Unlock()
		return TestResult{}, ErrRateLimited
	}
	testLast[id] = time.Now()
	testMu.Unlock()

	opt, err := option(d)
	if err != nil {
		return TestResult{Error: "invalid configuration"}, nil
	}
	event, _ := json.Marshal(map[string]any{
		"timestamp": time.Now().UnixMilli(), "message": "gitdepo log shipping test event", "level": "INFO",
		"logtype": "test", "logger": "test", "service": log.ServiceName,
	})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	code, err := log.ProbeHTTP(ctx, writerName(id), opt, event)
	switch {
	case err != nil:
		return TestResult{Error: err.Error()}, nil // a class only: ProbeHTTP drops the text of the network error
	case code/100 != 2:
		return TestResult{Status: code, Error: fmt.Sprintf("status %dxx", code/100)}, nil
	}
	return TestResult{Status: code}, nil
}
