// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"

	lru "github.com/hashicorp/golang-lru/v2"
)

// WriteErrors counts activity entries that could not be written.
var WriteErrors atomic.Int64

// Written counts the entries this process wrote (and whose transaction committed), per category.
var Written = func() map[string]*atomic.Int64 {
	m := make(map[string]*atomic.Int64, len(Categories))
	for _, c := range Categories {
		m[c] = new(atomic.Int64)
	}
	return m
}()

// RecordActivity records what already happened (a sign-in, a credential use, a refusal) outside any change: a
// failed write is logged and counted, never returned, so it doesn't fail the request. It reports whether the entry
// was written.
func RecordActivity(ctx context.Context, ev Event) bool {
	if err := Record(ctx, ev); err != nil {
		log.Error("audit: unable to record %s: %v", ev.Action, err)
		WriteErrors.Add(1)
		return false
	}
	return true
}

// SeenCap bounds the keys remembered per pod for SeenToday. An evicted key can only repeat an entry.
var SeenCap = 100_000

var seen atomic.Pointer[lru.Cache[string, struct{}]]

func init() {
	ResetActivity()
}

// ResetActivity forgets the seen keys and drops the pending aggregates, for tests.
func ResetActivity() {
	c, err := lru.New[string, struct{}](SeenCap)
	if err != nil {
		panic(err)
	}
	seen.Store(c)
	agg.Lock()
	agg.buckets, agg.overflow = map[string]*aggBucket{}, map[string]*aggBucket{}
	agg.windowStart, agg.firstWrites = 0, 0
	agg.Unlock()
}

func dayKey(key string) string {
	return strconv.FormatInt(int64(timeutil.TimeStampNow())/86400, 10) + "|" + key
}

// SeenToday reports whether key was marked on this pod during the current UTC day.
func SeenToday(key string) bool {
	return seen.Load().Contains(dayKey(key))
}

// MarkSeenToday remembers key for the rest of the current UTC day on this pod.
func MarkSeenToday(key string) {
	seen.Load().Add(dayKey(key), struct{}{})
}

// Seen reports whether key was marked on this pod, whatever the day.
func Seen(key string) bool {
	return seen.Load().Contains("once|" + key)
}

// MarkSeen remembers key on this pod until it is evicted.
func MarkSeen(key string) {
	seen.Load().Add("once|"+key, struct{}{})
}

// IPKey is the actor's client IP for dedupe and aggregation: an IPv6 address cut to its /bits, and an ambiguous IP
// with its candidates, so that conflicting headers can't fold several clients into one key.
func IPKey(a *Actor, bits int) string {
	k := ipPrefix(a.IP, bits)
	if a.IPAmbiguous {
		cs := make([]string, len(a.IPCandidates))
		for i, c := range a.IPCandidates {
			cs[i] = ipPrefix(c, bits)
		}
		slices.Sort(cs)
		k += "|" + strings.Join(cs, ",")
	}
	return k
}

func ipPrefix(ip string, bits int) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr = addr.Unmap(); addr.Is6() {
		p, _ := addr.Prefix(bits)
		return p.String()
	}
	return addr.String()
}

// RecordCredentialUsed records the first use of the request's credential from its client IP (/64 for IPv6) per UTC
// day on this pod. Sessions and reverse proxy sign-ins are not credentials of their own.
func RecordCredentialUsed(ctx context.Context, method string) {
	a := ActorFromContext(ctx)
	if a == nil || a.Type == ActorAnonymous || a.Type == ActorUnknown {
		return
	}
	c := a.Credential
	switch c.Type {
	case "", CredentialSession, CredentialReverseProxy, CredentialSystem, CredentialCLI, CredentialUnknown:
		return
	}
	id := c.ID
	if id == 0 {
		id = c.OwnerID // a password has no ID of its own
	}
	key := "cred|" + c.Type + ":" + strconv.FormatInt(id, 10) + "|" + IPKey(a, 64)
	if SeenToday(key) {
		return
	}
	subject := c.OwnerID
	if subject == 0 {
		subject = a.ID
	}
	if RecordActivity(ctx, Event{
		Action: "auth.credential.used", Result: ResultSuccess, OwnerID: subject, SubjectUserID: subject,
		TargetType: "credential_use", TargetID: c.ID, Data: map[string]any{"method": method},
	}) {
		MarkSeenToday(key)
	}
}
