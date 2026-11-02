// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ratelimit implements in-memory token buckets for incoming traffic, configured by [rate_limit].
package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"forgejo.org/modules/httplib"
	"forgejo.org/modules/setting"
)

// Traffic classes, matching the [rate_limit.<class>] sections.
const (
	API      = "api"
	APIWrite = "api_write"
	Git      = "git"
	Web      = "web"
	Heavy    = "heavy"
	Auth     = "auth"
	// SSH limits git commands over SSH, per key (authenticated half) and per client IP (anonymous half).
	SSH = "ssh"
	// SSHConnect limits the connections of the built-in SSH server per client IP.
	SSHConnect = "ssh_connect"
)

const maxKeys = 100_000

// auth48 names the store of the per-/48 aggregate of IPv6 clients in the auth class, with aggregateFactor times
// its rate and burst. Its keys are /48s, never "ip:" keys, so it never takes the overflow path of store.get and
// may exceed maxKeys between sweeps.
const (
	auth48          = "auth/ipv6-48"
	aggregateFactor = 10
)

// Result describes the state of the bucket that decided a request. Limit is 0 when no limit applies.
type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	Reset      time.Duration
}

// RetryAfterSeconds is RetryAfter rounded up to whole seconds, at least 1.
func (r Result) RetryAfterSeconds() int {
	return max(1, int(math.Ceil(r.RetryAfter.Seconds())))
}

// LimitedError is returned by authentication methods when the auth class rejects an attempt.
type LimitedError struct {
	Result
}

func (e *LimitedError) Error() string {
	return fmt.Sprintf("rate limit exceeded, retry in %ds", e.RetryAfterSeconds())
}

type bucket struct {
	tokens float64
	last   time.Time
}

// ponytail: one mutex per class store, shard it if lock contention ever shows up in profiles
type store struct {
	mu        sync.Mutex
	rate      float64
	burst     int
	buckets   map[string]*bucket
	lastSweep time.Time
}

var (
	storesMu sync.Mutex
	stores   = map[string]*store{}
	now      = time.Now
)

// getStore returns the store of a class half, or nil when it is not limited.
func getStore(class string, authenticated bool) *store {
	if !setting.RateLimit.Enabled {
		return nil
	}
	c := setting.RateLimit.Classes[class]
	rate, burst, name := c.AuthenticatedRate, c.AuthenticatedBurst, class
	if class == auth48 {
		c = setting.RateLimit.Classes[Auth]
		rate, burst = c.AuthenticatedRate*aggregateFactor, c.AuthenticatedBurst*aggregateFactor
	}
	if !authenticated && class != Auth && class != auth48 {
		rate, burst, name = c.AnonymousRate, c.AnonymousBurst, class+"/anonymous"
	}
	if rate <= 0 || burst <= 0 {
		return nil
	}
	storesMu.Lock()
	defer storesMu.Unlock()
	s, ok := stores[name]
	if !ok {
		s = &store{rate: rate, burst: burst, buckets: map[string]*bucket{}}
		stores[name] = s
	}
	return s
}

// get returns the refilled bucket of key for a client. The caller holds s.mu.
func (s *store) get(key, remoteAddr string, t time.Time) *bucket {
	b, ok := s.buckets[key]
	if !ok {
		// A full bucket is the same as a missing one, so dropping full buckets loses nothing. Sweep once a minute,
		// or once a second while the map is full so that a flood of new keys can't make every request a full scan.
		if t.Sub(s.lastSweep) >= time.Minute || (len(s.buckets) >= maxKeys && t.Sub(s.lastSweep) >= time.Second) {
			s.sweep(t)
		}
		// When the map is still full, new IP keys share a bucket per network of the client, so that whoever filled
		// the map only limits their own network. User, 2FA and task keys always get their own bucket, or a full map
		// would let attackers bypass the per-user limit. Both may exceed the cap: per-user keys are only created
		// after the IP or overflow bucket of the client allowed the request.
		if len(s.buckets) >= maxKeys && strings.HasPrefix(key, "ip:") {
			key = overflowKey(remoteAddr)
			b, ok = s.buckets[key]
		}
		if !ok {
			b = &bucket{tokens: float64(s.burst), last: t}
			s.buckets[key] = b
		}
	}
	b.tokens = min(float64(s.burst), b.tokens+t.Sub(b.last).Seconds()*s.rate)
	b.last = t
	return b
}

func (s *store) sweep(t time.Time) {
	for k, b := range s.buckets {
		if b.tokens+t.Sub(b.last).Seconds()*s.rate >= float64(s.burst) {
			delete(s.buckets, k)
		}
	}
	s.lastSweep = t
}

func (s *store) result(b *bucket, allowed bool) Result {
	r := Result{
		Allowed:   allowed,
		Limit:     s.burst,
		Remaining: int(b.tokens),
		Reset:     time.Duration((float64(s.burst) - b.tokens) / s.rate * float64(time.Second)),
	}
	if !allowed {
		r.RetryAfter = time.Duration((1 - b.tokens) / s.rate * float64(time.Second))
	}
	return r
}

// Check takes one token from the bucket of key in a traffic class, for a client at remoteAddr.
func Check(class, remoteAddr, key string, authenticated bool) Result {
	s := getStore(class, authenticated)
	if s == nil {
		return Result{Allowed: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.get(key, remoteAddr, now())
	if b.tokens < 1 {
		return s.result(b, false)
	}
	b.tokens--
	return s.result(b, true)
}

// CheckSSH takes one token for an SSH git command from the bucket of the client IP and of the key, none when one
// is empty. The key is the public key ID, which serv only sees after the SSH server authenticated that key. An
// empty remoteAddr (no usable client address) skips the IP bucket. Exempt addresses are never limited.
func CheckSSH(remoteAddr string, keyID int64) Result {
	if remoteAddr != "" {
		if IsExempt(remoteAddr) {
			return Result{Allowed: true}
		}
		if r := Check(SSH, remoteAddr, IPKey(remoteAddr), false); !r.Allowed {
			return r
		}
	}
	return Check(SSH, remoteAddr, "key:"+strconv.FormatInt(keyID, 10), true)
}

// CheckSSHConnect takes one token for a connection to the built-in SSH server from the bucket of the client IP.
func CheckSSHConnect(remoteAddr string) Result {
	if IsExempt(remoteAddr) {
		return Result{Allowed: true}
	}
	return Check(SSHConnect, remoteAddr, IPKey(remoteAddr), true)
}

// AuthAttempt is a credential check counted against the auth class.
type AuthAttempt struct {
	Result
	taken []takenToken
}

type takenToken struct {
	s *store
	b *bucket
}

// StartAuth takes one token from the auth buckets of the client IP and of each key before a credential check, so
// that parallel attempts can't overshoot the limit. IPv6 clients also draw on the shared bucket of their /48. It
// takes nothing when a bucket is empty. Call Succeeded after a successful check to give the tokens back: only
// failed attempts count.
func StartAuth(remoteAddr string, keys ...string) *AuthAttempt {
	s := getStore(Auth, true)
	if s == nil || IsExempt(remoteAddr) {
		return &AuthAttempt{Result: Result{Allowed: true}}
	}
	// both stores are fetched before any s.mu is taken, and locked in a fixed order
	var s48 *store
	if ip := parseIP(remoteAddr); ip != nil && ip.To4() == nil {
		s48 = getStore(auth48, true)
	}
	keys = append([]string{IPKey(remoteAddr)}, keys...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s48 != nil {
		s48.mu.Lock()
		defer s48.mu.Unlock()
	}
	t := now()
	taken := make([]takenToken, 0, len(keys)+1)
	add := func(s *store, key string) *AuthAttempt {
		b := s.get(key, remoteAddr, t)
		if b.tokens < 1 {
			return &AuthAttempt{Result: s.result(b, false)}
		}
		if !slices.Contains(taken, takenToken{s, b}) { // keys may share an overflow bucket
			taken = append(taken, takenToken{s, b})
		}
		return nil
	}
	for _, k := range keys {
		if r := add(s, k); r != nil {
			return r
		}
	}
	if s48 != nil {
		if r := add(s48, overflowKey(remoteAddr)); r != nil {
			return r
		}
	}
	for _, tt := range taken {
		tt.b.tokens--
	}
	return &AuthAttempt{Result: Result{Allowed: true}, taken: taken}
}

// Succeeded gives back the tokens taken by StartAuth, each capped at the burst of its own store.
func (a *AuthAttempt) Succeeded() {
	for _, tt := range a.taken {
		tt.s.mu.Lock()
		tt.b.tokens = min(float64(tt.s.burst), tt.b.tokens+1)
		tt.s.mu.Unlock()
	}
}

// Err returns a *LimitedError when the attempt was rejected.
func (a *AuthAttempt) Err() error {
	if a.Allowed {
		return nil
	}
	return &LimitedError{a.Result}
}

func parseIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

// IPKey returns the bucket key of a client address: the IPv4 address, or the /64 of an IPv6 address.
func IPKey(remoteAddr string) string {
	ip := parseIP(remoteAddr)
	if ip == nil {
		return "ip:invalid"
	}
	if ip4 := ip.To4(); ip4 != nil {
		return "ip:" + ip4.String()
	}
	return "ip:" + ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// overflowKey returns the shared bucket key of the IPv4 /24 or IPv6 /48 of a client.
func overflowKey(remoteAddr string) string {
	ip := parseIP(remoteAddr)
	if ip == nil {
		return "overflow:invalid"
	}
	if ip4 := ip.To4(); ip4 != nil {
		return "overflow:" + ip4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return "overflow:" + ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// UserKey returns the auth bucket key of a sign-in name. It is hashed so that its size doesn't depend on the input.
func UserKey(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return "user:" + hex.EncodeToString(sum[:])
}

// UserIDKey returns the auth bucket key of an account that a sign-in name resolved to.
func UserIDKey(uid int64) string {
	return "uid:" + strconv.FormatInt(uid, 10)
}

// TwoFactorKey returns the auth bucket key of the second factor of a user.
func TwoFactorKey(uid int64) string {
	return "2fa:" + strconv.FormatInt(uid, 10)
}

// ClientAddr returns the client address that the limiter counts for a request. When a trusted proxy sent an
// ambiguous client IP (see httplib.WithAmbiguousClientIP), RemoteAddr may be an address the client chose, so all
// such requests get one fixed address that doesn't parse: they share the "ip:invalid" bucket, have no /48 bucket
// and are never exempt.
func ClientAddr(req *http.Request) string {
	if httplib.IsClientIPAmbiguous(req) {
		return "ambiguous"
	}
	return req.RemoteAddr
}

// IsExempt reports whether the client address is in [rate_limit] EXEMPT_CIDRS.
func IsExempt(remoteAddr string) bool {
	ip := parseIP(remoteAddr)
	return ip != nil && setting.RateLimit.ExemptCIDRs.MatchIPAddr(ip)
}

// ResetForTest drops all buckets, so that changed settings apply.
func ResetForTest() {
	storesMu.Lock()
	defer storesMu.Unlock()
	stores = map[string]*store{}
}
