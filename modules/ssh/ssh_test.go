// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package ssh

import (
	"context"
	"io"
	"net"
	"os/exec"
	"slices"
	"testing"
	"time"

	"forgejo.org/modules/hostmatcher"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/assert"
)

type badAddr struct{}

func (badAddr) Network() string { return "tcp" }
func (badAddr) String() string  { return "garbage" }

// AC7: the built-in server always sets SSH_CONNECTION from the (PROXY protocol) client address, after the inherited
// environment, so a value inherited from the server's own environment never wins
func TestServEnv(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.1.2.3 1 10.0.0.1 22")
	remote := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 51234}
	local := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

	cmd := exec.Command("true")
	cmd.Env = servEnv("git-upload-pack 'user2/repo1.git'", "version=2", remote, local)
	env := cmd.Environ()
	assert.Contains(t, env, "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")
	assert.NotContains(t, env, "SSH_CONNECTION=10.1.2.3 1 10.0.0.1 22")
	assert.Contains(t, env, "SSH_ORIGINAL_COMMAND=git-upload-pack 'user2/repo1.git'")
	assert.Contains(t, env, "GIT_PROTOCOL=version=2")

	cmd.Env = servEnv("", "", badAddr{}, local)
	env = cmd.Environ()
	assert.True(t, slices.Contains(env, "SSH_CONNECTION="), env)
	assert.NotContains(t, env, "SSH_CONNECTION=10.1.2.3 1 10.0.0.1 22")
}

func sshLimits(t *testing.T, classes map[string]setting.RateLimitClass) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.Enabled, true))
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.Classes, classes))
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.ExemptCIDRs, hostmatcher.ParseHostMatchList("", "192.0.2.0/24")))
	ratelimit.ResetForTest()
	t.Cleanup(ratelimit.ResetForTest)
}

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

// connection returns the server side of a pipe that claims to come from ip, and its client side
func connection(ip string) (server addrConn, client net.Conn) {
	s, c := net.Pipe()
	return addrConn{s, &net.TCPAddr{IP: net.ParseIP(ip), Port: 4000}}, c
}

// AC3: repeated connects from one IP are closed with a message, other IPs and exempt ones are not affected
func TestConnRateLimit(t *testing.T) {
	sshLimits(t, map[string]setting.RateLimitClass{ratelimit.SSHConnect: {AuthenticatedRate: 0.0001, AuthenticatedBurst: 2}})
	for range 2 {
		server, client := connection("198.51.100.1")
		assert.Equal(t, net.Conn(server), connRateLimit(nil, server))
		client.Close()
	}

	server, client := connection("198.51.100.1")
	defer client.Close()
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(client)
		done <- b
	}()
	assert.Nil(t, connRateLimit(nil, server))
	server.Close()
	assert.Contains(t, string(<-done), "rate limit exceeded, retry in")

	// other IPs have their own budget of 2
	for _, ip := range []string{"198.51.100.2", "2001:db8::1"} {
		for i := range 3 {
			server, client := connection(ip)
			go io.Copy(io.Discard, client)
			assert.Equal(t, i < 2, connRateLimit(nil, server) != nil, ip)
			client.Close()
		}
	}
	// exempt IPs are never limited
	for range 5 {
		server, client := connection("192.0.2.5")
		assert.NotNil(t, connRateLimit(nil, server))
		client.Close()
	}
}

// stubContext keeps just the connection values that the authentication counting uses
type stubContext struct {
	ssh.Context
	values map[any]any
	addr   net.Addr
}

func (c *stubContext) Value(k any) any      { return c.values[k] }
func (c *stubContext) SetValue(k, v any)    { c.values[k] = v }
func (c *stubContext) RemoteAddr() net.Addr { return c.addr }

func newStubContext(ip string) *stubContext {
	return &stubContext{values: map[any]any{}, addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 4000}}
}

// AC3: a connection costs one auth token however many wrong keys it offers; an accepted public key (which is no
// proof, the signature is checked later) refunds nothing, only refundAuth after the session started does, once
func TestCountAuthFailures(t *testing.T) {
	sshLimits(t, map[string]setting.RateLimitClass{ratelimit.Auth: {AuthenticatedRate: 0.0001, AuthenticatedBurst: 2}})
	reject := func() bool { return false }
	accept := func() bool { return true }

	// ten wrong keys on one connection: one token
	c1 := newStubContext("198.51.100.1")
	for range 10 {
		assert.False(t, countAuthFailures(c1, reject))
	}
	// a second connection takes the second token, the third is refused even with a valid key
	assert.False(t, countAuthFailures(newStubContext("198.51.100.1"), reject))
	assert.False(t, countAuthFailures(newStubContext("198.51.100.1"), accept))

	// unknown key, then a victim's public key whose signature then fails: no refund
	c2 := newStubContext("198.51.100.2")
	assert.False(t, countAuthFailures(c2, reject))
	assert.True(t, countAuthFailures(c2, accept))
	assert.True(t, countAuthFailures(c2, accept)) // the signed request
	refundAuth(newStubContext("198.51.100.2"))    // other connections' contexts hold nothing
	assert.False(t, countAuthFailures(newStubContext("198.51.100.2"), reject))
	assert.False(t, countAuthFailures(newStubContext("198.51.100.2"), accept), "both tokens are spent")

	// an authenticated connection (its session started) gets its token back exactly once
	c3 := newStubContext("198.51.100.3")
	assert.True(t, countAuthFailures(c3, accept))
	assert.True(t, countAuthFailures(c3, accept))
	refundAuth(c3)
	refundAuth(c3)
	for range 2 {
		assert.True(t, countAuthFailures(newStubContext("198.51.100.3"), accept))
	}
	assert.False(t, countAuthFailures(newStubContext("198.51.100.3"), accept), "burst 2, refunded once")

	// exempt IPs are never limited
	for range 5 {
		assert.True(t, countAuthFailures(newStubContext("192.0.2.1"), accept))
	}
}

// drainRefusals empties the queue of refused connections and returns what it held.
func drainRefusals() (got []refusal) {
	for {
		select {
		case r := <-refusals:
			got = append(got, r)
		default:
			return got
		}
	}
}

// C2: a refused connection is queued for the audit log, never recorded by the code that closes it
func TestConnRefusalsQueued(t *testing.T) {
	sshLimits(t, map[string]setting.RateLimitClass{
		ratelimit.SSHConnect: {AuthenticatedRate: 0.0001, AuthenticatedBurst: 1},
		ratelimit.Auth:       {AuthenticatedRate: 0.0001, AuthenticatedBurst: 1},
	})
	drainRefusals()
	t.Cleanup(func() { drainRefusals() })

	for range 2 {
		server, client := connection("198.51.100.1")
		go io.Copy(io.Discard, client)
		connRateLimit(nil, server)
		client.Close()
	}
	assert.Equal(t, []refusal{{ratelimit.SSHConnect, "198.51.100.1:4000"}}, drainRefusals())

	accept := func() bool { return true }
	assert.True(t, countAuthFailures(newStubContext("198.51.100.2"), accept))
	assert.False(t, countAuthFailures(newStubContext("198.51.100.2"), accept))
	assert.Equal(t, []refusal{{ratelimit.Auth, "198.51.100.2:4000"}}, drainRefusals())
}

// C2: with nobody reading, a flood of refusals never blocks the caller
func TestQueueRefusalNeverBlocks(t *testing.T) {
	drainRefusals()
	t.Cleanup(func() { drainRefusals() })
	done := make(chan struct{})
	go func() {
		for range 10 * cap(refusals) {
			queueRefusal(ratelimit.SSHConnect, "198.51.100.1:4000")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queueRefusal blocked")
	}
	assert.Len(t, drainRefusals(), cap(refusals))
}

// C2: the worker hands queued refusals to the recorder until it is stopped
func TestRecordRefusals(t *testing.T) {
	drainRefusals()
	got := make(chan refusal, 1)
	t.Cleanup(test.MockVariableValue(&recordRefusal, func(_ context.Context, class, addr string) { got <- refusal{class, addr} }))
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { recordRefusals(ctx); close(stopped) }()

	queueRefusal(ratelimit.Auth, "198.51.100.3:4000")
	assert.Equal(t, refusal{ratelimit.Auth, "198.51.100.3:4000"}, <-got)
	cancel()
	<-stopped
}
