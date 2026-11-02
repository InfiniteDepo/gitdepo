// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// impostor offers the public key of someone else and signs with its own key, like a client that only knows the
// public key of a victim
type impostor struct {
	gossh.Signer
	victim gossh.PublicKey
}

func (i impostor) PublicKey() gossh.PublicKey { return i.victim }

// serveLoopback runs the real connection callback, the real counting wrapper and the real sessionHandler (with
// /bin/true as `forgejo serv`) on a loopback listener, with the database lookup of the key replaced by known
func serveLoopback(t *testing.T, known gossh.PublicKey) string {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.AppPath, "/bin/true"))
	srv := &ssh.Server{
		ConnCallback: connRateLimit,
		Handler:      sessionHandler,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			return countAuthFailures(ctx, func() bool { return ssh.KeysEqual(key, known) })
		},
	}
	srv.AddHostKey(newSigner(t))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

func dial(addr string, signers ...gossh.Signer) (*gossh.Client, error) {
	return gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "git",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signers...)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server
	})
}

// run authenticates and runs a command, the point where the session handler refunds the auth token
func run(t *testing.T, addr string, signers ...gossh.Signer) error {
	t.Helper()
	c, err := dial(addr, signers...)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	require.NoError(t, err)
	defer s.Close()
	return s.Run("git-upload-pack 'user2/repo1.git'")
}

// AC3 over a real handshake: only a connection whose signature was verified gets its auth token back, once
func TestLoopbackAuthRefund(t *testing.T) {
	sshLimits(t, map[string]setting.RateLimitClass{ratelimit.Auth: {AuthenticatedRate: 0.0001, AuthenticatedBurst: 2}})
	valid, unknown := newSigner(t), newSigner(t)
	addr := serveLoopback(t, valid.PublicKey())
	attack := impostor{unknown, valid.PublicKey()} // offers the victim's public key without its private key

	// an unknown key and a known public key without its private key: the handshake fails and the token stays spent
	_, err := dial(addr, newSigner(t), attack)
	require.Error(t, err)
	// the valid key works, takes a token and gets it back when its session starts
	require.NoError(t, run(t, addr, valid))
	require.NoError(t, run(t, addr, valid))
	// a second attack spends the second token: with a double refund above there would be one left
	_, err = dial(addr, newSigner(t), attack)
	require.Error(t, err)
	assert.Error(t, run(t, addr, valid), "both tokens are spent, the valid key is refused too")
}

func TestLoopbackConnectLimit(t *testing.T) {
	sshLimits(t, map[string]setting.RateLimitClass{ratelimit.SSHConnect: {AuthenticatedRate: 0.0001, AuthenticatedBurst: 1}})
	valid := newSigner(t)
	addr := serveLoopback(t, valid.PublicKey())
	require.NoError(t, run(t, addr, valid))
	_, err := dial(addr, valid)
	assert.Error(t, err)
}
