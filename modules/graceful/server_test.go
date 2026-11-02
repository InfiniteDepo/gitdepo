// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package graceful

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A deadline set from outside caps the one each write moves forward, so a handler can bound its writes to a client
// that stops reading; the zero time lifts it.
func TestWrappedConnWriteCap(t *testing.T) {
	server, client := net.Pipe() // writes block until read
	defer client.Close()
	w := &wrappedConn{Conn: server, perWriteTimeout: time.Minute, perWritePerKbTimeout: time.Minute}
	require.NoError(t, w.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
	start := time.Now()
	_, err := w.Write(make([]byte, 4096))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)

	require.NoError(t, w.SetWriteDeadline(time.Time{}))
	go func() { _, _ = client.Read(make([]byte, 4096)) }()
	_, err = w.Write([]byte("x"))
	require.NoError(t, err, "no cap: the write's own deadline")
}
