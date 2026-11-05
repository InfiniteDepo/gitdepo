// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package approvers

import (
	"context"
	"testing"

	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A failed load leaves the repository unloaded, so the next Load computes it instead of reporting nobody can write.
func TestWritersLoadFailureIsNotRemembered(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	w := NewWriters()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	require.Error(t, w.Load(cancelled, 1))
	assert.False(t, w.Can(1, 2))

	require.NoError(t, w.Load(t.Context(), 1))
	assert.True(t, w.Can(1, 2), "user 2 owns repository 1")
	assert.True(t, w.WouldWrite(1, 2))
	assert.False(t, w.TwoFactorBlocked(1, 2))
}
