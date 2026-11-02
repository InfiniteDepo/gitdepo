// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"testing"
	"time"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcquireOperation(t *testing.T) {
	defer test.MockVariableValue(&setting.Git.MaxConcurrentOperations, 1)()
	defer test.MockVariableValue(&setting.Git.OperationQueueTimeout, 50*time.Millisecond)()

	release, err := AcquireOperation(t.Context())
	require.NoError(t, err)

	_, err = AcquireOperation(t.Context())
	require.ErrorIs(t, err, ErrServerBusy)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = AcquireOperation(ctx)
	require.ErrorIs(t, err, context.Canceled)

	release()
	release, err = AcquireOperation(t.Context())
	require.NoError(t, err)
	release()

	t.Run("no limit", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Git.MaxConcurrentOperations, 0)()
		for range 3 {
			_, err := AcquireOperation(t.Context())
			assert.NoError(t, err)
		}
	})
}
