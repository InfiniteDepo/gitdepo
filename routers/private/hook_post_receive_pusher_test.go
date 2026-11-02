// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package private

import (
	"testing"

	"forgejo.org/modules/private"

	"github.com/stretchr/testify/assert"
)

// The digest tells a pusher "your push": a deploy key pushes under the repository owner's ID and an Actions task
// under the Actions user's, and neither names a person who pushed.
func TestHookPusherID(t *testing.T) {
	assert.EqualValues(t, 5, hookPusherID(&private.HookOptions{UserID: 5}))
	assert.Zero(t, hookPusherID(&private.HookOptions{UserID: 2, DeployKeyKeyID: 7}))
	assert.Zero(t, hookPusherID(&private.HookOptions{UserID: -2, ActionTaskID: 3}))
}
