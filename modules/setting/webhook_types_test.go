// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// AC1: no stored setting means every type is enabled
func TestWebhookTypesState(t *testing.T) {
	var s WebhookTypesState
	assert.True(t, s.Enabled("slack"))
	assert.True(t, s.Enabled("forgejo"))
	s.Disabled = []string{"slack"}
	assert.False(t, s.Enabled("slack"))
	assert.True(t, s.Enabled("gitea"))
}
