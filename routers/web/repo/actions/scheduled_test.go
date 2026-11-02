// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/modules/translation"

	"github.com/stretchr/testify/assert"
)

func TestScheduledReasonText(t *testing.T) {
	translation.InitLocales(t.Context())
	locale := translation.NewLocale("en-US")
	unknown := scheduledReasonText(locale, "no-such-code")
	assert.NotEmpty(t, unknown)
	assert.NotContains(t, unknown, "actions.scheduled")
	assert.Equal(t, unknown, scheduledReasonText(locale, ""))
	seen := map[string]string{}
	for _, code := range actions_model.ScheduledDispatchCancelReasons {
		text := scheduledReasonText(locale, code)
		assert.NotContains(t, text, "actions.scheduled", code)
		assert.NotContains(t, text, code, code) // never the stored code
		if code != "internal_error" {
			assert.NotEqual(t, unknown, text, code)
		}
		assert.NotContains(t, seen, text, code)
		seen[text] = code
	}
}
