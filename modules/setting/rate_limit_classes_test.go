// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting_test

import (
	"testing"

	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A class without a default or a [rate_limit.<class>] section would be silently unlimited.
func TestRateLimitClassesHaveDefaultsAndSections(t *testing.T) {
	for _, class := range []string{ratelimit.API, ratelimit.APIWrite, ratelimit.Git, ratelimit.Web, ratelimit.Heavy, ratelimit.Auth} {
		key := "AUTHENTICATED_BURST"
		if class == ratelimit.Auth {
			key = "BURST"
		}
		cfg, err := setting.NewConfigProviderFromData("[rate_limit." + class + "]\n" + key + " = 7777\n")
		require.NoError(t, err)
		setting.LoadRateLimitFrom(cfg)
		assert.Equal(t, 7777, setting.RateLimit.Classes[class].AuthenticatedBurst, class)

		cfg, err = setting.NewConfigProviderFromData("")
		require.NoError(t, err)
		setting.LoadRateLimitFrom(cfg)
		assert.NotZero(t, setting.RateLimit.Classes[class].AuthenticatedRate, class)
		assert.NotZero(t, setting.RateLimit.Classes[class].AuthenticatedBurst, class)
	}
}
