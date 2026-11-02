// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRateLimit(t *testing.T) {
	cfg, err := NewConfigProviderFromData(``)
	require.NoError(t, err)
	loadRateLimitFrom(cfg)
	assert.False(t, RateLimit.Enabled)
	assert.True(t, RateLimit.ExemptCIDRs.IsEmpty())
	assert.False(t, RateLimit.ExemptAdmins)
	assert.Equal(t, RateLimitClass{60, 600, 5, 50}, RateLimit.Classes["api"])
	assert.Equal(t, RateLimitClass{10, 100, 0, 0}, RateLimit.Classes["api_write"])
	assert.Equal(t, RateLimitClass{0.0167, 10, 0, 0}, RateLimit.Classes["auth"])
	assert.Equal(t, RateLimitClass{10, 100, 20, 200}, RateLimit.Classes["ssh"])
	assert.Equal(t, RateLimitClass{5, 100, 0, 0}, RateLimit.Classes["ssh_connect"])
	assert.Equal(t, RateLimitClass{1, 20, 0.2, 30}, RateLimit.Classes["heavy"])
	web, heavy := RateLimit.Classes["web"], RateLimit.Classes["heavy"]
	assert.Less(t, heavy.AuthenticatedRate, web.AuthenticatedRate)
	assert.Less(t, heavy.AuthenticatedBurst, web.AuthenticatedBurst)
	assert.Less(t, heavy.AnonymousRate, web.AnonymousRate)
	assert.Less(t, heavy.AnonymousBurst, web.AnonymousBurst)

	cfg, err = NewConfigProviderFromData(`
[rate_limit]
ENABLED = true
EXEMPT_CIDRS = 10.0.0.0/8, 192.0.2.1
EXEMPT_ADMINS = true
[rate_limit.git]
AUTHENTICATED_RATE = 0.5
ANONYMOUS_BURST = 3
[rate_limit.api_write]
ANONYMOUS_RATE = 99
[rate_limit.auth]
RATE = 2
BURST = 4
[rate_limit.ssh]
ANONYMOUS_RATE = 0
[rate_limit.ssh_connect]
RATE = 1
BURST = 7
[rate_limit.heavy]
AUTHENTICATED_RATE = 0
ANONYMOUS_BURST = 3
`)
	require.NoError(t, err)
	loadRateLimitFrom(cfg)
	assert.True(t, RateLimit.Enabled)
	assert.True(t, RateLimit.ExemptAdmins)
	assert.True(t, RateLimit.ExemptCIDRs.MatchIPAddr(net.ParseIP("10.1.2.3")))
	assert.True(t, RateLimit.ExemptCIDRs.MatchIPAddr(net.ParseIP("192.0.2.1")))
	assert.False(t, RateLimit.ExemptCIDRs.MatchIPAddr(net.ParseIP("192.0.2.2")))
	assert.Equal(t, RateLimitClass{0.5, 100, 2, 3}, RateLimit.Classes["git"])
	assert.Equal(t, RateLimitClass{10, 100, 0, 0}, RateLimit.Classes["api_write"])
	assert.Equal(t, RateLimitClass{2, 4, 0, 0}, RateLimit.Classes["auth"])
	assert.Equal(t, RateLimitClass{10, 100, 0, 200}, RateLimit.Classes["ssh"])
	assert.Equal(t, RateLimitClass{1, 7, 0, 0}, RateLimit.Classes["ssh_connect"])
	assert.Equal(t, RateLimitClass{0, 20, 0.2, 3}, RateLimit.Classes["heavy"])
}
