// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"forgejo.org/modules/hostmatcher"
)

// RateLimitClass holds the token bucket settings of one traffic class. A rate of 0 means no limit.
type RateLimitClass struct {
	AuthenticatedRate  float64
	AuthenticatedBurst int
	AnonymousRate      float64
	AnonymousBurst     int
}

// RateLimit settings
var RateLimit = struct {
	Enabled      bool
	ExemptCIDRs  *hostmatcher.HostMatchList
	ExemptAdmins bool
	Classes      map[string]RateLimitClass
}{}

func loadRateLimitFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("rate_limit")
	RateLimit.Enabled = sec.Key("ENABLED").MustBool(false)
	RateLimit.ExemptCIDRs = hostmatcher.ParseHostMatchList("rate_limit.EXEMPT_CIDRS", sec.Key("EXEMPT_CIDRS").String())
	RateLimit.ExemptAdmins = sec.Key("EXEMPT_ADMINS").MustBool(false)

	defaults := map[string]RateLimitClass{
		"api":       {60, 600, 5, 50},
		"api_write": {10, 100, 0, 0},
		"git":       {10, 100, 2, 20},
		"web":       {20, 200, 5, 50},
		"heavy":     {1, 20, 0.2, 30},
		"auth":      {0.0167, 10, 0, 0},
		// ssh: per key and per client IP for each git command; ssh_connect: per client IP for each connection of the built-in server
		"ssh":         {10, 100, 20, 200},
		"ssh_connect": {5, 100, 0, 0},
	}
	RateLimit.Classes = make(map[string]RateLimitClass, len(defaults))
	for name, d := range defaults {
		sec := rootCfg.Section("rate_limit." + name)
		if name == "auth" || name == "ssh_connect" {
			// these classes are per IP (and per username), there is no authenticated/anonymous split
			RateLimit.Classes[name] = RateLimitClass{
				AuthenticatedRate:  sec.Key("RATE").MustFloat64(d.AuthenticatedRate),
				AuthenticatedBurst: sec.Key("BURST").MustInt(d.AuthenticatedBurst),
			}
			continue
		}
		c := RateLimitClass{
			AuthenticatedRate:  sec.Key("AUTHENTICATED_RATE").MustFloat64(d.AuthenticatedRate),
			AuthenticatedBurst: sec.Key("AUTHENTICATED_BURST").MustInt(d.AuthenticatedBurst),
		}
		if name != "api_write" {
			c.AnonymousRate = sec.Key("ANONYMOUS_RATE").MustFloat64(d.AnonymousRate)
			c.AnonymousBurst = sec.Key("ANONYMOUS_BURST").MustInt(d.AnonymousBurst)
		}
		RateLimit.Classes[name] = c
	}
}
