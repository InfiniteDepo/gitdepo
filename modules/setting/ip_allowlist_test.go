// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"context"
	"net/netip"
	"testing"

	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC6: matching for IPv4, IPv6 and IPv4-mapped IPv6
func TestIPAllowlistAllows(t *testing.T) {
	s := IPAllowlistState{Entries: []IPAllowlistEntry{
		{CIDR: netip.MustParsePrefix("10.0.0.0/8")},
		{CIDR: netip.MustParsePrefix("2001:db8::/32")},
	}}
	for ip, allowed := range map[string]bool{
		"10.1.2.3":           true,
		"11.0.0.1":           false,
		"::ffff:10.0.0.1":    true,
		"::ffff:11.0.0.1":    false,
		"2001:db8::1":        true,
		"2001:db9::1":        false,
		"fe80::1%eth0":       false,
		"::ffff:192.168.0.1": false,
	} {
		assert.Equal(t, allowed, s.Allows(netip.MustParseAddr(ip)), ip)
	}
	assert.False(t, s.Allows(netip.Addr{}))

	for remote, want := range map[string]string{
		"10.1.2.3:1234":        "10.1.2.3",
		"[2001:db8::1]:22":     "2001:db8::1",
		"[::ffff:10.0.0.1]:22": "::ffff:10.0.0.1",
		"test-mock:12345":      "invalid IP",
		"10.1.2.3":             "invalid IP",
		"":                     "invalid IP",
	} {
		assert.Equal(t, want, IPFromRemoteAddr(remote).String(), remote)
	}
}

// AC2: an empty list or a disabled setting enforces nothing
func TestIPAllowlistEnforced(t *testing.T) {
	entry := []IPAllowlistEntry{{CIDR: netip.MustParsePrefix("10.0.0.0/8")}}
	s := IPAllowlistState{Enabled: true, Web: true, Git: true, Entries: entry}
	assert.True(t, s.Enforced(IPAllowlistSurfaceWeb))
	assert.True(t, s.Enforced(IPAllowlistSurfaceGit))
	assert.False(t, s.Enforced(IPAllowlistSurfaceAPI))
	assert.False(t, s.Enforced(IPAllowlistSurfaceSSH))
	assert.False(t, s.Enforced(IPAllowlistSurfacePackages))
	assert.True(t, s.WouldBlock(netip.MustParseAddr("11.0.0.1")))
	assert.False(t, s.WouldBlock(netip.MustParseAddr("10.0.0.1")))

	s.Entries = nil
	assert.False(t, s.Enforced(IPAllowlistSurfaceWeb))
	assert.False(t, s.WouldBlock(netip.MustParseAddr("11.0.0.1")))
	s.Entries, s.Enabled = entry, false
	assert.False(t, s.Enforced(IPAllowlistSurfaceWeb))
}

type ipAllowlistGetter struct{ v string }

func (g *ipAllowlistGetter) GetValue(_ context.Context, key string) (string, bool) {
	return g.v, key == "ip_allowlist.state" && g.v != ""
}
func (g *ipAllowlistGetter) GetRevision(context.Context) int { return len(g.v) + 1 }
func (g *ipAllowlistGetter) InvalidateCache()                {}

// AC1, AC9: admins are exempt by default, and [ip_allowlist] ENABLED = false wins over the database
func TestGetIPAllowlist(t *testing.T) {
	g := &ipAllowlistGetter{}
	config.SetDynGetter(g)
	defer config.SetDynGetter(nil)
	old := IPAllowlist
	defer func() { IPAllowlist = old }()
	IPAllowlist.Enabled = optional.None[bool]()

	assert.True(t, GetIPAllowlist(t.Context()).ExemptAdmins)

	g.v = `{"enabled":true,"web":true,"exempt_admins":false,"entries":[{"cidr":"10.0.0.0/8","description":"corporate"}]}`
	s := GetIPAllowlist(t.Context())
	assert.True(t, s.Enforced(IPAllowlistSurfaceWeb))
	assert.False(t, s.ExemptAdmins)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), s.Entries[0].CIDR)

	IPAllowlist.Enabled = optional.Some(false)
	s = GetIPAllowlist(t.Context())
	assert.False(t, s.Enforced(IPAllowlistSurfaceWeb))
	assert.True(t, s.FromConfig)
	assert.Len(t, s.Entries, 1)

	cfg, err := NewConfigProviderFromData("[ip_allowlist]\nENABLED = false\n")
	require.NoError(t, err)
	IPAllowlist.Enabled = optional.None[bool]()
	loadIPAllowlistFrom(cfg)
	assert.Equal(t, optional.Some(false), IPAllowlist.Enabled)
	cfg, _ = NewConfigProviderFromData("")
	loadIPAllowlistFrom(cfg)
	assert.False(t, IPAllowlist.Enabled.Has())
}
