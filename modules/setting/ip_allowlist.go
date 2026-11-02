// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"forgejo.org/modules/optional"
)

// The surfaces the IP allowlist can be enforced on.
const (
	IPAllowlistSurfaceWeb      = "web"
	IPAllowlistSurfaceAPI      = "api"
	IPAllowlistSurfaceGit      = "git"
	IPAllowlistSurfaceSSH      = "ssh"
	IPAllowlistSurfacePackages = "packages"
)

// IPAllowlist is the [ip_allowlist] section of app.ini. ENABLED = false turns the list off whatever the database says.
var IPAllowlist = struct {
	Enabled optional.Option[bool]
}{}

func loadIPAllowlistFrom(rootCfg ConfigProvider) {
	IPAllowlist.Enabled = optional.None[bool]()
	if sec := rootCfg.Section("ip_allowlist"); sec.HasKey("ENABLED") {
		IPAllowlist.Enabled = optional.Some(sec.Key("ENABLED").MustBool())
	}
}

// IPAllowlistEntry is one allowed network.
type IPAllowlistEntry struct {
	CIDR        netip.Prefix `json:"cidr"`
	Description string       `json:"description"`
	CreatedByID int64        `json:"created_by_id"`
	CreatedUnix int64        `json:"created_unix"`
}

// IPAllowlistToken is an exempt access token, matched on both its ID and its owner.
type IPAllowlistToken struct {
	ID  int64 `json:"id"`
	UID int64 `json:"uid"`
}

// IPAllowlistState is the instance IP allowlist, stored as JSON in the "ip_allowlist.state" system setting.
type IPAllowlistState struct {
	Enabled       bool               `json:"enabled"`
	Web           bool               `json:"web"`
	API           bool               `json:"api"`
	Git           bool               `json:"git"`
	SSH           bool               `json:"ssh"`
	Packages      bool               `json:"packages"`
	ExemptAdmins  bool               `json:"exempt_admins"`
	Entries       []IPAllowlistEntry `json:"entries"`
	ExemptUserIDs []int64            `json:"exempt_user_ids"`
	ExemptTokens  []IPAllowlistToken `json:"exempt_tokens"`
	FromConfig    bool               `json:"-"`
}

// GetIPAllowlist returns the IP allowlist. [ip_allowlist] ENABLED = false in app.ini turns it off.
func GetIPAllowlist(ctx context.Context) IPAllowlistState {
	s := Config().IPAllowlist.Value(ctx)
	if has, enabled := IPAllowlist.Enabled.Get(); has && !enabled {
		s.Enabled, s.FromConfig = false, true
	}
	return s
}

// Enforced reports whether the list is checked on the surface. An empty list is never enforced.
func (s IPAllowlistState) Enforced(surface string) bool {
	if !s.Enabled || len(s.Entries) == 0 {
		return false
	}
	switch surface {
	case IPAllowlistSurfaceWeb:
		return s.Web
	case IPAllowlistSurfaceAPI:
		return s.API
	case IPAllowlistSurfaceGit:
		return s.Git
	case IPAllowlistSurfaceSSH:
		return s.SSH
	case IPAllowlistSurfacePackages:
		return s.Packages
	}
	return false
}

// Allows reports whether the address is in the list. Invalid and zoned addresses never are.
func (s IPAllowlistState) Allows(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, e := range s.Entries {
		if e.CIDR.Contains(ip) {
			return true
		}
	}
	return false
}

// WouldBlock reports whether the address is refused on any surface, ignoring exemptions.
func (s IPAllowlistState) WouldBlock(ip netip.Addr) bool {
	surfaces := []string{IPAllowlistSurfaceWeb, IPAllowlistSurfaceAPI, IPAllowlistSurfaceGit, IPAllowlistSurfaceSSH, IPAllowlistSurfacePackages}
	return slices.ContainsFunc(surfaces, s.Enforced) && !s.Allows(ip)
}

// NormalizeIPPrefix returns the network with the host bits cleared, and IPv4-mapped IPv6 networks as IPv4, so that it
// contains unmapped addresses.
func NormalizeIPPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
	}
	return p.Masked()
}

// IPFromRemoteAddr parses the "host:port" of a client; the address is invalid if it can't be parsed.
func IPFromRemoteAddr(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip, _ := netip.ParseAddr(host)
	return ip
}
