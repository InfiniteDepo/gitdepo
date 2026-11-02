// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"forgejo.org/modules/setting"
	ipallowlist_service "forgejo.org/services/ipallowlist"

	"github.com/urfave/cli/v3"
)

func subcmdIPAllowlist() *cli.Command {
	cidrFlag := &cli.StringFlag{Name: "cidr", Usage: "IPv4 or IPv6 network, e.g. 10.0.0.0/8", Required: true}
	return &cli.Command{
		Name:  "ip-allowlist",
		Usage: "Show and change the instance IP allowlist",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "Show the IP allowlist",
				Before: noDanglingArgs,
				Action: runIPAllowlistList,
			},
			{
				Name:   "add",
				Usage:  "Add a network to the IP allowlist",
				Before: noDanglingArgs,
				Action: runIPAllowlistAdd,
				Flags:  []cli.Flag{cidrFlag, &cli.StringFlag{Name: "description", Usage: "What the network is"}},
			},
			{
				Name:   "remove",
				Usage:  "Remove a network from the IP allowlist",
				Before: noDanglingArgs,
				Action: runIPAllowlistRemove,
				Flags:  []cli.Flag{cidrFlag},
			},
			{
				Name:   "disable",
				Usage:  "Stop enforcing the IP allowlist, e.g. after a lock-out; the entries are kept",
				Before: noDanglingArgs,
				Action: runIPAllowlistDisable,
			},
		},
	}
}

// editIPAllowlist changes the stored IP allowlist, straight in the database
func editIPAllowlist(ctx context.Context, edit func(*setting.IPAllowlistState) error) error {
	ctx, cancel := installSignals(ctx)
	defer cancel()

	if err := initDB(ctx); err != nil {
		return err
	}
	s := setting.GetIPAllowlist(ctx)
	if err := edit(&s); err != nil {
		return err
	}
	return ipallowlist_service.Set(ctx, nil, s)
}

func runIPAllowlistList(ctx context.Context, _ *cli.Command) error {
	ctx, cancel := installSignals(ctx)
	defer cancel()

	if err := initDB(ctx); err != nil {
		return err
	}
	s := setting.GetIPAllowlist(ctx)
	fmt.Printf("enabled: %t (web: %t, api: %t, git: %t, ssh: %t, packages: %t), exempt admins: %t\n",
		s.Enabled, s.Web, s.API, s.Git, s.SSH, s.Packages, s.ExemptAdmins)
	for _, e := range s.Entries {
		fmt.Printf("%s\t%s\n", e.CIDR, e.Description)
	}
	return nil
}

func runIPAllowlistAdd(ctx context.Context, c *cli.Command) error {
	return editIPAllowlist(ctx, func(s *setting.IPAllowlistState) error {
		p, err := netip.ParsePrefix(c.String("cidr"))
		if err != nil {
			return err
		}
		s.Entries = append(s.Entries, setting.IPAllowlistEntry{CIDR: p, Description: c.String("description")})
		return nil
	})
}

func runIPAllowlistRemove(ctx context.Context, c *cli.Command) error {
	return editIPAllowlist(ctx, func(s *setting.IPAllowlistState) error {
		p, err := netip.ParsePrefix(c.String("cidr"))
		if err != nil {
			return err
		}
		p = setting.NormalizeIPPrefix(p)
		n := len(s.Entries)
		s.Entries = slices.DeleteFunc(slices.Clone(s.Entries), func(e setting.IPAllowlistEntry) bool { return e.CIDR == p })
		if len(s.Entries) == n {
			return fmt.Errorf("%s is not in the IP allowlist", p)
		}
		return nil
	})
}

func runIPAllowlistDisable(ctx context.Context, _ *cli.Command) error {
	err := editIPAllowlist(ctx, func(s *setting.IPAllowlistState) error {
		s.Enabled = false
		return nil
	})
	if err == nil {
		fmt.Println("The IP allowlist is now disabled")
	}
	return err
}
