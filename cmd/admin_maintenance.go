// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"
	"time"

	"forgejo.org/modules/setting"
	maintenance_service "forgejo.org/services/maintenance"

	"github.com/urfave/cli/v3"
)

func subcmdMaintenance() *cli.Command {
	return &cli.Command{
		Name:  "maintenance",
		Usage: "Turn read-only or maintenance mode on and off",
		Commands: []*cli.Command{
			{
				Name:   "enable",
				Usage:  "Turn on read-only or maintenance mode",
				Before: noDanglingArgs,
				Action: runMaintenanceEnable,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "mode",
						Value: setting.MaintenanceReadOnly,
						Usage: "read-only (everyone can read, nobody can write) or maintenance (only site admins can use the instance)",
					},
					&cli.StringFlag{
						Name:  "message",
						Usage: "Message shown to users",
					},
					&cli.TimestampFlag{
						Name:  "until",
						Usage: "End time (RFC3339), after which the mode turns itself off",
						Config: cli.TimestampConfig{
							Layouts: []string{time.RFC3339},
						},
					},
				},
			},
			{
				Name:   "disable",
				Usage:  "Turn read-only or maintenance mode off",
				Before: noDanglingArgs,
				Action: runMaintenanceDisable,
			},
		},
	}
}

func runMaintenanceEnable(ctx context.Context, c *cli.Command) error {
	return setMaintenance(ctx, c.String("mode"), c.String("message"), c.Timestamp("until"))
}

func runMaintenanceDisable(ctx context.Context, c *cli.Command) error {
	return setMaintenance(ctx, setting.MaintenanceOff, "", time.Time{})
}

func setMaintenance(ctx context.Context, mode, message string, until time.Time) error {
	ctx, cancel := installSignals(ctx)
	defer cancel()

	if err := initDB(ctx); err != nil {
		return err
	}
	if err := maintenance_service.Set(ctx, nil, mode, message, until); err != nil {
		return err
	}
	fmt.Printf("Maintenance mode is now %s\n", mode)
	return nil
}
