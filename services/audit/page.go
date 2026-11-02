// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"

	audit_model "forgejo.org/models/audit"
)

// ActionKeys are the catalog keys the action filter suggests.
var ActionKeys = []string{
	"admin.*", "admin.login_source.*", "admin.user_group.*", "admin.setting.changed", "admin.log_shipping.*", "admin.quota_rule.*",
	"admin.quota_group.*", "admin.cron.run", "admin.logging.changed",
	"admin.queue.items_removed", "org.*", "org.organization.*", "org.team.*", "org.verified_domain.*",
	"audit.*", "audit.exported", "audit.instance.started",
	"credential.*", "credential.access_token.*", "credential.access_token.created", "credential.access_token.deleted",
	"credential.access_token.regenerated", "credential.access_token.rotated",
}

// Page returns at most limit entries of f, newest first, from the keyset position of f (before_id, after_id), and
// whether there are newer and older entries.
func Page(ctx context.Context, f *Filter, limit int) (entries []*audit_model.Entry, newer, older bool, err error) {
	entries, err = audit_model.FindEntries(ctx, &f.Opts, limit+1)
	if err != nil || len(entries) <= limit {
		return entries, f.Opts.BeforeID != 0, f.Opts.AfterID != 0, err
	}
	if f.Opts.AfterID != 0 {
		return entries[1:], true, true, nil // the extra one is newer
	}
	return entries[:limit], f.Opts.BeforeID != 0, true, nil
}
