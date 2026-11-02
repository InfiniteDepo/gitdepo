// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"
	"html"
	"html/template"

	"forgejo.org/modules/translation"
)

type PreExecutionWarning int64

// PreExecutionWarning values are stored in the database in ActionRun.PreExecutionWarningCodes and therefore values
// can't be reordered or changed without a database migration.  Translation arguments are stored in the database in
// PreExecutionWarningDetails, and so they can't be changed or reordered without creating a migration or a new error
// code to represent the new argument details.
const (
	// WarningCodePermissions is no longer created: `permissions:` was ignored before gitdepo supported it.
	WarningCodePermissions PreExecutionWarning = iota + 1
	// WarningCodePermissionsIgnored: details are the job ID and the ignored `permissions:` keys, comma-separated.
	WarningCodePermissionsIgnored
)

func TranslatePreExecutionWarning(lang translation.Locale, run *ActionRun) []template.HTML {
	warnings := make([]template.HTML, len(run.PreExecutionWarningCodes))
	for i, code := range run.PreExecutionWarningCodes {
		switch code {
		case WarningCodePermissions:
			warnings[i] = lang.Tr("actions.workflow.permissions_warning", run.PreExecutionWarningDetails[i]...)
		case WarningCodePermissionsIgnored:
			warnings[i] = lang.Tr("actions.workflow.permissions_ignored_warning", run.PreExecutionWarningDetails[i]...)
		default:
			warnings[i] = template.HTML(html.EscapeString(fmt.Sprintf("unsupported warning: code=%v details=%#v", code, run.PreExecutionWarningDetails[i])))
		}
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}
