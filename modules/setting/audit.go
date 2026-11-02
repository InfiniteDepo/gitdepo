// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

// Audit holds the [audit] settings.
var Audit = struct {
	// LogReads also records reads made with a web session, and API reads of private repositories (credential
	// downloads and git reads are always recorded).
	LogReads bool
}{}

func loadAuditFrom(rootCfg ConfigProvider) {
	Audit.LogReads = rootCfg.Section("audit").Key("LOG_READS").MustBool(false)
}
