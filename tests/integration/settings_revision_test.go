// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"testing"

	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/modules/setting/config"

	"github.com/stretchr/testify/require"
)

// lastSettingsRevision: fixtures reset the settings revision, so two tests could store different values under the
// same revision and the cached one would win; keep the revision above every one seen so far. It starts far above
// the fixtures' revision, because tests that store a setting without bumping (e.g. through maintenance_service)
// count up from there, and a value they cached (also from a stale revision, as the cache refreshes once a second)
// would otherwise be served again at a bumped revision.
var lastSettingsRevision = 1 << 20

// bumpSettingsRevision must follow every test write to a system setting (including a web or API request that
// stores one) before the setting is read again.
func bumpSettingsRevision(t *testing.T) {
	t.Helper()
	lastSettingsRevision = max(lastSettingsRevision, system_model.GetRevision(db.DefaultContext)) + 1
	_, err := db.Exec(db.DefaultContext, "UPDATE system_setting SET version=? WHERE setting_key='revision'", lastSettingsRevision)
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
}
