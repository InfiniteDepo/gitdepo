// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package automerge

import (
	"testing"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
)

func TestAutoMergeWaitsInMaintenance(t *testing.T) {
	defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
	// unhandled items go back to the queue and are retried when the mode is off
	assert.Equal(t, []string{"1_abc"}, handler("1_abc"))
}
