// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package webhook

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC1: nothing stored means every type is on
func TestSetDisabledTypes(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	assert.Len(t, EnabledList(ctx), len(List()))

	// unknown names are refused and nothing is stored
	require.ErrorIs(t, SetDisabledTypes(ctx, nil, []string{"slack", "nope"}), util.ErrInvalidArgument)
	require.ErrorIs(t, SetDisabledTypes(ctx, nil, []string{"Slack"}), util.ErrInvalidArgument)
	assert.Empty(t, setting.Config().WebhookTypes.Value(ctx).Disabled)

	// duplicates are dropped
	require.NoError(t, SetDisabledTypes(ctx, nil, []string{"slack", "gitea", "slack"}))
	assert.Equal(t, []string{"slack", "gitea"}, setting.Config().WebhookTypes.Value(ctx).Disabled)
	assert.Len(t, EnabledList(ctx), len(List())-2)
	require.ErrorIs(t, CheckTypeEnabled(ctx, "slack"), util.ErrInvalidArgument)
	require.NoError(t, CheckTypeEnabled(ctx, "matrix"))
}
