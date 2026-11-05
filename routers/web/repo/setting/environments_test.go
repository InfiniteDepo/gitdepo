// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"strconv"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	actions_service "forgejo.org/services/actions"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reviewer list of a form is read once, by one parser, and never holds more than a save could.
func TestParseReviewers(t *testing.T) {
	listed, err := parseReviewers(" user:2, team:7 ,,")
	require.NoError(t, err)
	assert.Equal(t, []*actions_model.ActionEnvironmentReviewer{{UserID: 2}, {TeamID: 7}}, listed)

	for _, bad := range []string{"user:x", "user:-2", "user:0", "org:3", "2"} {
		listed, err = parseReviewers("user:2," + bad)
		require.ErrorIs(t, err, errBadReviewer, bad)
		assert.Len(t, listed, 1, bad)
	}

	keys := make([]string, 40000)
	for i := range keys {
		keys[i] = "user:" + strconv.Itoa(i+1)
	}
	listed, err = parseReviewers(strings.Join(keys, ","))
	require.ErrorIs(t, err, actions_service.ErrTooManyReviewers)
	assert.Len(t, listed, actions_model.MaxEnvironmentReviewers)
	listed, err = parseReviewers(strings.Join(keys[:actions_model.MaxEnvironmentReviewers], ","))
	require.NoError(t, err)
	assert.Len(t, listed, actions_model.MaxEnvironmentReviewers)
}
