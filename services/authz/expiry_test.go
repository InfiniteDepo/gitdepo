// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"testing"
	"time"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateExpiry(t *testing.T) {
	defer test.MockVariableValue(&setting.DefaultUILocation, time.UTC)()
	timeutil.MockSet(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	defer timeutil.MockUnset()

	now := timeutil.TimeStampNow()
	lastAllowed := timeutil.TimeStamp(time.Date(2026, 11, 3, 23, 59, 59, 0, time.UTC).Unix())
	none := setting.CredentialExpiryPolicy{}
	required := setting.CredentialExpiryPolicy{Required: true}
	max30 := setting.CredentialExpiryPolicy{MaxLifetimeDays: 30}

	for _, tc := range []struct {
		name    string
		policy  setting.CredentialExpiryPolicy
		expires timeutil.TimeStamp
		err     error
	}{
		{"no policy, never", none, 0, nil},
		{"no policy, future", none, now.Add(1), nil},
		{"required, never", required, 0, ErrExpiryRequired},
		{"required, future", required, now.Add(3600), nil},
		{"max implies required", max30, 0, ErrExpiryRequired},
		{"now is in the past", none, now, ErrExpiryInPast},
		{"past", required, now.Add(-1), ErrExpiryInPast},
		{"end of the last allowed day", max30, lastAllowed, nil},
		{"after the last allowed day", max30, lastAllowed.Add(1), ErrExpiryTooLate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExpiry(tc.policy, tc.expires)
			if tc.err == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.err)
			require.ErrorIs(t, err, ErrExpiryPolicy)
		})
	}

	require.ErrorContains(t, ValidateExpiry(max30, lastAllowed.Add(1)), "the maximum lifetime is 30 days")
	require.ErrorContains(t, ValidateExpiry(max30, 0), "the maximum lifetime is 30 days")
	require.NoError(t, ValidateExpiry(max30, MaxExpiry(max30)))
	assert.Zero(t, MaxExpiry(required))
	assert.Equal(t, "2026-11-03", DefaultExpiryDate(max30))
	assert.Equal(t, "2026-11-03", DefaultExpiryDate(setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 365}))
	assert.Equal(t, "2026-10-14", DefaultExpiryDate(setting.CredentialExpiryPolicy{MaxLifetimeDays: 10}))
	assert.Equal(t, "2026-11-03", DefaultExpiryDate(required))
	assert.Empty(t, DefaultExpiryDate(none))
	assert.Equal(t, "2026-11-03", MaxExpiryDate(max30))
	assert.Empty(t, MaxExpiryDate(required))
}

func TestParseExpiryDate(t *testing.T) {
	defer test.MockVariableValue(&setting.DefaultUILocation, time.UTC)()

	ts, err := ParseExpiryDate("")
	require.NoError(t, err)
	assert.Zero(t, ts)

	ts, err = ParseExpiryDate("2026-09-30")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC).Unix(), int64(ts))

	_, err = ParseExpiryDate("30/09/2026")
	require.ErrorIs(t, err, ErrExpiryInvalid)
}
