// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package migrations

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/migrations/allowlist"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBitbucketServer(t *testing.T) {
	for in, want := range map[string]string{
		"https://BB.Example.com":       "https://bb.example.com",
		"HTTP://bb.example.com:7990/":  "http://bb.example.com:7990",
		"https://bb.example.com/ctx//": "https://bb.example.com/ctx",
	} {
		u, err := parseBitbucketServer(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, u.String(), in)
	}
	for _, in := range []string{"", "bb.example.com", "ftp://bb.example.com", "file:///srv", "https://u:p@bb.example.com", "https://bb.example.com?x=1", "https://bb.example.com#f", "https://"} {
		_, err := parseBitbucketServer(in)
		require.ErrorIs(t, err, util.ErrInvalidArgument, in)
	}
}

func TestBitbucketProjectName(t *testing.T) {
	for name, want := range map[string]string{
		"Payments Team":        "payments-team",
		"  API -- Core  ":      "api-core",
		"Pay\x1b[31m\r\nments": "pay-31m-ments",
		"Équipe":               "quipe",
		"---":                  "key",
		"":                     "key",
		"..":                   "key",
		"a.b_c":                "a.b_c",
	} {
		assert.Equal(t, want, bitbucketProjectName(name, "KEY"), name)
	}
}

func TestImportBitbucketChecks(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, true, func() { require.NoError(t, allowlist.Init()) })()
	opts := BitbucketImportOptions{Server: "https://127.0.0.1:1", Token: "sometoken", DryRun: true}
	set := func(t *testing.T, query string, args ...any) {
		t.Helper()
		_, err := db.Exec(db.DefaultContext, append([]any{query}, args...)...)
		require.NoError(t, err)
	}

	// org3 is owned by user2; user5 isn't a member; user1 is a site admin
	_, err := ImportBitbucket(t.Context(), "user5", "org3", opts)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, err = ImportBitbucket(t.Context(), "user2", "user5", opts)
	require.Error(t, err, "not an organization")
	_, err = ImportBitbucket(t.Context(), "user2", "org3", BitbucketImportOptions{Server: "file:///srv", DryRun: true})
	require.ErrorIs(t, err, util.ErrInvalidArgument)

	for name, flag := range map[string]string{
		"an owner blocked by the two-factor requirement": "UPDATE `user` SET require_two_factor = ? WHERE id = 3",
		"a doer who can't sign in":                       "UPDATE `user` SET prohibit_login = ? WHERE id = 2",
		"an inactive doer":                               "UPDATE `user` SET is_active = NOT ? WHERE id = 2",
	} {
		t.Run(name, func(t *testing.T) {
			set(t, flag, true)
			t.Cleanup(func() { set(t, flag, false) })
			_, err := ImportBitbucket(t.Context(), "user2", "org3", opts)
			require.ErrorIs(t, err, util.ErrPermissionDenied)
		})
	}

	t.Run("maintenance mode refuses a real run only", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
		real := opts
		real.DryRun = false
		_, err := ImportBitbucket(t.Context(), "user1", "org3", real)
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, err = ImportBitbucket(t.Context(), "user1", "org3", opts)
		require.NotErrorIs(t, err, util.ErrPermissionDenied, "a dry run still reaches the server")
	})

	// one import per organization at a time
	bitbucketImports.Store(int64(3), true)
	_, err = ImportBitbucket(t.Context(), "user1", "org3", opts)
	require.ErrorIs(t, err, util.ErrAlreadyExist)
	bitbucketImports.Delete(int64(3))

	// the site admin gets past the checks and reaches the (missing) server
	_, err = ImportBitbucket(t.Context(), "user1", "org3", opts)
	require.Error(t, err)
	require.NotErrorIs(t, err, util.ErrPermissionDenied)
	require.NotErrorIs(t, err, util.ErrAlreadyExist)
	_, held := bitbucketImports.Load(int64(3))
	assert.False(t, held, "the lock is released")
}

func TestBitbucketKeyExpiry(t *testing.T) {
	const bb, maxExpiry, flag = timeutil.TimeStamp(100), timeutil.TimeStamp(200), timeutil.TimeStamp(300)
	assert.Equal(t, bb, bitbucketKeyExpiry(bb, maxExpiry, flag))
	assert.Equal(t, maxExpiry, bitbucketKeyExpiry(0, maxExpiry, flag))
	assert.Equal(t, maxExpiry, bitbucketKeyExpiry(400, maxExpiry, 0))
	assert.Equal(t, flag, bitbucketKeyExpiry(400, 0, flag))
	assert.Equal(t, bb, bitbucketKeyExpiry(bb, 0, 0))
	assert.Zero(t, bitbucketKeyExpiry(0, 0, 0))
}
