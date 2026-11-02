// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var secretAlertIndexes = []string{
	"unique:repo_id,index",
	"unique:repo_id,rule_id,fingerprint",
	"index:repo_id,state",
	"index:repo_id,fingerprint",
}

var secretScanIndexes = []string{
	"unique:repo_id,kind",
	"index:retry_unix",
	"index:updated_unix",
}

func Test_addSecretAlertFingerprintIndex(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)
	require.NoError(t, x.Sync(new(v18zzlSecretScanningAlert)))
	require.ElementsMatch(t, secretAlertIndexes[:3], indexSets(t, x, "secret_scanning_alert"))

	require.NoError(t, x.Sync(new(v18zzlSecretScan)))
	require.ElementsMatch(t, secretScanIndexes, indexSets(t, x, "secret_scan"))
	_, err := x.Insert(&v18zzlSecretScan{RepoID: 7, Kind: "repo"})
	require.NoError(t, err)

	require.NoError(t, addSecretAlertFingerprintIndex(x))
	require.NoError(t, addSecretAlertFingerprintIndex(x), "the migration can run again")

	assert.ElementsMatch(t, secretAlertIndexes, indexSets(t, x, "secret_scanning_alert"), "the unique keys and the state index survive, the new index exists")
	assert.ElementsMatch(t, append([]string{"index:requeue"}, secretScanIndexes...), indexSets(t, x, "secret_scan"), "the scan state keeps its keys and gets the new one")
	n, err := x.Where("repo_id = 7 AND requeue = ?", 0).Count(new(v18zzmSecretScan))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "an existing row is not marked")
	n, err = x.Where("repo_id = 7 AND notify_after_unix = 0 AND notify_seq = 0 AND notify_alert_id = 0 AND notify_pusher_id = 0 AND notify_ref = '' AND notify_commit = '' AND notify_kinds = 0 AND notify_last_unix = 0 AND notify_floor = 0 AND queue_stuck_unix = 0 AND completed = ?", false).Count(new(v18zzmSecretScan))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "an existing row has no digest mark")
}
