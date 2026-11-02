// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addSecretTextLocations(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)
	require.NoError(t, x.Sync(new(v18zzlSecretScanningLocation)))
	before := indexSets(t, x, "secret_scanning_location")
	require.Contains(t, before, "unique:alert_id,kind,blob_id,path_hash,start_line")
	_, err := x.Insert(&v18zzlSecretScanningLocation{AlertID: 1, RepoID: 7, Kind: "repo", BlobID: "b", PathHash: "h", StartLine: 3})
	require.NoError(t, err)

	require.NoError(t, addSecretTextLocations(x))
	require.NoError(t, addSecretTextLocations(x), "the migration can run again")

	after := indexSets(t, x, "secret_scanning_location")
	for _, set := range before {
		assert.Contains(t, after, set, "an existing key survives")
	}
	n, err := x.Where("repo_id = 7 AND source_id = 0 AND issue_id = 0 AND field = '' AND poster_id = 0 AND removed_unix = 0").Count(new(v18zzoSecretScanningLocation))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "an existing place has the defaults")

	_, err = x.Insert(&v18zzoSecretScanningLocation{AlertID: 1, RepoID: 7, Kind: "comment", PathHash: "h", StartLine: 3, SourceID: 9, IssueID: 4, PosterID: 2})
	require.NoError(t, err)
}
