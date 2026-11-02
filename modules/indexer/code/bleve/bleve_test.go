// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package bleve

import (
	"testing"

	inner_bleve "forgejo.org/modules/indexer/internal/bleve"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC13: an index written before the document-ID change (version 7) is dropped
// and reported as not existing, so the repo indexer is repopulated; the new
// version is then reopened as is.
func TestExistingIndexIsRebuilt(t *testing.T) {
	assert.Greater(t, repoIndexerLatestVersion, 7)

	dir := t.TempDir()
	old := inner_bleve.NewIndexer(dir, 7, generateBleveIndexMapping)
	exists, err := old.Init(t.Context())
	require.NoError(t, err)
	assert.False(t, exists)
	old.Close()

	idx := NewIndexer(dir)
	exists, err = idx.Init(t.Context())
	require.NoError(t, err)
	assert.False(t, exists, "old index must be rebuilt")
	idx.Close()

	idx = NewIndexer(dir)
	exists, err = idx.Init(t.Context())
	require.NoError(t, err)
	assert.True(t, exists)
	idx.Close()
}
