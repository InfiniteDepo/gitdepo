// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zaMirrorBefore struct {
	ID          int64 `xorm:"pk autoincr"`
	RepoID      int64
	EnablePrune bool `xorm:"NOT NULL DEFAULT true"`
}

func (v18zaMirrorBefore) TableName() string { return "mirror" }

func Test_migrationFilenameRegexMultiLetter(t *testing.T) {
	for file, group := range map[string]string{"/m/v18z_add-trash.go": "v18z", "/m/v18za_x.go": "v18za", "/m/v18zb_y.go": "v18zb"} {
		match := migrationFilenameRegex.FindStringSubmatch(file)
		require.NotEmpty(t, match, file)
		assert.Equal(t, group, match[1])
	}
	assert.Empty(t, migrationFilenameRegex.FindStringSubmatch("/m/v18_x.go"))
}

// An existing pull mirror gets empty filters, i.e. it keeps mirroring everything.
func Test_addMirrorFilters(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zaMirrorBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO mirror (repo_id, enable_prune) VALUES (7, true)")
	require.NoError(t, err)

	require.NoError(t, addMirrorFilters(x))

	var rows []struct {
		RepoID       int64
		EnablePrune  bool
		BranchFilter string
		TagFilter    string
		FilterError  *string
	}
	require.NoError(t, x.Table("mirror").Find(&rows))
	require.Len(t, rows, 1)
	assert.EqualValues(t, 7, rows[0].RepoID)
	assert.True(t, rows[0].EnablePrune)
	assert.Empty(t, rows[0].BranchFilter)
	assert.Empty(t, rows[0].TagFilter)
	assert.Empty(t, rows[0].FilterError)
}
