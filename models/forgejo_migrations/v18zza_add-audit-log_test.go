// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"strings"
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addAuditLog(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addAuditLog(x))
	require.NoError(t, addAuditLog(x), "the migration can run again")

	var heads []v18zzaAuditChainHead
	require.NoError(t, x.Find(&heads))
	assert.Empty(t, heads, "the head row is created by the sealer: fresh installs record this migration without running it")

	tables, err := x.DBMetas()
	require.NoError(t, err)
	var cols, indexes []string
	for _, table := range tables {
		if table.Name != "audit_event" {
			continue
		}
		cols = table.ColumnsSeq()
		for _, index := range table.Indexes {
			indexes = append(indexes, strings.Join(index.Cols, ","))
		}
		assert.Empty(t, table.PrimaryKeys[1:])
		assert.True(t, table.GetColumn("seq").Nullable)
		assert.True(t, table.GetColumn("hash").Nullable)
		assert.True(t, table.GetColumn("prev_hash").Nullable)
	}
	assert.Len(t, cols, 27)
	assert.ElementsMatch(t, []string{
		"created_unix", "action,id", "category,id", "actor_id,id", "sudo_by_id,id", "credential_type,credential_id,id",
		"owner_id,id", "repo_id,id", "subject_user_id,id", "target_type,target_id", "seq",
	}, indexes)

	// a NULL seq may repeat
	_, err = x.Insert(&v18zzaAuditEvent{Action: "a"}, &v18zzaAuditEvent{Action: "b"})
	require.NoError(t, err)
}
