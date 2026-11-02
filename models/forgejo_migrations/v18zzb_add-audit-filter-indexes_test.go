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

func Test_addAuditFilterIndexes(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addAuditLog(x))
	require.NoError(t, addAuditFilterIndexes(x))

	tables, err := x.DBMetas()
	require.NoError(t, err)
	var indexes []string
	for _, table := range tables {
		if table.Name == "audit_event" {
			for _, index := range table.Indexes {
				indexes = append(indexes, strings.Join(index.Cols, ","))
			}
		}
	}
	assert.ElementsMatch(t, []string{
		"created_unix", "action,id", "category,id", "actor_id,id", "sudo_by_id,id", "credential_type,credential_id,id",
		"owner_id,id", "repo_id,id", "subject_user_id,id", "target_type,target_id", "seq",
		"group_id,id", "credential_owner_id,id", "ip,id", "request_id",
	}, indexes)
}
