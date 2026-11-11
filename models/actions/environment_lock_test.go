// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"code.forgejo.org/xorm/xorm"
	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

type sqlRecorder struct{ sqls *[]string }

func (h sqlRecorder) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	*h.sqls = append(*h.sqls, c.SQL)
	return c.Ctx, nil
}

// engineCtx makes the queries of the code under test run on eng.
type engineCtx struct {
	context.Context
	eng *xorm.Engine
}

func (c engineCtx) Engine() db.Engine { return c.eng }

func (h sqlRecorder) AfterProcess(*contexts.ContextHook) error { return nil }

// The twin checks must lock what they read on MySQL and PostgreSQL: xorm's Exist and Count drop ForUpdate, so they
// read with Get and Find. Nothing listens on the addresses; the SQL is recorded before it is sent.
func TestTwinChecksKeepForUpdate(t *testing.T) {
	for _, d := range [][2]string{{"mysql", "u:p@tcp(127.0.0.1:1)/x"}, {"pgx", "postgres://u:p@127.0.0.1:1/x?sslmode=disable"}} {
		eng, err := xorm.NewEngine(d[0], d[1])
		require.NoError(t, err)
		var sqls []string
		eng.AddHook(sqlRecorder{&sqls})

		// the transfer check: every table it reads is locked, so the organization's names come from a join, not a subquery
		sqls = nil
		dbType := setting.DatabaseType("mysql")
		if d[0] == "pgx" {
			dbType = "postgres"
		}
		defer test.MockVariableValue(&setting.Database.Type, dbType)()
		_, _ = hasTwinOnTransfer(engineCtx{context.Background(), eng}, 1, 3)
		require.Len(t, sqls, 1, d[0])
		assert.NotContains(t, sqls[0], "(SELECT", "%s: %s", d[0], sqls[0])
		assert.Contains(t, sqls[0], "FOR UPDATE", "%s: %s", d[0], sqls[0])
		sqls = nil

		_, _ = lockedExist(eng.Table("action_environment").ForUpdate().Where(scopeCond(3, 0)).And("lower_name = ?", "x"))
		var ids2 []int64
		_ = eng.Table("action_environment").ForUpdate().Join("INNER", "repository", "repository.id = action_environment.repo_id").
			Where(builder.Eq{"action_environment.owner_id": 0}).Cols("action_environment.id").Find(&ids2)
		require.Len(t, sqls, 2, d[0])
		for _, s := range sqls {
			assert.Contains(t, s, "FOR UPDATE", "%s: %s", d[0], s)
		}
	}
}
