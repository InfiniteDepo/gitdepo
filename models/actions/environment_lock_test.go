// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"testing"

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

func (h sqlRecorder) AfterProcess(*contexts.ContextHook) error { return nil }

// The twin checks must lock what they read on MySQL and PostgreSQL: xorm's Exist and Count drop ForUpdate, so they
// read with Get and Find. Nothing listens on the addresses; the SQL is recorded before it is sent.
func TestTwinChecksKeepForUpdate(t *testing.T) {
	for _, d := range [][2]string{{"mysql", "u:p@tcp(127.0.0.1:1)/x"}, {"pgx", "postgres://u:p@127.0.0.1:1/x?sslmode=disable"}} {
		eng, err := xorm.NewEngine(d[0], d[1])
		require.NoError(t, err)
		var sqls []string
		eng.AddHook(sqlRecorder{&sqls})

		_, _ = lockedExist(eng.Table("action_environment").ForUpdate().Where(scopeCond(3, 0)).And("lower_name = ?", "x"))
		_, _ = lockedExist(eng.Table("action_environment").ForUpdate().Where(scopeCond(0, 1)).And(builder.In("lower_name",
			builder.Select("lower_name").From("action_environment").Where(scopeCond(3, 0)))))
		var ids []int64
		_ = eng.Table("action_environment").ForUpdate().Join("INNER", "repository", "repository.id = action_environment.repo_id").
			Where(builder.Eq{"action_environment.owner_id": 0}).Cols("action_environment.id").Find(&ids)

		require.Len(t, sqls, 3, d[0])
		for _, s := range sqls {
			assert.Contains(t, s, "FOR UPDATE", "%s: %s", d[0], s)
		}
	}
}
