// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan_test

import (
	"strings"
	"testing"

	"forgejo.org/models/unittest"

	"code.forgejo.org/xorm/xorm/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

// A fresh install creates the alert table from the model: it has the same indexes as an upgraded one
// (the migrations v18zzl and v18zzm).
func TestAlertModelIndexes(t *testing.T) {
	unittest.PrepareTestEnv(t)
	x, err := unittest.GetXORMEngine()
	require.NoError(t, err)
	tables, err := x.DBMetas()
	require.NoError(t, err)
	indexes := func(table string) (got []string) {
		for _, tb := range tables {
			if tb.Name != table {
				continue
			}
			for _, index := range tb.Indexes {
				kind := "index:"
				if index.Type == schemas.UniqueType {
					kind = "unique:"
				}
				got = append(got, kind+strings.Join(index.Cols, ","))
			}
		}
		return got
	}
	assert.ElementsMatch(t, []string{
		"unique:repo_id,index", "unique:repo_id,rule_id,fingerprint", "index:repo_id,state", "index:repo_id,fingerprint",
	}, indexes("secret_scanning_alert"))
	assert.ElementsMatch(t, []string{"unique:repo_id,kind", "index:retry_unix", "index:updated_unix", "index:requeue"}, indexes("secret_scan"))
}
