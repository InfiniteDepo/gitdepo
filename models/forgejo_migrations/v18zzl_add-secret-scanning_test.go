// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"strings"
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"code.forgejo.org/xorm/xorm"
	"code.forgejo.org/xorm/xorm/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzlTestRepository struct {
	ID      int64  `xorm:"pk autoincr"`
	OwnerID int64  `xorm:"UNIQUE(s) INDEX"`
	Name    string `xorm:"UNIQUE(s) INDEX"`
}

// indexSets lists the indexes of a table as "unique:col1,col2" / "index:col1,col2".
func indexSets(t *testing.T, x *xorm.Engine, table string) []string {
	t.Helper()
	tables, err := x.DBMetas()
	require.NoError(t, err)
	var sets []string
	for _, tb := range tables {
		if tb.Name != table {
			continue
		}
		for _, index := range tb.Indexes {
			kind := "index:"
			if index.Type == schemas.UniqueType {
				kind = "unique:"
			}
			sets = append(sets, kind+strings.Join(index.Cols, ","))
		}
	}
	return sets
}

func (v18zzlTestRepository) TableName() string {
	return "repository"
}

func Test_addSecretScanning(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)
	// a repository that exists before the migration
	require.NoError(t, x.Sync(new(v18zzlTestRepository)))
	_, err := x.Insert(&v18zzlTestRepository{Name: "before"})
	require.NoError(t, err)
	indexesBefore := indexSets(t, x, "repository")
	require.ElementsMatch(t, []string{"unique:owner_id,name", "index:owner_id", "index:name"}, indexesBefore)

	require.NoError(t, addSecretScanning(x))
	require.NoError(t, addSecretScanning(x), "the migration can run again")

	assert.ElementsMatch(t, indexesBefore, indexSets(t, x, "repository"), "the indexes and unique keys of the repository table survive")

	var disabled []bool
	require.NoError(t, x.SQL("SELECT secret_scanning_disabled FROM repository WHERE name = 'before'").Find(&disabled))
	assert.Equal(t, []bool{false}, disabled, "secret scanning is on for a repository by default")

	_, err = x.Exec("INSERT INTO secret_scan (repo_id, kind, scanned_tips, status) VALUES (1, 'repo', ?, 'ok')", strings.Repeat("a", 70000))
	require.NoError(t, err, "a long list of tips fits (MySQL TEXT would cut it)")
	_, err = x.Exec("INSERT INTO secret_scan (repo_id, kind) VALUES (1, 'repo')")
	require.Error(t, err, "one state row per repository and kind")
	_, err = x.Exec("INSERT INTO secret_scan (repo_id, kind) VALUES (1, 'wiki')")
	require.NoError(t, err)
	var version []int64
	require.NoError(t, x.SQL("SELECT version FROM secret_scan WHERE kind = 'wiki'").Find(&version))
	assert.Equal(t, []int64{0}, version)
	// the progress and backoff columns start at zero (nothing to retry), and the large-file count has its name
	var progress []int64
	require.NoError(t, x.SQL("SELECT fail_count + retry_unix + holes + skipped_large FROM secret_scan WHERE kind = 'wiki'").Find(&progress))
	assert.Equal(t, []int64{0}, progress)
	_, err = x.Exec("UPDATE secret_scan SET retry_unix = 5 WHERE kind = 'wiki'")
	require.NoError(t, err, "the cron task finds due rows by retry_unix")

	fp := strings.Repeat("f", 64)
	insertAlert := "INSERT INTO secret_scanning_alert (repo_id, `index`, rule_id, fingerprint) VALUES (?, ?, ?, ?)"
	_, err = x.Exec(insertAlert, 1, 1, "github-token", fp)
	require.NoError(t, err)
	_, err = x.Exec(insertAlert, 1, 2, "github-token", fp)
	require.Error(t, err, "one alert per repository, rule and fingerprint")
	_, err = x.Exec(insertAlert, 1, 1, "gitlab-token", fp)
	require.Error(t, err, "one alert per repository and number")
	_, err = x.Exec(insertAlert, 2, 1, "github-token", fp)
	require.NoError(t, err, "the same secret in another repository")
	var state []string
	require.NoError(t, x.SQL("SELECT state FROM secret_scanning_alert WHERE repo_id = 1").Find(&state))
	assert.Equal(t, []string{"open"}, state)
	var viaPull []bool
	require.NoError(t, x.SQL("SELECT via_pull FROM secret_scanning_alert WHERE repo_id = 1").Find(&viaPull))
	assert.Equal(t, []bool{false}, viaPull, "an alert is not a pull-ref one by default")

	insertLocation := "INSERT INTO secret_scanning_location (alert_id, repo_id, kind, blob_id, path, path_hash, start_line) VALUES (1, 1, ?, 'b1', 'p', 'h', ?)"
	_, err = x.Exec(insertLocation, "repo", 3)
	require.NoError(t, err)
	_, err = x.Exec(insertLocation, "repo", 3)
	require.Error(t, err, "one location per alert, kind, blob, path and line")
	_, err = x.Exec(insertLocation, "wiki", 3)
	require.NoError(t, err)

	_, err = x.Exec("INSERT INTO secret_scanning_alert_index (group_id, max_index) VALUES (1, 1)")
	require.NoError(t, err)
}
