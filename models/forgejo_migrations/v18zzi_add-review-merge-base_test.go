// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzgOldReview struct {
	ID      int64 `xorm:"pk autoincr"`
	IssueID int64
}

func (v18zzgOldReview) TableName() string {
	return "review"
}

func Test_addReviewMergeBase(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzgOldReview))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO review (issue_id) VALUES (7)")
	require.NoError(t, err)

	require.NoError(t, addReviewMergeBase(x))
	require.NoError(t, addReviewMergeBase(x), "the migration can run again")

	count, err := x.Table("review").Where("issue_id = 7 AND (merge_base IS NULL OR merge_base = '')").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing reviews have no merge base")
}
