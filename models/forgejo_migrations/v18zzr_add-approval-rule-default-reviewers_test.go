// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// v18zzrApprovalRuleBefore is the table before the migration.
type v18zzrApprovalRuleBefore struct {
	ID                int64   `xorm:"pk autoincr"`
	ProtectedBranchID int64   `xorm:"INDEX UNIQUE(s) NOT NULL"`
	Name              string  `xorm:"VARCHAR(255) UNIQUE(s) NOT NULL"`
	RequiredCount     int64   `xorm:"NOT NULL DEFAULT 1"`
	UserIDs           []int64 `xorm:"JSON TEXT"`
	TeamIDs           []int64 `xorm:"JSON TEXT"`
	PathPatterns      string  `xorm:"TEXT"`
	RequireCodeOwners bool    `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzrApprovalRuleBefore) TableName() string {
	return "approval_rule"
}

// v18zzrReviewBefore is the part of the review table the test uses.
type v18zzrReviewBefore struct {
	ID       int64 `xorm:"pk autoincr"`
	Type     int
	Official bool `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzrReviewBefore) TableName() string {
	return "review"
}

func Test_addApprovalRuleDefaultReviewers(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzrApprovalRuleBefore), new(v18zzrReviewBefore))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO approval_rule (protected_branch_id, name, required_count, user_i_ds, team_i_ds, path_patterns) VALUES (1, 'Security', 2, '[2]', '[]', 'docs/**')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO review (type, official) VALUES (4, ?)", true)
	require.NoError(t, err)

	require.NoError(t, addApprovalRuleDefaultReviewers(x))
	require.NoError(t, addApprovalRuleDefaultReviewers(x), "the migration can run again")

	n, err := x.Table("approval_rule").Where("name = 'Security' AND required_count = 2 AND path_patterns = 'docs/**' AND request_reviews = ? AND source_branch_pattern = ''", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "an existing rule keeps its values and gets the defaults")
	n, err = x.Table("review").Where("type = 4 AND official = ? AND advisory = ?", true, false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "an existing review request is not advisory")
	// the unique name per protected branch survives
	_, err = x.Exec("INSERT INTO approval_rule (protected_branch_id, name, required_count, user_i_ds, team_i_ds, path_patterns) VALUES (1, 'Security', 1, '[2]', '[]', '')")
	require.Error(t, err)
}
