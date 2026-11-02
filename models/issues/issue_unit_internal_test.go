// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues

import (
	"context"
	"errors"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

// The condition is plain SQL on every database: no unit type is written as an identifier
func TestIssueUnitCondSQL(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	sql, args, err := builder.ToSQL(issueUnitCond(db.DefaultContext))
	require.NoError(t, err)
	assert.NotRegexp(t, `[`+"`"+`"'][0-9]+[`+"`"+`"']|(^|[ (])[0-9]+ *=`, sql)
	assert.Contains(t, args, unit.TypeIssues)
	assert.Contains(t, args, unit.TypePullRequests)
}

// A repository whose owner turned a unit off keeps its issue rows, but they leave every list; they return with the unit
func TestIssuesOfDisabledUnit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	const repoID = 1

	opts := func(isPull bool) *IssuesOptions {
		return &IssuesOptions{RepoIDs: []int64{repoID}, IsPull: optional.Some(isPull)}
	}
	counts := func(isPull bool) (int, int64, int64, int64) {
		ids, total, err := IssueIDs(ctx, opts(isPull))
		require.NoError(t, err)
		list, err := Issues(ctx, opts(isPull))
		require.NoError(t, err)
		assert.Len(t, list, len(ids))
		n, err := CountIssues(ctx, opts(isPull))
		require.NoError(t, err)
		byRepo, err := CountIssuesByRepo(ctx, opts(isPull))
		require.NoError(t, err)
		return len(ids), total, n, byRepo[repoID]
	}
	issues, _, _, _ := counts(false)
	pulls, _, _, _ := counts(true)
	require.Positive(t, issues)
	require.Positive(t, pulls)

	for _, tc := range []struct {
		off  unit.Type
		isPu bool
	}{{unit.TypeIssues, false}, {unit.TypePullRequests, true}} {
		ru := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repoID, Type: tc.off})
		_, err := db.GetEngine(ctx).ID(ru.ID).Delete(&repo_model.RepoUnit{})
		require.NoError(t, err)

		a, b, c, d := counts(tc.isPu)
		assert.Zero(t, a+int(b)+int(c)+int(d), "%s off", tc.off)
		// the other type is untouched
		other := map[bool]int{false: pulls, true: issues}[tc.isPu]
		got, total, n, byRepo := counts(!tc.isPu)
		assert.Equal(t, other, got)
		assert.EqualValues(t, other, total)
		assert.EqualValues(t, other, n)
		assert.EqualValues(t, other, byRepo)

		unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: repoID, Type: tc.off, Config: &repo_model.IssuesConfig{}})
		a, b, _, _ = counts(tc.isPu)
		assert.Equal(t, map[bool]int{false: issues, true: pulls}[tc.isPu], a)
		assert.EqualValues(t, a, b)
	}
}

// The indexer path: lists that are not filtered in SQL are filtered by the repository's units
func TestIssueListFilterHiddenUnitsDisabledUnit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	list := func() IssueList {
		return IssueList{
			unittest.AssertExistsAndLoadBean(t, &Issue{ID: 1}), // repo 1, issue
			unittest.AssertExistsAndLoadBean(t, &Issue{ID: 2}), // repo 1, pull
			unittest.AssertExistsAndLoadBean(t, &Issue{ID: 4}), // repo 2, issue
			unittest.AssertExistsAndLoadBean(t, &Issue{ID: 5}), // repo 1, issue
		}
	}
	ids := func(l IssueList) (r []int64) {
		for _, i := range l {
			r = append(r, i.ID)
		}
		return r
	}
	require.True(t, unittest.AssertExistsAndLoadBean(t, &Issue{ID: 2}).IsPull)

	all, err := list().FilterHiddenUnits(ctx)
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 2, 4, 5}, ids(all))

	del := func(tp unit.Type) {
		ru := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 1, Type: tp})
		_, err := db.GetEngine(ctx).ID(ru.ID).Delete(&repo_model.RepoUnit{})
		require.NoError(t, err)
	}
	del(unit.TypePullRequests)
	got, err := list().FilterHiddenUnits(ctx)
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 4, 5}, ids(got), "pulls of repo 1 are dropped, its issues and other repos stay")

	del(unit.TypeIssues)
	got, err = list().FilterHiddenUnits(ctx)
	require.NoError(t, err)
	assert.Equal(t, []int64{4}, ids(got))
}

// Fail closed: a missing repository drops the issue, a failing unit lookup is an error
func TestIssueListFilterHiddenUnitsFailsClosed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	list := IssueList{unittest.AssertExistsAndLoadBean(t, &Issue{ID: 1}), {ID: 1000, RepoID: 99999}}
	got, err := list.FilterHiddenUnits(db.DefaultContext)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.EqualValues(t, 1, got[0].ID)

	// the repositories are loaded already, so the units query is the one that fails
	list = IssueList{unittest.AssertExistsAndLoadBean(t, &Issue{ID: 1})}
	_, err = list.LoadRepositories(db.DefaultContext)
	require.NoError(t, err)
	errRollback := errors.New("rollback")
	err = db.WithTx(db.DefaultContext, func(ctx context.Context) error {
		_, err := db.GetEngine(ctx).Exec("DROP TABLE repo_unit")
		require.NoError(t, err)
		_, err = list.FilterHiddenUnits(ctx)
		require.Error(t, err)
		return errRollback
	})
	require.ErrorIs(t, err, errRollback)
}
