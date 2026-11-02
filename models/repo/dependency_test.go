// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"context"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestReplaceRepoDependencies(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	first := []*repo_model.Dependency{
		{RepoID: 1, Ecosystem: "Go", Name: "a", Version: "v1", ManifestPath: "go.mod", Direct: true},
		{RepoID: 1, Ecosystem: "npm", Name: "b", Version: "2", ManifestPath: "web/package-lock.json"},
	}
	scan := &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: repo_model.DependencyScanOK, ManifestCount: 2, DependencyCount: 2}
	scan.SetSkippedManifests([]repo_model.SkippedManifest{{Path: "x/yarn.lock", Code: repo_model.DependencySkipParse}})
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, scan, first))
	other := &repo_model.Dependency{RepoID: 2, Ecosystem: "Go", Name: "z"}
	require.NoError(t, db.Insert(ctx, other))

	got, err := repo_model.GetRepoDependencyScan(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "aaaa", got.CommitSHA)
	assert.Equal(t, []repo_model.SkippedManifest{{Path: "x/yarn.lock", Code: "parse_error"}}, got.SkippedManifests())

	// a failed scan keeps the rows and the commit
	fail := &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: repo_model.DependencyScanFailed, Error: repo_model.DependencyErrTimeout}
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, fail, nil))
	n := countDeps(t, 1)
	assert.EqualValues(t, 2, n)
	got, _ = repo_model.GetRepoDependencyScan(ctx, 1)
	assert.Equal(t, "timeout", got.Error)

	// a scan replaces the rows of its repository only
	second := []*repo_model.Dependency{{RepoID: 1, Ecosystem: "Go", Name: "c", Version: "v3", ManifestPath: "go.mod", Direct: true}}
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "bbbb", Status: repo_model.DependencyScanOK}, second))
	n = countDeps(t, 1)
	assert.EqualValues(t, 1, n)
	n = countDeps(t, 2)
	assert.EqualValues(t, 1, n)
	count, err := db.GetEngine(ctx).Where("repo_id = 1").Count(new(repo_model.DependencyScan))
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "one scan row")

	// an empty result (no manifests) clears the rows
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "cccc", Status: repo_model.DependencyScanOK}, []*repo_model.Dependency{}))
	n = countDeps(t, 1)
	assert.EqualValues(t, 0, n)
}

func TestSkippedManifests(t *testing.T) {
	s := &repo_model.DependencyScan{Skipped: `[{"path":"a","code":"<script>"},{"path":"b","code":"parse_error"}]`}
	assert.Equal(t, []repo_model.SkippedManifest{{Path: "a", Code: "internal_error"}, {Path: "b", Code: "parse_error"}}, s.SkippedManifests())
	assert.Nil(t, (&repo_model.DependencyScan{Skipped: "{"}).SkippedManifests())

	var many []repo_model.SkippedManifest
	for range 300 {
		many = append(many, repo_model.SkippedManifest{Path: "p", Code: "parse_error"})
	}
	s = &repo_model.DependencyScan{}
	s.SetSkippedManifests(many)
	assert.Len(t, s.SkippedManifests(), 100)
}

func TestSearchRepoDependencies(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	var rows []*repo_model.Dependency
	for _, n := range []string{"100%_sure", "left-pad", "Left_Pad2", "x!y", "other"} {
		rows = append(rows, &repo_model.Dependency{RepoID: 1, Ecosystem: "npm", Name: n, Version: "1", ManifestPath: "a/package-lock.json", Direct: n == "other"})
	}
	rows = append(rows, &repo_model.Dependency{RepoID: 1, Ecosystem: "Go", Name: "go-thing", ManifestPath: "go.mod"}, &repo_model.Dependency{RepoID: 2, Ecosystem: "Go", Name: "left-pad"})
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: 1, Status: "ok"}, rows[:6]))
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: 2, Status: "ok"}, rows[6:]))

	names := func(o *repo_model.DependencySearchOptions) []string {
		o.RepoID = 1
		got, total, err := db.FindAndCount[repo_model.Dependency](ctx, o)
		require.NoError(t, err)
		assert.EqualValues(t, len(got), total)
		var out []string
		for _, d := range got {
			out = append(out, d.Name)
		}
		return out
	}
	assert.Len(t, names(&repo_model.DependencySearchOptions{}), 6)
	assert.Equal(t, []string{"100%_sure"}, names(&repo_model.DependencySearchOptions{Q: "%"}), "% is a literal")
	assert.Equal(t, []string{"100%_sure", "Left_Pad2"}, names(&repo_model.DependencySearchOptions{Q: "_"}), "_ is a literal")
	assert.Equal(t, []string{"x!y"}, names(&repo_model.DependencySearchOptions{Q: "!"}))
	assert.Equal(t, []string{"left-pad", "Left_Pad2"}, names(&repo_model.DependencySearchOptions{Q: "LEFT"}), "sorted by name, ignoring case")
	assert.Equal(t, []string{"go-thing"}, names(&repo_model.DependencySearchOptions{Ecosystem: "Go"}))
	assert.Equal(t, []string{"other"}, names(&repo_model.DependencySearchOptions{Direct: optional.Some(true)}))
	assert.Equal(t, []string{"go-thing"}, names(&repo_model.DependencySearchOptions{Manifest: "go.mod"}))
	assert.Empty(t, names(&repo_model.DependencySearchOptions{Q: "left-pad", Ecosystem: "Go"}))

	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: 2, Status: "ok"}, []*repo_model.Dependency{
		{RepoID: 2, Ecosystem: "RubyGems", Name: "rails"}, {RepoID: 2, Ecosystem: "npm", Name: "a"}, {RepoID: 2, Ecosystem: "npm", Name: "b"}, {RepoID: 2, Ecosystem: "Go", Name: "c"},
	}))
	facets, err := repo_model.GetDependencyFacets(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, []repo_model.DependencyFacet{{Value: "Go", Count: 1}, {Value: "npm", Count: 2}, {Value: "RubyGems", Count: 1}}, facets.Ecosystems, "ecosystems sorted ignoring case")
}

func countDeps(t *testing.T, repoID int64) int64 {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Where("repo_id = ?", repoID).Count(new(repo_model.Dependency))
	require.NoError(t, err)
	return n
}

func TestReplaceRepoDependenciesIf(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	row := func(name string) []*repo_model.Dependency {
		return []*repo_model.Dependency{{RepoID: 1, Ecosystem: "Go", Name: name, Version: "v1", ManifestPath: "go.mod"}}
	}

	// no row yet: the first writer inserts, the second (who also read "none") hits the unique key and writes nothing
	ok, err := repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: "ok"}, row("a"), nil, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "bbbb", Status: "ok"}, row("b"), nil, nil)
	require.NoError(t, err)
	assert.False(t, ok)

	// two scans that both read "aaaa": the first replaces, the second finds another commit and writes nothing
	read, err := repo_model.GetRepoDependencyScan(ctx, 1)
	require.NoError(t, err)
	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "cccc", Status: "ok"}, row("c"), read, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "dddd", Status: "ok"}, row("d"), read, nil)
	require.NoError(t, err)
	assert.False(t, ok)
	// neither a failure of the stale scan
	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: repo_model.DependencyScanFailed, Error: "timeout"}, nil, read, nil)
	require.NoError(t, err)
	assert.False(t, ok)

	got, _ := repo_model.GetRepoDependencyScan(ctx, 1)
	assert.Equal(t, "cccc", got.CommitSHA)
	assert.Empty(t, got.Error)
	assert.EqualValues(t, 1, countDeps(t, 1))

	// the switch went off while the scan ran: asked inside the transaction, it writes nothing, not even the scan row
	off := func(context.Context) (bool, error) { return false, nil }
	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "eeee", Status: "ok"}, row("e"), got, off)
	require.NoError(t, err)
	assert.False(t, ok)
	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 2, CommitSHA: "eeee", Status: "ok"}, row("e"), nil, off)
	require.NoError(t, err)
	assert.False(t, ok)
	got, _ = repo_model.GetRepoDependencyScan(ctx, 1)
	assert.Equal(t, "cccc", got.CommitSHA)
	got, _ = repo_model.GetRepoDependencyScan(ctx, 2)
	assert.Nil(t, got)
}

// The purge finds a repository by its scan row or by rows left without one.
func TestScannedDependencyRepoIDs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: 3, CommitSHA: "a", Status: "ok"}, nil))
	require.NoError(t, db.Insert(ctx, &repo_model.Dependency{RepoID: 2, Ecosystem: "Go", Name: "x", Version: "v1", ManifestPath: "go.mod"}))
	ids, err := repo_model.ScannedDependencyRepoIDs(ctx, nil, 10)
	require.NoError(t, err)
	assert.Equal(t, []int64{2, 3}, ids)
	ids, err = repo_model.ScannedDependencyRepoIDs(ctx, builder.Eq{"repository.id": 2}, 10)
	require.NoError(t, err)
	assert.Equal(t, []int64{2}, ids)
	ids, err = repo_model.ScannedDependencyRepoIDs(ctx, nil, 1)
	require.NoError(t, err)
	assert.Equal(t, []int64{2}, ids)
}

// A failing scan can't flip the row of a scan of the same commit that finished while it ran.
func TestReplaceRepoDependenciesIfSameCommitRescanned(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	first := &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: repo_model.DependencyScanOK, ScannedUnix: 100}
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, first, []*repo_model.Dependency{}))
	read, err := repo_model.GetRepoDependencyScan(ctx, 1)
	require.NoError(t, err)

	// another process rescans the same commit meanwhile
	ok, err := repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: repo_model.DependencyScanOK, ScannedUnix: 101}, []*repo_model.Dependency{}, read, nil)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = repo_model.ReplaceRepoDependenciesIf(ctx, &repo_model.DependencyScan{RepoID: 1, CommitSHA: "aaaa", Status: repo_model.DependencyScanFailed, Error: "timeout", ScannedUnix: 102}, nil, read, nil)
	require.NoError(t, err)
	assert.False(t, ok)
	got, _ := repo_model.GetRepoDependencyScan(ctx, 1)
	assert.Equal(t, repo_model.DependencyScanOK, got.Status)
	assert.Empty(t, got.Error)
}
