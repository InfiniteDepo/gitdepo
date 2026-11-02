// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/modules/indexer/code/internal"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// searchRecorder is an indexer that records the search it gets.
type searchRecorder struct {
	internal.Indexer
	regex bool
	opts  *internal.SearchOptions
}

func (s *searchRecorder) Search(_ context.Context, opts *internal.SearchOptions) (int64, []*internal.SearchResult, []*internal.SearchResultLanguages, error) {
	s.opts = opts
	return 0, nil, nil, nil
}

func (s *searchRecorder) SupportsRegex() bool { return s.regex }

func useIndexer(t *testing.T, idx internal.Indexer) {
	t.Helper()
	old := globalIndexer.Load()
	globalIndexer.Store(&idx)
	t.Cleanup(func() { globalIndexer.Store(old) })
}

func search(opts *SearchOptions) error {
	_, _, _, err := PerformSearch(context.Background(), opts)
	return err
}

// The keyword and the path are capped for every mode.
func TestPerformSearchLengthCaps(t *testing.T) {
	rec := &searchRecorder{Indexer: internal.NewDummyIndexer(), regex: true}
	useIndexer(t, rec)
	long := strings.Repeat("a", internal.MaxKeywordLength+1)
	page := &db.ListOptions{Page: 1, PageSize: 10}

	for _, mode := range []SearchMode{SearchModeExact, SearchModeUnion, SearchModeFuzzy, SearchModeRegex} {
		require.ErrorIs(t, search(&SearchOptions{Keyword: long, Mode: mode, Paginator: page}), internal.ErrInvalidQuery, mode.String())
		require.NoError(t, search(&SearchOptions{Keyword: long[1:], Mode: mode, Paginator: page}), mode.String())
	}
	require.ErrorIs(t, search(&SearchOptions{Keyword: "a", Filename: long, Paginator: page}), internal.ErrInvalidQuery)
}

// AC8/AC10: regex needs a backend that supports it.
func TestPerformSearchRegexSupport(t *testing.T) {
	page := &db.ListOptions{Page: 1, PageSize: 10}

	useIndexer(t, &searchRecorder{Indexer: internal.NewDummyIndexer(), regex: false})
	require.ErrorIs(t, search(&SearchOptions{Keyword: "a", Mode: SearchModeRegex, Paginator: page}), internal.ErrRegexNotSupported)
	assert.False(t, SupportsRegex())

	rec := &searchRecorder{Indexer: internal.NewDummyIndexer(), regex: true}
	useIndexer(t, rec)
	require.NoError(t, search(&SearchOptions{Keyword: "a", Mode: SearchModeRegex, Paginator: page}))
	assert.True(t, SupportsRegex())
	assert.Equal(t, SearchModeRegex, rec.opts.Mode)
}

// F4: skip+take stays inside the window, pages beyond it are empty without asking the backend.
func TestPerformSearchWindow(t *testing.T) {
	rec := &searchRecorder{Indexer: internal.NewDummyIndexer()}
	useIndexer(t, rec)

	require.NoError(t, search(&SearchOptions{Keyword: "a", Paginator: &db.ListOptions{Page: 100, PageSize: 11}})) // skip 1089
	assert.Nil(t, rec.opts, "backend asked for a page beyond the window")

	require.NoError(t, search(&SearchOptions{Keyword: "a", Paginator: &db.ListOptions{Page: 34, PageSize: 30}})) // skip 990, take 30
	skip, take := rec.opts.GetSkipTake()
	assert.Equal(t, 990, skip)
	assert.Equal(t, 10, take)

	require.NoError(t, search(&SearchOptions{Keyword: "a", Paginator: &db.ListOptions{Page: 2, PageSize: 10}}))
	skip, take = rec.opts.GetSkipTake()
	assert.Equal(t, 10, skip)
	assert.Equal(t, 10, take)
}

type resultRecorder struct {
	searchRecorder
	results []*internal.SearchResult
}

func (r *resultRecorder) Search(context.Context, *internal.SearchOptions) (int64, []*internal.SearchResult, []*internal.SearchResultLanguages, error) {
	return int64(len(r.results)), r.results, nil, nil
}

// AC5: results on the default branch carry no branch, whatever the indexer calls it; other
// branches keep theirs.
func TestPerformSearchResultBranch(t *testing.T) {
	page := &db.ListOptions{Page: 1, PageSize: 10}
	run := func(opts *SearchOptions) []string {
		useIndexer(t, &resultRecorder{searchRecorder: searchRecorder{Indexer: internal.NewDummyIndexer()}, results: []*internal.SearchResult{
			{Filename: "a.go", Content: "x", Branch: "main"},
			{Filename: "b.go", Content: "x", Branch: "HEAD"},
			{Filename: "c.go", Content: "x", Branch: "dev"},
		}})
		opts.Keyword, opts.Paginator = "x", page
		_, res, _, err := PerformSearch(context.Background(), opts)
		require.NoError(t, err)
		branches := make([]string, 0, len(res))
		for _, r := range res {
			branches = append(branches, r.Branch)
		}
		return branches
	}

	assert.Equal(t, []string{"", "", ""}, run(&SearchOptions{}), "default branch search")
	assert.Equal(t, []string{"main", "", "dev"}, run(&SearchOptions{AllBranches: true}))
	assert.Equal(t, []string{"main", "", "dev"}, run(&SearchOptions{Branch: "dev"}))
}
