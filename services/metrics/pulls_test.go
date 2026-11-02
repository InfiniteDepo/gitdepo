// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"bytes"
	"encoding/csv"
	"testing"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	day = 24 * 3600
	now = timeutil.TimeStamp(1_000_000_000)
)

func ago(days float64) timeutil.TimeStamp { return now - timeutil.TimeStamp(days*day) }

func TestPercentile(t *testing.T) {
	assert.Equal(t, Stat{}, newStat(nil))
	assert.Equal(t, Stat{N: 1, Median: 7, P85: 7}, newStat([]int64{7}))
	assert.Equal(t, Stat{N: 2, Median: 1, P85: 2}, newStat([]int64{2, 1}))
	assert.Equal(t, Stat{N: 10, Median: 5, P85: 9}, newStat([]int64{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}))
	assert.Equal(t, Stat{N: 20, Median: 10, P85: 17}, newStat([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}))
}

func TestParsePeriod(t *testing.T) {
	for in, want := range map[string]int{"7": 7, "30": 30, "90": 90, "": 30, "8": 30, "-7": 30, "90d": 30, "abc": 30} {
		assert.Equal(t, want, ParsePeriod(in), in)
	}
}

func titleChange(issue int64, at timeutil.TimeStamp, from, to string) *event {
	return &event{IssueID: issue, PosterID: 1, Type: issues_model.CommentTypeChangeTitle, OldTitle: from, NewTitle: to, CreatedUnix: at}
}

func review(issue, poster int64, at timeutil.TimeStamp) *event {
	return &event{IssueID: issue, PosterID: poster, Type: issues_model.CommentTypeReview, CreatedUnix: at}
}

func TestBuild(t *testing.T) {
	prs := []*prRow{
		// a: ready when opened, reviewed after 1 day, merged after 2
		{IssueID: 1, PosterID: 1, Number: 1, Title: "a", Created: ago(10), HasMerged: true, Merged: ago(8), Commits: 3},
		// b: opened as a draft, a review while it was a draft is ignored, ready 5 days later
		{IssueID: 2, PosterID: 1, Number: 2, Title: "b", Created: ago(20), HasMerged: true, Merged: ago(13), Commits: 1},
		// c: only the author reviewed
		{IssueID: 3, PosterID: 5, Number: 3, Title: "c", Created: ago(5)},
		// d: still a draft: reviews don't count, merge time from creation
		{IssueID: 4, PosterID: 1, Number: 4, Title: "[WIP] d", Created: ago(4), HasMerged: true, Merged: ago(1)},
		// e: merged before the period, reviewed in it (late review, still counts for first review)
		{IssueID: 5, PosterID: 1, Number: 5, Title: "e", Created: ago(50), HasMerged: true, Merged: ago(40), Commits: 9},
		// f: renamed to WIP and back after opening: ready when opened
		{IssueID: 6, PosterID: 1, Number: 6, Title: "f", Created: ago(3)},
		// g: became ready after it was merged: merge time from creation
		{IssueID: 7, PosterID: 1, Number: 7, Title: "g", Created: ago(6), HasMerged: true, Merged: ago(5)},
	}
	events := []*event{
		review(1, 2, ago(9)),
		review(1, 3, ago(8.5)),
		titleChange(2, ago(15), "WIP: b", "b"),
		review(2, 2, ago(16)),
		review(2, 3, ago(14)),
		review(3, 5, ago(4)),
		review(4, 2, ago(3)),
		review(5, 2, ago(2)),
		titleChange(6, ago(2.5), "f", "WIP: f"),
		titleChange(6, ago(2), "WIP: f", "f"),
		review(6, 2, ago(1)),
		titleChange(7, ago(4), "WIP: g", "g"),
	}
	r := build(prs, events, ago(30), now, 30)

	rows := map[int64]*Row{}
	for _, row := range r.Rows {
		rows[row.Number] = row
	}
	assert.Equal(t, ago(10), rows[1].Ready)
	assert.EqualValues(t, day, rows[1].ToFirstReview)
	assert.EqualValues(t, 2*day, rows[1].ToMerge)
	assert.Equal(t, ago(15), rows[2].Ready)
	assert.Equal(t, ago(14), rows[2].FirstReview)
	assert.EqualValues(t, 2*day, rows[2].ToMerge)
	assert.Zero(t, rows[3].FirstReview)
	assert.EqualValues(t, -1, rows[3].ToFirstReview)
	assert.EqualValues(t, -1, rows[3].ToMerge)
	assert.Zero(t, rows[4].Ready)
	assert.Zero(t, rows[4].FirstReview)
	assert.EqualValues(t, 3*day, rows[4].ToMerge)
	assert.EqualValues(t, 48*day, rows[5].ToFirstReview)
	assert.Equal(t, ago(3), rows[6].Ready)
	assert.EqualValues(t, 2*day, rows[6].ToFirstReview)
	assert.Equal(t, ago(4), rows[7].Ready)
	assert.EqualValues(t, day, rows[7].ToMerge)

	// first reviews in the period: a 1d, b 1d, e 48d, f 2d
	assert.Equal(t, Stat{N: 4, Median: day, P85: 48 * day}, r.FirstReview)
	// merges in the period: a 2d, b 2d, d 3d, g 1d
	assert.Equal(t, Stat{N: 4, Median: 2 * day, P85: 3 * day}, r.Merge)
	assert.Equal(t, Stat{N: 2, Median: 1, P85: 3}, r.Commits)
	assert.Equal(t, 4, r.Merged)
	assert.InDelta(t, 4*7/30.0, r.PerWeek, 0.0001)

	require.Len(t, r.Weeks, 5)
	assert.Equal(t, ago(30), r.Weeks[0].From, "the oldest week starts with the period")
	assert.Equal(t, ago(28), r.Weeks[0].To)
	assert.Equal(t, now, r.Weeks[4].To)
	assert.Equal(t, ago(7), r.Weeks[4].From)
	// this week: d and g merged, e and f first reviewed
	assert.Equal(t, 2, r.Weeks[4].Merged)
	assert.Equal(t, Stat{N: 2, Median: day, P85: 3 * day}, r.Weeks[4].Merge)
	assert.Equal(t, Stat{N: 2, Median: 2 * day, P85: 48 * day}, r.Weeks[4].FirstReview)
	// a (merged 8 days ago) and b (merged 13 days ago) in the week before
	assert.Equal(t, 2, r.Weeks[3].Merged)
	assert.Equal(t, Stat{N: 1, Median: day, P85: day}, r.Weeks[3].FirstReview)
	assert.Equal(t, Stat{N: 1, Median: day, P85: day}, r.Weeks[2].FirstReview, "b, first reviewed exactly 14 days ago")

	assert.Len(t, build(nil, nil, ago(7), now, 7).Weeks, 1)
	assert.Len(t, build(nil, nil, ago(90), now, 90).Weeks, 13)
	empty := build(nil, nil, ago(90), now, 90)
	assert.Equal(t, Stat{}, empty.Merge)
	assert.Zero(t, empty.PerWeek)
}

func TestWriteCSV(t *testing.T) {
	r := &Report{Rows: []*Row{
		{OwnerName: "org", RepoName: "repo", Number: 3, Title: "=HYPERLINK(\"x\")", Created: ago(2), Ready: ago(2), FirstReview: ago(1), ToFirstReview: day, ToMerge: -1, Commits: 2},
		{OwnerName: "org", RepoName: "repo", Number: 4, Title: " @cmd", Created: ago(2), ToFirstReview: -1, Merged: ago(1), ToMerge: day},
	}}
	var buf bytes.Buffer
	require.NoError(t, WriteCSV(&buf, r))
	lines, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, lines, 3)
	assert.Equal(t, []string{"repository", "number", "title", "url", "created", "ready", "first_review", "merged", "seconds_to_first_review", "seconds_to_merge", "commits"}, lines[0])
	assert.Equal(t, "'=HYPERLINK(\"x\")", lines[1][2])
	assert.Equal(t, "' @cmd", lines[2][2])
	assert.Equal(t, "2001-09-07T01:46:40Z", lines[1][4])
	assert.Equal(t, []string{"86400", "", "2"}, lines[1][8:])
	assert.Equal(t, []string{"", "", "2001-09-08T01:46:40Z", "", "86400", ""}, lines[2][5:])
	assert.Contains(t, lines[1][3], "org/repo/pulls/3")
}
