// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan_test

import (
	"testing"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTextPlaces(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	issue := &issues_model.Issue{RepoID: 1, Index: 900, PosterID: 2, Title: "t"}
	pull := &issues_model.Issue{RepoID: 1, Index: 901, PosterID: 2, Title: "p", IsPull: true}
	other := &issues_model.Issue{RepoID: 2, Index: 902, PosterID: 2, Title: "o"}
	for _, i := range []*issues_model.Issue{issue, pull, other} {
		require.NoError(t, db.Insert(ctx, i))
	}
	insert := func(l *secretscan_model.Location) *secretscan_model.Location {
		t.Helper()
		l.AlertID, l.BlobID = 1, ""
		require.NoError(t, db.Insert(ctx, l))
		return l
	}
	inIssue := insert(secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, issue.ID, issue.ID, "body", 3, 3, 2))
	inPull := insert(secretscan_model.NewTextLocation(1, secretscan_model.KindComment, 77, pull.ID, "", 1, 1, 3))
	foreign := insert(secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, other.ID, other.ID, "title", 1, 1, 2)) // the issue is of another repository
	code := insert(&secretscan_model.Location{RepoID: 1, Kind: secretscan_model.KindRepo, PathHash: "x", Path: "a.go"})
	locs := []*secretscan_model.Location{inIssue, inPull, foreign, code}

	load := func(a secretscan_model.TextAccess) map[int64]*secretscan_model.TextPlace {
		t.Helper()
		got, err := secretscan_model.LoadTextPlaces(ctx, 1, locs, a)
		require.NoError(t, err)
		assert.NotContains(t, got, code.ID, "only places in text")
		assert.Len(t, got, 3)
		return got
	}
	t.Run("no read access: nothing is told", func(t *testing.T) {
		for _, p := range load(secretscan_model.TextAccess{}) {
			assert.False(t, p.Readable)
			assert.Zero(t, p.Number)
			assert.Nil(t, p.Poster)
		}
	})
	t.Run("issues only", func(t *testing.T) {
		got := load(secretscan_model.TextAccess{Issues: true})
		assert.True(t, got[inIssue.ID].Readable)
		assert.EqualValues(t, 900, got[inIssue.ID].Number)
		assert.Equal(t, "user2", got[inIssue.ID].Poster.Name)
		assert.Equal(t, "body", got[inIssue.ID].FieldName())
		assert.False(t, got[inPull.ID].Readable, "a pull request needs the pull request unit")
		assert.Nil(t, got[inPull.ID].Poster, "the poster is for readers only")
	})
	t.Run("pull requests only", func(t *testing.T) {
		got := load(secretscan_model.TextAccess{Pulls: true})
		assert.False(t, got[inIssue.ID].Readable)
		assert.True(t, got[inPull.ID].Readable)
		assert.True(t, got[inPull.ID].IsPull)
		assert.Equal(t, "comment", got[inPull.ID].FieldName())
	})
	t.Run("both, and an issue of another repository stays hidden", func(t *testing.T) {
		got := load(secretscan_model.TextAccess{Issues: true, Pulls: true})
		assert.True(t, got[inIssue.ID].Readable)
		assert.True(t, got[inPull.ID].Readable)
		assert.False(t, got[foreign.ID].Readable)
	})
}
