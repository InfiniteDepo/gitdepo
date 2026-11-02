// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomRuleID(t *testing.T) {
	assert.Equal(t, "custom-12", CustomRuleID(12))
	for id, want := range map[string]int64{"custom-12": 12, "custom-1": 1} {
		got, ok := ParseCustomRuleID(id)
		assert.True(t, ok, id)
		assert.Equal(t, want, got)
	}
	for _, id := range []string{"", "github-token", "custom-", "custom-0", "custom--1", "custom-1x", "Custom-1", "custom- 1", "custom-99999999999999999999"} {
		_, ok := ParseCustomRuleID(id)
		assert.False(t, ok, id)
	}
}

func TestCustomPatternQueries(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	add := func(owner int64, name string, enabled bool, deleted int64) *CustomPattern {
		p := &CustomPattern{OwnerID: owner, Name: name, Pattern: "x", Keywords: EncodeKeywords([]string{"abc", "def"}), Enabled: enabled}
		require.NoError(t, db.Insert(ctx, p))
		if deleted != 0 {
			_, err := db.GetEngine(ctx).Exec("UPDATE secret_custom_pattern SET deleted_unix = ? WHERE id = ?", deleted, p.ID)
			require.NoError(t, err)
		}
		return p
	}
	site := add(0, "site", true, 0)
	siteOff := add(0, "site off", false, 0)
	org := add(7, "org", true, 0)
	add(7, "org gone", true, 5)
	add(8, "other org", true, 0)

	got, err := FindActiveCustomPatterns(ctx, 0, 7)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, []int64{site.ID, org.ID}, []int64{got[0].ID, got[1].ID}, "the site's first")
	assert.Equal(t, []string{"abc", "def"}, got[0].KeywordList())
	n, err := CountActiveCustomPatterns(ctx, 0, 7)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)
	live, err := FindCustomPatterns(ctx, 7)
	require.NoError(t, err)
	assert.Len(t, live, 1)

	p, err := GetCustomPattern(ctx, 7, site.ID)
	require.NoError(t, err)
	assert.Nil(t, p, "another owner's pattern is not found")
	p, err = GetCustomPattern(ctx, 0, siteOff.ID)
	require.NoError(t, err)
	require.NotNil(t, p)

	byID, err := GetCustomPatternsByIDs(ctx, []int64{site.ID, org.ID, 99999})
	require.NoError(t, err)
	assert.Len(t, byID, 2)
	byID, err = GetCustomPatternsByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, byID)
	assert.Empty(t, (&CustomPattern{Keywords: "not json"}).KeywordList())
}
