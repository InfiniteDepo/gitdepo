// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git_test

import (
	"testing"

	git_model "forgejo.org/models/git"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeMergeStyles(t *testing.T) {
	got, err := git_model.NormalizeMergeStyles([]string{"squash", "merge", "squash"}, "squash")
	require.NoError(t, err)
	assert.Equal(t, []string{"merge", "squash"}, got, "fixed order, no duplicates")

	got, err = git_model.NormalizeMergeStyles(nil, "")
	require.NoError(t, err)
	assert.Nil(t, got)

	for _, c := range []struct {
		styles []string
		def    string
	}{
		{[]string{"merge", "rebase-update-only"}, ""}, // not a merge style
		{[]string{"merge", ""}, ""},
		{[]string{"nope"}, ""},
		{[]string{"merge"}, "squash"}, // default outside the list
		{nil, "merge"},                // a default needs a list
	} {
		_, err := git_model.NormalizeMergeStyles(c.styles, c.def)
		require.ErrorIs(t, err, util.ErrInvalidArgument, "%v %q", c.styles, c.def)
	}
}

func TestMergeStyleConflicts(t *testing.T) {
	rule := func(repoID, groupID, orgID int64, name string, styles ...string) *git_model.ProtectedBranch {
		return &git_model.ProtectedBranch{RepoID: repoID, GroupID: groupID, OrgID: orgID, RuleName: name, AllowedMergeStyles: styles}
	}
	repoRule := rule(1, 0, 0, "main", "merge")
	orgSame := rule(0, 0, 5, "main", "squash")
	orgGlob := rule(0, 0, 5, "ma*", "squash")
	orgOther := rule(0, 0, 5, "develop", "squash")
	orgShared := rule(0, 0, 5, "main", "merge", "squash")
	orgNone := rule(0, 0, 5, "main")
	repoSibling := rule(1, 0, 0, "ma*", "squash")

	assert.Equal(t, []*git_model.ProtectedBranch{orgSame, orgGlob}, git_model.MergeStyleConflicts(repoRule, []*git_model.ProtectedBranch{orgSame, orgGlob, orgOther, orgShared, orgNone, repoSibling}))
	assert.Empty(t, git_model.MergeStyleConflicts(rule(1, 0, 0, "main"), []*git_model.ProtectedBranch{orgSame}), "no styles, no conflict")
	assert.Equal(t, []*git_model.ProtectedBranch{repoRule}, git_model.MergeStyleConflicts(orgGlob, []*git_model.ProtectedBranch{repoRule}), "a plain name matched by the other's glob")
}

func TestMergeStyleShadowing(t *testing.T) {
	rule := func(id int64, name string, styles ...string) *git_model.ProtectedBranch {
		return &git_model.ProtectedBranch{ID: id, RepoID: 1, RuleName: name, AllowedMergeStyles: styles}
	}
	plain := rule(1, "main")
	glob := rule(2, "ma*", "squash")
	other := rule(3, "develop", "squash")
	orgRule := &git_model.ProtectedBranch{ID: 4, OrgID: 5, RuleName: "ma*", AllowedMergeStyles: []string{"squash"}}
	all := []*git_model.ProtectedBranch{glob, plain, other, orgRule}

	// the plain name matches first, so the glob's styles are ignored for "main"; the saved rule is either one
	want := [][2]*git_model.ProtectedBranch{{plain, glob}}
	assert.Equal(t, want, git_model.MergeStyleShadowing(glob, all))
	assert.Equal(t, want, git_model.MergeStyleShadowing(plain, all))
	assert.Empty(t, git_model.MergeStyleShadowing(other, all), "no other rule matches its names")
	assert.Empty(t, git_model.MergeStyleShadowing(glob, []*git_model.ProtectedBranch{glob, rule(5, "main", "squash")}), "same styles: nothing is dropped")
	assert.Empty(t, git_model.MergeStyleShadowing(plain, []*git_model.ProtectedBranch{plain, rule(6, "ma*")}), "the shadowed rule sets no styles")
}
