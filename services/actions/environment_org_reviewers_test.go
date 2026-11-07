// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reviewers of an organization environment are members and teams of the organization (3: members 2, 4 and 28,
// teams 1, 2, 7, 12 and 14), whoever saves.
func TestSaveOrgEnvironmentReviewers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: 1}})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	e := func() *actions_model.ActionEnvironment {
		return &actions_model.ActionEnvironment{OwnerID: 3, Name: "prod"}
	}

	for _, id := range []int64{1, 5, 24} {
		_, err := SaveEnvironment(ctx, admin, e(), []int64{2, id}, nil)
		require.ErrorIs(t, err, ErrReviewerNotMember, "user %d", id)
	}
	_, err := SaveEnvironment(ctx, admin, e(), nil, []int64{3}) // a team of organization 6
	require.ErrorIs(t, err, ErrUnknownReviewer)
	unittest.AssertNotExistsBean(t, &actions_model.ActionEnvironment{OwnerID: 3, LowerName: "prod"})

	created, err := SaveEnvironment(ctx, admin, e(), []int64{4, 28}, []int64{2})
	require.NoError(t, err)
	assert.True(t, created)
	env := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionEnvironment{OwnerID: 3, LowerName: "prod"})
	assert.True(t, env.ReviewsRequired)
	reviewers, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
	require.NoError(t, err)
	var keys []string
	for _, r := range reviewers {
		keys = append(keys, r.Key())
	}
	assert.ElementsMatch(t, []string{"team:2", "user:4", "user:28"}, keys)

	// a team's deletion removes it from the reviewers (recorded on the organization)
	since := auditSince(t)
	require.NoError(t, actions_model.RemoveReviewers(ctx, actions_model.TeamReviewerCond(2)))
	reviewers, err = actions_model.FindEnvironmentReviewers(ctx, env.ID)
	require.NoError(t, err)
	assert.Len(t, reviewers, 2)
	var actions []string
	require.NoError(t, db.GetEngine(ctx).Table("audit_event").Where("id > ?", since).Cols("action").Find(&actions))
	assert.Equal(t, []string{"org.actions_env.updated"}, actions)
}

// The organization's settings page decides its reviewers by the rules that don't depend on a repository.
func TestCheckOrgEnvironmentReviewers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	_, err := db.GetEngine(ctx).ID(28).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
	require.NoError(t, err)
	env := &actions_model.ActionEnvironment{ID: 1, OwnerID: 3, ReviewsRequired: true}
	reviewers := map[int64][]*actions_model.ActionEnvironmentReviewer{1: {{UserID: 4}, {UserID: 5}, {UserID: 28}, {TeamID: 7}}}

	check, err := CheckOrgEnvironmentReviewers(ctx, org, []*actions_model.ActionEnvironment{env}, reviewers)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"user:5": ReviewerOutsider, "user:28": ReviewerNotUsable, "team:7": ReviewerNoneInTeam}, check.Ineligible)
	assert.False(t, check.NoReviewer[1])
	var readers []int64
	for _, u := range check.Readers {
		readers = append(readers, u.ID)
	}
	assert.Equal(t, []int64{2, 4}, readers, "usable members, in name order")
	assert.Equal(t, []int64{4}, check.Approvers[1])

	// the organization requires two-factor authentication, which nobody here has
	org.RequireTwoFactor = true
	check, err = CheckOrgEnvironmentReviewers(ctx, org, []*actions_model.ActionEnvironment{env}, reviewers)
	require.NoError(t, err)
	assert.Equal(t, ReviewerTwoFactor, check.Ineligible["user:4"])
	assert.True(t, check.NoReviewer[1])
	assert.Empty(t, check.Readers)
}

// A user who is the only one who can approve an organization environment (in any repository of the organization)
// is its last approver.
func TestFindOrgEnvironmentLastApprovers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions}))
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 3, UserID: 4, Mode: perm.AccessModeRead}))
	env := &actions_model.ActionEnvironment{OwnerID: 3, Name: "prod"}
	require.NoError(t, actions_model.CreateEnvironment(ctx, env, []actions_model.ActionEnvironmentReviewer{{UserID: 4}, {UserID: 5}}))

	found, err := FindEnvironmentLastApprovers(ctx, []int64{4})
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, env.ID, found[0].Env.ID)
	assert.Nil(t, found[0].Repo)
	assert.EqualValues(t, 3, found[0].Org.ID)
	found, err = FindEnvironmentLastApprovers(ctx, []int64{5})
	require.NoError(t, err)
	assert.Empty(t, found, "user 5 can't approve in any repository of the organization")
}
