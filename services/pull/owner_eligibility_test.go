// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"fmt"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/translation"
	"forgejo.org/services/approvers"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queryCounter counts queries until the test ends (xorm can't remove a hook, so it is switched off).
type queryCounter struct {
	n   atomic.Int64
	off atomic.Bool
}

func (h *queryCounter) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if !h.off.Load() {
		h.n.Add(1)
	}
	return db.TracingHook{}.BeforeProcess(c)
}
func (*queryCounter) AfterProcess(*contexts.ContextHook) error { return nil }

// The work of a CODEOWNERS view depends on the people named, not on how many lines name them: 2000 lines naming a
// team of 1500 members cost the same queries as one line, take about the time of a normal file view, and the team
// is one mark that names no member.
func TestCodeOwnerLineMarksBounded(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	// a team without access to the repository
	team := &organization.Team{OrgID: 3, Name: "bulkteam", LowerName: "bulkteam", AccessMode: perm.AccessModeRead}
	require.NoError(t, db.Insert(ctx, team))
	const members = 1500
	for i := range members {
		u := &user_model.User{Name: fmt.Sprintf("bulk%d", i), LowerName: fmt.Sprintf("bulk%d", i), Email: fmt.Sprintf("bulk%d@example.com", i), IsActive: true}
		require.NoError(t, db.Insert(ctx, u))
		require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: team.OrgID, TeamID: team.ID, UID: u.ID}))
	}
	lines := func(n int) []*issues_model.CodeOwnerRule {
		out := make([]*issues_model.CodeOwnerRule, n)
		section := &issues_model.CodeOwnerSection{Required: 1}
		for i := range out {
			out[i] = &issues_model.CodeOwnerRule{Line: i + 1, Section: section, Teams: []*organization.Team{team}}
		}
		return out
	}
	engine, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
	require.NoError(t, err)
	counter := &queryCounter{}
	engine.AddHook(counter)
	t.Cleanup(func() { counter.off.Store(true) })
	run := func(n int) (int64, []LineOwnerMarks, time.Duration) {
		counter.n.Store(0)
		start := time.Now()
		marks, _, err := CodeOwnerLineMarks(ctx, repo, OwnerViewer{Details: true}, lines(n))
		require.NoError(t, err)
		return counter.n.Load(), marks, time.Since(start)
	}
	run(1) // warm up
	// the counter is process-wide: a query of a background goroutine can land in one reading, so read until two agree
	stable := func(n int) (int64, []LineOwnerMarks, time.Duration) {
		prev, marks, took := run(n)
		for range 5 {
			cur, m, d := run(n)
			if cur == prev {
				return cur, m, d
			}
			prev, marks, took = cur, m, d
		}
		return prev, marks, took
	}
	one, _, _ := stable(1)
	many, marks, took := stable(2000)
	assert.Equal(t, one, many, "the queries don't depend on the number of lines")
	assert.Less(t, took, 3*time.Second)
	t.Logf("2000 lines naming a team of %d members: %d queries, %v", members, many, took)
	require.NotEmpty(t, marks)
	assert.LessOrEqual(t, len(marks), maxOwnerMarks)
	assert.Len(t, marks[0].Marks, 1)
	assert.True(t, marks[0].Marks[0].Team, "one mark for the team")
	assert.NotContains(t, string(marks[0].Marks[0].Text(translation.MockLocale{})), "bulk")
}

func ownerMarks(t *testing.T, repo *repo_model.Repository, v OwnerViewer, set OwnerSet) (OwnerCheck, bool) {
	t.Helper()
	checks, more, err := IneligibleOwners(t.Context(), repo, approvers.NewWriters(), v, []OwnerSet{set}, 1000)
	require.NoError(t, err)
	return checks[0], more
}

func reasonsOf(c OwnerCheck) map[string]OwnerReason {
	out := map[string]OwnerReason{}
	for _, m := range c.Marks {
		out[m.Name] = m.Reason
	}
	return out
}

func grantAccess(t *testing.T, repoID, uid int64, mode perm.AccessMode) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND user_id = ?", repoID, uid).Delete(&repo_model.Collaboration{})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND user_id = ?", repoID, uid).Delete(&access_model.Access{})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: repoID, UserID: uid, Mode: mode}))
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: repoID, UserID: uid, Mode: mode}))
}

// The reason a person can't approve is decided by its real cause: someone who would have no write access even if
// active, allowed to sign in and enrolled in two-factor is "no write access" for every viewer, so the reason can't
// be used to probe who has two-factor, or who is inactive, among people the repository doesn't know. The two-factor
// reason is only for someone who would otherwise write.
func TestIneligibleOwnersReasonByCause(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	org.RequireTwoFactor = true
	require.NoError(t, user_model.UpdateUserCols(ctx, org, "require_two_factor"))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // private, of org3
	for _, uid := range []int64{11, 12, 4} {                                   // enrolled; user 4 is not, and writes through team1
		if uid != 4 {
			require.NoError(t, db.Insert(ctx, &auth_model.TwoFactor{UID: uid, Secret: []byte("secret")}))
		}
	}
	grantAccess(t, 3, 10, perm.AccessModeRead) // read-only, without two-factor
	grantAccess(t, 3, 12, perm.AccessModeRead) // read-only, with two-factor
	all := OwnerViewer{Details: true, TwoFactor: true}
	set := OwnerSet{UserIDs: []int64{8, 11, 10, 12, 4, 9}}

	c, _ := ownerMarks(t, repo, all, set)
	assert.Equal(t, map[string]OwnerReason{
		"user8":  OwnerNoWrite, // outside, no two-factor
		"user11": OwnerNoWrite, // outside, with two-factor: the same
		"user10": OwnerNoWrite, // read-only member, no two-factor
		"user12": OwnerNoWrite, // read-only member, with two-factor: the same
		"user9":  OwnerNoWrite, // inactive, but never had access
		"user4":  OwnerTwoFactor,
	}, reasonsOf(c))

	// a code reader sees none of it
	c, _ = ownerMarks(t, repo, OwnerViewer{}, set)
	for _, r := range reasonsOf(c) {
		assert.Equal(t, OwnerReason(""), r)
	}
	// a repository admin sees the cause, but not the two-factor one
	c, _ = ownerMarks(t, repo, OwnerViewer{Details: true}, set)
	assert.Equal(t, OwnerReason(""), reasonsOf(c)["user4"])
	assert.Equal(t, OwnerNoWrite, reasonsOf(c)["user8"])

	// the state reasons apply once the person would write
	grantAccess(t, 3, 9, perm.AccessModeWrite)
	c, _ = ownerMarks(t, repo, all, set)
	assert.Equal(t, OwnerInactive, reasonsOf(c)["user9"])
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
	grantAccess(t, 3, 10, perm.AccessModeWrite)
	user.ProhibitLogin = true
	require.NoError(t, user_model.UpdateUserCols(ctx, user, "prohibit_login"))
	c, _ = ownerMarks(t, repo, all, set)
	assert.Equal(t, OwnerProhibited, reasonsOf(c)["user10"])
}

// A team is one mark named org/team: a reader sees it only when no member can approve (an empty team too) and never
// a count; a repository admin also sees how many can when only some can.
func TestIneligibleOwnersTeamMarks(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}) // team1: users 2 and 4, write
	empty := &organization.Team{OrgID: 3, Name: "empty", LowerName: "empty", AccessMode: perm.AccessModeWrite}
	require.NoError(t, db.Insert(ctx, empty))
	set := OwnerSet{Teams: []*organization.Team{team, empty}}
	admin, reader := OwnerViewer{Details: true}, OwnerViewer{}

	c, _ := ownerMarks(t, repo, admin, set)
	require.Len(t, c.Marks, 1, "the team with its members able to approve has no mark")
	assert.Equal(t, OwnerMark{Name: "org3/empty", Team: true}, c.Marks[0], "named org/team, with no member able to approve")
	assert.Equal(t, []string{"org3/team1"}, c.Can)

	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	u.IsActive = false
	require.NoError(t, user_model.UpdateUserCols(ctx, u, "is_active"))
	c, _ = ownerMarks(t, repo, admin, set)
	assert.Equal(t, []OwnerMark{{Name: "org3/team1", Team: true, Eligible: 1}, {Name: "org3/empty", Team: true}}, c.Marks, "an admin sees how many can")
	c, _ = ownerMarks(t, repo, reader, set)
	assert.Equal(t, []OwnerMark{{Name: "org3/empty", Team: true}}, c.Marks, "a reader sees no mark for a team where someone can approve, and no count")

	u = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	u.IsActive = false
	require.NoError(t, user_model.UpdateUserCols(ctx, u, "is_active"))
	c, _ = ownerMarks(t, repo, reader, set)
	assert.Equal(t, []OwnerMark{{Name: "org3/team1", Team: true}, {Name: "org3/empty", Team: true}}, c.Marks)
}

// The team membership of the approvers is read once for all lines, not once per approver per line.
func TestUnmetLinesQueriesIndependentOfApprovers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	section := &issues_model.CodeOwnerSection{Required: 1}
	rules := make([]*issues_model.CodeOwnerRule, 30)
	for i := range rules {
		rules[i] = &issues_model.CodeOwnerRule{Line: i + 1, Section: section, Rule: regexp.MustCompile(".*"), Teams: []*organization.Team{team}}
	}
	engine, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
	require.NoError(t, err)
	counter := &queryCounter{}
	engine.AddHook(counter)
	t.Cleanup(func() { counter.off.Store(true) })
	run := func(people []*user_model.User) (int64, int) {
		counter.n.Store(0)
		s := &ApprovalRuleStatus{Rule: &git_model.ApprovalRule{}, Approvers: people, files: []string{"a"}, codeOwners: &issues_model.CodeOwners{Rules: rules}}
		lines, err := s.unmetLines(ctx)
		require.NoError(t, err)
		return counter.n.Load(), len(lines)
	}
	few := []*user_model.User{unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})}
	var many []*user_model.User
	for _, id := range []int64{2, 4, 5, 8, 10, 11, 12, 13, 15, 16} {
		many = append(many, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id}))
	}
	run(few) // warm up
	q1, n1 := run(few)
	q2, n2 := run(many)
	assert.Equal(t, q1, q2)
	assert.Equal(t, 1, int(q1))
	assert.Zero(t, n1, "user 4 is in the team: every line is covered")
	assert.Zero(t, n2)
	q3, n3 := run([]*user_model.User{many[3]}) // user 8 is no member
	assert.Equal(t, 1, int(q3))
	assert.Equal(t, 30, n3, "no line is dropped past a hundred or any other number")
}
