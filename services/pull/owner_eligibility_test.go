// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/translation"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type queryCounter struct{ n atomic.Int64 }

func (h *queryCounter) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	h.n.Add(1)
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
	run := func(n int) (int64, []LineOwnerMarks, time.Duration) {
		counter.n.Store(0)
		start := time.Now()
		marks, _, err := CodeOwnerLineMarks(ctx, repo, OwnerViewer{Details: true}, lines(n))
		require.NoError(t, err)
		return counter.n.Load(), marks, time.Since(start)
	}
	run(1) // warm up
	one, _, _ := run(1)
	many, marks, took := run(2000)
	assert.Equal(t, one, many, "the queries don't depend on the number of lines")
	assert.Less(t, took, 3*time.Second)
	t.Logf("2000 lines naming a team of %d members: %d queries, %v", members, many, took)
	require.NotEmpty(t, marks)
	assert.LessOrEqual(t, len(marks), maxOwnerMarks)
	assert.Len(t, marks[0].Marks, 1)
	assert.True(t, marks[0].Marks[0].Team, "one mark for the team")
	assert.NotContains(t, string(marks[0].Marks[0].Text(translation.MockLocale{})), "bulk")
}

// A team of another organization can never grant write: it is one mark and its members are not loaded.
func TestIneligibleOwnersForeignTeam(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // owned by user 2, not an organization
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	marks, _, err := CodeOwnerLineMarks(t.Context(), repo, OwnerViewer{Details: true}, []*issues_model.CodeOwnerRule{
		{Line: 1, Section: &issues_model.CodeOwnerSection{Required: 1}, Teams: []*organization.Team{team}},
	})
	require.NoError(t, err)
	require.Len(t, marks, 1)
	assert.True(t, marks[0].Marks[0].Foreign)
	assert.Equal(t, "@team1", marks[0].Marks[0].Name)
}
