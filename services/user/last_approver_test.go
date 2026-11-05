// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/translation"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countHook counts queries until the test ends (xorm can't remove a hook, so it is switched off).
type countHook struct {
	n   atomic.Int64
	off atomic.Bool
}

func (h *countHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if !h.off.Load() {
		h.n.Add(1)
	}
	return db.TracingHook{}.BeforeProcess(c)
}
func (*countHook) AfterProcess(*contexts.ContextHook) error { return nil }

// grantWrite makes the user a collaborator with write access to repository 1.
func grantWrite(t *testing.T, uid int64) {
	t.Helper()
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: uid, Mode: perm.AccessModeWrite}))
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: uid, Mode: perm.AccessModeWrite}))
}

func addRule(t *testing.T, pb *git_model.ProtectedBranch, rule *git_model.ApprovalRule) {
	t.Helper()
	require.NoError(t, db.Insert(t.Context(), pb))
	rule.ProtectedBranchID = pb.ID
	require.NoError(t, db.Insert(t.Context(), rule))
}

func TestLastApproverWarnings(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	translation.InitLocales(t.Context())
	ctx := t.Context()
	kinds := func(userIDs ...int64) map[string]string {
		w, err := LastApproverWarnings(ctx, userIDs)
		require.NoError(t, err)
		got := map[string]string{}
		for _, x := range w {
			assert.Contains(t, userIDs, x.UserID)
			got[x.Name] = x.Kind + " " + x.Link
		}
		return got
	}

	// users 4 and 5 can write repository 1
	for _, uid := range []int64{4, 5} {
		grantWrite(t, uid)
	}
	// a repository rule listing user 4 only, an organization rule listing team 2 (users 2 and 4) with 2 approvals,
	// and a repository rule that user 4 shares with user 5
	addRule(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: "main"}, &git_model.ApprovalRule{Name: "Lead", RequiredCount: 1, UserIDs: []int64{4}})
	addRule(t, &git_model.ProtectedBranch{OrgID: 3, RuleName: "release"}, &git_model.ApprovalRule{Name: "Team", RequiredCount: 2, TeamIDs: []int64{2}})
	addRule(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: "dev"}, &git_model.ApprovalRule{Name: "Pair", RequiredCount: 1, UserIDs: []int64{4, 5}})

	got := kinds(4)
	assert.Equal(t, map[string]string{
		`Approval rule Lead of branch rule main in user2/repo1`: "admin.users.last_approver.kind.repo_rule /user2/repo1/settings/branches/edit?rule_name=main",
		`Approval rule Team of branch rule release in org3`:     "admin.users.last_approver.kind.org_rule /org/org3/settings/branches/edit?rule_name=release",
	}, got, "the shared rule keeps user 5, so it is no warning")

	// user 5 loses write access to the repository: they no longer count as remaining approver of the pair
	_, err := db.GetEngine(ctx).Where("repo_id = 1 AND user_id = 5").Delete(&repo_model.Collaboration{})
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Where("repo_id = 1 AND user_id = 5").Delete(&access_model.Access{})
	require.NoError(t, err)
	assert.Contains(t, kinds(4), `Approval rule Pair of branch rule dev in user2/repo1`)
	grantWrite(t, 5)
	assert.NotContains(t, kinds(4), `Approval rule Pair of branch rule dev in user2/repo1`)

	// via team: user 2 is in team 2 as well
	assert.Equal(t, []string{`Approval rule Team of branch rule release in org3`}, keysOf(kinds(2)))
	// both users leave: the pair is empty too
	assert.Len(t, kinds(4, 5), 3)
	assert.Empty(t, kinds(8), "a user no rule lists")

	// the user is already unable to sign in: nothing changes by leaving
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	u.IsActive = false
	require.NoError(t, user_model.UpdateUserCols(ctx, u, "is_active"))
	assert.Empty(t, kinds(4))
	u.IsActive = true
	require.NoError(t, user_model.UpdateUserCols(ctx, u, "is_active"))

	t.Run("queries do not grow with the rules", func(t *testing.T) {
		engine, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
		require.NoError(t, err)
		h := &countHook{}
		engine.AddHook(h)
		t.Cleanup(func() { h.off.Store(true) })
		count := func() int64 {
			h.n.Store(0)
			_, err := LastApproverWarnings(ctx, []int64{4})
			require.NoError(t, err)
			return h.n.Load()
		}
		// one rule of every level first: each kind of rule adds its fixed queries once
		require.NoError(t, db.Insert(ctx, &repo_model.RepoGroup{OwnerID: 3, Name: "proj", LowerName: "proj"}))
		group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: 3, LowerName: "proj"})
		more := func(i int) {
			addRule(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: fmt.Sprintf("extra-%d", i)}, &git_model.ApprovalRule{Name: "Extra", RequiredCount: 1, UserIDs: []int64{4}})
			addRule(t, &git_model.ProtectedBranch{RepoID: 3, RuleName: fmt.Sprintf("extra-%d", i)}, &git_model.ApprovalRule{Name: "Extra", RequiredCount: 1, UserIDs: []int64{4}})
			addRule(t, &git_model.ProtectedBranch{OrgID: 3, GroupID: group.ID, RuleName: fmt.Sprintf("proj-%d", i)}, &git_model.ApprovalRule{Name: "Extra", RequiredCount: 1, UserIDs: []int64{4}})
			addRule(t, &git_model.ProtectedBranch{OrgID: 3, RuleName: fmt.Sprintf("org-%d", i)}, &git_model.ApprovalRule{Name: "Extra", RequiredCount: 1, UserIDs: []int64{4}})
		}
		more(0)
		count() // warm up
		before := count()
		for i := 1; i < 5; i++ {
			more(i)
		}
		h.n.Store(0)
		w, err := LastApproverWarnings(ctx, []int64{4})
		require.NoError(t, err)
		assert.Greater(t, len(w), 12)
		names := map[string]string{}
		for _, x := range w {
			names[x.Name] = x.Kind
		}
		assert.Equal(t, "admin.users.last_approver.kind.project_rule", names["Approval rule Extra of branch rule proj-0 in org3/proj"], "a project rule names its project")
		assert.Equal(t, before, count(), "the same number of queries with more rules, repositories and levels")
	})
}

func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
