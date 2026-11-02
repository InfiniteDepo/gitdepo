// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package accessreport

import (
	"fmt"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

// addPathCases adds the access paths the fixtures don't cover, and returns the IDs of the auditor and of the
// group-synced team member.
func addPathCases(t *testing.T) (auditorID, groupMemberID int64) {
	t.Helper()
	ctx := db.DefaultContext
	e := db.GetEngine(ctx)

	// user 5 is a member of team 2 (org 3) through a user group synced by an LDAP source
	source := &auth_model.Source{Type: auth_model.LDAP, Name: "corp-ldap", IsActive: true}
	require.NoError(t, auth_model.CreateSource(ctx, source))
	group := &organization.UserGroup{Name: "platform-devs"}
	require.NoError(t, organization.InsertUserGroup(ctx, group))
	require.NoError(t, organization.InsertUserGroupMember(ctx, group.ID, 5, source.ID))
	team2 := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, organization.InsertUserGroupTeam(ctx, group.ID, team2, organization.LinkManual))
	require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: 3, TeamID: 2, UID: 5, Reason: organization.MembershipReasonAddedByUserGroup}))
	require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: 3, UID: 5}))
	// and a read collaborator on repo 3, which team 2 has with write, but only read on issues: a collaborator gets
	// the access table's write on every unit
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 3, UserID: 5, Mode: perm_model.AccessModeRead}))
	_, err := e.Exec("UPDATE team_unit SET access_mode = ? WHERE team_id = 2 AND type = ?", perm_model.AccessModeRead, unit.TypeIssues)
	require.NoError(t, err)

	// user 4 is a member of the admin team 12 (org 3), which has repo 3
	require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: 12, RepoID: 3}))
	require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: 3, TeamID: 12, UID: 4}))

	// the restricted user 29 is a read collaborator on the public repo 1
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 1, UserID: 29, Mode: perm_model.AccessModeRead}))

	// a public org repo with a globally writeable wiki and a read collaborator
	writeable := &repo_model.Repository{}
	has, err := e.Where("is_private = ? AND owner_id = ?", false, 3).Get(writeable)
	require.NoError(t, err)
	require.True(t, has)
	_, err = e.Exec("UPDATE repo_unit SET default_permissions = ? WHERE repo_id = ?", repo_model.UnitAccessModeWrite, writeable.ID)
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: writeable.ID, UserID: 10, Mode: perm_model.AccessModeRead}))

	// a public repo in the private org 23, and user 10, a member of the org in no team
	_, err = e.Exec("UPDATE repository SET is_private = ? WHERE id = (SELECT MIN(id) FROM repository WHERE owner_id = 23)", false)
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: 23, UID: 10}))

	// user 8 is an auditor
	_, err = e.Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
	require.NoError(t, err)

	repos := make([]*repo_model.Repository, 0, 70)
	require.NoError(t, e.Find(&repos))
	for _, repo := range repos {
		require.NoError(t, access_model.RecalculateAccesses(ctx, repo))
	}
	return 8, 5
}

// effective finds the access of the user (nil for anonymous) to the repo in the rows: their own row, or else the
// pseudo-row that applies to them.
func effective(t *testing.T, rows []*Row, repo *repo_model.Repository, u *user_model.User) access_model.Permission {
	t.Helper()
	var pseudo *Row
	for _, r := range rows {
		if r.Repo.ID != repo.ID || r.DeployKey != nil {
			continue
		}
		switch {
		case u == nil && r.Anonymous:
			return r.Perm
		case u != nil && r.User != nil && r.User.ID == u.ID:
			return r.Perm
		case r.User == nil && !r.Anonymous:
			pseudo = r
		}
	}
	if u == nil || pseudo == nil || u.IsRestricted {
		return access_model.Permission{}
	}
	if pseudo.Paths[0].Kind == KindOrgMember {
		isMember, err := organization.IsOrganizationMember(db.DefaultContext, repo.OwnerID, u.ID)
		require.NoError(t, err)
		blocked, err := u.TwoFactorBlocked(db.DefaultContext, repo.Owner)
		require.NoError(t, err)
		if !isMember || blocked {
			return access_model.Permission{}
		}
	}
	return pseudo.Perm
}

func assertSamePerm(t *testing.T, expected, actual access_model.Permission, msg string) {
	t.Helper()
	assert.Equal(t, expected.AccessMode, actual.AccessMode, "%s: access mode", msg)
	for _, tp := range unit.AllRepoUnitTypes {
		assert.Equal(t, expected.UnitAccessMode(tp), actual.UnitAccessMode(tp), "%s: unit %s", msg, tp.LogString())
	}
}

func countRows(t *testing.T) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	for _, table := range []string{"access", "collaboration", "team_user", "team_repo", "org_user", "user_group_user", "user_group_team", "`user`", "repository"} {
		n, err := db.GetEngine(db.DefaultContext).Table(table).Count()
		require.NoError(t, err)
		counts[table] = n
	}
	return counts
}

func TestComputeMatchesGetUserRepoPermission(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	auditorID, _ := addPathCases(t)
	assertComputeMatches(t, auditorID)
}

// A team's rows through a linked project (via_group) count like any other team_repo row.
func TestComputeMatchesGetUserRepoPermissionViaGroup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	auditorID, _ := addPathCases(t)
	group := &repo_model.RepoGroup{OwnerID: 3, Name: "pay", LowerName: "pay"}
	require.NoError(t, db.Insert(ctx, group))
	_, err := db.GetEngine(ctx).Exec("UPDATE repository SET group_id = ?, group_name = ? WHERE id = 3", group.ID, group.Name)
	require.NoError(t, err)
	for _, teamID := range []int64{7, 12} { // a write and an admin team of org3, now with org3/repo3 only through the link
		require.NoError(t, db.Insert(ctx, &organization.TeamGroup{OrgID: 3, TeamID: teamID, GroupID: group.ID}))
		_, err := db.GetEngine(ctx).Delete(&organization.TeamRepo{TeamID: teamID, RepoID: 3})
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: teamID, RepoID: 3, ViaGroup: true}))
	}
	assertComputeMatches(t, auditorID)
}

func assertComputeMatches(t *testing.T, auditorID int64) {
	t.Helper()
	ctx := db.DefaultContext
	repos := make([]*repo_model.Repository, 0, 70)
	require.NoError(t, db.GetEngine(ctx).OrderBy("id").Find(&repos))
	users := make([]*user_model.User, 0, 50)
	require.NoError(t, db.GetEngine(ctx).In("type", user_model.UserTypeIndividual, user_model.UserTypeBot).OrderBy("id").Find(&users))
	repoIDs := make([]int64, len(repos))
	for i, r := range repos {
		repoIDs[i] = r.ID
	}

	before := countRows(t)
	rows, err := Compute(ctx, Options{RepoIDs: repoIDs})
	require.NoError(t, err)
	assert.Equal(t, before, countRows(t), "Compute writes nothing")

	for _, repo := range repos {
		expected, err := access_model.GetUserRepoPermission(ctx, repo, nil)
		require.NoError(t, err)
		assertSamePerm(t, expected, effective(t, rows, repo, nil), fmt.Sprintf("anonymous on repo %d", repo.ID))

		for _, u := range users {
			if u.ID == auditorID {
				expected, err = access_model.GetUserRepoReadPermission(ctx, repo, u, nil)
			} else {
				expected, err = access_model.GetUserRepoPermission(ctx, repo, u)
			}
			require.NoError(t, err)
			assertSamePerm(t, expected, effective(t, rows, repo, u), fmt.Sprintf("user %d on repo %d", u.ID, repo.ID))

			// the per-user report (user view) gives the same answer
			if u.ID%7 == 0 || u.ID == 5 || u.ID == 29 {
				userRows, err := Compute(ctx, Options{RepoIDs: []int64{repo.ID}, User: u})
				require.NoError(t, err)
				for _, r := range userRows {
					assertSamePerm(t, expected, r.Perm, fmt.Sprintf("user view: user %d on repo %d", u.ID, repo.ID))
				}
			}
		}
	}
}

func findRow(rows []*Row, repoID, uid int64) *Row {
	for _, r := range rows {
		if r.Repo.ID == repoID && r.User != nil && r.User.ID == uid {
			return r
		}
	}
	return nil
}

func findPath(r *Row, kind Kind) *Path {
	for _, p := range r.Paths {
		if p.Kind == kind {
			return p
		}
	}
	return nil
}

func TestPathThrough(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	_, groupMemberID := addPathCases(t)

	writeable := &repo_model.Repository{}
	_, err := db.GetEngine(ctx).Where("is_private = ? AND owner_id = ?", false, 3).Get(writeable)
	require.NoError(t, err)
	privateOrgRepo := &repo_model.Repository{}
	_, err = db.GetEngine(ctx).Where("owner_id = 23 AND is_private = ?", false).Get(privateOrgRepo)
	require.NoError(t, err)

	rows, err := Compute(ctx, Options{RepoIDs: []int64{1, 3, writeable.ID, privateOrgRepo.ID, 38}})
	require.NoError(t, err)

	t.Run("org owner", func(t *testing.T) {
		r := findRow(rows, 3, 2) // user 2 is in the owners team of org 3
		require.NotNil(t, r)
		p := findPath(r, KindOrgOwner)
		require.NotNil(t, p)
		assert.Equal(t, "Owners", p.Team.Name)
		assert.True(t, p.Applied)
	})

	t.Run("admin team wins, the others are not applied", func(t *testing.T) {
		r := findRow(rows, 3, 4)
		require.NotNil(t, r)
		p := findPath(r, KindAdminTeam)
		require.NotNil(t, p)
		assert.Equal(t, int64(12), p.Team.ID)
		assert.True(t, p.Applied)
		assert.Equal(t, perm_model.AccessModeAdmin, r.Perm.AccessMode)
		if c := findPath(r, KindCollaborator); c != nil {
			assert.False(t, c.Applied)
		}
	})

	t.Run("team through a synced user group", func(t *testing.T) {
		r := findRow(rows, 3, groupMemberID)
		require.NotNil(t, r)
		p := findPath(r, KindTeam)
		require.NotNil(t, p)
		assert.Equal(t, int64(2), p.Team.ID)
		require.Len(t, p.Groups, 1)
		assert.Equal(t, "platform-devs", p.Groups[0].Group.Name)
		require.NotNil(t, p.Groups[0].Source)
		assert.Equal(t, "corp-ldap", p.Groups[0].Source.Name)
	})

	t.Run("collaborator on a user repo, and its owner", func(t *testing.T) {
		r := findRow(rows, 1, 29)
		require.NotNil(t, r)
		p := findPath(r, KindCollaborator)
		require.NotNil(t, p)
		assert.Equal(t, perm_model.AccessModeRead, p.Mode)
		assert.Nil(t, findPath(r, KindPublic), "restricted users get no public defaults")

		r = findRow(rows, 1, 2)
		require.NotNil(t, r)
		assert.NotNil(t, findPath(r, KindOwnerUser))
	})

	t.Run("public default not applied over a read collaborator", func(t *testing.T) {
		r := findRow(rows, writeable.ID, 10)
		require.NotNil(t, r)
		assert.True(t, findPath(r, KindCollaborator).Applied)
		pub := findPath(r, KindPublic)
		require.NotNil(t, pub)
		require.NotEmpty(t, r.Repo.Units)
		tp := r.Repo.Units[0].Type
		assert.Equal(t, perm_model.AccessModeWrite, pub.Units[tp])
		assert.Equal(t, perm_model.AccessModeRead, r.Perm.UnitAccessMode(tp))
	})

	t.Run("public and internal pseudo-rows", func(t *testing.T) {
		kinds := map[int64][]Kind{}
		for _, r := range rows {
			if r.User == nil && r.DeployKey == nil {
				kinds[r.Repo.ID] = append(kinds[r.Repo.ID], r.Paths[0].Kind)
			}
		}
		assert.ElementsMatch(t, []Kind{KindPublic, KindPublic}, kinds[1], "anyone and any signed-in user")
		assert.Empty(t, kinds[3], "private repo")
		assert.Equal(t, []Kind{KindOrgMember}, kinds[privateOrgRepo.ID], "private org: any member")
		limited := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 38})
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: limited.OwnerID})
		if owner.Visibility == structs.VisibleTypeLimited && !limited.IsPrivate {
			assert.Equal(t, []Kind{KindInternal}, kinds[38], "limited org: any signed-in user only")
		}
	})

	t.Run("member of a private org has no row of their own", func(t *testing.T) {
		assert.Nil(t, findRow(rows, privateOrgRepo.ID, 10))
	})

	t.Run("site admin", func(t *testing.T) {
		r := findRow(rows, 3, 1)
		require.NotNil(t, r)
		assert.True(t, findPath(r, KindSiteAdmin).Applied)

		plain, err := Compute(ctx, Options{RepoIDs: []int64{3}, Plain: true})
		require.NoError(t, err)
		assert.Nil(t, findRow(plain, 3, 1), "plain reports leave out site admins")
	})
}

// the replay follows the organizations' two-factor requirement
func TestComputeMatchesGetUserRepoPermissionTwoFactorRequired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	auditorID, _ := addPathCases(t)
	flagged := []int64{3, 17, 22, 23}
	_, err := db.GetEngine(ctx).In("id", flagged).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &auth_model.TwoFactor{UID: 4}))
	require.NoError(t, db.Insert(ctx, &auth_model.WebAuthnCredential{UserID: 15, Name: "key", CredentialID: []byte("cred-15")}))

	repos := make([]*repo_model.Repository, 0, 20)
	require.NoError(t, db.GetEngine(ctx).In("owner_id", flagged).OrderBy("id").Find(&repos))
	users := make([]*user_model.User, 0, 50)
	require.NoError(t, db.GetEngine(ctx).In("type", user_model.UserTypeIndividual, user_model.UserTypeBot).OrderBy("id").Find(&users))
	repoIDs := make([]int64, len(repos))
	for i, r := range repos {
		repoIDs[i] = r.ID
	}
	rows, err := Compute(ctx, Options{RepoIDs: repoIDs})
	require.NoError(t, err)

	for _, repo := range repos {
		for _, u := range users {
			var expected access_model.Permission
			if u.ID == auditorID {
				expected, err = access_model.GetUserRepoReadPermission(ctx, repo, u, nil)
			} else {
				expected, err = access_model.GetUserRepoPermission(ctx, repo, u)
			}
			require.NoError(t, err)
			assertSamePerm(t, expected, effective(t, rows, repo, u), fmt.Sprintf("user %d on repo %d", u.ID, repo.ID))
		}
	}
	// user 4 has TOTP: still writes repo 3 through team1; user 2's paths to repo 3 no longer apply
	assert.True(t, findRow(rows, 3, 4).Perm.CanWrite(unit.TypeCode))
	assert.False(t, findRow(rows, 3, 2).Perm.HasAccess())
	assert.False(t, findPath(findRow(rows, 3, 2), KindTeam).Applied)
}
