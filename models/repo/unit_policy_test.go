// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func setUnitPolicy(t *testing.T, p setting.RepoUnitPolicyState) {
	t.Helper()
	v, err := json.Marshal(p)
	require.NoError(t, err)
	setRawUnitPolicy(t, string(v))
}

var lastSettingsRevision int

// setRawUnitPolicy stores v under a revision no earlier test used: fixtures reset the revision, and a cached value
// of the same revision would win
func setRawUnitPolicy(t *testing.T, v string) {
	t.Helper()
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().RepoUnitPolicy.DynKey(): v}))
	for system_model.GetRevision(db.DefaultContext) <= lastSettingsRevision {
		require.NoError(t, system_model.SetSettings(db.DefaultContext, nil))
	}
	lastSettingsRevision = system_model.GetRevision(db.DefaultContext)
	config.GetDynGetter().InvalidateCache()
}

func TestOrgAllowed(t *testing.T) {
	p := setting.RepoUnitPolicyState{
		NotAllowed:   []string{"repo.issues"},
		OrgOverrides: map[string][]int64{"repo.issues": {3}, "repo.wiki": {6}},
	}
	assert.True(t, p.OrgAllowed("repo.issues", 3))
	assert.False(t, p.OrgAllowed("repo.issues", 6))
	assert.False(t, p.OrgAllowed("repo.wiki", 6))
	assert.True(t, p.OrgAllowed("repo.wiki", 3))
	assert.True(t, p.OrgAllowed("repo.projects", 3))
	assert.True(t, setting.RepoUnitPolicyState{}.OrgAllowed("repo.issues", 3))
	assert.False(t, setting.RepoUnitPolicyState{Invalid: true}.OrgAllowed("repo.issues", 3))
}

// HiddenUnitCond must match HiddenUnits for every owner and unit
func TestHiddenUnitCondMatchesHiddenUnits(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer setUnitPolicy(t, setting.RepoUnitPolicyState{})

	var owners []*user_model.User
	require.NoError(t, db.GetEngine(db.DefaultContext).Find(&owners))
	// org owners' choices: org3 turned Wiki off and Projects back on, org6 turned Issues off
	unittest.AssertSuccessfulInsert(t,
		&repo_model.OrgUnit{OrgID: 3, Type: unit.TypeWiki, Disabled: true},
		&repo_model.OrgUnit{OrgID: 3, Type: unit.TypeProjects, Disabled: false},
		&repo_model.OrgUnit{OrgID: 6, Type: unit.TypeIssues, Disabled: true},
	)
	defer db.DeleteAllRecords("org_unit")

	for name, p := range map[string]setting.RepoUnitPolicyState{
		"empty":       {},
		"corrupt":     {Invalid: true},
		"not allowed": {NotAllowed: []string{"repo.issues", "repo.packages"}},
		"overrides": {
			NotAllowed:   []string{"repo.issues"},
			OrgOverrides: map[string][]int64{"repo.issues": {3, 999999}, "repo.wiki": {3, 6}},
		},
		"everything": {NotAllowed: []string{"repo.issues", "repo.ext_issues", "repo.pulls", "repo.releases", "repo.wiki", "repo.ext_wiki", "repo.projects", "repo.packages", "repo.actions"}},
	} {
		t.Run(name, func(t *testing.T) {
			if p.Invalid {
				setRawUnitPolicy(t, `{"not_allowed": 5`)
				require.True(t, setting.Config().RepoUnitPolicy.Value(db.DefaultContext).Invalid)
			} else {
				setUnitPolicy(t, p)
			}
			for _, owner := range owners {
				hidden := repo_model.HiddenUnits(db.DefaultContext, owner)
				for _, tp := range unit.AllRepoUnitTypes {
					cond := repo_model.HiddenUnitTypeCond(db.DefaultContext, "`user`.id", tp)
					got := false
					if cond.IsValid() {
						var err error
						got, err = db.GetEngine(db.DefaultContext).Table("user").Where("`user`.id = ?", owner.ID).And(cond).Exist()
						require.NoError(t, err)
					}
					// the column form gives the same answer on repo_unit rows
					if colCond := repo_model.HiddenUnitCond(db.DefaultContext, "`repository`.owner_id", "`repo_unit`.type"); colCond.IsValid() {
						all, err := db.GetEngine(db.DefaultContext).Table("repo_unit").Join("INNER", "repository", "`repository`.id = `repo_unit`.repo_id").
							Where(builder.Eq{"`repository`.owner_id": owner.ID, "`repo_unit`.type": tp}).Count()
						require.NoError(t, err)
						matched, err := db.GetEngine(db.DefaultContext).Table("repo_unit").Join("INNER", "repository", "`repository`.id = `repo_unit`.repo_id").
							Where(builder.Eq{"`repository`.owner_id": owner.ID, "`repo_unit`.type": tp}).And(colCond).Count()
						require.NoError(t, err)
						assert.Equal(t, map[bool]int64{true: all, false: 0}[hidden.Contains(tp)], matched, "owner %s unit %s column form", owner.Name, tp)
					}
					assert.Equal(t, hidden.Contains(tp), got, "owner %s unit %s", owner.Name, tp)
				}
			}
		})
	}
}

// The conditions are plain SQL on every database: no unit type or ID is written as an identifier
func TestHiddenUnitCondSQL(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer setUnitPolicy(t, setting.RepoUnitPolicyState{})
	setUnitPolicy(t, setting.RepoUnitPolicyState{NotAllowed: []string{"repo.issues"}, OrgOverrides: map[string][]int64{"repo.issues": {3}, "repo.wiki": {6}}})

	for _, cond := range []builder.Cond{
		repo_model.HiddenUnitCond(db.DefaultContext, "`repository`.owner_id", "`repo_unit`.type"),
		repo_model.HiddenUnitTypeCond(db.DefaultContext, "`repository`.owner_id", unit.TypeIssues),
		repo_model.AvailableUnitTypeCond(db.DefaultContext, "`repository`.owner_id", unit.TypeWiki),
	} {
		sql, _, err := builder.ToSQL(cond)
		require.NoError(t, err)
		assert.NotRegexp(t, `[`+"`"+`"'][0-9]+[`+"`"+`"']|(^|[ (])[0-9]+ *=`, sql)
	}
}

// The organization owner's off rows hide a unit, and SetOrgUnits refuses what the owner may not change
func TestOrgUnits(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer setUnitPolicy(t, setting.RepoUnitPolicyState{})
	defer db.DeleteAllRecords("org_unit")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})

	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit.Type]bool{unit.TypeIssues: false, unit.TypeWiki: true}))
	row := unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeIssues})
	assert.True(t, row.Disabled)
	assert.EqualValues(t, 2, row.UpdatedBy)
	assert.True(t, repo_model.HiddenUnits(db.DefaultContext, org3).Contains(unit.TypeIssues))
	assert.False(t, repo_model.HiddenUnits(db.DefaultContext, org3).Contains(unit.TypeWiki))
	orgRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	assert.False(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypeIssues))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeIssues})

	// back on: the row stays with who and when
	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 1, map[unit.Type]bool{unit.TypeIssues: true}))
	row = unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeIssues})
	assert.False(t, row.Disabled)
	assert.EqualValues(t, 1, row.UpdatedBy)
	orgRepo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	assert.True(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypeIssues))

	// refused: Code, an unknown unit, a unit Not allowed by the site
	for _, tp := range []unit.Type{unit.TypeCode, unit.Type(99)} {
		require.ErrorIs(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit.Type]bool{tp: false}), util.ErrInvalidArgument)
	}
	setUnitPolicy(t, setting.RepoUnitPolicyState{NotAllowed: []string{"repo.packages"}})
	require.ErrorIs(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit.Type]bool{unit.TypePackages: true}), util.ErrInvalidArgument)
	unittest.AssertNotExistsBean(t, &repo_model.OrgUnit{OrgID: 3, Type: unit.TypePackages})
}

// An empty policy adds no condition until an organization turns a unit off
func TestOrgUnitCondFastPath(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer db.DeleteAllRecords("org_unit")
	setUnitPolicy(t, setting.RepoUnitPolicyState{})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	sql := func() string {
		s, err := builder.ToBoundSQL(builder.And(
			repo_model.AvailableUnitCond(db.DefaultContext, "`repository`.owner_id", "`repo_unit`.type"),
			repo_model.AvailableUnitTypeCond(db.DefaultContext, "`repository`.owner_id", unit.TypeIssues),
		))
		require.NoError(t, err)
		return s
	}

	assert.Empty(t, sql())
	// a row that turns a unit back on changes nothing
	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit.Type]bool{unit.TypeWiki: false}))
	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit.Type]bool{unit.TypeWiki: true}))
	assert.Empty(t, sql())

	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit.Type]bool{unit.TypeWiki: false}))
	assert.Contains(t, sql(), "org_unit")
}

func TestLoadUnitsHidesPolicyUnits(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer setUnitPolicy(t, setting.RepoUnitPolicyState{})
	setUnitPolicy(t, setting.RepoUnitPolicyState{NotAllowed: []string{"repo.issues"}})

	orgRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})  // org3
	userRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // user2
	// the owner is read in the query, never from repo.Owner
	require.Nil(t, orgRepo.Owner)
	assert.False(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypeIssues))
	orgRepo.Units = nil
	assert.False(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypeIssues))
	assert.True(t, repo_model.HiddenUnits(db.DefaultContext, nil).Contains(unit.TypeIssues), "a nil owner hides everything")
	assert.True(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypePullRequests))
	assert.True(t, userRepo.UnitEnabled(db.DefaultContext, unit.TypeIssues))
	// the row is kept
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeIssues})

	list := repo_model.RepositoryList{
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}),
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}),
	}
	require.NoError(t, list.LoadUnits(db.DefaultContext))
	assert.False(t, list[0].UnitEnabled(db.DefaultContext, unit.TypeIssues))
	assert.True(t, list[1].UnitEnabled(db.DefaultContext, unit.TypeIssues))

	// a corrupt stored value fails closed for organizations, user repositories are not restricted
	setRawUnitPolicy(t, "{not json")
	orgRepo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	assert.False(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypePullRequests))
	userRepo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	assert.True(t, userRepo.UnitEnabled(db.DefaultContext, unit.TypePullRequests))

	// nothing stored allows everything
	setRawUnitPolicy(t, "")
	orgRepo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	assert.True(t, orgRepo.UnitEnabled(db.DefaultContext, unit.TypeIssues))
}
