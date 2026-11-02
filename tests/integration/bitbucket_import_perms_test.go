// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"forgejo.org/models"
	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/migrations"
	"forgejo.org/services/migrations/allowlist"
	"forgejo.org/services/usergroup"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findBitbucketItem(t *testing.T, report *migrations.BitbucketImportReport, kind, bitbucket, target string) *migrations.BitbucketImportItem {
	t.Helper()
	for _, item := range report.Items {
		if item.Kind == kind && item.Bitbucket == bitbucket && (target == "" || item.Target == target || item.Name == target) {
			return item
		}
	}
	require.Failf(t, "no such item", "%s %s on %s", kind, bitbucket, target)
	return nil
}

func TestBitbucketImportPermissions(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, true, func() { require.NoError(t, allowlist.Init()) })()
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowUnencrypted, true, func() { require.NoError(t, allowlist.Init()) })()
		defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{MaxLifetimeDays: 30})()
		ctx := t.Context()
		server := newBitbucketMock(t, nil, map[string][]string{"GATE": {"g"}, "TFA": {"f"}, "NOX": {"n"}, "CA": {"x"}})
		defer server.Close()

		page := func(values ...any) map[string]any { return map[string]any{"isLastPage": true, "values": values} }
		usr := func(name, email string, active bool, permission string) map[string]any {
			return map[string]any{"user": map[string]any{"name": name, "emailAddress": email, "active": active}, "permission": permission}
		}
		grp := func(name, permission string) map[string]any {
			return map[string]any{"group": map[string]any{"name": name}, "permission": permission}
		}
		now := time.Now()
		accessKey := func(id int, text, label string, created time.Time, days int, permission string) map[string]any {
			key := map[string]any{"id": id, "text": text, "label": label}
			if days > 0 {
				key["createdDate"], key["expiryDays"] = created.UnixMilli(), days
			}
			return map[string]any{"key": key, "permission": permission}
		}
		keys := map[int]string{}
		for i := 1; i <= 7; i++ {
			keys[i], _ = newTestSSHKey(t)
		}
		user8 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
		_, err := asymkey_model.AddPublicKey(ctx, user8.ID, "user8 key", keys[5], 0, 0)
		require.NoError(t, err)

		server.pages = map[string]any{
			"api/1.0/projects": page(
				map[string]any{"key": "PAY", "name": "Payments", "public": true},
				map[string]any{"key": "GATE", "name": "Gate"},
				map[string]any{"key": "TFA", "name": "Tfa"},
				map[string]any{"key": "NOX", "name": "Nox"},
				map[string]any{"key": "CA", "name": "Coll"},   // repository x: team coll-x-read
				map[string]any{"key": "CB", "name": "Coll X"}, // project team coll-x-read
			),
			"api/1.0/projects/PAY/repos": page(map[string]any{"slug": "api", "public": true}, map[string]any{"slug": "web"}),
			"api/1.0/projects/PAY/permissions/users": page(
				usr("user4", "user4@example.com", true, "PROJECT_READ"),
				usr("user5", "user5@example.com", true, "PROJECT_WRITE"),
				usr("user8", "USER8@example.com", true, "PROJECT_ADMIN"),
				usr("user10", "user4@example.com", true, "PROJECT_READ"),  // another user's email
				usr("user14", "", true, "PROJECT_READ"),                   // the name only
				usr("user11", "user11@example.com", true, "PROJECT_READ"), // not activated
				usr("user9", "user9@example.com", true, "PROJECT_READ"),   // inactive in gitdepo
				usr("user37", "user37@example.com", true, "PROJECT_READ"), // login prohibited
				usr("nobody", "nobody@example.com", true, "PROJECT_READ"),
				usr("user12", "user12@example.com", false, "PROJECT_READ"), // inactive in Bitbucket
				usr("user13", "user13@example.com", true, "PROJECT_CREATE"),
				usr("user27", "user27@example.com", true, "PROJECT_READ"), // restricted: gets what the team grants
			),
			"api/1.0/projects/PAY/permissions/groups":           page(grp("bb-devs", "PROJECT_WRITE"), grp("bb-nogroup", "PROJECT_READ")),
			"api/1.0/projects/PAY/permissions/PROJECT_READ/all": map[string]any{"permitted": true},
			"api/1.0/projects/PAY/repos/api/permissions/users": page(
				usr("user16", "user16@example.com", true, "REPO_READ"),
				usr("user18", "user18@example.com", true, "REPO_WRITE"),
				usr("user20", "user20@example.com", true, "REPO_ADMIN"),
				usr("user2", "user2@example.com", true, "REPO_WRITE"),  // an owner of the organization
				usr("user21", "user21@example.com", true, "REPO_READ"), // blocked by the organization
			),
			"api/1.0/projects/PAY/repos/api/permissions/groups": page(grp("bb-devs", "REPO_ADMIN"), grp("bb-nogroup", "REPO_READ")),
			"api/1.0/projects/CA/repos/x/permissions/groups":    page(grp("bb-devs", "REPO_READ")),
			"api/1.0/projects/CB/permissions/users":             page(usr("user4", "user4@example.com", true, "PROJECT_READ")),
			"keys/1.0/projects/PAY/ssh": page(
				accessKey(1, keys[1], "ci\x1b[2J", now.Add(-24*time.Hour), 10, "PROJECT_READ"),
				accessKey(2, keys[2], "deploy", now, 0, "PROJECT_WRITE"),
				accessKey(3, keys[3], "old", now.Add(-20*24*time.Hour), 10, "PROJECT_READ"),
				accessKey(4, keys[4], "odd", now, 0, "PROJECT_ADMIN"),
				accessKey(5, keys[5], "mine", now, 0, "PROJECT_READ"),
			),
			"keys/1.0/projects/PAY/repos/api/ssh":     page(accessKey(6, keys[6], "", now, 0, "REPO_WRITE")),
			"api/1.0/projects/GATE/permissions/users": page(usr("user4", "user4@example.com", true, "PROJECT_READ")),
			"api/1.0/projects/TFA/permissions/users":  page(usr("user4", "user4@example.com", true, "PROJECT_READ")),
			"keys/1.0/projects/NOX/ssh":               page(accessKey(7, keys[7], "x", now, 0, "PROJECT_READ")),
		}

		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		newOrg := func(t *testing.T, name string) *organization.Organization {
			t.Helper()
			org := &organization.Organization{Name: name}
			require.NoError(t, organization.CreateOrganization(ctx, org, user2))
			return org
		}
		org := newOrg(t, "bbperms")
		user27 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 27})
		user27.IsRestricted = true
		require.NoError(t, user_model.UpdateUserCols(ctx, user27, "is_restricted"))
		require.NoError(t, db.Insert(ctx, &user_model.BlockedUser{UserID: org.ID, BlockID: 21}))
		devs := &organization.UserGroup{Name: "bb-devs"}
		require.NoError(t, usergroup.CreateGroup(ctx, devs))
		require.NoError(t, usergroup.AddMember(ctx, devs, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})))

		keyExpiry := now.AddDate(0, 0, 20).Format("2006-01-02")
		opts := migrations.BitbucketImportOptions{Server: server.URL, Token: bitbucketTestToken, Projects: []string{"PAY"}, KeyExpiry: keyExpiry}
		doer := "user2"
		run := func(t *testing.T, orgName string, o migrations.BitbucketImportOptions) *migrations.BitbucketImportReport {
			t.Helper()
			report, err := migrations.ImportBitbucket(ctx, doer, orgName, o)
			require.NoError(t, err)
			b, err := json.Marshal(report)
			require.NoError(t, err)
			assert.NotContains(t, string(b), "@example.com", "Bitbucket emails are never reported")
			assert.NotContains(t, string(b), "\x1b")
			return report
		}
		blocked := func(t *testing.T, orgName string, o migrations.BitbucketImportOptions) *migrations.BitbucketImportReport {
			t.Helper()
			before := countBitbucketImportRows(t)
			report := run(t, orgName, o)
			assert.True(t, report.Blocked)
			assert.Equal(t, before, countBitbucketImportRows(t))
			return report
		}

		t.Run("a team that isn't the importer's blocks the run", func(t *testing.T) {
			units := func(mode perm.AccessMode) []*organization.TeamUnit {
				return []*organization.TeamUnit{{OrgID: org.ID, Type: unit.TypeCode, AccessMode: mode}, {OrgID: org.ID, Type: unit.TypePullRequests, AccessMode: mode}}
			}
			for name, team := range map[string]*organization.Team{
				"wider units":      {Name: "payments-read", AccessMode: perm.AccessModeWrite, Units: units(perm.AccessModeWrite)},
				"all repositories": {Name: "payments-read", AccessMode: perm.AccessModeRead, Units: units(perm.AccessModeRead), IncludesAllRepositories: true},
				"another unit":     {Name: "payments-write", AccessMode: perm.AccessModeWrite, Units: append(units(perm.AccessModeWrite), &organization.TeamUnit{OrgID: org.ID, Type: unit.TypeIssues, AccessMode: perm.AccessModeWrite})},
				"repository team":  {Name: "payments-api-write", AccessMode: perm.AccessModeWrite, Units: units(perm.AccessModeWrite)},
			} {
				t.Run(name, func(t *testing.T) {
					team.OrgID = org.ID
					require.NoError(t, models.NewTeam(ctx, team))
					defer func() { require.NoError(t, models.DeleteTeam(ctx, team)) }()
					report := blocked(t, org.Name, opts)
					assert.Equal(t, migrations.BitbucketConflict, findBitbucketItem(t, report, "team", "", team.Name).Status)
				})
			}
		})

		t.Run("keys need an expiry", func(t *testing.T) {
			noMax := opts
			noMax.Projects, noMax.KeyExpiry = []string{"NOX"}, ""
			func() {
				defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{})()
				report := blocked(t, org.Name, noMax)
				assert.Equal(t, migrations.BitbucketConflict, findBitbucketItem(t, report, "key", "NOX key 7", "").Status)
			}()

			for _, expiry := range []string{now.AddDate(0, 0, 40).Format("2006-01-02"), now.AddDate(0, 0, -1).Format("2006-01-02"), "tomorrow"} {
				late := noMax
				late.KeyExpiry = expiry
				before := countBitbucketImportRows(t)
				_, err := migrations.ImportBitbucket(ctx, "user2", org.Name, late)
				require.Error(t, err, expiry)
				assert.Equal(t, before, countBitbucketImportRows(t))
			}
		})

		t.Run("SSH disabled skips the keys", func(t *testing.T) {
			defer test.MockVariableValue(&setting.SSH.Disabled, true)()
			dry := opts
			dry.Projects, dry.DryRun = []string{"NOX"}, true
			report := run(t, org.Name, dry)
			assert.False(t, report.Blocked)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "key", "NOX key 7", "").Status)
		})

		t.Run("dry run", func(t *testing.T) {
			dry := opts
			dry.DryRun = true
			before := countBitbucketImportRows(t)
			report := run(t, org.Name, dry)
			assert.False(t, report.Blocked)
			assert.Equal(t, before, countBitbucketImportRows(t))
			assert.Equal(t, migrations.BitbucketPlanned, findBitbucketItem(t, report, "team", "", "payments-read").Status)
			assert.Equal(t, migrations.BitbucketPlanned, findBitbucketItem(t, report, "member", "user4", "payments-read").Status)
			assert.Equal(t, migrations.BitbucketPlanned, findBitbucketItem(t, report, "key", "PAY key 1", "").Status)
		})

		var report *migrations.BitbucketImportReport
		t.Run("import", func(t *testing.T) {
			since := auditMaxID(t)
			report = run(t, org.Name, opts)
			require.False(t, report.Blocked)
			// a command line run as user2: actor cli, the account in data.task
			teams := auditActions(t, since, "org.team.created")
			require.NotEmpty(t, teams)
			for _, e := range append(teams, auditActions(t, since, "org.team.member_added")...) {
				assert.Equal(t, audit_model.ActorCLI, e.ActorType)
				assert.Equal(t, "bitbucket_import:user2(2)", auditData(t, e)["task"])
			}
			assert.NotEmpty(t, auditActions(t, since, "org.team.repo_added"))
		})
		group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: org.ID, LowerName: "payments"})
		api, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, "api")
		require.NoError(t, err)
		web, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, "web")
		require.NoError(t, err)
		// InsertTeamMember watches the team's repositories in a goroutine (AUTO_WATCH_NEW_REPOS): wait until every
		// member of an imported team watches every repository of the team before counting rows
		assert.Eventually(t, func() bool {
			missing, err := db.GetEngine(db.DefaultContext).Table("team_user").
				Join("INNER", "team_repo", "team_repo.team_id = team_user.team_id").
				Join("INNER", "team", "team.id = team_user.team_id").
				Where("team.org_id = ? AND team.lower_name <> ?", org.ID, "owners").
				And("NOT EXISTS (SELECT 1 FROM watch WHERE watch.user_id = team_user.uid AND watch.repo_id = team_repo.repo_id)").Count()
			return err == nil && missing == 0
		}, 10*time.Second, 50*time.Millisecond)

		t.Run("teams", func(t *testing.T) {
			for name, want := range map[string]struct {
				mode    perm.AccessMode
				members []int64
				project bool
			}{
				"payments-read":      {perm.AccessModeRead, []int64{4, 27}, true},
				"payments-write":     {perm.AccessModeWrite, []int64{5, 8, 15}, true},
				"payments-api-write": {perm.AccessModeWrite, []int64{15}, false},
			} {
				team, err := organization.GetTeam(ctx, org.ID, name)
				require.NoError(t, err, name)
				assert.Equal(t, want.mode, team.AccessMode, name)
				assert.False(t, team.IncludesAllRepositories, name)
				require.NoError(t, team.LoadUnits(ctx))
				got := map[unit.Type]perm.AccessMode{}
				for _, u := range team.Units {
					if u.AccessMode != perm.AccessModeNone {
						got[u.Type] = u.AccessMode
					}
				}
				assert.Equal(t, map[unit.Type]perm.AccessMode{unit.TypeCode: want.mode, unit.TypePullRequests: want.mode}, got, name)
				var members []int64
				require.NoError(t, db.GetEngine(ctx).Table("team_user").Where("team_id = ?", team.ID).Cols("uid").OrderBy("uid").Find(&members))
				assert.Equal(t, want.members, members, name)
				linked, err := db.GetEngine(ctx).Exist(&organization.TeamGroup{TeamID: team.ID, GroupID: group.ID})
				require.NoError(t, err)
				assert.Equal(t, want.project, linked, name)
			}
			assert.Contains(t, findBitbucketItem(t, report, "member", "user8", "payments-write").Reason, "admin mapped to write")
			_, err := organization.GetTeam(ctx, org.ID, "payments-api-read")
			assert.True(t, organization.IsErrTeamNotExist(err), "no team for a group without a user group")
		})

		t.Run("unmatched and unmapped are reported", func(t *testing.T) {
			for name, reason := range map[string]string{
				"user10": "email_mismatch", "user14": "email_mismatch", "user11": "email_not_activated", "user9": "inactive",
				"user37": "inactive", "nobody": "no_user", "user12": "bb_inactive",
			} {
				item := findBitbucketItem(t, report, "member", name, "")
				assert.Equal(t, migrations.BitbucketSkipped, item.Status, name)
				assert.Equal(t, reason, item.Reason, name)
				assert.Empty(t, item.Name, name)
			}
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "permission", "user13 PROJECT_CREATE", "").Status)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "permission", "PAY public", "").Status)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "permission", "PAY default PROJECT_READ", "").Status)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "permission", "PAY/api public", "").Status)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "group", "bb-nogroup", "").Status)
		})

		t.Run("collaborators", func(t *testing.T) {
			got := map[int64]perm.AccessMode{}
			var collabs []*repo_model.Collaboration
			require.NoError(t, db.GetEngine(ctx).Where("repo_id = ?", api.ID).Find(&collabs))
			for _, c := range collabs {
				got[c.UserID] = c.Mode
			}
			assert.Equal(t, map[int64]perm.AccessMode{16: perm.AccessModeRead, 18: perm.AccessModeWrite, 20: perm.AccessModeWrite}, got)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "collaborator", "user2", "").Status)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, report, "collaborator", "user21", "").Status)
		})

		t.Run("keys", func(t *testing.T) {
			projectKeys, err := asymkey_model.FindOrgDeployKeys(ctx, org.ID, group.ID)
			require.NoError(t, err)
			byName := map[string]*asymkey_model.OrgDeployKey{}
			for _, k := range projectKeys {
				byName[k.Name] = k
			}
			require.Len(t, byName, 2)
			ci, deploy := byName["ci?[2J"], byName["deploy"]
			require.NotNil(t, ci)
			require.NotNil(t, deploy)
			assert.Equal(t, perm.AccessModeRead, ci.Mode)
			assert.Equal(t, perm.AccessModeWrite, deploy.Mode)
			// the Bitbucket expiry is the earliest for ci, --key-expiry for deploy
			assert.InDelta(t, now.Add(9*24*time.Hour).Unix(), int64(ci.ExpiresUnix), 5)
			flag, err := time.ParseInLocation("2006-01-02", keyExpiry, setting.DefaultUILocation)
			require.NoError(t, err)
			assert.Equal(t, flag.Format("2006-01-02"), deploy.ExpiresUnix.FormatDate())
			for _, k := range []struct {
				id     int
				reason string
			}{{3, "expired"}, {4, "unmapped"}, {5, "user key"}} {
				item := findBitbucketItem(t, report, "key", fmt.Sprint("PAY key ", k.id), "")
				assert.Equal(t, migrations.BitbucketSkipped, item.Status, k.id)
				assert.Contains(t, item.Reason, k.reason, k.id)
			}

			repoKeys, err := db.Find[asymkey_model.DeployKey](ctx, asymkey_model.ListDeployKeysOptions{RepoID: api.ID})
			require.NoError(t, err)
			require.Len(t, repoKeys, 1)
			assert.Equal(t, perm.AccessModeWrite, repoKeys[0].Mode)
			assert.Equal(t, flag.Format("2006-01-02"), repoKeys[0].ExpiresUnix.FormatDate())

			// a project key covers the repositories of the project, a repository key only its repository
			for _, repo := range []*repo_model.Repository{api, web} {
				eff, err := asymkey_model.GetEffectiveDeployKey(ctx, ci.KeyID, repo)
				require.NoError(t, err)
				assert.NotNil(t, eff, repo.Name)
			}
			_, err = asymkey_model.GetEffectiveDeployKey(ctx, repoKeys[0].KeyID, web)
			assert.True(t, asymkey_model.IsErrDeployKeyNotExist(err), "the repository key doesn't cover web")
		})

		t.Run("nobody gets more than the mapping", func(t *testing.T) {
			rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: []int64{api.ID, web.ID}, Plain: true})
			require.NoError(t, err)
			want := map[int64]map[string]perm.AccessMode{
				4:  {"api": perm.AccessModeRead, "web": perm.AccessModeRead},
				27: {"api": perm.AccessModeRead, "web": perm.AccessModeRead},
				5:  {"api": perm.AccessModeWrite, "web": perm.AccessModeWrite},
				8:  {"api": perm.AccessModeWrite, "web": perm.AccessModeWrite},
				15: {"api": perm.AccessModeWrite, "web": perm.AccessModeWrite},
				16: {"api": perm.AccessModeRead},
				18: {"api": perm.AccessModeWrite},
				20: {"api": perm.AccessModeWrite},
			}
			collaborators := map[int64]bool{16: true, 18: true, 20: true}
			seen := map[int64]map[string]bool{}
			for _, row := range rows {
				if row.User == nil || row.User.ID == user2.ID { // the organization's owner
					continue
				}
				uid, repo := row.User.ID, row.Repo
				for _, u := range repo.Units {
					got := row.Perm.UnitAccessMode(u.Type)
					limit := want[uid][repo.Name]
					if u.Type != unit.TypeCode && u.Type != unit.TypePullRequests && !collaborators[uid] {
						limit = perm.AccessModeNone // teams carry Code and pull requests only
					}
					assert.LessOrEqual(t, got, limit, "user %d on %s, unit %d", uid, repo.Name, u.Type)
				}
				if got := row.Perm.UnitAccessMode(unit.TypeCode); got > perm.AccessModeNone {
					assert.Equal(t, want[uid][repo.Name], got, "user %d on %s", uid, repo.Name)
					if seen[uid] == nil {
						seen[uid] = map[string]bool{}
					}
					seen[uid][repo.Name] = true
				}
			}
			for uid, repos := range want {
				for name := range repos {
					assert.True(t, seen[uid][name], "user %d has access to %s", uid, name)
				}
			}
		})

		t.Run("a rerun changes nothing", func(t *testing.T) {
			// an existing collaborator is kept as it is
			require.NoError(t, repo_module.ChangeCollaborationAccessMode(ctx, api, 16, perm.AccessModeWrite))
			before := countBitbucketImportRows(t)
			again := run(t, org.Name, opts)
			assert.Equal(t, before, countBitbucketImportRows(t))
			for _, item := range again.Items {
				assert.NotContains(t, []string{migrations.BitbucketPlanned, migrations.BitbucketCreated, migrations.BitbucketFailed}, item.Status, "%s %s", item.Kind, item.Bitbucket)
			}
			for _, name := range []string{"payments-read", "payments-write", "payments-api-write"} {
				assert.Equal(t, migrations.BitbucketReused, findBitbucketItem(t, again, "team", "", name).Status, "a team of the importer's shape is reused")
			}
			c := unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: api.ID, UserID: 16})
			assert.Equal(t, perm.AccessModeWrite, c.Mode)
			assert.Equal(t, migrations.BitbucketSkipped, findBitbucketItem(t, again, "collaborator", "user16", "").Status)
		})

		t.Run("a reused team that changed shape blocks the run", func(t *testing.T) {
			read, err := organization.GetTeam(ctx, org.ID, "payments-read")
			require.NoError(t, err)
			apiTeam, err := organization.GetTeam(ctx, org.ID, "payments-api-write")
			require.NoError(t, err)
			other, err := repo_model.CreateRepoGroup(ctx, org.AsUser(), "other", "")
			require.NoError(t, err)
			for name, change := range map[string]struct {
				team *organization.Team
				do   []any // a bean to insert, or a statement to run
				undo []any
			}{
				"a direct repository":  {read, []any{&organization.TeamRepo{OrgID: org.ID, TeamID: read.ID, RepoID: 1}}, []any{&organization.TeamRepo{TeamID: read.ID, RepoID: 1}}},
				"another unit row":     {read, []any{&organization.TeamUnit{OrgID: org.ID, TeamID: read.ID, Type: unit.TypeIssues}}, []any{&organization.TeamUnit{TeamID: read.ID, Type: unit.TypeIssues}}},
				"owner mode":           {read, []any{"UPDATE team SET authorize = ? WHERE id = ?", perm.AccessModeOwner, read.ID}, []any{"UPDATE team SET authorize = ? WHERE id = ?", perm.AccessModeRead, read.ID}},
				"a linked repo team":   {apiTeam, []any{&organization.TeamGroup{OrgID: org.ID, TeamID: apiTeam.ID, GroupID: group.ID}}, []any{&organization.TeamGroup{TeamID: apiTeam.ID, GroupID: group.ID}}},
				"another repo in team": {apiTeam, []any{&organization.TeamRepo{OrgID: org.ID, TeamID: apiTeam.ID, RepoID: web.ID}}, []any{&organization.TeamRepo{TeamID: apiTeam.ID, RepoID: web.ID}}},
				"write units":          {read, []any{"UPDATE team_unit SET access_mode = ? WHERE team_id = ?", perm.AccessModeWrite, read.ID}, []any{"UPDATE team_unit SET access_mode = ? WHERE team_id = ?", perm.AccessModeRead, read.ID}},
				"another project":      {read, []any{&organization.TeamGroup{OrgID: org.ID, TeamID: read.ID, GroupID: other.ID}}, []any{&organization.TeamGroup{TeamID: read.ID, GroupID: other.ID}}},
				"all repositories":     {read, []any{"UPDATE team SET includes_all_repositories = ? WHERE id = ?", true, read.ID}, []any{"UPDATE team SET includes_all_repositories = ? WHERE id = ?", false, read.ID}},
				"can create repos":     {read, []any{"UPDATE team SET can_create_org_repo = ? WHERE id = ?", true, read.ID}, []any{"UPDATE team SET can_create_org_repo = ? WHERE id = ?", false, read.ID}},
			} {
				t.Run(name, func(t *testing.T) {
					apply := func(change []any, insert bool) {
						if sql, ok := change[0].(string); ok {
							_, err := db.Exec(ctx, append([]any{sql}, change[1:]...)...)
							require.NoError(t, err)
						} else if insert {
							require.NoError(t, db.Insert(ctx, change[0]))
						} else {
							_, err := db.DeleteByBean(ctx, change[0])
							require.NoError(t, err)
						}
					}
					apply(change.do, true)
					report := blocked(t, org.Name, opts)
					assert.Equal(t, migrations.BitbucketConflict, findBitbucketItem(t, report, "team", "", change.team.Name).Status)
					apply(change.undo, false)
				})
			}
			assert.False(t, run(t, org.Name, opts).Blocked, "the shapes are back")
		})

		t.Run("two teams of one name in a run block it", func(t *testing.T) {
			o := opts
			o.Projects = []string{"CA", "CB"}
			report := blocked(t, org.Name, o)
			conflicts := 0
			for _, item := range report.Items {
				if item.Kind == "team" && item.Name == "coll-x-read" && item.Status == migrations.BitbucketConflict {
					conflicts++
				}
			}
			assert.Equal(t, 1, conflicts, "the second team of that name")
		})

		t.Run("a verified-domain refusal skips the member", func(t *testing.T) {
			gate := newOrg(t, "bbgate")
			require.NoError(t, user_model.SetUserSetting(ctx, gate.ID, organization.SettingKeyRequireVerifiedDomain, "true"))
			o := opts
			o.Projects = []string{"GATE"}
			report := run(t, gate.Name, o)
			item := findBitbucketItem(t, report, "member", "user4", "")
			assert.Equal(t, migrations.BitbucketSkipped, item.Status)
			member, err := organization.IsOrganizationMember(ctx, gate.ID, 4)
			require.NoError(t, err)
			assert.False(t, member)
		})

		t.Run("a member without two-factor is added and gets nothing", func(t *testing.T) {
			tfa := newOrg(t, "bbtfa")
			tfa.RequireTwoFactor = true
			require.NoError(t, user_model.UpdateUserCols(ctx, tfa.AsUser(), "require_two_factor"))
			o := opts
			o.Projects = []string{"TFA"}
			doer = "user1" // user2 has no two-factor either, so it isn't an acting owner there
			defer func() { doer = "user2" }()
			report := run(t, tfa.Name, o)
			item := findBitbucketItem(t, report, "member", "user4", "")
			assert.Equal(t, migrations.BitbucketCreated, item.Status)
			assert.Contains(t, item.Reason, "blocked until two-factor")
			repo, err := repo_model.GetRepositoryByPath(ctx, tfa.ID, "tfa", "f")
			require.NoError(t, err)
			rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: []int64{repo.ID}, Plain: true})
			require.NoError(t, err)
			for _, row := range rows {
				if row.User != nil && row.User.ID == 4 {
					assert.Equal(t, perm.AccessModeNone, row.Perm.UnitAccessMode(unit.TypeCode))
				}
			}
		})
	})
}
