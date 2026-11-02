// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/url"
	"testing"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/migrations"
	"forgejo.org/services/migrations/allowlist"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitbucketImportRules(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, true, func() { require.NoError(t, allowlist.Init()) })()
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowUnencrypted, true, func() { require.NoError(t, allowlist.Init()) })()
		ctx := t.Context()
		server := newBitbucketMock(t, nil, map[string][]string{"RUL": {"api", "lib", "ov2", "ov3", "ovl", "svc"}, "UNM": {"u"}})
		defer server.Close()

		page := func(values ...any) map[string]any { return map[string]any{"isLastPage": true, "values": values} }
		usr := func(name string) map[string]any {
			return map[string]any{"name": name, "emailAddress": name + "@example.com", "active": true}
		}
		restriction := func(typ, matcherType, id string, users []map[string]any, groups []string, keys ...int) map[string]any {
			accessKeys := []any{}
			for _, k := range keys {
				accessKeys = append(accessKeys, map[string]any{"key": map[string]any{"id": k}})
			}
			return map[string]any{
				"type": typ, "matcher": map[string]any{"id": id, "type": map[string]any{"id": matcherType}},
				"users": users, "groups": groups, "accessKeys": accessKeys,
			}
		}
		keys := map[int]string{}
		for _, id := range []int{30, 21, 22, 23} {
			keys[id], _ = newTestSSHKey(t)
		}
		const hookSecret, hookToken = "s3cret-hook-value-1234", "tok-in-query-5678"
		server.pages = map[string]any{
			"api/1.0/projects": page(map[string]any{"key": "RUL", "name": "Rules"}, map[string]any{"key": "UNM", "name": "Unmapped"}),
			"api/1.0/projects/RUL/permissions/users": page(
				map[string]any{"user": usr("user4"), "permission": "PROJECT_WRITE"},
				map[string]any{"user": usr("user5"), "permission": "PROJECT_WRITE"},
			),
			"keys/1.0/projects/RUL/ssh": page(map[string]any{"key": map[string]any{"id": 30, "text": keys[30], "label": "proj"}, "permission": "PROJECT_READ"}),
			"keys/1.0/projects/RUL/repos/svc/ssh": page(
				map[string]any{"key": map[string]any{"id": 21, "text": keys[21], "label": "ci"}, "permission": "REPO_WRITE"},
				map[string]any{"key": map[string]any{"id": 22, "text": keys[22], "label": "other"}, "permission": "REPO_WRITE"},
				map[string]any{"key": map[string]any{"id": 23, "text": keys[23], "label": "reader"}, "permission": "REPO_READ"},
			),
			"branch-permissions/2.0/projects/RUL/restrictions": page(
				// user8 is no member of the organization; the group and the project key can't be held by a project rule
				restriction("read-only", "BRANCH", "refs/heads/release", []map[string]any{usr("user4"), usr("user8")}, []string{"bb-devs"}, 30),
				restriction("read-only", "BRANCH", "refs/heads/main", []map[string]any{usr("user4"), usr("user5")}, nil),
				restriction("pull-request-only", "BRANCH", "refs/heads/main", []map[string]any{usr("user5")}, nil),
				restriction("no-deletes", "BRANCH", "refs/heads/develop", []map[string]any{usr("user4")}, nil),
				// the same type twice on one matcher: Bitbucket applies both, so only user4 may delete
				restriction("no-deletes", "BRANCH", "refs/heads/develop", []map[string]any{usr("user4"), usr("user5")}, nil),
				restriction("fast-forward-only", "BRANCH", "refs/heads/develop", []map[string]any{usr("user5")}, nil),
				// every exception dropped: nobody may push, merge, delete or force-push
				restriction("read-only", "BRANCH", "refs/heads/frozen", []map[string]any{usr("nobody")}, []string{"g"}),
				restriction("no-deletes", "BRANCH", "refs/heads/frozen", []map[string]any{usr("nobody")}, nil),
				restriction("fast-forward-only", "BRANCH", "refs/heads/frozen", []map[string]any{usr("nobody")}, nil),
			),
			"branch-permissions/2.0/projects/RUL/repos/svc/restrictions": page(
				// user20 can't write svc; key 99 is unknown
				restriction("read-only", "BRANCH", "refs/heads/main", []map[string]any{usr("user4"), usr("user20")}, nil, 21, 99),
				// the same type twice on one matcher, for keys: only key 21 is in both
				restriction("no-deletes", "BRANCH", "refs/heads/main", nil, nil, 21, 22),
				restriction("no-deletes", "BRANCH", "refs/heads/main", nil, nil, 21),
				// a read key never pushes: dropped, and nobody else is excepted
				restriction("read-only", "BRANCH", "refs/heads/rk", nil, nil, 23),
			),
			"branch-permissions/2.0/projects/RUL/repos/api/restrictions": page(
				restriction("no-deletes", "BRANCH", "refs/heads/master", nil, nil),
			),
			"branch-permissions/2.0/projects/RUL/repos/lib/restrictions": page(
				restriction("pull-request-only", "PATTERN", "rel,x/*", []map[string]any{usr("user4")}, nil),
			),
			// overlapping restrictions: gitdepo applies only the first matching rule, so both get the strictest
			"branch-permissions/2.0/projects/RUL/repos/ovl/restrictions": page(
				restriction("no-deletes", "BRANCH", "refs/heads/main", nil, nil),
				restriction("read-only", "PATTERN", "**", nil, nil),
			),
			// plain names match case-insensitively: main and Main both match "main"
			"branch-permissions/2.0/projects/RUL/repos/ov3/restrictions": page(
				restriction("no-deletes", "BRANCH", "refs/heads/main", nil, nil),
				restriction("read-only", "BRANCH", "refs/heads/Main", nil, nil),
			),
			"branch-permissions/2.0/projects/RUL/repos/ov2/restrictions": page(
				restriction("fast-forward-only", "PATTERN", "release/**", []map[string]any{usr("user4")}, nil),
				restriction("pull-request-only", "PATTERN", "release/*", []map[string]any{usr("user5")}, nil),
			),
			"api/1.0/projects/RUL/webhooks": page(
				map[string]any{
					"id": 1, "url": "https://user:pw@hooks.example.com/ci?token=" + hookToken + "#frag", "active": true,
					"events": []string{"repo:refs_changed", "pr:opened", "mirror:repo_synchronized"}, "configuration": map[string]string{"secret": hookSecret},
				},
				map[string]any{"id": 2, "url": "https://hooks.example.com/nosecret", "active": true, "events": []string{"repo:refs_changed"}},
			),
			"api/1.0/projects/RUL/repos/svc/webhooks": page(
				map[string]any{"id": 3, "url": "https://hooks.example.com/none", "active": true, "events": []string{"mirror:repo_synchronized"}},
				map[string]any{"id": 4, "url": "ftp://hooks.example.com/x", "active": true, "events": []string{"repo:refs_changed"}},
				map[string]any{"id": 5, "url": "https://hooks.example.com/repo", "active": true, "events": []string{"pr:comment:added"}, "configuration": map[string]string{"secret": hookSecret}},
			),
			"branch-utils/1.0/projects/RUL/repos/svc/branchmodel": map[string]any{
				"development": map[string]any{"displayId": "develop", "isDefault": false},
				"production":  map[string]any{"displayId": "master", "isDefault": true},
				"types":       []map[string]string{{"id": "RELEASE", "prefix": "release/"}, {"id": "HOTFIX", "prefix": "hotfix/"}},
			},
			"branch-utils/1.0/projects/RUL/repos/lib/branchmodel": map[string]any{
				"development": map[string]any{"displayId": "master", "isDefault": true},
				"types":       []map[string]string{{"id": "FEATURE", "prefix": "feature/"}},
			},
			"branch-permissions/2.0/projects/UNM/restrictions": page(
				restriction("read-only", "MODEL_BRANCH", "production", nil, nil),
				restriction("read-only", "PATTERN", "refs/tags/*", nil, nil),
			),
		}

		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := &organization.Organization{Name: "bbrules"}
		require.NoError(t, organization.CreateOrganization(ctx, org, user2))
		opts := migrations.BitbucketImportOptions{Server: server.URL, Token: bitbucketTestToken, Projects: []string{"RUL"}, PullRequests: true, KeyExpiry: time.Now().AddDate(0, 0, 20).Format("2006-01-02")}
		run := func(t *testing.T, o migrations.BitbucketImportOptions) *migrations.BitbucketImportReport {
			t.Helper()
			report, err := migrations.ImportBitbucket(ctx, "user2", org.Name, o)
			require.NoError(t, err)
			b, err := json.Marshal(report)
			require.NoError(t, err)
			for _, secret := range []string{hookSecret, hookToken, "pw@", "#frag", "@example.com"} {
				assert.NotContains(t, string(b), secret, "the report never shows secrets, URL query or emails")
			}
			return report
		}
		blocked := func(t *testing.T, o migrations.BitbucketImportOptions) *migrations.BitbucketImportReport {
			t.Helper()
			before := countBitbucketImportRows(t)
			report := run(t, o)
			assert.True(t, report.Blocked)
			assert.Equal(t, before, countBitbucketImportRows(t))
			return report
		}
		item := func(t *testing.T, report *migrations.BitbucketImportReport, kind, bitbucket string) *migrations.BitbucketImportItem {
			return findBitbucketItem(t, report, kind, bitbucket, "")
		}

		t.Run("unmapped matchers block the run unless skipped", func(t *testing.T) {
			o := opts
			o.Projects, o.DryRun = []string{"UNM"}, true
			report := blocked(t, o)
			assert.Equal(t, migrations.BitbucketConflict, item(t, report, "rule", "UNM read-only production").Status)
			assert.Equal(t, migrations.BitbucketConflict, item(t, report, "rule", "UNM read-only refs/tags/*").Status)
			o.SkipUnmapped = true
			report = run(t, o)
			assert.False(t, report.Blocked)
			assert.Equal(t, migrations.BitbucketSkipped, item(t, report, "rule", "UNM read-only production").Status)
		})

		t.Run("dry run", func(t *testing.T) {
			o := opts
			o.DryRun = true
			before := countBitbucketImportRows(t)
			report := run(t, o)
			assert.False(t, report.Blocked)
			assert.Equal(t, before, countBitbucketImportRows(t))
			assert.Equal(t, migrations.BitbucketPlanned, item(t, report, "rule", "RUL refs/heads/release").Status)
			// the dry run already names the users a rule can't hold
			assert.Contains(t, item(t, report, "rule", "RUL refs/heads/release").Reason, "user8 (not an org member)")
			assert.Contains(t, item(t, report, "rule", "RUL/svc refs/heads/main").Reason, "user20 (no write access)")
			assert.Equal(t, migrations.BitbucketPlanned, item(t, report, "hook", "RUL hook 1").Status)
		})

		logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.TRACE)
		logChecker.Filter(hookSecret, hookToken)
		var report *migrations.BitbucketImportReport
		t.Run("import", func(t *testing.T) {
			report = run(t, opts)
			require.False(t, report.Blocked)
		})
		found, _ := logChecker.Check(time.Second)
		cleanup()
		assert.Equal(t, []bool{false, false}, found, "the hook secret and URL query are never logged")

		group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: org.ID, LowerName: "rules"})
		svc, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, "svc")
		require.NoError(t, err)
		// InsertTeamMember adds the watches in a goroutine: wait before any later row count
		assert.Eventually(t, func() bool {
			missing, err := db.GetEngine(db.DefaultContext).Table("team_user").
				Join("INNER", "team_repo", "team_repo.team_id = team_user.team_id").
				Join("INNER", "team", "team.id = team_user.team_id").
				Where("team.org_id = ? AND team.lower_name <> ?", org.ID, "owners").
				And("NOT EXISTS (SELECT 1 FROM watch WHERE watch.user_id = team_user.uid AND watch.repo_id = team_repo.repo_id)").Count()
			return err == nil && missing == 0
		}, 10*time.Second, 50*time.Millisecond)

		projectRule := func(t *testing.T, name string) *git_model.ProtectedBranch {
			t.Helper()
			rule, err := git_model.GetOrgProtectedBranchRuleByName(ctx, org.ID, group.ID, name)
			require.NoError(t, err)
			require.NotNil(t, rule, name)
			return rule
		}

		t.Run("project rules", func(t *testing.T) {
			release := projectRule(t, "release")
			assert.True(t, release.CanPush)
			assert.True(t, release.EnableWhitelist)
			assert.Equal(t, []int64{4}, release.WhitelistUserIDs, "user8 is no org member")
			assert.True(t, release.EnableMergeWhitelist)
			assert.Equal(t, []int64{4}, release.MergeWhitelistUserIDs)
			assert.Empty(t, release.DeleteAllowlistUserIDs)
			assert.Empty(t, release.ForcePushAllowlistUserIDs)
			assert.Empty(t, release.WhitelistDeployKeyIDs)
			assert.True(t, release.ApplyToAdmins)
			reason := item(t, report, "rule", "RUL refs/heads/release").Reason
			for _, s := range []string{"deletion blocked", "force push blocked", "group bb-devs", "key 30", "dropped"} {
				assert.Contains(t, reason, s)
			}

			main := projectRule(t, "main")
			assert.Equal(t, []int64{5}, main.WhitelistUserIDs, "read-only and pull-request-only: only who both let through")
			assert.ElementsMatch(t, []int64{4, 5}, main.MergeWhitelistUserIDs)

			develop := projectRule(t, "develop")
			assert.True(t, develop.CanPush)
			assert.False(t, develop.EnableWhitelist)
			assert.False(t, develop.EnableMergeWhitelist)
			assert.Equal(t, []int64{4}, develop.DeleteAllowlistUserIDs, "the intersection of both no-deletes lists")
			assert.Equal(t, []int64{5}, develop.ForcePushAllowlistUserIDs)

			frozen := projectRule(t, "frozen")
			assert.True(t, frozen.CanPush)
			assert.True(t, frozen.EnableWhitelist, "pushes only through the allowlist")
			assert.Empty(t, frozen.WhitelistUserIDs, "nobody may push")
			assert.True(t, frozen.EnableMergeWhitelist)
			assert.Empty(t, frozen.MergeWhitelistUserIDs, "nobody may merge")
			assert.Empty(t, frozen.DeleteAllowlistUserIDs, "nobody may delete")
			assert.Empty(t, frozen.ForcePushAllowlistUserIDs, "nobody may force-push")
			assert.False(t, frozen.CanUserPush(ctx, user2), "not even an owner")
		})

		t.Run("repository rule", func(t *testing.T) {
			rule, err := git_model.GetProtectedBranchRuleByName(ctx, svc.ID, "main")
			require.NoError(t, err)
			require.NotNil(t, rule)
			assert.Equal(t, []int64{4}, rule.WhitelistUserIDs)
			key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{RepoID: svc.ID, Name: "ci"})
			other := unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{RepoID: svc.ID, Name: "other"})
			assert.False(t, rule.WhitelistDeployKeys, "never every deploy key")
			assert.Equal(t, []int64{key.KeyID}, rule.WhitelistDeployKeyIDs, "the imported key, not the unknown one")
			assert.True(t, rule.CanDeployKeyPush(key.KeyID))
			assert.False(t, rule.CanDeployKeyPush(other.KeyID), "another write key of the repository may not push")
			assert.Equal(t, []int64{key.KeyID}, rule.DeleteAllowlistDeployKeyIDs, "the intersection of both no-deletes key lists")
			assert.Contains(t, item(t, report, "rule", "RUL/svc refs/heads/main").Reason, "key 99")

			rk, err := git_model.GetProtectedBranchRuleByName(ctx, svc.ID, "rk")
			require.NoError(t, err)
			require.NotNil(t, rk)
			reader := unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{RepoID: svc.ID, Name: "reader"})
			assert.Empty(t, rk.WhitelistDeployKeyIDs)
			assert.False(t, rk.CanDeployKeyPush(reader.KeyID))
			assert.False(t, rk.CanDeployKeyPush(key.KeyID))
			assert.False(t, rk.CanUserPush(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})), "nobody pushes")
			assert.Contains(t, item(t, report, "rule", "RUL/svc refs/heads/rk").Reason, "key 23")

			lib, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, "lib")
			require.NoError(t, err)
			rules, err := git_model.GetMatchedProtectedBranchRules(ctx, lib.ID, "rel,x/1")
			require.NoError(t, err)
			require.Len(t, rules, 1, "a comma in a pattern is a character, not an alternative")
			assert.Contains(t, item(t, report, "rule", "RUL/lib rel,x/*").Reason, "tags too")
		})

		t.Run("overlapping restrictions take the strictest", func(t *testing.T) {
			user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
			refused := func(t *testing.T, repoName, branch string, can func(*git_model.ProtectedBranch) bool) bool {
				t.Helper()
				repo, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, repoName)
				require.NoError(t, err)
				rules, err := git_model.GetMatchedProtectedBranchRules(ctx, repo.ID, branch)
				require.NoError(t, err)
				require.NotEmpty(t, rules)
				for _, rule := range rules { // enforcement checks every matched rule
					if !can(rule) {
						return true
					}
				}
				return false
			}
			// main is matched by its plain rule first: without the combination, pushes would be allowed
			assert.True(t, refused(t, "ovl", "main", func(r *git_model.ProtectedBranch) bool { return r.CanUserPush(ctx, user4) }), "a direct push to main is refused")
			assert.True(t, refused(t, "ovl", "main", func(r *git_model.ProtectedBranch) bool { return r.CanUserDelete(ctx, user4) }))
			assert.Contains(t, item(t, report, "rule", "RUL/ovl refs/heads/main").Reason, "overlapping restrictions")
			for _, branch := range []string{"main", "Main"} {
				assert.True(t, refused(t, "ov3", branch, func(r *git_model.ProtectedBranch) bool { return r.CanUserPush(ctx, user4) }), "a direct push to %s is refused", branch)
			}

			// release/1 is matched by both globs: only user5 (pull-request-only exception) pushes directly, and nobody
			// force-pushes, since the pull-request-only rule allows no force push either
			assert.True(t, refused(t, "ov2", "release/1", func(r *git_model.ProtectedBranch) bool { return r.CanUserPush(ctx, user4) }), "user4 may not push")
			assert.False(t, refused(t, "ov2", "release/1", func(r *git_model.ProtectedBranch) bool { return r.CanUserPush(ctx, user5) }), "user5 may push")
			for _, u := range []*user_model.User{user4, user5} {
				assert.True(t, refused(t, "ov2", "release/1", func(r *git_model.ProtectedBranch) bool { return r.CanUserForcePush(ctx, u) }), "user %d may not force-push", u.ID)
			}
		})

		t.Run("hooks", func(t *testing.T) {
			hooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{OwnerID: org.ID, GroupID: group.ID})
			require.NoError(t, err)
			require.Len(t, hooks, 2)
			byURL := map[string]*webhook_model.Webhook{}
			for _, h := range hooks {
				byURL[h.URL] = h
			}
			ci := byURL["https://hooks.example.com/ci?token="+hookToken+"#frag"]
			require.NotNil(t, ci, "the user info is stripped, the rest of the URL kept")
			assert.True(t, ci.IsActive)
			assert.Equal(t, hookSecret, ci.Secret)
			assert.True(t, ci.Push && ci.Create && ci.Delete && ci.PullRequest)
			assert.False(t, ci.Fork)
			assert.Equal(t, "https://hooks.example.com", item(t, report, "hook", "RUL hook 1").Name)
			assert.Contains(t, item(t, report, "hook", "RUL hook 1").Reason, "mirror:repo_synchronized")
			nosecret := byURL["https://hooks.example.com/nosecret"]
			require.NotNil(t, nosecret)
			assert.False(t, nosecret.IsActive, "no secret: inactive")

			repoHooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{RepoID: svc.ID})
			require.NoError(t, err)
			require.Len(t, repoHooks, 1)
			assert.Equal(t, "https://hooks.example.com/repo", repoHooks[0].URL)
			assert.True(t, repoHooks[0].PullRequestComment)
			assert.Equal(t, migrations.BitbucketSkipped, item(t, report, "hook", "RUL/svc hook 3").Status)
			assert.Equal(t, migrations.BitbucketSkipped, item(t, report, "hook", "RUL/svc hook 4").Status)
		})

		t.Run("branching model", func(t *testing.T) {
			eff, err := branchworkflow.GetEffectiveModel(ctx, svc)
			require.NoError(t, err)
			require.NotNil(t, eff.Configured)
			assert.Equal(t, repo_model.BranchingModel{DevelopmentBranch: "develop", ProductionBranch: "master", ReleasePrefixes: []string{"release/"}}, *eff.Configured, "only release branches cascade in Bitbucket")
			assert.Equal(t, migrations.BitbucketCreated, item(t, report, "branching_model", "RUL/svc branching model").Status)

			lib, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, "lib")
			require.NoError(t, err)
			eff, err = branchworkflow.GetEffectiveModel(ctx, lib)
			require.NoError(t, err)
			assert.Nil(t, eff.Configured, "no release branch type: nothing to import")
		})

		t.Run("a rerun creates nothing new", func(t *testing.T) {
			before := countBitbucketImportRows(t)
			again := run(t, opts)
			assert.False(t, again.Blocked)
			assert.Equal(t, before, countBitbucketImportRows(t))
			for _, kind := range []string{"rule", "hook", "branching_model"} {
				for _, it := range again.Items {
					if it.Kind == kind {
						assert.NotContains(t, []string{migrations.BitbucketPlanned, migrations.BitbucketCreated, migrations.BitbucketFailed}, it.Status, it.Bitbucket)
					}
				}
			}
		})

		t.Run("writing a rule rechecks the open pull requests", func(t *testing.T) {
			api, err := repo_model.GetRepositoryByPath(ctx, org.ID, group.Name, "api")
			require.NoError(t, err)
			rule, err := git_model.GetProtectedBranchRuleByName(ctx, api.ID, "master")
			require.NoError(t, err)
			require.NotNil(t, rule)
			_, err = db.Exec(ctx, "DELETE FROM protected_branch WHERE id = ? AND repo_id = ?", rule.ID, api.ID)
			require.NoError(t, err)
			checker, cleanup := test.NewLogChecker(log.DEFAULT, log.TRACE)
			defer cleanup()
			checker.Filter("to the test pull requests queue")
			again := run(t, opts)
			assert.Equal(t, migrations.BitbucketCreated, item(t, again, "rule", "RUL/api refs/heads/master").Status)
			found, _ := checker.Check(5 * time.Second)
			assert.True(t, found[0], "the imported pull request of api was queued for a check")
		})

		t.Run("a rule or hook in another shape blocks the run", func(t *testing.T) {
			develop := projectRule(t, "develop")
			_, err := db.Exec(ctx, "UPDATE protected_branch SET require_signed_commits = ? WHERE id = ? AND org_id = ? AND group_id = ?", true, develop.ID, org.ID, group.ID)
			require.NoError(t, err)
			assert.Equal(t, migrations.BitbucketConflict, item(t, blocked(t, opts), "rule", "RUL refs/heads/develop").Status)
			_, err = db.Exec(ctx, "UPDATE protected_branch SET require_signed_commits = ? WHERE id = ? AND org_id = ? AND group_id = ?", false, develop.ID, org.ID, group.ID)
			require.NoError(t, err)

			_, err = db.Exec(ctx, "UPDATE webhook SET is_active = ? WHERE owner_id = ? AND group_id = ? AND url = ?", false, org.ID, group.ID, "https://hooks.example.com/ci?token="+hookToken+"#frag")
			require.NoError(t, err)
			assert.Equal(t, migrations.BitbucketConflict, item(t, blocked(t, opts), "hook", "RUL hook 1").Status)
			_, err = db.Exec(ctx, "UPDATE webhook SET is_active = ? WHERE owner_id = ? AND group_id = ? AND url = ?", true, org.ID, group.ID, "https://hooks.example.com/ci?token="+hookToken+"#frag")
			require.NoError(t, err)

			assert.False(t, run(t, opts).Blocked, "both are back in shape")
		})
	})
}
