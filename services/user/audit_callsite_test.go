// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditedUserColumns are the user columns whose changes the audit log must see. rands is not one of them: it only
// salts the activation and reset tokens (updateActivation writes it with every email activation).
var auditedUserColumns = []string{
	"is_active", "prohibit_login", "is_admin", "is_auditor", "is_restricted", "passwd", "must_change_password", "email",
	"login_source", "login_name", "login_type", "visibility", "require_two_factor", "restrict_repo_visibility_change",
	"private_fork_policy", "repo_admin_change_team_access",
}

// auditedRepoColumns are the repository columns whose changes the audit log must see.
var auditedRepoColumns = []string{"is_private", "is_archived", "default_branch"}

// auditedWrites are the functions allowed to write those columns, or to delete keys, key selections or access tokens,
// with why.
// A new write elsewhere fails TestAuditCallSites: record it in its function, or add it here with a reason.
var auditedWrites = map[string]string{
	// user columns
	"services/user.UpdateUser":                       "records account.user.updated",
	"services/user.UpdateAuth":                       "records account.user.password_changed and account.user.updated",
	"services/user.deleteUserAccount":                "records account.user.purge_started",
	"services/user.tombstoneUser":                    "part of account.user.deleted (tombstone)",
	"services/user.AdminAddOrSetPrimaryEmailAddress": "records account.email.*",
	"services/user.ReplacePrimaryEmailAddress":       "records account.email.*",
	"services/user.MakeEmailAddressPrimary":          "records account.email.primary",
	"services/user.ActivateAccount":                  "records account.user.activated",
	"models/user.ActivateUserEmail":                  "records account.email.* and account.user.updated",
	"models/user.DeletePrimaryEmailAddressOfUser":    "records account.email.deleted (organizations only)",
	"models/user.SetMustChangePassword":              "records account.user.must_change_password",
	"services/usergroup.syncRoles":                   "records account.user.role_granted|revoked",
	"services/remote.MaybePromoteRemoteUser":         "records account.user.updated",
	"services/auth/source/db.Authenticate":           "not recorded: the password rehash at sign-in keeps the same password",
	"models/actions.NewRunnerToken":                  "not the user table (a runner token's is_active)",

	// SSH keys and access tokens
	"services/user.deleteUser":                     "counted in account.user.deleted (bulk, with the account)",
	"models/auth.DeleteAccessTokenByID":            "records credential.access_token.deleted",
	"models/asymkey.deleteKeysMarkedForDeletion":   "records credential.ssh_key.deleted (login source sync)",
	"services/asymkey.DeletePublicKey":             "records credential.ssh_key.deleted",
	"models/asymkey.deleteGPGKey":                  "its one caller DeleteGPGKey records credential.gpg_key.deleted",
	"models.DeleteDeployKey":                       "records credential.deploy_key.deleted",
	"models/asymkey.DeleteOrgDeployKey":            "records credential.org_deploy_key|project_deploy_key.deleted",
	"models/asymkey.SetOrgDeployKeyRepos":          "records credential.org_deploy_key.updated",
	"models/asymkey.RemoveOrgDeployKeyRepo":        "records credential.org_deploy_key.updated",
	"services/repository.DeleteRepositoryDirectly": "records repo.repository.deleted with the counts (selection rows, runners, tokens, collaborators)",
	"services/repository.transferOwnership":        "records repo.repository.transferred or repo.transfer.accepted with the counts",

	// OAuth2 apps and grants, authorized integrations, runners
	"models/auth.deleteOAuth2Application":            "its caller DeleteOAuth2Application records credential.oauth2_app.deleted; Init removes builtin apps unrecorded",
	"models/auth.RevokeOAuth2Grant":                  "records credential.oauth2_grant.revoked",
	"models/auth.DeleteOAuth2RelictsByUserID":        "counted in account.user.deleted (bulk, with the account)",
	"models/auth.DeleteOrphanedOAuth2Applications":   "doctor: apps of users that no longer exist",
	"models/auth.DeleteAuthorizedIntegrationByID":    "records credential.authorized_integration.deleted",
	"models/actions.deleteRunner":                    "records credential.runner.deleted",
	"models/actions.FixRunnersWithoutBelongingOwner": "doctor: runners of owners that no longer exist",
	"models/actions.FixRunnersWithoutBelongingRepo":  "doctor: runners of repositories that no longer exist",
	"models/auth.DeleteOwnedAccessTokens":            "its callers record repo.repository.deleted|transferred, org.project.deleted or org.organization.deleted with the counts (access_tokens)",
	"models/organization.DeleteOrganization":         "its caller services/org.DeleteOrganization records org.organization.deleted with the counts; its repositories are deleted first, each recording repo.repository.deleted",

	// login sources, user groups, quota, dynamic settings
	"models/auth.CreateSource":                        "records admin.login_source.created (and deleted when registering fails)",
	"services/auth.DeleteSource":                      "records admin.login_source.deleted",
	"services/usergroup.DeleteGroup":                  "records admin.user_group.deleted",
	"models/organization.DeleteUserGroupMember":       "its caller RemoveMember records admin.user_group.member_removed",
	"models/organization.DeleteSyncedUserGroupMember": "its caller SyncDirectoryGroups records admin.user_group.member_removed",
	"models/organization.DeleteUserGroupTeam":         "its callers UnlinkTeam (records admin.user_group.team_unlinked) and syncOrgAdminLinks",
	"services/usergroup.syncOrgAdminLinks":            "managed links follow the org-admin role and exclusions, recorded with the group or exclusion change",
	"models.DeleteTeam":                               "records org.team.deleted with the counts",
	"models/quota.DeleteRuleByName":                   "records admin.quota_rule.deleted",
	"models/quota.DeleteGroupByName":                  "records admin.quota_group.deleted",
	"models/quota.(*Group).RemoveUserByID":            "records admin.quota_group.user_removed",
	"models/quota.(*Group).RemoveRuleByName":          "records admin.quota_group.rule_removed",
	"models/quota.SetUserGroups":                      "records admin.quota_group.user_groups_set",
	"models/system.SetSettings":                       "records admin.setting.changed",
	"models/system.GetRevision":                       "not a setting: the revision counter of the settings cache",
	"models/system.GetSettingForUpdate":               "not a change: a no-op update that locks the row",

	// organizations and teams
	"models.UpdateTeam":                           "records org.team.updated (its units are rewritten)",
	"models.removeTeamMember":                     "records org.team.member_removed",
	"models.RemoveOrgUser":                        "the org membership follows the team ones, each recorded as org.team.member_removed",
	"models.removeAllRepositories":                "its callers record org.team.repos_removed_all or org.team.deleted with the counts",
	"models/organization.RemoveTeamRepo":          "its callers record org.team.repo_removed or are counted by the project unlink, repository move or delete",
	"models/organization.RemoveOrgRepo":           "team rows of a transferred repository: counted in repo.repository.transferred",
	"models/organization.removeInvite":            "records org.team.invite_removed",
	"models/organization.RemoveVerifiedDomain":    "records org.verified_domain.removed",
	"services/repository.UnlinkTeamFromRepoGroup": "records org.team.project_unlinked",
	"services/user.removeTrashedOrgMemberships":   "records org.team.member_removed for each team",
	"models/repo.DeleteRepoGroup":                 "its callers record org.project.deleted with the counts",

	// repositories
	"models.DeleteRepositoryTransfer":                     "its callers record repo.transfer.accepted|canceled|rejected, or repo.repository.trashed",
	"models/git.RenameBranch":                             "records repo.branch.renamed (the default branch follows the rename)",
	"models/repo.DeleteMirrorByRepoID":                    "its caller ConvertMirrorToNormalRepo records repo.repository.updated (is_mirror) first",
	"models/repo.FixNullArchivedRepository":               "doctor: is_archived NULL to false, no change of state",
	"models/repo.SetArchiveRepoState":                     "its caller services/repository.SetArchiveRepoState records repo.repository.archived|unarchived",
	"models/repo.UpdateDefaultBranch":                     "its caller SetRepoDefaultBranch records repo.repository.updated",
	"modules/repository.UpdateRepository":                 "records repo.repository.updated",
	"modules/repository.ApplyVisibilityChange":            "not the repository table: the actions' is_private follows the recorded visibility change",
	"services/mirror.checkAndUpdateEmptyRepository":       "records repo.repository.updated (the default branch of a mirror's first sync)",
	"services/org.ArchiveOrganization":                    "its repositories, counted in org.organization.archived",
	"services/org.UnarchiveOrganization":                  "its repositories, counted in org.organization.unarchived",
	"services/repository.UpdateRepositoryFromPushOptions": "records repo.repository.updated",
	"services/repository.UpdateRepositoryUnits":           "records repo.units.changed",
	"services/repository.pushUpdates":                     "the default branch of the first push to an empty repository: push activity (PR 3)",
	"services/repository/files.ChangeRepoFiles":           "the default branch of the first commit to an empty repository: push activity (PR 3)",
	"services/user.BlockUser":                             "records repo.collaborator.removed and repo.transfer.canceled (reason blocked)",

	// repository integrations
	"models/repo.deletePushMirrors":              "records repo.push_mirror.deleted for each",
	"models/webhook.DeleteWebhookByID":           "records <level>.webhook.deleted",
	"models/webhook.DeleteDefaultSystemWebhook":  "records admin.webhook.deleted",
	"models/webhook.DeleteOrphanedGroupWebhooks": "doctor: hooks of projects that no longer exist",
	"models/git.DeleteProtectedBranch":           "records repo.branch_protection.deleted",
	"models/git.DeleteOrgProtectedBranch":        "records org.branch_protection.deleted",
	"models/git.DeleteOrgProtectedBranches":      "part of org.organization.deleted: the rules of the deleted organization",
	"models/git.DeleteOrphanedProtectedBranches": "doctor: rules of repositories or organizations that no longer exist",
	"models/git.DeleteProtectedTag":              "records repo.tag_protection.deleted",
	"models/secret.DeleteSecret":                 "records <level>.actions_secret.deleted",
	"models/actions.DeleteRun":                   "its caller services/actions.deleteRun records repo.actions_run.deleted, or its callers DeleteOldRuns/CleanupRuns record repo.actions_runs.*",
	"models/actions.DeleteUnkeptRun":             "its callers DeleteOldRuns and CleanupRuns record repo.actions_runs.deleted_old|cleaned",
}

// TestAuditCallSites walks the code for writes of the audited user columns (UpdateUserCols, and Update/Exec chains on
// the user table) and for deletes of SSH keys and access tokens, and fails on one in a function not listed in
// auditedWrites.
func TestAuditCallSites(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string]token.Position{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "web_src", "public", "tests", "vendor",
				"gitea_migrations", "forgejo_migrations", "forgejo_migrations_legacy": // schema migrations run before any account exists
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil //nolint:nilerr // not our concern here
		}
		pkg, _ := filepath.Rel(root, filepath.Dir(path))
		pkg = filepath.ToSlash(pkg)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := pkg + "." + fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				name = pkg + ".(" + types(fn.Recv.List[0].Type) + ")." + fn.Name.Name
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && isAuditedWrite(call) {
					if _, seen := found[name]; !seen {
						found[name] = fset.Position(call.Pos())
					}
				}
				return true
			})
		}
		return nil
	}))

	for name, pos := range found {
		_, ok := auditedWrites[name]
		assert.True(t, ok, "%s (%s) writes an audited user column or deletes keys/tokens outside a recorded function", name, pos)
	}
	for name := range auditedWrites {
		_, ok := found[name]
		assert.True(t, ok, "%s is listed in auditedWrites but writes nothing audited: remove it", name)
	}
}

func types(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return "*" + types(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return types(e.X)
	}
	return "?"
}

// isAuditedWrite reports whether call writes an audited user column or deletes SSH keys or access tokens.
func isAuditedWrite(call *ast.CallExpr) bool {
	name := callName(call.Fun)
	switch name {
	case "UpdateRepositoryCols":
		return slices.ContainsFunc(literals(call), isAuditedRepoColumn) || len(call.Args) > 2 && slices.ContainsFunc(call.Args[2:], func(a ast.Expr) bool {
			_, lit := a.(*ast.BasicLit)
			return !lit
		}) || call.Ellipsis.IsValid()
	case "UpdateUserCols":
		// a column list that isn't all literals (a variable, a spread) counts: the test can't see what it writes
		return slices.ContainsFunc(literals(call), isAuditedColumn) || len(call.Args) > 2 && slices.ContainsFunc(call.Args[2:], func(a ast.Expr) bool {
			_, lit := a.(*ast.BasicLit)
			return !lit
		}) || call.Ellipsis.IsValid()
	case "Update", "Exec":
		if writesSystemSetting(call) || name == "Exec" && slices.ContainsFunc(literals(call), deletesAuditedTable) {
			return true
		}
		var lits []string
		userTable := false
		for c := call; c != nil; c = receiverCall(c) {
			for _, l := range literals(c) {
				lits = append(lits, l)
				lower := strings.ToLower(l)
				if callName(c.Fun) == "Table" && strings.Trim(lower, "`\"") == "user" ||
					strings.Contains(lower, "update `user`") || strings.Contains(lower, `update "user"`) {
					userTable = true
				}
			}
			for _, a := range c.Args {
				if mentionsType(a, "User") {
					userTable = true
				}
			}
		}
		if slices.ContainsFunc(lits, isAuditedRepoColumn) || slices.ContainsFunc(call.Args, mapHasAuditedRepoKey) {
			return true
		}
		if !userTable && !slices.ContainsFunc(lits, isAuditedColumn) {
			return false
		}
		for _, l := range lits {
			if isAuditedColumn(l) || slices.ContainsFunc(auditedUserColumns, func(c string) bool { return strings.Contains(l, c) && strings.Contains(strings.ToLower(l), "update") }) {
				return true
			}
		}
		return slices.ContainsFunc(call.Args, mapHasAuditedKey)
	case "From":
		if del := receiverCall(call); del == nil || callName(del.Fun) != "Delete" {
			return false
		}
		return slices.ContainsFunc(literals(call), func(l string) bool {
			return slices.Contains(auditedDeleteTables, strings.Trim(l, "`\""))
		})
	case "Delete", "DeleteByBean", "DeleteBeans", "DeleteByID":
		return slices.ContainsFunc(append([]ast.Expr{call.Fun}, call.Args...), func(a ast.Expr) bool {
			return slices.ContainsFunc(auditedDeletes, func(typ string) bool { return mentionsType(a, typ) })
		})
	}
	return false
}

// auditedDeletes are the credential types whose deletes the audit log must see.
var auditedDeletes = []string{
	"PublicKey", "AccessToken", "GPGKey", "DeployKey", "OrgDeployKey", "OrgDeployKeyRepo",
	"OAuth2Application", "OAuth2Grant", "AuthorizedIntegration", "ActionRunner",
	"Source", "UserGroup", "UserGroupUser", "UserGroupTeam", "Rule", "Group", "GroupMapping", "GroupRuleMapping",
	"Team", "TeamUser", "TeamRepo", "TeamUnit", "TeamGroup", "TeamInvite", "OrgUser", "OrgVerifiedDomain", "OrgUnit",
	"Repository", "Collaboration", "RepoUnit", "Mirror", "RepoTransfer", "RepoGroup",
	"PushMirror", "Webhook", "ProtectedBranch", "ProtectedTag", "PushRule", "Secret", "ActionVariable", "ActionRun",
}

// auditedDeleteTables are the tables of auditedDeletes that raw deletes (builder.Delete(...).From(table)) name.
var auditedDeleteTables = []string{
	"oauth2_application", "oauth2_grant", "authorized_integration", "action_runner", "login_source", "user_group",
	"user_group_user", "user_group_team", "quota_rule", "quota_group", "quota_group_mapping", "quota_group_rule_mapping",
	"team", "team_user", "team_repo", "team_unit", "team_group", "team_invite", "org_user", "org_verified_domain", "org_unit",
	"repository", "collaboration", "repo_unit", "mirror", "repo_transfer", "repo_group",
	"push_mirror", "webhook", "protected_branch", "protected_tag", "push_rule", "secret", "action_variable", "action_run",
}

// deletesAuditedTable reports whether the SQL statement sql deletes rows of a table of auditedDeleteTables.
func deletesAuditedTable(sql string) bool {
	sql = strings.ToLower(sql)
	return strings.Contains(sql, "delete from") && slices.ContainsFunc(auditedDeleteTables, func(t string) bool {
		return strings.Contains(sql, "from `"+t+"`") || strings.Contains(sql, `from "`+t+`"`) || strings.Contains(sql, "from "+t+" ")
	})
}

// writesSystemSetting reports whether an Update or Exec chain writes the system_setting table, whose writes only
// SetSettings may make (it records them).
func writesSystemSetting(call *ast.CallExpr) bool {
	for c := call; c != nil; c = receiverCall(c) {
		for _, l := range literals(c) {
			if strings.Contains(strings.ToLower(l), "system_setting") {
				return true
			}
		}
	}
	return false
}

func isAuditedColumn(s string) bool {
	return slices.Contains(auditedUserColumns, s)
}

func isAuditedRepoColumn(s string) bool {
	return slices.Contains(auditedRepoColumns, s)
}

func mapHasAuditedRepoKey(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	return slices.ContainsFunc(lit.Elts, func(el ast.Expr) bool {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		k, ok := kv.Key.(*ast.BasicLit)
		if !ok {
			return false
		}
		s, err := strconv.Unquote(k.Value)
		return err == nil && isAuditedRepoColumn(s)
	})
}

func callName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	case *ast.IndexExpr:
		return callName(f.X)
	case *ast.IndexListExpr:
		return callName(f.X)
	}
	return ""
}

// receiverCall is the call that a method call is made on, as in a.Table(...).Update(...).
func receiverCall(call *ast.CallExpr) *ast.CallExpr {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if c, ok := sel.X.(*ast.CallExpr); ok {
			return c
		}
	}
	return nil
}

func literals(call *ast.CallExpr) []string {
	var out []string
	for _, a := range call.Args {
		if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

// mentionsType reports whether e names the type (as T, pkg.T, &T{} or a type argument).
func mentionsType(e ast.Node, typ string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			found = found || n.Name == typ
		case *ast.FuncLit:
			return false
		}
		return !found
	})
	return found
}

func mapHasAuditedKey(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.BasicLit); ok {
				if s, err := strconv.Unquote(k.Value); err == nil && isAuditedColumn(s) {
					return true
				}
			}
		}
	}
	return false
}
