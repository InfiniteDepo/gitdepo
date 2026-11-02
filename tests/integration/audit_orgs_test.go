// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/branchworkflow"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	trash_service "forgejo.org/services/trash"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orgOne returns the one entry of action written after since, and checks it is an organization entry.
func orgOne(t *testing.T, since int64, action string) *audit_model.Entry {
	t.Helper()
	entries := auditActions(t, since, action)
	require.Len(t, entries, 1, action)
	assert.Equal(t, audit_model.CategoryOrg, entries[0].Category)
	return entries[0]
}

func TestAuditOrgLifecycle(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Trash.RetentionDays, 30)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization)

	since := auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "audit-org", Visibility: "public"}).AddTokenAuth(token), http.StatusCreated)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "audit-org", Type: user_model.UserTypeOrganization})
	e := orgOne(t, since, "org.organization.created")
	assert.EqualValues(t, 2, e.ActorID)
	assert.Equal(t, org.ID, e.OwnerID)
	assert.Equal(t, "org", e.TargetType)
	assert.Equal(t, org.ID, e.TargetID)
	assert.EqualValues(t, 2, auditData(t, e)["user_id"])
	created := e.ID

	// settings: before/after of what changed, nothing for an unchanged save
	edit := func(opt api.EditOrgOption) {
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/"+org.Name, &opt).AddTokenAuth(token), http.StatusOK)
	}
	since = auditMaxID(t)
	edit(api.EditOrgOption{Visibility: new("private"), PrivateForkPolicy: new("none")})
	data := auditData(t, orgOne(t, since, "org.organization.updated"))
	assert.Equal(t, map[string]any{"visibility": float64(0), "private_fork_policy": float64(0)}, data["before"])
	assert.Equal(t, map[string]any{"visibility": float64(2), "private_fork_policy": float64(2)}, data["after"])
	since = auditMaxID(t)
	edit(api.EditOrgOption{Visibility: new("private"), Description: new("only text")})
	assert.Empty(t, auditActions(t, since, "org.organization.updated"), "an unchanged save records nothing")

	// renames, on the API and the web
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/audit-org/rename", &api.RenameOrgOption{NewName: "audit-org-2"}).AddTokenAuth(token), http.StatusNoContent)
	data = auditData(t, orgOne(t, since, "org.organization.renamed"))
	assert.Equal(t, map[string]any{"name": "audit-org"}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-org-2"}, data["after"])
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/audit-org-2/settings", map[string]string{"name": "audit-org-3", "visibility": "2"}), http.StatusSeeOther)
	assert.Equal(t, map[string]any{"name": "audit-org-3"}, auditData(t, orgOne(t, since, "org.organization.renamed"))["after"])
	org = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: org.ID})

	// archive and unarchive count the repositories they change
	ctx := asActor(t, 2, "user2")
	repo, err := repo_service.CreateRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), org, repo_service.CreateRepoOptions{Name: "audit-repo"})
	require.NoError(t, err)
	since = auditMaxID(t)
	require.NoError(t, org_service.ArchiveOrganization(ctx, (*org_model.Organization)(org), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), false))
	assert.Equal(t, map[string]any{"repos": float64(1)}, auditData(t, orgOne(t, since, "org.organization.archived"))["counts"])
	require.NoError(t, org_service.UnarchiveOrganization(ctx, (*org_model.Organization)(org)))
	assert.Equal(t, map[string]any{"repos": float64(1)}, auditData(t, orgOne(t, since, "org.organization.unarchived"))["counts"])

	// trash, restore, then purge: the purge is the delete with purge set, and the earlier entries stay
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	admin := asActor(t, 1, "user1")
	since = auditMaxID(t)
	require.NoError(t, org_service.TrashOrganization(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), (*org_model.Organization)(org)))
	assert.Equal(t, map[string]any{"repos": float64(1)}, auditData(t, orgOne(t, since, "org.organization.trashed"))["counts"])
	require.NoError(t, trash_service.RestoreOrg(admin, doer, org.ID, trash_service.RestoreOptions{}))
	assert.Equal(t, map[string]any{"repos": float64(1)}, auditData(t, orgOne(t, since, "org.organization.restored"))["counts"])

	require.NoError(t, db.Insert(ctx, &actions_model.ActionRunner{UUID: "audit-org-runner", Name: "r", OwnerID: org.ID}))
	require.NoError(t, org_service.TrashOrganization(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), (*org_model.Organization)(org)))
	since = auditMaxID(t)
	require.NoError(t, trash_service.PurgeOrg(admin, doer, org.ID))
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	e = orgOne(t, since, "org.organization.deleted")
	assert.EqualValues(t, 1, e.ActorID)
	data = auditData(t, e)
	assert.Equal(t, true, data["purge"])
	counts := data["counts"].(map[string]any)
	assert.EqualValues(t, 1, counts["teams"])
	assert.EqualValues(t, 1, counts["members"])
	assert.EqualValues(t, 1, counts["runners"])
	unittest.AssertExistsAndLoadBean(t, &audit_model.Entry{ID: created})
}

func TestAuditOrgSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&org_service.LookupTXT, func(_ context.Context, name string) ([]string, error) {
		return []string{org_service.DomainRecordValue(3, "audit.example")}, nil
	})()
	ctx := asActor(t, 2, "user2")
	org3 := unittest.AssertExistsAndLoadBean(t, &org_model.Organization{ID: 3})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	since := auditMaxID(t)
	require.NoError(t, org_service.VerifyDomain(ctx, org3, owner, "audit.example", false))
	e := orgOne(t, since, "org.verified_domain.added")
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Equal(t, map[string]any{"domain": "audit.example"}, auditData(t, e))
	require.NoError(t, org_service.VerifyDomain(asActor(t, 1, "user1"), org3, admin, "admin.example", true))
	assert.Equal(t, true, auditData(t, auditActions(t, since, "org.verified_domain.added")[1])["verified_by_admin"])

	since = auditMaxID(t)
	require.NoError(t, org_service.SetVerifiedDomainRequired(ctx, org3, true))
	require.NoError(t, org_service.SetVerifiedDomainRequired(ctx, org3, true))
	assert.Equal(t, map[string]any{"required": true}, auditData(t, orgOne(t, since, "org.verified_domain.required_changed"))["after"])

	// removing a domain records it; removing the last one also clears the requirement
	since = auditMaxID(t)
	require.NoError(t, org_model.RemoveVerifiedDomain(ctx, org3.AsUser(), "admin.example"))
	require.NoError(t, org_model.RemoveVerifiedDomain(ctx, org3.AsUser(), "admin.example"))
	assert.Equal(t, "admin.example", auditData(t, orgOne(t, since, "org.verified_domain.removed"))["domain"])
	assert.Empty(t, auditActions(t, since, "org.verified_domain.required_changed"))
	require.NoError(t, org_model.RemoveVerifiedDomain(ctx, org3.AsUser(), "audit.example"))
	assert.Len(t, auditActions(t, since, "org.verified_domain.removed"), 2)
	assert.Equal(t, map[string]any{"required": false}, auditData(t, orgOne(t, since, "org.verified_domain.required_changed"))["after"])
	required, err := org_model.IsVerifiedDomainRequired(t.Context(), 3)
	require.NoError(t, err)
	assert.False(t, required)

	since = auditMaxID(t)
	require.NoError(t, repo_model.SetOrgUnits(ctx, org3.AsUser(), 2, map[unit.Type]bool{unit.TypeWiki: false, unit.TypeIssues: true}))
	require.NoError(t, repo_model.SetOrgUnits(ctx, org3.AsUser(), 2, map[unit.Type]bool{unit.TypeWiki: false}))
	data := auditData(t, orgOne(t, since, "org.units.changed"))
	assert.Equal(t, map[string]any{"units": []any{"wiki:on"}}, data["before"])
	assert.Equal(t, map[string]any{"units": []any{"wiki:off"}}, data["after"])

	since = auditMaxID(t)
	require.NoError(t, branchworkflow.SetOrg(ctx, org3.AsUser(), repo_model.DeleteBranchAlways, true))
	require.NoError(t, branchworkflow.SetOrg(ctx, org3.AsUser(), repo_model.DeleteBranchAlways, true))
	data = auditData(t, orgOne(t, since, "org.branch_workflow.changed"))
	assert.Equal(t, map[string]any{"mode": "inherit", "locked": false}, data["before"])
	assert.Equal(t, map[string]any{"mode": "always", "locked": true}, data["after"])
	mode, locked, err := branchworkflow.GetOrg(t.Context(), org3.AsUser())
	require.NoError(t, err)
	assert.Equal(t, repo_model.DeleteBranchAlways, mode)
	assert.True(t, locked)

	since = auditMaxID(t)
	model := &repo_model.BranchingModel{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}}
	require.NoError(t, branchworkflow.SetOrgModel(ctx, org3.AsUser(), model, true))
	require.NoError(t, branchworkflow.SetOrgModel(ctx, org3.AsUser(), model, true))
	data = auditData(t, orgOne(t, since, "org.branch_workflow.changed"))
	assert.Equal(t, map[string]any{"development_branch": "", "release_prefixes": []any{}, "model_locked": false}, data["before"])
	assert.Equal(t, map[string]any{"development_branch": "develop", "release_prefixes": []any{"release/"}, "model_locked": true}, data["after"])

	require.NoError(t, branchworkflow.SetOrgModel(ctx, org3.AsUser(), nil, false))
	since = auditMaxID(t)
	repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	require.NoError(t, branchworkflow.SetRepoModel(ctx, repo3, &repo_model.BranchingModel{ReleasePrefixes: []string{"rel-"}}))
	repo3 = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	require.NoError(t, branchworkflow.SetRepoModel(ctx, repo3, &repo_model.BranchingModel{ReleasePrefixes: []string{"rel-"}}))
	data = auditData(t, auditOne(t, since, "repo.branch_workflow.changed"))
	assert.Equal(t, map[string]any{"release_prefixes": []any{}, "inherit": true}, data["before"])
	assert.Equal(t, map[string]any{"release_prefixes": []any{"rel-"}, "inherit": false}, data["after"])
}

// TestAuditOrgSettingsRollback checks that a failed entry fails the change and leaves no new value cached.
func TestAuditOrgSettingsRollback(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	func() {
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
			return errors.New("audit down")
		})()
		require.Error(t, branchworkflow.SetOrg(ctx, org3, repo_model.DeleteBranchAlways, true))
		require.Error(t, user_service.UpdateUser(ctx, org3, &user_service.UpdateOptions{RequireTwoFactor: optional.Some(true)}))
	}()
	mode, locked, err := branchworkflow.GetOrg(t.Context(), org3)
	require.NoError(t, err)
	assert.Equal(t, repo_model.DeleteBranchInherit, mode)
	assert.False(t, locked)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
}

func TestAuditAdminRefusesOrgEdit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteAdmin)

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/3/edit"), http.StatusNotFound)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/3/edit", map[string]string{"login_name": "org3", "email": "org3@example.com", "prohibit_login": "on"}), http.StatusNotFound)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/org3", &api.EditUserOption{ProhibitLogin: new(true)}).AddTokenAuth(token), http.StatusNotFound)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/org3/rename", &api.RenameUserOption{NewName: "org3-renamed"}).AddTokenAuth(token), http.StatusNotFound)
	assert.Empty(t, auditSince(t, since))
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).ProhibitLogin)

	// a site admin sets an organization's limits on its settings page
	limit := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).MaxRepoCreation
	form := getOrgSettingsFormData(t, session, "org3")
	form["email"], form["max_repo_creation"] = "org3@example.com", "7"
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", form), http.StatusSeeOther)
	data := auditData(t, orgOne(t, since, "org.organization.updated"))
	assert.EqualValues(t, limit, data["before"].(map[string]any)["max_repo_creation"])
	assert.EqualValues(t, 7, data["after"].(map[string]any)["max_repo_creation"])
}

func TestAuditQueueRemoveAll(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	var qid int64
	var name string
	for id, mq := range queue.GetManager().ManagedQueues() {
		qid, name = id, mq.GetName()
		break
	}
	require.NotZero(t, qid)

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/monitor/queue/%d/remove-all-items", qid)), http.StatusSeeOther)
	e := adminOne(t, since, "admin.queue.items_removed")
	assert.EqualValues(t, 1, e.ActorID)
	assert.Equal(t, name, auditData(t, e)["name"])
}
