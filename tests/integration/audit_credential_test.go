// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	asymkey_service "forgejo.org/services/asymkey"
	"forgejo.org/tests"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// newSSHKey returns a fresh authorized_keys line and its SHA256 fingerprint.
func newSSHKey(t *testing.T) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), ssh.FingerprintSHA256(sshPub)
}

// credentialOne returns the one entry of action written after since.
func credentialOne(t *testing.T, since int64, action string) *audit_model.Entry {
	t.Helper()
	entries := auditActions(t, since, action)
	require.Len(t, entries, 1, action)
	assert.Equal(t, audit_model.CategoryCredential, entries[0].Category)
	return entries[0]
}

func TestAuditCredentialSSHKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// web, by the owner
	session := loginUser(t, "user2")
	content, fingerprint := newSSHKey(t)
	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys", map[string]string{
		"type": "ssh", "title": "web-key", "content": content,
	}), http.StatusSeeOther)
	e := credentialOne(t, since, "credential.ssh_key.created")
	assertSubject(t, e, 2, 2)
	assert.Equal(t, "ssh_key", e.TargetType)
	assert.Equal(t, "web-key", e.TargetName)
	data := auditData(t, e)
	assert.Equal(t, fingerprint, data["fingerprint"])
	assert.Equal(t, "user", data["key_type"])
	assert.NotContains(t, data, "on_behalf")
	assert.NotContains(t, e.Data, strings.Fields(content)[1])

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys/delete", map[string]string{
		"type": "ssh", "id": fmt.Sprint(e.TargetID),
	}), http.StatusOK)
	e = credentialOne(t, since, "credential.ssh_key.deleted")
	assertSubject(t, e, 2, 2)
	assert.Equal(t, fingerprint, auditData(t, e)["fingerprint"])

	// API, by the owner
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteUser)
	content, _ = newSSHKey(t)
	since = auditMaxID(t)
	var key api.PublicKey
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/keys", api.CreateKeyOption{Title: "api-key", Key: content}).
		AddTokenAuth(token), http.StatusCreated), &key)
	assertSubject(t, credentialOne(t, since, "credential.ssh_key.created"), 2, 2)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/user/keys/%d", key.ID).AddTokenAuth(token), http.StatusNoContent)
	assertSubject(t, credentialOne(t, since, "credential.ssh_key.deleted"), 2, 2)

	// by a site admin for the user: on_behalf
	admin := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteAdmin)
	content, _ = newSSHKey(t)
	since = auditMaxID(t)
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user2/keys", api.CreateKeyOption{Title: "admin-key", Key: content}).
		AddTokenAuth(admin), http.StatusCreated), &key)
	e = credentialOne(t, since, "credential.ssh_key.created")
	assertSubject(t, e, 1, 2)
	assert.Equal(t, true, auditData(t, e)["on_behalf"])
	since = auditMaxID(t)
	MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/admin/users/user2/keys/%d", key.ID).AddTokenAuth(admin), http.StatusNoContent)
	e = credentialOne(t, since, "credential.ssh_key.deleted")
	assertSubject(t, e, 1, 2)
	assert.Equal(t, true, auditData(t, e)["on_behalf"])
}

func TestAuditCredentialPrincipal(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SSH.RootPath, t.TempDir())()
	ctx := asActor(t, 2, "user2")

	since := auditMaxID(t)
	key, err := asymkey_model.AddPrincipalKey(ctx, 2, "user2@principal", 0)
	require.NoError(t, err)
	e := credentialOne(t, since, "credential.ssh_key.created")
	assertSubject(t, e, 2, 2)
	assert.Equal(t, "principal", auditData(t, e)["key_type"])

	since = auditMaxID(t)
	require.NoError(t, asymkey_service.DeletePublicKey(ctx, &user_model.User{ID: 2}, key.ID))
	assert.Equal(t, "principal", auditData(t, credentialOne(t, since, "credential.ssh_key.deleted"))["key_type"])
}

func TestAuditCredentialKeySync(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SSH.RootPath, t.TempDir())()
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	source := &auth_model.Source{ID: 77, Name: "ldap-audit"}
	ctx := audit_model.WithSystem(t.Context(), "cron:sync_external_users")

	content, fingerprint := newSSHKey(t)
	content2, fingerprint2 := newSSHKey(t)
	since := auditMaxID(t)
	require.True(t, asymkey_model.AddPublicKeysBySource(ctx, user, source, []string{content}))
	require.True(t, asymkey_model.AddPublicKeysBySource(ctx, user, source, []string{content2}))
	e := auditActions(t, since, "credential.ssh_key.created")[0]
	assert.Equal(t, audit_model.ActorSystem, e.ActorType)
	assert.Equal(t, "cron:sync_external_users", e.ActorName)
	assert.EqualValues(t, 2, e.SubjectUserID)
	assert.EqualValues(t, 77, auditData(t, e)["login_source_id"])
	assert.NotContains(t, auditData(t, e), "on_behalf")

	// the second delete's audit write fails: the whole batch rolls back and both keys stay
	func() {
		calls := 0
		defer test.MockVariableValue(&audit_model.InsertEntry, func(ctx context.Context, e *audit_model.Entry) error {
			if calls++; calls == 2 {
				return errors.New("audit down")
			}
			return db.Insert(ctx, e)
		})()
		since := auditMaxID(t)
		asymkey_model.SynchronizePublicKeys(ctx, user, source, nil)
		assert.Equal(t, 2, calls)
		assert.Empty(t, auditActions(t, since, "credential.ssh_key.deleted"))
	}()
	unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{Fingerprint: fingerprint})
	unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{Fingerprint: fingerprint2})

	since = auditMaxID(t)
	require.True(t, asymkey_model.SynchronizePublicKeys(ctx, user, source, nil))
	entries := auditActions(t, since, "credential.ssh_key.deleted")
	require.Len(t, entries, 2)
	e = entries[0]
	assert.Equal(t, "cron:sync_external_users", e.ActorName)
	data := auditData(t, e)
	assert.Equal(t, "login_source_sync", data["reason"])
	assert.EqualValues(t, 77, data["login_source_id"])
	unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{Fingerprint: fingerprint})
	unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{Fingerprint: fingerprint2})
}

func TestAuditCredentialGPGKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")

	entity, err := openpgp.NewEntity("user2", "", "user2@example.com", nil)
	require.NoError(t, err)
	var armored bytes.Buffer
	w, err := armor.Encode(&armored, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, entity.Serialize(w))
	require.NoError(t, w.Close())

	since := auditMaxID(t)
	keys, err := asymkey_model.AddGPGKey(ctx, 2, armored.String(), "", "")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	e := credentialOne(t, since, "credential.gpg_key.created")
	assertSubject(t, e, 2, 2)
	data := auditData(t, e)
	assert.Equal(t, keys[0].KeyID, data["key_id"])
	assert.Len(t, data["subkey_ids"], len(keys[0].SubsKey))
	assert.Equal(t, false, data["verified"])
	assert.NotContains(t, e.Data, "user2@example.com")
	assert.NotContains(t, e.Data, keys[0].Content)

	token := asymkey_model.VerificationToken(unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), 1)
	var sig bytes.Buffer
	require.NoError(t, openpgp.ArmoredDetachSign(&sig, entity, strings.NewReader(token), nil))
	since = auditMaxID(t)
	_, err = asymkey_model.VerifyGPGKey(ctx, 2, keys[0].KeyID, token, sig.String())
	require.NoError(t, err)
	e = credentialOne(t, since, "credential.gpg_key.verified")
	assertSubject(t, e, 2, 2)
	assert.Equal(t, true, auditData(t, e)["verified"])
	require.NotEmpty(t, entity.Subkeys)
	assert.Len(t, auditData(t, e)["subkey_ids"], len(entity.Subkeys))

	since = auditMaxID(t)
	require.NoError(t, asymkey_model.DeleteGPGKey(ctx, &user_model.User{ID: 2}, keys[0].ID))
	assert.Equal(t, keys[0].KeyID, auditData(t, credentialOne(t, since, "credential.gpg_key.deleted"))["key_id"])
}

func TestAuditCredentialDeployKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)

	var repo api.Repository
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", api.CreateRepoOption{Name: "audit-deploy"}).
		AddTokenAuth(token), http.StatusCreated), &repo)

	content, fingerprint := newSSHKey(t)
	since := auditMaxID(t)
	var key api.DeployKey
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/audit-deploy/keys", api.CreateKeyOption{Title: "deploy", Key: content, ReadOnly: true}).
		AddTokenAuth(token), http.StatusCreated), &key)
	e := credentialOne(t, since, "credential.deploy_key.created")
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 2, e.OwnerID)
	assert.Equal(t, repo.ID, e.RepoID)
	assert.Zero(t, e.SubjectUserID)
	data := auditData(t, e)
	assert.Equal(t, fingerprint, data["fingerprint"])
	assert.EqualValues(t, 1, data["mode"])

	since = auditMaxID(t)
	MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/repos/user2/audit-deploy/keys/%d", key.ID).AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, repo.ID, credentialOne(t, since, "credential.deploy_key.deleted").RepoID)

	// a repository delete records each of its keys
	for _, title := range []string{"deploy2", "deploy3"} {
		content, _ = newSSHKey(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/audit-deploy/keys", api.CreateKeyOption{Title: title, Key: content}).
			AddTokenAuth(token), http.StatusCreated)
	}
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/audit-deploy").AddTokenAuth(token), http.StatusNoContent)
	entries := auditActions(t, since, "credential.deploy_key.deleted")
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.Equal(t, repo.ID, e.RepoID)
	}
	assert.ElementsMatch(t, []string{"deploy2", "deploy3"}, []string{entries[0].TargetName, entries[1].TargetName})

	// a key of a repository in a project records the project
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(t.Context(), org, "audit-deploy-project", "")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET group_id = ? WHERE id = 3", group.ID)
	require.NoError(t, err)
	content, _ = newSSHKey(t)
	since = auditMaxID(t)
	_, err = asymkey_model.AddDeployKey(asActor(t, 2, "user2"), 3, "in-project", content, true, 0)
	require.NoError(t, err)
	e = credentialOne(t, since, "credential.deploy_key.created")
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Equal(t, group.ID, e.GroupID)
	assert.EqualValues(t, 3, e.RepoID)
}

func TestAuditCredentialOrgDeployKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SSH.RootPath, t.TempDir())()
	ctx := asActor(t, 2, "user2")

	content, fingerprint := newSSHKey(t)
	since := auditMaxID(t)
	key, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "org-key", content, false, false, []int64{3}, 0)
	require.NoError(t, err)
	e := credentialOne(t, since, "credential.org_deploy_key.created")
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Zero(t, e.GroupID)
	assert.Zero(t, e.SubjectUserID)
	data := auditData(t, e)
	assert.Equal(t, fingerprint, data["fingerprint"])
	assert.Equal(t, false, data["all_repos"])
	assert.Equal(t, []any{float64(3)}, data["repo_ids"])

	since = auditMaxID(t)
	require.NoError(t, asymkey_service.AddOrgDeployKeyRepo(ctx, 3, key.ID, &repo_model.Repository{ID: 5}))
	assert.Equal(t, []any{float64(5)}, auditData(t, credentialOne(t, since, "credential.org_deploy_key.updated"))["repos_added"])

	since = auditMaxID(t)
	require.NoError(t, asymkey_service.RemoveOrgDeployKeyRepo(ctx, 3, key.ID, &repo_model.Repository{ID: 3, OwnerID: 3}))
	assert.Equal(t, []any{float64(3)}, auditData(t, credentialOne(t, since, "credential.org_deploy_key.updated"))["repos_removed"])

	since = auditMaxID(t)
	require.NoError(t, asymkey_service.SetOrgDeployKeyRepos(ctx, 3, key.ID, false, []int64{3, 32}))
	data = auditData(t, credentialOne(t, since, "credential.org_deploy_key.updated"))
	assert.ElementsMatch(t, []any{float64(3), float64(32)}, data["repos_added"])
	assert.Equal(t, []any{float64(5)}, data["repos_removed"])

	since = auditMaxID(t)
	require.NoError(t, asymkey_service.SetOrgDeployKeyAllRepos(ctx, 3, key.ID, true))
	data = auditData(t, credentialOne(t, since, "credential.org_deploy_key.updated"))
	assert.Equal(t, map[string]any{"all_repos": false}, data["before"])
	assert.Equal(t, map[string]any{"all_repos": true}, data["after"])

	since = auditMaxID(t)
	require.NoError(t, asymkey_service.DeleteOrgDeployKey(ctx, 3, 0, key.ID))
	assert.Equal(t, "org-key", credentialOne(t, since, "credential.org_deploy_key.deleted").TargetName)

	// a project key
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(t.Context(), org, "audit-project", "")
	require.NoError(t, err)
	content, _ = newSSHKey(t)
	since = auditMaxID(t)
	key, err = asymkey_model.AddOrgDeployKey(ctx, 3, group.ID, "project-key", content, true, false, nil, 0)
	require.NoError(t, err)
	e = credentialOne(t, since, "credential.project_deploy_key.created")
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Equal(t, group.ID, e.GroupID)
	since = auditMaxID(t)
	require.NoError(t, asymkey_service.DeleteOrgDeployKey(ctx, 3, group.ID, key.ID))
	assert.Equal(t, group.ID, credentialOne(t, since, "credential.project_deploy_key.deleted").GroupID)
}

func TestAuditCredentialOrgDeployKeyLargeSelection(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")

	repoIDs := make([]int64, 1000)
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		for i := range repoIDs {
			name := fmt.Sprintf("audit-sel-%d", i)
			repo := &repo_model.Repository{OwnerID: 3, OwnerName: "org3", Name: name, LowerName: name}
			if err := db.Insert(ctx, repo); err != nil {
				return err
			}
			repoIDs[i] = repo.ID
		}
		return nil
	}))

	content, _ := newSSHKey(t)
	key, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "big-key", content, true, false, []int64{3}, 0)
	require.NoError(t, err)
	since := auditMaxID(t)
	require.NoError(t, asymkey_service.SetOrgDeployKeyRepos(ctx, 3, key.ID, false, repoIDs))
	data := auditData(t, credentialOne(t, since, "credential.org_deploy_key.updated"))
	assert.Len(t, data["repos_added"], 1000)
	assert.Equal(t, []any{float64(3)}, data["repos_removed"])
}

func TestAuditCredentialFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SSH.RootPath, t.TempDir())()
	ctx := asActor(t, 2, "user2")
	orgKeyContent, _ := newSSHKey(t)
	key, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "kept-key", orgKeyContent, true, false, []int64{3}, 0)
	require.NoError(t, err)
	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
		return errors.New("audit down")
	})()

	// the authorized_keys file gets no line for the rolled-back key
	defer test.MockVariableValue(&setting.SSH.StartBuiltinServer, false)()
	defer test.MockVariableValue(&setting.SSH.CreateAuthorizedKeysFile, true)()
	content, fingerprint := newSSHKey(t)
	_, err = asymkey_model.AddPublicKey(ctx, 2, "fail-key", content, 0, 0)
	require.Error(t, err)
	unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{Fingerprint: fingerprint})
	deployContent, deployFingerprint := newSSHKey(t)
	_, err = asymkey_model.AddDeployKey(ctx, 1, "fail-deploy", deployContent, true, 0)
	require.Error(t, err)
	unittest.AssertNotExistsBean(t, &asymkey_model.DeployKey{Fingerprint: deployFingerprint})
	unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{Fingerprint: deployFingerprint})
	orgContent, orgFingerprint := newSSHKey(t)
	_, err = asymkey_model.AddOrgDeployKey(ctx, 3, 0, "fail-org", orgContent, true, true, nil, 0)
	require.Error(t, err)
	unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{Fingerprint: orgFingerprint})
	unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{Fingerprint: orgFingerprint})
	authorizedKeys, _ := os.ReadFile(filepath.Join(setting.SSH.RootPath, "authorized_keys"))
	for _, c := range []string{content, deployContent, orgContent} {
		assert.NotContains(t, string(authorizedKeys), strings.Fields(c)[1])
	}

	before, err := asymkey_model.GetOrgDeployKeyRepoIDs(t.Context(), []int64{key.ID})
	require.NoError(t, err)
	require.Error(t, asymkey_service.SetOrgDeployKeyAllRepos(ctx, key.OrgID, key.ID, !key.IncludesAllRepos))
	require.Error(t, asymkey_service.SetOrgDeployKeyRepos(ctx, key.OrgID, key.ID, false, []int64{3, 5}))
	unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID, IncludesAllRepos: key.IncludesAllRepos})
	after, err := asymkey_model.GetOrgDeployKeyRepoIDs(t.Context(), []int64{key.ID})
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
