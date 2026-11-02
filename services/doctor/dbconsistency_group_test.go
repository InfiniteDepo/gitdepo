// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package doctor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Project secrets and variables whose project is gone, belongs to another organization, or whose owner is not an
// organization are orphans; everything else stays.
func TestOrphanedGroupRows(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	_, err = secret_model.InsertEncryptedSecret(ctx, 3, group.ID, 0, "GOOD", "x")
	require.NoError(t, err)
	_, err = secret_model.InsertEncryptedSecret(ctx, 3, 0, 0, "ORG", "x")
	require.NoError(t, err)
	_, err = actions_model.InsertVariable(ctx, 3, group.ID, 0, "GOOD", "x")
	require.NoError(t, err)
	for _, table := range []string{"secret", "action_variable"} {
		count := func() int64 {
			n, err := db.GetEngine(ctx).Table(table).Where(orphanedGroupRowsCond(table, "owner_id")).Count()
			require.NoError(t, err)
			return n
		}
		assert.EqualValues(t, 0, count(), table)
		extraCol, extraVal := "created_unix", "0"
		if table == "action_variable" {
			extraCol, extraVal = "created_unix, data", "0, ''"
		}
		for _, ids := range [][2]int64{{3, 999}, {4, group.ID}, {2, group.ID}} { // missing project, another owner's, a user
			_, err := db.Exec(ctx, "INSERT INTO `"+table+"` (owner_id, group_id, repo_id, name, "+extraCol+") VALUES (?, ?, 0, 'BAD', "+extraVal+")", ids[0], ids[1])
			require.NoError(t, err)
		}
		assert.EqualValues(t, 3, count(), table)
		_, err := db.GetEngine(ctx).Table(table).Where(orphanedGroupRowsCond(table, "owner_id")).Delete()
		require.NoError(t, err)
		assert.EqualValues(t, 0, count(), table)
		n, err := db.GetEngine(ctx).Table(table).Where("name = 'GOOD'").Count()
		require.NoError(t, err)
		assert.EqualValues(t, 1, n, table)
	}
}

// Project deploy keys whose project is gone or belongs to another organization are orphans: the fix deletes them
// with their public keys; organization keys and keys of a live project stay.
func TestOrphanedProjectDeployKeys(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(func() { require.NoError(t, unittest.PrepareTestDatabase()) })
	ctx := t.Context()
	dir := t.TempDir()
	defer test.MockVariableValue(&setting.SSH.StartBuiltinServer, false)()
	defer test.MockVariableValue(&setting.SSH.CreateAuthorizedKeysFile, true)()
	defer test.MockVariableValue(&setting.SSH.RootPath, dir)()
	authorizedKeys := func() string {
		data, err := os.ReadFile(filepath.Join(dir, "authorized_keys"))
		require.NoError(t, err)
		return string(data)
	}
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	orphanContent := newDeployKeyContent(t)
	orphan, err := asymkey_model.AddOrgDeployKey(ctx, 3, group.ID, "orphan", orphanContent, true, false, nil, 0)
	require.NoError(t, err)
	_, err = db.Exec(ctx, "UPDATE org_deploy_key SET group_id = 999 WHERE id = ?", orphan.ID) // its project is gone
	require.NoError(t, err)
	good, err := asymkey_model.AddOrgDeployKey(ctx, 3, group.ID, "good", newDeployKeyContent(t), true, false, nil, 0)
	require.NoError(t, err)
	org, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "org", newDeployKeyContent(t), true, true, nil, 0)
	require.NoError(t, err)
	for i, ids := range [][2]int64{{3, 999}, {17, group.ID}} { // missing project, another organization's
		_, err := db.Exec(ctx, "INSERT INTO org_deploy_key (key_id, org_id, group_id, name, mode) VALUES (?, ?, ?, 'bad', 1)", 9000+i, ids[0], ids[1])
		require.NoError(t, err)
	}

	require.NoError(t, asymkey_model.RewriteAllPublicKeys(ctx))
	require.Contains(t, authorizedKeys(), strings.Fields(orphanContent)[1])
	assert.EqualValues(t, 3, countOrphanedProjectDeployKeys(ctx, t))
	_, err = fixOrphanedProjectDeployKeys(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 0, countOrphanedProjectDeployKeys(ctx, t))
	unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{ID: orphan.KeyID})
	assert.NotContains(t, authorizedKeys(), strings.Fields(orphanContent)[1], "the fix rewrites authorized_keys")
	unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: good.ID})
	unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: org.ID})
}

func countOrphanedProjectDeployKeys(ctx context.Context, t *testing.T) int64 {
	t.Helper()
	n, err := db.GetEngine(ctx).Table("org_deploy_key").Where(orphanedGroupRowsCond("org_deploy_key", "org_id")).Count()
	require.NoError(t, err)
	return n
}

func newDeployKeyContent(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(sshPub))
}
