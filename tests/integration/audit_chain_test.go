// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sealAll(t *testing.T) error {
	t.Helper()
	return audit_service.SealAll(t.Context())
}

func sealedThrough(t *testing.T) string {
	t.Helper()
	head, err := audit_model.GetHead(t.Context())
	require.NoError(t, err)
	return fmt.Sprintf("%d:%s", head.Seq, head.Hash)
}

// AC5: every export seals first, so its headers and its seq columns are filled.
func TestAuditChainExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	insertAuditRows(t)
	admin := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeReadAdmin)

	resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=credential&format=csv"), http.StatusOK)
	through := resp.Header().Get("X-Audit-Sealed-Through")
	assert.Equal(t, sealedThrough(t), through)
	assert.NotEqual(t, "0:", through[:2], through)
	records, err := csv.NewReader(strings.NewReader(resp.Body.String())).ReadAll()
	require.NoError(t, err)
	require.Greater(t, len(records), 1)
	seqCol := len(records[0]) - 3
	assert.Equal(t, "seq", records[0][seqCol])
	for _, r := range records[1:] {
		assert.NotEmpty(t, r[seqCol])
		assert.Len(t, r[seqCol+2], 64)
	}

	insertAuditRows(t) // new unsealed rows; the API export seals them too
	resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?category=all&format=json").AddTokenAuth(token), http.StatusOK)
	assert.Equal(t, sealedThrough(t), resp.Header().Get("X-Audit-Sealed-Through"))

	insertAuditRows(t)
	path := filepath.Join(t.TempDir(), "audit.csv")
	_, err = runMainApp("admin", "audit", "export", "--category", "all", "--output", path)
	require.NoError(t, err)
	out, err := os.ReadFile(path)
	require.NoError(t, err)
	records, err = csv.NewReader(strings.NewReader(string(out))).ReadAll()
	require.NoError(t, err)
	for _, r := range records[1:] {
		assert.NotEmpty(t, r[seqCol], "every exported row is sealed")
	}
}

// AC6
func TestAuditChainPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	insertAuditRows(t)
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM audit_chain_head") // a fresh install has no head row
	require.NoError(t, err)
	setUserFlag(t, 2, "is_auditor", true)
	sessions := map[string]*TestSession{"user1": loginUser(t, "user1"), "user2": loginUser(t, "user2")}
	for name, session := range sessions { // the sign-ins are unsealed entries too
		body := session.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Nothing sealed yet · ", name)
		assert.Contains(t, body, " unsealed (oldest ")
	}

	require.NoError(t, sealAll(t))
	head, err := audit_model.GetHead(t.Context())
	require.NoError(t, err)
	for name, session := range sessions {
		body := session.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all"), http.StatusOK).Body.String()
		assert.Contains(t, body, fmt.Sprintf("Sealed through #%d (", head.Seq), name)
		assert.Contains(t, body, " UTC) · 0 unsealed")
		assert.Contains(t, body, fmt.Sprintf("Current anchor %d:%s", head.Seq, head.Hash))
		assert.Contains(t, body, "gitdepo admin audit verify")
		assert.NotContains(t, body, "✓")
		assert.NotContains(t, body, "&#10003;")
	}
}

// AC4: the CLI exits 1 on a broken chain and 0 on a clean one.
func TestAuditChainVerifyCLI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	insertAuditRows(t)
	require.NoError(t, sealAll(t))

	out, err := runMainApp("admin", "audit", "verify")
	require.NoError(t, err)
	assert.Contains(t, out, "OK")
	assert.Contains(t, out, sealedThrough(t))

	_, err = db.GetEngine(t.Context()).Exec("UPDATE audit_event SET target_name = 'edited' WHERE seq = 3")
	require.NoError(t, err)
	out, err = runMainApp("admin", "audit", "verify")
	require.Error(t, err)
	assert.Contains(t, out, "FAILED at seq 3: hash")

	out, err = runMainApp("admin", "audit", "verify", "--from", "4")
	require.NoError(t, err)
	assert.Contains(t, out, "rows before seq 4 were not checked")
}
