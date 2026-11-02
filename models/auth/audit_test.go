// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth_test

import (
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Redirect URIs and issuers keep only scheme, host and path; an unparseable one is left out (S2).
func TestAuditOAuth2AppRedirectURIs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2"})

	app, err := auth_model.CreateOAuth2Application(ctx, auth_model.CreateOAuth2ApplicationOptions{
		Name: "s2", UserID: 2,
		RedirectURIs: []string{"https://u:p@example.com/cb?code=x#frag", "::bad", "http://localhost:8080/a/b?x=1", "myapp:user:secret@host"},
	})
	require.NoError(t, err)
	e := &audit_model.Entry{}
	has, err := db.GetEngine(db.DefaultContext).Where("action = ? AND target_id = ?", "credential.oauth2_app.created", app.ID).Get(e)
	require.NoError(t, err)
	require.True(t, has)
	data := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(e.Data), &data))
	assert.Equal(t, []any{"https://example.com/cb", "http://localhost:8080/a/b", "myapp:"}, data["redirect_uris"])
	assert.NotContains(t, e.Data, "u:p")
	assert.NotContains(t, e.Data, "secret")
	assert.NotContains(t, e.Data, "::bad")

	assert.Equal(t, "https://issuer.example.org/x", audit_model.URL("https://user:pw@issuer.example.org/x?q=1#f"))
	assert.Empty(t, audit_model.URL("::bad"))
	assert.Equal(t, "myapp:", audit_model.URL("myapp:user:secret@host"))
}
