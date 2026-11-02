// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestActionCatalog checks that every action is written somewhere (a string literal outside the catalog), is used by
// a test, and has a phrase on the audit page.
func TestActionCatalog(t *testing.T) {
	root := filepath.Join("..", "..")
	code, tests := map[string]bool{}, map[string]bool{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "public", "web_src":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, filepath.Join("models", "audit", "catalog.go")) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil //nolint:nilerr // not our concern here
		}
		seen := code
		if strings.HasSuffix(path, "_test.go") {
			seen = tests
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					if _, ok := audit_model.Actions[s]; ok {
						seen[s] = true
					}
				}
			}
			return true
		})
		return nil
	}))

	raw, err := os.ReadFile(filepath.Join(root, "options", "locale_next", "locale_en-US.json"))
	require.NoError(t, err)
	locale := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &locale))

	for action, category := range audit_model.Actions {
		assert.Contains(t, audit_model.Categories, category, action)
		// FlushAggregated writes "<action>.aggregated" for the actions given to RecordAggregated
		assert.True(t, code[action] || code[strings.TrimSuffix(action, ".aggregated")], "%s is never recorded", action)
		assert.True(t, tests[action], "%s has no test", action)
		assert.NotEmpty(t, locale["admin.audit.action."+action], "%s has no phrase", action)
	}
	for _, actor := range []string{
		audit_model.ActorAnonymous, audit_model.ActorDeployKey, audit_model.ActorActions,
		audit_model.ActorRunner, audit_model.ActorLoginSource, audit_model.ActorSystem, audit_model.ActorCLI, audit_model.ActorUnknown,
	} {
		assert.NotEmpty(t, locale["admin.audit.actor."+actor], "actor %s has no phrase", actor)
	}
}

// TestFieldsHoldNoSecrets fails when a whitelist lists a field that holds a secret.
func TestFieldsHoldNoSecrets(t *testing.T) {
	deny := []string{
		"password", "passwd", "salt", "rands", "secret", "client_secret", "secret_hash", "token", "token_hash",
		"token_salt", "token_last_eight", "scratch", "scratch_token", "scratch_hash", "totp_secret", "bind_password",
		"public_key", "credential_id", "headers", "url", "typed_name", "login_name", "content", "armor", "emails",
		"remote_address", "encrypted_remote_address", "userinfo", "message", "value", "meta", "private_key",
	}
	for typ, fields := range audit_model.Fields {
		for _, f := range fields {
			assert.NotContains(t, deny, f, typ)
		}
	}
}
