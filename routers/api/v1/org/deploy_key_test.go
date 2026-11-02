// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"
	"testing"

	"forgejo.org/services/authz"
	"forgejo.org/services/contexttest"

	"github.com/stretchr/testify/assert"
)

// An organization deploy key reaches every repository of the organization: only a token that isn't limited to
// public or specific repositories may manage them.
func TestOrgWideToken(t *testing.T) {
	for name, tc := range map[string]struct {
		reducer    authz.AuthorizationReducer
		publicOnly bool
		ok         bool
	}{
		"all access":         {reducer: &authz.AllAccessAuthorizationReducer{}, ok: true},
		"public only":        {reducer: &authz.AllAccessAuthorizationReducer{}, publicOnly: true},
		"public repos":       {reducer: &authz.PublicReposAuthorizationReducer{}},
		"specific repos":     {reducer: &authz.SpecificReposAuthorizationReducer{}},
		"no reducer present": {},
	} {
		ctx, resp := contexttest.MockAPIContext(t, "GET /api/v1/orgs/org3/keys")
		ctx.SetReducer(tc.reducer)
		ctx.SetPublicOnly(tc.publicOnly)
		assert.Equal(t, tc.ok, orgWideToken(ctx), name)
		if !tc.ok {
			assert.Equal(t, http.StatusForbidden, resp.Code, name)
		}
	}
}
