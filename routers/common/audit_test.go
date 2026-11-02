// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/httplib"
	auth_service "forgejo.org/services/auth"
	"forgejo.org/services/context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The actor is copied into every aggregate, so it must not keep large header values (or their arrays) alive.
func TestSetAuditActorCaps(t *testing.T) {
	candidates := make([]string, 0, 1000)
	for i := range 1000 {
		candidates = append(candidates, fmt.Sprintf("198.51.100.%d", i%250))
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", strings.Repeat("u", 1<<20))
	req = httplib.WithAmbiguousClientIP(req, "127.0.0.1", candidates)
	base, cleanup := context.NewBaseContext(httptest.NewRecorder(), req)
	defer cleanup()

	SetAuditActor(base, &auth_service.UnauthenticatedResult{})
	a := audit_model.ActorFromContext(base)
	require.NotNil(t, a)
	assert.Len(t, a.UserAgent, audit_model.MaxUserAgent)
	assert.Len(t, a.IPCandidates, audit_model.MaxIPCandidates)
	assert.LessOrEqual(t, cap(a.IPCandidates), audit_model.MaxIPCandidates)
	assert.Equal(t, "127.0.0.1", a.IP)
}
