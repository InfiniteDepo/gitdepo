// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"context"
	"errors"
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":           "example.com",
		"\tExample.COM\n":       "example.com",
		"a-b.example.co.uk":     "a-b.example.co.uk",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	} {
		got, err := NormalizeDomain(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{
		"", "com", "example.com.", ".example.com", "exa mple.com", "-a.com", "a-.com", "a..com",
		"bücher.example", "Kompany.com", "1.2.3.4", "[::1]", "::1", "a_b.com", "user@example.com",
		"a." + strings.Repeat("b", 64) + ".com",
	} {
		_, err := NormalizeDomain(in)
		require.ErrorIs(t, err, ErrInvalidDomain, in)
	}
	_, err := NormalizeDomain(strings.Repeat("abcdefghi.", 25) + "com") // 253 is the limit
	require.NoError(t, err)
	_, err = NormalizeDomain(strings.Repeat("abcdefghi.", 25) + "comx")
	assert.ErrorIs(t, err, ErrInvalidDomain)
}

func TestDomainRecord(t *testing.T) {
	defer test.MockVariableValue(&setting.SecretKey, "secret")()
	assert.Equal(t, "_gitdepo-verify.example.com", DomainRecordName("example.com"))
	v := DomainRecordValue(3, "example.com")
	assert.Regexp(t, `^gitdepo-verification=[A-Za-z0-9_-]{43}$`, v)
	assert.Equal(t, v, DomainRecordValue(3, "example.com"))
	assert.NotEqual(t, v, DomainRecordValue(6, "example.com"))
	assert.NotEqual(t, v, DomainRecordValue(3, "example.org"))
	defer test.MockVariableValue(&setting.SecretKey, "other")()
	assert.NotEqual(t, v, DomainRecordValue(3, "example.com"))
}

func mockTXT(t *testing.T, records []string, err error) *string {
	var asked string
	t.Cleanup(test.MockVariableValue(&LookupTXT, func(ctx context.Context, name string) ([]string, error) {
		asked = name
		_, hasDeadline := ctx.Deadline()
		assert.True(t, hasDeadline)
		return records, err
	}))
	return &asked
}

func TestVerifyDomain(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
	org6 := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 6})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	t.Run("mismatch", func(t *testing.T) {
		asked := mockTXT(t, []string{"gitdepo-verification=wrong", DomainRecordValue(6, "example.com")}, nil)
		err := VerifyDomain(ctx, org3, owner, "Example.com", false)
		require.ErrorIs(t, err, ErrDomainRecordNotFound)
		assert.Equal(t, "_gitdepo-verify.example.com.", *asked)
	})
	t.Run("dns error is neutral", func(t *testing.T) {
		mockTXT(t, nil, errors.New("lookup _gitdepo-verify.example.com on 10.0.0.1: no such host"))
		err := VerifyDomain(ctx, org3, owner, "example.com", false)
		require.ErrorIs(t, err, ErrDomainRecordNotFound)
		assert.NotContains(t, err.Error(), "10.0.0.1")
	})
	t.Run("match", func(t *testing.T) {
		mockTXT(t, []string{"v=spf1", DomainRecordValue(3, "example.com")}, nil)
		require.NoError(t, VerifyDomain(ctx, org3, owner, "example.com", false))
		d := unittest.AssertExistsAndLoadBean(t, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "example.com"})
		assert.Zero(t, d.VerifiedByAdminID)
		assert.NotZero(t, d.VerifiedUnix)
		// verifying it again is a no-op
		require.NoError(t, VerifyDomain(ctx, org3, owner, "example.com", false))
	})
	t.Run("another org can't take it", func(t *testing.T) {
		mockTXT(t, []string{DomainRecordValue(6, "example.com")}, nil)
		require.ErrorIs(t, VerifyDomain(ctx, org6, owner, "example.com", false), organization.ErrDomainVerifiedByOtherOrg)
		require.ErrorIs(t, VerifyDomain(ctx, org6, admin, "example.com", true), organization.ErrDomainVerifiedByOtherOrg)
		require.ErrorIs(t, organization.AddVerifiedDomain(ctx, &organization.OrgVerifiedDomain{OrgID: 6, Domain: "example.com"}), organization.ErrDomainVerifiedByOtherOrg)
	})
	t.Run("without DNS", func(t *testing.T) {
		mockTXT(t, nil, errors.New("must not be asked"))
		require.ErrorIs(t, VerifyDomain(ctx, org6, owner, "example.org", true), util.ErrPermissionDenied)
		prohibited := *admin
		prohibited.ProhibitLogin = true
		require.ErrorIs(t, VerifyDomain(ctx, org6, &prohibited, "example.org", true), util.ErrPermissionDenied)
		require.NoError(t, VerifyDomain(ctx, org6, admin, "example.org", true))
		d := unittest.AssertExistsAndLoadBean(t, &organization.OrgVerifiedDomain{OrgID: 6, Domain: "example.org"})
		assert.Equal(t, admin.ID, d.VerifiedByAdminID)
	})
	t.Run("cap", func(t *testing.T) {
		for i := range 9 {
			require.NoError(t, VerifyDomain(ctx, org3, admin, string(rune('a'+i))+".example.net", true))
		}
		require.ErrorIs(t, VerifyDomain(ctx, org3, admin, "z.example.net", true), ErrTooManyDomains)
	})
}

func TestSetVerifiedDomainRequired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, true)()
	org3 := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})

	require.ErrorIs(t, SetVerifiedDomainRequired(ctx, org3, true), ErrNoVerifiedDomains)
	require.NoError(t, organization.AddVerifiedDomain(ctx, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "example.com"}))
	func() {
		defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, false)()
		require.ErrorIs(t, SetVerifiedDomainRequired(ctx, org3, true), ErrEmailConfirmationOff)
	}()
	require.NoError(t, SetVerifiedDomainRequired(ctx, org3, true))
	on, err := organization.IsVerifiedDomainRequired(ctx, 3)
	require.NoError(t, err)
	assert.True(t, on)

	// removing the last domain turns the restriction off
	require.NoError(t, organization.RemoveVerifiedDomain(ctx, org3.AsUser(), "example.com"))
	on, err = organization.IsVerifiedDomainRequired(ctx, 3)
	require.NoError(t, err)
	assert.False(t, on)
}
