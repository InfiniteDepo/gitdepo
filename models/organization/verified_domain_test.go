// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization_test

import (
	"context"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserHasVerifiedDomainEmail(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	require.NoError(t, organization.AddVerifiedDomain(ctx, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "company.com"}))
	for uid, email := range map[int64]string{
		4:  "user4@sub.company.com",
		5:  "User5@Company.COM",
		8:  "user8@company.com.evil",
		10: "user10@Kompany.com",
	} {
		require.NoError(t, db.Insert(ctx, &user_model.EmailAddress{UID: uid, Email: email, LowerEmail: email, IsActivated: true}))
	}
	require.NoError(t, db.Insert(ctx, &user_model.EmailAddress{UID: 9, Email: "user9@company.com", LowerEmail: "user9@company.com"}))

	for uid, want := range map[int64]bool{2: false, 4: false, 5: true, 8: false, 9: false, 10: false} {
		ok, err := organization.UserHasVerifiedDomainEmail(ctx, 3, uid)
		require.NoError(t, err)
		assert.Equal(t, want, ok, uid)
	}
	// another organization's domain doesn't count
	ok, err := organization.UserHasVerifiedDomainEmail(ctx, 6, 5)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestAddOrgUserVerifiedDomain(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, true)()
	require.NoError(t, organization.AddVerifiedDomain(ctx, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "company.com"}))
	require.NoError(t, db.Insert(ctx, &user_model.EmailAddress{UID: 5, Email: "user5@company.com", LowerEmail: "user5@company.com", IsActivated: true}))

	// off: unchanged
	require.NoError(t, organization.AddOrgUser(ctx, 3, 8))
	unittest.AssertExistsAndLoadBean(t, &organization.OrgUser{OrgID: 3, UID: 8})

	require.NoError(t, user_model.SetUserSetting(ctx, 3, organization.SettingKeyRequireVerifiedDomain, "true"))
	err := organization.AddOrgUser(ctx, 3, 10)
	require.ErrorAs(t, err, &organization.ErrUserNoVerifiedDomainEmail{})
	unittest.AssertNotExistsBean(t, &organization.OrgUser{OrgID: 3, UID: 10})
	require.NoError(t, organization.AddOrgUser(ctx, 3, 5))
	unittest.AssertExistsAndLoadBean(t, &organization.OrgUser{OrgID: 3, UID: 5})
	// already a member: allowed
	require.NoError(t, organization.AddOrgUser(ctx, 3, 8))

	// a refused add inside a shared transaction doesn't roll the transaction back
	require.NoError(t, db.WithTx(ctx, func(ctx context.Context) error {
		require.NoError(t, user_model.SetUserSetting(ctx, 10, "test.marker", "1"))
		require.True(t, organization.IsErrUserNoVerifiedDomainEmail(organization.AddOrgUser(ctx, 3, 10)))
		return nil
	}))
	unittest.AssertExistsAndLoadBean(t, &user_model.Setting{UserID: 10, SettingKey: "test.marker"})

	// email confirmation turned off later: every gated add fails
	defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, false)()
	require.NoError(t, db.Insert(ctx, &user_model.EmailAddress{UID: 10, Email: "user10@company.com", LowerEmail: "user10@company.com", IsActivated: true}))
	err = organization.AddOrgUser(ctx, 3, 10)
	var e organization.ErrUserNoVerifiedDomainEmail
	require.ErrorAs(t, err, &e)
	assert.True(t, e.ConfirmationOff)
}
