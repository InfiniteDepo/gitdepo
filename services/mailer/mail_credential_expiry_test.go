// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"fmt"
	"testing"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendCredentialExpiryNotices(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	timeutil.MockSet(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	defer timeutil.MockUnset()

	var messages []*Message
	defer MockMailSettings(func(msgs ...*Message) { messages = append(messages, msgs...) })()
	send := func(t *testing.T) map[string]*Message {
		t.Helper()
		messages = nil
		require.NoError(t, SendCredentialExpiryNotices(t.Context()))
		bySubject := map[string]*Message{}
		for _, m := range messages {
			bySubject[m.To+" "+m.Subject] = m
		}
		return bySubject
	}
	now := timeutil.TimeStampNow()
	n := 0
	token := func(name string, expires timeutil.TimeStamp, t2 *auth_model.AccessToken) *auth_model.AccessToken {
		n++
		t2.Name, t2.ExpiresUnix, t2.TokenHash = name, expires, fmt.Sprintf("expiry-%d", n)
		require.NoError(t, db.Insert(t.Context(), t2))
		return t2
	}

	token("personal", now.AddDuration(7*24*time.Hour-time.Minute), &auth_model.AccessToken{UID: 2})
	token("ci-repo", now.AddDuration(3*24*time.Hour), &auth_model.AccessToken{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1, Mode: 1})
	token("ci-org", now.AddDuration(2*time.Hour), &auth_model.AccessToken{OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3, Mode: 1})
	token("later", now.AddDuration(8*24*time.Hour), &auth_model.AccessToken{UID: 2})
	token("past", now.AddDuration(-time.Hour), &auth_model.AccessToken{UID: 2})
	token("revoked", now.AddDuration(time.Hour), &auth_model.AccessToken{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1, Mode: 1, RevokedUnix: now})
	require.NoError(t, db.Insert(t.Context(), &asymkey_model.DeployKey{KeyID: 999, RepoID: 1, Name: "deploy-expiring", ExpiresUnix: now.AddDuration(5 * 24 * time.Hour)}))

	user2 := `"User Two" <user2@example.com>`
	got := send(t)
	personal := got[user2+" Access token personal expires in 7 days"]
	require.NotNil(t, personal, "%v", got)
	assert.Contains(t, personal.Body, "The access token personal of your account expires on 2026-10-08.")
	assert.Contains(t, personal.Body, `href="https://try.gitea.io/user/settings/keys"`)
	assert.Contains(t, personal.Body, "Regenerate it")
	assert.NotContains(t, personal.Body, "Rotate it")
	assert.NotContains(t, personal.Body, "expiry-1")

	repo := got[user2+" Access token ci-repo expires in 3 days"]
	require.NotNil(t, repo, "the owner of user2/repo1 administers it")
	assert.Contains(t, repo.Body, "Rotate it")
	assert.Contains(t, repo.Body, "of repository user2/repo1")
	assert.Contains(t, repo.Body, "administrator of user2/repo1")
	assert.Contains(t, repo.Body, `href="https://try.gitea.io/user2/repo1/settings/keys"`)

	org := got[user2+" Access token ci-org expires within a day"]
	require.NotNil(t, org, "user2 owns org3")
	assert.Contains(t, org.Body, "owner of org3")
	assert.Contains(t, org.Body, `href="https://try.gitea.io/org/org3/settings/keys"`)
	for k := range got {
		assert.NotContains(t, k, "later")
		assert.NotContains(t, k, "past")
		assert.NotContains(t, k, "revoked")
		assert.NotContains(t, k, "ci-org expires in", "the last day sends only the last-day mail")
	}

	deployMail := got[user2+" Deploy key deploy-expiring expires in 5 days"]
	require.NotNil(t, deployMail)
	assert.Contains(t, deployMail.Body, "Add a new key")

	assert.Empty(t, send(t), "each notice goes out once")

	// a day later the 7-day notice is sent, the last-day one waits; on the last day it goes out
	timeutil.MockSet(time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC))
	got = send(t)
	assert.NotNil(t, got[user2+" Access token personal expires within a day"])
	assert.NotNil(t, got[user2+" Access token later expires in 2 days"])

	// a credential nobody can be mailed about is claimed once, not looked at again
	gone := token("ownerless", timeutil.TimeStampNow().AddDuration(time.Hour), &auth_model.AccessToken{UID: 99999})
	assert.Empty(t, send(t))
	unittest.AssertExistsAndLoadBean(t, &auth_model.CredentialExpiryNotice{Kind: "access_token", CredentialID: gone.ID})

	// someone who turned mail off gets none
	_, err := db.GetEngine(t.Context()).ID(2).Cols("email_notifications_preference").Update(&user_model.User{EmailNotificationsPreference: user_model.EmailNotificationsDisabled})
	require.NoError(t, err)
	token("quiet", timeutil.TimeStampNow().AddDuration(time.Hour), &auth_model.AccessToken{UID: 2})
	assert.Empty(t, send(t))
}

// The day count of the subject is the calendar days to the date the body names: just after midnight, 36 hours ahead
// is tomorrow, not in two days.
func TestCredentialExpiryNoticeCountsCalendarDays(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	timeutil.MockSet(time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC))
	defer timeutil.MockUnset()
	var messages []*Message
	defer MockMailSettings(func(msgs ...*Message) { messages = append(messages, msgs...) })()

	now := timeutil.TimeStampNow()
	require.NoError(t, db.Insert(t.Context(), &auth_model.AccessToken{UID: 2, Name: "overnight", TokenHash: "overnight-hash", ExpiresUnix: now.AddDuration(36 * time.Hour)}))
	require.NoError(t, SendCredentialExpiryNotices(t.Context()))
	require.Len(t, messages, 1)
	assert.Equal(t, "Access token overnight expires in 1 day", messages[0].Subject)
	assert.Contains(t, messages[0].Body, "expires on 2026-10-02.")
}
