// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"fmt"
	"net/mail"
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/inbucket/html2text"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const kindsCode = secretscan_model.DigestKindCode | secretscan_model.DigestWikiScanned

func TestSendSecretDigest(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	var messages []*Message
	defer MockMailSettings(func(msgs ...*Message) { messages = append(messages, msgs...) })()

	// repository 1 is user2's. user4 administers it too, user5 writes to it, user10 only reads it
	collab := func(userID int64, mode perm.AccessMode) {
		t.Helper()
		require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 1, UserID: userID, Mode: mode}))
		require.NoError(t, db.Insert(ctx, &access_model.Access{UserID: userID, RepoID: 1, Mode: mode}))
	}
	collab(4, perm.AccessModeAdmin)
	collab(5, perm.AccessModeWrite)
	collab(10, perm.AccessModeRead)
	setPref := func(id int64, pref string) {
		t.Helper()
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET email_notifications_preference = ? WHERE id = ?", pref, id)
		require.NoError(t, err)
	}
	repo := func() *repo_model.Repository {
		r, err := repo_model.GetRepositoryByID(ctx, 1)
		require.NoError(t, err)
		return r
	}

	var boundary int64
	alert := func(index int64, rule string, places int, kinds ...string) {
		t.Helper()
		a := &secretscan_model.Alert{RepoID: 1, Index: index, RuleID: rule, Fingerprint: fmt.Sprintf("%064d", index*7919), LocationCount: places}
		require.NoError(t, db.Insert(ctx, a))
		for i, kind := range kinds {
			l := secretscan_model.NewLocation(1, kind, fmt.Sprintf("blob-%d-%d", index, i), fmt.Sprintf("config/file%d.env", index), i+10, i+10, "c", "n", "e", 0)
			l.AlertID = a.ID
			require.NoError(t, db.Insert(ctx, l))
		}
	}
	send := func(in SecretDigestInput) map[string]*Message {
		t.Helper()
		messages = nil
		in.AfterAlertID = boundary
		require.NoError(t, SendSecretDigest(ctx, repo(), in))
		by := map[string]*Message{}
		for _, m := range messages {
			addr, err := mail.ParseAddress(m.To)
			require.NoError(t, err)
			by[addr.Address] = m
		}
		return by
	}
	user2, user4, user5 := "user2@example.com", "user4@example.com", "user5@example.com"
	for _, id := range []int64{2, 4, 5} {
		setPref(id, user_model.EmailNotificationsEnabled)
	}

	alert(1, "github-pat-classic", 1, secretscan_model.KindRepo)
	_, err := db.GetEngine(ctx).Table("secret_scanning_alert").Select("MAX(id)").Get(&boundary)
	require.NoError(t, err)

	t.Run("nothing new: no mail", func(t *testing.T) {
		assert.Empty(t, send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f"}))
	})

	alert(2, "aws-access-key-id", 1, secretscan_model.KindRepo)
	t.Run("one secret: singular subject, admins and the pusher with their own subject", func(t *testing.T) {
		got := send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 5})
		require.Len(t, got, 3, "%v", got)
		admin := got[user2]
		require.NotNil(t, admin)
		assert.Equal(t, "New secret found in user2/repo1", admin.Subject)
		assert.Contains(t, admin.Body, `A scan of <code>main</code> (commit <a href="https://try.gitea.io/user2/repo1/commit/1a2b3c4d5e6f">1a2b3c4</a>) found 1 secret that was not in the alert list yet.`)
		assert.Contains(t, admin.Body, "config/file2.env:10")
		assert.Contains(t, admin.Body, `href="https://try.gitea.io/user2/repo1/security/secrets/2"`, "one alert: a link straight to it")
		assert.Less(t, strings.Index(admin.Body, "View secret alert<"), strings.Index(admin.Body, "Revoke each credential"), "the button comes before the advice")
		assert.Contains(t, admin.Body, "</code>")
		assert.Contains(t, admin.Body, "View secret alert<")
		assert.Contains(t, admin.Body, "You receive this because you can manage secret alerts in user2/repo1.")
		assert.NotContains(t, admin.Body, "Your push")
		assert.Contains(t, got[user4].Subject, "New secret found")
		pusher := got[user5]
		require.NotNil(t, pusher)
		assert.Equal(t, "Your push to user2/repo1 contained a secret", pusher.Subject)
		assert.Contains(t, pusher.Body, `Your push to <code>main</code> (commit <a href="https://try.gitea.io/user2/repo1/commit/1a2b3c4d5e6f">1a2b3c4</a>) contains 1 secret.`)
		assert.Contains(t, pusher.Body, "Revoke the credential with its provider now.", "singular advice")
		assert.Contains(t, pusher.Body, "Repository administrators have been notified.", "admin mails went out")
		assert.NotContains(t, admin.Body, "have been notified")
		assert.Contains(t, pusher.Body, "You receive this because you pushed these commits to user2/repo1.")
		for _, m := range got {
			assert.NotContains(t, m.Subject+m.Body, fmt.Sprintf("%064d", 2*7919), "no fingerprint")
			assert.NotContains(t, m.Subject+m.Body, "GitHub", "an alert below the boundary is not in it")
		}
	})

	t.Run("who is left out", func(t *testing.T) {
		got := send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 10})
		assert.NotContains(t, got, "user10@example.com", "a reader isn't told: they can't see alerts")
		assert.NotContains(t, got, user5, "a writer who didn't push gets no mail")
		got = send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 2})
		assert.Len(t, got, 2, "a pusher who administers the repository gets the digest only: %v", got)
		assert.NotContains(t, got[user2].Subject, "Your push")
		got = send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: -2})
		assert.Len(t, got, 2, "nobody pushed (an Actions task or a deploy key)")
		got = send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 99999})
		assert.Len(t, got, 2, "a pusher who is gone")

		setPref(4, user_model.EmailNotificationsDisabled)
		assert.NotContains(t, send(SecretDigestInput{Kinds: kindsCode, Ref: "main"}), user4, "mail turned off")
		setPref(4, user_model.EmailNotificationsOnMention)
		assert.Contains(t, send(SecretDigestInput{Kinds: kindsCode, Ref: "main"}), user4, "a security mail isn't a mention-only preset's to drop")
		setPref(4, user_model.EmailNotificationsCustom)
		require.NoError(t, user_model.SaveNotificationSettings(ctx, 4, 0, map[user_model.NotifyEvent]bool{user_model.NotifyEventSecretAlert: false}))
		assert.NotContains(t, send(SecretDigestInput{Kinds: kindsCode, Ref: "main"}), user4, "Custom with the event ticked off")
		require.NoError(t, user_model.SaveNotificationSettings(ctx, 4, 0, map[user_model.NotifyEvent]bool{user_model.NotifyEventSecretAlert: true}))
		assert.Contains(t, send(SecretDigestInput{Kinds: kindsCode, Ref: "main"}), user4, "Custom with the event")
		setPref(4, user_model.EmailNotificationsEnabled)
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET prohibit_login = ? WHERE id = 4", true)
		require.NoError(t, err)
		assert.NotContains(t, send(SecretDigestInput{Kinds: kindsCode, Ref: "main"}), user4, "an account that can't sign in")
		_, err = db.GetEngine(ctx).Exec("UPDATE `user` SET prohibit_login = ? WHERE id = 4", false)
		require.NoError(t, err)
	})

	t.Run("several secrets, the cap and the wiki", func(t *testing.T) {
		alert(3, "github-token", 1, secretscan_model.KindWiki)
		alert(4, "aws-access-key-id", 3, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo)
		alert(5, "aws-access-key-id", 14, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo, secretscan_model.KindRepo)
		got := send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 5})
		admin := got[user2]
		require.NotNil(t, admin)
		assert.Equal(t, "New secrets found in user2/repo1", admin.Subject)
		assert.Contains(t, admin.Body, "found 4 secrets that were not in the alert list yet.")
		assert.Contains(t, admin.Body, "Locations (10 of 19)")
		assert.Contains(t, admin.Body, "…and 9 more locations in the alerts.")
		assert.Equal(t, 10, strings.Count(admin.Body, "<li><code>"))
		assert.Contains(t, admin.Body, "(wiki)", "the wiki's place is listed for someone who reads the wiki")
		assert.Equal(t, "Your push to user2/repo1 contained secrets", got[user5].Subject)
		assert.Contains(t, got[user5].Body, "View secret alerts<")

		// the pusher is told only of the kind they pushed, an administrator of everything new
		alert(6, "github-token", 1, secretscan_model.KindPull)
		got = send(SecretDigestInput{Kinds: secretscan_model.DigestKindCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 5})
		assert.Contains(t, got[user2].Body, "found 4 secrets", "an administrator hears of the pull ref's alert too")
		assert.Contains(t, got[user5].Body, "contains 3 secrets", "the pusher of a branch hears of the code alerts only: not the wiki's, not the pull ref's")
		got = send(SecretDigestInput{Kinds: secretscan_model.DigestKindWiki, PusherID: 5})
		assert.Contains(t, got[user5].Body, "contains 1 secret.", "the pusher of the wiki hears of the wiki's alert only")
		assert.Contains(t, got[user5].Body, "Your push to the wiki", "a wiki push names the wiki")
		got = send(SecretDigestInput{Kinds: secretscan_model.DigestKindCode, Ref: "main", Commit: "1a2b3c4d5e6f"})
		assert.NotContains(t, got[user2].Body, "(wiki)", "a wiki that was not scanned before the push is left out")

		// the plain-text version lists the types, one a line
		plain, err := html2text.FromString(got[user2].Body)
		require.NoError(t, err)
		assert.Regexp(t, `(?m)^\* AWS access key ID: 3$`, plain)

		// nobody to tell the pusher's "administrators were notified" of
		setPref(2, user_model.EmailNotificationsDisabled)
		setPref(4, user_model.EmailNotificationsDisabled)
		got = send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 5})
		require.Len(t, got, 1)
		assert.NotContains(t, got[user5].Body, "have been notified", "no administrator mail went out")
		setPref(2, user_model.EmailNotificationsEnabled)
		setPref(4, user_model.EmailNotificationsEnabled)

		// the wiki unit off: nobody reads it, so the alert that is only there is not counted or listed
		_, err = db.GetEngine(ctx).Exec("DELETE FROM repo_unit WHERE repo_id = 1 AND type = ?", unit.TypeWiki)
		require.NoError(t, err)
		got = send(SecretDigestInput{Kinds: kindsCode, Ref: "main", Commit: "1a2b3c4d5e6f"})
		admin = got[user2]
		require.NotNil(t, admin)
		assert.Contains(t, admin.Body, "found 4 secrets that were not")
		assert.NotContains(t, admin.Body, "(wiki)")
		assert.Contains(t, admin.Body, "Locations (10 of 19)")
		got = send(SecretDigestInput{Kinds: secretscan_model.DigestKindWiki | secretscan_model.DigestWikiScanned})
		assert.Contains(t, got[user2].Body, "A scan of a push found", "someone who can't read the wiki is never told of a push to it")
		assert.NotContains(t, got[user2].Body, "wiki")
	})

	t.Run("several pushes are not named after the last, and invisible characters are stripped", func(t *testing.T) {
		got := send(SecretDigestInput{Kinds: kindsCode | secretscan_model.DigestSeveral, Ref: "main", Commit: "1a2b3c4d5e6f", PusherID: 5})
		assert.Contains(t, got[user2].Body, "A scan of several recent pushes found")
		assert.NotContains(t, got[user2].Body, "1a2b3c4")
		assert.Contains(t, got[user5].Body, "Your push to the repository contains")
		got = send(SecretDigestInput{Kinds: kindsCode, Ref: "ma\u202ein\u200b", Commit: "1a2b3c4d5e6f"})
		assert.Contains(t, got[user2].Body, "<code>main</code>")
		assert.NotContains(t, got[user2].Body, "\u202e")
		assert.NotContains(t, got[user2].Body, "\u200b")
	})
}

// The digest names the alerts of a custom pattern by the one label rule: the pattern, a deleted one and one of
// another owner generically.
func TestSendSecretDigestCustomPattern(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	var messages []*Message
	defer MockMailSettings(func(msgs ...*Message) { messages = append(messages, msgs...) })()
	_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET email_notifications_preference = ? WHERE id = 2", user_model.EmailNotificationsEnabled)
	require.NoError(t, err)

	live := &secretscan_model.CustomPattern{OwnerID: 0, Name: "Acme internal key", Pattern: "x", Keywords: "[]", Enabled: true}
	gone := &secretscan_model.CustomPattern{OwnerID: 0, Name: "Retired key", Pattern: "x", Keywords: "[]", Enabled: true, DeletedUnix: 5}
	off := &secretscan_model.CustomPattern{OwnerID: 0, Name: "Paused key", Pattern: "x", Keywords: "[]"}
	foreign := &secretscan_model.CustomPattern{OwnerID: 3, Name: "Org three key", Pattern: "x", Keywords: "[]", Enabled: true} // repo 1 is user2's
	all := []*secretscan_model.CustomPattern{live, gone, off, foreign}
	for _, p := range all {
		require.NoError(t, db.Insert(ctx, p))
	}
	_, err = db.GetEngine(ctx).Exec("UPDATE secret_custom_pattern SET enabled = ? WHERE id = ?", false, off.ID)
	require.NoError(t, err)
	for i, p := range all {
		a := &secretscan_model.Alert{RepoID: 1, Index: int64(i + 1), RuleID: p.RuleID(), Fingerprint: fmt.Sprintf("%064d", i+1), LocationCount: 1}
		require.NoError(t, db.Insert(ctx, a))
		l := secretscan_model.NewLocation(1, secretscan_model.KindRepo, fmt.Sprintf("blob-%d", i), "a.env", 1, 1, "c", "n", "e", 0)
		l.AlertID = a.ID
		require.NoError(t, db.Insert(ctx, l))
	}
	repo, err := repo_model.GetRepositoryByID(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, SendSecretDigest(ctx, repo, SecretDigestInput{Kinds: kindsCode, Ref: "main"}))
	require.NotEmpty(t, messages)
	body := messages[0].Body
	assert.Contains(t, body, "Acme internal key")
	assert.Contains(t, body, "Deleted pattern")
	assert.Contains(t, body, "Paused key (disabled)")
	assert.Contains(t, body, "Pattern of a previous owner")
	assert.NotContains(t, body, "Retired key")
	assert.NotContains(t, body, "Org three key")
	assert.NotContains(t, body, "custom-")
}
