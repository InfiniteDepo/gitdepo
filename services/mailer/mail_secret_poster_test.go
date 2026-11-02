// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"fmt"
	"net/mail"
	"testing"
	"time"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	mc "code.forgejo.org/go-chi/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendSecretPosterNotice(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.CacheService.Cache, setting.Cache{Adapter: "memory", TTL: time.Hour})()
	require.NoError(t, cache.Init())
	ctx := t.Context()
	var messages []*Message
	defer MockMailSettings(func(msgs ...*Message) { messages = append(messages, msgs...) })()
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	timeutil.MockSet(now)
	defer timeutil.MockUnset()

	// repository 1 is user2's; user4 administers it, user5 writes to it
	for id, mode := range map[int64]perm.AccessMode{4: perm.AccessModeAdmin, 5: perm.AccessModeWrite} {
		require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 1, UserID: id, Mode: mode}))
		require.NoError(t, db.Insert(ctx, &access_model.Access{UserID: id, RepoID: 1, Mode: mode}))
	}
	setPref := func(id int64, pref string) {
		t.Helper()
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET email_notifications_preference = ? WHERE id = ?", pref, id)
		require.NoError(t, err)
	}
	for _, id := range []int64{2, 4, 5} {
		setPref(id, user_model.EmailNotificationsEnabled)
	}
	index := int64(500)
	newIssue := func(poster int64, isPull bool) *issues_model.Issue {
		t.Helper()
		index++
		i := &issues_model.Issue{RepoID: 1, Index: index, PosterID: poster, Title: "t", IsPull: isPull}
		require.NoError(t, db.Insert(ctx, i))
		return i
	}
	send := func(n SecretPosterNotice) []*Message {
		t.Helper()
		messages = nil
		r, err := repo_model.GetRepositoryByID(ctx, 1) // the units are cached on the repository
		require.NoError(t, err)
		require.NoError(t, SendSecretPosterNotice(ctx, r, n))
		return messages
	}
	issue := newIssue(5, false)

	t.Run("the writer of an issue is told: a link to the text, none to the alert, nothing of the secret", func(t *testing.T) {
		got := send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID})
		require.Len(t, got, 1)
		addr, err := mail.ParseAddress(got[0].To)
		require.NoError(t, err)
		assert.Equal(t, "user5@example.com", addr.Address)
		assert.Equal(t, fmt.Sprintf("Possible secret in your issue description on user2/repo1#%d", issue.Index), got[0].Subject)
		assert.Contains(t, got[0].Body, fmt.Sprintf(`href="https://try.gitea.io/user2/repo1/issues/%d"`, issue.Index))
		assert.NotContains(t, got[0].Body, "security/secrets", "the poster may not be allowed to see alerts")
		assert.Contains(t, got[0].Body, "you get at most 5 of these a day.")
		assert.Contains(t, got[0].Body, "edit history")
		assert.Contains(t, got[0].Body, "If it is not a real secret")
		AssertTranslatedLocale(t, got[0].Body, "mail.", "secret_poster")
	})

	t.Run("a comment links to the comment", func(t *testing.T) {
		got := send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID, CommentID: 77})
		require.Len(t, got, 1)
		assert.Contains(t, got[0].Body, fmt.Sprintf(`/issues/%d#issuecomment-77"`, issue.Index))
		assert.Equal(t, fmt.Sprintf("Possible secret in your comment on user2/repo1#%d", issue.Index), got[0].Subject)
	})

	t.Run("the item and field are named", func(t *testing.T) {
		got := send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID, Field: "title"})
		require.Len(t, got, 1)
		assert.Equal(t, fmt.Sprintf("Possible secret in your issue title on user2/repo1#%d", issue.Index), got[0].Subject)
		pull := newIssue(5, true)
		got = send(SecretPosterNotice{PosterID: 5, IssueID: pull.ID, Field: "body"})
		require.Len(t, got, 1)
		assert.Equal(t, fmt.Sprintf("Possible secret in your pull request description on user2/repo1#%d", pull.Index), got[0].Subject)
		assert.Contains(t, got[0].Body, "Open the pull request")
	})

	t.Run("who is not told", func(t *testing.T) {
		assert.Empty(t, send(SecretPosterNotice{PosterID: 4, IssueID: newIssue(4, false).ID}), "an administrator gets the digest")
		assert.Empty(t, send(SecretPosterNotice{PosterID: 2, IssueID: newIssue(2, false).ID}), "the owner is an administrator")
		assert.Empty(t, send(SecretPosterNotice{PosterID: 0, IssueID: issue.ID}), "an imported text has no author")
		assert.Empty(t, send(SecretPosterNotice{PosterID: -1, IssueID: issue.ID}), "the ghost")
		assert.Empty(t, send(SecretPosterNotice{PosterID: 99999, IssueID: issue.ID}), "a user who is gone")
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: 999999}), "an issue that is gone")
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET prohibit_login = ? WHERE id = 5", true)
		require.NoError(t, err)
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID}), "an account that can't sign in")
		_, err = db.GetEngine(ctx).Exec("UPDATE `user` SET prohibit_login = ? WHERE id = 5", false)
		require.NoError(t, err)
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: 2}).ID}), "an issue of another repository")

		setPref(5, user_model.EmailNotificationsDisabled)
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID}), "mail turned off")
		setPref(5, user_model.EmailNotificationsCustom)
		require.NoError(t, user_model.SaveNotificationSettings(ctx, 5, 0, map[user_model.NotifyEvent]bool{user_model.NotifyEventSecretAlert: false}))
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID}), "Custom with the event ticked off")
		require.NoError(t, user_model.SaveNotificationSettings(ctx, 5, 0, map[user_model.NotifyEvent]bool{user_model.NotifyEventSecretAlert: true}))
		setPref(5, user_model.EmailNotificationsEnabled)
	})

	t.Run("a poster who can no longer read the unit is not told", func(t *testing.T) {
		pull := newIssue(5, true)
		assert.Len(t, send(SecretPosterNotice{PosterID: 5, IssueID: pull.ID}), 1)
		_, err := db.GetEngine(ctx).Exec("DELETE FROM repo_unit WHERE repo_id = 1 AND type = ?", unit.TypePullRequests)
		require.NoError(t, err)
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: pull.ID}))
	})

	t.Run("the latest editor of the text must be the poster", func(t *testing.T) {
		cache.GetCache().Delete("secret_poster_notices_5_2026-11-02")
		edited := newIssue(5, false)
		require.NoError(t, db.Insert(ctx, &issues_model.ContentHistory{PosterID: 5, IssueID: edited.ID, EditedUnix: 1, ContentText: "a", IsFirstCreated: true}))
		require.NoError(t, db.Insert(ctx, &issues_model.ContentHistory{PosterID: 4, IssueID: edited.ID, EditedUnix: 2, ContentText: "b"}))
		assert.Empty(t, send(SecretPosterNotice{PosterID: 5, IssueID: edited.ID, Field: "body"}), "somebody else wrote it as it is now")
		assert.Len(t, send(SecretPosterNotice{PosterID: 5, IssueID: edited.ID, Field: "title"}), 1, "a title has no history")
		require.NoError(t, db.Insert(ctx, &issues_model.ContentHistory{PosterID: 5, IssueID: edited.ID, EditedUnix: 3, ContentText: "c"}))
		assert.Len(t, send(SecretPosterNotice{PosterID: 5, IssueID: edited.ID, Field: "body"}), 1)
		cache.GetCache().Delete("secret_poster_notices_5_2026-11-02")
	})

	t.Run("at most five a day for one poster, then again the next day", func(t *testing.T) {
		cache.GetCache().Delete("secret_poster_notices_5_2026-11-02")
		for i := range MaxPosterNoticesPerDay + 2 {
			got := send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID, CommentID: int64(100 + i)})
			assert.Len(t, got, boolToInt(i < MaxPosterNoticesPerDay), "mail %d", i+1)
		}
		timeutil.MockSet(now.Add(24 * time.Hour))
		assert.Len(t, send(SecretPosterNotice{PosterID: 5, IssueID: issue.ID}), 1)
	})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// A digest of a text that opened an alert counts it without naming an issue, a comment or a place.
func TestSendSecretDigestText(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	var messages []*Message
	defer MockMailSettings(func(msgs ...*Message) { messages = append(messages, msgs...) })()
	repo, err := repo_model.GetRepositoryByID(ctx, 1)
	require.NoError(t, err)

	a := &secretscan_model.Alert{RepoID: 1, Index: 1, RuleID: "github-pat-classic", Fingerprint: fmt.Sprintf("%064d", 7919), LocationCount: 1}
	require.NoError(t, db.Insert(ctx, a))
	l := secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, 1, 1, "body", 4, 4, 5)
	l.AlertID = a.ID
	require.NoError(t, db.Insert(ctx, l))

	require.NoError(t, SendSecretDigest(ctx, repo, SecretDigestInput{Kinds: secretscan_model.DigestKindText}))
	var body string
	for _, m := range messages {
		addr, err := mail.ParseAddress(m.To)
		require.NoError(t, err)
		if addr.Address == "user2@example.com" {
			body = m.Body
		}
	}
	require.NotEmpty(t, body, "the owner administers the repository")
	assert.Contains(t, body, "A scan of the text of an issue, pull request or comment found 1 secret")
	assert.NotContains(t, body, "1 of them is in the text", "a text-only digest says it once")
	assert.Contains(t, body, "Editing the text is not enough")
	assert.NotContains(t, body, "<code>", "no place is listed")
	assert.NotContains(t, body, "Location")
	assert.NotContains(t, body, "/issues/")
	assert.Contains(t, body, `href="https://try.gitea.io/user2/repo1/security/secrets/1"`)
}

// The cap works the same on every cache adapter: Incr of a missing key is an error in one and a silent nothing in
// another, so the counter is seeded and nothing is assumed.
func TestTakePosterSlotAdapters(t *testing.T) {
	timeutil.MockSet(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	defer timeutil.MockUnset()
	for _, adapter := range []string{"memory", "twoqueue"} {
		t.Run(adapter, func(t *testing.T) {
			c, err := mc.NewCacher(mc.Options{Adapter: adapter, AdapterConfig: map[string]string{"twoqueue": "100"}[adapter]})
			require.NoError(t, err)
			for i := range MaxPosterNoticesPerDay + 2 {
				assert.Equal(t, i < MaxPosterNoticesPerDay, takePosterSlotIn(c, 77), "call %d", i+1)
			}
			assert.True(t, takePosterSlotIn(c, 78), "another user has their own count")
		})
	}
}
