// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deploymentMailOf(t *testing.T, repoID int64, status actions_model.DeploymentStatus) *DeploymentMail {
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
	return &DeploymentMail{
		Run:         &actions_model.ActionRun{Index: 7, Title: "<script>title</script>", WorkflowID: "deploy.yml", RepoID: repoID, Repo: repo},
		JobName:     "<b>job</b>",
		Environment: "prod<i>",
		Deployment: &actions_model.ActionDeployment{
			Status: status, Ref: "refs/heads/main", CommitSHA: "0123456789abcdef0123456789abcdef01234567",
			ReviewComment: "not <b>now</b>",
		},
		TriggerUser: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}),
		Reviewer:    unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}),
		Expires:     time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
	}
}

// The deployment mails link to the run, escape everything that comes from users and carry the environment in the
// subject; the decided mail goes only to a user who can still read the repository's Actions.
func TestMailDeployment(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	var sent []*Message
	defer MockMailSettings(func(msgs ...*Message) { sent = append(sent, msgs...) })()
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	t.Run("review", func(t *testing.T) {
		sent = nil
		m := deploymentMailOf(t, 1, actions_model.DeploymentWaitingReview)
		require.NoError(t, MailDeploymentReview(t.Context(), []*user_model.User{user4}, m))
		require.Len(t, sent, 1)
		assert.Equal(t, user4.EmailTo(), sent[0].To)
		assert.Equal(t, "[user2/repo1] Deployment to prod<i> waiting for your review", sent[0].Subject)
		body := sent[0].Body
		assert.Contains(t, body, m.Run.HTMLURL())
		assert.Contains(t, body, "&lt;script&gt;title&lt;/script&gt;")
		assert.Contains(t, body, "&lt;b&gt;job&lt;/b&gt;")
		assert.Contains(t, body, "prod&lt;i&gt;")
		assert.NotContains(t, body, "<script>")
		assert.NotContains(t, body, "<b>job")
	})

	t.Run("expiry in the reviewer's time zone", func(t *testing.T) {
		sent = nil
		require.NoError(t, user_model.SetUserSetting(t.Context(), user4.ID, user_model.SettingsKeyTimeZone, "Asia/Tokyo"))
		defer func() {
			require.NoError(t, user_model.DeleteUserSetting(t.Context(), user4.ID, user_model.SettingsKeyTimeZone))
		}()
		require.NoError(t, MailDeploymentReview(t.Context(), []*user_model.User{user4}, deploymentMailOf(t, 1, actions_model.DeploymentWaitingReview)))
		require.Len(t, sent, 1)
		assert.Contains(t, sent[0].Body, "2026-11-05 21:00 JST (+09:00)")
	})

	t.Run("rejected", func(t *testing.T) {
		sent = nil
		m := deploymentMailOf(t, 1, actions_model.DeploymentRejected)
		require.NoError(t, MailDeploymentDecided(t.Context(), user2, m))
		require.Len(t, sent, 1)
		assert.Equal(t, "[user2/repo1] Deployment to prod<i> rejected", sent[0].Subject)
		assert.Contains(t, sent[0].Body, "not &lt;b&gt;now&lt;/b&gt;")
		assert.NotContains(t, sent[0].Body, "<b>now")
		assert.Contains(t, sent[0].Body, user4.GetDisplayName())
	})

	t.Run("expired", func(t *testing.T) {
		sent = nil
		m := deploymentMailOf(t, 1, actions_model.DeploymentExpired)
		m.Reviewer = nil
		require.NoError(t, MailDeploymentDecided(t.Context(), user2, m))
		require.Len(t, sent, 1)
		assert.Equal(t, "[user2/repo1] Deployment to prod<i> expired", sent[0].Subject)
	})

	t.Run("not to a user who can no longer read the repository's Actions", func(t *testing.T) {
		sent = nil
		// repo2 is private to user2
		require.NoError(t, MailDeploymentDecided(t.Context(), user4, deploymentMailOf(t, 2, actions_model.DeploymentRejected)))
		assert.Empty(t, sent)
	})

	t.Run("not to a user who turned the event off", func(t *testing.T) {
		sent = nil
		u := *user4
		u.EmailNotificationsPreference = user_model.EmailNotificationsDisabled
		require.NoError(t, MailDeploymentReview(t.Context(), []*user_model.User{&u}, deploymentMailOf(t, 1, actions_model.DeploymentWaitingReview)))
		assert.Empty(t, sent)
	})
}
