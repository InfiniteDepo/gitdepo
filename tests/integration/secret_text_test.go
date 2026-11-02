// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	secretscan_service "forgejo.org/services/secretscan"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// textPlace reads the place of a kind of the alert, inside Eventually: no require, no t.Context().
func textPlace(alertID int64, kind string) *secretscan_model.Location {
	var l secretscan_model.Location
	if has, err := db.GetEngine(db.DefaultContext).Where("alert_id = ? AND kind = ?", alertID, kind).Get(&l); err != nil || !has {
		return nil
	}
	return &l
}

// A secret written in an issue and in a comment is found when the text is saved, follows an edit and a delete, and
// shows up in the alert list and, for a reader of the issue, in its places.
func TestSecretTextScanFlow(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		defer test.MockVariableValue(&setting.SecretScanning.ScanText, true)()
		defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<20)()
		write := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeWriteRepository)
		const base = "/api/v1/repos/user2/repo1"
		issueTok, commentTok := secretToken("text-issue"), secretToken("text-comment")

		var issue api.Issue
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/issues", api.CreateIssueOption{Title: "a leak", Body: "line one\nkey: " + issueTok}).AddTokenAuth(write), http.StatusCreated)
		DecodeJSON(t, resp, &issue)
		a := secretAlertOf(t, 1, issueTok)
		assert.True(t, a.ViaPull, "text shares the cap of the pull refs")
		var l *secretscan_model.Location
		require.Eventually(t, func() bool { l = textPlace(a.ID, secretscan_model.KindIssue); return l != nil }, 10*time.Second, 50*time.Millisecond)
		assert.Equal(t, 2, l.StartLine)
		assert.Equal(t, "body", l.Field)

		var comment api.Comment
		resp = MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/issues/%d/comments", base, issue.Index), api.CreateIssueCommentOption{Body: "and " + commentTok}).AddTokenAuth(write), http.StatusCreated)
		DecodeJSON(t, resp, &comment)
		b := secretAlertOf(t, 1, commentTok)
		require.Eventually(t, func() bool { return textPlace(b.ID, secretscan_model.KindComment) != nil }, 10*time.Second, 50*time.Millisecond)

		t.Run("the alert is listed, with its place in text for a reader of the issue", func(t *testing.T) {
			var list []*api.SecretScanningAlert
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", base+"/secret-scanning/alerts").AddTokenAuth(write), http.StatusOK), &list)
			numbers := map[int64]bool{}
			for _, al := range list {
				numbers[al.Number] = true
			}
			assert.True(t, numbers[a.Index] && numbers[b.Index])
			var locs []*api.SecretScanningLocation
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/secret-scanning/alerts/%d/locations", base, a.Index)).AddTokenAuth(write), http.StatusOK), &locs)
			require.Len(t, locs, 1)
			assert.Equal(t, "issue_body", locs[0].Type)
			assert.Equal(t, issue.Index, locs[0].Details.IssueNumber)
			assert.Equal(t, 2, locs[0].Details.StartLine)
			assert.Equal(t, "user2", locs[0].Details.Poster)
		})

		t.Run("an edit that removes the secret marks the place, a delete too", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/issues/%d", base, issue.Index), api.EditIssueOption{Body: new("fixed")}).AddTokenAuth(write), http.StatusCreated)
			require.Eventually(t, func() bool { p := textPlace(a.ID, secretscan_model.KindIssue); return p != nil && p.RemovedUnix != 0 }, 10*time.Second, 50*time.Millisecond)
			MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/issues/comments/%d", base, comment.ID)).AddTokenAuth(write), http.StatusNoContent)
			require.Eventually(t, func() bool { p := textPlace(b.ID, secretscan_model.KindComment); return p != nil && p.RemovedUnix != 0 }, 10*time.Second, 50*time.Millisecond)
			assert.Equal(t, secretscan_model.StateOpen, secretAlertRow(t, 1, a.Index).State, "the secret was exposed: the alert stays")
		})

		t.Run("with the text scan off nothing is stored", func(t *testing.T) {
			defer test.MockVariableValue(&setting.SecretScanning.ScanText, false)()
			off := secretToken("text-off")
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/issues", api.CreateIssueOption{Title: "quiet", Body: off}).AddTokenAuth(write), http.StatusCreated)
			assert.Never(t, func() bool { return secretAlertWith(1, off, 1) != nil }, time.Second, 100*time.Millisecond)
		})
	})
}

// The text scan has a switch on the Site administration page: a post without its field keeps it, and with the field
// (shown marker) an unticked box turns it off.
func TestSecretScanningTextSwitch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	defer test.MockVariableValue(&setting.SecretScanning.ScanText, true)()
	keepSecretScanningSettings(t)
	const switches = "/admin/config/secret-scanning/switches"
	admin := loginUser(t, "user1")
	effective := func() setting.SecretScanningOptions { return setting.SecretScanningSettings(t.Context()) }
	require.True(t, secretscan_service.SiteEnabled(t.Context()))

	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/config/secret-scanning"), http.StatusOK).Body)
	doc.AssertElement(t, "#secret-scanning-text[checked]", true)

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{"enabled": "on", "generic": "on"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	assert.True(t, effective().ScanText, "a post without the field keeps the setting")

	since := auditMaxID(t)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{"enabled": "on", "scan_text_shown": "true"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	assert.False(t, effective().ScanText)
	assert.Contains(t, auditOne(t, since, "admin.setting.changed").Data, `"scan_text":false`)
	doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/config/secret-scanning"), http.StatusOK).Body)
	doc.AssertElement(t, "#secret-scanning-text[checked]", false)
	doc.AssertElement(t, "#secret-scanning-text-file-default", true)

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{"enabled": "on", "scan_text_shown": "true", "scan_text": "on"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	assert.True(t, effective().ScanText)

	t.Run("the limit is on the limits form", func(t *testing.T) {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/secret-scanning/limits", map[string]string{"max_text_bytes": "64"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.EqualValues(t, 64<<10, effective().MaxTextBytes)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/secret-scanning/limits", map[string]string{"max_text_bytes": "0.5"}), http.StatusUnprocessableEntity)
	})
}

// A text-only alert in a repository without a wiki (so nobody can read it) is listed, and it can be opened and closed
// on the page and through the API: its places stay hidden, the alert itself is the code writers'.
func TestSecretTextOnlyAlertWithoutWiki(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repo.ID, unit.TypeWiki).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	a := seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindComment, "")
	b := seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindIssue, "body")
	session := loginUser(t, "user2")
	write := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	const alerts = "/api/v1/repos/user2/repo1/secret-scanning/alerts"

	var list []*api.SecretScanningAlert
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", alerts).AddTokenAuth(write), http.StatusOK), &list)
	numbers := map[int64]bool{}
	for _, al := range list {
		numbers[al.Number] = true
	}
	assert.True(t, numbers[a.Index] && numbers[b.Index], "listed")
	assert.Contains(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/security/secrets"), http.StatusOK).Body.String(),
		fmt.Sprintf("/user2/repo1/security/secrets/%d", a.Index))

	session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user2/repo1/security/secrets/%d", a.Index)), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", alerts, a.Index)).AddTokenAuth(write), http.StatusOK)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/security/secrets/%d/close", a.Index), map[string]string{"reason": "revoked"}), http.StatusSeeOther)
	assert.Equal(t, secretscan_model.StateRevoked, secretAlertRow(t, repo.ID, a.Index).State)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/%d", alerts, b.Index), map[string]string{"state": "resolved", "resolution": "revoked"}).AddTokenAuth(write), http.StatusOK)
	assert.Equal(t, secretscan_model.StateRevoked, secretAlertRow(t, repo.ID, b.Index).State)

	var locs []*api.SecretScanningLocation
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d/locations", alerts, a.Index)).AddTokenAuth(write), http.StatusOK), &locs)
	require.NotEmpty(t, locs)
	for _, l := range locs {
		assert.Equal(t, api.SecretScanningLocation{Type: "comment_text"}, *l, "the places in text stay hidden")
	}

	t.Run("a path search doesn't find the places in text", func(t *testing.T) {
		body := session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/security/secrets?state=closed&q=body"), http.StatusOK).Body.String()
		assert.NotContains(t, body, fmt.Sprintf("/user2/repo1/security/secrets/%d\"", b.Index))
	})
}

// Turning the Pull requests unit on (here through the API; the settings page takes the same path) reads the text that
// was in it while it was off.
func TestSecretTextUnitTurnedOn(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	defer test.MockVariableValue(&setting.SecretScanning.ScanText, true)()
	defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<20)()
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", 1, unit.TypePullRequests).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	tok := secretToken("text-unit-on")
	require.NoError(t, db.Insert(t.Context(), &issues_model.Issue{RepoID: 1, Index: 9001, PosterID: 2, IsPull: true, Title: "t", Content: tok}))
	require.NoError(t, secretscan_service.Scan(t.Context(), 1))
	assert.Nil(t, secretAlertWith(1, tok, 0), "the unit is off: not scanned")

	write := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasPullRequests: new(true)}).AddTokenAuth(write), http.StatusOK)
	require.Eventually(t, func() bool { return secretAlertWith(1, tok, 1) != nil }, 10*time.Second, 50*time.Millisecond)

	t.Run("saving the same units again doesn't reset the text scan", func(t *testing.T) {
		before, err := secretscan_model.GetScan(t.Context(), 1, secretscan_model.KindIssue)
		require.NoError(t, err)
		require.NotNil(t, before)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasPullRequests: new(true)}).AddTokenAuth(write), http.StatusOK)
		after, err := secretscan_model.GetScan(t.Context(), 1, secretscan_model.KindIssue)
		require.NoError(t, err)
		assert.Equal(t, before.Status, after.Status)
		assert.Equal(t, before.Version, after.Version)
	})
}
