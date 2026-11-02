// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	issue_service "forgejo.org/services/issue"
	"forgejo.org/services/mailer"
	maintenance_service "forgejo.org/services/maintenance"
	repo_service "forgejo.org/services/repository"
	secretscan_service "forgejo.org/services/secretscan"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redactSeed is an issue of user2/repo1 whose body holds a secret, and a comment that holds it too, with the alert and
// its places as a scan stores them (the real fingerprint, so the detector finds the secret again).
type redactSeed struct {
	issue   *issues_model.Issue
	comment *issues_model.Comment
	alert   *secretscan_model.Alert
	tok     string
}

func seedRedact(t *testing.T, seed string, index int64) *redactSeed {
	t.Helper()
	tok := secretToken(seed)
	issue := &issues_model.Issue{RepoID: 1, Index: index, PosterID: 5, Title: "deploy notes", Content: "use\n" + tok + "\nfor staging"}
	require.NoError(t, db.Insert(t.Context(), issue))
	comment := &issues_model.Comment{Type: issues_model.CommentTypeComment, IssueID: issue.ID, PosterID: 5, Content: "again " + tok}
	require.NoError(t, db.Insert(t.Context(), comment))
	a := &secretscan_model.Alert{RepoID: 1, RuleID: "github-token", SecretType: "github", LocationCount: 2, ViaPull: true, Fingerprint: secretFingerprint(tok)}
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		if err := secretscan_model.InsertAlert(ctx, a); err != nil {
			return err
		}
		locs := []*secretscan_model.Location{
			secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, issue.ID, issue.ID, "body", 2, 2, 5),
			secretscan_model.NewTextLocation(1, secretscan_model.KindComment, comment.ID, issue.ID, "", 1, 1, 5),
		}
		for _, l := range locs {
			l.AlertID = a.ID
		}
		return secretscan_model.InsertLocations(ctx, locs)
	}))
	return &redactSeed{issue: issue, comment: comment, alert: a, tok: tok}
}

func (s *redactSeed) body(t *testing.T) string {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: s.issue.ID}).Content
}

// An alert manager removes a secret from the text of an issue on the alert page or through the API; everyone else
// is refused without learning anything, and nothing is mailed.
func TestSecretTextRedact(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	defer test.MockVariableValue(&setting.SecretScanning.ScanText, true)()
	defer test.MockVariableValue(&setting.SecretScanning.MaxTextBytes, 1<<20)()
	mails := 0
	defer test.MockVariableValue(&mailer.SendAsync, func(msgs ...*mailer.Message) { mails += len(msgs) })()
	sys := audit_model.WithSystem(db.DefaultContext, "test")
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := loginUser(t, "user2")

	t.Run("web", func(t *testing.T) {
		s := seedRedact(t, "redact-web", 9301)
		page := fmt.Sprintf("/user2/repo1/security/secrets/%d", s.alert.Index)
		doc := secretPage(t, owner, page, http.StatusOK)
		assert.Equal(t, 2, doc.Find("button.secret-redact").Length(), "one per place in a text the owner reads")
		body := doc.Find(fmt.Sprintf(`button.secret-redact[data-modal-secret-redact-field="body"][data-modal-secret-redact-issue="%d"]`, s.issue.Index))
		require.Equal(t, 1, body.Length())
		assert.Equal(t, "Issue #9301 · description", body.AttrOr("data-modal-secret-redact-where", ""))
		doc.AssertElement(t, fmt.Sprintf(`button.secret-redact[data-modal-secret-redact-comment="%d"]`, s.comment.ID), true)
		doc.AssertElement(t, "#secret-redact-modal form[action$=\"/redact\"]", true)
		assert.NotContains(t, doc.Find("body").Text(), s.tok[4:])

		since := auditMaxID(t)
		secretPost(t, owner, page+"/redact", url.Values{"issue": {"9301"}, "field": {"body"}}, http.StatusSeeOther)
		assert.Contains(t, flashMessage(t, owner), "The secret was replaced with [secret removed] and its earlier versions were deleted from the edit history. Revoke it, then close the alert.")
		assert.Equal(t, "use\n"+secretscan_service.RedactedMark+"\nfor staging", s.body(t))
		e := auditOne(t, since, "repo.secret_alert.text_redacted")
		assert.Equal(t, s.alert.ID, e.TargetID)
		assert.Equal(t, int64(2), e.ActorID)
		data := auditData(t, e)
		assert.EqualValues(t, 9301, data["issue"])
		assert.Equal(t, "body", data["field"])
		assert.EqualValues(t, 1, data["replaced"])
		assert.NotContains(t, e.Data, s.tok[4:])
		assert.NotContains(t, e.Data, "staging")

		// the history: the old version is gone, the redaction is user2's
		var history []*issues_model.ContentHistory
		require.NoError(t, db.GetEngine(t.Context()).Where("issue_id = ? AND comment_id = 0", s.issue.ID).OrderBy("id").Find(&history))
		require.Len(t, history, 2)
		assert.True(t, history[0].IsDeleted)
		assert.Empty(t, history[0].ContentText)
		assert.Equal(t, int64(2), history[1].PosterID)
		for _, h := range history {
			assert.NotContains(t, h.ContentText, s.tok[4:])
		}
		// the history's own pages show nothing of it (the entry is deleted)
		resp := owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user2/repo1/issues/%d/content-history/detail?comment_id=0&history_id=%d", s.issue.Index, history[0].ID)), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), s.tok[4:])

		doc = secretPage(t, owner, page, http.StatusOK)
		assert.Equal(t, 2, doc.Find("button.secret-redact").Length(), "a removed place keeps its button: its history may hold the secret")
		assert.Equal(t, "Redact the secret from Issue #9301 · description", body.AttrOr("aria-label", ""))
		assert.Contains(t, doc.Find(".secret-locations").Text(), "Removed from the text")
		assert.Contains(t, doc.Find("#secret-activity").Text(), "removed the secret from an issue or pull request text")

		// again: nothing is left, nothing changes and nothing is recorded
		since = auditMaxID(t)
		secretPost(t, owner, page+"/redact", url.Values{"issue": {"9301"}, "field": {"body"}}, http.StatusSeeOther)
		assert.Contains(t, flashMessage(t, owner), "Nothing left to remove")
		var n int64
		_, err := db.GetEngine(t.Context()).Table("audit_event").Where("id > ? AND action = ?", since, "repo.secret_alert.text_redacted").Select("COUNT(*)").Get(&n)
		require.NoError(t, err)
		assert.Zero(t, n)

		// the comment, after its poster edited the secret out: its edit history is still erased
		require.NoError(t, issues_model.SaveIssueContentHistory(t.Context(), 5, s.issue.ID, s.comment.ID, s.comment.CreatedUnix, s.comment.Content, true))
		require.NoError(t, issues_model.SaveIssueContentHistory(t.Context(), 5, s.issue.ID, s.comment.ID, s.comment.CreatedUnix+1, "again (edited)", false))
		_, err = db.GetEngine(t.Context()).ID(s.comment.ID).Cols("content").Update(&issues_model.Comment{Content: "again (edited)"})
		require.NoError(t, err)
		since = auditMaxID(t)
		secretPost(t, owner, page+"/redact", url.Values{"comment": {fmt.Sprint(s.comment.ID)}}, http.StatusSeeOther)
		assert.Contains(t, flashMessage(t, owner), "The secret was already gone from the text. Its earlier versions were deleted from the edit history.")
		assert.Equal(t, "again (edited)", unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: s.comment.ID}).Content)
		history = nil
		require.NoError(t, db.GetEngine(t.Context()).Where("comment_id = ?", s.comment.ID).Find(&history))
		require.Len(t, history, 2)
		assert.True(t, history[0].IsDeleted, "the version that held the secret")
		assert.Empty(t, history[0].ContentText)
		assert.False(t, history[1].IsDeleted, "a clean version stays")
		assert.Equal(t, "again (edited)", history[1].ContentText)
		data = auditData(t, auditOne(t, since, "repo.secret_alert.text_redacted"))
		assert.Equal(t, true, data["history_only"])
		assert.EqualValues(t, 0, data["replaced"])

		// a target that names no text: 404
		secretPost(t, owner, page+"/redact", url.Values{"issue": {"9301"}, "field": {"path"}}, http.StatusNotFound)
	})

	t.Run("refused", func(t *testing.T) {
		s := seedRedact(t, "redact-refused", 9302)
		page := fmt.Sprintf("/user2/repo1/security/secrets/%d", s.alert.Index)
		post := url.Values{"issue": {"9302"}, "field": {"body"}}

		// a reader of the public repository: not an alert manager
		reader := loginUser(t, "user4")
		secretPage(t, reader, page, http.StatusNotFound)
		secretPost(t, reader, page+"/redact", post, http.StatusNotFound)

		// an auditor sees the alert, read-only
		_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", false)
			assert.NoError(t, err)
		}()
		auditor := loginUser(t, "user8")
		secretPage(t, auditor, page, http.StatusOK).AssertElement(t, "button.secret-redact", false)
		secretPost(t, auditor, page+"/redact", post, http.StatusNotFound)
		auditorToken := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)
		MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/secret-scanning/alerts/%d/redact", s.alert.Index), api.RedactSecretScanningTextOption{IssueNumber: 9302, Field: "body"}).AddTokenAuth(auditorToken), http.StatusNotFound)

		// archived
		require.NoError(t, repo_service.SetArchiveRepoState(sys, repo, true))
		secretPost(t, owner, page+"/redact", post, http.StatusNotFound)
		require.NoError(t, repo_service.SetArchiveRepoState(sys, repo, false))

		// read-only maintenance
		require.NoError(t, maintenance_service.Set(sys, nil, setting.MaintenanceReadOnly, maintenanceMessage, time.Time{}))
		secretPost(t, owner, page+"/redact", post, http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		require.NoError(t, maintenance_service.Set(sys, nil, setting.MaintenanceOff, "", time.Time{}))

		// the owner can't read the issue (the Issues unit is off): the place is hidden and the text can't be named
		var issues repo_model.RepoUnit
		has, err := db.GetEngine(t.Context()).Where("repo_id = 1 AND type = ?", unit.TypeIssues).Get(&issues)
		require.NoError(t, err)
		require.True(t, has)
		_, err = db.GetEngine(t.Context()).ID(issues.ID).Delete(&repo_model.RepoUnit{})
		require.NoError(t, err)
		secretPage(t, owner, page, http.StatusOK).AssertElement(t, "button.secret-redact", false)
		secretPost(t, owner, page+"/redact", post, http.StatusNotFound)
		_, err = db.GetEngine(t.Context()).Insert(&issues)
		require.NoError(t, err)

		assert.Equal(t, "use\n"+s.tok+"\nfor staging", s.body(t), "nothing was changed")
	})

	t.Run("API", func(t *testing.T) {
		s := seedRedact(t, "redact-api", 9303)
		path := fmt.Sprintf("/api/v1/repos/user2/repo1/secret-scanning/alerts/%d/redact", s.alert.Index)
		body := api.RedactSecretScanningTextOption{IssueNumber: 9303, Field: "body"}
		write := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)

		// the location carries the comment ID the API names a comment by
		var locs []*api.SecretScanningLocation
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", strings.TrimSuffix(path, "/redact")+"/locations").AddTokenAuth(write), http.StatusOK), &locs)
		var commentID int64
		for _, l := range locs {
			if l.Type == "issue_comment" {
				commentID = l.Details.CommentID
			}
		}
		assert.Equal(t, s.comment.ID, commentID)

		for _, scopes := range [][]auth_model.AccessTokenScope{
			{auth_model.AccessTokenScopeWriteRepository},                                       // no write:issue: 403 before any lookup
			{auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeWriteIssue}, // a write needs write:repository
		} {
			MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(getUserToken(t, "user2", scopes...)), http.StatusForbidden)
		}
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)), http.StatusNotFound)
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, api.RedactSecretScanningTextOption{IssueNumber: 9303, Field: "path"}).AddTokenAuth(write), http.StatusUnprocessableEntity)
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, api.RedactSecretScanningTextOption{IssueNumber: 1, Field: "body"}).AddTokenAuth(write), http.StatusNotFound)

		require.NoError(t, repo_service.SetArchiveRepoState(sys, repo, true))
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(write), http.StatusLocked)
		require.NoError(t, repo_service.SetArchiveRepoState(sys, repo, false))
		require.NoError(t, maintenance_service.Set(sys, nil, setting.MaintenanceReadOnly, maintenanceMessage, time.Time{}))
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(write), http.StatusServiceUnavailable)
		require.NoError(t, maintenance_service.Set(sys, nil, setting.MaintenanceOff, "", time.Time{}))
		assert.Contains(t, s.body(t), s.tok)

		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(write), http.StatusNoContent)
		assert.Equal(t, "use\n"+secretscan_service.RedactedMark+"\nfor staging", s.body(t))
		assert.Equal(t, s.alert.ID, auditOne(t, since, "repo.secret_alert.text_redacted").TargetID)
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(write), http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "no longer in this text")

		MakeRequest(t, NewRequestWithJSON(t, "POST", path, api.RedactSecretScanningTextOption{CommentID: s.comment.ID}).AddTokenAuth(write), http.StatusNoContent)
		assert.NotContains(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: s.comment.ID}).Content, s.tok)

		// a review's body: the reviews API reads the review's own copy, which is redacted too
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: 1, Index: 2})
		review := &issues_model.Review{Type: issues_model.ReviewTypeComment, ReviewerID: 2, IssueID: pr.ID, Content: "see " + s.tok}
		require.NoError(t, db.Insert(t.Context(), review))
		reviewComment := &issues_model.Comment{Type: issues_model.CommentTypeReview, IssueID: pr.ID, PosterID: 2, ReviewID: review.ID, Content: review.Content}
		require.NoError(t, db.Insert(t.Context(), reviewComment))
		place := secretscan_model.NewTextLocation(1, secretscan_model.KindComment, reviewComment.ID, pr.ID, "", 1, 1, 2)
		place.AlertID = s.alert.ID
		require.NoError(t, secretscan_model.InsertLocations(t.Context(), []*secretscan_model.Location{place}))
		reviews := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/pulls/2/reviews").AddTokenAuth(write), http.StatusOK)
		require.Contains(t, reviews.Body.String(), s.tok)
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, api.RedactSecretScanningTextOption{CommentID: reviewComment.ID}).AddTokenAuth(write), http.StatusNoContent)
		reviews = MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/pulls/2/reviews").AddTokenAuth(write), http.StatusOK)
		assert.NotContains(t, reviews.Body.String(), s.tok)
		assert.Contains(t, reviews.Body.String(), "see "+secretscan_service.RedactedMark)

		// scanning off: the route is gone
		restore := test.MockVariableValue(&setting.SecretScanning.Enabled, false)
		t.Cleanup(func() { // the cached "off" must not outlive the mock
			restore()
			bumpSettingsRevision(t)
		})
		bumpSettingsRevision(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(write), http.StatusNotFound)
	})

	// nothing in the whole flow mailed anyone, also from a queue that ran late
	require.NoError(t, queue.GetManager().FlushAll(t.Context(), 10*time.Second))
	assert.Zero(t, mails, "a redaction mails nobody")

	// and the count does see mail: a plain comment by user2 on user5's issue mails user5
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: 1, Index: 9301})
	_, err := issue_service.CreateIssueComment(sys, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), repo, issue, "a plain comment", nil)
	require.NoError(t, err)
	require.NoError(t, queue.GetManager().FlushAll(t.Context(), 10*time.Second))
	assert.Positive(t, mails)
}
