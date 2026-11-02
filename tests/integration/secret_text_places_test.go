// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// textAlert stores an alert whose places are the given locations (AlertID is set here).
func textAlert(t *testing.T, repo *repo_model.Repository, locs ...*secretscan_model.Location) *secretscan_model.Alert {
	t.Helper()
	a := &secretscan_model.Alert{RepoID: repo.ID, RuleID: "github-token", SecretType: "github", LocationCount: len(locs), ViaPull: true, Fingerprint: fmt.Sprintf("%064x", secretAlertSeq.Add(1))}
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		if err := secretscan_model.InsertAlert(ctx, a); err != nil {
			return err
		}
		for _, l := range locs {
			l.AlertID = a.ID
			if _, err := db.GetEngine(ctx).Insert(l); err != nil {
				return err
			}
		}
		return nil
	}))
	return a
}

// The places of an alert in text show their issue number, link, part and poster to someone who may read that issue or
// pull request, and otherwise only "in an issue" or "in a comment": the page, the list, the API and a list across
// repositories, for every access the Issues and Pull requests units can give.
func TestSecretTextPlacesGating(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	ctx := t.Context()
	repo := &repo_model.Repository{ID: 1}
	issue := &issues_model.Issue{RepoID: 1, Index: 9101, PosterID: 5, Title: "t"}
	pull := &issues_model.Issue{RepoID: 1, Index: 9102, PosterID: 4, Title: "p", IsPull: true}
	require.NoError(t, db.Insert(ctx, issue))
	require.NoError(t, db.Insert(ctx, pull))
	const issueComment, pullComment = 424242, 424243
	a := textAlert(t, repo,
		secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, issue.ID, issue.ID, "body", 2, 2, 5),
		secretscan_model.NewTextLocation(1, secretscan_model.KindComment, issueComment, issue.ID, "", 1, 1, 4),
		secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, pull.ID, pull.ID, "title", 1, 1, 4),
		secretscan_model.NewTextLocation(1, secretscan_model.KindComment, pullComment, pull.ID, "", 1, 1, 5),
	)
	_, err := db.GetEngine(ctx).Exec("UPDATE secret_scanning_location SET removed_unix = 1700000000 WHERE source_id = ?", pullComment)
	require.NoError(t, err)
	// an alert that is only in text, and one that is in code too
	onlyText := textAlert(t, repo, secretscan_model.NewTextLocation(1, secretscan_model.KindIssue, issue.ID, issue.ID, "title", 1, 1, 5))
	code := seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindRepo, "deploy/env")

	owner := loginUser(t, "user2")
	page := fmt.Sprintf("/user2/repo1/security/secrets/%d", a.Index)
	read := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadIssue)
	locsURL := fmt.Sprintf("/api/v1/repos/user2/repo1/secret-scanning/alerts/%d/locations", a.Index)
	places := func(t *testing.T) string { // the text of the table of places
		return NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body).Find(".secret-locations").Text()
	}
	apiTypes := func(t *testing.T) (types []string, raw string) {
		t.Helper()
		resp := MakeRequest(t, NewRequest(t, "GET", locsURL).AddTokenAuth(read), http.StatusOK)
		var locs []*api.SecretScanningLocation
		DecodeJSON(t, resp, &locs)
		for _, l := range locs {
			types = append(types, l.Type)
		}
		return types, resp.Body.String()
	}
	removeUnit := func(typ unit.Type) {
		t.Helper()
		_, err := db.GetEngine(ctx).Exec("DELETE FROM repo_unit WHERE repo_id = 1 AND type = ?", typ)
		require.NoError(t, err)
	}

	t.Run("a reader of issues and pull requests", func(t *testing.T) {
		text := places(t)
		for _, want := range []string{"Issue #9101", "Pull request #9102", "user5", "user4", "Removed from the text", "description, line 2", "· title"} {
			assert.Contains(t, text, want)
		}
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
		hrefs := map[string]bool{}
		doc.Find(".secret-locations a").Each(func(_ int, s *goquery.Selection) { hrefs[s.AttrOr("href", "")] = true })
		assert.True(t, hrefs[setting.AppURL+"user2/repo1/issues/9101"], "%v", hrefs)
		assert.True(t, hrefs["/user5"], "the poster links to the profile: %v", hrefs)
		assert.NotContains(t, text, "Details hidden")

		// a text-only alert was not first seen "in a pull request"
		first := func(alert *secretscan_model.Alert) string {
			return NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user2/repo1/security/secrets/%d", alert.Index)), http.StatusOK).Body).Find("body").Text()
		}
		assert.Contains(t, first(onlyText), "in an issue, pull request or comment")
		assert.NotContains(t, first(onlyText), "in a pull request")
		assert.Contains(t, first(onlyText), "Editing or deleting the text is not enough")

		types, _ := apiTypes(t)
		assert.ElementsMatch(t, []string{"issue_body", "issue_comment", "pull_request_title", "pull_request_comment"}, types)
		var locs []*api.SecretScanningLocation
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", locsURL).AddTokenAuth(read), http.StatusOK), &locs)
		for _, l := range locs {
			if l.Type == "issue_comment" {
				assert.EqualValues(t, 9101, l.Details.IssueNumber)
				assert.Equal(t, "user4", l.Details.Poster)
				assert.Equal(t, fmt.Sprintf("/api/v1/repos/user2/repo1/issues/comments/%d", issueComment), strings.TrimPrefix(l.Details.IssueCommentURL, setting.AppURL[:len(setting.AppURL)-1]))
				assert.Contains(t, l.Details.HTMLURL, fmt.Sprintf("/issues/9101#issuecomment-%d", issueComment))
			}
			if l.Type == "pull_request_comment" {
				assert.True(t, l.Details.Removed)
				assert.Contains(t, l.Details.HTMLURL, "/pulls/9102#issuecomment-")
			}
		}
	})

	t.Run("a token without read:issue sees the places as a non-reader does", func(t *testing.T) {
		repoOnly := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		withIssue := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadIssue)
		types := func(token string) (types []string, raw string) {
			resp := MakeRequest(t, NewRequest(t, "GET", locsURL).AddTokenAuth(token), http.StatusOK)
			var locs []*api.SecretScanningLocation
			DecodeJSON(t, resp, &locs)
			for _, l := range locs {
				types = append(types, l.Type)
			}
			return types, resp.Body.String()
		}
		got, raw := types(repoOnly)
		assert.ElementsMatch(t, []string{"issue_text", "comment_text", "issue_text", "comment_text"}, got)
		for _, secret := range []string{"9101", "9102", "user5", "user4", "removed", "html_url"} {
			assert.NotContains(t, raw, secret)
		}
		got, _ = types(withIssue)
		assert.ElementsMatch(t, []string{"issue_body", "issue_comment", "pull_request_title", "pull_request_comment"}, got)
	})

	t.Run("without the Pull requests unit the pull request's places are hidden, the issue's are not", func(t *testing.T) {
		removeUnit(unit.TypePullRequests)
		text := places(t)
		assert.Contains(t, text, "Issue #9101")
		assert.NotContains(t, text, "#9102")
		assert.Contains(t, text, "Revoking the credential covers these places too.")
		assert.NotContains(t, text, "Removed from the text", "the removal of a hidden place is hidden")
		assert.Equal(t, 2, strings.Count(text, "Details hidden: you don't have access to issues or pull requests here"))
		types, _ := apiTypes(t)
		assert.ElementsMatch(t, []string{"issue_body", "issue_comment", "issue_text", "comment_text"}, types)
	})

	t.Run("without the Issues unit nothing of any text is told", func(t *testing.T) {
		removeUnit(unit.TypeIssues)
		text := places(t)
		for _, secret := range []string{"#91", "user5", "user4", "Removed", "title", "description", "9101", "9102", "424242"} {
			assert.NotContains(t, text, secret)
		}
		assert.Equal(t, 4, strings.Count(text, "Details hidden: you don't have access to issues or pull requests here"))
		assert.Equal(t, 2, strings.Count(text, "In an issue"))
		assert.Equal(t, 2, strings.Count(text, "In a comment"))
		types, raw := apiTypes(t)
		assert.ElementsMatch(t, []string{"issue_text", "issue_text", "comment_text", "comment_text"}, types)
		for _, secret := range []string{"9101", "9102", "user5", "user4", "424242", "removed", "issue_title_url", "issue_body_url", "issue_comment_url", "pull_request_title_url", "pull_request_body_url", "pull_request_comment_url", "html_url"} {
			assert.NotContains(t, raw, secret)
		}

		// the alert is still there, with its places counted, and the list names the place without a number
		list := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/security/secrets"), http.StatusOK).Body).Find(".secret-alerts-table").Text()
		assert.Contains(t, list, "In an issue")
		assert.NotContains(t, list, "#91")
		assert.NotContains(t, list, "user5")
	})

	t.Run("the facet: found in", func(t *testing.T) {
		count := func(query string) int {
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/security/secrets?"+query), http.StatusOK).Body)
			return doc.Find(".secret-alerts-table .repo-security-row:not(.repo-security-head)").Length()
		}
		assert.Equal(t, 3, count(""))
		assert.Equal(t, 2, count("found=text"), "the alert in code only is not in it")
		assert.Equal(t, 1, count("found=code"))
		assert.Equal(t, 0, count("found=pull"), "a place in text is no pull ref")
		assert.Equal(t, 3, count("found=bogus"), "an unknown value is ignored, and the page says so")
		assert.NotZero(t, onlyText.ID+code.ID)
	})
}

// A list across repositories names a place in text only as "in an issue" or "in a comment", and its CSV by a fixed
// token: no number, no link, no poster.
func TestSecretTextPlacesOrgList(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	issue := &issues_model.Issue{RepoID: f.root.ID, Index: 1, PosterID: 5, Title: "t"}
	require.NoError(t, db.Insert(t.Context(), issue))
	textAlert(t, f.root, secretscan_model.NewTextLocation(f.root.ID, secretscan_model.KindComment, 424242, issue.ID, "", 1, 1, 5))
	owner := loginUser(t, "user2")

	rows := slCSV(t, slPost(t, owner, slOrg, map[string]string{}, http.StatusOK))
	require.NotEmpty(t, rows)
	assert.Equal(t, "text:comment", rows[0][8], "newest first")
	assert.NotContains(t, strings.Join(rows[0], ","), "424242")
	assert.NotContains(t, strings.Join(rows[0], ","), "user5")

	body := secGet(t, owner, slOrg, http.StatusOK).Body.String()
	doc := NewHTMLParser(t, bytes.NewBufferString(body))
	table := doc.Find("table.secret-search-table").Text()
	assert.Contains(t, table, "In a comment")
	assert.NotContains(t, table, "424242")
	assert.NotContains(t, table, "#1 ")
}

// A real non-reader (a team with the Code unit and no Issues unit) gets the hidden places; an auditor, who reads every
// repository, gets the full details; a place whose issue is gone shows as deleted to a reader.
func TestSecretTextPlacesRealAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	ctx := t.Context()
	issue := &issues_model.Issue{RepoID: f.root.ID, Index: 7701, PosterID: 5, Title: "t"}
	require.NoError(t, db.Insert(ctx, issue))
	gone := textAlert(t, f.root, secretscan_model.NewTextLocation(f.root.ID, secretscan_model.KindIssue, 987654, 987654, "body", 1, 1, 5))
	a := textAlert(t, f.root, secretscan_model.NewTextLocation(f.root.ID, secretscan_model.KindIssue, issue.ID, issue.ID, "body", 3, 3, 5))
	page := func(user string, alert *secretscan_model.Alert) string {
		return NewHTMLParser(t, loginUser(t, user).MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/sl-root/security/secrets/%d", alert.Index)), http.StatusOK).Body).Find(".secret-locations").Text()
	}

	// user4 writes code through a team that has the Code unit only
	text := page("user4", a)
	assert.Contains(t, text, "Details hidden: you don't have access to issues or pull requests here")
	for _, secret := range []string{"7701", "user5", "body"} {
		assert.NotContains(t, text, secret)
	}

	setUserFlag(t, 5, "is_auditor", true)
	text = page("user5", a)
	assert.Contains(t, text, "Issue #7701")
	assert.Contains(t, text, "description, line 3")
	assert.NotContains(t, text, "Details hidden")

	// an alert in code and in text gets the combined guidance
	both := textAlert(t, f.root, secretscan_model.NewTextLocation(f.root.ID, secretscan_model.KindIssue, issue.ID, issue.ID, "body", 1, 1, 5))
	codePlace := secretscan_model.NewLocation(f.root.ID, secretscan_model.KindRepo, "blobboth", "a.env", 1, 1, "commitsha1", "An Author", "author@example.com", 1700000000)
	codePlace.AlertID = both.ID
	require.NoError(t, db.Insert(ctx, codePlace))
	body := NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/sl-root/security/secrets/%d", both.Index)), http.StatusOK).Body).Find("#secret-guidance").Text()
	assert.Contains(t, body, "it stays in git history and in notification mails, and in the text's edit history until you redact it")

	text = page("user2", gone)
	assert.Contains(t, text, "The issue or pull request was deleted")
	assert.NotContains(t, text, "Details hidden")
}
