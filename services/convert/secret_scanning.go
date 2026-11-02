// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package convert

import (
	"context"
	"strconv"
	"time"

	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/translation"
	"forgejo.org/modules/util"
)

// ToSecretScanningAlerts converts alerts of one repository (one query for the users who closed them, one for the
// places). The count is the one the locations endpoint gives the viewer: without canReadWiki, places in the wiki
// are not in it.
func ToSecretScanningAlerts(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, alerts []*secretscan_model.Alert, canReadWiki bool) ([]*api.SecretScanningAlert, error) {
	var userIDs, alertIDs []int64
	for _, a := range alerts {
		alertIDs = append(alertIDs, a.ID)
		if a.ClosedByID != 0 {
			userIDs = append(userIDs, a.ClosedByID)
		}
	}
	users, err := user_model.GetUsersByIDsWithBots(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	counts, err := secretscan_model.CountLocations(ctx, repo.ID, alertIDs, !canReadWiki)
	if err != nil {
		return nil, err
	}
	ruleIDs := make([]string, len(alerts))
	for i, a := range alerts {
		ruleIDs[i] = a.RuleID
	}
	labels, err := secretscan_model.LoadRuleLabels(ctx, ruleIDs) // one query; a deleted pattern's name stays out
	if err != nil {
		return nil, err
	}
	locale := translation.NewLocale("en-US") // the API's names are English
	out := make([]*api.SecretScanningAlert, 0, len(alerts))
	for _, a := range alerts {
		index := strconv.FormatInt(a.Index, 10)
		res := &api.SecretScanningAlert{
			Number: a.Index, State: secretscan_model.StateOpen, SecretType: a.RuleID, SecretTypeDisplayName: labels.Label(a.RuleID, repo.OwnerID, nil).Text(locale),
			Fingerprint: a.Fingerprint, ViaPull: a.ViaPull, LocationsCount: counts[a.ID],
			URL:       repo.APIURL() + "/secret-scanning/alerts/" + index,
			CreatedAt: time.Unix(int64(a.CreatedUnix), 0).UTC(), UpdatedAt: time.Unix(int64(a.UpdatedUnix), 0).UTC(),
			HTMLURL: repo.HTMLURL() + "/security/secrets/" + index, LocationsURL: repo.APIURL() + "/secret-scanning/alerts/" + index + "/locations",
		}
		if a.State != secretscan_model.StateOpen {
			res.State, res.Resolution, res.ResolutionComment = "resolved", a.Reason, a.Comment
		}
		if a.ClosedByID != 0 {
			_, u := user_model.GetUserFromMap(a.ClosedByID, users)
			res.ResolvedBy = ToUser(ctx, u, doer)
		}
		if a.ClosedUnix != 0 {
			t := time.Unix(int64(a.ClosedUnix), 0).UTC()
			res.ResolvedAt = &t
		}
		out = append(out, res)
	}
	return out, nil
}

// ToSecretScanningLocations converts places of an alert of the repository, in GitHub's shape; wikiURL turns the
// path of a wiki place into its page URL. texts has the places in text as the caller may see them
// (LoadTextPlaces): one the caller may not read is only named issue_text or comment_text, without any detail.
func ToSecretScanningLocations(repo *repo_model.Repository, locs []*secretscan_model.Location, texts map[int64]*secretscan_model.TextPlace, wikiURL func(path string) string) []*api.SecretScanningLocation {
	out := make([]*api.SecretScanningLocation, 0, len(locs))
	for _, l := range locs {
		if l.IsText() {
			out = append(out, toTextLocation(repo, l, texts[l.ID]))
			continue
		}
		res := &api.SecretScanningLocation{Type: "commit", Details: api.SecretScanningLocationDetails{
			Path: l.Path, StartLine: l.StartLine, EndLine: l.EndLine, BlobSHA: l.BlobID, CommitSHA: l.CommitID,
			CommitAuthorName: l.AuthorName, CommitAuthorEmail: l.AuthorEmail, PullRef: l.Kind == secretscan_model.KindPull,
		}}
		if l.CommitUnix != 0 {
			t := time.Unix(l.CommitUnix, 0).UTC()
			res.Details.CommitDate = &t
		}
		switch {
		case l.Kind == secretscan_model.KindWiki:
			res.Type, res.Details.PageURL = "wiki_commit", wikiURL(l.Path)
		case l.CommitID != "":
			res.Details.BlobURL = repo.APIURL() + "/git/blobs/" + l.BlobID
			res.Details.CommitURL = repo.APIURL() + "/git/commits/" + l.CommitID
			res.Details.HTMLURL = repo.HTMLURL() + "/src/commit/" + l.CommitID + "/" + util.PathEscapeSegments(l.Path) + "#L" + strconv.Itoa(l.StartLine)
			if l.EndLine > l.StartLine {
				res.Details.HTMLURL += "-L" + strconv.Itoa(l.EndLine)
			}
		}
		out = append(out, res)
	}
	return out
}

func toTextLocation(repo *repo_model.Repository, l *secretscan_model.Location, p *secretscan_model.TextPlace) *api.SecretScanningLocation {
	if p == nil || !p.Readable {
		hidden := &api.SecretScanningLocation{Type: l.Kind + "_text"} // issue_text, comment_text
		if p != nil && p.Deleted {
			hidden.Details.Removed = true // the caller reads both units: the issue is gone
		}
		return hidden
	}
	what := util.Iif(p.IsPull, "pull_request", "issue")
	field := util.Iif(l.Kind == secretscan_model.KindComment, "comment", l.Field)
	num := strconv.FormatInt(p.Number, 10)
	d := api.SecretScanningLocationDetails{
		StartLine: l.StartLine, EndLine: l.EndLine, IssueNumber: p.Number, Field: field, Removed: p.Removed(),
		HTMLURL: repo.HTMLURL() + util.Iif(p.IsPull, "/pulls/", "/issues/") + num,
	}
	url := repo.APIURL() + util.Iif(p.IsPull, "/pulls/", "/issues/") + num
	if l.Kind == secretscan_model.KindComment {
		id := strconv.FormatInt(l.SourceID, 10)
		url, d.HTMLURL = repo.APIURL()+"/issues/comments/"+id, d.HTMLURL+"#issuecomment-"+id
		d.CommentID = l.SourceID
	}
	typ := what + "_" + field
	switch typ { // GitHub's names: one URL key per type
	case "issue_title":
		d.IssueTitleURL = url
	case "issue_body":
		d.IssueBodyURL = url
	case "issue_comment":
		d.IssueCommentURL = url
	case "pull_request_title":
		d.PullRequestTitleURL = url
	case "pull_request_body":
		d.PullRequestBodyURL = url
	case "pull_request_comment":
		d.PullRequestCommentURL = url
	}
	if p.Poster != nil {
		d.Poster = p.Poster.Name
	}
	return &api.SecretScanningLocation{Type: typ, Details: d}
}

// ToSecretScanningStatus sums up the state rows of a repository's code, wiki and pull refs: failed beats incomplete
// beats ok (the reason is the code of the row that decides), holes and skipped files add up, and no row is pending.
// The scanned tips never leave the model.
func ToSecretScanningStatus(scans []*secretscan_model.Scan) *api.SecretScanningStatus {
	res := &api.SecretScanningStatus{Status: "pending"}
	rank := map[string]int{secretscan_model.StatusOK: 1, secretscan_model.StatusIncomplete: 2, secretscan_model.StatusFailed: 3}
	best := 0
	for _, s := range scans {
		res.Holes += s.Holes
		res.SkippedLarge += s.SkippedLarge
		if t := s.UpdatedUnix.AsTimePtr(); s.Status != secretscan_model.StatusFailed && t != nil && (res.LastScanned == nil || t.After(*res.LastScanned)) {
			res.LastScanned = t
		}
		if r := rank[s.Status]; r > best {
			best, res.Status, res.Reason = r, s.Status, s.Error
		}
	}
	return res
}
