// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package metrics computes delivery metrics from existing pull request, review and comment rows.
package metrics

import (
	"cmp"
	"context"
	"encoding/csv"
	"io"
	"slices"
	"strconv"
	"time"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// MaxPRs caps the pull requests a report reads (and 10 times as many events); beyond it the report is Truncated.
var MaxPRs = 10000

// maxReviewers is how many reviewers the review load table lists.
const maxReviewers = 50

const week = 7 * 24 * 3600

// ParsePeriod reads the period in days: 7, 30 or 90, anything else is 30.
func ParsePeriod(s string) int {
	switch s {
	case "7", "90":
		n, _ := strconv.Atoi(s)
		return n
	}
	return 30
}

// Stat is the nearest-rank median and 85th percentile of N samples.
type Stat struct {
	N           int
	Median, P85 int64
}

func newStat(samples []int64) Stat {
	slices.Sort(samples)
	return Stat{N: len(samples), Median: percentile(samples, 50), P85: percentile(samples, 85)}
}

// percentile is the nearest-rank percentile p of sorted, 0 if it is empty.
func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[(p*len(sorted)+99)/100-1]
}

// Week is one of the rolling weeks of a report, the newest ending now.
type Week struct {
	From, To    timeutil.TimeStamp
	Merged      int
	Merge       Stat // time to merge of the pull requests merged in the week
	FirstReview Stat // time to first review of the first reviews in the week
}

// Reviewer is the number of reviews a user submitted on pull requests of others.
type Reviewer struct {
	User    *user_model.User
	Reviews int64
}

// Row is one pull request of a report. Times are 0 and durations -1 when unknown.
type Row struct {
	OwnerName, RepoName         string
	Number                      int64
	Title                       string
	Created, Ready, FirstReview timeutil.TimeStamp
	Merged                      timeutil.TimeStamp
	ToFirstReview, ToMerge      int64
	Commits                     int // 0 when unknown
}

// Report holds the pull request metrics of a period ending now.
type Report struct {
	Days                   int
	From, To               timeutil.TimeStamp
	FirstReview, Merge     Stat
	Commits                Stat // commits of the pull requests merged in the period, where known
	Merged                 int
	PerWeek                float64
	Weeks                  []Week // oldest first
	Reviews, ReviewerCount int64
	Reviewers              []*Reviewer // only when asked for
	Rows                   []*Row
	Truncated              bool
}

// prRow is what the first query reads.
type prRow struct {
	IssueID, PosterID, Number int64
	Title                     string
	Created, Merged           timeutil.TimeStamp
	HasMerged                 bool
	Commits                   int
	OwnerName, RepoName       string
}

// event is a title change or a review submission.
type event struct {
	IssueID, PosterID  int64
	Type               issues_model.CommentType
	OldTitle, NewTitle string
	CreatedUnix        timeutil.TimeStamp
}

// RepoReport is the report of the pull requests of a repository the caller has checked the doer may read.
func RepoReport(ctx context.Context, repoID int64, days int, withReviewers bool, now timeutil.TimeStamp) (*Report, error) {
	return report(ctx, builder.Eq{"`repository`.id": repoID}, days, withReviewers, now)
}

// OrgReport is the report of the pull requests of the repositories of org whose pull requests doer may read.
// admin is whether doer acts as a site admin.
func OrgReport(ctx context.Context, orgID int64, doer *user_model.User, admin bool, days int, withReviewers bool, now timeutil.TimeStamp) (*Report, error) {
	// before any session: it reads dynamic settings
	return report(ctx, repo_model.OrgUnitRepoCond(ctx, orgID, doer, admin, unit.TypePullRequests), days, withReviewers, now)
}

func report(ctx context.Context, repoCond builder.Cond, days int, withReviewers bool, now timeutil.TimeStamp) (*Report, error) {
	from := now - timeutil.TimeStamp(days*24*3600)
	pulls := builder.Eq{"`issue`.is_pull": true}.And(builder.In("`issue`.repo_id", builder.Select("id").From("repository").Where(repoCond)))
	inPeriod := builder.Or(
		builder.Eq{"`pull_request`.has_merged": true}.And(builder.Gte{"`pull_request`.merged_unix": from}),
		builder.In("`issue`.id", builder.Select("`comment`.issue_id").From("comment").
			Where(builder.Eq{"`comment`.type": issues_model.CommentTypeReview}.And(builder.Gte{"`comment`.created_unix": from}))),
	)
	rowCond := pulls.And(inPeriod)

	var prs []*prRow
	if err := db.GetEngine(ctx).Table("pull_request").
		Select("`issue`.id AS issue_id, `issue`.poster_id, `issue`.`index` AS number, `issue`.name AS title, `issue`.created_unix AS created, "+
			"`pull_request`.merged_unix AS merged, `pull_request`.has_merged, `pull_request`.commits_ahead AS commits, "+
			"`repository`.owner_name, `repository`.name AS repo_name").
		Join("INNER", "issue", "`issue`.id = `pull_request`.issue_id").
		Join("INNER", "repository", "`repository`.id = `issue`.repo_id").
		Where(rowCond).Desc("`issue`.id").Limit(MaxPRs + 1).Find(&prs); err != nil {
		return nil, err
	}
	truncated := len(prs) > MaxPRs
	prs = prs[:min(len(prs), MaxPRs)]

	var events []*event
	if len(prs) > 0 {
		// newest first, so the rows from the oldest loaded one on are exactly the loaded ones
		ids := builder.Select("`issue`.id").From("issue").
			Join("INNER", "pull_request", "`pull_request`.issue_id = `issue`.id").Where(rowCond)
		if err := db.GetEngine(ctx).Table("comment").Cols("issue_id", "poster_id", "type", "old_title", "new_title", "created_unix").
			Where(builder.In("type", issues_model.CommentTypeChangeTitle, issues_model.CommentTypeReview).
				And(builder.Gte{"issue_id": prs[len(prs)-1].IssueID}).And(builder.In("issue_id", ids))).
			OrderBy("id").Limit(10*MaxPRs + 1).Find(&events); err != nil {
			return nil, err
		}
		if len(events) > 10*MaxPRs {
			truncated = true
			events = events[:10*MaxPRs]
		}
	}

	r := build(prs, events, from, now, days)
	r.Truncated = truncated

	var load []*struct {
		PosterID, Reviews int64
	}
	if err := db.GetEngine(ctx).Table("comment").Select("`comment`.poster_id, COUNT(*) AS reviews").
		Join("INNER", "issue", "`issue`.id = `comment`.issue_id").
		Where(pulls.And(builder.Eq{"`comment`.type": issues_model.CommentTypeReview}, builder.Gte{"`comment`.created_unix": from},
			builder.Expr("`comment`.poster_id <> `issue`.poster_id"))).
		GroupBy("`comment`.poster_id").Find(&load); err != nil {
		return nil, err
	}
	for _, l := range load {
		r.Reviews += l.Reviews
	}
	r.ReviewerCount = int64(len(load))
	if !withReviewers || len(load) == 0 {
		return r, nil
	}
	slices.SortFunc(load, func(a, b *struct{ PosterID, Reviews int64 }) int {
		return cmp.Or(cmp.Compare(b.Reviews, a.Reviews), cmp.Compare(a.PosterID, b.PosterID))
	})
	load = load[:min(len(load), maxReviewers)]
	ids := make([]int64, len(load))
	for i, l := range load {
		ids[i] = l.PosterID
	}
	users, err := user_model.GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*user_model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	for _, l := range load {
		u := byID[l.PosterID]
		if u == nil {
			u = user_model.NewGhostUser()
		}
		r.Reviewers = append(r.Reviewers, &Reviewer{User: u, Reviews: l.Reviews})
	}
	return r, nil
}

// build computes the report of the period [from, now) from the pull requests and their events, ordered by id.
func build(prs []*prRow, events []*event, from, now timeutil.TimeStamp, days int) *Report {
	byIssue := make(map[int64][]*event, len(prs))
	for _, e := range events {
		byIssue[e.IssueID] = append(byIssue[e.IssueID], e)
	}
	r := &Report{Days: days, From: from, To: now}
	weeks := make([]struct{ merge, review []int64 }, (days+6)/7)
	weekOf := func(t timeutil.TimeStamp) int { return min(int((now-t)/week), len(weeks)-1) }
	var reviewSamples, mergeSamples, commits []int64
	for _, pr := range prs {
		row := &Row{
			OwnerName: pr.OwnerName, RepoName: pr.RepoName, Number: pr.Number, Title: pr.Title, Created: pr.Created,
			ToFirstReview: -1, ToMerge: -1, Commits: pr.Commits,
		}
		initial := pr.Title
		for _, e := range byIssue[pr.IssueID] {
			if e.Type == issues_model.CommentTypeChangeTitle {
				initial = e.OldTitle
				break
			}
		}
		if !issues_model.HasWorkInProgressPrefix(initial) {
			row.Ready = pr.Created
		} else {
			for _, e := range byIssue[pr.IssueID] {
				if e.Type == issues_model.CommentTypeChangeTitle && issues_model.HasWorkInProgressPrefix(e.OldTitle) && !issues_model.HasWorkInProgressPrefix(e.NewTitle) {
					row.Ready = e.CreatedUnix
					break
				}
			}
		}
		if row.Ready != 0 {
			for _, e := range byIssue[pr.IssueID] {
				if e.Type == issues_model.CommentTypeReview && e.PosterID != pr.PosterID && e.CreatedUnix >= row.Ready &&
					(row.FirstReview == 0 || e.CreatedUnix < row.FirstReview) {
					row.FirstReview = e.CreatedUnix
				}
			}
		}
		if row.FirstReview != 0 {
			row.ToFirstReview = int64(row.FirstReview - row.Ready)
			if row.FirstReview >= from && row.FirstReview < now {
				reviewSamples = append(reviewSamples, row.ToFirstReview)
				w := &weeks[weekOf(row.FirstReview)]
				w.review = append(w.review, row.ToFirstReview)
			}
		}
		if pr.HasMerged {
			row.Merged = pr.Merged
			start := pr.Created
			if row.Ready > 0 && row.Ready <= pr.Merged {
				start = row.Ready
			}
			row.ToMerge = int64(pr.Merged - start)
			if pr.Merged >= from {
				r.Merged++
				mergeSamples = append(mergeSamples, row.ToMerge)
				if pr.Commits > 0 {
					commits = append(commits, int64(pr.Commits))
				}
				w := &weeks[weekOf(min(pr.Merged, now))]
				w.merge = append(w.merge, row.ToMerge)
			}
		}
		r.Rows = append(r.Rows, row)
	}
	r.FirstReview, r.Merge, r.Commits = newStat(reviewSamples), newStat(mergeSamples), newStat(commits)
	r.PerWeek = float64(r.Merged) * 7 / float64(days)
	for k, samples := range slices.Backward(weeks) {
		w := Week{To: now - timeutil.TimeStamp(k*week), From: max(now-timeutil.TimeStamp((k+1)*week), from), Merged: len(samples.merge)}
		w.Merge, w.FirstReview = newStat(samples.merge), newStat(samples.review)
		r.Weeks = append(r.Weeks, w)
	}
	return r
}

// URL is the web address of the pull request.
func (row *Row) URL() string {
	return (&repo_model.Repository{OwnerName: row.OwnerName, Name: row.RepoName}).HTMLURL() + "/pulls/" + strconv.FormatInt(row.Number, 10)
}

// WriteCSV writes one line per pull request of the report.
func WriteCSV(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"repository", "number", "title", "url", "created", "ready", "first_review", "merged", "seconds_to_first_review", "seconds_to_merge", "commits"})
	for _, row := range r.Rows {
		commits := ""
		if row.Commits > 0 {
			commits = strconv.Itoa(row.Commits)
		}
		_ = cw.Write([]string{
			util.CSVSafe(row.OwnerName + "/" + row.RepoName), strconv.FormatInt(row.Number, 10), util.CSVSafe(row.Title), util.CSVSafe(row.URL()),
			csvTime(row.Created), csvTime(row.Ready), csvTime(row.FirstReview), csvTime(row.Merged),
			csvInt(row.ToFirstReview), csvInt(row.ToMerge), commits,
		})
	}
	cw.Flush()
	return cw.Error()
}

func csvTime(t timeutil.TimeStamp) string {
	if t == 0 {
		return ""
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

func csvInt(v int64) string {
	if v < 0 {
		return ""
	}
	return strconv.FormatInt(v, 10)
}
