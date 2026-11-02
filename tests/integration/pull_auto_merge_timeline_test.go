// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	activities_model "forgejo.org/models/activities"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	pull_model "forgejo.org/models/pull"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/automerge"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullAutoMergeTimeline(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		reviewer := forgery.CreateUser(t, nil)
		stranger := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, nil, &forgery.CreateRepositoryOptions{
			Files:         forgery.FilesInit{},
			Collaborators: map[*user_model.User]perm.AccessMode{reviewer: perm.AccessModeWrite},
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		owner := repo.Owner
		session := loginUser(t, owner.Name)
		reviewerSession := loginUser(t, reviewer.Name)
		strangerSession := loginUser(t, stranger.Name)
		statusCtx := APITestContext{Session: session, Token: getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository), Username: owner.Name, Reponame: repo.Name}

		session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/settings/branches/edit", repo.FullName()), map[string]string{
			"rule_name":             "main",
			"required_approvals":    "1",
			"enable_status_check":   "true",
			"status_check_contexts": "ci",
		}), http.StatusSeeOther)

		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()

		now := time.Now()
		defer timeutil.MockUnset()
		timeutil.MockSet(now)
		passTime := func() {
			now = now.Add(2 * time.Hour)
			timeutil.MockSet(now)
			require.NoError(t, automerge.StartDueScheduledAutoMerges(t.Context()))
		}

		pulls := 0
		newPull := func(t *testing.T) (*issues_model.PullRequest, string) {
			pulls++
			branch := fmt.Sprintf("timeline-%d", pulls)
			testEditFileToNewBranch(t, session, owner.Name, repo.Name, "main", branch, "README.md", branch)
			testPullCreate(t, session, owner.Name, repo.Name, true, "main", branch, branch)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: branch})
			sha, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
			require.NoError(t, err)
			return pr, sha
		}
		index := func(pr *issues_model.PullRequest) string { return strconv.FormatInt(pr.Index, 10) }
		schedule := func(t *testing.T, s *TestSession, pr *issues_model.PullRequest, sha string, after time.Time) {
			testPullMergeForm(t, s, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{
				"do":                        "squash",
				"merge_when_checks_succeed": "true",
				"head_commit_id":            sha,
				"scheduled_after":           after.Format(time.RFC3339),
				"merge_title_field":         "scheduled title",
				"merge_message_field":       "scheduled message",
				"delete_branch_after_merge": "true",
			})
		}
		entries := func(pr *issues_model.PullRequest, typ issues_model.CommentType) []*issues_model.Comment {
			var cs []*issues_model.Comment
			require.NoError(t, db.GetEngine(t.Context()).Where("issue_id = ? AND `type` = ?", pr.IssueID, typ).Asc("id").Find(&cs))
			return cs
		}
		page := func(pr *issues_model.PullRequest) string {
			return session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/pulls/%s", repo.FullName(), index(pr))), http.StatusOK).Body.String()
		}
		changeTime := func(t *testing.T, s *TestSession, pr *issues_model.PullRequest, values map[string]string) {
			s.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/pulls/%s/change_auto_merge_time", repo.FullName(), index(pr)), values), http.StatusSeeOther)
		}

		t.Run("Schedule, change time, merge", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pr, sha := newPull(t)
			after := now.Add(time.Hour)
			schedule(t, session, pr, sha, after)

			scheduled := entries(pr, issues_model.CommentTypePRScheduledToAutoMerge)
			require.Len(t, scheduled, 1)
			assert.Equal(t, owner.ID, scheduled[0].PosterID)
			assert.Equal(t, issues_model.AutoMergeInfo{After: after.Unix()}, scheduled[0].AutoMergeInfo())
			assert.Contains(t, page(pr), "after")

			before := unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
			notifications := unittest.GetCount(t, &activities_model.Notification{})
			actions := unittest.GetCount(t, &activities_model.Action{})

			t.Run("Refused changes", func(t *testing.T) {
				// in the past, empty, give up before the time: nothing changes, no entry
				changeTime(t, session, pr, map[string]string{"scheduled_after": now.Add(-time.Minute).Format(time.RFC3339)})
				changeTime(t, session, pr, map[string]string{"scheduled_after": ""})
				changeTime(t, session, pr, map[string]string{"scheduled_after": "tomorrow"})
				changeTime(t, session, pr, map[string]string{
					"scheduled_after": now.Add(2 * time.Hour).Format(time.RFC3339), "give_up_after": now.Add(time.Hour).Format(time.RFC3339),
				})
				// a user without write access
				strangerSession.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/pulls/%s/change_auto_merge_time", repo.FullName(), index(pr)), map[string]string{
					"scheduled_after": now.Add(3 * time.Hour).Format(time.RFC3339),
				}), NoExpectedStatus)
				assert.Equal(t, before, unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID}))
				assert.Empty(t, entries(pr, issues_model.CommentTypePRAutoMergeTimeChanged))
			})

			t.Run("Changed by the one who scheduled it and by another merger", func(t *testing.T) {
				newAfter := now.Add(2 * time.Hour)
				changeTime(t, session, pr, map[string]string{"scheduled_after": newAfter.Format(time.RFC3339)})
				am := unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
				assert.Equal(t, timeutil.TimeStamp(newAfter.Unix()), am.ScheduledAfterUnix)
				// the pinned head, the merge style, the message and who merges stay
				assert.Equal(t, sha, am.HeadCommitID)
				assert.Equal(t, before.MergeStyle, am.MergeStyle)
				assert.Equal(t, before.Message, am.Message)
				assert.True(t, am.DeleteBranchAfterMerge)
				assert.Equal(t, owner.ID, am.DoerID)

				changed := entries(pr, issues_model.CommentTypePRAutoMergeTimeChanged)
				require.Len(t, changed, 1)
				assert.Equal(t, owner.ID, changed[0].PosterID)
				assert.Equal(t, issues_model.AutoMergeInfo{Old: after.Unix(), New: newAfter.Unix()}, changed[0].AutoMergeInfo())

				newAfter = now.Add(3 * time.Hour)
				changeTime(t, reviewerSession, pr, map[string]string{"scheduled_after": newAfter.Format(time.RFC3339), "give_up_after": now.Add(30 * time.Hour).Format(time.RFC3339)})
				am = unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
				assert.Equal(t, timeutil.TimeStamp(newAfter.Unix()), am.ScheduledAfterUnix)
				assert.Equal(t, timeutil.TimeStamp(now.Add(30*time.Hour).Unix()), am.GiveUpAfterUnix)
				assert.Equal(t, owner.ID, am.DoerID)
				require.Len(t, entries(pr, issues_model.CommentTypePRAutoMergeTimeChanged), 2)

				// the entries are timeline comments only
				assert.Equal(t, notifications, unittest.GetCount(t, &activities_model.Notification{}))
				assert.Equal(t, actions, unittest.GetCount(t, &activities_model.Action{}))

				body := page(pr)
				assert.Contains(t, body, "changed the scheduled merge time of this pull request")
				assert.Contains(t, body, `'textChangeTime': "Change time"`)
			})

			t.Run("Merged by the schedule", func(t *testing.T) {
				testSubmitReview(t, reviewerSession, owner.Name, repo.Name, index(pr), sha, "approve", http.StatusOK)
				doAPICreateCommitStatus(statusCtx, sha, api.CreateStatusOption{State: api.CommitStatusSuccess, Context: "ci"})(t)

				// pending until its time: nothing is recorded
				passTime()
				assert.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
				passTime()
				assert.True(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)

				merged := entries(pr, issues_model.CommentTypePRMergedBySchedule)
				require.Len(t, merged, 1)
				assert.Equal(t, owner.ID, merged[0].PosterID)
				assert.Len(t, entries(pr, issues_model.CommentTypeMergePull), 1)
				assert.Empty(t, entries(pr, issues_model.CommentTypePRAutoMergeSkipped))
				assert.Contains(t, page(pr), "merged this pull request as scheduled")
			})
		})

		t.Run("Skipped is recorded once per reason", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pr, sha := newPull(t)
			testSubmitReview(t, reviewerSession, owner.Name, repo.Name, index(pr), sha, "approve", http.StatusOK)
			schedule(t, session, pr, sha, now.Add(time.Hour))
			evaluate := func() {
				passTime()
				automerge.StartPRCheckAndAutoMerge(t.Context(), unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}))
			}

			// waiting for the time and pending checks: nothing to report
			automerge.StartPRCheckAndAutoMerge(t.Context(), pr)
			evaluate()
			evaluate()
			assert.Empty(t, entries(pr, issues_model.CommentTypePRAutoMergeSkipped))

			// the checks fail: one entry however often it is evaluated
			doAPICreateCommitStatus(statusCtx, sha, api.CreateStatusOption{State: api.CommitStatusFailure, Context: "ci"})(t)
			for range 3 {
				evaluate()
			}
			skipped := entries(pr, issues_model.CommentTypePRAutoMergeSkipped)
			require.Len(t, skipped, 1)
			assert.Equal(t, owner.ID, skipped[0].PosterID)
			assert.Equal(t, issues_model.AutoMergeInfo{Reason: "checks_failed", SHA: sha}, skipped[0].AutoMergeInfo())
			assert.Contains(t, page(pr), "could not merge this pull request as scheduled")
			assert.Contains(t, page(pr), "Required status checks failed.")

			// the API timeline carries the type and its data
			token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadIssue, auth_model.AccessTokenScopeReadRepository)
			var timeline []*api.TimelineComment
			resp := MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/issues/%s/timeline", repo.FullName(), index(pr))).AddTokenAuth(token), http.StatusOK)
			DecodeJSON(t, resp, &timeline)
			found := false
			for _, c := range timeline {
				if c.Type == "pull_auto_merge_skipped" {
					found = true
					assert.JSONEq(t, `{"reason":"checks_failed","sha":"`+sha+`"}`, c.Body)
				}
			}
			assert.True(t, found)

			// a new reason is a new entry, back to the first reason is another one
			testSubmitReview(t, reviewerSession, owner.Name, repo.Name, index(pr), sha, "reject", http.StatusOK)
			doAPICreateCommitStatus(statusCtx, sha, api.CreateStatusOption{State: api.CommitStatusSuccess, Context: "ci"})(t)
			evaluate()
			evaluate()
			skipped = entries(pr, issues_model.CommentTypePRAutoMergeSkipped)
			require.Len(t, skipped, 2)
			assert.Equal(t, "blocked", skipped[1].AutoMergeInfo().Reason)
		})

		t.Run("Head moved", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pr, sha := newPull(t)
			schedule(t, session, pr, sha, now.Add(time.Hour))
			testEditFile(t, session, owner.Name, repo.Name, pr.HeadBranch, "README.md", "moved")
			newSHA, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
			require.NoError(t, err)
			passTime()
			for range 2 {
				automerge.StartPRCheckAndAutoMerge(t.Context(), unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}))
			}
			skipped := entries(pr, issues_model.CommentTypePRAutoMergeSkipped)
			require.Len(t, skipped, 1)
			assert.Equal(t, issues_model.AutoMergeInfo{Reason: "head_moved", SHA: newSHA}, skipped[0].AutoMergeInfo())
		})

		t.Run("Cancel", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pr, sha := newPull(t)
			schedule(t, session, pr, sha, now.Add(time.Hour))
			session.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/%s/pulls/%s/cancel_auto_merge", repo.FullName(), index(pr))), http.StatusSeeOther)
			cancelled := entries(pr, issues_model.CommentTypePRUnScheduledToAutoMerge)
			require.Len(t, cancelled, 1)
			assert.Equal(t, owner.ID, cancelled[0].PosterID)
			assert.Empty(t, cancelled[0].Content)

			// changing the time of a schedule that is gone is refused
			changeTime(t, session, pr, map[string]string{"scheduled_after": now.Add(5 * time.Hour).Format(time.RFC3339)})
			assert.Empty(t, entries(pr, issues_model.CommentTypePRAutoMergeTimeChanged))
		})

		t.Run("Rendering", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pr, _ := newPull(t)
			pr.LoadIssue(t.Context())
			doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: owner.ID})
			for _, c := range []struct {
				typ  issues_model.CommentType
				info issues_model.AutoMergeInfo
				text string
			}{
				{issues_model.CommentTypePRScheduledToAutoMerge, issues_model.AutoMergeInfo{}, "scheduled this pull request to auto merge when all checks succeed"},
				{issues_model.CommentTypePRScheduledToAutoMerge, issues_model.AutoMergeInfo{After: now.Unix()}, "scheduled this pull request to auto merge after"},
				{issues_model.CommentTypePRUnScheduledToAutoMerge, issues_model.AutoMergeInfo{}, "canceled auto merging this pull request"},
				{issues_model.CommentTypePRUnScheduledToAutoMerge, issues_model.AutoMergeInfo{Reason: "permission"}, "may no longer merge this pull request."},
				{issues_model.CommentTypePRUnScheduledToAutoMerge, issues_model.AutoMergeInfo{Reason: "push"}, "New commits were pushed."},
				{issues_model.CommentTypePRUnScheduledToAutoMerge, issues_model.AutoMergeInfo{Reason: "give_up"}, "did not happen before its give-up time."},
				{issues_model.CommentTypePRAutoMergeTimeChanged, issues_model.AutoMergeInfo{Old: now.Unix(), New: now.Add(time.Hour).Unix()}, "changed the scheduled merge time"},
				{issues_model.CommentTypePRMergedBySchedule, issues_model.AutoMergeInfo{}, "merged this pull request as scheduled"},
				{issues_model.CommentTypePRAutoMergeSkipped, issues_model.AutoMergeInfo{Reason: "conflict"}, "The pull request has merge conflicts."},
				{issues_model.CommentTypePRAutoMergeSkipped, issues_model.AutoMergeInfo{Reason: "head_moved"}, "The head of the pull request changed"},
				{issues_model.CommentTypePRAutoMergeSkipped, issues_model.AutoMergeInfo{Reason: "<script>alert(1)</script>"}, "could not merge this pull request as scheduled"},
			} {
				_, err := issues_model.CreateAutoMergeComment(t.Context(), c.typ, pr, doer, c.info)
				require.NoError(t, err)
				assert.Contains(t, page(pr), c.text, "%v %+v", c.typ, c.info)
			}
			// Content is never put into the page, only the typed fields
			assert.NotContains(t, page(pr), "<script>alert(1)</script>")
			assert.NotContains(t, page(pr), "alert(1)")
		})
	})
}

func TestUserTimeZoneSetting(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, user, &forgery.CreateRepositoryOptions{Files: forgery.FilesInit{}})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		session := loginUser(t, user.Name)
		post := func(zone string) {
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/appearance/time_zone", map[string]string{"time_zone": zone}), http.StatusSeeOther)
		}
		stored := func() string {
			zone, err := user_model.GetUserSetting(t.Context(), user.ID, user_model.SettingsKeyTimeZone)
			require.NoError(t, err)
			return zone
		}
		mergeBox := func(pr *issues_model.PullRequest) string {
			return session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/pulls/%d", repo.FullName(), pr.Index)), http.StatusOK).Body.String()
		}

		testEditFileToNewBranch(t, session, user.Name, repo.Name, "main", "tz", "README.md", "tz")
		testPullCreate(t, session, user.Name, repo.Name, true, "main", "tz", "tz")
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: "tz"})

		assert.Contains(t, mergeBox(pr), `'timeZone': ""`)

		post("Europe/Paris")
		assert.Equal(t, "Europe/Paris", stored())
		assert.Contains(t, mergeBox(pr), `'timeZone': "Europe/Paris"`)
		assert.Contains(t, session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/appearance"), http.StatusOK).Body.String(), `value="Europe/Paris"`)

		// invalid names are refused and the stored value stays
		for _, bad := range []string{"Local", "Not/AZone", "../x", fmt.Sprintf("Europe/%065d", 1)} {
			post(bad)
			assert.Equal(t, "Europe/Paris", stored(), bad)
		}

		post("")
		assert.Empty(t, stored())
		assert.Contains(t, mergeBox(pr), `'timeZone': ""`)
	})
}
