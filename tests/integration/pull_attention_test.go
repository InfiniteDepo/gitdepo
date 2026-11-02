// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	repo_module "forgejo.org/modules/repository"
	app_context "forgejo.org/services/context"
	issue_service "forgejo.org/services/issue"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
	files_service "forgejo.org/services/repository/files"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests/forgery"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attentionOf(t *testing.T, issueID int64) []int64 {
	t.Helper()
	// Also called from Eventually/Never conditions, which run in a goroutine that can outlive the
	// subtest: no t.Context() (cancelled by then) and no require (FailNow off the test goroutine).
	ids, err := issues_model.GetPullAttentionUserIDs(db.DefaultContext, issueID)
	assert.NoError(t, err)
	return ids
}

func assertAttention(t *testing.T, issueID int64, users ...*user_model.User) {
	t.Helper()
	want := make([]int64, 0, len(users))
	for _, u := range users {
		want = append(want, u.ID)
	}
	assert.ElementsMatch(t, want, attentionOf(t, issueID))
}

func (c *conversationCheckPR) issue(t *testing.T) *issues_model.Issue {
	t.Helper()
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: c.pr.IssueID})
	require.NoError(t, issue.LoadRepo(t.Context()))
	return issue
}

func (c *conversationCheckPR) review(t *testing.T, session *TestSession, typ string) {
	t.Helper()
	testSubmitReview(t, session, c.repo.OwnerName, c.repo.Name, strconv.FormatInt(c.pr.Index, 10), c.headSHA, typ, http.StatusOK)
}

// changeAttention posts the attention form and returns the flash cookie, which holds any refusal.
func (c *conversationCheckPR) changeAttention(t *testing.T, session *TestSession, action, username, reason string) string {
	t.Helper()
	session.MakeRequest(t, NewRequestWithValues(t, "POST", c.link()+"/attention/"+action, map[string]string{
		"username": username,
		"reason":   reason,
	}), http.StatusSeeOther)
	if flash := session.GetCookie(app_context.CookieNameFlash); flash != nil {
		return flash.Value
	}
	return ""
}

// AC2–AC5: the automatic transitions.
func TestPullAttentionTransitions(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		reviewer := forgery.CreateUser(t, nil)
		approver := forgery.CreateUser(t, nil)
		writer := forgery.CreateUser(t, nil)
		c := prepareConversationCheckPR(t, map[*user_model.User]perm.AccessMode{
			reviewer: perm.AccessModeRead,
			approver: perm.AccessModeRead,
			writer:   perm.AccessModeWrite,
		})
		author := c.repo.Owner
		issue := c.issue(t)
		ctx := t.Context()
		authorSession := loginUser(t, author.Name)
		reviewerSession := loginUser(t, reviewer.Name)

		t.Run("review request adds, removing it removes", func(t *testing.T) {
			_, err := issue_service.ReviewRequest(ctx, issue, author, reviewer, true)
			require.NoError(t, err)
			_, err = issue_service.ReviewRequest(ctx, issue, author, approver, true)
			require.NoError(t, err)
			assertAttention(t, issue.ID, reviewer, approver)
			row := unittest.AssertExistsAndLoadBean(t, &issues_model.PullAttention{IssueID: issue.ID, UserID: reviewer.ID})
			assert.Equal(t, issues_model.AttentionReviewRequested, row.Kind)
			assert.Equal(t, author.ID, row.DoerID)

			_, err = issue_service.ReviewRequest(ctx, issue, author, approver, false)
			require.NoError(t, err)
			assertAttention(t, issue.ID, reviewer)

			// a self-request adds nobody
			_, err = issue_service.ReviewRequest(ctx, issue, approver, approver, true)
			require.NoError(t, err)
			assertAttention(t, issue.ID, reviewer)
		})

		t.Run("a review moves attention to the author", func(t *testing.T) {
			c.review(t, reviewerSession, "reject")
			assertAttention(t, issue.ID, author)
			c.review(t, loginUser(t, approver.Name), "approve")
			assertAttention(t, issue.ID, author)
			row := unittest.AssertExistsAndLoadBean(t, &issues_model.PullAttention{IssueID: issue.ID, UserID: author.ID})
			assert.Equal(t, issues_model.AttentionReviewed, row.Kind)
		})

		t.Run("an author reply moves attention to reviewers who didn't approve", func(t *testing.T) {
			c.topLevelComment(t, authorSession, "fixed it")
			assertAttention(t, issue.ID, reviewer)
		})

		t.Run("a plain comment by a reviewer in the set moves attention to the author", func(t *testing.T) {
			c.topLevelComment(t, reviewerSession, "not quite")
			assertAttention(t, issue.ID, author)
			// a commenter outside the set changes nothing
			c.topLevelComment(t, loginUser(t, writer.Name), "drive-by")
			assertAttention(t, issue.ID, author)
		})

		t.Run("an author push over HTTP moves attention to reviewers", func(t *testing.T) {
			dst := t.TempDir()
			cloneURL, _ := url.Parse(u.String())
			cloneURL.Path = c.repo.FullName() + ".git"
			cloneURL.User = url.UserPassword(author.Name, userPassword)
			doGitClone(dst, cloneURL)(t)
			doGitCheckoutBranch(dst, "feature")(t)
			generateCommitWithNewData(t, 16, dst, author.Email, author.Name, "attention-")
			doGitPushTestRepository(dst, "origin", "feature")(t)
			assert.Eventually(t, func() bool {
				ids := attentionOf(t, issue.ID)
				return len(ids) == 1 && ids[0] == reviewer.ID
			}, 10*time.Second, 100*time.Millisecond)
		})

		t.Run("a push by someone else changes nothing", func(t *testing.T) {
			_, err := files_service.ChangeRepoFiles(git.DefaultContext, c.repo, writer, &files_service.ChangeRepoFilesOptions{
				Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "writer.txt", ContentReader: strings.NewReader("w")}},
				Message:   "by writer",
				OldBranch: "feature",
				NewBranch: "feature",
			})
			require.NoError(t, err)
			assert.Eventually(t, func() bool {
				return unittest.GetCount(t, &issues_model.Comment{IssueID: issue.ID, Type: issues_model.CommentTypePullRequestPush}) >= 3
			}, 10*time.Second, 100*time.Millisecond)
			assertAttention(t, issue.ID, reviewer)
		})

		t.Run("closing empties the set, deleting removes the rows", func(t *testing.T) {
			testIssueClose(t, authorSession, c.repo.OwnerName, c.repo.Name, strconv.FormatInt(c.pr.Index, 10), true)
			assertAttention(t, issue.ID)

			require.NoError(t, issues_model.AddPullAttention(ctx, issue.ID, []int64{reviewer.ID}, author.ID, issues_model.AttentionManual, ""))
			require.NoError(t, issue_service.DeleteIssue(ctx, author, nil, c.issue(t)))
			unittest.AssertNotExistsBean(t, &issues_model.PullAttention{IssueID: issue.ID})
		})

		t.Run("merging empties the set", func(t *testing.T) {
			m := prepareConversationCheckPR(t, nil)
			mIssue := m.issue(t)
			require.NoError(t, issues_model.AddPullAttention(ctx, mIssue.ID, []int64{reviewer.ID}, m.repo.OwnerID, issues_model.AttentionManual, ""))
			testPullMerge(t, loginUser(t, m.repo.OwnerName), m.repo.OwnerName, m.repo.Name, strconv.FormatInt(m.pr.Index, 10), repo_model.MergeStyleMerge, false)
			assertAttention(t, mIssue.ID)
		})

		t.Run("a dismissed reviewer isn't added back by an author reply or push", func(t *testing.T) {
			d := prepareConversationCheckPR(t, map[*user_model.User]perm.AccessMode{reviewer: perm.AccessModeRead})
			dIssue := d.issue(t)
			d.review(t, loginUser(t, reviewer.Name), "reject")
			assertAttention(t, dIssue.ID, d.repo.Owner)
			review, err := issues_model.GetReviewByIssueIDAndUserID(ctx, dIssue.ID, reviewer.ID)
			require.NoError(t, err)
			_, err = pull_service.DismissReview(ctx, review.ID, d.repo.ID, "outdated", d.repo.Owner, true, true)
			require.NoError(t, err)

			d.topLevelComment(t, loginUser(t, d.repo.OwnerName), "reply")
			assertAttention(t, dIssue.ID)

			require.NoError(t, issues_model.AddPullAttention(ctx, dIssue.ID, []int64{d.repo.OwnerID}, d.repo.OwnerID, issues_model.AttentionManual, ""))
			_, err = files_service.ChangeRepoFiles(git.DefaultContext, d.repo, d.repo.Owner, &files_service.ChangeRepoFilesOptions{
				Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "author.txt", ContentReader: strings.NewReader("a")}},
				Message:   "by author",
				OldBranch: "feature",
				NewBranch: "feature",
			})
			require.NoError(t, err)
			// the push takes the author out of the set and adds nobody
			assert.Eventually(t, func() bool { return len(attentionOf(t, dIssue.ID)) == 0 }, 10*time.Second, 100*time.Millisecond)
			assert.Never(t, func() bool { return len(attentionOf(t, dIssue.ID)) != 0 }, time.Second, 100*time.Millisecond)
		})

		t.Run("deleting a repository removes its rows", func(t *testing.T) {
			d := prepareConversationCheckPR(t, nil)
			require.NoError(t, issues_model.AddPullAttention(ctx, d.pr.IssueID, []int64{reviewer.ID}, d.repo.OwnerID, issues_model.AttentionManual, ""))
			require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, d.repo.ID, repo_service.DeleteRepositoryOpts{}))
			unittest.AssertNotExistsBean(t, &issues_model.PullAttention{IssueID: d.pr.IssueID})
		})

		t.Run("deleting a user removes their rows", func(t *testing.T) {
			d := prepareConversationCheckPR(t, nil)
			gone := forgery.CreateUser(t, nil)
			require.NoError(t, issues_model.AddPullAttention(ctx, d.pr.IssueID, []int64{gone.ID}, d.repo.OwnerID, issues_model.AttentionManual, ""))
			require.NoError(t, user_service.DeleteUser(ctx, gone, false))
			unittest.AssertNotExistsBean(t, &issues_model.PullAttention{UserID: gone.ID})
		})
	})
}

// AC6: manual add and remove, and every refusal.
func TestPullAttentionManual(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		reviewer := forgery.CreateUser(t, nil)
		involved := forgery.CreateUser(t, nil)
		other := forgery.CreateUser(t, nil)
		stranger := forgery.CreateUser(t, nil)
		blocker := forgery.CreateUser(t, nil)
		c := prepareConversationCheckPR(t, map[*user_model.User]perm.AccessMode{
			reviewer: perm.AccessModeRead,
			involved: perm.AccessModeRead,
			other:    perm.AccessModeRead,
			blocker:  perm.AccessModeRead,
		})
		author := c.repo.Owner
		issue := c.issue(t)
		ctx := t.Context()
		authorSession := loginUser(t, author.Name)

		t.Run("the author adds anyone with a reason and removes them", func(t *testing.T) {
			assert.NotContains(t, c.changeAttention(t, authorSession, "add", other.Name, "please look at the docs"), "error")
			row := unittest.AssertExistsAndLoadBean(t, &issues_model.PullAttention{IssueID: issue.ID, UserID: other.ID})
			assert.Equal(t, issues_model.AttentionManual, row.Kind)
			assert.Equal(t, "please look at the docs", row.Reason)
			assert.Equal(t, author.ID, row.DoerID)
			c.changeAttention(t, authorSession, "remove", other.Name, "")
			assertAttention(t, issue.ID)
		})

		t.Run("an uninvolved reader can't add", func(t *testing.T) {
			assert.Contains(t, c.changeAttention(t, loginUser(t, stranger.Name), "add", author.Name, ""), "error")
			assertAttention(t, issue.ID)
		})

		t.Run("a reviewer adds only the author or involved users", func(t *testing.T) {
			_, err := issue_service.ReviewRequest(ctx, issue, author, involved, true)
			require.NoError(t, err)
			reviewerSession := loginUser(t, reviewer.Name)
			c.topLevelComment(t, reviewerSession, "a question")
			// a plain commenter is not a reviewer
			assert.Contains(t, c.changeAttention(t, reviewerSession, "add", author.Name, ""), "error")
			c.review(t, reviewerSession, "comment")
			assertAttention(t, issue.ID, involved, author)
			_, err = issues_model.ClearPullAttention(ctx, issue.ID)
			require.NoError(t, err)

			assert.Contains(t, c.changeAttention(t, reviewerSession, "add", other.Name, ""), "error")
			assertAttention(t, issue.ID)
			c.changeAttention(t, reviewerSession, "add", involved.Name, "")
			c.changeAttention(t, reviewerSession, "add", author.Name, "")
			assertAttention(t, issue.ID, involved, author)
		})

		t.Run("anyone removes themselves, others can't remove them", func(t *testing.T) {
			strangerSession := loginUser(t, stranger.Name)
			assert.Contains(t, c.changeAttention(t, strangerSession, "remove", involved.Name, ""), "error")
			// a reviewer may add but not remove others
			assert.Contains(t, c.changeAttention(t, loginUser(t, reviewer.Name), "remove", involved.Name, ""), "error")
			assertAttention(t, issue.ID, involved, author)
			c.changeAttention(t, loginUser(t, involved.Name), "remove", involved.Name, "")
			assertAttention(t, issue.ID, author)
		})

		t.Run("targets", func(t *testing.T) {
			private := forgery.CreateUser(t, nil)
			privateRepo := forgery.CreateRepository(t, nil, &forgery.CreateRepositoryOptions{Files: forgery.FilesInit{}, IsPrivate: true})
			forgery.EnableRepoUnits(t, privateRepo, unit_model.TypeCode, unit_model.TypePullRequests)
			p := &conversationCheckPR{repo: privateRepo, pr: createPullRequest(t, privateRepo.Owner, privateRepo, "feature", "private")}
			// no read access to the private repository
			assert.Contains(t, p.changeAttention(t, loginUser(t, privateRepo.OwnerName), "add", private.Name, ""), "error")
			unittest.AssertNotExistsBean(t, &issues_model.PullAttention{IssueID: p.pr.IssueID})

			inactive := forgery.CreateUser(t, nil)
			inactive.IsActive = false
			require.NoError(t, user_model.UpdateUserCols(ctx, inactive, "is_active"))
			prohibited := forgery.CreateUser(t, nil)
			prohibited.ProhibitLogin = true
			require.NoError(t, user_model.UpdateUserCols(ctx, prohibited, "prohibit_login"))
			// both can read the public repository
			for _, target := range []*user_model.User{inactive, prohibited} {
				assert.Contains(t, c.changeAttention(t, authorSession, "add", target.Name, ""), "error")
			}

			org := forgery.CreateOrganisation(t, author)
			assert.Contains(t, c.changeAttention(t, authorSession, "add", org.Name, ""), "error")

			require.NoError(t, user_service.BlockUser(ctx, blocker.ID, author.ID))
			assert.Contains(t, c.changeAttention(t, authorSession, "add", blocker.Name, ""), "error")
			assert.Contains(t, c.changeAttention(t, authorSession, "add", "no-such-user", ""), "error")
			assertAttention(t, issue.ID, author)
		})

		t.Run("a locked pull request refuses a reader but not a pulls writer", func(t *testing.T) {
			// involved, a reader in the set, may add the reviewer while unlocked
			c.changeAttention(t, authorSession, "add", involved.Name, "")
			_, err := db.GetEngine(ctx).ID(issue.ID).Cols("is_locked").Update(&issues_model.Issue{IsLocked: true})
			require.NoError(t, err)
			assert.Contains(t, c.changeAttention(t, loginUser(t, involved.Name), "add", reviewer.Name, ""), "error")
			assertAttention(t, issue.ID, author, involved)
			assert.NotContains(t, c.changeAttention(t, authorSession, "add", other.Name, ""), "error")
			assertAttention(t, issue.ID, author, involved, other)
			_, err = db.GetEngine(ctx).ID(issue.ID).Cols("is_locked").Update(&issues_model.Issue{IsLocked: false})
			require.NoError(t, err)
			assert.NotContains(t, c.changeAttention(t, loginUser(t, involved.Name), "add", reviewer.Name, ""), "error")
			assertAttention(t, issue.ID, author, involved, other, reviewer)
			for _, u := range []*user_model.User{involved, other, reviewer} {
				c.changeAttention(t, authorSession, "remove", u.Name, "")
			}
			assertAttention(t, issue.ID, author)
		})

		t.Run("a user blocked by the author can't add", func(t *testing.T) {
			require.NoError(t, user_service.BlockUser(ctx, author.ID, reviewer.ID))
			assert.Contains(t, c.changeAttention(t, loginUser(t, reviewer.Name), "add", involved.Name, ""), "error")
			assertAttention(t, issue.ID, author)
		})

		t.Run("a reason over 255 characters is refused", func(t *testing.T) {
			assert.Contains(t, c.changeAttention(t, authorSession, "add", other.Name, strings.Repeat("x", 256)), "error")
			assertAttention(t, issue.ID, author)
		})

		t.Run("an archived repository refuses", func(t *testing.T) {
			_, err := db.GetEngine(ctx).ID(c.repo.ID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: true})
			require.NoError(t, err)
			authorSession.MakeRequest(t, NewRequestWithValues(t, "POST", c.link()+"/attention/add", map[string]string{"username": other.Name}), http.StatusNotFound)
			_, err = db.GetEngine(ctx).ID(c.repo.ID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: false})
			require.NoError(t, err)
			assertAttention(t, issue.ID, author)
		})

		t.Run("a closed pull request refuses", func(t *testing.T) {
			testIssueClose(t, authorSession, c.repo.OwnerName, c.repo.Name, strconv.FormatInt(c.pr.Index, 10), true)
			assert.Contains(t, c.changeAttention(t, authorSession, "add", other.Name, ""), "error")
			assertAttention(t, issue.ID)
		})
	})
}

// AC7–AC8: the sidebar, the list marker, the dashboard filter and the search filter.
func TestPullAttentionViews(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		member := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, nil, &forgery.CreateRepositoryOptions{
			Files:         forgery.FilesInit{},
			IsPrivate:     true,
			Collaborators: map[*user_model.User]perm.AccessMode{member: perm.AccessModeRead},
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		pr := createPullRequest(t, repo.Owner, repo, "feature", "waiting on member")
		c := &conversationCheckPR{repo: repo, pr: pr}
		other := createPullRequest(t, repo.Owner, repo, "other", "waiting on nobody")
		ctx := t.Context()
		ownerSession := loginUser(t, repo.OwnerName)
		memberSession := loginUser(t, member.Name)
		prLink := fmt.Sprintf("/%s/pulls/%d", repo.FullName(), pr.Index)
		otherLink := fmt.Sprintf("/%s/pulls/%d", repo.FullName(), other.Index)

		c.changeAttention(t, ownerSession, "add", member.Name, "your area")
		candidates := func(section *goquery.Selection) []string {
			var names []string
			section.Find(`form[action$="/attention/add"] select[name="username"] option[value!=""]`).Each(func(_ int, s *goquery.Selection) {
				names = append(names, s.AttrOr("value", ""))
			})
			return names
		}

		t.Run("sidebar", func(t *testing.T) {
			doc := NewHTMLParser(t, memberSession.MakeRequest(t, NewRequest(t, "GET", prLink), http.StatusOK).Body)
			section := doc.Find("#pull-attention")
			assert.Contains(t, section.Text(), member.Name)
			tooltip, _ := section.Find("[data-tooltip-content]").First().Attr("data-tooltip-content")
			assert.Equal(t, "Added by "+repo.OwnerName+": your area", tooltip)
			// a member of the set may remove themselves and pick the author, but nobody already in the set
			assert.Equal(t, 1, section.Find(`form[action$="/attention/remove"]`).Length())
			assert.Equal(t, []string{repo.OwnerName}, candidates(section))
			c.changeAttention(t, ownerSession, "add", repo.OwnerName, "")
			doc = NewHTMLParser(t, memberSession.MakeRequest(t, NewRequest(t, "GET", prLink), http.StatusOK).Body)
			assert.Equal(t, 1, doc.Find(`#pull-attention form[action$="/attention/remove"]`).Length())
			// nobody left to pick: no add form
			assert.Equal(t, 0, doc.Find(`#pull-attention form[action$="/attention/add"]`).Length())
			ownerDoc := NewHTMLParser(t, ownerSession.MakeRequest(t, NewRequest(t, "GET", prLink), http.StatusOK).Body)
			assert.Equal(t, 2, ownerDoc.Find(`#pull-attention form[action$="/attention/remove"]`).Length())
			assert.NotContains(t, candidates(ownerDoc.Find("#pull-attention")), member.Name)
			assert.NotContains(t, candidates(ownerDoc.Find("#pull-attention")), repo.OwnerName)
			c.changeAttention(t, ownerSession, "remove", repo.OwnerName, "")
			// an empty set
			empty := NewHTMLParser(t, ownerSession.MakeRequest(t, NewRequest(t, "GET", otherLink), http.StatusOK).Body)
			assert.Contains(t, empty.Find("#pull-attention").Text(), "Not waiting on anyone")
		})

		t.Run("list marker", func(t *testing.T) {
			doc := NewHTMLParser(t, memberSession.MakeRequest(t, NewRequest(t, "GET", "/"+repo.FullName()+"/pulls"), http.StatusOK).Body)
			markers := doc.Find(".pull-attention-marker")
			assert.Equal(t, 1, markers.Length())
			assert.Contains(t, markers.Find("a").AttrOr("href", ""), member.Name)
			assert.Equal(t, "Waiting on: "+member.Name, markers.AttrOr("data-tooltip-content", ""))
		})

		listed := func(t *testing.T, session *TestSession, link string) []string {
			t.Helper()
			var hrefs []string
			NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body).Find("#issue-list a.issue-title").Each(func(_ int, s *goquery.Selection) {
				hrefs = append(hrefs, s.AttrOr("href", ""))
			})
			return hrefs
		}

		t.Run("Waiting on me and its count", func(t *testing.T) {
			resp := memberSession.MakeRequest(t, NewRequest(t, "GET", "/pulls?type=attention"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			assert.Equal(t, "1", strings.TrimSpace(doc.Find(`a[href^="?type=attention"] .label`).Text()))
			assert.Equal(t, []string{prLink}, listed(t, memberSession, "/pulls?type=attention"))
			assert.Empty(t, listed(t, ownerSession, "/pulls?type=attention"))
		})

		t.Run("attention: in search", func(t *testing.T) {
			list := "/" + repo.FullName() + "/pulls?q="
			assert.Equal(t, []string{prLink}, listed(t, memberSession, list+url.QueryEscape("attention:@me")))
			assert.Equal(t, []string{prLink}, listed(t, ownerSession, list+url.QueryEscape("attention:"+member.Name)))
			assert.Empty(t, listed(t, ownerSession, list+url.QueryEscape("attention:@me")))
			assert.Contains(t, listed(t, ownerSession, list), otherLink)
		})

		t.Run("revoked access hides the private pull request", func(t *testing.T) {
			require.NoError(t, repo_module.DeleteCollaboration(ctx, repo, member.ID))
			assert.Empty(t, listed(t, memberSession, "/pulls?type=attention"))
		})

		t.Run("a missing poster or member doesn't break the page", func(t *testing.T) {
			reviewer := forgery.CreateUser(t, nil)
			g := prepareConversationCheckPR(t, map[*user_model.User]perm.AccessMode{reviewer: perm.AccessModeRead})
			_, err := db.GetEngine(ctx).Exec("UPDATE issue SET poster_id = ? WHERE id = ?", 99999999, g.pr.IssueID)
			require.NoError(t, err)
			require.NoError(t, db.Insert(ctx, &issues_model.PullAttention{IssueID: g.pr.IssueID, UserID: 99999998, DoerID: 99999997}))
			g.review(t, loginUser(t, reviewer.Name), "comment")
			assert.ElementsMatch(t, []int64{99999998}, attentionOf(t, g.pr.IssueID))
			loginUser(t, g.repo.OwnerName).MakeRequest(t, NewRequest(t, "GET", g.link()), http.StatusOK)
			loginUser(t, g.repo.OwnerName).MakeRequest(t, NewRequest(t, "GET", "/"+g.repo.FullName()+"/pulls"), http.StatusOK)
		})
	})
}
