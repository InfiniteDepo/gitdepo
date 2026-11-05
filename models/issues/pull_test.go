// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues_test

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullRequest_LoadAttributes(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	require.NoError(t, pr.LoadAttributes(db.DefaultContext))
	assert.NotNil(t, pr.Merger)
	assert.Equal(t, pr.MergerID, pr.Merger.ID)
}

func TestPullRequest_LoadIssue(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	require.NoError(t, pr.LoadIssue(db.DefaultContext))
	assert.NotNil(t, pr.Issue)
	assert.Equal(t, int64(2), pr.Issue.ID)
	require.NoError(t, pr.LoadIssue(db.DefaultContext))
	assert.NotNil(t, pr.Issue)
	assert.Equal(t, int64(2), pr.Issue.ID)
}

func TestPullRequest_LoadBaseRepo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	require.NoError(t, pr.LoadBaseRepo(db.DefaultContext))
	assert.NotNil(t, pr.BaseRepo)
	assert.Equal(t, pr.BaseRepoID, pr.BaseRepo.ID)
	require.NoError(t, pr.LoadBaseRepo(db.DefaultContext))
	assert.NotNil(t, pr.BaseRepo)
	assert.Equal(t, pr.BaseRepoID, pr.BaseRepo.ID)
}

func TestPullRequest_LoadHeadRepo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	require.NoError(t, pr.LoadHeadRepo(db.DefaultContext))
	assert.NotNil(t, pr.HeadRepo)
	assert.Equal(t, pr.HeadRepoID, pr.HeadRepo.ID)
}

// TODO TestMerge

// TODO TestNewPullRequest

func TestPullRequestsNewest(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	prs, count, err := issues_model.PullRequests(db.DefaultContext, 1, &issues_model.PullRequestsOptions{
		ListOptions: db.ListOptions{
			Page: 1,
		},
		State:    "open",
		SortType: "newest",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 3, count)
	if assert.Len(t, prs, 3) {
		assert.EqualValues(t, 5, prs[0].ID)
		assert.EqualValues(t, 2, prs[1].ID)
		assert.EqualValues(t, 1, prs[2].ID)
	}
}

func TestPullRequests_Closed_RecentSortType(t *testing.T) {
	// Issue ID | Closed At.  | Updated At
	//    2     | 1707270001  | 1707270001
	//    3     | 1707271000  | 1707279999
	//    11    | 1707279999  | 1707275555
	tests := []struct {
		sortType             string
		expectedIssueIDOrder []int64
	}{
		{"recentupdate", []int64{3, 11, 2}},
		{"recentclose", []int64{11, 3, 2}},
	}

	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.Exec(db.DefaultContext, "UPDATE issue SET closed_unix = 1707270001, updated_unix = 1707270001, is_closed = true WHERE id = 2")
	require.NoError(t, err)
	_, err = db.Exec(db.DefaultContext, "UPDATE issue SET closed_unix = 1707271000, updated_unix = 1707279999, is_closed = true WHERE id = 3")
	require.NoError(t, err)
	_, err = db.Exec(db.DefaultContext, "UPDATE issue SET closed_unix = 1707279999, updated_unix = 1707275555, is_closed = true WHERE id = 11")
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.sortType, func(t *testing.T) {
			prs, _, err := issues_model.PullRequests(db.DefaultContext, 1, &issues_model.PullRequestsOptions{
				ListOptions: db.ListOptions{
					Page: 1,
				},
				State:    "closed",
				SortType: test.sortType,
			})
			require.NoError(t, err)

			if assert.Len(t, prs, len(test.expectedIssueIDOrder)) {
				for i := range test.expectedIssueIDOrder {
					assert.Equal(t, test.expectedIssueIDOrder[i], prs[i].IssueID)
				}
			}
		})
	}
}

func TestLoadRequestedReviewers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	pull := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	require.NoError(t, pull.LoadIssue(db.DefaultContext))
	issue := pull.Issue
	require.NoError(t, issue.LoadRepo(db.DefaultContext))
	assert.Empty(t, pull.RequestedReviewers)

	user1, err := user_model.GetUserByID(db.DefaultContext, 1)
	require.NoError(t, err)

	comment, err := issues_model.AddReviewRequest(db.DefaultContext, issue, user1, &user_model.User{})
	require.NoError(t, err)
	assert.NotNil(t, comment)

	require.NoError(t, pull.LoadRequestedReviewers(db.DefaultContext))
	assert.Len(t, pull.RequestedReviewers, 1)

	comment, err = issues_model.RemoveReviewRequest(db.DefaultContext, issue, user1, &user_model.User{})
	require.NoError(t, err)
	assert.NotNil(t, comment)

	pull.RequestedReviewers = nil
	require.NoError(t, pull.LoadRequestedReviewers(db.DefaultContext))
	assert.Empty(t, pull.RequestedReviewers)
}

func TestPullRequestsOldest(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	prs, count, err := issues_model.PullRequests(db.DefaultContext, 1, &issues_model.PullRequestsOptions{
		ListOptions: db.ListOptions{
			Page: 1,
		},
		State:    "open",
		SortType: "oldest",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 3, count)
	if assert.Len(t, prs, 3) {
		assert.EqualValues(t, 1, prs[0].ID)
		assert.EqualValues(t, 2, prs[1].ID)
		assert.EqualValues(t, 5, prs[2].ID)
	}
}

func TestGetUnmergedPullRequest(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr, err := issues_model.GetUnmergedPullRequest(db.DefaultContext, 1, 1, "branch2", "master", issues_model.PullRequestFlowGithub)
	require.NoError(t, err)
	assert.Equal(t, int64(2), pr.ID)

	prList, err := issues_model.GetUnmergedPullRequestsAnyTarget(db.DefaultContext, 1, 1, "branch2", issues_model.PullRequestFlowGithub)
	require.NoError(t, err)
	assert.Len(t, prList, 1)
	assert.Equal(t, int64(2), prList[0].ID)

	_, err = issues_model.GetUnmergedPullRequest(db.DefaultContext, 1, 9223372036854775807, "branch1", "master", issues_model.PullRequestFlowGithub)
	require.Error(t, err)
	assert.True(t, issues_model.IsErrPullRequestNotExist(err))
}

func TestHasUnmergedPullRequestsByHeadInfo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	exist, err := issues_model.HasUnmergedPullRequestsByHeadInfo(db.DefaultContext, 1, "branch2")
	require.NoError(t, err)
	assert.True(t, exist)

	exist, err = issues_model.HasUnmergedPullRequestsByHeadInfo(db.DefaultContext, 1, "not_exist_branch")
	require.NoError(t, err)
	assert.False(t, exist)
}

func TestGetUnmergedPullRequestsByHeadInfo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	prs, err := issues_model.GetUnmergedPullRequestsByHeadInfo(db.DefaultContext, 1, "branch2")
	require.NoError(t, err)
	assert.Len(t, prs, 1)
	for _, pr := range prs {
		assert.Equal(t, int64(1), pr.HeadRepoID)
		assert.Equal(t, "branch2", pr.HeadBranch)
	}
}

func TestGetUnmergedPullRequestsByHeadInfoMax(t *testing.T) {
	defer unittest.OverrideFixtures("models/fixtures/TestGetUnmergedPullRequestsByHeadInfoMax")()
	require.NoError(t, unittest.PrepareTestDatabase())

	repoID := int64(1)
	olderThan := int64(0)

	// for NULL created field the olderThan condition is ignored
	prs, err := issues_model.GetUnmergedPullRequestsByHeadInfoMax(db.DefaultContext, repoID, olderThan, "branch2")
	require.NoError(t, err)
	assert.Equal(t, int64(1), prs[0].HeadRepoID)

	// test for when the created field is set
	branch := "branchmax"
	prs, err = issues_model.GetUnmergedPullRequestsByHeadInfoMax(db.DefaultContext, repoID, olderThan, branch)
	require.NoError(t, err)
	assert.Empty(t, prs)
	olderThan = time.Now().UnixNano()
	require.NoError(t, err)
	prs, err = issues_model.GetUnmergedPullRequestsByHeadInfoMax(db.DefaultContext, repoID, olderThan, branch)
	require.NoError(t, err)
	assert.Len(t, prs, 1)
	for _, pr := range prs {
		assert.Equal(t, int64(1), pr.HeadRepoID)
		assert.Equal(t, branch, pr.HeadBranch)
	}
	pr := prs[0]

	for _, testCase := range []struct {
		table   string
		field   string
		id      int64
		match   any
		nomatch any
	}{
		{
			table:   "issue",
			field:   "is_closed",
			id:      pr.IssueID,
			match:   false,
			nomatch: true,
		},
		{
			table:   "pull_request",
			field:   "flow",
			id:      pr.ID,
			match:   issues_model.PullRequestFlowGithub,
			nomatch: issues_model.PullRequestFlowAGit,
		},
		{
			table:   "pull_request",
			field:   "head_repo_id",
			id:      pr.ID,
			match:   pr.HeadRepoID,
			nomatch: 0,
		},
		{
			table:   "pull_request",
			field:   "head_branch",
			id:      pr.ID,
			match:   pr.HeadBranch,
			nomatch: "something else",
		},
		{
			table:   "pull_request",
			field:   "has_merged",
			id:      pr.ID,
			match:   false,
			nomatch: true,
		},
	} {
		t.Run(testCase.field, func(t *testing.T) {
			update := fmt.Sprintf("UPDATE `%s` SET `%s` = ? WHERE `id` = ?", testCase.table, testCase.field)

			// expect no match
			_, err = db.GetEngine(db.DefaultContext).Exec(update, testCase.nomatch, testCase.id)
			require.NoError(t, err)
			prs, err = issues_model.GetUnmergedPullRequestsByHeadInfoMax(db.DefaultContext, repoID, olderThan, branch)
			require.NoError(t, err)
			assert.Empty(t, prs)

			// expect one match
			_, err = db.GetEngine(db.DefaultContext).Exec(update, testCase.match, testCase.id)
			require.NoError(t, err)
			prs, err = issues_model.GetUnmergedPullRequestsByHeadInfoMax(db.DefaultContext, repoID, olderThan, branch)
			require.NoError(t, err)
			assert.Len(t, prs, 1)

			// identical to the known PR
			assert.Equal(t, pr.ID, prs[0].ID)
		})
	}
}

func TestGetUnmergedPullRequestsByBaseInfo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	prs, err := issues_model.GetUnmergedPullRequestsByBaseInfo(db.DefaultContext, 1, "master")
	require.NoError(t, err)
	assert.Len(t, prs, 1)
	pr := prs[0]
	assert.Equal(t, int64(2), pr.ID)
	assert.Equal(t, int64(1), pr.BaseRepoID)
	assert.Equal(t, "master", pr.BaseBranch)
}

func TestGetPullRequestByIndex(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr, err := issues_model.GetPullRequestByIndex(db.DefaultContext, 1, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pr.BaseRepoID)
	assert.Equal(t, int64(2), pr.Index)

	_, err = issues_model.GetPullRequestByIndex(db.DefaultContext, 9223372036854775807, 9223372036854775807)
	require.Error(t, err)
	assert.True(t, issues_model.IsErrPullRequestNotExist(err))

	_, err = issues_model.GetPullRequestByIndex(db.DefaultContext, 1, 0)
	require.Error(t, err)
	assert.True(t, issues_model.IsErrPullRequestNotExist(err))
}

func TestGetPullRequestByID(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr, err := issues_model.GetPullRequestByID(db.DefaultContext, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pr.ID)
	assert.Equal(t, int64(2), pr.IssueID)

	_, err = issues_model.GetPullRequestByID(db.DefaultContext, 9223372036854775807)
	require.Error(t, err)
	assert.True(t, issues_model.IsErrPullRequestNotExist(err))
}

func TestGetPullRequestByIssueID(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr, err := issues_model.GetPullRequestByIssueID(db.DefaultContext, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(2), pr.IssueID)

	_, err = issues_model.GetPullRequestByIssueID(db.DefaultContext, 9223372036854775807)
	require.Error(t, err)
	assert.True(t, issues_model.IsErrPullRequestNotExist(err))
}

func TestPullRequest_Update(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	pr.BaseBranch = "baseBranch"
	pr.HeadBranch = "headBranch"
	pr.Update(db.DefaultContext)

	pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	assert.Equal(t, "baseBranch", pr.BaseBranch)
	assert.Equal(t, "headBranch", pr.HeadBranch)
	unittest.CheckConsistencyFor(t, pr)
}

func TestPullRequest_UpdateCols(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := &issues_model.PullRequest{
		ID:         1,
		BaseBranch: "baseBranch",
		HeadBranch: "headBranch",
	}
	require.NoError(t, pr.UpdateCols(db.DefaultContext, "head_branch"))

	pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	assert.Equal(t, "master", pr.BaseBranch)
	assert.Equal(t, "headBranch", pr.HeadBranch)
	unittest.CheckConsistencyFor(t, pr)
}

func TestPullRequestList_LoadAttributes(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	prs := []*issues_model.PullRequest{
		unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1}),
		unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2}),
	}
	require.NoError(t, issues_model.PullRequestList(prs).LoadAttributes(db.DefaultContext))
	for _, pr := range prs {
		assert.NotNil(t, pr.Issue)
		assert.Equal(t, pr.IssueID, pr.Issue.ID)
	}

	require.NoError(t, issues_model.PullRequestList([]*issues_model.PullRequest{}).LoadAttributes(db.DefaultContext))
}

// TODO TestAddTestPullRequestTask

func TestPullRequest_IsWorkInProgress(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	pr.LoadIssue(db.DefaultContext)

	assert.False(t, pr.IsWorkInProgress(db.DefaultContext))

	pr.Issue.Title = "WIP: " + pr.Issue.Title
	assert.True(t, pr.IsWorkInProgress(db.DefaultContext))

	pr.Issue.Title = "[wip]: " + pr.Issue.Title
	assert.True(t, pr.IsWorkInProgress(db.DefaultContext))
}

func TestPullRequest_GetWorkInProgressPrefixWorkInProgress(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	pr.LoadIssue(db.DefaultContext)

	assert.Empty(t, pr.GetWorkInProgressPrefix(db.DefaultContext))

	original := pr.Issue.Title
	pr.Issue.Title = "WIP: " + original
	assert.Equal(t, "WIP:", pr.GetWorkInProgressPrefix(db.DefaultContext))

	pr.Issue.Title = "[wip] " + original
	assert.Equal(t, "[wip]", pr.GetWorkInProgressPrefix(db.DefaultContext))
}

func TestParseCodeOwnersLine(t *testing.T) {
	type CodeOwnerTest struct {
		Line   string
		Tokens []string
	}

	given := []CodeOwnerTest{
		{Line: "", Tokens: nil},
		{Line: "# comment", Tokens: []string{}},
		{Line: "!.* @user1 @org1/team1", Tokens: []string{"!.*", "@user1", "@org1/team1"}},
		{Line: `.*\\.js @user2 #comment`, Tokens: []string{`.*\.js`, "@user2"}},
		{Line: `docs/(aws|google|azure)/[^/]*\\.(md|txt) @org3 @org2/team2`, Tokens: []string{`docs/(aws|google|azure)/[^/]*\.(md|txt)`, "@org3", "@org2/team2"}},
		{Line: `\#path @org3`, Tokens: []string{`#path`, "@org3"}},
		{Line: `path\ with\ spaces/ @org3`, Tokens: []string{`path with spaces/`, "@org3"}},
	}

	for _, g := range given {
		tokens := issues_model.TokenizeCodeOwnersLine(g.Line)
		assert.Equal(t, g.Tokens, tokens, "Codeowners tokenizer failed")
	}
}

func TestGetApprovers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 5})
	// Official reviews are already deduplicated. Allow unofficial reviews
	// to assert that there are no duplicated approvers.
	setting.Repository.PullRequest.DefaultMergeMessageOfficialApproversOnly = false
	approvers := pr.GetApprovers(db.DefaultContext)
	expected := "Reviewed-by: User Five <user5@example.com>\nReviewed-by: Org Six <org6@example.com>\n"
	assert.Equal(t, expected, approvers)
}

func TestGetPullRequestByMergedCommit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr, err := issues_model.GetPullRequestByMergedCommit(db.DefaultContext, 1, "1a8823cd1a9549fde083f992f6b9b87a7ab74fb3")
	require.NoError(t, err)
	assert.EqualValues(t, 1, pr.ID)

	_, err = issues_model.GetPullRequestByMergedCommit(db.DefaultContext, 0, "1a8823cd1a9549fde083f992f6b9b87a7ab74fb3")
	require.ErrorAs(t, err, &issues_model.ErrPullRequestNotExist{})
	_, err = issues_model.GetPullRequestByMergedCommit(db.DefaultContext, 1, "")
	require.ErrorAs(t, err, &issues_model.ErrPullRequestNotExist{})
}

func TestPullRequest_IsForkPullRequest(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	t.Run("FlowGithub from a fork", func(t *testing.T) {
		pr := &issues_model.PullRequest{
			Flow:       issues_model.PullRequestFlowGithub,
			HeadRepoID: 111,
			BaseRepoID: 222,
		}
		assert.True(t, pr.IsForkPullRequest())
	})

	t.Run("FlowGithub from the same repository", func(t *testing.T) {
		pr := &issues_model.PullRequest{
			Flow:       issues_model.PullRequestFlowGithub,
			HeadRepoID: 111,
			BaseRepoID: 111,
		}
		assert.False(t, pr.IsForkPullRequest())
	})

	t.Run("PullRequestFlowAGit", func(t *testing.T) {
		pr := &issues_model.PullRequest{
			Flow: issues_model.PullRequestFlowAGit,
		}
		assert.True(t, pr.IsForkPullRequest())
	})

	t.Run("Other", func(t *testing.T) {
		unknown := issues_model.PullRequestFlow(4854)
		pr := &issues_model.PullRequest{
			Flow: unknown,
		}
		assert.True(t, pr.IsForkPullRequest())
	})
}

func TestMigrate_InsertPullRequests(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	reponame := "repo1"
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{Name: reponame})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})

	i := &issues_model.Issue{
		RepoID:   repo.ID,
		Repo:     repo,
		Title:    "title1",
		Content:  "issuecontent1",
		IsPull:   true,
		PosterID: owner.ID,
		Poster:   owner,
	}

	p := &issues_model.PullRequest{
		Issue:      i,
		BaseRepoID: repo.ID,
	}

	err := issues_model.InsertPullRequests(db.DefaultContext, p)
	require.NoError(t, err)

	_ = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: i.ID})

	unittest.CheckConsistencyFor(t, &issues_model.Issue{}, &issues_model.PullRequest{})
}

func TestFindUnresolvedConversations(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: 2})
	pb := &git_model.ProtectedBranch{}

	ids := func(ignoreOutdated bool) []int64 {
		t.Helper()
		comments, err := issues_model.FindUnresolvedConversations(db.DefaultContext, 2, ignoreOutdated)
		require.NoError(t, err)
		var ids []int64
		for _, c := range comments {
			ids = append(ids, c.ID)
		}
		return ids
	}

	// comment 4 is in a pending review and doesn't count; comments 5 and 6 form one
	// conversation, linked by its first comment
	assert.Equal(t, []int64{5}, ids(false))
	assert.Equal(t, []int64{5}, ids(true))

	// the option is off: no block
	assert.False(t, issues_model.MergeBlockedByUnresolvedConversations(db.DefaultContext, pb, pr))
	pb.BlockOnUnresolvedConversations = true
	assert.True(t, issues_model.MergeBlockedByUnresolvedConversations(db.DefaultContext, pb, pr))

	// an outdated conversation counts unless outdated conversations are ignored
	_, err := db.GetEngine(db.DefaultContext).ID(5).Cols("invalidated").Update(&issues_model.Comment{Invalidated: true})
	require.NoError(t, err)
	assert.Equal(t, []int64{5}, ids(false))
	assert.Empty(t, ids(true))
	pb.IgnoreOutdatedConversations = true
	assert.False(t, issues_model.MergeBlockedByUnresolvedConversations(db.DefaultContext, pb, pr))
	pb.IgnoreOutdatedConversations = false

	// a resolved comment resolves the conversation
	_, err = db.GetEngine(db.DefaultContext).ID(6).Cols("resolve_doer_id").Update(&issues_model.Comment{ResolveDoerID: 1})
	require.NoError(t, err)
	assert.Empty(t, ids(false))
	assert.False(t, issues_model.MergeBlockedByUnresolvedConversations(db.DefaultContext, pb, pr))

	// once the pending review is submitted, its conversation counts
	_, err = db.GetEngine(db.DefaultContext).ID(4).Cols("type").Update(&issues_model.Review{Type: issues_model.ReviewTypeComment})
	require.NoError(t, err)
	assert.Equal(t, []int64{4}, ids(false))
}

// A pull request whose head repository is in the trash is shown like one whose head repository was deleted.
func TestPullRequest_LoadHeadRepoTrashed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(t.Context()).Exec("UPDATE `repository` SET trashed_unix = 1 WHERE id = 11")
	require.NoError(t, err)

	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 3})
	require.Equal(t, int64(11), pr.HeadRepoID)
	require.NoError(t, pr.LoadHeadRepo(t.Context()))
	assert.Nil(t, pr.HeadRepo)
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	assert.EqualValues(t, 10, pr.BaseRepo.ID)
}

func parseCodeOwnersText(t *testing.T, text string) *issues_model.CodeOwners {
	require.NoError(t, unittest.PrepareTestDatabase())
	return issues_model.ParseCodeOwners(t.Context(), 0, io.NopCloser(strings.NewReader(text)), false)
}

func TestParseCodeOwnersSections(t *testing.T) {
	owners := parseCodeOwnersText(t, strings.Join([]string{
		".* @user2",
		"[Docs][2] @user4 # default owners",
		"docs/.*",
		"docs/x/.* @user2",
		"^[Optional][9]",
		"opt/.* @user2",
		"[docs]", // the same section again, case-insensitively
		"more/.*",
		"[Docs][3]",
		"",
	}, "\n"))
	assert.Zero(t, owners.ErrorLine)
	require.Len(t, owners.Rules, 4, "headers are no patterns")
	assert.Equal(t, 1, owners.Rules[0].Section.Required, "before any header: the default section")
	assert.Equal(t, "Docs", owners.Rules[1].Section.Name)
	assert.Equal(t, 3, owners.Rules[1].Section.Required, "duplicate sections merge, the larger number counts")
	assert.Same(t, owners.Rules[1].Section, owners.Rules[2].Section)
	require.Len(t, owners.Rules[1].Users, 1)
	assert.EqualValues(t, 4, owners.Rules[1].Users[0].ID, "a line without owners takes the default owners")
	assert.True(t, owners.Rules[3].Section.Optional)
	assert.Contains(t, owners.Warnings, "Line: 8: incorrect format", "the default owners belong to their header, not to the merged section")
	assert.Contains(t, strings.Join(owners.Warnings, "\n"), "repeated with another number of approvals")
}

func TestParseCodeOwnersHeaderIsNoPattern(t *testing.T) {
	owners := parseCodeOwnersText(t, "[Docs] @user2\ndocs/.* @user2\n")
	require.Len(t, owners.Rules, 1)
	assert.False(t, owners.Rules[0].Rule.MatchString("D"), "[Docs] used to be a character class")
}

func TestParseCodeOwnersMalformedHeaders(t *testing.T) {
	for _, header := range []string{
		"[Docs", "[Docs][0]", "[Docs][x]", "[Docs][-1]", "[Docs][+1]", "[]", "[ ]", "[Docs][2", "[Docs][1001]",
		"[Docs][99999999999999999999999]", "[Docs]x", "[Docs][2]x", "^[Docs", "^[]", "[Docs][]", "[Docs] [2]",
	} {
		owners := parseCodeOwnersText(t, ".* @user2\n"+header+" @user2\n")
		assert.Equal(t, 2, owners.ErrorLine, header)
		assert.Contains(t, strings.Join(owners.Warnings, "\n"), "Line: 2: incorrect section header", header)
	}
	for _, header := range []string{"[Docs][1000]", "[Docs][1]", "^[Docs][0]", "[Docs]\t@user2", "[Two words][2]", "[Docs] # comment"} {
		owners := parseCodeOwnersText(t, header+"\n")
		if header == "^[Docs][0]" {
			assert.NotZero(t, owners.ErrorLine, "the number of an optional section is checked too: "+header)
			continue
		}
		assert.Zero(t, owners.ErrorLine, header)
	}
}

// The file is bounded: past the caps, or with a line the scanner can't read, it is malformed (every rule fails closed).
func TestParseCodeOwnersBounds(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= issues_model.MaxCodeOwnerSections; i++ {
		fmt.Fprintf(&sb, "[S%d]\n", i)
	}
	owners := parseCodeOwnersText(t, sb.String())
	assert.Equal(t, issues_model.MaxCodeOwnerSections+1, owners.ErrorLine, "the section over the cap")
	assert.Contains(t, strings.Join(owners.Warnings, "\n"), "more than 200 sections")
	assert.Zero(t, parseCodeOwnersText(t, strings.TrimSuffix(sb.String(), fmt.Sprintf("[S%d]\n", issues_model.MaxCodeOwnerSections))).ErrorLine, "the cap itself is fine")

	sb.Reset()
	for i := 0; i <= issues_model.MaxCodeOwnerLines; i++ {
		fmt.Fprintf(&sb, "f%d/.* @user2\n", i)
	}
	owners = parseCodeOwnersText(t, sb.String())
	assert.Equal(t, issues_model.MaxCodeOwnerLines+1, owners.ErrorLine, "the pattern line over the cap")
	assert.Len(t, owners.Rules, issues_model.MaxCodeOwnerLines)

	owners = parseCodeOwnersText(t, ".* @user2\n"+strings.Repeat("x", 70*1024)+" @user2\n.* @user4\n")
	assert.Equal(t, 2, owners.ErrorLine, "a line over 64 KiB stops the parse, which is an error")
	assert.Len(t, owners.Rules, 1)
}

func TestParseCodeOwnersNoHeaders(t *testing.T) {
	owners := parseCodeOwnersText(t, ".* @user2\ndocs/.*\n!x/.* @user4 @nobody\n")
	require.Len(t, owners.Rules, 2)
	assert.Zero(t, owners.ErrorLine)
	assert.Equal(t, []string{"Line: 2: incorrect format", "Line: 3: incorrect codeowner user: nobody"}, owners.Warnings)
	assert.True(t, owners.Rules[1].Negative)
}

// A team resolves only within the organization that owns the repository, so a team of another organization is as
// unknown as one that doesn't exist or lives in an organization that doesn't: the same line, the same warning.
func TestParseCodeOwnersForeignTeamLooksMissing(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	parse := func(ownerID int64, text string) *issues_model.CodeOwners {
		return issues_model.ParseCodeOwners(t.Context(), ownerID, io.NopCloser(strings.NewReader(text)), false)
	}
	// user2 owns the repository: org3/team1 exists, org3/ghost doesn't, nosuchorg doesn't either
	for _, team := range []string{"org3/team1", "org3/ghost", "nosuchorg/team1"} {
		owners := parse(2, "a/.* @user2 @"+team+"\n")
		require.Len(t, owners.Rules, 1, team)
		assert.Empty(t, owners.Rules[0].Teams, team)
		assert.Equal(t, []string{"Line: 1: incorrect codeowner team: " + team}, owners.Warnings, team)
	}
	// org3 owns it: its own team resolves, a missing one is warned about the same way
	owners := parse(3, "a/.* @user2 @org3/team1 @org3/ghost @org2/team1\n")
	require.Len(t, owners.Rules, 1)
	require.Len(t, owners.Rules[0].Teams, 1)
	assert.EqualValues(t, 2, owners.Rules[0].Teams[0].ID)
	assert.Equal(t, []string{"Line: 1: incorrect codeowner team: org3/ghost", "Line: 1: incorrect codeowner team: org2/team1"}, owners.Warnings)
}

// A line whose owners all fail to resolve is kept without owners, so no approval covers its files: it blocks.
func TestParseCodeOwnersUnresolvableLineIsKept(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	parse := func(ownerID int64, text string) *issues_model.CodeOwners {
		return issues_model.ParseCodeOwners(t.Context(), ownerID, io.NopCloser(strings.NewReader(text)), false)
	}
	for name, text := range map[string]string{
		"deleted user":   "a/.* @nosuchuser\n",
		"foreign team":   "a/.* @org2/team1\n",
		"missing org":    "a/.* @nosuchorg/team1\n",
		"typo in a team": "a/.* @org3/typo\n",
		"header":         "[Docs] @nosuchuser\na/.*\n",
	} {
		owners := parse(3, text)
		require.Len(t, owners.Rules, 1, name)
		assert.Empty(t, owners.Rules[0].Users, name)
		assert.Empty(t, owners.Rules[0].Teams, name)
		assert.Contains(t, strings.Join(owners.Warnings, "\n"), "this line blocks merges", name)
	}
	owners := parse(3, "a/.* @user2 @org2/team1\n")
	require.Len(t, owners.Rules, 1)
	assert.Len(t, owners.Rules[0].Users, 1, "the name that resolves stays")
}
