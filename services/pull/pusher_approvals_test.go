// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	user_model "forgejo.org/models/user"
	pull_service "forgejo.org/services/pull"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gitIn runs git in dir and returns its trimmed output.
func gitIn(t *testing.T, dir string, env []string, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), append(env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// commitOn makes a commit with the files on top of rev in the base repository and returns its ID.
func (f *approvalFixture) commitOn(t *testing.T, rev string, files map[string]string, authorEmail, committerEmail string) string {
	dir := f.pr.BaseRepo.RepoPath()
	index := t.TempDir() + "/index"
	env := []string{"GIT_INDEX_FILE=" + index}
	gitIn(t, dir, env, "", "read-tree", rev)
	for name, content := range files {
		blob := gitIn(t, dir, nil, content, "hash-object", "-w", "--stdin")
		gitIn(t, dir, env, "", "update-index", "--add", "--cacheinfo", "100644,"+blob+","+name)
	}
	tree := gitIn(t, dir, env, "", "write-tree")
	return gitIn(t, dir, []string{
		"GIT_AUTHOR_NAME=A", "GIT_AUTHOR_EMAIL=" + authorEmail,
		"GIT_COMMITTER_NAME=C", "GIT_COMMITTER_EMAIL=" + committerEmail,
	}, "", "commit-tree", tree, "-p", rev, "-m", "change")
}

// setHead points the pull request at a new commit on top of master changing the files, and gives master the
// CODEOWNERS file, if any: the merge base stays at the old master.
func (f *approvalFixture) setHead(t *testing.T, codeowners string, files map[string]string, authorEmail, committerEmail string) {
	dir := f.pr.BaseRepo.RepoPath()
	master := gitIn(t, dir, nil, "", "rev-parse", "refs/heads/master")
	head := f.commitOn(t, master, files, authorEmail, committerEmail)
	gitIn(t, dir, nil, "", "update-ref", f.pr.GetGitRefName(), head)
	if codeowners != "" {
		base := f.commitOn(t, master, map[string]string{"CODEOWNERS": codeowners}, "o@example.org", "o@example.org")
		gitIn(t, dir, nil, "", "update-ref", "refs/heads/master", base)
	}
}

func (f *approvalFixture) pushComment(t *testing.T, posterID int64) {
	_, err := db.GetEngine(t.Context()).Insert(&issues_model.Comment{Type: issues_model.CommentTypePullRequestPush, PosterID: posterID, IssueID: f.pr.IssueID, Content: "{}"})
	require.NoError(t, err)
}

func (f *approvalFixture) status(t *testing.T, name string) *pull_service.ApprovalRuleStatus {
	statuses, err := pull_service.EvaluateApprovalRules(t.Context(), f.pb, f.pr)
	require.NoError(t, err)
	for _, s := range statuses {
		if s.Name == name {
			return s
		}
	}
	require.FailNow(t, "no such rule", name)
	return nil
}

func ownersRule() *git_model.ApprovalRule {
	return &git_model.ApprovalRule{Name: "Owners", RequiredCount: 1, RequireCodeOwners: true}
}

// R3: a pusher, by push comment or by the email of a commit, is no approver of a rule that ignores them.
func TestEvaluateApprovalRulesIgnorePusherApprovals(t *testing.T) {
	f := newApprovalFixture(t, rule("Writers", 2, 4))
	approve := issues_model.ReviewTypeApprove
	f.review(t, 2, approve, false)
	f.review(t, 4, approve, false)
	f.setHead(t, "", map[string]string{"a.txt": "a"}, "x@example.org", "x@example.org")
	assert.EqualValues(t, 2, f.status(t, "Writers").Granted)

	f.pb.IgnorePusherApprovals = true
	assert.EqualValues(t, 2, f.status(t, "Writers").Granted, "nobody pushed")

	f.pushComment(t, 4)
	assert.EqualValues(t, 1, f.status(t, "Writers").Granted, "the poster of a push comment doesn't count")
	f.pb.IgnorePusherApprovals = false
	assert.EqualValues(t, 2, f.status(t, "Writers").Granted, "the flag is per rule")

	// user4's activated address as the committer of a commit (any case), user2's unactivated address as the author
	f.pb.IgnorePusherApprovals = true
	_, err := db.GetEngine(t.Context()).Where("type = ?", issues_model.CommentTypePullRequestPush).Delete(&issues_model.Comment{})
	require.NoError(t, err)
	f.setHead(t, "", map[string]string{"a.txt": "a"}, "user2-private@example.org", "USER4@Example.com")
	assert.EqualValues(t, 1, f.status(t, "Writers").Granted, "the committer email of user4 is activated")

	f.setHead(t, "", map[string]string{"a.txt": "a"}, "USER4@example.com", "nobody@example.org")
	assert.EqualValues(t, 1, f.status(t, "Writers").Granted, "so is the author email")

	f.setHead(t, "", map[string]string{"a.txt": "a"}, "user2-private@example.org", "nobody@example.org")
	assert.EqualValues(t, 2, f.status(t, "Writers").Granted, "an address no user has activated admits nobody and removes nobody")
}

// R3: the default approvals of a rule count the same way, and an error fails closed.
func TestGetGrantedApprovalsCountIgnorePusherApprovals(t *testing.T) {
	f := newApprovalFixture(t)
	for _, id := range []int64{2, 4} {
		_, err := issues_model.CreateReview(t.Context(), issues_model.CreateReviewOptions{
			Issue: f.pr.Issue, Reviewer: &user_model.User{ID: id}, Type: issues_model.ReviewTypeApprove, Official: true,
		})
		require.NoError(t, err)
	}
	f.setHead(t, "", map[string]string{"a.txt": "a"}, "x@example.org", "x@example.org")
	f.pb.RequiredApprovals = 2
	assert.EqualValues(t, 2, issues_model.GetGrantedApprovalsCount(t.Context(), f.pb, f.pr))
	assert.True(t, issues_model.HasEnoughApprovals(t.Context(), f.pb, f.pr))

	f.pb.IgnorePusherApprovals = true
	f.pushComment(t, 2)
	assert.EqualValues(t, 1, issues_model.GetGrantedApprovalsCount(t.Context(), f.pb, f.pr))
	assert.False(t, issues_model.HasEnoughApprovals(t.Context(), f.pb, f.pr))

	pushed, err := pull_service.PusherApprovers(t.Context(), f.pb, f.pr)
	require.NoError(t, err)
	require.Len(t, pushed, 1)
	assert.EqualValues(t, 2, pushed[0].ID)
	f.pb.IgnorePusherApprovals = false
	pushed, err = pull_service.PusherApprovers(t.Context(), f.pb, f.pr)
	require.NoError(t, err)
	assert.Empty(t, pushed)

	// the pull request's head can't be read: no approval counts, and the rule can't be evaluated
	f.pb.IgnorePusherApprovals = true
	gitIn(t, f.pr.BaseRepo.RepoPath(), nil, "", "update-ref", "-d", f.pr.GetGitRefName())
	assert.Zero(t, issues_model.GetGrantedApprovalsCount(t.Context(), f.pb, f.pr))
	_, err = issues_model.ValidReviewers(t.Context(), f.pb, f.pr, issues_model.ReviewTypeApprove)
	require.Error(t, err)
}

// R3 with code owners: a pusher doesn't cover a file as an owner.
func TestIgnorePusherApprovalsCodeOwners(t *testing.T) {
	f := newApprovalFixture(t, ownersRule())
	f.setHead(t, "docs/.* @user2\n", map[string]string{"docs/a.md": "a"}, "x@example.org", "x@example.org")
	f.review(t, 2, issues_model.ReviewTypeApprove, false)
	s := f.status(t, "Owners")
	assert.True(t, s.Satisfied)

	f.pb.IgnorePusherApprovals = true
	f.pushComment(t, 2)
	s = f.status(t, "Owners")
	assert.False(t, s.Satisfied)
	assert.EqualValues(t, 0, s.Granted)
}

// R1: sections of CODEOWNERS.
func TestEvaluateApprovalRulesCodeOwnerSections(t *testing.T) {
	approve := issues_model.ReviewTypeApprove
	docs := map[string]string{"docs/a.md": "a"}
	cases := []struct {
		name      string
		owners    string
		approvers []int64
		satisfied bool
		contains  string
	}{
		{"no header, one owner of two is enough", "docs/.* @user2 @user4\n", []int64{4}, true, ""},
		{"no header, no owner", "docs/.* @user2\n", []int64{4}, false, "not approved by a code owner"},
		{"N=2 with one owner", "[Docs][2]\ndocs/.* @user2 @user4\n", []int64{2}, false, `section "Docs" needs 2 approvals, has 1`},
		{"N=2 with two owners", "[Docs][2]\ndocs/.* @user2 @user4\n", []int64{2, 4}, true, ""},
		{"N=3 needs more people than exist", "[Docs][3]\ndocs/.* @user2 @user4\n", []int64{2, 4}, false, "only 2 people can approve"},
		{"N counts over the matching lines of the section", "[Docs][2]\ndocs/.* @user2\n.*\\.md @user4\n", []int64{2, 4}, true, ""},
		{"every matching line still needs an owner", "[Docs][1]\ndocs/.* @user2\n.*\\.md @user4\n", []int64{2}, false, "not approved by a code owner"},
		{"optional never blocks", "^[Docs][5]\ndocs/.* @user2\n", []int64{4}, true, ""},
		{"default owners", "[Docs] @user2\ndocs/.*\n", []int64{2}, true, ""},
		{"default owners, other approver", "[Docs] @user2\ndocs/.*\n", []int64{4}, false, `section "Docs" needs 1 approvals, has 0`},
		{"duplicate sections merge, the larger N counts", "[Docs][1]\ndocs/.* @user2 @user4\n[docs][2]\n.*\\.md @user2 @user4\n", []int64{2}, false, `section "Docs" needs 2`},
		{"a header isn't a pattern", "[Docs] @user2\ndocs/.* @user2\n", []int64{2}, true, ""},
		{"malformed header", "[Docs\ndocs/.* @user2\n", []int64{2}, false, "CODEOWNERS has an error on line 1"},
		{"zero approvals", "docs/.* @user2\n[Docs][0]\n", []int64{2}, false, "CODEOWNERS has an error on line 2"},
		{"not a number", "[Docs][x] @user2\n", []int64{2}, false, "CODEOWNERS has an error on line 1"},
		{"empty name", "[] @user2\n", []int64{2}, false, "CODEOWNERS has an error on line 1"},
		{"absurd N", "[Docs][99999999999999999999]\n", []int64{2}, false, "CODEOWNERS has an error on line 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newApprovalFixture(t, ownersRule())
			f.setHead(t, c.owners, docs, "x@example.org", "x@example.org")
			for _, id := range c.approvers {
				f.review(t, id, approve, false)
			}
			s := f.status(t, "Owners")
			assert.Equal(t, c.satisfied, s.Satisfied, s.Reason())
			if c.contains != "" {
				assert.Contains(t, s.Reason(), c.contains)
			}
		})
	}
}

// R1: CODEOWNERS changed only on the head branch never changes who the owners are.
func TestCodeOwnerSectionsReadFromBase(t *testing.T) {
	f := newApprovalFixture(t, ownersRule())
	f.setHead(t, "docs/.* @user2\n", map[string]string{"docs/a.md": "a", "CODEOWNERS": "[Docs][1]\ndocs/.* @user4\n"}, "x@example.org", "x@example.org")
	f.review(t, 4, issues_model.ReviewTypeApprove, false)
	assert.False(t, f.status(t, "Owners").Satisfied, "the owners of the base branch decide")
}
