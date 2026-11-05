// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/forms"
	pull_service "forgejo.org/services/pull"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pusherNote = "pushed to this pull request"

// pusherEnv is approvalRulesEnv with helpers for pushes by other users.
type pusherEnv struct {
	*approvalRulesEnv
}

func (e *pusherEnv) protectPushers(base string, ignore bool, rules ...*api.ApprovalRule) {
	req := NewRequestWithJSON(e.t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.CreateBranchProtectionOption{
		RuleName: base, RequiredApprovals: 1, ApplyToAdmins: true, IgnorePusherApprovals: ignore, ApprovalRules: rules,
	}).AddTokenAuth(e.owner.Token)
	var bp api.BranchProtection
	DecodeJSON(e.t, e.owner.Session.MakeRequest(e.t, req, http.StatusCreated), &bp)
	assert.Equal(e.t, ignore, bp.IgnorePusherApprovals)
}

// pushAs commits a new file to a branch as user and waits until the push comment exists.
func (e *pusherEnv) pushAs(user string, index int64, branch, path string, identity *api.Identity) {
	ctx := e.writer[user]
	before := e.pushComments(index)
	req := NewRequestWithJSON(e.t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{
		FileOptions: api.FileOptions{BranchName: branch, Message: "push", Committer: *identity, Author: *identity},
		Files:       []*api.ChangeFileOperation{create(path, path)},
	}).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(e.t, req, http.StatusCreated)
	assert.Eventually(e.t, func() bool { return e.pushComments(index) > before }, 10*time.Second, 50*time.Millisecond)
}

func (e *pusherEnv) pushComments(index int64) int64 {
	n, err := db.GetEngine(e.t.Context()).Table("comment").Join("INNER", "issue", "issue.id = comment.issue_id").
		Where("issue.repo_id = 1 AND issue.`index` = ? AND comment.type = ?", index, issues_model.CommentTypePullRequestPush).Count()
	require.NoError(e.t, err)
	return n
}

func (e *pusherEnv) mergeBox(ctx APITestContext, index int64) *HTMLDoc {
	resp := ctx.Session.MakeRequest(e.t, NewRequestf(e.t, "GET", "/user2/repo1/pulls/%d", index), http.StatusOK)
	return NewHTMLParser(e.t, resp.Body)
}

func ident(email string) *api.Identity { return &api.Identity{Name: "Pusher", Email: email} }

func TestPusherApprovals(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := &pusherEnv{newApprovalRulesEnv(t)}
		user4Email := "user4@example.com"

		// the poster of a push comment doesn't count; merging through the API and the web needs another approver
		for _, mode := range []string{"api", "web"} {
			t.Run("push comment "+mode, func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()
				base := "pa-push-" + mode
				e.base(base)
				e.protectPushers(base, true)
				index := e.pr(base, create("a.txt", "a"))

				e.approve("user4", index)
				e.pushAs("user4", index, "head-"+base, "b.txt", ident("someone-else@example.org"))
				if mode == "api" {
					assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), pusherNote)
				} else {
					testPullMergeForm(t, e.owner.Session, http.StatusBadRequest, "user2", "repo1", fmt.Sprint(index), optionsPullMerge{"do": "merge"})
				}
				note := strings.Join(strings.Fields(e.mergeBox(e.owner, index).doc.Find(".pusher-approval").Text()), " ")
				assert.Equal(t, "The approval of user4 does not count: they pushed to this pull request.", note, "no email is shown")

				e.approve("user5", index)
				if mode == "api" {
					e.apiMerge(e.owner, index, false, http.StatusOK)
				} else {
					testPullMergeForm(t, e.owner.Session, http.StatusOK, "user2", "repo1", fmt.Sprint(index), optionsPullMerge{"do": "merge"})
				}
			})
		}

		t.Run("off by default", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-off")
			e.protectPushers("pa-off", false)
			index := e.pr("pa-off", create("a.txt", "a"))
			e.approve("user4", index)
			e.pushAs("user4", index, "head-pa-off", "b.txt", ident("someone-else@example.org"))
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// a push that left no push comment: made before the pull request existed (its only push comment is the creation's)
		t.Run("push before the pull request", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-pre")
			e.protectPushers("pa-pre", true)
			user4 := e.writer["user4"]
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{
				FileOptions: api.FileOptions{BranchName: "pa-pre", NewBranchName: "head-pa-pre", Message: "c", Author: *ident("a@example.org"), Committer: *ident("a@example.org")},
				Files:       []*api.ChangeFileOperation{create("a.txt", "a")},
			}).AddTokenAuth(user4.Token)
			user4.Session.MakeRequest(t, req, http.StatusCreated)
			pr, err := doAPICreatePullRequest(e.owner, "user2", "repo1", "pa-pre", "head-pa-pre")(t)
			require.NoError(t, err)
			e.approve("user4", pr.Index)
			assert.Contains(t, e.apiMerge(e.owner, pr.Index, false, http.StatusMethodNotAllowed), pusherNote)
			e.approve("user5", pr.Index)
			e.apiMerge(e.owner, pr.Index, false, http.StatusOK)
		})

		// close, push, reopen: the approver's push while the pull request was closed leaves no push comment
		for _, mode := range []string{"api", "web"} {
			t.Run("push while closed, reopened by "+mode, func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()
				base := "pa-closed-" + mode
				e.base(base)
				e.protectPushers(base, true)
				index := e.pr(base, create("a.txt", "a"))
				e.approve("user4", index)

				setState := func(state string) {
					req := NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d", index), &api.EditPullRequestOption{State: &state}).AddTokenAuth(e.owner.Token)
					e.owner.Session.MakeRequest(t, req, http.StatusCreated)
				}
				setState("closed")
				commentsBefore := e.pushComments(index)
				user4 := e.writer["user4"]
				req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{
					FileOptions: api.FileOptions{BranchName: "head-" + base, Message: "c", Author: *ident("a@example.org"), Committer: *ident("a@example.org")},
					Files:       []*api.ChangeFileOperation{create("evil.txt", "evil")},
				}).AddTokenAuth(user4.Token)
				user4.Session.MakeRequest(t, req, http.StatusCreated)
				assert.Equal(t, commentsBefore, e.pushComments(index), "a closed pull request gets no push comment")
				if mode == "api" {
					setState("open")
				} else {
					e.owner.Session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/pulls/%d/comments", index), map[string]string{"status": "reopen"}), http.StatusOK)
				}

				// refused: by the pin when the head ref was not refreshed (API), by the pusher record when it was (web)
				req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(e.owner.Token)
				code := e.owner.Session.MakeRequest(t, req, NoExpectedStatus).Code
				assert.NotEqual(t, http.StatusOK, code)
				pull := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{Index: index, BaseRepoID: 1})
				assert.False(t, pull.HasMerged)
				if mode == "web" {
					assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), pusherNote)
					note := strings.Join(strings.Fields(e.mergeBox(e.owner, index).doc.Find(".pusher-approval").Text()), " ")
					assert.Equal(t, "The approval of user4 does not count: they pushed to this pull request.", note)
				}
			})
		}

		// the merge is pinned to the head that was checked: a head that moved while the pull request was closed (the
		// pull ref is not refreshed by an API reopen) is refused until the pull request is updated by a push
		t.Run("merge pinned to the checked head", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-pin")
			e.protectPushers("pa-pin", true)
			index := e.pr("pa-pin", create("a.txt", "a"))
			e.approve("user4", index)
			setState := func(state string) {
				req := NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d", index), &api.EditPullRequestOption{State: &state}).AddTokenAuth(e.owner.Token)
				e.owner.Session.MakeRequest(t, req, http.StatusCreated)
			}
			setState("closed")
			user5 := e.writer["user5"]
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{
				FileOptions: api.FileOptions{BranchName: "head-pa-pin", Message: "c", Author: *ident("a@example.org"), Committer: *ident("a@example.org")},
				Files:       []*api.ChangeFileOperation{create("unreviewed.txt", "x")},
			}).AddTokenAuth(user5.Token)
			user5.Session.MakeRequest(t, req, http.StatusCreated)
			setState("open")
			req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(e.owner.Token)
			assert.NotEqual(t, http.StatusOK, e.owner.Session.MakeRequest(t, req, NoExpectedStatus).Code)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{Index: index, BaseRepoID: 1}).HasMerged)

			// the head that is merged is the one the pull ref names
			e.pushAs("user5", index, "head-pa-pin", "again.txt", ident("a@example.org"))
			assert.Eventually(t, func() bool {
				req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(e.owner.Token)
				return e.owner.Session.MakeRequest(t, req, NoExpectedStatus).Code == http.StatusOK
			}, 15*time.Second, 200*time.Millisecond)
		})

		// a deploy key with no recorded owner pushed: nobody's approval can be checked
		// the pin is the head the check read: a head that moves between the check and the merge (the branch and the pull
		// ref both, as a push and its async update would) is refused, not re-read
		t.Run("head moves between the check and the merge", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-race")
			e.protectPushers("pa-race", true)
			index := e.pr("pa-race", create("a.txt", "a"))
			e.approve("user4", index)
			e.approve("user5", index)
			moved := false
			defer test.MockVariableValue(&pull_service.TestHookBeforeHeadPin, func(ctx context.Context, pr *issues_model.PullRequest) {
				if moved {
					return
				}
				moved = true
				dir := repo_model.RepoPath("user2", "repo1")
				other, err := git.GetFullCommitID(ctx, dir, "refs/heads/master")
				require.NoError(t, err)
				require.NoError(t, git.NewCommand(ctx, "update-ref", "refs/heads/head-pa-race").AddDynamicArguments(other).Run(&git.RunOpts{Dir: dir}))
				require.NoError(t, git.NewCommand(ctx, "update-ref").AddDynamicArguments(pr.GetGitRefName(), other).Run(&git.RunOpts{Dir: dir}))
			})()
			e.apiMerge(e.owner, index, false, http.StatusConflict)
			assert.True(t, moved)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{Index: index, BaseRepoID: 1}).HasMerged)
		})

		t.Run("deploy key without owner", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-key")
			e.protectPushers("pa-key", true)
			index := e.pr("pa-key", create("a.txt", "a"))
			e.approve("user4", index)
			require.NoError(t, git_model.AddBranchPusher(t.Context(), 1, "head-pa-key", 0))
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "a push to this pull request has no recorded person, so approvals can't be checked")
			text := strings.Join(strings.Fields(e.mergeBox(e.owner, index).doc.Find(".pusher-block").Text()), " ")
			assert.Equal(t, "A push to this pull request has no recorded person, so approvals can't be checked.", text)
			// the line follows the approvals line it explains
			assert.Contains(t, e.mergeBox(e.owner, index).Find(".pusher-block").Prev().Text(), "approvals")
		})

		// an approver whose activated email is the committer or author of a commit of the pull request
		// AGit: the head is the poster's, not a branch, so there are no branch rows; the commit emails still exclude their owner
		t.Run("agit", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-agit")
			e.protectPushers("pa-agit", true)
			dst := t.TempDir()
			clone := *u
			clone.Path = "user2/repo1.git"
			clone.User = url.UserPassword("user4", userPassword)
			doGitClone(dst, &clone)(t)
			require.NoError(t, git.NewCommand(t.Context(), "checkout", "-b", "agit-work", "origin/pa-agit").Run(&git.RunOpts{Dir: dst}))
			require.NoError(t, os.WriteFile(filepath.Join(dst, "agit.txt"), []byte("agit"), 0o666))
			require.NoError(t, git.AddChanges(dst, true))
			sig := &git.Signature{Email: "user5@example.com", Name: "Pusher", When: time.Now()}
			require.NoError(t, git.CommitChanges(dst, git.CommitChangesOptions{Committer: sig, Author: sig, Message: "agit"}))
			require.NoError(t, git.NewCommand(t.Context(), "push", "origin", "HEAD:refs/for/pa-agit", "-o", "topic=pa-agit").Run(&git.RunOpts{Dir: dst}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: 1, HeadBranch: "user4/pa-agit"})

			e.approve("user5", pr.Index)
			assert.Contains(t, e.apiMerge(e.owner, pr.Index, false, http.StatusMethodNotAllowed), pusherNote)
			ids, err := git_model.FindBranchPusherIDs(t.Context(), 1, pr.HeadBranch)
			require.NoError(t, err)
			assert.Empty(t, ids, "no rows for an AGit head")
		})

		t.Run("commit email", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-email")
			e.protectPushers("pa-email", true)
			index := e.pr("pa-email", create("a.txt", "a"))
			e.approve("user4", index)
			// user2 pushes a commit that user4's address authored
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{
				FileOptions: api.FileOptions{BranchName: "head-pa-email", Message: "c", Author: *ident(strings.ToUpper(user4Email)), Committer: *ident("nobody@example.org")},
				Files:       []*api.ChangeFileOperation{create("b.txt", "b")},
			}).AddTokenAuth(e.owner.Token)
			e.owner.Session.MakeRequest(t, req, http.StatusCreated)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), pusherNote)
			e.approve("user5", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// the approvals endpoint lists no pusher, and has no list of them
		t.Run("approvals endpoint", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-endpoint")
			e.protectPushers("pa-endpoint", true, ruleOf("Writers", 1, "user4", "user5"))
			index := e.pr("pa-endpoint", create("a.txt", "a"))
			e.approve("user4", index)
			e.pushAs("user4", index, "head-pa-endpoint", "b.txt", ident("x@example.org"))
			e.approve("user5", index)
			for _, r := range e.approvals(index) {
				if r.Name == "Writers" {
					assert.Equal(t, []string{"user5"}, r.Approvers)
					assert.EqualValues(t, 1, r.Granted)
				}
			}
			req := NewRequestf(t, "GET", "/api/v1/repos/user2/repo1/pulls/%d/approvals", index).AddTokenAuth(e.owner.Token)
			assert.NotContains(t, e.owner.Session.MakeRequest(t, req, http.StatusOK).Body.String(), "pusher")
		})

		// clicking "Update branch" is a push: the button asks first, and the approval stops counting
		t.Run("update branch", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-update")
			index := e.pr("pa-update", create("a.txt", "a"))
			e.changeFiles("pa-update", "", create("newer.txt", "n")) // the base moves on: the head is behind
			e.protectPushers("pa-update", true)
			e.approve("user4", index)

			confirm := func(ctx APITestContext) string { // the text of the confirm modal the button opens
				box := e.mergeBox(ctx, index)
				if box.Find("[data-modal-id=update-branch-confirm]").Length() == 0 {
					return ""
				}
				return strings.TrimSpace(box.Find("#update-branch-confirm .content").Text())
			}
			assert.Equal(t, 1, e.mergeBox(e.owner, index).Find(".update-button, .update-branch-form").Length(), "the update button is shown")
			assert.Equal(t, "Updating the branch counts as a push: your approval will no longer count toward this branch's approval requirements.", confirm(e.writer["user4"]))
			assert.Empty(t, confirm(e.writer["user5"]), "no approval to lose")
			assert.Empty(t, confirm(e.owner), "the author has none either")

			user4 := e.writer["user4"]
			user4.Session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/pulls/%d/update?style=merge", index), nil), http.StatusSeeOther)
			assert.Eventually(t, func() bool { return e.pushComments(index) > 0 }, 10*time.Second, 50*time.Millisecond)
			assert.Eventually(t, func() bool { // the conflict check of the updated head may still be running
				req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(e.owner.Token)
				return strings.Contains(e.owner.Session.MakeRequest(t, req, NoExpectedStatus).Body.String(), pusherNote)
			}, 10*time.Second, 100*time.Millisecond)

			e.approve("user5", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// a web edit of the head branch is a push too
		t.Run("web edit", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-web-edit")
			e.protectPushers("pa-web-edit", true)
			index := e.pr("pa-web-edit", create("a.txt", "a"))
			e.approve("user4", index)
			testEditFile(t, e.writer["user4"].Session, "user2", "repo1", "head-pa-web-edit", "a.txt", "edited\n")
			assert.Eventually(t, func() bool { return e.pushComments(index) > 0 }, 10*time.Second, 50*time.Millisecond)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), pusherNote)
		})

		// scheduled auto merge waits while only a pusher approved
		t.Run("auto merge", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-auto")
			e.protectPushers("pa-auto", true)
			index := e.pr("pa-auto", create("a.txt", "a"))
			e.approve("user4", index)
			e.pushAs("user4", index, "head-pa-auto", "b.txt", ident("x@example.org"))
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge", MergeWhenChecksSucceed: true}).AddTokenAuth(e.owner.Token)
			e.owner.Session.MakeRequest(t, req, http.StatusCreated)
			assert.False(t, doAPIGetPullRequest(e.owner, "user2", "repo1", index)(t).HasMerged)
			e.approve("user5", index)
			assert.Eventually(t, func() bool { return doAPIGetPullRequest(e.owner, "user2", "repo1", index)(t).HasMerged }, 10*time.Second, 200*time.Millisecond)
		})

		// the API field and the web form
		t.Run("settings round trip", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("pa-settings")
			since := auditMaxID(t)
			e.protectPushers("pa-settings", false)
			get := func() bool {
				resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/branch_protections/pa-settings").AddTokenAuth(e.owner.Token), http.StatusOK)
				var bp api.BranchProtection
				DecodeJSON(t, resp, &bp)
				return bp.IgnorePusherApprovals
			}
			patch := func(v *bool) {
				req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branch_protections/pa-settings", &api.EditBranchProtectionOption{IgnorePusherApprovals: v}).AddTokenAuth(e.owner.Token)
				e.owner.Session.MakeRequest(t, req, http.StatusOK)
			}
			assert.False(t, get())
			patch(new(true))
			assert.True(t, get())
			patch(nil)
			assert.True(t, get(), "an absent field keeps the value")
			data := auditData(t, repoOne(t, since+1, "repo.branch_protection.updated", loadRepo(t, "user2", "repo1")))
			assert.Equal(t, map[string]any{"ignore_pusher_approvals": false}, data["before"])
			assert.Equal(t, map[string]any{"ignore_pusher_approvals": true}, data["after"])
			patch(new(false))
			assert.False(t, get())

			// the web form: the checkbox is on the page and saves
			page := NewHTMLParser(t, e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=pa-settings"), http.StatusOK).Body)
			assert.Equal(t, 1, page.Find(`input#ignore_pusher_approvals[name="ignore_pusher_approvals"]`).Length())
			ruleID, _ := page.Find(`input[name="rule_id"]`).Attr("value")
			e.owner.Session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{
				"rule_id": ruleID, "rule_name": "pa-settings", "ignore_pusher_approvals": "on",
			}), http.StatusSeeOther)
			assert.True(t, get())
		})
	})
}

// The flag on an organization rule and on a project rule: each matching rule is evaluated alone, so the stricter wins.
func TestPusherApprovalsOrg(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newOrgRuleEnv(t)
		repo := e.repo("pa-org", map[string]perm.AccessMode{"user4": perm.AccessModeWrite, "user28": perm.AccessModeWrite})
		e.create(api.CreateOrgBranchProtectionOption{
			CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "master", RequiredApprovals: 1, IgnorePusherApprovals: true},
			ApplyToSelectedRepos:         true, Repos: []string{"pa-org"},
		})
		// the repository's own rule doesn't ask for it
		e.repoRule("pa-org", api.CreateBranchProtectionOption{RuleName: "master", RequiredApprovals: 1})
		got := e.rule(e.owner, "GET", "master", nil, http.StatusOK)
		assert.True(t, got.IgnorePusherApprovals)

		user4 := NewAPITestContext(t, "user4", "pa-org", auth_model.AccessTokenScopeWriteRepository)
		user28 := NewAPITestContext(t, "user28", "pa-org", auth_model.AccessTokenScopeWriteRepository)
		link := "/api/v1/repos/org3/pa-org"
		req := NewRequestWithJSON(t, "POST", link+"/contents", &api.ChangeFilesOptions{
			FileOptions: api.FileOptions{BranchName: "master", NewBranchName: "pa-head", Message: "change"},
			Files:       []*api.ChangeFileOperation{create("a.txt", "a")},
		}).AddTokenAuth(repo.Token)
		MakeRequest(t, req, http.StatusCreated)
		pr, err := doAPICreatePullRequest(repo, "org3", "pa-org", "master", "pa-head")(t)
		require.NoError(t, err)
		review := func(ctx APITestContext) {
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/pulls/%d/reviews", link, pr.Index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(ctx.Token), http.StatusOK)
		}
		merge := func(expected int) string {
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/pulls/%d/merge", link, pr.Index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(repo.Token)
			return MakeRequest(t, req, expected).Body.String()
		}

		review(user4)
		MakeRequest(t, NewRequestWithJSON(t, "POST", link+"/contents", &api.ChangeFilesOptions{
			FileOptions: api.FileOptions{BranchName: "pa-head", Message: "push"},
			Files:       []*api.ChangeFileOperation{create("b.txt", "b")},
		}).AddTokenAuth(user4.Token), http.StatusCreated)
		// the repository's rule is satisfied, the organization's isn't
		assert.Contains(t, merge(http.StatusMethodNotAllowed), pusherNote)
		review(user28)
		merge(http.StatusOK)
	})
}

// A project rule with the flag, in a repository inside the project.
func TestPusherApprovalsProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, _ := prepareRepoGroupGit(t)
		group, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "proj")
		require.NoError(t, err)
		proj := group.ID
		rule := &git_model.ProtectedBranch{RuleName: "main", RequiredApprovals: 1, IgnorePusherApprovals: true}
		require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, proj, rule, git_model.WhitelistOptions{}, nil))
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID}).IgnorePusherApprovals)

		owner := loginUser(t, "user2")
		ownerToken := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		user4 := loginUser(t, "user4")
		user4Token := getTokenForLoggedInUser(t, user4, auth_model.AccessTokenScopeWriteRepository)
		user28 := loginUser(t, "user28")
		user28Token := getTokenForLoggedInUser(t, user28, auth_model.AccessTokenScopeWriteRepository)
		call := func(token, method, path string, body any, status int) *httptest.ResponseRecorder {
			return MakeRequest(t, NewRequestWithJSON(t, method, "/api/v1/repos/org3/proj/priv/-"+path, body).AddTokenAuth(token), status)
		}
		call(ownerToken, "PUT", "/collaborators/user4", &api.AddCollaboratorOption{Permission: new("write")}, http.StatusNoContent)
		call(ownerToken, "PUT", "/collaborators/user28", &api.AddCollaboratorOption{Permission: new("write")}, http.StatusNoContent)
		call(ownerToken, "POST", "/branches", &api.CreateBranchRepoOption{BranchName: "feat", OldBranchName: "main"}, http.StatusCreated)
		file := func(token, name string) {
			call(token, "POST", "/contents/"+name, &api.CreateFileOptions{FileOptions: api.FileOptions{BranchName: "feat"}, ContentBase64: base64.StdEncoding.EncodeToString([]byte(name))}, http.StatusCreated)
		}
		file(ownerToken, "feat.txt")
		var pr api.PullRequest
		DecodeJSON(t, call(ownerToken, "POST", "/pulls", &api.CreatePullRequestOption{Head: "feat", Base: "main", Title: "feat"}, http.StatusCreated), &pr)
		review := func(token string) {
			call(token, "POST", fmt.Sprintf("/pulls/%d/reviews", pr.Index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}, http.StatusOK)
		}
		merge := func(status int) string {
			return call(ownerToken, "POST", fmt.Sprintf("/pulls/%d/merge", pr.Index), &forms.MergePullRequestForm{Do: "merge"}, status).Body.String()
		}

		review(user4Token)
		file(user4Token, "more.txt")
		issue, err := issues_model.GetIssueByIndex(db.DefaultContext, f.priv.ID, pr.Index)
		require.NoError(t, err)
		assert.Eventually(t, func() bool {
			n, err := db.GetEngine(db.DefaultContext).Where("issue_id = ? AND type = ? AND poster_id = ?", issue.ID, issues_model.CommentTypePullRequestPush, 4).Count(new(issues_model.Comment))
			return err == nil && n > 0
		}, 10*time.Second, 50*time.Millisecond)
		assert.Contains(t, merge(http.StatusMethodNotAllowed), pusherNote)
		review(user28Token)
		merge(http.StatusOK)
	})
}
