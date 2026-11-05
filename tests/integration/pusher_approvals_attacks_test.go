// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Attacks on "ignore pusher approvals" and CODEOWNERS sections that the other tests do not cover,
// run end to end over HTTP, the API and git.
func TestPusherApprovalsAttacks(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := &pusherEnv{newApprovalRulesEnv(t)} // user4, user5 are write collaborators on the base user2/repo1

		mustPushers := func(repoID int64, branch string) []int64 {
			ids, err := git_model.FindBranchPusherIDs(t.Context(), repoID, branch)
			require.NoError(t, err)
			return ids
		}

		// ATTACK 1 (fork head repo): a colluding reviewer approves, then pushes a commit into the PR's head branch,
		// which lives in a *fork* (a different repository than the base). The pre-receive hook runs in the fork, so
		// the pusher must be recorded against the fork's repo id (pr.HeadRepoID), not the base. Every one of the PR's
		// own tests uses a head branch in the base repo, so this path is otherwise untested.
		t.Run("push to the fork head repo disqualifies the reviewer", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			owner := e.owner
			author := e.writer["user4"]
			reviewer := e.writer["user5"]

			base := "rt-fork-base"
			e.base(base)
			e.protectPushers(base, true)

			// user4 forks user2/repo1 -> user4/repo1
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{}).AddTokenAuth(author.Token)
			var fork api.Repository
			DecodeJSON(t, author.Session.MakeRequest(t, req, http.StatusAccepted), &fork)
			require.Equal(t, "user4", fork.Owner.UserName)
			forkRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: fork.ID})
			require.NotEqual(t, int64(1), forkRepo.ID)

			// user4 lets the colluding reviewer (user5) push to the fork
			req = NewRequestWithJSON(t, "PUT", "/api/v1/repos/user4/repo1/collaborators/user5", &api.AddCollaboratorOption{Permission: new("write")}).AddTokenAuth(author.Token)
			author.Session.MakeRequest(t, req, http.StatusNoContent)

			// user4 creates the head branch in the fork and opens a cross-repo PR into the protected base branch
			head := "rt-fork-head"
			req = NewRequestWithJSON(t, "POST", "/api/v1/repos/user4/repo1/contents", &api.ChangeFilesOptions{
				FileOptions: api.FileOptions{BranchName: forkRepo.DefaultBranch, NewBranchName: head, Message: "work"},
				Files:       []*api.ChangeFileOperation{create("feat.txt", "feat")},
			}).AddTokenAuth(author.Token)
			author.Session.MakeRequest(t, req, http.StatusCreated)
			pr, err := doAPICreatePullRequest(owner, "user2", "repo1", base, "user4:"+head)(t)
			require.NoError(t, err)
			require.Equal(t, forkRepo.ID, pr.Head.Repository.ID, "the head is the fork")

			// the reviewer approves (official: write on the base repo)
			e.approve("user5", pr.Index)

			// the reviewer now pushes a commit into the fork's head branch
			assert.NotContains(t, mustPushers(forkRepo.ID, head), int64(5), "no pusher row before the push")
			req = NewRequestWithJSON(t, "POST", "/api/v1/repos/user4/repo1/contents", &api.ChangeFilesOptions{
				FileOptions: api.FileOptions{BranchName: head, Message: "sneak"},
				Files:       []*api.ChangeFileOperation{create("sneak.txt", "sneak")},
			}).AddTokenAuth(reviewer.Token)
			reviewer.Session.MakeRequest(t, req, http.StatusCreated)

			// the pusher must be recorded against the fork's repo id, not the base
			assert.Contains(t, mustPushers(forkRepo.ID, head), int64(5), "recorded against the fork")
			assert.Empty(t, mustPushers(1, head), "nothing leaks into the base repo under the same branch name")

			// the merge is refused: the only approval is the reviewer's, who pushed
			assert.Contains(t, e.apiMerge(owner, pr.Index, false, http.StatusMethodNotAllowed), pusherNote)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{Index: pr.Index, BaseRepoID: 1}).HasMerged)

			// a clean approver who never pushed nor authored a commit (user8, added as a base collaborator) satisfies
			// the rule: the pusher exclusion only removes the pushers, not everyone. (user2 opened this pull request, so
			// their own approval never counts: an author can't approve.)
			req = NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user8", &api.AddCollaboratorOption{Permission: new("write")}).AddTokenAuth(owner.Token)
			owner.Session.MakeRequest(t, req, http.StatusNoContent)
			user8 := NewAPITestContext(t, "user8", "repo1", auth_model.AccessTokenScopeWriteRepository)
			req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/reviews", pr.Index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(user8.Token)
			user8.Session.MakeRequest(t, req, http.StatusOK)
			assert.Eventually(t, func() bool {
				req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", pr.Index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(owner.Token)
				code := owner.Session.MakeRequest(t, req, NoExpectedStatus).Code
				return code == http.StatusOK
			}, 15*time.Second, 200*time.Millisecond, "a non-pusher approval satisfies the rule")
		})

		// ATTACK 2 (head CODEOWNERS can't weaken): the attacker rewrites CODEOWNERS on the PR's own head branch to
		// name their accomplice as owner. The merge check must read CODEOWNERS from the base branch only.
		t.Run("CODEOWNERS on the head branch is ignored", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			owner := e.owner
			base := "rt-co-base"
			e.base(base, create("CODEOWNERS", "docs/.* @user5\n"))
			e.protect(base, true, &api.ApprovalRule{Name: "Owners", RequiredCount: 1, RequireCodeOwners: true})

			head := "head-" + base
			e.changeFiles(base, head, create("docs/a.md", "a"), &api.ChangeFileOperation{
				Operation: "update", Path: "CODEOWNERS", ContentBase64: base64.StdEncoding.EncodeToString([]byte("docs/.* @user4\n")),
			})
			pr, err := doAPICreatePullRequest(owner, "user2", "repo1", base, head)(t)
			require.NoError(t, err)

			// user4's approval must NOT cover docs (the head CODEOWNERS is ignored); only user5 (base owner) does
			e.approve("user4", pr.Index)
			assert.Contains(t, e.apiMerge(owner, pr.Index, false, http.StatusMethodNotAllowed), "not approved by a code owner")
			e.approve("user5", pr.Index)
			e.apiMerge(owner, pr.Index, false, http.StatusOK)
		})

		// ATTACK 3 (force-push laundering): a reviewer approves, pushes a commit (recorded), then force-pushes the head
		// branch to a history that no longer contains their commit. The branch_pusher row must survive the rewrite, so
		// recomputing pushers from the current commits alone would not clear it.
		t.Run("force-push does not launder the pusher record", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			base := "rt-force"
			e.base(base)
			e.protectPushers(base, true)
			index := e.pr(base, create("a.txt", "a"))
			head := "head-" + base

			e.approve("user4", index)

			dst := t.TempDir()
			clone := *u
			clone.Path = "user2/repo1.git"
			clone.User = url.UserPassword("user4", userPassword)
			doGitClone(dst, &clone)(t)
			require.NoError(t, git.NewCommand(t.Context(), "checkout", "-b", "w").AddDynamicArguments("origin/"+head).Run(&git.RunOpts{Dir: dst}))
			require.NoError(t, os.WriteFile(filepath.Join(dst, "evil.txt"), []byte("evil"), 0o666))
			require.NoError(t, git.AddChanges(dst, true))
			sig := &git.Signature{Email: "nobody@nowhere.test", Name: "N", When: time.Now()}
			require.NoError(t, git.CommitChanges(dst, git.CommitChangesOptions{Committer: sig, Author: sig, Message: "evil"}))
			// a normal push: records user4 as a pusher
			require.NoError(t, git.NewCommand(t.Context(), "push", "origin").AddDynamicArguments("HEAD:"+head).Run(&git.RunOpts{Dir: dst}))
			assert.Eventually(t, func() bool { return slices.Contains(mustPushers(1, head), 4) }, 10*time.Second, 100*time.Millisecond)

			// now force-push the branch back to the clean base tip, erasing user4's commit from history
			require.NoError(t, git.NewCommand(t.Context(), "fetch", "origin").AddDynamicArguments(base).Run(&git.RunOpts{Dir: dst}))
			require.NoError(t, git.NewCommand(t.Context(), "push", "--force", "origin").AddDynamicArguments("FETCH_HEAD:"+head).Run(&git.RunOpts{Dir: dst}))

			// the record persists regardless of the rewritten history
			assert.Contains(t, mustPushers(1, head), int64(4), "the row survives the force-push")
		})
	})
}
