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

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/private"
	repo_module "forgejo.org/modules/repository"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/services/forms"
	"forgejo.org/services/mergequeue"
	repo_service "forgejo.org/services/repository"
	files_service "forgejo.org/services/repository/files"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullMergeQueue(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		merger := forgery.CreateUser(t, nil)
		reader := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, nil, &forgery.CreateRepositoryOptions{
			Files: forgery.FilesInit{},
			Collaborators: map[*user_model.User]perm.AccessMode{
				merger: perm.AccessModeWrite,
				reader: perm.AccessModeRead,
			},
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		forgery.EnableRepoUnit(t, repo, unit_model.TypeActions, nil)
		owner := repo.Owner
		session := loginUser(t, owner.Name)
		mergerSession := loginUser(t, merger.Name)
		readerSession := loginUser(t, reader.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		statusCtx := APITestContext{Session: session, Token: token, Username: owner.Name, Reponame: repo.Name}

		// a merge_group workflow, and a file the pull requests change in turn
		_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
			Files: []*files_service.ChangeRepoFile{{
				Operation: "create",
				TreePath:  ".forgejo/workflows/queue.yml",
				ContentReader: strings.NewReader(`on:
  merge_group:
    types: [checks_requested]
    branches: [main]
jobs:
  test:
    runs-on: docker
    steps:
      - run: true
`),
			}},
		})
		require.NoError(t, err)

		session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/settings/branches/edit", repo.FullName()), map[string]string{
			"rule_name":                     "main",
			"enable_push":                   "all",
			"enable_status_check":           "true",
			"status_check_contexts":         "ci",
			"require_merge_queue":           "true",
			"merge_queue_build_concurrency": "3",
			"merge_queue_max_group_size":    "3",
		}), http.StatusSeeOther)

		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()

		pulls := 0
		newPull := func(t *testing.T) *issues_model.PullRequest {
			t.Helper()
			pulls++
			branch := fmt.Sprintf("queue-%d", pulls)
			_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				NewBranch: branch,
				Files: []*files_service.ChangeRepoFile{{
					Operation:     "create",
					TreePath:      branch + ".txt",
					ContentReader: strings.NewReader(branch),
				}},
			})
			require.NoError(t, err)
			testPullCreate(t, session, owner.Name, repo.Name, true, "main", branch, branch)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: branch})
			// the pull request's own required check
			head, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
			require.NoError(t, err)
			setStatus(t, statusCtx, head, api.CommitStatusSuccess)
			return pr
		}
		index := func(pr *issues_model.PullRequest) string { return strconv.FormatInt(pr.Index, 10) }
		add := func(t *testing.T, s *TestSession, pr *issues_model.PullRequest) {
			t.Helper()
			testPullMergeForm(t, s, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge"})
			settleMergeQueues(t)
		}
		entry := func(pr *issues_model.PullRequest) *pull_model.MergeQueueEntry {
			e, err := pull_model.GetMergeQueueEntryByPullID(t.Context(), pr.ID)
			require.NoError(t, err)
			return e
		}
		mainTip := func() string {
			sha, err := gitRepo.GetBranchCommitID("main")
			require.NoError(t, err)
			return sha
		}
		merged := func(pr *issues_model.PullRequest) bool {
			return unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged
		}
		removedReason := func(pr *issues_model.PullRequest) string {
			var cs []*issues_model.Comment
			require.NoError(t, db.GetEngine(t.Context()).Where("issue_id = ? AND `type` = ?", pr.IssueID, issues_model.CommentTypePRRemovedFromMergeQueue).Desc("id").Find(&cs))
			if len(cs) == 0 {
				return ""
			}
			return cs[0].AutoMergeInfo().Reason
		}

		t.Run("Direct merges are refused", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pr := newPull(t)
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/pulls/%s/merge", repo.FullName(), index(pr)), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusMethodNotAllowed)
			assert.False(t, merged(pr))

			// the hook refuses a merge of the pull request that isn't the queue's
			head, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
			require.NoError(t, err)
			extra := private.HookPreReceive(t.Context(), repo.ID, private.HookOptions{
				OldCommitIDs: []string{mainTip()}, NewCommitIDs: []string{head}, RefFullNames: []git.RefName{git.RefNameFromBranch("main")},
				UserID: owner.ID, UserName: owner.Name, PullRequestID: pr.ID, PushTrigger: repo_module.PushTriggerPRMergeToBase,
			})
			require.Error(t, extra.Error)
			assert.Contains(t, extra.UserMsg, "requires a merge queue")

			// fast-forward only can't be combined with the pull requests ahead
			testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "fast-forward-only"})
			assert.Nil(t, entry(pr))

			// only the queue writes merge-queue/
			req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/branches", repo.FullName()), &api.CreateBranchRepoOption{BranchName: "merge-queue/main/999", OldRefName: "main"}).AddTokenAuth(token)
			resp := MakeRequest(t, req, NoExpectedStatus)
			assert.NotEqual(t, http.StatusCreated, resp.Code)
			assert.False(t, gitRepo.IsBranchExist("merge-queue/main/999"))

			// a reader can't add it
			testPullMergeForm(t, readerSession, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge"})
			assert.Nil(t, entry(pr))

			add(t, session, pr)
			require.NotNil(t, entry(pr))
			req = NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/%s/pulls/%s/merge-queue", repo.FullName(), index(pr))).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusNoContent)
			assert.Nil(t, entry(pr))
			assert.Equal(t, mergequeue.ReasonRemoved, removedReason(pr))
		})

		t.Run("Each tested on the ones ahead, merged as tested", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			tip := mainTip()
			a, b, c := newPull(t), newPull(t), newPull(t)
			add(t, session, a)
			add(t, mergerSession, b)
			add(t, session, c)

			ea, eb, ec := entry(a), entry(b), entry(c)
			require.NotNil(t, ea)
			require.NotNil(t, eb)
			require.NotNil(t, ec)
			assert.Equal(t, pull_model.MergeQueueBuilding, ea.Status)
			assert.Equal(t, tip, ea.BaseCommitID)
			assert.Equal(t, ea.TempCommitID, eb.BaseCommitID)
			assert.Equal(t, eb.TempCommitID, ec.BaseCommitID)
			sha, err := gitRepo.GetBranchCommitID(ec.TempBranch())
			require.NoError(t, err)
			assert.Equal(t, ec.TempCommitID, sha)
			// the test commit of c holds a, b and c
			commit, err := gitRepo.GetCommit(ec.TempCommitID)
			require.NoError(t, err)
			for _, f := range []string{"queue-2.txt", "queue-3.txt", "queue-4.txt"} {
				_, err = commit.GetTreeEntryByPath(f)
				require.NoError(t, err, f)
			}

			t.Run("merge_group run", func(t *testing.T) {
				run := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRun{RepoID: repo.ID, CommitSHA: ea.TempCommitID})
				assert.Equal(t, webhook_module.HookEventMergeGroup, run.Event)
				assert.Equal(t, git.BranchPrefix+ea.TempBranch(), run.Ref)
			})

			t.Run("Queue API", func(t *testing.T) {
				var list []*api.MergeQueueEntry
				resp := MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/merge-queue/main", repo.FullName())).AddTokenAuth(token), http.StatusOK)
				DecodeJSON(t, resp, &list)
				require.Len(t, list, 3)
				assert.Equal(t, a.Index, list[0].Number)
				assert.Equal(t, 1, list[0].Position)
				assert.Equal(t, mergequeue.StateTesting, list[0].State)
				assert.Equal(t, ec.TempCommitID, list[2].TestSHA)
				assert.Equal(t, merger.Name, list[1].EnqueuedBy.UserName)

				MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/merge-queue/no-such-branch", repo.FullName())).AddTokenAuth(token), http.StatusNotFound)
			})

			// b's test commit has a and b: its success merges both, each at its own test commit
			setStatus(t, statusCtx, eb.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
			assert.True(t, merged(b))
			assert.False(t, merged(c))
			assert.Equal(t, eb.TempCommitID, mainTip())
			pa := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: a.ID})
			assert.Equal(t, ea.TempCommitID, pa.MergedCommitID)
			assert.Nil(t, entry(a))
			assert.False(t, gitRepo.IsBranchExist(ea.TempBranch()))

			// c's build stays: it was made on b's test commit, which is main now
			assert.Equal(t, ec.TempCommitID, entry(c).TempCommitID)

			setStatus(t, statusCtx, ec.TempCommitID, api.CommitStatusFailure)
			assert.False(t, merged(c))
			assert.Nil(t, entry(c))
			assert.Equal(t, mergequeue.ReasonChecksFailed, removedReason(c))
			assert.Equal(t, eb.TempCommitID, mainTip())
		})

		t.Run("A failure rebuilds the ones behind without it", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			tip := mainTip()
			a, b := newPull(t), newPull(t)
			add(t, session, a)
			add(t, session, b)
			ea, eb := entry(a), entry(b)
			assert.Equal(t, ea.TempCommitID, eb.BaseCommitID)

			setStatus(t, statusCtx, ea.TempCommitID, api.CommitStatusFailure)
			assert.Nil(t, entry(a))
			eb2 := entry(b)
			require.NotNil(t, eb2)
			assert.Equal(t, tip, eb2.BaseCommitID)
			assert.NotEqual(t, eb.TempCommitID, eb2.TempCommitID)

			setStatus(t, statusCtx, eb2.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(b))
			assert.False(t, merged(a))
		})

		t.Run("A push to the branch rebuilds the queue", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			before := entry(a)
			_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "direct.txt", ContentReader: strings.NewReader("direct")}},
			})
			require.NoError(t, err)
			after := entry(a)
			require.NotNil(t, after)
			assert.Equal(t, mainTip(), after.BaseCommitID)
			assert.NotEqual(t, before.TempCommitID, after.TempCommitID)

			// a build that is no longer on top of main never merges
			setStatus(t, statusCtx, before.TempCommitID, api.CommitStatusSuccess)
			assert.False(t, merged(a))
			setStatus(t, statusCtx, after.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
		})

		t.Run("New commits take it out", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: a.HeadBranch,
				Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "more.txt", ContentReader: strings.NewReader("more")}},
			})
			require.NoError(t, err)
			// the pull request is updated in the background
			assert.Eventually(t, func() bool {
				e, err := pull_model.GetMergeQueueEntryByPullID(db.DefaultContext, a.ID)
				return err == nil && e == nil
			}, 10*time.Second, 50*time.Millisecond)
			assert.Equal(t, mergequeue.ReasonHeadMoved, removedReason(a))
		})

		t.Run("Remove from the web", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, mergerSession, a)
			link := fmt.Sprintf("/%s/pulls/%s/merge_queue/remove", repo.FullName(), index(a))
			readerSession.MakeRequest(t, NewRequest(t, "POST", link), NoExpectedStatus)
			require.NotNil(t, entry(a))
			session.MakeRequest(t, NewRequest(t, "POST", link), http.StatusSeeOther)
			assert.Nil(t, entry(a))
		})

		t.Run("Conflicts with the ones ahead", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			same := func(content string) *issues_model.PullRequest {
				pulls++
				branch := fmt.Sprintf("queue-%d", pulls)
				_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
					OldBranch: "main",
					NewBranch: branch,
					Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "same.txt", ContentReader: strings.NewReader(content)}},
				})
				require.NoError(t, err)
				testPullCreate(t, session, owner.Name, repo.Name, true, "main", branch, branch)
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: branch})
				head, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
				require.NoError(t, err)
				setStatus(t, statusCtx, head, api.CommitStatusSuccess)
				return pr
			}
			a, b := same("a"), same("b")
			add(t, session, a)
			add(t, session, b)
			require.NotNil(t, entry(a))
			assert.Nil(t, entry(b))
			assert.Equal(t, mergequeue.ReasonConflict, removedReason(b))
			MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/%s/pulls/%s/merge-queue", repo.FullName(), index(a))).AddTokenAuth(token), http.StatusNoContent)
		})

		t.Run("Check time-out", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			now := time.Now()
			defer timeutil.MockUnset()
			timeutil.MockSet(now)
			a := newPull(t)
			add(t, session, a)
			require.NotNil(t, entry(a))
			timeutil.MockSet(now.Add(59 * time.Minute))
			require.NoError(t, mergequeue.TriggerAll(t.Context()))
			settleMergeQueues(t)
			require.NotNil(t, entry(a))
			timeutil.MockSet(now.Add(61 * time.Minute))
			require.NoError(t, mergequeue.TriggerAll(t.Context()))
			settleMergeQueues(t)
			assert.Nil(t, entry(a))
			assert.Equal(t, mergequeue.ReasonTimeout, removedReason(a))
		})

		t.Run("Groups wait for the minimum size", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			editRule := func(opt *api.EditBranchProtectionOption) {
				MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/%s/branch_protections/main", repo.FullName()), opt).AddTokenAuth(token), http.StatusOK)
			}
			two, wait := 2, 5
			editRule(&api.EditBranchProtectionOption{MergeQueueMinGroupSize: &two, MergeQueueWaitMinutes: &wait})
			defer func() {
				zero := 0
				editRule(&api.EditBranchProtectionOption{MergeQueueMinGroupSize: &zero})
			}()
			bad := 4
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/%s/branch_protections/main", repo.FullName()), &api.EditBranchProtectionOption{MergeQueueMinGroupSize: &bad}).AddTokenAuth(token), http.StatusUnprocessableEntity)

			a, b := newPull(t), newPull(t)
			add(t, session, a)
			setStatus(t, statusCtx, entry(a).TempCommitID, api.CommitStatusSuccess)
			assert.False(t, merged(a))
			add(t, session, b)
			setStatus(t, statusCtx, entry(b).TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
			assert.True(t, merged(b))

			// alone, it merges once the wait time is over
			now := time.Now()
			defer timeutil.MockUnset()
			c := newPull(t)
			add(t, session, c)
			setStatus(t, statusCtx, entry(c).TempCommitID, api.CommitStatusSuccess)
			assert.False(t, merged(c))
			timeutil.MockSet(now.Add(6 * time.Minute))
			require.NoError(t, mergequeue.TriggerAll(t.Context()))
			settleMergeQueues(t)
			assert.True(t, merged(c))
		})

		t.Run("Merge when checks succeed joins the queue", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			pulls++
			branch := fmt.Sprintf("queue-%d", pulls)
			_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				NewBranch: branch,
				Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: branch + ".txt", ContentReader: strings.NewReader(branch)}},
			})
			require.NoError(t, err)
			testPullCreate(t, session, owner.Name, repo.Name, true, "main", branch, branch)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: branch})
			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge", "merge_when_checks_succeed": "true"})
			assert.Nil(t, entry(pr))
			head, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
			require.NoError(t, err)
			setStatus(t, statusCtx, head, api.CommitStatusSuccess)
			require.NotNil(t, entry(pr))
			setStatus(t, statusCtx, entry(pr).TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(pr))
		})

		t.Run("A fork's build runs like the fork's pull request", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			forker := forgery.CreateUser(t, nil)
			fork, err := repo_service.ForkRepositoryAndUpdates(t.Context(), forker, forker, repo_service.ForkRepoOptions{BaseRepo: repo, Name: repo.Name})
			require.NoError(t, err)
			// the fork changes the workflows: they must not run with the base repository's trust
			_, err = files_service.ChangeRepoFiles(t.Context(), fork, forker, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				NewBranch: "from-fork",
				Files: []*files_service.ChangeRepoFile{{
					Operation:     "create",
					TreePath:      ".forgejo/workflows/fork.yml",
					ContentReader: strings.NewReader("on: merge_group\njobs:\n  leak:\n    runs-on: docker\n    steps:\n      - run: true\n"),
				}},
			})
			require.NoError(t, err)
			forkToken := getTokenForLoggedInUser(t, loginUser(t, forker.Name), auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/pulls", repo.FullName()), &api.CreatePullRequestOption{Head: forker.Name + ":from-fork", Base: "main", Title: "from a fork"}).AddTokenAuth(forkToken)
			var pull api.PullRequest
			DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &pull)
			setStatus(t, statusCtx, pull.Head.Sha, api.CommitStatusSuccess)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: pull.Index})

			add(t, session, pr)
			e := entry(pr)
			require.NotNil(t, e)
			runs, err := db.Find[actions_model.ActionRun](t.Context(), actions_model.FindRunOptions{RepoID: repo.ID, CommitSHA: e.TempCommitID})
			require.NoError(t, err)
			require.NotEmpty(t, runs)
			for _, run := range runs {
				assert.True(t, run.IsForkPullRequest, run.WorkflowID)
				assert.NotEqual(t, "fork.yml", run.WorkflowID)
			}
			setStatus(t, statusCtx, e.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(pr))
		})

		t.Run("Web pages", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			b := newPull(t)
			prLink := func(pr *issues_model.PullRequest) string {
				return fmt.Sprintf("/%s/pulls/%s", repo.FullName(), index(pr))
			}

			// the merge box offers the queue, not a merge
			resp := session.MakeRequest(t, NewRequest(t, "GET", prLink(a)), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Add to merge queue")
			NewHTMLParser(t, resp.Body).AssertElement(t, "#merge-queue-info", true)

			add(t, mergerSession, a)
			add(t, mergerSession, b)
			for _, s := range []*TestSession{session, mergerSession, readerSession} {
				htmlDoc := NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", prLink(b)), http.StatusOK).Body)
				status := htmlDoc.Find("#merge-queue-status").Text()
				assert.Contains(t, status, "position 2 of 2")
				assert.Contains(t, status, merger.Name)
				// the one who added it and the repository's writers may remove it, a reader may not
				htmlDoc.AssertElement(t, fmt.Sprintf(`form[action="%s/merge_queue/remove"]`, prLink(b)), s != readerSession)
			}

			queue := fmt.Sprintf("/%s/merge-queue/main", repo.FullName())
			htmlDoc := NewHTMLParser(t, readerSession.MakeRequest(t, NewRequest(t, "GET", queue), http.StatusOK).Body)
			rows := htmlDoc.Find("#merge-queue-table tbody tr")
			require.Equal(t, 2, rows.Length())
			assert.Equal(t, 1, rows.Eq(0).Find(fmt.Sprintf(`a[href="%s"]`, prLink(a))).Length())
			assert.Equal(t, 1, rows.Eq(1).Find(fmt.Sprintf(`a[href="%s"]`, prLink(b))).Length())
			readerSession.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/merge-queue/no-such-branch", repo.FullName())), http.StatusNotFound)

			htmlDoc = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/branches", repo.FullName())), http.StatusOK).Body)
			htmlDoc.AssertElement(t, fmt.Sprintf(`a[href="%s"]`, queue), true)

			htmlDoc = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/settings/branches/edit?rule_name=main", repo.FullName())), http.StatusOK).Body)
			htmlDoc.AssertElement(t, `input[name="require_merge_queue"][checked]`, true)
			v, _ := htmlDoc.Find(`input[name="merge_queue_build_concurrency"]`).Attr("value")
			assert.Equal(t, "3", v)

			session.MakeRequest(t, NewRequest(t, "POST", prLink(a)+"/merge_queue/remove"), http.StatusSeeOther)
			session.MakeRequest(t, NewRequest(t, "POST", prLink(b)+"/merge_queue/remove"), http.StatusSeeOther)
			htmlDoc = NewHTMLParser(t, readerSession.MakeRequest(t, NewRequest(t, "GET", queue), http.StatusOK).Body)
			htmlDoc.AssertElement(t, "#merge-queue-empty", true)
		})

		t.Run("A merge under way can't be removed", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			e := entry(a)
			require.NotEmpty(t, e.TempCommitID)
			ok, err := pull_model.StartMergeQueueMerge(t.Context(), e.ID, e.TempCommitID)
			require.NoError(t, err)
			require.True(t, ok)
			req := NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/%s/pulls/%s/merge-queue", repo.FullName(), index(a))).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusConflict)
			require.NotNil(t, entry(a))
			// the queue goes on and merges it
			setStatus(t, statusCtx, e.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
		})

		t.Run("A merge pushed but never recorded is recorded", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			e := entry(a)
			ok, err := pull_model.StartMergeQueueMerge(t.Context(), e.ID, e.TempCommitID)
			require.NoError(t, err)
			require.True(t, ok)
			// the push went through, the server stopped before its post-receive hook
			require.NoError(t, git.NewCommand(t.Context(), "update-ref").AddDynamicArguments(git.BranchPrefix+"main", e.TempCommitID).Run(&git.RunOpts{Dir: repo.RepoPath()}))
			setStatus(t, statusCtx, e.TempCommitID, api.CommitStatusSuccess)
			assert.False(t, merged(a)) // another server may still be recording it
			_, err = db.GetEngine(t.Context()).Exec("UPDATE merge_queue_entry SET merging_unix = ? WHERE id = ?", timeutil.TimeStampNow()-3600, e.ID)
			require.NoError(t, err)
			setStatus(t, statusCtx, e.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
			assert.Nil(t, entry(a))
		})

		t.Run("Stale build branches are deleted", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			e := entry(a)
			stale := git.BranchPrefix + pull_model.MergeQueueBranchPrefix + "main/999999"
			other := git.BranchPrefix + pull_model.MergeQueueBranchPrefix + "main/x/" + strconv.FormatInt(e.ID, 10)
			for _, ref := range []string{stale, other} {
				require.NoError(t, git.NewCommand(t.Context(), "update-ref").AddDynamicArguments(ref, mainTip()).Run(&git.RunOpts{Dir: repo.RepoPath()}))
			}
			require.NoError(t, mergequeue.DeleteStaleBranches(t.Context()))
			assert.False(t, gitRepo.IsBranchExist(strings.TrimPrefix(stale, git.BranchPrefix)))
			// another branch's build with the ID of a live entry of main is no build of main
			assert.False(t, gitRepo.IsBranchExist(strings.TrimPrefix(other, git.BranchPrefix)))
			assert.True(t, gitRepo.IsBranchExist(e.TempBranch()))
			setStatus(t, statusCtx, e.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
		})

		t.Run("A pull request that changes nothing on top leaves", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			// b makes the same change as a
			_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				NewBranch: a.HeadBranch + "-again",
				Files: []*files_service.ChangeRepoFile{{
					Operation:     "create",
					TreePath:      a.HeadBranch + ".txt",
					ContentReader: strings.NewReader(a.HeadBranch),
				}},
			})
			require.NoError(t, err)
			testPullCreate(t, session, owner.Name, repo.Name, true, "main", a.HeadBranch+"-again", "again")
			b := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: a.HeadBranch + "-again"})
			head, err := gitRepo.GetRefCommitID(b.GetGitRefName())
			require.NoError(t, err)
			setStatus(t, statusCtx, head, api.CommitStatusSuccess)
			c := newPull(t)

			add(t, session, a)
			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(b), optionsPullMerge{"do": "rebase"})
			add(t, session, c)
			// b's rebase onto a's build is a's build: it leaves, and c is built behind a instead of the queue stalling
			assert.Nil(t, entry(b))
			assert.Equal(t, mergequeue.ReasonEmpty, removedReason(b))
			ea, ec := entry(a), entry(c)
			require.NotNil(t, ec)
			assert.Equal(t, ea.TempCommitID, ec.BaseCommitID)
			setStatus(t, statusCtx, ea.TempCommitID, api.CommitStatusSuccess)
			setStatus(t, statusCtx, ec.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
			assert.True(t, merged(c))
			assert.False(t, merged(b))
		})

		t.Run("A build that keeps failing leaves", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			setStatus(t, statusCtx, entry(a).TempCommitID, api.CommitStatusSuccess)
			require.True(t, merged(a))
			// b makes a's change again: a squash of it onto the branch commits nothing
			_, err := files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				NewBranch: a.HeadBranch + "-squash",
				Files: []*files_service.ChangeRepoFile{{
					Operation:     "create",
					TreePath:      a.HeadBranch + "-squash.txt",
					ContentReader: strings.NewReader("x"),
				}},
			})
			require.NoError(t, err)
			testPullCreate(t, session, owner.Name, repo.Name, true, "main", a.HeadBranch+"-squash", "squash")
			b := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: a.HeadBranch + "-squash"})
			head, err := gitRepo.GetRefCommitID(b.GetGitRefName())
			require.NoError(t, err)
			setStatus(t, statusCtx, head, api.CommitStatusSuccess)
			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(b), optionsPullMerge{"do": "squash"})
			e := entry(b)
			require.NotNil(t, e)
			// its file lands on the branch by another way, so the squash has nothing left to commit
			_, err = files_service.ChangeRepoFiles(t.Context(), repo, owner, &files_service.ChangeRepoFilesOptions{
				OldBranch: "main",
				Files: []*files_service.ChangeRepoFile{{
					Operation:     "create",
					TreePath:      a.HeadBranch + "-squash.txt",
					ContentReader: strings.NewReader("x"),
				}},
			})
			require.NoError(t, err)
			// a pass started by the push above can still hold the branch, and Process then returns at once
			assert.Eventually(t, func() bool {
				_ = mergequeue.Process(db.DefaultContext, repo.ID, "main")
				got, err := pull_model.GetMergeQueueEntryByPullID(db.DefaultContext, b.ID)
				return err == nil && got == nil
			}, 30*time.Second, 100*time.Millisecond)
			assert.Equal(t, mergequeue.ReasonBuildFailed, removedReason(b))
		})

		t.Run("A build pushed to the branch by a user is recorded", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			e := entry(a)
			require.NoError(t, git.NewCommand(t.Context(), "update-ref").AddDynamicArguments(git.BranchPrefix+"main", e.TempCommitID).Run(&git.RunOpts{Dir: repo.RepoPath()}))
			// a pass of the subtest before may still hold the branch, and Process then returns at once
			assert.Eventually(t, func() bool {
				_ = mergequeue.Process(db.DefaultContext, repo.ID, "main")
				pr := &issues_model.PullRequest{}
				has, err := db.GetEngine(db.DefaultContext).ID(a.ID).Get(pr)
				return err == nil && has && pr.HasMerged
			}, 30*time.Second, 100*time.Millisecond)
			assert.Nil(t, entry(a))
		})

		t.Run("The pull request's own checks don't pass its build", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			head, err := gitRepo.GetRefCommitID(a.GetGitRefName())
			require.NoError(t, err)
			// its "ci" status is older than the build
			_, err = db.GetEngine(t.Context()).Exec("UPDATE commit_status SET created_unix = created_unix - 10 WHERE repo_id = ? AND sha = ?", repo.ID, head)
			require.NoError(t, err)
			// a rebase onto an up-to-date branch: the build is the head commit of the pull request
			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(a), optionsPullMerge{"do": "rebase"})
			e := entry(a)
			require.NotNil(t, e)
			assert.Equal(t, head, e.TempCommitID)
			assert.False(t, merged(a))
			setStatus(t, statusCtx, e.TempCommitID, api.CommitStatusSuccess)
			assert.True(t, merged(a))
		})

		t.Run("Turning the queue off empties it", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			a := newPull(t)
			add(t, session, a)
			req := NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/%s/branch_protections/main", repo.FullName()), &api.EditBranchProtectionOption{RequireMergeQueue: new(bool)}).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusOK)
			require.NoError(t, mergequeue.TriggerAll(t.Context()))
			settleMergeQueues(t)
			assert.Nil(t, entry(a))
			assert.Equal(t, mergequeue.ReasonDisabled, removedReason(a))
		})
	})
}

func setStatus(t *testing.T, ctx APITestContext, sha string, state api.CommitStatusState) {
	t.Helper()
	doAPICreateCommitStatus(ctx, sha, api.CreateStatusOption{State: state, Context: "ci"})(t)
	settleMergeQueues(t)
}

// settleMergeQueues runs a pass of every merge queue in the test's own goroutine. A pass started elsewhere (the pull
// request check after a merge runs in a goroutine) can hold a branch, and a status or merge request then returns
// before that pass took it into account; waiting until a pass of our own runs means the test sees the result.
func settleMergeQueues(t *testing.T) {
	t.Helper()
	keys, err := pull_model.FindMergeQueueKeys(db.DefaultContext)
	require.NoError(t, err)
	for _, k := range keys {
		assert.Eventually(t, func() bool {
			ran, err := mergequeue.TryProcess(db.DefaultContext, k.RepoID, k.BaseBranch)
			return ran || err != nil
		}, 30*time.Second, 50*time.Millisecond)
	}
}

// a repository in a project: the queue's builds, pushes and pages use the repository's own path
func TestPullMergeQueueInProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := t.Context()
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(ctx, org, "mq", "")
		require.NoError(t, err)
		repo, err := repo_service.CreateRepository(ctx, user2, org, repo_service.CreateRepoOptions{Name: "q", Readme: "Default", AutoInit: true, DefaultBranch: "main", GroupID: group.ID})
		require.NoError(t, err)
		session := loginUser(t, user2.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		web := "/org3/mq/q"
		apiRepo := "/api/v1/repos/org3/mq/q/-"

		session.MakeRequest(t, NewRequestWithValues(t, "POST", web+"/settings/branches/edit", map[string]string{
			"rule_name":             "main",
			"enable_push":           "all",
			"enable_status_check":   "true",
			"status_check_contexts": "ci",
			"require_merge_queue":   "true",
		}), http.StatusSeeOther)

		_, err = files_service.ChangeRepoFiles(ctx, repo, user2, &files_service.ChangeRepoFilesOptions{
			OldBranch: "main",
			NewBranch: "feature",
			Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "feature.txt", ContentReader: strings.NewReader("feature")}},
		})
		require.NoError(t, err)
		req := NewRequestWithJSON(t, "POST", apiRepo+"/pulls", &api.CreatePullRequestOption{Head: "feature", Base: "main", Title: "feature"}).AddTokenAuth(token)
		var pull api.PullRequest
		DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &pull)
		statusCtx := APITestContext{Session: session, Token: token, Username: "org3", Reponame: "mq/q/-"}
		setStatus(t, statusCtx, pull.Head.Sha, api.CommitStatusSuccess)

		req = NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/pulls/%d/merge-queue", apiRepo, pull.Index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(token)
		var e api.MergeQueueEntry
		DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &e)
		require.NotEmpty(t, e.TestSHA)

		htmlDoc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/pulls/%d", web, pull.Index)), http.StatusOK).Body)
		queueLink, _ := htmlDoc.Find("#merge-queue-status ~ div a.button").Attr("href")
		assert.Equal(t, web+"/merge-queue/main", queueLink)
		htmlDoc.AssertElement(t, fmt.Sprintf(`form[action="%s/pulls/%d/merge_queue/remove"]`, web, pull.Index), true)
		htmlDoc = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", queueLink), http.StatusOK).Body)
		assert.Equal(t, 1, htmlDoc.Find("#merge-queue-table tbody tr").Length())
		req = NewRequest(t, "GET", apiRepo+"/merge-queue/main").AddTokenAuth(token)
		var list []*api.MergeQueueEntry
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &list)
		assert.Len(t, list, 1)

		setStatus(t, statusCtx, e.TestSHA, api.CommitStatusSuccess)
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: pull.Index})
		assert.True(t, pr.HasMerged)
		assert.Equal(t, e.TestSHA, pr.MergedCommitID)
	})
}
