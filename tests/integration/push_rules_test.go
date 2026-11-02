// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	private_router "forgejo.org/routers/private"
	app_context "forgejo.org/services/context"
	"forgejo.org/services/forms"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushRuleCommit commits content to file (or removes the file if content is empty) with the given author and message.
func pushRuleCommit(t *testing.T, dstPath, file, content, email, message string) string {
	t.Helper()
	fullPath := filepath.Join(dstPath, file)
	if content == "" {
		require.NoError(t, os.Remove(fullPath))
	} else {
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
	}
	require.NoError(t, git.AddChanges(dstPath, true))
	sig := &git.Signature{Email: email, Name: "Pusher", When: time.Now()}
	require.NoError(t, git.CommitChanges(dstPath, git.CommitChangesOptions{Committer: sig, Author: sig, Message: message}))
	return gitHead(t, dstPath)
}

func gitOutput(t *testing.T, dstPath string, args ...string) string {
	t.Helper()
	out, _, err := git.NewCommand(git.DefaultContext).AddArguments(git.ToTrustedCmdArgs(args)...).RunStdString(&git.RunOpts{Dir: dstPath})
	require.NoError(t, err)
	return strings.TrimSpace(out)
}

func TestPushRules(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner := NewAPITestContext(t, "user2", "push-rules", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		t.Run("CreateRepository", doAPICreateRepository(owner, nil, git.Sha1ObjectFormat))
		t.Run("AddCollaborator", doAPIAddCollaborator(owner, "user4", perm.AccessModeWrite))
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", Name: "push-rules"})
		settingsURL := "/user2/push-rules/settings/push_rules"
		apiURL := "/api/v1/repos/user2/push-rules"

		remote := *u
		remote.Path = owner.GitPath()
		remote.User = url.UserPassword("user2", userPassword)
		user2 := branchPusher{remote: &remote}
		dstPath := t.TempDir()
		t.Run("Clone", doGitClone(dstPath, &remote))
		master := gitHead(t, dstPath)

		setRule := func(t *testing.T, values map[string]string) {
			t.Helper()
			loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, values), http.StatusSeeOther)
		}
		// push commits start..head of a commit list built on master to branch
		push := func(t *testing.T, ref string) (string, error) {
			t.Helper()
			return user2.push(t, dstPath, "HEAD:"+ref)
		}
		reset := func(t *testing.T) { doGitCheckoutBranch(dstPath, "-B", "work", master)(t) }

		t.Run("Settings", func(t *testing.T) {
			user4 := loginUser(t, "user4")
			user4.MakeRequest(t, NewRequest(t, "GET", settingsURL), http.StatusNotFound)
			user4.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, map[string]string{"branch_name_regex": "^x"}), http.StatusNotFound)

			session := loginUser(t, "user2")
			resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, map[string]string{"commit_message_regex": "("}), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Invalid push rule")
			resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, map[string]string{"banned_file_patterns": "[a"}), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Invalid push rule")
			rule, err := git_model.GetPushRule(t.Context(), repo.ID)
			require.NoError(t, err)
			assert.Nil(t, rule)

			setRule(t, map[string]string{"branch_name_regex": "^x", "require_verified_author_email": "on", "max_file_size_mb": "3"})
			rule, err = git_model.GetPushRule(t.Context(), repo.ID)
			require.NoError(t, err)
			assert.Equal(t, "^x", rule.BranchNameRegex)
			assert.True(t, rule.RequireVerifiedAuthorEmail)
			assert.EqualValues(t, 3, rule.MaxFileSizeMB)
			resp = session.MakeRequest(t, NewRequest(t, "GET", settingsURL), http.StatusOK)
			assert.Contains(t, resp.Body.String(), `value="^x"`)
			setRule(t, map[string]string{})
		})

		reset(t)
		pushRuleCommit(t, dstPath, "old.txt", "old", "user2@example.com", "bad old message")
		_, err := push(t, "refs/heads/old")
		require.NoError(t, err)
		oldHead := gitHead(t, dstPath)
		var side string

		t.Run("CommitMessage", func(t *testing.T) {
			setRule(t, map[string]string{"commit_message_regex": `^ABC-\d+ `, "commit_message_banned_regex": "WIP"})
			reset(t)
			pushRuleCommit(t, dstPath, "a.txt", "1", "user2@example.com", "ABC-1 good")
			pushRuleCommit(t, dstPath, "b.txt", "2", "user2@example.com", "bad")
			stderr, err := push(t, "refs/heads/msg")
			require.Error(t, err)
			assert.Contains(t, stderr, "message does not match")

			reset(t)
			pushRuleCommit(t, dstPath, "a.txt", "1", "user2@example.com", "ABC-1 WIP")
			stderr, err = push(t, "refs/heads/msg")
			require.Error(t, err)
			assert.Contains(t, stderr, "matches the banned pattern")

			reset(t)
			pushRuleCommit(t, dstPath, "a.txt", "1", "user2@example.com", "ABC-1 good")
			_, err = push(t, "refs/heads/msg")
			require.NoError(t, err)

			// a bad commit already on a branch isn't checked again
			doGitCheckoutBranch(dstPath, "-B", "work", oldHead)(t)
			pushRuleCommit(t, dstPath, "c.txt", "3", "user2@example.com", "ABC-2 on old")
			_, err = push(t, "refs/heads/old2")
			require.NoError(t, err)

			// a commit only a tag points to is checked when it enters a branch
			reset(t)
			pushRuleCommit(t, dstPath, "d.txt", "4", "user2@example.com", "bad tagged")
			_, err = push(t, "refs/tags/bad-tag")
			require.NoError(t, err)
			stderr, err = push(t, "refs/heads/from-tag")
			require.Error(t, err)
			assert.Contains(t, stderr, "message does not match")

			// merge commits are checked
			reset(t)
			pushRuleCommit(t, dstPath, "side.txt", "side", "user2@example.com", "ABC-3 side")
			side = gitHead(t, dstPath)
			_, err = push(t, "refs/heads/side")
			require.NoError(t, err)
			reset(t)
			merge := gitOutput(t, dstPath, "commit-tree", side+"^{tree}", "-p", master, "-p", side, "-m", "Merge side")
			stderr, err = user2.push(t, dstPath, merge+":refs/heads/master")
			require.Error(t, err)
			assert.Contains(t, stderr, "message does not match")
		})

		// a merge whose parents are both on branches already, but which adds a file itself
		t.Run("EvilMerge", func(t *testing.T) {
			setRule(t, map[string]string{"banned_file_patterns": ".env", "max_file_size_mb": "1"})
			for file, expected := range map[string]string{"cfg/.env": `file "cfg/.env" matches a banned file pattern`, "big.bin": `file "big.bin" is 2.0 MB`} {
				doGitCheckoutBranch(dstPath, "-B", "work", side)(t)
				require.NoError(t, os.MkdirAll(filepath.Join(dstPath, "cfg"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dstPath, file), []byte(strings.Repeat("x", 2<<20)), 0o644))
				require.NoError(t, git.AddChanges(dstPath, true))
				merge := gitOutput(t, dstPath, "commit-tree", gitOutput(t, dstPath, "write-tree"), "-p", master, "-p", side, "-m", "ABC-5 evil merge")
				gitOutput(t, dstPath, "reset", "--hard")
				stderr, err := user2.push(t, dstPath, merge+":refs/heads/evil")
				require.Error(t, err)
				assert.Contains(t, stderr, expected)
			}
		})

		t.Run("Files", func(t *testing.T) {
			setRule(t, map[string]string{"banned_file_patterns": "*.exe;id_rsa", "max_file_size_mb": "1"})
			reset(t)
			pushRuleCommit(t, dstPath, "sub/dir/x.tar.exe", "MZ", "user2@example.com", "add")
			pushRuleCommit(t, dstPath, "sub/dir/x.tar.exe", "", "user2@example.com", "remove")
			stderr, err := push(t, "refs/heads/files")
			require.Error(t, err)
			assert.Contains(t, stderr, `file "sub/dir/x.tar.exe" matches a banned file pattern`)

			reset(t)
			pushRuleCommit(t, dstPath, "big.bin", strings.Repeat("x", 2<<20), "user2@example.com", "big")
			stderr, err = push(t, "refs/heads/files")
			require.Error(t, err)
			assert.Contains(t, stderr, `file "big.bin" is 2.0 MB, larger than the 1 MB limit`)

			reset(t)
			pushRuleCommit(t, dstPath, "small.bin", strings.Repeat("x", 1<<20), "user2@example.com", "small")
			_, err = push(t, "refs/heads/files")
			require.NoError(t, err)
		})

		t.Run("Limits", func(t *testing.T) {
			setRule(t, map[string]string{"commit_message_regex": "."})
			reset(t)
			for i := range 3 {
				pushRuleCommit(t, dstPath, fmt.Sprintf("n%d.txt", i), "n", "user2@example.com", "n")
			}
			defer test.MockVariableValue(&private_router.PushRuleMaxCommits, 2)()
			stderr, err := push(t, "refs/heads/limits")
			require.Error(t, err)
			assert.Contains(t, stderr, "more than 2 new commits")

			setRule(t, map[string]string{"banned_file_patterns": "nothing"})
			reset(t)
			for i := range 3 {
				require.NoError(t, os.WriteFile(filepath.Join(dstPath, fmt.Sprintf("p%d.txt", i)), []byte("p"), 0o644))
			}
			pushRuleCommit(t, dstPath, "p3.txt", "p", "user2@example.com", "paths")
			defer test.MockVariableValue(&private_router.PushRuleMaxPaths, 3)()
			stderr, err = push(t, "refs/heads/limits")
			require.Error(t, err)
			assert.Contains(t, stderr, "more than 3 files")
		})

		t.Run("AuthorEmail", func(t *testing.T) {
			setRule(t, map[string]string{"require_verified_author_email": "on"})
			for email, ok := range map[string]bool{
				"someone@example.org":       false,
				"user2-2@example.com":       false, // not activated
				"USER2@example.com":         true,
				"user2@noreply.example.org": true, // placeholder email
			} {
				reset(t)
				pushRuleCommit(t, dstPath, "author.txt", email, email, "author")
				stderr, err := push(t, "refs/heads/author-"+strings.ReplaceAll(email, "@", "-at-"))
				if ok {
					require.NoError(t, err, email)
				} else {
					require.Error(t, err, email)
					assert.Contains(t, stderr, "is not a verified email of user2")
				}
			}
		})

		t.Run("BranchName", func(t *testing.T) {
			setRule(t, map[string]string{"branch_name_regex": "^(feature|bugfix)/"})
			reset(t)
			pushRuleCommit(t, dstPath, "branch.txt", "b", "user2@example.com", "branch")
			stderr, err := push(t, "refs/heads/wrong")
			require.Error(t, err)
			assert.Contains(t, stderr, `branch name "wrong" does not match`)
			_, err = push(t, "refs/heads/feature/ok")
			require.NoError(t, err)
			// existing branches can still be pushed to
			doGitCheckoutBranch(dstPath, "-B", "work", oldHead)(t)
			pushRuleCommit(t, dstPath, "branch.txt", "c", "user2@example.com", "branch")
			_, err = push(t, "refs/heads/old")
			require.NoError(t, err)

			// the default branch is exempt when it is created
			extra := private.HookPreReceive(t.Context(), repoIDByName(t, "user2", "push-rules"), private.HookOptions{
				OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()},
				NewCommitIDs: []string{master},
				RefFullNames: []git.RefName{git.RefNameFromBranch("master")},
				UserID:       2,
				UserName:     "user2",
			})
			require.NoError(t, extra.Error)

			// renaming
			token := owner.Token
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiURL+"/branches/old", &api.UpdateBranchRepoOption{Name: "renamed"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiURL+"/branches/old", &api.UpdateBranchRepoOption{Name: "feature/renamed"}).AddTokenAuth(token), http.StatusNoContent)
			session := loginUser(t, "user2")
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/push-rules/settings/rename_branch", map[string]string{"from": "feature/renamed", "to": "renamed"}), http.StatusSeeOther)
			flash := session.GetCookie(app_context.CookieNameFlash)
			require.NotNil(t, flash)
			assert.Contains(t, flash.Value, "does%2Bnot%2Bmatch%2Bthe%2Bpush%2Brule")
			MakeRequest(t, NewRequest(t, "GET", apiURL+"/branches/feature/renamed").AddTokenAuth(token), http.StatusOK)
		})

		t.Run("WebEditAndMerge", func(t *testing.T) {
			setRule(t, map[string]string{"commit_message_regex": `^ABC-\d+ `})
			token := owner.Token
			req := NewRequestWithJSON(t, "POST", apiURL+"/contents/web.txt", &api.CreateFileOptions{
				FileOptions:   api.FileOptions{Message: "bad web edit"},
				ContentBase64: "aGk=",
			}).AddTokenAuth(token)
			resp := MakeRequest(t, req, http.StatusForbidden)
			assert.Contains(t, resp.Body.String(), "message does not match")
			req = NewRequestWithJSON(t, "POST", apiURL+"/contents/web.txt", &api.CreateFileOptions{
				FileOptions:   api.FileOptions{Message: "ABC-6 web edit"},
				ContentBase64: "aGk=",
			}).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusCreated)

			reset(t)
			pushRuleCommit(t, dstPath, "pr.txt", "pr", "user2@example.com", "ABC-7 pr")
			_, err := push(t, "refs/heads/pr")
			require.NoError(t, err)
			pr, err := doAPICreatePullRequest(owner, "user2", "push-rules", "master", "pr")(t)
			require.NoError(t, err)

			conflict := owner
			conflict.ExpectedCode = http.StatusConflict
			resp = doAPIMergePullRequestForm(t, conflict, "user2", "push-rules", pr.Index, &forms.MergePullRequestForm{Do: "squash", MergeTitleField: "bad squash"})
			assert.Contains(t, resp.Body.String(), "message does not match")
			doAPIMergePullRequestForm(t, owner, "user2", "push-rules", pr.Index, &forms.MergePullRequestForm{Do: "squash", MergeTitleField: "ABC-8 squash"})
		})

		// Calls the pre-receive hook the way the SSH command does for a deploy key, so this runs without an ssh client.
		t.Run("DeployKeyHook", func(t *testing.T) {
			keys := createProtectionTestDeployKeys(t, owner)
			setRule(t, map[string]string{"commit_message_regex": `^ABC-\d+ `, "require_verified_author_email": "on"})
			reset(t)
			foreign := pushRuleCommit(t, dstPath, "key.txt", "1", "someone@example.org", "ABC-9 foreign author")
			_, err := push(t, "refs/tags/key-foreign")
			require.NoError(t, err)
			badMessage := pushRuleCommit(t, dstPath, "key.txt", "2", "someone@example.org", "bad")
			_, err = push(t, "refs/tags/key-bad")
			require.NoError(t, err)

			preReceive := func(deployKeyKeyID int64, newCommitID string) private.ResponseExtra {
				return private.HookPreReceive(t.Context(), repoIDByName(t, "user2", "push-rules"), private.HookOptions{
					OldCommitIDs:   []string{master},
					NewCommitIDs:   []string{newCommitID},
					RefFullNames:   []git.RefName{git.RefNameFromBranch("master")},
					UserID:         2,
					UserName:       "user2",
					DeployKeyKeyID: deployKeyKeyID,
				})
			}
			require.NoError(t, preReceive(keys["listed"].keyID, foreign).Error)
			extra := preReceive(keys["listed"].keyID, badMessage)
			assert.Equal(t, http.StatusForbidden, extra.StatusCode)
			assert.Contains(t, extra.UserMsg, "message does not match")
			// without the deploy key, the author is checked against user2
			extra = preReceive(0, foreign)
			assert.Equal(t, http.StatusForbidden, extra.StatusCode)
			assert.Contains(t, extra.UserMsg, "is not a verified email of user2")
		})

		t.Run("Archived", func(t *testing.T) {
			archived := true
			t.Run("Archive", doAPIEditRepository(owner, &api.EditRepoOption{Archived: &archived}))
			loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, map[string]string{"branch_name_regex": "^archived"}), NoExpectedStatus)
			rule, err := git_model.GetPushRule(t.Context(), repo.ID)
			require.NoError(t, err)
			assert.Empty(t, rule.BranchNameRegex)
		})
	})
}
