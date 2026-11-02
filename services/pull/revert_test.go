// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/git"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRevertBase(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.com", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	run("init", "--bare", "-q", ".")
	tree := run("hash-object", "-t", "tree", "-w", "--stdin")
	commit := func(msg string, parents ...string) string {
		args := []string{"commit-tree", tree, "-m", msg}
		for _, p := range parents {
			args = append(args, "-p", p)
		}
		return run(args...)
	}

	b0 := commit("base")
	p1 := commit("pr 1", b0)
	p2 := commit("pr 2", p1)
	b1 := commit("later base", b0)
	mergeCommit := commit("merge", b1, p2)
	squashed := commit("squash", b1)
	evil := commit("evil", b0)
	mergeHead := commit("merge head", evil, p1) // a PR head that is itself a merge commit

	gitRepo, err := git.OpenRepository(t.Context(), dir)
	require.NoError(t, err)
	defer gitRepo.Close()

	cases := []struct {
		name string
		pr   issues_model.PullRequest
		head string
		want string
	}{
		{"not merged", issues_model.PullRequest{MergedCommitID: mergeCommit}, p2, ""},
		{"stored base", issues_model.PullRequest{HasMerged: true, MergedCommitID: squashed, MergedBaseCommitID: b1}, p2, b1},
		{"fast-forward", issues_model.PullRequest{HasMerged: true, MergedCommitID: p2, MergeBase: b0}, p2, b0},
		{"merge commit of head", issues_model.PullRequest{HasMerged: true, MergedCommitID: mergeCommit, MergeBase: b0}, p2, b1},
		{"merge commit of another head", issues_model.PullRequest{HasMerged: true, MergedCommitID: mergeCommit, MergeBase: b0}, p1, ""},
		{"fast-forwarded merge-commit head", issues_model.PullRequest{HasMerged: true, MergedCommitID: mergeHead, MergeBase: b0}, mergeHead, b0},
		{"single commit squashed", issues_model.PullRequest{HasMerged: true, MergedCommitID: squashed, MergeBase: b0}, p1, b1},
		{"multi-commit squashed", issues_model.PullRequest{HasMerged: true, MergedCommitID: squashed, MergeBase: b0}, p2, ""},
		{"unknown commit", issues_model.PullRequest{HasMerged: true, MergedCommitID: strings.Repeat("1", 40), MergeBase: b0}, p2, ""},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.pr.Index = int64(i + 1)
			run("update-ref", c.pr.GetGitRefName(), c.head)
			got, err := GetRevertBase(gitRepo, &c.pr)
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestRevertBranchName(t *testing.T) {
	for head, want := range map[string]string{
		"feature/x":   "revert-7-feature/x",
		"fix.1_a-b":   "revert-7-fix.1_a-b",
		"bad name":    "revert-7",
		"ünicode":     "revert-7",
		"a..b":        "revert-7",
		"x.lock":      "revert-7",
		"$(whoami)":   "revert-7",
		"trailing/":   "revert-7",
		"refs/heads/": "revert-7",
	} {
		assert.Equal(t, want, RevertBranchName(&issues_model.PullRequest{Index: 7, HeadBranch: head}), head)
	}
}
