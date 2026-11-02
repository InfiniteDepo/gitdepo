// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/git"
)

// maxLsRemoteOutput bounds what an upstream can make us keep from `git ls-remote`.
const maxLsRemoteOutput = 1 << 20

type cappedWriter struct {
	bytes.Buffer
	truncated bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	room := max(maxLsRemoteOutput-w.Len(), 0)
	w.Buffer.Write(p[:min(len(p), room)])
	w.truncated = w.truncated || len(p) > room
	return len(p), nil
}

// upstreamRefs is what the remote has for the mirror's filter: its HEAD branch and which exact refs exist.
type upstreamRefs struct {
	head    string
	present map[string]bool
}

// addLsRemoteArgs adds `ls-remote --symref -- <remote name> HEAD <exact refs>`. There is no --heads/--tags (they would
// hide the HEAD line) and the remote is the configured one by name, never a URL.
func addLsRemoteArgs(cmd *git.Command, m *repo_model.Mirror) *git.Command {
	return cmd.AddArguments("ls-remote", "--symref").
		AddDashesAndList(append([]string{m.GetRemoteName(), "HEAD"}, m.ExactRefs()...)...)
}

// lsRemoteUpstream asks the remote (by name, so the stored URL settings apply) for HEAD and the exact refs of the
// filters. Patterns of `ls-remote` match the tail of a ref, so the result is only used by exact comparison.
func lsRemoteUpstream(ctx context.Context, m *repo_model.Mirror, remoteAddr string, env []string, timeout time.Duration) (*upstreamRefs, error) {
	cmd := git.NewCommand(ctx)
	_, credCleanup, err := cmd.AddAuthCredentialHelperForRemote(remoteAddr)
	if err != nil {
		return nil, err
	}
	defer credCleanup()

	stdout := &cappedWriter{}
	stderr := &cappedWriter{}
	if err := addLsRemoteArgs(cmd, m).
		SetDescription(fmt.Sprintf("Mirror.lsRemote: %s", m.Repo.FullName())).
		Run(&git.RunOpts{Timeout: timeout, Dir: m.Repo.RepoPath(), Env: env, Stdout: stdout, Stderr: stderr}); err != nil {
		return nil, fmt.Errorf("ls-remote: %w: %s", err, stderr.String())
	}

	if stdout.truncated {
		// refs past the cut would look missing upstream and be dropped from the fetch
		return nil, errors.New("ls-remote: output is too large")
	}

	up := &upstreamRefs{present: map[string]bool{}}
	for line := range strings.SplitSeq(stdout.String(), "\n") {
		if target, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
			up.head, _, _ = strings.Cut(target, "\t")
		} else if _, ref, ok := strings.Cut(line, "\t"); ok {
			up.present[ref] = true
		}
	}
	return up, nil
}

// filterErrorFor returns the value for Mirror.FilterError: the upstream HEAD branch name when the branch filter
// excludes it. The name comes from the remote, so it is cut and stripped of control characters.
func filterErrorFor(m *repo_model.Mirror, head string) string {
	if head == "" || repo_model.MatchRefFilter(m.BranchFilter, head) {
		return ""
	}
	head = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(head, ""))
	if r := []rune(head); len(r) > 255 {
		head = string(r[:255])
	}
	return head
}

// applyRefFilter deletes the local refs the mirror's filters exclude: branches and tags that don't match, and every
// other ref (refs/pull, refs/changes, notes, ...). HEAD's target and the default branch are always kept. A mirror has
// no pull requests of its own (CanEnablePulls), so no AGit pull request ref can be among them; the notification loop
// in SyncPullMirror skips refs/pull anyway. If something
// was deleted, the objects that are no longer reachable are removed too, so an excluded commit can't be read by its
// SHA. It returns the deletions for the usual ref-deleted notifications; the caller rewrites the commit graph.
//
// absent holds the local refs of exact patterns that the remote no longer has: they are not fetched, so `fetch --prune`
// can't delete them, and they are deleted here.
func applyRefFilter(ctx context.Context, m *repo_model.Mirror, repoPath string, absent []string) ([]*mirrorSyncResult, error) {
	opts := &git.RunOpts{Dir: repoPath}
	out, _, err := git.NewCommand(ctx, "for-each-ref", "--format=%(refname) %(objectname)").RunStdString(opts)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{"refs/heads/" + m.Repo.DefaultBranch: true}
	if head, _, err := git.NewCommand(ctx, "symbolic-ref", "-q", "HEAD").RunStdString(opts); err == nil {
		keep[strings.TrimSpace(head)] = true
	}

	var results []*mirrorSyncResult
	var stdin strings.Builder
	for line := range strings.SplitSeq(out, "\n") {
		ref, sha, ok := strings.Cut(line, " ")
		if !ok || keep[ref] {
			continue
		}
		if !slices.Contains(absent, ref) {
			if name, ok := strings.CutPrefix(ref, "refs/heads/"); ok && repo_model.MatchRefFilter(m.BranchFilter, name) {
				continue
			}
			if name, ok := strings.CutPrefix(ref, "refs/tags/"); ok && repo_model.MatchRefFilter(m.TagFilter, name) {
				continue
			}
		}
		stdin.WriteString("delete " + ref + "\n")
		results = append(results, &mirrorSyncResult{refName: git.RefName(ref), oldCommitID: sha, newCommitID: gitShortEmptySha})
	}
	if len(results) == 0 {
		return nil, nil
	}

	if _, _, err := git.NewCommand(ctx, "update-ref", "--stdin").RunStdString(&git.RunOpts{Dir: repoPath, Stdin: strings.NewReader(stdin.String())}); err != nil {
		return nil, err
	}
	// the refs are gone already; if this fails, the unreachable objects stay until the next narrowing or a gc
	if _, _, err := git.NewCommand(ctx, "repack", "-a", "-d", "-q").RunStdString(opts); err != nil {
		return results, fmt.Errorf("refs deleted, but repack failed: %w", err)
	}
	if _, _, err := git.NewCommand(ctx, "prune", "--expire=now").RunStdString(opts); err != nil {
		return results, fmt.Errorf("refs deleted, but prune failed: %w", err)
	}
	return results, nil
}

// FilterNewMirror applies the (normalized) filters of m to a repository that was just cloned with `--mirror`, before
// anything is read from it. If the clone's HEAD branch is excluded, the first matching branch (by name) becomes HEAD;
// it is an error if no branch matches.
func FilterNewMirror(ctx context.Context, repo *repo_model.Repository, m *repo_model.Mirror) error {
	m.Repo = repo
	repoPath := repo.RepoPath()
	opts := &git.RunOpts{Dir: repoPath}
	out, _, err := git.NewCommand(ctx, "for-each-ref", "--format=%(refname:strip=2)", "refs/heads").RunStdString(opts)
	if err != nil {
		return err
	}
	if branches := strings.Fields(out); len(branches) > 0 { // an empty upstream has nothing to filter
		head, _, _ := git.NewCommand(ctx, "symbolic-ref", "-q", "--short", "HEAD").RunStdString(opts)
		if head = strings.TrimSpace(head); head == "" || !repo_model.MatchRefFilter(m.BranchFilter, head) {
			i := slices.IndexFunc(branches, func(b string) bool { return repo_model.MatchRefFilter(m.BranchFilter, b) })
			if i < 0 {
				return errors.New("no branch of the repository matches the branch filter")
			}
			if _, _, err := git.NewCommand(ctx, "symbolic-ref", "HEAD").AddDynamicArguments("refs/heads/" + branches[i]).RunStdString(opts); err != nil {
				return err
			}
		}
	}
	_, applyErr := applyRefFilter(ctx, m, repoPath, nil)
	return applyErr
}
