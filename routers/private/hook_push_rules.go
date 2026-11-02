// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package private

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	git_model "forgejo.org/models/git"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
)

// Limits per hook request, so a huge push can't stall the hook. Vars so tests can lower them.
var (
	PushRuleMaxCommits = 1000
	PushRuleMaxPaths   = 100_000
)

const pushRuleMaxOutput = 16 << 20 // bytes buffered from one git command

var errPushTooLarge = errors.New("push too large to check")

// pushRuleError is a rejection reported to the pusher.
type pushRuleError string

func (e pushRuleError) Error() string { return string(e) }

// cappedBuffer fails writes past pushRuleMaxOutput, so a truncated output is never evaluated.
type cappedBuffer struct {
	bytes.Buffer
	full bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > pushRuleMaxOutput {
		b.full = true
		return 0, errPushTooLarge
	}
	return b.Buffer.Write(p)
}

func (ctx *preReceiveContext) runCapped(cmd *git.Command, stdin string) ([]byte, error) {
	var stdout cappedBuffer
	var stderr bytes.Buffer
	err := cmd.Run(&git.RunOpts{Dir: ctx.Repo.Repository.RepoPath(), Env: ctx.env, Stdin: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr})
	if stdout.full {
		return nil, errPushTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// checkPushRules checks the repository's push rule against a branch update. If the update is rejected, it writes
// the response and returns false.
func (ctx *preReceiveContext) checkPushRules(oldCommitID, newCommitID, branchName string) bool {
	repo := ctx.Repo.Repository
	emptyID := ctx.Repo.GetObjectFormat().EmptyObjectID().String()
	if ctx.opts.IsWiki || newCommitID == emptyID {
		return true
	}
	if !ctx.gotPushRule {
		rule, err := git_model.GetPushRule(ctx, repo.ID)
		if err == nil && rule != nil {
			err = rule.Compile()
		}
		if err != nil {
			log.Error("Unable to load the push rule of %-v: %v", repo, err)
			ctx.JSON(http.StatusInternalServerError, private.Response{Err: fmt.Sprintf("Unable to load the push rule: %v", err)})
			return false
		}
		ctx.pushRule, ctx.gotPushRule = rule, true
	}
	rule := ctx.pushRule
	if rule == nil {
		return true
	}

	err := ctx.checkPushRule(rule, oldCommitID == emptyID, newCommitID, branchName)
	var ruleErr pushRuleError
	switch {
	case err == nil:
		ctx.pushRuleCheckedTips = append(ctx.pushRuleCheckedTips, newCommitID)
		return true
	case errors.As(err, &ruleErr), errors.Is(err, errPushTooLarge):
		log.Warn("Forbidden: push to branch %s in %-v rejected by push rule: %v", branchName, repo, err)
		ctx.refuse(http.StatusForbidden, "push_rule", git.BranchPrefix+branchName, fmt.Sprintf("push rule: %v", err))
	default:
		log.Error("Unable to check the push rule for branch %s in %-v: %v", branchName, repo, err)
		ctx.JSON(http.StatusInternalServerError, private.Response{Err: fmt.Sprintf("Unable to check the push rule: %v", err)})
	}
	return false
}

func (ctx *preReceiveContext) checkPushRule(rule *git_model.PushRule, isCreate bool, newCommitID, branchName string) error {
	if isCreate && rule.BranchNameRe != nil && branchName != ctx.Repo.Repository.DefaultBranch && !rule.BranchNameRe.MatchString(branchName) {
		return pushRuleError(fmt.Sprintf("branch name %q does not match %q", branchName, rule.BranchNameRegex))
	}
	// the author rule only applies to the pusher's own commits, not to deploy keys, Actions or PR merges
	checkAuthor := rule.RequireVerifiedAuthorEmail && ctx.opts.DeployKeyKeyID == 0 && ctx.opts.UserID != user_model.ActionsUserID && ctx.opts.PullRequestID == 0
	checkFiles := rule.MaxFileSizeMB > 0 || len(rule.BannedFileGlobs) > 0
	if rule.CommitMessageRe == nil && rule.CommitMessageBannedRe == nil && !checkAuthor && !checkFiles {
		return nil
	}

	// New commits are those not on any branch yet, so commits that only a tag or a pull request ref points to are
	// checked when they enter a branch. Tips already checked in this request are excluded with their history.
	cmd := git.NewCommand(ctx, "log", "-z", "--format=%H%x00%ae%x00%B").
		AddOptionFormat("--max-count=%d", PushRuleMaxCommits+1).AddDynamicArguments(newCommitID)
	for _, tip := range ctx.pushRuleCheckedTips {
		cmd.AddDynamicArguments("^" + tip)
	}
	out, err := ctx.runCapped(cmd.AddArguments("--not", "--branches"), "")
	if err != nil {
		return err
	}
	// %B ends at the first NUL in a commit message, so the message rules only see the text before it.
	fields := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(out) == 0 {
		return nil
	} else if len(fields)%3 != 0 {
		return fmt.Errorf("unexpected git log output (%d fields)", len(fields))
	} else if len(fields)/3 > PushRuleMaxCommits {
		return pushRuleError(fmt.Sprintf("the push contains more than %d new commits, push them in smaller batches", PushRuleMaxCommits))
	}

	var allowedEmails map[string]bool
	if checkAuthor {
		emails, err := user_model.GetActivatedEmailAddresses(ctx, ctx.user.ID)
		if err != nil {
			return err
		}
		allowedEmails = map[string]bool{strings.ToLower(ctx.user.GetPlaceholderEmail()): true}
		for _, e := range emails {
			allowedEmails[strings.ToLower(e.Email)] = true
		}
	}

	shas := make([]string, 0, len(fields)/3)
	for i := 0; i < len(fields); i += 3 {
		sha, email, message := fields[i], fields[i+1], fields[i+2]
		shas = append(shas, sha)
		if rule.CommitMessageRe != nil && !rule.CommitMessageRe.MatchString(message) {
			return pushRuleError(fmt.Sprintf("commit %.10s: message does not match %q", sha, rule.CommitMessageRegex))
		}
		if rule.CommitMessageBannedRe != nil && rule.CommitMessageBannedRe.MatchString(message) {
			return pushRuleError(fmt.Sprintf("commit %.10s: message matches the banned pattern %q", sha, rule.CommitMessageBannedRegex))
		}
		if checkAuthor && !allowedEmails[strings.ToLower(email)] {
			return pushRuleError(fmt.Sprintf("commit %.10s: author email %q is not a verified email of %s", sha, email, ctx.user.Name))
		}
	}
	if !checkFiles {
		return nil
	}
	return ctx.checkPushRuleFiles(rule, shas)
}

type pushRuleFile struct{ commit, path string }

// checkPushRuleFiles checks the files added or modified by the commits. Merges are diffed against their first parent,
// so a merge that introduces a file itself is caught too.
func (ctx *preReceiveContext) checkPushRuleFiles(rule *git_model.PushRule, shas []string) error {
	blobs := map[string]pushRuleFile{} // deduplicated by blob ID
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
	}()
	err = git.NewCommand(ctx, "diff-tree", "--stdin", "-r", "-z", "--root", "--no-renames", "--diff-filter=d", "--diff-merges=first-parent").
		Run(&git.RunOpts{
			Dir:    ctx.Repo.Repository.RepoPath(),
			Env:    ctx.env,
			Stdin:  strings.NewReader(strings.Join(shas, "\n") + "\n"),
			Stdout: stdoutWriter,
			PipelineFunc: func(_ context.Context, cancel context.CancelFunc) error {
				_ = stdoutWriter.Close()
				defer stdoutReader.Close()
				err := ctx.readPushRuleDiffTree(rule, bufio.NewReader(stdoutReader), blobs)
				if err != nil {
					cancel()
				}
				return err
			},
		})
	if err != nil || rule.MaxFileSizeMB == 0 || len(blobs) == 0 {
		return err
	}

	stdin := make([]string, 0, len(blobs))
	for id := range blobs {
		stdin = append(stdin, id)
	}
	out, err := ctx.runCapped(git.NewCommand(ctx, "cat-file", "--batch-check=%(objectname) %(objectsize)"), strings.Join(stdin, "\n")+"\n")
	if err != nil {
		return err
	}
	maxSize := rule.MaxFileSizeMB << 20
	for line := range strings.Lines(string(out)) {
		id, sizeStr, _ := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return fmt.Errorf("unexpected git cat-file output %q", line)
		}
		if size > maxSize {
			f := blobs[id]
			return pushRuleError(fmt.Sprintf("commit %.10s: file %q is %.1f MB, larger than the %d MB limit", f.commit, f.path, float64(size)/(1<<20), rule.MaxFileSizeMB))
		}
	}
	return nil
}

// readPushRuleDiffTree reads `git diff-tree --stdin -z` output: a commit ID, then ":modes ids status" and path pairs.
func (ctx *preReceiveContext) readPushRuleDiffTree(rule *git_model.PushRule, rd *bufio.Reader, blobs map[string]pushRuleFile) error {
	var commit string
	for {
		field, err := rd.ReadString('\x00')
		if err != nil {
			if errors.Is(err, io.EOF) && field == "" {
				return nil
			}
			return fmt.Errorf("unexpected git diff-tree output: %w", err)
		}
		field = strings.TrimSuffix(field, "\x00")
		if !strings.HasPrefix(field, ":") {
			commit = field
			continue
		}
		// :<old mode> <new mode> <old id> <new id> <status>
		meta := strings.Fields(field)
		filePath, err := rd.ReadString('\x00')
		if err != nil || len(meta) != 5 {
			return fmt.Errorf("unexpected git diff-tree output %q", field)
		}
		filePath = strings.TrimSuffix(filePath, "\x00")

		ctx.pushRulePaths++
		if ctx.pushRulePaths > PushRuleMaxPaths {
			return pushRuleError(fmt.Sprintf("the push changes more than %d files, push it in smaller batches", PushRuleMaxPaths))
		}
		if rule.IsBannedFile(filePath) {
			return pushRuleError(fmt.Sprintf("commit %.10s: file %q matches a banned file pattern", commit, filePath))
		}
		if meta[1] != "160000" { // not a submodule
			if _, ok := blobs[meta[3]]; !ok {
				blobs[meta[3]] = pushRuleFile{commit, filePath}
			}
		}
	}
}
