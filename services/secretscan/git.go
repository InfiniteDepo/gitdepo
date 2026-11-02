// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/modules/git"
)

// maxRecord is the most bytes kept of one line or record read from git. A path is at most 4096 bytes in any file
// system we serve and a tree entry of a pushed object can be much longer: the rest is dropped, the leading bytes
// are kept. Two paths that share their first 16 KiB therefore become one place.
const maxRecord = 16 << 10

// splitWriter calls fn for every sep-terminated record git writes. A record over maxRecord is cut to its leading
// bytes. fn must not keep the slice.
type splitWriter struct {
	sep byte
	buf []byte
	fn  func([]byte) error
	err error
}

func (w *splitWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, w.sep)
		chunk := p
		if i >= 0 {
			chunk = p[:i]
		}
		w.buf = append(w.buf, chunk[:min(len(chunk), max(maxRecord-len(w.buf), 0))]...)
		if i < 0 {
			break
		}
		if err := w.fn(w.buf); err != nil {
			w.err = err
			return 0, err
		}
		w.buf = w.buf[:0]
		p = p[i+1:]
	}
	return n, nil
}

// isObjectID tells whether b is a full SHA-1 or SHA-256 object ID in lower case hex.
func isObjectID(b []byte) bool {
	if len(b) != 40 && len(b) != 64 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// refTips returns the commits the refs point to, sorted and without duplicates: for the refs under refs/pull/ (which
// any reader can write) or for all the others. A tag object is peeled to its commit; a ref to a tree or a file has no commit and is not
// scanned (what only such a ref reaches is not read).
func refTips(ctx context.Context, dir string, pull bool) ([]string, error) {
	seen := map[string]struct{}{}
	var tags strings.Builder // tag objects: git peels them with ^{commit}
	w := &splitWriter{sep: '\n', fn: func(line []byte) error {
		f := strings.Fields(string(line)) // object, type, ref
		if len(f) != 3 || strings.HasPrefix(f[2], "refs/pull/") != pull || !isObjectID([]byte(f[0])) {
			return nil
		}
		switch f[1] {
		case "commit":
			seen[f[0]] = struct{}{}
		case "tag":
			tags.WriteString(f[0] + "^{commit}\n")
		}
		return nil
	}}
	if err := git.NewCommand(ctx, "for-each-ref", "--format=%(objectname) %(objecttype) %(refname)").Run(&git.RunOpts{Dir: dir, Stdout: w, Stderr: io.Discard, UseContextTimeout: true}); err != nil {
		return nil, err
	}
	if tags.Len() > 0 { // a missing object or a tag of a tree or file answers "missing"
		out, _, err := git.NewCommand(ctx, "cat-file", "--batch-check").RunStdString(&git.RunOpts{Dir: dir, Stdin: strings.NewReader(tags.String()), UseContextTimeout: true})
		if err != nil {
			return nil, err
		}
		for line := range strings.SplitSeq(out, "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[1] == "commit" && isObjectID([]byte(f[0])) {
				seen[f[0]] = struct{}{}
			}
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}

// existingTips keeps the IDs that are objects of the repository: a stored tip can be gone after the garbage
// collection took an unreachable commit, and git refuses a revision it doesn't know.
func existingTips(ctx context.Context, gitRepo *git.Repository, tips []string) ([]string, error) {
	var kept []string
	err := gitRepo.WithCatFileBatchCheck(ctx, func(w io.Writer, r *bufio.Reader) error {
		for _, id := range tips {
			if !isObjectID([]byte(id)) {
				continue
			}
			if _, err := io.WriteString(w, id+"\n"); err != nil {
				return err
			}
			switch _, _, _, err := git.ReadBatchLine(r); {
			case err == nil:
				kept = append(kept, id)
			case !git.IsErrNotExist(err):
				return err
			}
		}
		return nil
	})
	return kept, err
}

// rangeInput is the standard input of log: the tips to read and, after `--not`, the tips already scanned. Thousands
// of refs never go on the command line.
func rangeInput(tips, scanned []string) *strings.Reader {
	in := strings.Join(tips, "\n") + "\n"
	if len(scanned) > 0 {
		in += "--not\n" + strings.Join(scanned, "\n") + "\n"
	}
	return strings.NewReader(in)
}

// commitInfo is the header of a commit of the log.
type commitInfo struct {
	ID          string
	Parents     []string
	AuthorName  string
	AuthorEmail string
	Unix        int64
}

// change is one record of `git log --raw`: a file that a commit set to the blob NewID.
type change struct {
	NewID, Path string
}

// logCommits runs `git log --raw -z` over the range, oldest commits first, and calls commit at the start of each
// commit and file for every file it added or changed (a merge's diff is against its first parent). A commit is
// complete when the next one starts or logCommits returns nil. An error of commit or file stops git and is returned.
func logCommits(ctx context.Context, dir string, input io.Reader, commit func(commitInfo) error, file func(change) error) error {
	p := &logParser{commit: commit, file: file}
	w := &splitWriter{sep: 0, fn: p.token}
	err := git.NewCommand(ctx, "-c", "log.showSignature=false", "log", "--stdin", "--root", "--raw", "-z", "--no-renames", "--no-abbrev", "--topo-order", "--reverse", "--diff-merges=first-parent", "--format=%H%x00%P%x00%an%x00%ae%x00%ct").
		Run(&git.RunOpts{Dir: dir, Stdin: input, Stdout: w, Stderr: io.Discard, UseContextTimeout: true})
	if w.err != nil {
		return w.err
	}
	return err
}

// logParser reads the tokens of the log: five tokens per commit (ID, parents, author name, author email, time), then,
// for each changed file, `:<mode> <mode> <old> <new> <status>` and the path. The fields are positional, so no commit
// text can pass for a record.
type logParser struct {
	commit  func(commitInfo) error
	file    func(change) error
	header  [5]string
	headerN int // fields of the header read so far
	pending *change
}

func (p *logParser) token(tok []byte) error {
	switch {
	case p.pending != nil:
		c := p.pending
		p.pending = nil
		if c.NewID != "" {
			c.Path = string(tok)
			return p.file(*c)
		}
	case p.headerN > 0 && p.headerN < len(p.header):
		p.header[p.headerN] = string(tok)
		if p.headerN++; p.headerN == len(p.header) {
			unix, _ := strconv.ParseInt(p.header[4], 10, 64)
			return p.commit(commitInfo{ID: p.header[0], Parents: strings.Fields(p.header[1]), AuthorName: p.header[2], AuthorEmail: p.header[3], Unix: unix})
		}
	default:
		tok = bytes.TrimPrefix(tok, []byte{'\n'})
		if p.headerN == len(p.header) && len(tok) > 0 && tok[0] == ':' {
			f := strings.Fields(string(tok))
			p.pending = &change{}
			if len(f) >= 5 && (f[4] == "A" || f[4] == "M" || f[4] == "T") && isObjectID([]byte(f[3])) && isObjectID([]byte(p.header[0])) {
				p.pending.NewID = f[3]
			}
			return nil
		}
		p.header[0], p.headerN = string(tok), 1
	}
	return nil
}
