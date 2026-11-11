// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/optional"

	"xorm.io/builder"
)

const (
	maxSlugName       = 50 // bytes of "<index>-<slug>"
	maxLinkedBranches = 20
	bugfixTypeName    = "Bugfix"
)

// IssueSlug turns an issue into the part of a branch name after the type prefix: "<index>-<slug>" where the slug is
// the title in lower-case ASCII letters and digits, every other run of characters one dash, and the whole at most
// maxSlugName bytes, cut at a dash. A title without such characters gives "issue-<index>".
func IssueSlug(index int64, title string) string {
	n := strconv.FormatInt(index, 10)
	var b strings.Builder
	dash := true
	for _, r := range title {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 'a' - 'A')
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		return "issue-" + n
	}
	name := n + "-" + slug
	if len(name) > maxSlugName {
		cut := name[:maxSlugName]
		if name[maxSlugName] != '-' {
			cut = cut[:strings.LastIndexByte(cut, '-')+1]
		}
		if name = strings.TrimRight(cut, "-"); len(name) <= len(n) {
			return "issue-" + n
		}
	}
	return name
}

// IssueSuggestion is the branch the dialog offers for an issue: the type (a TypeChoice name, "" for none) and the
// name after the type's prefix.
type IssueSuggestion struct {
	Type string
	Name string
}

// SuggestIssueBranch suggests <type>/<index>-<slug>. The type is Bugfix for an issue with the label "bug" (or one
// ending in "/bug") when that type is enabled, else the first enabled type besides Release; with no such type there is none.
// The name must be a valid ref and pass the model's rules for doer, else it falls back to "issue-<index>", else
// nothing is suggested (ok is false).
func SuggestIssueBranch(ctx context.Context, repo *repo_model.Repository, doer *user_model.User, c CreateChoices, index int64, title string, labels []string) (s IssueSuggestion, ok bool, err error) {
	var typed []TypeChoice
	for _, t := range c.Types {
		if t.Name != ReleaseTypeName {
			typed = append(typed, t)
		}
	}
	var prefix string
	if len(typed) > 0 {
		chosen := typed[0]
		isBug := slices.ContainsFunc(labels, func(l string) bool {
			l = strings.ToLower(l)
			return l == "bug" || strings.HasSuffix(l, "/bug")
		})
		if i := slices.IndexFunc(typed, func(t TypeChoice) bool { return strings.EqualFold(t.Name, bugfixTypeName) }); isBug && i >= 0 {
			chosen = typed[i]
		}
		s.Type, prefix = chosen.Name, chosen.Prefix
	}
	for _, name := range []string{IssueSlug(index, title), "issue-" + strconv.FormatInt(index, 10)} {
		if !git.IsValidRefPattern(prefix+name) || git.IsReservedRefName(prefix+name) {
			continue
		}
		if _, err := CheckNewBranchWith(ctx, repo, c.Effective, doer.ID, false, prefix+name); err == nil {
			s.Name = name
			return s, true, nil
		} else if _, refused := errors.AsType[ErrBranchTypeRequired](err); !refused {
			return s, false, err
		}
	}
	return s, false, nil
}

// LinkedBranches returns the names of the branches that carry the issue's number by the naming convention: an enabled
// type or release prefix followed by "<index>-" (or exactly the number), and, when the model has none of those,
// "<index>-" at the start.
func LinkedBranches(ctx context.Context, repo *repo_model.Repository, m repo_model.BranchingModel, index int64) ([]string, error) {
	prefixes := slices.Clone(m.ReleasePrefixes)
	for _, t := range m.Types {
		if !t.Off {
			prefixes = append(prefixes, t.Prefix)
		}
	}
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}
	n := strconv.FormatInt(index, 10)
	cond := builder.NewCond()
	for _, p := range prefixes {
		cond = cond.Or(builder.Expr(binary("name")+" = "+binary("?"), p+n), namePrefix(p+n+"-"))
	}
	return git_model.FindBranchNames(ctx, git_model.FindBranchOptions{
		RepoID: repo.ID, IsDeletedBranch: optional.Some(false), Cond: cond,
		ListOptions: db.ListOptions{Page: 1, PageSize: maxLinkedBranches},
	})
}
