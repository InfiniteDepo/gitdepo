// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/glob"
	"forgejo.org/modules/setting"
)

// BranchInfo is a branch that may be indexed.
type BranchInfo struct {
	Name       string
	CommitID   string
	CommitTime int64
}

// indexedBranchPatterns returns the patterns repo admins saved for code search.
func indexedBranchPatterns(ctx context.Context, repo *repo_model.Repository) []string {
	ru, err := repo.GetUnit(ctx, unit.TypeCode)
	if err != nil {
		return nil
	}
	return ru.CodeConfig().IndexedBranches
}

func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if matches(p, name) {
			return true
		}
	}
	return false
}

// matches compiles and matches in one place; an invalid pattern counts as no match.
func matches(pattern, name string) bool {
	g, err := glob.CompileExact(pattern, '/')
	return err == nil && g.MatchString(name)
}

// isIndexedBranchName tells if a branch is, or may be, indexed: it is the default branch or matches a pattern.
func isIndexedBranchName(defaultBranch string, patterns []string, name string) bool {
	return name == defaultBranch || matchesAny(patterns, name)
}

// IsIndexedBranchName is isIndexedBranchName with the saved patterns of the repo.
func IsIndexedBranchName(ctx context.Context, repo *repo_model.Repository, name string) bool {
	return isIndexedBranchName(repo.DefaultBranch, indexedBranchPatterns(ctx, repo), name)
}

// selectBranches returns the branches to index: the default branch first, then the most recent
// branches matching a pattern. The limit caps the whole list, the default branch included.
func selectBranches(defaultBranch string, patterns []string, branches []BranchInfo, limit int) []string {
	selected := []string{defaultBranch}
	candidates := make([]BranchInfo, 0, len(branches))
	for _, b := range branches {
		if b.Name != defaultBranch && matchesAny(patterns, b.Name) {
			candidates = append(candidates, b)
		}
	}
	slices.SortStableFunc(candidates, func(a, b BranchInfo) int { return int(b.CommitTime - a.CommitTime) })
	for _, b := range candidates {
		if len(selected) >= limit {
			break
		}
		selected = append(selected, b.Name)
	}
	return selected
}

// expandIndexedBranches lists the non-default branches to index, with their commit, from the branch table.
func expandIndexedBranches(ctx context.Context, repo *repo_model.Repository) ([]BranchInfo, error) {
	patterns := indexedBranchPatterns(ctx, repo)
	if len(patterns) == 0 {
		return nil, nil
	}
	var rows []*git_model.Branch
	if err := db.GetEngine(ctx).Where("repo_id = ? AND is_deleted = ?", repo.ID, false).Find(&rows); err != nil {
		return nil, err
	}
	infos := make([]BranchInfo, 0, len(rows))
	byName := make(map[string]BranchInfo, len(rows))
	for _, r := range rows {
		if r.Name == "HEAD" { // zoekt's name for the default branch
			continue
		}
		bi := BranchInfo{Name: r.Name, CommitID: r.CommitID, CommitTime: int64(r.CommitTime)}
		infos = append(infos, bi)
		byName[r.Name] = bi
	}
	names := selectBranches(repo.DefaultBranch, patterns, infos, setting.Indexer.MaxIndexedBranchesPerRepo)
	result := make([]BranchInfo, 0, len(names)-1)
	for _, n := range names[1:] {
		result = append(result, byName[n])
	}
	return result, nil
}

const (
	maxBranchPatterns      = 20
	maxBranchPatternLength = 100
)

// ParseIndexedBranchPatterns reads the branch names or patterns, one per line, repo admins enter.
func ParseIndexedBranchPatterns(text string) ([]string, error) {
	patterns := []string{}
	for line := range strings.SplitSeq(text, "\n") {
		p := strings.TrimSpace(line)
		if p == "" || slices.Contains(patterns, p) {
			continue
		}
		if len(p) > maxBranchPatternLength {
			return nil, fmt.Errorf("pattern %q is longer than %d characters", p, maxBranchPatternLength)
		}
		if _, err := glob.CompileExact(p, '/'); err != nil {
			return nil, fmt.Errorf("pattern %q is invalid: %w", p, err)
		}
		patterns = append(patterns, p)
	}
	if len(patterns) > maxBranchPatterns {
		return nil, fmt.Errorf("more than %d patterns", maxBranchPatterns)
	}
	return patterns, nil
}

// IndexedBranchNames returns the indexed branches of a repo besides the default one, sorted.
func IndexedBranchNames(ctx context.Context, repo *repo_model.Repository) ([]string, error) {
	stored, err := repo_model.GetIndexerBranches(ctx, repo.ID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(stored))
	for name := range stored {
		if name != repo.DefaultBranch {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}
