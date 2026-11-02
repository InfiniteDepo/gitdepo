// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package release

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"

	"go.yaml.in/yaml/v3"
	"xorm.io/builder"
)

const (
	maxNotesCommits    = 1000
	maxNotesConfigSize = 64 << 10
)

var notesConfigPaths = []string{".forgejo/release.yml", ".github/release.yml"}

type GenerateNotesOptions struct {
	TagName         string
	Target          string
	PreviousTagName string
	ConfigFilePath  string
	// IncludeDirectCommits lists the commits of the range that are not the merge of a pull request.
	IncludeDirectCommits bool
}

type notesConfig struct {
	Changelog struct {
		Exclude struct {
			Labels  []string `yaml:"labels"`
			Authors []string `yaml:"authors"`
		} `yaml:"exclude"`
		Categories []struct {
			Title   string   `yaml:"title"`
			Labels  []string `yaml:"labels"`
			Exclude struct {
				Labels  []string `yaml:"labels"`
				Authors []string `yaml:"authors"`
			} `yaml:"exclude"`
		} `yaml:"categories"`
	} `yaml:"changelog"`
}

// GenerateReleaseNotes lists the pull requests merged between the previous tag and the given tag (or target) as Markdown.
func GenerateReleaseNotes(ctx context.Context, repo *repo_model.Repository, gitRepo *git.Repository, opts GenerateNotesOptions) (string, error) {
	var end *git.Commit
	var err error
	if gitRepo.IsTagExist(opts.TagName) {
		end, err = gitRepo.GetTagCommit(opts.TagName)
	} else {
		if opts.Target == "" {
			opts.Target = repo.DefaultBranch
		}
		end, err = gitRepo.GetCommit(opts.Target)
	}
	if err != nil {
		return "", err
	}

	prevTag := opts.PreviousTagName
	if prevTag == "" {
		if prevTag, err = findPreviousTag(gitRepo, end.ID.String(), opts.TagName); err != nil {
			return "", err
		}
	}
	var prev *git.Commit
	if prevTag != "" {
		if prev, err = gitRepo.GetTagCommit(prevTag); err != nil {
			return "", err
		}
	}

	commits, err := gitRepo.CommitsBetweenLimit(end, prev, maxNotesCommits, 0)
	if err != nil {
		return "", err
	}
	shas := make([]string, 0, len(commits))
	for _, c := range commits {
		shas = append(shas, c.ID.String())
	}

	var prs issues_model.PullRequestList
	if len(shas) > 0 {
		if err := db.GetEngine(ctx).Where(builder.Eq{"base_repo_id": repo.ID, "has_merged": true}.And(builder.In("merged_commit_id", shas))).Find(&prs); err != nil {
			return "", err
		}
	}
	issues, err := prs.LoadIssues(ctx)
	if err != nil {
		return "", err
	}
	if err := issues.LoadPosters(ctx); err != nil {
		return "", err
	}
	if err := issues.LoadLabels(ctx); err != nil {
		return "", err
	}
	slices.SortFunc(prs, func(a, b *issues_model.PullRequest) int {
		return cmp.Or(cmp.Compare(a.MergedUnix, b.MergedUnix), cmp.Compare(a.ID, b.ID))
	})

	cfg, err := loadNotesConfig(end, opts.ConfigFilePath)
	if err != nil {
		return "", err
	}

	var extras notesExtras
	if extras.contributors, err = findNewContributors(ctx, repo.ID, prs, cfg); err != nil {
		return "", err
	}
	if opts.IncludeDirectCommits {
		merged := make(map[string]bool, len(prs))
		for _, pr := range prs {
			merged[pr.MergedCommitID] = true
		}
		if extras.commits, err = firstParentCommits(gitRepo, end, prev, merged); err != nil {
			return "", err
		}
	}
	return renderNotes(repo.HTMLURL(), prs, cfg, extras, prevTag, opts.TagName, len(commits) == maxNotesCommits), nil
}

type newContributor struct {
	name  string
	index int64
}

type directCommit struct {
	title, author, sha string
}

type notesExtras struct {
	contributors []newContributor
	commits      []directCommit
}

func isExcludedAuthor(authors []string, name string) bool {
	return slices.ContainsFunc(authors, func(a string) bool { return strings.EqualFold(a, name) })
}

// findNewContributors returns the authors whose earliest merged pull request in the repository is in prs (sorted by merge time and ID).
// merged_unix has second resolution, so a pull request merged in the same second counts as earlier only with a lower ID.
// It runs one query for all authors, and prs holds at most maxNotesCommits entries.
func findNewContributors(ctx context.Context, repoID int64, prs issues_model.PullRequestList, cfg *notesConfig) ([]newContributor, error) {
	first := make(map[int64]*issues_model.PullRequest, len(prs))
	var order []int64
	var earlier []builder.Cond
	for _, pr := range prs {
		if pr.Issue.PosterID <= 0 || isExcludedAuthor(cfg.Changelog.Exclude.Authors, pr.Issue.Poster.Name) || first[pr.Issue.PosterID] != nil {
			continue
		}
		first[pr.Issue.PosterID] = pr
		order = append(order, pr.Issue.PosterID)
		earlier = append(earlier, builder.Eq{"issue.poster_id": pr.Issue.PosterID}.And(builder.Or(
			builder.Lt{"pull_request.merged_unix": pr.MergedUnix},
			builder.Eq{"pull_request.merged_unix": pr.MergedUnix}.And(builder.Lt{"pull_request.id": pr.ID}),
		)))
	}
	if len(order) == 0 {
		return nil, nil
	}
	var veterans []int64
	if err := db.GetEngine(ctx).Table("pull_request").Join("INNER", "issue", "issue.id = pull_request.issue_id").
		Select("DISTINCT issue.poster_id").
		Where(builder.Eq{"pull_request.base_repo_id": repoID, "pull_request.has_merged": true}.And(builder.Or(earlier...))).
		Find(&veterans); err != nil {
		return nil, err
	}
	for _, id := range veterans {
		delete(first, id)
	}
	var contributors []newContributor
	for _, id := range order {
		if pr, ok := first[id]; ok {
			contributors = append(contributors, newContributor{pr.Issue.Poster.Name, pr.Issue.Index})
		}
	}
	return contributors, nil
}

// firstParentCommits returns the first-parent commits of prev..end that are not in merged (the merge commits of pull requests).
func firstParentCommits(gitRepo *git.Repository, end, prev *git.Commit, merged map[string]bool) ([]directCommit, error) {
	rng := end.ID.String()
	if prev != nil {
		rng = prev.ID.String() + ".." + rng
	}
	stdout, _, err := git.NewCommand(gitRepo.Ctx, "log", "--first-parent", "--reverse", "--format=%H%x00%an%x00%s%x00").
		AddOptionValues("--max-count", strconv.Itoa(maxNotesCommits)).
		AddDynamicArguments(rng).
		RunStdString(&git.RunOpts{Dir: gitRepo.Path})
	if err != nil {
		return nil, err
	}
	var commits []directCommit
	fields := strings.Split(stdout, "\x00")
	for ; len(fields) > 3; fields = fields[3:] {
		if sha := strings.TrimSpace(fields[0]); !merged[sha] {
			commits = append(commits, directCommit{title: fields[2], author: fields[1], sha: sha})
		}
	}
	return commits, nil
}

// findPreviousTag returns the nearest tag reachable from endSHA other than tagName, or "" if there is none.
func findPreviousTag(gitRepo *git.Repository, endSHA, tagName string) (string, error) {
	stdout, _, err := git.NewCommand(gitRepo.Ctx, "describe", "--tags", "--abbrev=0").
		AddOptionValues("--exclude", tagName).
		AddDynamicArguments(endSHA).
		RunStdString(&git.RunOpts{Dir: gitRepo.Path})
	if err != nil {
		if strings.Contains(err.Error(), "No names found") || strings.Contains(err.Error(), "No tags can describe") {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}

func loadNotesConfig(commit *git.Commit, path string) (*notesConfig, error) {
	paths := notesConfigPaths
	if path != "" {
		paths = []string{path}
	}
	for _, p := range paths {
		content, err := commit.GetFileContent(p, maxNotesConfigSize)
		if git.IsErrNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		cfg := &notesConfig{}
		if err := yaml.Unmarshal([]byte(content), cfg); err != nil {
			log.Debug("invalid release notes configuration %q: %v", p, err)
			return nil, util.NewInvalidArgumentErrorf("invalid release notes configuration")
		}
		return cfg, nil
	}
	if path != "" {
		return nil, util.NewInvalidArgumentErrorf("release notes configuration file not found")
	}
	return &notesConfig{}, nil
}

var markdownPunct = regexp.MustCompile("[!-/:-@\\[-`{-~]")

// escapeMarkdown backslash-escapes all ASCII punctuation, so the text renders literally.
func escapeMarkdown(s string) string {
	return markdownPunct.ReplaceAllString(strings.NewReplacer("\r", " ", "\n", " ").Replace(s), `\$0`)
}

func renderNotes(repoURL string, prs issues_model.PullRequestList, cfg *notesConfig, extras notesExtras, prevTag, tagName string, truncated bool) string {
	type category struct {
		title   string
		labels  []string
		exclude struct{ Labels, Authors []string }
		lines   []string
	}
	var categories []*category
	if cfg != nil {
		for _, c := range cfg.Changelog.Categories {
			cat := &category{title: c.Title, labels: c.Labels}
			cat.exclude.Labels, cat.exclude.Authors = c.Exclude.Labels, c.Exclude.Authors
			categories = append(categories, cat)
		}
	}
	other := &category{title: "Other Changes", labels: []string{"*"}}
	categories = append(categories, other)

	for _, pr := range prs {
		issue := pr.Issue
		labels := make([]string, 0, len(issue.Labels))
		for _, l := range issue.Labels {
			labels = append(labels, l.Name)
		}
		hasLabel := func(wanted []string) bool {
			return slices.ContainsFunc(labels, func(l string) bool { return slices.Contains(wanted, l) })
		}
		if cfg != nil && (isExcludedAuthor(cfg.Changelog.Exclude.Authors, issue.Poster.Name) || hasLabel(cfg.Changelog.Exclude.Labels)) {
			continue
		}
		line := fmt.Sprintf("* %s by @%s in #%d", escapeMarkdown(issue.Title), issue.Poster.Name, issue.Index)
		for _, c := range categories {
			if isExcludedAuthor(c.exclude.Authors, issue.Poster.Name) || hasLabel(c.exclude.Labels) {
				continue
			}
			if slices.Contains(c.labels, "*") || hasLabel(c.labels) {
				c.lines = append(c.lines, line)
				break
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("## What's Changed\n")
	for _, c := range categories {
		if len(c.lines) == 0 {
			continue
		}
		if len(categories) > 1 {
			fmt.Fprintf(&sb, "### %s\n", escapeMarkdown(c.title))
		}
		sb.WriteString(strings.Join(c.lines, "\n") + "\n")
	}
	if len(extras.commits) > 0 {
		sb.WriteString("### Direct commits\n")
		for _, c := range extras.commits {
			fmt.Fprintf(&sb, "* %s by %s ([%s](%s/commit/%s))\n", escapeMarkdown(c.title), escapeMarkdown(c.author), c.sha[:min(10, len(c.sha))], repoURL, c.sha)
		}
	}
	if len(extras.contributors) > 0 {
		sb.WriteString("\n## New Contributors\n")
		for _, c := range extras.contributors {
			fmt.Fprintf(&sb, "* @%s made their first contribution in #%d\n", c.name, c.index)
		}
	}
	if truncated {
		fmt.Fprintf(&sb, "\n_Only the latest %d commits were scanned._\n", maxNotesCommits)
	}
	if prevTag != "" {
		fmt.Fprintf(&sb, "\n**Full Changelog**: %s/compare/%s...%s\n", repoURL, util.PathEscapeSegments(prevTag), util.PathEscapeSegments(tagName))
	} else {
		fmt.Fprintf(&sb, "\n**Full Changelog**: %s/commits/tag/%s\n", repoURL, util.PathEscapeSegments(tagName))
	}
	return sb.String()
}
