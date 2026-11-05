// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package test

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A repository in a project is `org/project/repo`: names and links come from Repository.FullName and Link, and a
// name glued from the owner and the leaf drops the project. New concatenations fail here; the ones that stay are
// listed with the reason.
func TestNoRepoNameConcatenation(t *testing.T) {
	concat := regexp.MustCompile(`(OwnerName|Owner\.Name)(\}\}/\{\{|\s*\+\s*"/"\s*\+\s*)[\w.$ ]*?Name\b`)
	allowed := map[string]string{
		`models/repo/repo.go: OwnerName + "/" + repo.Name`:                                        "FullName itself, for a root repository",
		`models/repo/repo.go: OwnerName + "/" + repo.TrashedName`:                                 "TrashedFullName itself, for a root repository",
		`routers/web/repo/editor.go: Owner.Name + "/" + repo.Name`:                                "compare head grammar owner/repo:branch; forks into projects come later",
		`templates/repo/issue/view_content/sidebar/pull_review.tmpl: OwnerName}}/{{.Team.Name`:    "a team, org/team",
		`templates/repo/issue/view_content/sidebar/pull_reviewers.tmpl: OwnerName}}/{{.Team.Name`: "a team, org/team",
		`templates/repo/settings/environment.tmpl: Owner.Name}}/{{.Team.Name`:                     "a team, org/team",
		`services/packages/container/common.go: OwnerName+"/"+p.LowerName`:                        "a package name, not a repository",
		`routers/private/serv.go: OwnerName + "/" + results.RepoName`:                             "the path a git client asked for, before any repository is loaded",
		`routers/private/serv.go: OwnerName + "/" + groupName`:                                    "the path a git client asked for, before any repository is loaded",
		`services/pull/owner_eligibility.go: Owner.Name + "/" + t.Name`:                           "a team, org/team",
		`services/actions/deployment_notify.go: OwnerName+"/"+t.Name`:                             "a team, org/team",
		`services/metrics/pulls.go: OwnerName + "/" + row.RepoName`:                               "metrics rows carry the owner and leaf only; references and mail come with their own PR",
	}
	seen := map[string]bool{}
	for _, dir := range []string{"templates", "routers", "services", "models", "modules"} {
		require.NoError(t, filepath.WalkDir(filepath.Join("../..", dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(path, "_test.go") || !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".tmpl") {
				return err
			}
			rel, _ := filepath.Rel("../..", path)
			for i, line := range readLines(t, path) {
				for _, m := range concat.FindAllString(line, -1) {
					key := filepath.ToSlash(rel) + ": " + m
					seen[key] = true
					_, ok := allowed[key]
					assert.True(t, ok, "%s:%d builds a repository name from owner and leaf (%s); use FullName or Link", rel, i+1, m)
				}
			}
			return nil
		}))
	}
	for key := range allowed {
		assert.True(t, seen[key], "allow-list entry no longer matches: %s", key)
	}
}
