// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A manifest without a lock file: its direct dependencies are listed with their ranges, marked as not pinned on the
// page, with one hint per ecosystem, in the API and in the SBOM. A lock file covers the workspaces it lists.
func TestDependencyGraphFallbackManifests(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		repo := depNewRepo(t, user2, user2, "dep-fallback", true, 0)
		sha := depPush(t, u, token, repo, "refs/heads/main", map[string]string{
			"go.mod":            depGoMod,
			"web/package.json":  `{"dependencies":{"express":"^4.18.0"},"devDependencies":{"lodash":"~4.17.20"}}`,
			"docs/package.json": `{"dependencies":{"marked":"^12"}}`,
			"rust/Cargo.toml":   "[dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\n",
			// a lock file covers the workspaces it lists, never a directory below it by presence alone
			"lib/package-lock.json":  `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"^1.3.0"},"workspaces":["sub"]},"sub":{"name":"sub"},"node_modules/left-pad":{"version":"1.3.0","license":"WTFPL"}}}`,
			"lib/sub/package.json":   `{"dependencies":{"covered":"^1"}}`,
			"lib/other/package.json": `{"dependencies":{"uncovered":"^2"}}`,
		})
		require.Eventually(t, func() bool {
			scan := depScanOf(t, repo.ID)
			return scan != nil && scan.CommitSHA == sha
		}, 10*time.Second, 50*time.Millisecond)

		rows := depRows(t, repo.ID)
		require.Len(t, rows, 8, "%v", rows)
		assert.Equal(t, "^4.18.0", rows["npm|express@|web/package.json"].Requirement)
		assert.Equal(t, "1.0", rows["crates.io|serde@|rust/Cargo.toml"].Requirement)
		assert.NotContains(t, rows, "npm|covered@|lib/sub/package.json", "a workspace of lib/package-lock.json")
		assert.Equal(t, "^2", rows["npm|uncovered@|lib/other/package.json"].Requirement, "no workspace of the lock file")

		session := loginUser(t, "user2")
		doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/dep-fallback/activity/dependencies"), http.StatusOK).Body)
		var hints []string
		doc.Find(".repo-dependencies-hint").Each(func(_ int, s *goquery.Selection) {
			hints = append(hints, strings.Join(strings.Fields(s.Text()), " "))
		})
		assert.Equal(t, []string{
			"2 manifests have no lock file docs/package.json web/package.json Only their direct dependencies are listed, with the version ranges they declare. Commit package-lock.json, yarn.lock or pnpm-lock.yaml for exact versions and transitive packages.",
			"1 manifest is not a workspace of lib/package-lock.json lib/other/package.json Only its direct dependencies are listed, with the version ranges it declares. Add it to that lock file's workspaces, or commit its own package-lock.json, yarn.lock or pnpm-lock.yaml, for exact versions and transitive packages.",
			"1 manifest has no lock file rust/Cargo.toml Only its direct dependencies are listed, with the version ranges it declares. Commit Cargo.lock for exact versions and transitive packages.",
		}, hints)
		assert.Equal(t, 4, doc.Find(".repo-dependencies-hint li a").Length(), "one link per manifest")
		cells := map[string]string{}
		doc.Find(".repo-dependencies-row:not(.repo-dependencies-head)").Each(func(_ int, s *goquery.Selection) {
			cells[s.Find(".repo-dependencies-package strong").Text()] = strings.Join(strings.Fields(s.Find("[role=cell]").Eq(1).Text()), " ")
		})
		assert.Equal(t, "^4.18.0 not pinned", cells["express"])
		assert.Equal(t, "~4.17.20 not pinned", cells["lodash"])
		assert.Equal(t, "v1.9.1", cells["github.com/gin-gonic/gin"])
		assert.Equal(t, "1.3.0", cells["left-pad"])

		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/dep-fallback/dependencies?limit=50").AddTokenAuth(token), http.StatusOK)
		var list api.DependencyList
		DecodeJSON(t, resp, &list)
		byName := map[string]*api.Dependency{}
		for _, d := range list.Dependencies {
			byName[d.Name] = d
		}
		assert.Equal(t, "^4.18.0", byName["express"].Requirement)
		assert.Empty(t, byName["express"].Version)
		assert.Equal(t, "pkg:npm/express", byName["express"].PURL)
		assert.Empty(t, byName["left-pad"].Requirement)
		assert.NotContains(t, resp.Body.String(), `"requirement":""`, "omitted when empty")
		// the same at the mount by ID
		resp = MakeRequest(t, NewRequestf(t, "GET", "/api/v1/repositories/%d/dependencies?limit=50", repo.ID).AddTokenAuth(token), http.StatusOK)
		var byID api.DependencyList
		DecodeJSON(t, resp, &byID)
		assert.Equal(t, list, byID)

		cdx := session.MakeRequest(t, NewRequest(t, "GET", "/user2/dep-fallback/activity/dependencies/sbom?format=cyclonedx"), http.StatusOK).Body.String()
		assert.Contains(t, cdx, `{"name":"gitdepo:requirement","value":"^4.18.0"}`)
		spdx := session.MakeRequest(t, NewRequest(t, "GET", "/user2/dep-fallback/activity/dependencies/sbom?format=spdx"), http.StatusOK).Body.String()
		assert.Contains(t, spdx, `"comment":"not pinned (no lock file); declared range: ^4.18.0"`)
	})
}
