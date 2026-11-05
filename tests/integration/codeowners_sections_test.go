// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

// CODEOWNERS sections (GitLab syntax) decide a "Require approval from code owners" rule, read from the target branch.
func TestCodeOwnerSectionsMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := &pusherEnv{newApprovalRulesEnv(t)}
		owners := &api.ApprovalRule{Name: "Code owners", RequiredCount: 1, RequireCodeOwners: true}
		// base protects a new branch with the rule and the CODEOWNERS file, and opens a pull request changing docs/a.md
		open := func(base, codeowners string) int64 {
			e.base(base, create("CODEOWNERS", codeowners))
			e.protect(base, true, owners)
			return e.pr(base, create("docs/a.md", "a"))
		}
		box := func(index int64) string {
			return strings.Join(strings.Fields(e.mergeBox(e.owner, index).doc.Find(".merge-section").Text()), " ")
		}

		t.Run("N approvals", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := open("cos-n", "[Docs][2]\ndocs/.* @user4 @user5\n")
			e.approve("user4", index)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "needs 2 approvals, has 1")
			assert.Contains(t, box(index), "CODEOWNERS section Docs needs 2 approvals, has 1")

			req := NewRequestf(t, "GET", "/api/v1/repos/user2/repo1/pulls/%d/approvals", index).AddTokenAuth(e.owner.Token)
			body := e.owner.Session.MakeRequest(t, req, http.StatusOK).Body.String()
			assert.NotContains(t, body, "Docs", "the approvals endpoint shows no section names")

			e.approve("user5", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		t.Run("N above the people who can approve", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := open("cos-many", "[Docs][3]\ndocs/.* @user4 @user5\n")
			e.approve("user4", index)
			e.approve("user5", index)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "only 2 people can approve")
			assert.Contains(t, box(index), "CODEOWNERS section Docs needs 3 approvals, only 2 people can approve")
		})

		t.Run("optional section", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := open("cos-optional", "^[Docs][5]\ndocs/.* @user4\n")
			e.approve("user5", index) // not an owner, but the rule's own count is met and nothing else blocks
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		t.Run("default owners", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := open("cos-default", "[Docs] @user4\ndocs/.*\n")
			e.approve("user5", index)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "needs 1 approvals, has 0")
			e.approve("user4", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		t.Run("malformed header", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := open("cos-bad", "docs/.* @user4\n[Docs\n")
			e.approve("user4", index)
			e.approve("user5", index)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "CODEOWNERS has an error on line 2")
			assert.Contains(t, box(index), "CODEOWNERS on cos-bad has an error on line 2")

			// the file view warns about it
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/cos-bad/CODEOWNERS"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Line: 2: incorrect section header")
		})
	})
}
