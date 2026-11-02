// Copyright 2025 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/system"
	"forgejo.org/modules/test"
	"forgejo.org/modules/translation"
	"forgejo.org/modules/updatechecker"
	"forgejo.org/services/cron"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var commonEntries = []string{
	"delete_inactive_accounts",
	"delete_repo_archives",
	"delete_missing_repos",
	"git_gc_repos",
	"resync_all_hooks",
	"reinit_missing_repos",
	"sync_external_users",
	"repo_health_check",
	"delete_generated_repository_avatars",
	"sync_repo_branches",
	"sync_repo_tags",
}

var sshEntries = []string{
	"resync_all_sshkeys",
	"resync_all_sshprincipals",
}

// Check cron options on /admin, including those that are available conditionally
func testAssertAdminDashboardOptions(t *testing.T, page *HTMLDoc, locale translation.Locale, expectSSH bool) {
	for _, entry := range commonEntries {
		page.AssertSelection(t, page.FindByText("table tr td", locale.TrString(fmt.Sprintf("admin.dashboard.%s", entry))), true)
		page.AssertSelection(t, page.Find(fmt.Sprintf("table tr td button[value='%s']", entry)), true)
	}
	for _, entry := range sshEntries {
		page.AssertSelection(t, page.FindByText("table tr td", locale.TrString(fmt.Sprintf("admin.dashboard.%s", entry))), expectSSH)
		page.AssertSelection(t, page.Find(fmt.Sprintf("table tr td button[value='%s']", entry)), expectSSH)
	}
}

func TestAdminDashboard(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	session := loginUser(t, "user1")
	locale := translation.NewLocale("en-US")
	url := "/admin"

	t.Run("SSH disabled", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.SSH.Disabled, true)()

		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
		testAssertAdminDashboardOptions(t, page, locale, false)
	})

	t.Run("SSH enabled, but built-in", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.SSH.Disabled, false)()
		defer test.MockVariableValue(&setting.SSH.StartBuiltinServer, true)()

		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
		testAssertAdminDashboardOptions(t, page, locale, false)
	})

	t.Run("SSH enabled and external", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.SSH.Disabled, false)()
		defer test.MockVariableValue(&setting.SSH.StartBuiltinServer, false)()

		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
		testAssertAdminDashboardOptions(t, page, locale, true)
	})

	t.Run("System status", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()

		// Check data units translations in the System status table
		selector := ".table[hx-get='/admin/system_status'] > dl > dd"
		// ...in English
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
		assert.Contains(t, page.Find(selector).Text(), "MiB")

		// ...in another language
		lang := session.GetCookie("lang")
		lang.Value = "ru-RU"
		session.SetCookie(lang)

		page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
		assert.Contains(t, page.Find(selector).Text(), "МиБ")
	})
}

// The update checker is off by default: a result stored by an earlier run (e.g. Forgejo's) must not show a banner.
func TestAdminDashboardUpdateCheck(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.AppVer, "16.0.0")()
	defer func() { require.NoError(t, system.AppState.Set(t.Context(), &updatechecker.CheckerState{})) }()

	defer test.MockVariableValue(&cron.UpdateCheckerSettings.Enabled, false)()
	session := loginUser(t, "user1")

	dashboard := func(t *testing.T, state updatechecker.CheckerState) (string, *HTMLDoc) {
		t.Helper()
		require.NoError(t, system.AppState.Set(t.Context(), &state))
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin"), http.StatusOK)
		return resp.Body.String(), NewHTMLParser(t, bytes.NewBuffer(resp.Body.Bytes()))
	}

	t.Run("disabled ignores a stale result", func(t *testing.T) {
		body, _ := dashboard(t, updatechecker.CheckerState{SupportedVersions: []string{"99.0.0"}})
		assert.NotContains(t, body, "99.0.0")
	})

	cron.UpdateCheckerSettings.Enabled = true
	for name, state := range map[string]updatechecker.CheckerState{
		"minor": {SupportedVersions: []string{"16.0.1"}},
		"major": {SupportedVersions: []string{"99.0.0"}},
		"error": {Error: "boom"},
	} {
		t.Run("enabled "+name, func(t *testing.T) {
			body, doc := dashboard(t, state)
			doc.AssertSelection(t, doc.Find(`.flash-error a[href="https://github.com/InfiniteDepo/gitdepo/releases"]`), true)
			assert.NotContains(t, body, "forgejo.org/releases")
		})
	}
}
