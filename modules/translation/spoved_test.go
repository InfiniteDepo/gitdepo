// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package translation

import (
	"os"
	"testing"

	"forgejo.org/modules/json"
	"forgejo.org/modules/test"
	"forgejo.org/modules/translation/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spovedShadowKeys are upstream locale_en-US.ini keys that options/locale_next/locale_en-US.json
// overrides with spoved wording (see docs/branding.md).
var spovedShadowKeys = []string{
	"return_to_forgejo",
	"repo.settings.web_hook_name_forgejo",
	"startpage.platform_desc",
	"startpage.lightweight_desc",
	"startpage.license_desc",
	"install.docker_helper",
	"install.require_db_desc",
	"install.sqlite_helper",
	"install.reinstall_error",
	"install.reinstall_confirm_message",
	"install.reinstall_confirm_check_3",
	"install.run_user_helper",
	"install.http_port_helper",
	"install.smtp_from_helper",
	"install.install_btn_confirm",
	"install.sqlite3_not_available",
	"install.enable_update_checker_helper_forgejo",
	"auth.non_local_account",
	"settings.password_change_disabled",
	"settings.tokens_desc",
	"settings.oauth2_application_locked",
	"settings.authorized_oauth2_applications_description",
	"settings.manage_account_links_desc",
	"settings.remove_account_link_desc",
	"repo.mirror_use_ssh.helper",
	"repo.pulls.cmd_instruction_merge_desc",
	"repo.settings.trust_model.committer.long",
	"repo.settings.trust_model.committer.desc",
	"repo.settings.trust_model.collaboratorcommitter.desc",
	"repo.settings.hooks_desc",
	"repo.settings.add_webhook_desc",
	"repo.release.deletion_desc",
	"admin.users.allow_git_hook_tooltip",
	"admin.defaulthooks.desc",
	"admin.systemhooks.desc",
	"admin.auths.attribute_username_placeholder",
	"admin.config.app_ver",
	"admin.config.allow_only_internal_registration",
	"admin.self_check.database_collation_case_insensitive",
}

// boardsShadowKeys are upstream locale_en-US.ini keys for the kanban feature that
// options/locale_next/locale_en-US.json words as "boards" (see docs/branding.md), so that
// "Projects" can mean groups of repositories.
var boardsShadowKeys = []string{
	"search.project_kind",
	"user.projects",
	"settings.comment_type_group_project",
	"repo.project",
	"repo.projects",
	"repo.projects.create",
	"repo.projects.new",
	"repo.projects.new_subheader",
	"repo.projects.create_success",
	"repo.projects.deletion",
	"repo.projects.deletion_desc",
	"repo.projects.deletion_success",
	"repo.projects.edit",
	"repo.projects.edit_subheader",
	"repo.projects.modify",
	"repo.projects.edit_success",
	"repo.projects.template.desc_helper",
	"repo.projects.column.deletion_desc",
	"repo.issues.new.projects",
	"repo.issues.new.clear_projects",
	"repo.issues.new.no_projects",
	"repo.issues.new.open_projects",
	"repo.issues.new.closed_projects",
	"repo.issues.add_project_at",
	"repo.issues.change_project_at",
	"repo.issues.remove_project_at",
	"repo.issues.filter_project",
	"repo.issues.filter_project_all",
	"repo.issues.filter_project_none",
	"repo.settings.projects_desc",
	"projects.deleted.display_name",
	"projects.type-1.display_name",
	"projects.type-2.display_name",
	"projects.type-3.display_name",
	"repo.permissions.projects.read",
	"repo.permissions.projects.write",
}

func TestSpovedShadowKeys(t *testing.T) {
	ini, err := os.ReadFile("../../options/locale/locale_en-US.ini")
	require.NoError(t, err)
	next, err := os.ReadFile("../../options/locale_next/locale_en-US.json")
	require.NoError(t, err)

	upstream := i18n.NewLocaleStore()
	require.NoError(t, upstream.AddLocaleByIni("en-US", "English", PluralRules[0], UsedPluralForms[0], ini, nil))
	shadowed := i18n.NewLocaleStore()
	require.NoError(t, shadowed.AddLocaleByIni("en-US", "English", PluralRules[0], UsedPluralForms[0], ini, nil))
	require.NoError(t, shadowed.AddToLocaleFromJSON("en-US", next))
	upstreamEn, _ := upstream.Locale("en-US")
	en, _ := shadowed.Locale("en-US")

	for _, key := range spovedShadowKeys {
		assert.True(t, upstreamEn.HasKey(key), "%s is no longer in locale_en-US.ini: update the shadow key and docs/branding.md", key)
		value := en.TrString(key)
		assert.Contains(t, value, "gitdepo", key)
		assert.Empty(t, test.BrandMentions(value), key)
	}
}

func TestBoardsShadowKeys(t *testing.T) {
	ini, err := os.ReadFile("../../options/locale/locale_en-US.ini")
	require.NoError(t, err)
	next, err := os.ReadFile("../../options/locale_next/locale_en-US.json")
	require.NoError(t, err)

	upstream := i18n.NewLocaleStore()
	require.NoError(t, upstream.AddLocaleByIni("en-US", "English", PluralRules[0], UsedPluralForms[0], ini, nil))
	shadowed := i18n.NewLocaleStore()
	require.NoError(t, shadowed.AddLocaleByIni("en-US", "English", PluralRules[0], UsedPluralForms[0], ini, nil))
	require.NoError(t, shadowed.AddToLocaleFromJSON("en-US", next))
	upstreamEn, _ := upstream.Locale("en-US")
	en, _ := shadowed.Locale("en-US")

	for _, key := range boardsShadowKeys {
		assert.True(t, upstreamEn.HasKey(key), "%s is no longer in locale_en-US.ini: update the shadow key and docs/branding.md", key)
		value := en.TrString(key)
		assert.Regexp(t, `(?i)boards?`, value, key)
		assert.NotRegexp(t, `(?i)project`, value, key)
	}
}

func TestSpovedLocaleNextValues(t *testing.T) {
	next, err := os.ReadFile("../../options/locale_next/locale_en-US.json")
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, json.Unmarshal(next, &values))
	for key, v := range values {
		if s, ok := v.(string); ok {
			assert.NotRegexp(t, `CodeHat|GitHat|(?i:\bspoved\b)|Gitdepo|GITDEPO`, s, key)
		}
	}
}
