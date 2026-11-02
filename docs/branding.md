# gitdepo branding

gitdepo is a modified version of Forgejo. The interface, emails, logo and defaults say **gitdepo**; the code, the Go module path (`forgejo.org`), the `forgejo` binary and CLI, config sections, API paths and database stay Forgejo's, so upstream merges stay cheap. This page lists every place the rename touches, so an upstream merge can keep it.

## What stays "Forgejo"

Visible text keeps "Forgejo" where it names the upstream project or ecosystem, not the running product:

- the footer credit link "based on Forgejo" (CSS class `codehat-credit`, a code identifier kept from the first rename; locale key `based_on_forgejo`);
- Forgejo Actions, the `forgejo-runner` program (an external binary: the runner setup pages call it "gitdepo runner" and show its command `forgejo-runner daemon`; the example connection name is `gitdepo`), the `FORGEJO_` variable and secret prefixes;
- the "Forgejo" migration source and the `forgejo-*` theme names;
- the `MyForgejoOrganization` / `MyForgejoTeam*` group-map placeholders in the LDAP and OAuth2 auth-source forms (upstream templates kept; the guard's word boundaries ignore them);
- upstream documentation URLs (`forgejo.org/docs…`) where a page prints one;
- `next.forgejo.org`, upstream's example host in the installer's domain and URL placeholders;
- documentation links (`AppDocsURL`, "Forgejo documentation"), the translation-project line and the translators' strings `meta.last_line` and `test`;
- the API (`/api/forgejo/v1`, swagger titles), CLI help and output (the `forgejo` binary and its subcommands are code identifiers), log messages, git hook messages (`remote: Forgejo: …`), the git `user.name`, the `X-Mailer` header and the migration/LFS User-Agents.

`TestBranding` (`tests/integration/branding_test.go`) and the install, 500 and mail tests use `test.BrandMentions` (`modules/test/brand.go`). It fails on any visible old product name (Forgejo and the earlier product names, in any case) and on the capitalised "Gitdepo" and "GITDEPO": the name is always lowercase, even at the start of a sentence. It reads body text (including `<pre>` and `<code>`), the title and the `content`, `alt`, `title`, `placeholder` and `aria-label` attributes. Its `test.BrandAllowed` list holds the exact phrases above that appear on the pages it checks ("based on Forgejo", "Forgejo documentation", `forgejo-runner`, `forgejo.org/docs`, `next.forgejo.org`); each has a comment.

## Beyond the HTML pages

Text that never reaches the rendered pages `TestBranding` reads is guarded by `TestNoOldBrandInUserFacingSource` (`modules/test/brand_source_test.go`): plain-text error pages, `WWW-Authenticate` realms, the Teams card, the JS error banner, swagger descriptions and package install snippets. A new such string goes into its file list; an upstream reference that stays true as written goes into the swagger allow list. The LFS realm `gitea-lfs` stays (protocol string). Leftovers outside these places are tracked in the issue tracker.

## Strings: shadow keys

`modules/translation/i18n/localestore.go` looks a key up in `options/locale_next/` before `options/locale/`. So instead of editing upstream's `locale_en-US.ini`, gitdepo adds the **same key** with gitdepo wording at the top of `options/locale_next/locale_en-US.json`. The ini line, templates and Go call sites stay untouched. Other languages are untouched too.

Shadowed ini keys (also listed in `gitdepoShadowKeys`, `modules/translation/gitdepo_test.go`):

- `return_to_forgejo`
- `repo.settings.web_hook_name_forgejo`
- `startpage.platform_desc`
- `startpage.lightweight_desc`
- `startpage.license_desc`
- `install.docker_helper`
- `install.require_db_desc`
- `install.sqlite_helper`
- `install.reinstall_error`
- `install.reinstall_confirm_message`
- `install.reinstall_confirm_check_3`
- `install.run_user_helper`
- `install.http_port_helper`
- `install.smtp_from_helper`
- `install.install_btn_confirm`
- `install.sqlite3_not_available`
- `install.enable_update_checker_helper_forgejo`
- `auth.non_local_account`
- `settings.password_change_disabled`
- `settings.tokens_desc`
- `settings.oauth2_application_locked`
- `settings.authorized_oauth2_applications_description`
- `settings.manage_account_links_desc`
- `settings.remove_account_link_desc`
- `repo.mirror_use_ssh.helper`
- `repo.pulls.cmd_instruction_merge_desc`
- `repo.settings.trust_model.committer.long`
- `repo.settings.trust_model.committer.desc`
- `repo.settings.trust_model.collaboratorcommitter.desc`
- `repo.settings.hooks_desc`
- `repo.settings.add_webhook_desc`
- `repo.release.deletion_desc`
- `admin.users.allow_git_hook_tooltip`
- `admin.defaulthooks.desc`
- `admin.systemhooks.desc`
- `admin.auths.attribute_username_placeholder`
- `admin.config.app_ver`
- `admin.config.allow_only_internal_registration`
- `admin.self_check.database_collation_case_insensitive`

New key: `based_on_forgejo` (footer credit).

`locale_next` keys edited in place (they already lived in that file):

- `incorrect_root_url`
- `install.ssh_authorized_keys_unexpected_key`
- `admin.dashboard.new_major_version_hint`
- `admin.dashboard.new_minor_version_hint`
- `admin.dashboard.update_checker_error`
- `admin.dashboard.resync_all_sshkeys`
- `admin.dashboard.resync_all_sshprincipals`
- `settings.must_enable_2fa`
- `settings.authorized_integration.desc`
- `settings.authorized_integration.forgejo_actions_local.description`
- `error.must_enable_2fa`
- `packages.owner.settings.chef.keypair.description`
- `actions.runners.runner_details.labels_note`
- `actions.workflow.permissions_warning`
- `actions.variables.mutation.name_description`
- `actions.secrets.mutation.name_description`

`error.report_message_githat` (500 page) keeps its pre-rename key name (a code identifier); it shows no product name.

## Overridden templates

- `templates/base/footer_content.tmpl`: "Powered by gitdepo" links to the repository, plus the `based on Forgejo` credit link.
- `templates/home_forgejo.tmpl`: the `startpage.install_desc` and `startpage.license_desc` links point to the gitdepo repository.
- `templates/webhook/new/{slack,discord,packagist}.tmpl`: the username placeholder is "gitdepo".
- `templates/admin/dashboard.tmpl`: the update-checker hints link to the gitdepo releases.
- `templates/status/500.tmpl`: uses `error.report_message_githat` with `ISSUE_TRACKER_URL`.

## Boards

Forgejo's kanban "Projects" are called **Boards** in the interface, so that "Projects" can mean a group of repositories. The rename is text only: locale keys (`repo.projects.*`, `user.projects`, ...), routes (`/{owner}/-/projects`, `/{owner}/{repo}/projects`), the API, templates and code keep the upstream "project" names. The English wording is shadowed like the product name above (same key in `options/locale_next/locale_en-US.json`), and the keys are listed in `boardsShadowKeys` (`modules/translation/gitdepo_test.go`); `TestBoardsShadowKeys` fails when upstream renames or removes one. Generic uses of "project" (a software project, a Pagure or Bitbucket project, package metadata) stay. A new upstream string that names the kanban feature shows up as "project": shadow it and add it to the list.

## Defaults and assets

- `modules/setting/server.go`: `APP_NAME` defaults to `gitdepo`; `ISSUE_TRACKER_URL` to the gitdepo issues.
- `modules/setting/ui.go`: `[ui.meta]` `AUTHOR`, `DESCRIPTION`, `KEYWORDS`; `DEFAULT_THEME = company-auto`, and the company themes come first in `THEMES`.
- `routers/install/install.go`: the installer's default site title is `gitdepo` and its default slogan `A self-hosted Git forge` (upstream: Forgejo's slogan).
- `services/mailer/mail.go`: the admin test email's subject and body.
- `modules/updatechecker`: the `gitdepo-update-checker` User-Agent; `services/cron` checks the gitdepo GitHub releases.
- `assets/logo.svg`, `assets/favicon.svg`: the gitdepo mark. `make generate-images` writes `public/assets/img/{logo,favicon}.{svg,png}`, `apple-touch-icon.png` and `avatar_default.png`; the PWA manifest uses `logo.png`/`logo.svg`.
- `custom/conf/app.example.ini` documents the same defaults; `tests/*.ini.tmpl` set `APP_NAME = gitdepo`.

## Repository URLs

These link to `github.com/InfiniteDepo/gitdepo`; change them if the repository moves again: the footer, the home page (`startpage.install_desc` links to the releases, container package and repository; `startpage.license_desc` to the repository and its issues), the admin dashboard update hints, `ISSUE_TRACKER_URL` and the update checker's `HTTP_ENDPOINT` defaults (`modules/setting/server.go`, `services/cron/tasks_extended.go`, `custom/conf/app.example.ini` and their tests), README links, and the ACR OIDC subject comment in `.github/workflows/release-image.yml` (the subject itself is set in Azure). The image path is derived from the repository name, so the workflows need no change.

## Merging upstream

1. Merge as usual. Locale conflicts: keep both sides.
2. Run `go test ./modules/translation/ -run TestGitdepoShadowKeys`. It fails when upstream renames or removes a shadowed ini key: move the shadow to the new key, update the list above and in the test.
3. New upstream strings that name the product show up as "Forgejo": `make 'test-sqlite#TestBranding'` catches them on the pages it covers. Shadow them as above.
4. Conflicts in the templates above: keep upstream's change and re-apply the gitdepo line.
5. If upstream changes `assets/logo.svg`, keep ours and rerun `make generate-images`.
