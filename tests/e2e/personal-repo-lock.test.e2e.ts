// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/shared/personal_repo_limit.tmpl
// templates/repo/create.tmpl
// templates/repo/migrate/**
// templates/repo/pulls/fork.tmpl
// templates/repo/home.tmpl
// templates/repo/view_file.tmpl
// templates/repo/release_tag_header.tmpl
// templates/repo/wiki/**
// templates/admin/user/edit.tmpl
// templates/admin/personal_repos.tmpl
// services/context/quota.go
// services/context/repo.go
// web_src/js/features/admin/common.js
// @watch end

import {expect, type Page} from '@playwright/test';
import {test, create_temp_user, login_user} from './utils_e2e.ts';

test.use({user: null, storageState: {cookies: [], origins: []}});

async function setSiteLimitMiB(page: Page, mib: string) {
  await page.goto('/admin/personal-repos');
  await page.locator('#size_limit_mib').fill(mib);
  await page.getByRole('button', {name: 'Save'}).click();
  await expect(page.locator('#flash-message')).toContainText('The personal repository policy has been saved.');
}

test('Personal repository size lock: what the owner and others see', async ({browser, request}, workerInfo) => {
  const admin = await (await login_user(browser, workerInfo, 'user1')).newPage();
  const {context, username} = await create_temp_user(browser, workerInfo, request);
  const owner = await context.newPage();
  const basic = `Basic ${btoa(`${username}:password`)}`;
  const adminBasic = `Basic ${btoa('user1:password')}`;
  const created = await request.post('/api/v1/user/repos', {
    headers: {Authorization: basic},
    data: {name: 'locked', auto_init: true, readme: 'Default'},
  });
  expect(created.ok()).toBeTruthy();

  // a site limit nobody else reaches, and a 1-byte override for the new user
  await setSiteLimitMiB(admin, String(1 << 20));
  try {
    // E: the MiB field belongs to the custom mode
    const user = await (await request.get(`/api/v1/users/${username}`)).json();
    await admin.goto(`/admin/users/${user.id}/edit`);
    await expect(admin.locator('#personal_repo_size_limit')).toBeHidden();
    await admin.locator('#personal_repo_size_limit_mode').locator('..').click();
    await admin.locator('.menu .item[data-value="custom"]').click();
    await expect(admin.locator('#personal_repo_size_limit')).toBeVisible();
    await expect(admin.locator('#personal_repo_size_limit')).toBeEnabled();

    const patched = await request.patch(`/api/v1/admin/users/${username}`, {
      headers: {Authorization: adminBasic},
      data: {login_name: username, source_id: 0, personal_repo_size_limit: 1},
    });
    expect(patched.ok()).toBeTruthy();

    // A, #500: without an organization to choose, the create and migrate pages show the banner and no form
    for (const path of ['/repo/create', '/repo/migrate', '/repo/migrate?service_type=1']) {
      await owner.goto(path);
      await expect(owner.locator('#personal-repo-limit-banner')).toBeVisible();
      await expect(owner.locator('#personal-repo-limit-banner')).toContainText("You can't push or add content");
      await expect(owner.locator('form.ui.form, .ui.attached.segment, .migrate-entry')).toHaveCount(0);
    }

    // D: no add/edit actions for the owner
    await owner.goto(`/${username}/locked`);
    await expect(owner.locator('#personal-repo-limit-banner')).toBeVisible();
    await expect(owner.locator('a[href*="/_edit/"], a[href*="/_new/"], a[href*="/_upload/"]')).toHaveCount(0);
    await owner.goto(`/${username}/locked/releases`);
    await expect(owner.locator('a[href$="/releases/new"]')).toHaveCount(0);
    await owner.goto(`/${username}/locked/wiki`);
    await expect(owner.locator('a[href*="action=_new"]')).toHaveCount(0);

    // C: another signed-in user sees no banner
    const other = await (await login_user(browser, workerInfo, 'user2')).newPage();
    await other.goto(`/${username}/locked`);
    await expect(other.locator('#personal-repo-limit-banner')).toHaveCount(0);
  } finally {
    // the other specs run without a limit
    await setSiteLimitMiB(admin, '0');
  }
});
