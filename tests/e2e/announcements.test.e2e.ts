// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/announcement/**
// templates/admin/navbar.tmpl
// templates/base/announcements.tmpl
// templates/base/head.tmpl
// routers/web/admin/announcements.go
// routers/web/user/announcement.go
// services/announcement/**
// models/system/announcement.go
// web_src/css/base.css
// tests/e2e/shared/fake-data.ts
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {FakeData, fakeName, loginAs, loginAsAdmin} from './shared/fake-data.ts';

let data: FakeData;

test.beforeEach(({request}) => {
  data = new FakeData(request);
});

test.afterEach(async () => {
  await data.cleanup();
});

test('An administrator announces something and a user dismisses it', async ({browser}) => {
  test.setTimeout(120000);

  const user = await data.createUser();
  const admin = await (await loginAsAdmin(browser)).newPage();
  const word = fakeName('maintenance');
  let id = 0;

  await test.step('create the announcement with a preview', async () => {
    await admin.goto('/admin/announcements');
    await admin.getByRole('link', {name: 'Create announcement'}).click();
    await admin.getByRole('textbox', {name: 'Message'}).fill(`Planned **${word}** tonight`);
    await admin.getByRole('button', {name: 'Preview'}).click();
    await expect(admin.locator('.combo-markdown-editor .markup strong')).toHaveText(word);
    await admin.getByLabel('Type').selectOption('warning');
    await admin.getByLabel('Audience').selectOption('signed_in');
    await admin.getByLabel('Dismissible').check();
    await admin.getByRole('button', {name: 'Create announcement'}).click();
    await expect(admin).toHaveURL(/\/admin\/announcements$/);
    await expect(admin.locator('.flash-success')).toContainText('The announcement has been created.');

    const banner = admin.locator('.site-announcement', {hasText: word});
    await expect(banner).toBeVisible();
    id = Number(await banner.getAttribute('data-announcement-id'));
    data.trackAnnouncement(id);
    await expect(admin.locator('.admin-setting-content tr', {hasText: word})).toContainText('Active');
  });

  const page = await (await loginAs(browser, user.username, user.password)).newPage();
  const banner = page.locator('.site-announcement', {hasText: word});

  await test.step('a signed-in user sees it on every page and dismisses it', async () => {
    await page.goto('/explore/repos');
    await expect(banner).toBeVisible();
    await expect(banner.locator('strong')).toHaveText(word);
    await page.goto('/user/settings');
    await expect(banner).toBeVisible();

    await banner.getByRole('button', {name: 'Dismiss'}).click();
    await expect(page).toHaveURL(/\/user\/settings$/);
    await expect(banner).toHaveCount(0);
    await page.goto('/explore/repos');
    await expect(banner).toHaveCount(0);
  });

  await test.step('it comes back when the message changes', async () => {
    await admin.goto(`/admin/announcements/${id}`);
    await admin.getByRole('textbox', {name: 'Message'}).fill(`Planned **${word}** tomorrow`);
    await admin.getByRole('button', {name: 'Update announcement'}).click();
    await expect(admin.locator('.flash-success')).toContainText('The announcement has been updated.');

    await page.goto('/explore/repos');
    await expect(banner).toContainText('tomorrow');
  });

  await test.step('anonymous visitors do not see announcements for signed-in users', async () => {
    const anonymous = await browser.newPage();
    await anonymous.goto('/explore/repos');
    await expect(anonymous.locator('.site-announcement', {hasText: word})).toHaveCount(0);
    await anonymous.close();
  });

  await test.step('delete the announcement', async () => {
    await admin.goto(`/admin/announcements/${id}`);
    await admin.getByRole('button', {name: 'Delete announcement'}).click();
    await admin.locator('#delete-announcement').getByRole('button', {name: 'Yes'}).click();
    await expect(admin).toHaveURL(/\/admin\/announcements$/);
    await expect(admin.locator('.flash-success')).toContainText('The announcement has been deleted.');
    await page.goto('/explore/repos');
    await expect(banner).toHaveCount(0);
  });

  await page.context().close();
});

test('An anonymous visitor dismisses an announcement and it stays closed', async ({browser}) => {
  test.setTimeout(120000);

  const admin = await (await loginAsAdmin(browser)).newPage();
  const word = fakeName('anonymous');

  await admin.goto('/admin/announcements/new');
  await admin.getByRole('textbox', {name: 'Message'}).fill(`Hello ${word}`);
  await admin.getByLabel('Type').selectOption('info');
  await admin.getByLabel('Dismissible').check();
  await admin.getByRole('button', {name: 'Create announcement'}).click();
  await expect(admin.locator('.flash-success')).toContainText('The announcement has been created.');
  const id = Number(await admin.locator('.site-announcement', {hasText: word}).getAttribute('data-announcement-id'));
  data.trackAnnouncement(id);

  const context = await browser.newContext({storageState: {cookies: [], origins: []}});
  const page = await context.newPage();
  const banner = page.locator('.site-announcement', {hasText: word});
  await page.goto('/explore/repos');
  await expect(banner).toBeVisible();
  await banner.getByRole('button', {name: 'Dismiss'}).click();
  await expect(page).toHaveURL(/\/explore\/repos$/);
  await expect(banner).toHaveCount(0);
  await page.reload();
  await expect(banner).toHaveCount(0);
  await context.close();
  await admin.context().close();
});
