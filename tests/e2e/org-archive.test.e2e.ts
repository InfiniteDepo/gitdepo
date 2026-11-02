// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/header.tmpl
// templates/org/settings/delete.tmpl
// templates/explore/users.tmpl
// templates/admin/org/list.tmpl
// routers/web/org/setting.go
// routers/web/explore/org.go
// services/org/archive.go
// services/context/org.go
// tests/e2e/shared/fake-data.ts
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {adminAuth, FakeData, loginAs} from './shared/fake-data.ts';

let data: FakeData;
let orgName = '';

test.beforeEach(({request}) => {
  data = new FakeData(request);
});

test.afterEach(async ({request}) => {
  // an archived organization cannot have its repositories deleted by the cleanup
  if (orgName) await request.post(`/api/v1/orgs/${orgName}/unarchive`, {headers: adminAuth()});
  await data.cleanup();
});

test('An owner archives an organization and unarchives it again', async ({browser}) => {
  test.setTimeout(120000);

  const owner = await data.createUser();
  orgName = await data.createOrg(owner);
  await data.createRepo(orgName);
  const page = await (await loginAs(browser, owner.username, owner.password)).newPage();

  await test.step('archive from the danger zone', async () => {
    await page.goto(`/org/${orgName}/settings/delete`);
    await page.getByRole('button', {name: 'Archive organization'}).click();
    await expect(page.locator('.flash-success')).toContainText('The organization was archived.');
  });

  await test.step('the org shows the badge and the banner', async () => {
    await page.goto(`/${orgName}`);
    await expect(page.locator('.org-archived-banner')).toBeVisible();
  });

  await test.step('Explore hides it unless archived organizations are shown', async () => {
    await page.goto(`/explore/organizations?q=${orgName}`);
    await expect(page.getByRole('link', {name: orgName})).toHaveCount(0);
    await page.goto(`/explore/organizations?q=${orgName}&archived=true`);
    await expect(page.getByRole('link', {name: orgName})).toBeVisible();
  });

  await test.step('unarchive again', async () => {
    await page.goto(`/org/${orgName}/settings/delete`);
    await page.getByRole('button', {name: 'Unarchive organization'}).click();
    await expect(page.locator('.flash-success')).toContainText('The organization was unarchived.');
    await page.goto(`/${orgName}`);
    await expect(page.locator('.org-archived-banner')).toHaveCount(0);
  });
});
