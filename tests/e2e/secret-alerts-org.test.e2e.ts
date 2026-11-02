// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/settings/code_security.tmpl
// templates/org/settings/secret_scanning_off.tmpl
// routers/web/org/setting/code_security.go
// services/secretscan/**
// web_src/js/features/secret-alerts.js
// web_src/css/repo/secret-alerts.css
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {FakeData, loginAs} from './shared/fake-data.ts';
import {screenshot} from './shared/screenshots.ts';

test.describe('the organization page', () => {
  test.use({user: null, storageState: {cookies: [], origins: []}});

  let data: FakeData;

  test.beforeEach(({request}) => {
    data = new FakeData(request);
  });

  test.afterEach(async () => {
    await data.cleanup();
  });

  test('an owner turns scanning off and locks it, each after a confirmation', async ({browser}) => {
    const owner = await data.createUser();
    const org = await data.createOrg(owner);
    await data.createRepo(org);
    const page = await (await loginAs(browser, owner.username, owner.password)).newPage();
    await page.goto(`/org/${org}/settings/code_security`);
    const enabled = page.locator('#secret-scanning-enabled');
    const locked = page.locator('#secret-scanning-locked');
    await expect(enabled).toBeChecked();
    await expect(locked).not.toBeChecked();
    await expect(page.locator('#secret-scanning-counts')).toContainText('On in 1 of 1 repositories');
    await screenshot(page);

    // off asks first, and Cancel changes nothing
    await page.locator('label[for="secret-scanning-enabled"]').click();
    await page.locator('#secret-scanning-save').click();
    const off = page.locator('#secret-scanning-org-off-modal');
    await expect(off).toBeVisible();
    await expect(off).toContainText('Turn off secret scanning in 1 repository?');
    await screenshot(page);
    await off.getByRole('button', {name: 'Cancel'}).click();
    await expect(off).toBeHidden();
    await page.reload();
    await expect(enabled).toBeChecked();

    // confirmed
    await page.locator('label[for="secret-scanning-enabled"]').click();
    await page.locator('#secret-scanning-save').click();
    await off.getByRole('button', {name: 'Turn off scanning'}).click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(enabled).not.toBeChecked();
    await expect(page.locator('#secret-scanning-counts')).toContainText('Off for all 1 repositories');

    // with scanning off, ticking only the lock asks nothing (the lock asks only while scanning stays on)
    await page.locator('label[for="secret-scanning-locked"]').click();
    await page.locator('#secret-scanning-save').click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(enabled).not.toBeChecked();
    await expect(locked).toBeChecked();

    // lift it again, then turn scanning on and lock it in one save, which asks first
    await page.locator('label[for="secret-scanning-locked"]').click();
    await page.locator('#secret-scanning-save').click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(locked).not.toBeChecked();
    await page.locator('label[for="secret-scanning-enabled"]').click();
    await page.locator('label[for="secret-scanning-locked"]').click();
    await page.locator('#secret-scanning-save').click();
    const lock = page.locator('#secret-scanning-org-lock-modal');
    await expect(lock).toBeVisible();
    await expect(lock).toContainText(`Lock secret scanning on for all repositories of ${org}?`);
    await screenshot(page);
    await lock.getByRole('button', {name: 'Lock scanning on'}).click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(enabled).toBeChecked();
    await expect(locked).toBeChecked();
    await expect(page.locator('#secret-scanning-counts')).toContainText('On in 1 of 1 repositories');

    // unlocking and saving other changes ask nothing
    await page.locator('label[for="secret-scanning-locked"]').click();
    await page.locator('#secret-scanning-save').click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(locked).not.toBeChecked();
  });

  test('the list of repositories that turned scanning off', async ({browser}) => {
    const owner = await data.createUser();
    const org = await data.createOrg(owner);
    const repo = await data.createRepo(org);
    const page = await (await loginAs(browser, owner.username, owner.password)).newPage();

    // the repository's admin turns it off on the repository settings page
    await page.goto(`/${org}/${repo}/settings/code_security`);
    await page.locator('label[for="secret-scanning-enabled"]').click();
    await page.locator('#secret-scanning-save').click();
    await page.locator('#secret-scanning-off-submit').click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');

    await page.goto(`/org/${org}/settings/code_security`);
    await expect(page.locator('#secret-scanning-counts')).toContainText('1 repository was turned off');
    await page.locator('#secret-scanning-off-link').click();
    await expect(page.locator('#secret-scanning-off-list')).toContainText(`${org}/${repo}`);
    await expect(page.locator('#secret-scanning-off-list')).toContainText('Turned off by');
    await screenshot(page);
  });
});
