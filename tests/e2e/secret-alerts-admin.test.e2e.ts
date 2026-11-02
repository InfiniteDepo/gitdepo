// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/secret_scanning.tmpl
// routers/web/admin/secret_scanning.go
// services/secretscan/**
// web_src/js/features/secret-alerts.js
// web_src/css/repo/secret-alerts.css
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.describe('as the site admin', () => {
  test.use({user: 'user1'});

  // the instance starts with scanning on, the generic rule off and no saved limit: restored after each test
  test.afterEach(async ({page}) => {
    for (const [path, form] of [['switches', {enabled: 'on'}], ['limits', {max_blob_size: '1', scan_timeout: '300', max_scan_bytes: '2048'}]] as const) {
      const resp = await page.request.post(`/admin/config/secret-scanning/${path}`, {form, maxRedirects: 0});
      expect(resp.status()).toBe(303);
    }
  });

  test('the switches ask first when they turn scanning off or a rule on', async ({page}) => {
    await page.goto('/admin/config/secret-scanning');
    const enabled = page.locator('#secret-scanning-enabled');
    const generic = page.locator('#secret-scanning-generic');
    await expect(enabled).toBeChecked();
    await expect(generic).not.toBeChecked();
    await screenshot(page);

    // the generic rule
    await page.locator('label[for="secret-scanning-generic"]').click();
    await page.locator('#secret-scanning-switches-save').click();
    const rule = page.locator('#secret-scanning-generic-modal');
    await expect(rule).toBeVisible();
    await expect(rule).toContainText('Turn on the generic high-entropy rule?');
    await screenshot(page);
    await rule.getByRole('button', {name: 'Cancel'}).click();
    await page.reload();
    await expect(generic).not.toBeChecked();
    await page.locator('label[for="secret-scanning-generic"]').click();
    await page.locator('#secret-scanning-switches-save').click();
    await rule.getByRole('button', {name: 'Turn on rule'}).click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(generic).toBeChecked();
    await expect(page.locator('.admin-setting-content')).toContainText('Last changed');

    // the site off
    await page.locator('label[for="secret-scanning-enabled"]').click();
    await page.locator('#secret-scanning-switches-save').click();
    const site = page.locator('#secret-scanning-site-off-modal');
    await expect(site).toBeVisible();
    await expect(site).toContainText('Stop secret scanning on all repositories?');
    await screenshot(page);
    await site.getByRole('button', {name: 'Turn off scanning'}).click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(enabled).not.toBeChecked();
    // turning the rule off, and the site on, ask nothing
    await page.locator('label[for="secret-scanning-enabled"]').click();
    await page.locator('label[for="secret-scanning-generic"]').click();
    await page.locator('#secret-scanning-switches-save').click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(enabled).toBeChecked();
    await expect(generic).not.toBeChecked();
  });

  test('the limits are a separate form with their own errors', async ({page}) => {
    await page.goto('/admin/config/secret-scanning');
    const blob = page.locator('#secret-limit-max_blob_size');
    await expect(blob).toHaveValue('1');
    await expect(page.locator('#secret-limit-max_blob_size-default')).toContainText('Default from app.ini: 1');

    // refused: nothing is saved and the typed value stays
    await blob.fill('500');
    await page.locator('#secret-scanning-limits-save').click();
    await expect(page.locator('#secret-scanning-limits-error')).toContainText('Nothing was saved. Largest file scanned must be at least 64 KiB and at most 100 MiB.');
    await expect(blob).toHaveValue('500');
    await screenshot(page);

    await blob.fill('2');
    await page.locator('#secret-scanning-limits-save').click();
    await expect(page.locator('#flash-message')).toContainText('Secret scanning settings saved.');
    await expect(blob).toHaveValue('2');
    // the switches are untouched
    await expect(page.locator('#secret-scanning-enabled')).toBeChecked();
  });
});
