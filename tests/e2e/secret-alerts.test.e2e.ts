// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/security/**
// templates/repo/header.tmpl
// templates/repo/settings/code_security.tmpl
// routers/web/repo/secret_alerts.go
// routers/web/repo/setting/code_security.go
// services/secretscan/**
// web_src/js/features/secret-alerts.js
// web_src/css/repo/secret-alerts.css
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

const repo = '/user11/secret-alerts-test';
const rows = (page) => page.locator('.repo-security-row:not(.repo-security-head)');

test.describe('a writer', () => {
  test.use({user: 'user11'});

  test('list, filter, close with a reason and reopen', async ({page, isMobile}) => {
    test.skip(isMobile, 'the phone test covers the layout');
    await page.goto(repo);
    await page.getByRole('link', {name: /^Security\s*5$/}).click();
    await page.getByRole('link', {name: /^Secret alerts\b/}).click();
    await expect(page).toHaveURL(new RegExp(`${repo}/security/secrets$`));
    await expect(page.getByRole('link', {name: '5 Open', exact: true})).toBeVisible();
    await expect(page.getByRole('link', {name: '1 Closed', exact: true})).toBeVisible();
    await expect(rows(page)).toHaveCount(5);
    await expect(page.locator('#secret-scan-status')).toContainText('Last scanned');
    await screenshot(page);

    // filter by type and search by path
    await page.locator('select[name="type"]').selectOption({label: 'Slack token'});
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText('src/notify/slack.js');
    await page.locator('select[name="type"]').selectOption({value: ''});
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(rows(page)).toHaveCount(5);
    await page.getByRole('searchbox').fill('deploy/certs');
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(rows(page)).toHaveCount(1);
    await page.getByRole('searchbox').fill('nothing-like-this');
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await page.getByRole('link', {name: 'Clear filters'}).click();
    await expect(rows(page)).toHaveCount(5);

    // the alert page never holds the secret: only a short fingerprint
    await rows(page).filter({hasText: 'src/notify/slack.js'}).getByRole('link').first().click();
    await expect(page.locator('#secret-fingerprint')).toHaveText(/^[0-9a-f]{12}$/);
    await expect(page.locator('#secret-guidance')).toBeVisible();
    await expect(page.getByRole('heading', {level: 3, name: 'Locations'})).toBeVisible();

    // close needs a reason, nothing is preselected
    await page.getByRole('button', {name: 'Close alert…', exact: true}).click();
    const dialog = page.locator('#secret-close-modal');
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('input[name="reason"]:checked')).toHaveCount(0);
    await dialog.getByLabel('Revoked').check();
    await dialog.locator('textarea').fill('Rotated in the Slack admin.');
    await screenshot(page);
    await dialog.getByRole('button', {name: 'Close alert', exact: true}).click();
    await expect(page.getByText('The alert was closed.', {exact: true})).toBeVisible();
    await expect(page.locator('#alert-state')).toContainText('Closed as revoked');
    await expect(page.locator('#secret-closed-note')).toContainText('Closed by user11');
    await expect(page.locator('#secret-closed-note')).toContainText('Rotated in the Slack admin.');
    await expect(page.locator('#secret-activity')).toContainText('closed it as revoked');
    await screenshot(page);

    await page.getByRole('button', {name: 'Reopen', exact: true}).click();
    await expect(page.getByText('The alert was reopened.', {exact: true})).toBeVisible();
    await expect(page.locator('#alert-state')).toHaveText('Open');
  });

  test('bulk close from the list, then reopen', async ({page, isMobile}) => {
    test.skip(isMobile, 'the phone test covers the layout');
    await page.goto(`${repo}/security/secrets`);
    await page.getByLabel('Select Generic secret assignment').check();
    await expect(page.locator('#secret-bulk')).toBeVisible();
    // exactly one: the text is "1 alert selected", without quotes (html/template escapes a data-on* attribute as JavaScript)
    await expect(page.locator('#secret-bulk-count')).toHaveText('1 alert selected');
    await screenshot(page);
    await page.getByRole('button', {name: 'Close selected…'}).click();
    const dialog = page.locator('#secret-bulk-modal');
    await expect(dialog.locator('.secret-modal-title')).toHaveText('Close 1 alert');
    await expect(dialog.getByRole('button', {name: 'Close alert', exact: true})).toBeVisible();
    await dialog.getByLabel('Used in tests').check();
    await dialog.getByRole('button', {name: 'Close alert', exact: true}).click();
    await expect(page.getByText('1 alert was closed.', {exact: true})).toBeVisible();
    await expect(rows(page)).toHaveCount(4);

    await page.goto(`${repo}/security/secrets?state=closed&reason=used_in_tests`);
    await expect(rows(page)).toHaveCount(1);
    await rows(page).first().getByRole('link').first().click();
    await page.getByRole('button', {name: 'Reopen', exact: true}).click();
    await expect(page.locator('#alert-state')).toHaveText('Open');
  });

  test('the settings switch asks before it turns scanning off', async ({page, isMobile}) => {
    test.skip(isMobile, 'the phone test covers the layout');
    await page.goto(`${repo}/settings/code_security`);
    const box = page.locator('#secret-scanning-box');
    await expect(box.getByLabel(/Enable secret scanning/)).toBeChecked();
    await box.getByText(/Enable secret scanning/).click();
    await box.getByRole('button', {name: 'Save'}).click();
    const dialog = page.locator('#secret-scanning-off-modal');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('5 open alerts are kept');
    await screenshot(page);
    await dialog.getByRole('button', {name: 'Turn off scanning'}).click();
    await expect(page.getByText('Secret scanning settings saved.', {exact: true})).toBeVisible();

    // the alerts are kept but hidden: a banner with the link to the settings, no list, no count, 404 for one alert
    await page.goto(`${repo}/security/secrets`);
    await expect(page.locator('#secret-banner-off')).toBeVisible();
    await expect(page.locator('#secret-banner-off a[href$="/settings/code_security"]')).toBeVisible();
    await expect(rows(page)).toHaveCount(0);
    await expect(page.locator('#secret-rescan')).toHaveCount(0);
    await expect(page.locator('.repo-security-menu a[href$="/security/secrets"] .label')).toHaveCount(0);
    expect((await page.goto(`${repo}/security/secrets/1`))?.status()).toBe(404);
    await page.goto(`${repo}/security/secrets`);
    await screenshot(page);

    await page.goto(`${repo}/settings/code_security`);
    await box.getByText(/Enable secret scanning/).click();
    await box.getByRole('button', {name: 'Save'}).click();
    await expect(page.getByText('Secret scanning settings saved.', {exact: true})).toBeVisible();
    await expect(box.getByLabel(/Enable secret scanning/)).toBeChecked();
  });

  test('rescan queues a new scan', async ({page, isMobile}) => {
    test.skip(isMobile, 'the phone test covers the layout');
    await page.goto('/user11/secret-rescan-test/security/secrets');
    await page.locator('#secret-rescan').click();
    await expect(page.getByText(/A new scan was queued/)).toBeVisible();
  });

  test('phone width: the pages stack without a horizontal scroll', async ({page}) => {
    await page.setViewportSize({width: 390, height: 800});
    await page.goto(`${repo}/security/secrets`);
    await expect(rows(page)).toHaveCount(5);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await rows(page).first().getByRole('link').first().click();
    await expect(page.locator('#secret-fingerprint')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.goto(`${repo}/settings/code_security`);
    await expect(page.locator('#secret-scanning-box')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  });
});

test.describe('someone without write access', () => {
  test.use({user: 'user2'});

  test('does not find the pages', async ({page}) => {
    const response = await page.goto(`${repo}/security/secrets`);
    expect(response?.status()).toBe(404);
  });
});
