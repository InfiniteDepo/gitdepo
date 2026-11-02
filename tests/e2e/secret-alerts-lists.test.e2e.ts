// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/security_secrets.tmpl
// templates/org/security_tabs.tmpl
// templates/shared/secret_alerts.tmpl
// templates/admin/secret_alerts.tmpl
// routers/web/org/security.go
// routers/web/admin/security_search.go
// routers/web/shared/security/secrets.go
// services/secretscan/search.go
// web_src/css/repo/vulnerability.css
// @watch end

import {expect, type Page} from '@playwright/test';
import {readFile} from 'node:fs/promises';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

const rows = (page: Page) => page.locator('table.secret-search-table tbody tr');

// the page doesn't scroll sideways, on a phone too
async function fitsTheScreen(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
}

test.describe('an organization owner', () => {
  test.use({user: 'user2'});

  test('reads, filters and downloads the secret alerts of the organization', async ({page, isMobile}) => {
    if (isMobile) { // on a phone the tabs are in an overflow menu
      await page.goto('/org/org3/security/secrets');
    } else {
      await page.goto('/org3');
      await page.getByRole('link', {name: 'Security', exact: true}).click();
      await page.getByRole('link', {name: 'Secret alerts', exact: true}).click();
    }
    await expect(page).toHaveURL(/\/org\/org3\/security\/secrets$/);
    // the open alerts by default, as on the repository's page
    await expect(page.locator('#secret-search-total')).toHaveText('3 secret alerts in 2 repositories');
    await expect(rows(page)).toHaveCount(3);
    await expect(page.locator('#secret-search-note')).toContainText('Showing every repository in this organization that you can read.');
    await fitsTheScreen(page);
    await screenshot(page);

    // the state, reason and type filters; newest first: the closed alert, with its reason and who closed it
    await page.locator('select[name="state"]').selectOption('all');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    await expect(rows(page)).toHaveCount(4);
    await expect(rows(page).first()).toContainText('org3/secret-lists-web');
    await expect(rows(page).first()).toContainText('Private key');
    await expect(rows(page).first()).toContainText('Closed as revoked');
    await expect(rows(page).first()).toContainText('user2');
    await page.locator('select[name="state"]').selectOption('closed');
    await page.locator('select[name="reason"]').selectOption('revoked');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    await expect(rows(page)).toHaveCount(1);
    await page.locator('select[name="state"]').selectOption('');
    await page.locator('select[name="reason"]').selectOption('');
    await page.locator('select[name="type"]').selectOption({label: 'Slack token'});
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText('src/notify.js:14');
    await expect(rows(page).first()).toContainText('+1 more');

    // the repository search, and what an empty answer says
    await page.locator('select[name="type"]').selectOption('');
    await page.getByRole('searchbox').fill('lists-api');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    await expect(rows(page)).toHaveCount(2);
    await page.getByRole('searchbox').fill('no-such-repository');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    await expect(page.locator('#secret-search-none')).toContainText('No alerts match the filter.');
    await expect(page.locator('#secret-search-none')).toContainText('Repositories with secret scanning turned off are not listed.');
    await screenshot(page);
    await page.getByRole('link', {name: 'Clear filters'}).click();
    await expect(rows(page)).toHaveCount(3);

    // the download posts the filters and sends the file: no secret, a link to each alert
    await page.getByRole('searchbox').fill('lists-api');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', {name: 'Download CSV'}).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^secret-alerts-org3-\d{4}-\d\d-\d\d\.csv$/);
    const csv = await readFile(await download.path(), 'utf8');
    expect(csv.split('\n')[0]).toBe('state,reason,closed_by,closed_at,comment,first_seen,repository,type,location,alert_url');
    expect(csv).toContain('scripts/deploy.sh:14');
    expect(csv).toMatch(/\/org3\/secret-lists-api\/security\/secrets\/\d+/);
    expect(csv).not.toContain('secret-lists-web');

    // the type opens the alert in its repository
    await page.getByRole('link', {name: 'AWS access key ID'}).click();
    await expect(page).toHaveURL(/\/org3\/secret-lists-api\/security\/secrets\/\d+$/);
  });
});

test.describe('the site admin', () => {
  test.use({user: 'user1'});

  test('reads and downloads the secret alerts of every repository', async ({page}) => {
    await page.goto('/admin/security/secrets?owner=org3');
    await expect(page.getByRole('link', {name: 'Secret alerts', exact: true})).toBeVisible();
    await expect(page.locator('#secret-search-total')).toHaveText('3 secret alerts in 2 repositories');
    await expect(rows(page)).toHaveCount(3);
    await expect(page.locator('#secret-search-note')).toContainText('Every repository on the instance');
    await fitsTheScreen(page);
    await screenshot(page);

    // without the owner filter the repositories of other owners are there too
    await page.getByRole('textbox', {name: 'Owner'}).fill('');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    await expect(page.locator('#secret-search-total')).toHaveText(/^\s*\d+ secret alerts?\s+in \d+ repositor(y|ies)\s*$/);
    await expect(rows(page).filter({hasText: 'user11/secret-alerts-test'}).first()).toBeVisible();

    await page.getByRole('textbox', {name: 'Owner'}).fill('org3');
    await page.getByRole('button', {name: 'Search', exact: true}).click();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', {name: 'Download CSV'}).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^secret-alerts-instance-\d{4}-\d\d-\d\d\.csv$/);
    const csv = await readFile(await download.path(), 'utf8');
    expect(csv.trim().split('\n')).toHaveLength(4);
    expect(csv).toContain('org3/secret-lists-web');
  });
});

test.describe('an organization member', () => {
  test.use({user: 'user4'});

  test('sees the alerts of the repositories they can write to, and is told so', async ({page}) => {
    await page.goto('/org/org3/security/secrets');
    await expect(page.locator('#secret-search-none, #secret-search-total').first()).toBeVisible();
    await expect(page.locator('#secret-search-narrow')).toContainText('you can write to. Organization owners see every repository.');
    await fitsTheScreen(page);
    await screenshot(page);
  });
});

test.describe('someone with no alerts to read', () => {
  test.use({user: 'user12'});

  test('finds neither list', async ({page}) => {
    expect((await page.goto('/org/org3/security/secrets'))?.status()).toBe(404);
    expect((await page.goto('/admin/security/secrets'))?.status()).toBe(403);
  });
});
