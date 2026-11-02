// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/security.tmpl
// templates/shared/security_search.tmpl
// templates/org/menu.tmpl
// routers/web/org/security.go
// routers/web/shared/security/**
// web_src/css/repo/vulnerability.css
// @watch end

import {expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

test('an owner searches an advisory, reads the rows and downloads them', async ({page, isMobile}) => {
  await page.goto('/org3');
  if (!isMobile) { // on a phone the tabs are in an overflow menu
    await page.getByRole('link', {name: 'Security', exact: true}).click();
    await expect(page).toHaveURL(/\/org\/org3\/security\/vulnerabilities$/);
  } else {
    await page.goto('/org/org3/security');
  }
  await expect(page.getByText('Search for an advisory')).toBeVisible();
  await expect(page.locator('table.security-search-table')).toHaveCount(0);

  // a wrong ID marks the field and says how it should look
  await page.getByLabel('Advisory').fill('CVE 2026');
  await page.getByRole('button', {name: 'Search', exact: true}).click();
  await expect(page.locator('.negative.message')).toContainText('"CVE 2026" is not an advisory ID');
  await expect(page.getByLabel('Advisory')).toHaveAttribute('aria-invalid', 'true');

  await page.getByLabel('Advisory').fill('CVE-2099-0001');
  await page.getByRole('button', {name: 'Search', exact: true}).click();
  await expect(page).toHaveURL(/advisory=CVE-2099-0001/);
  await expect(page.locator('.security-search-card')).toContainText('Example ReDoS');
  await expect(page.locator('.security-search-card')).toContainText('GHSA-test-aaaa-bbbb');
  await expect(page.locator('.security-search-card')).toContainText('CVSS 7.5');
  await expect(page.locator('#security-search-total')).toHaveText('3 alerts in 2 repositories');
  const rows = page.locator('table.security-search-table tbody tr');
  await expect(rows).toHaveCount(3);
  await expect(rows.first()).toContainText('org3/repo3');
  await expect(rows.last()).toContainText('org3/repo5');
  await expect(rows.last()).toContainText('9.0.1');
  await expect(rows.last()).toContainText('9.0.7');
  await expect(rows.first().getByRole('link', {name: 'Open'})).toHaveAttribute('href', /\/org3\/repo3\/security\/alerts\/\d+$/);
  await screenshot(page);

  // the download posts the filters and sends the file
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', {name: 'Download CSV'}).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^vulnerability-alerts-org3-\d{4}-\d\d-\d\d\.csv$/);
  const csv = await readFile(await download.path(), 'utf8');
  expect(csv).toContain('GHSA-test-aaaa-bbbb');
  expect(csv).toContain('org3/repo5');
  expect(csv.trim().split('\n')).toHaveLength(4);
});

test('the dependencies tab lists the uses of a package, a range overlap marked', async ({page}) => {
  await page.goto('/org/org3/security');
  await page.getByRole('link', {name: 'Dependencies', exact: true}).click();
  await expect(page).toHaveURL(/\/org\/org3\/security\/dependencies$/);
  // no ecosystem yet: the field is marked instead of silently searching Go
  await page.getByLabel('Package').fill('example-glob');
  await page.getByRole('button', {name: 'Search', exact: true}).click();
  await expect(page.locator('.negative.message')).toHaveText('Choose an ecosystem.');
  await page.getByLabel('Ecosystem').selectOption('npm');
  await page.getByLabel('Version or range').fill('^3.0.0');
  await page.getByRole('button', {name: 'Search', exact: true}).click();
  await expect(page.locator('#security-search-total')).toHaveText('2 uses in 1 repository');
  const rows = page.locator('table.security-search-table tbody tr');
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText('3.0.4');
  await expect(rows.last()).toContainText('^3.0.0');
  await expect(rows.last()).toContainText('may match');
  await screenshot(page);
});

test('the rows stack with labels on a phone', async ({page}) => {
  await page.setViewportSize({width: 390, height: 900});
  await page.goto('/org/org3/security/vulnerabilities?advisory=CVE-2099-0001');
  const table = page.locator('table.security-search-table');
  // the header row is only visually hidden: a screen reader keeps the column names
  expect(await table.locator('thead').evaluate((e) => e.getBoundingClientRect().width)).toBeLessThanOrEqual(1);
  await expect(table.locator('thead th').first()).toHaveText('Repository');
  const row = table.locator('tbody tr').last();
  await expect(row.locator('td').first()).toBeVisible();
  await expect(row.getByText('Fixed in', {exact: false}).first()).toBeVisible();
  // the cells sit below each other, and the page doesn't scroll sideways
  const [a, b] = await row.locator('td').evaluateAll((cells) => cells.slice(0, 2).map((c) => c.getBoundingClientRect().top));
  expect(b).toBeGreaterThan(a);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await screenshot(page);
});
