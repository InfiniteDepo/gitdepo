// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/audit.tmpl
// routers/web/admin/audit.go
// services/audit/**
// web_src/css/admin.css
// web_src/js/features/admin/**
// @watch end

import {expect, type APIRequestContext} from '@playwright/test';
import {test} from './utils_e2e.ts';

test.use({user: 'user1'});

// createToken records a credential change for user1 and returns the token's name
async function createToken(request: APIRequestContext, project: string): Promise<string> {
  const name = `audit-e2e-${project.replace(/\W/g, '')}-${Date.now()}`;
  const resp = await request.post('/api/v1/users/user1/tokens', {
    headers: {Authorization: `Basic ${btoa('user1:password')}`},
    data: {name, scopes: ['read:user']},
  });
  expect(resp.ok()).toBeTruthy();
  return name;
}

test('Audit log filter bar', async ({page, request}, workerInfo) => {
  const token = await createToken(request, workerInfo.project.name);
  await page.setViewportSize({width: 1280, height: 900});
  const response = await page.goto('/admin/audit');
  expect(response?.status()).toBe(200);

  // the changes tab is the default and holds the token's creation
  await expect(page.locator('.audit-tabs .active.item')).toHaveText('Changes');
  const row = page.locator('.audit-entries > tbody > tr', {hasText: token});
  await expect(row).toContainText(`Created access token ${token}`);
  await expect(page.locator('#audit-org')).toBeVisible(); // the filters are open on wide screens

  // the details show the raw action key
  await row.locator('.audit-details summary').click();
  await expect(row.locator('.audit-details dd code').first()).toHaveText('credential.access_token.created');

  // a filter is a query parameter, the tab is kept
  await page.locator('.audit-tabs .item', {hasText: 'All'}).click();
  await page.locator('#audit-action').fill('credential.*');
  await page.getByRole('button', {name: 'Filter', exact: true}).click();
  await expect(page).toHaveURL(/category=all/);
  await expect(page).toHaveURL(/action=credential\.\*/);
  await expect(page.locator('.audit-filters summary')).toHaveText('Filters (1)');
  await expect(page.locator('.audit-entries')).toContainText(token);

  await page.locator('#audit-action').fill('nothing.here');
  await page.getByRole('button', {name: 'Filter', exact: true}).click();
  await expect(page.locator('.audit-empty')).toContainText('Nothing matches these filters.');
  await page.locator('.audit-empty').getByRole('link', {name: 'Clear filters'}).click();
  await expect(page).not.toHaveURL(/action=/);
  await expect(page.locator('.audit-entries')).toBeVisible();

  // an unknown name says so
  await page.goto('/admin/audit?org=no-such-org');
  await expect(page.locator('.audit-filter-error')).toHaveText('No organization named no-such-org.');

  // the credential pill removes its filter
  await page.goto('/admin/audit?category=all&credential=access_token:999999');
  await expect(page.locator('.audit-credential-pill')).toContainText('access_token:999999');
  await page.locator('.audit-credential-pill a').click();
  await expect(page).not.toHaveURL(/credential=/);
  await expect(page.locator('.audit-credential-pill')).toHaveCount(0);
});

test('Audit log on a phone', async ({page, request}, workerInfo) => {
  const token = await createToken(request, workerInfo.project.name);
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/admin/audit?category=all');

  // the filters fold into a disclosure
  const summary = page.locator('.audit-filters summary');
  await expect(summary).toHaveText('Filters (0)');
  await expect(page.locator('#audit-org')).toBeHidden();
  await summary.click();
  await expect(page.locator('#audit-org')).toBeVisible();

  // entries are cards: no table header, no horizontal scroll
  await expect(page.locator('.audit-entries > thead')).toBeHidden();
  await expect(page.locator('.audit-entries')).toContainText(token);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});
