// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/shared/metrics.tmpl
// templates/org/metrics.tmpl
// templates/org/menu.tmpl
// templates/repo/activity.tmpl
// templates/repo/navbar.tmpl
// routers/web/repo/metrics.go
// routers/web/org/metrics.go
// services/metrics/**
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

test('Repository pull request metrics', async ({page}) => {
  await page.goto('/user2/pull-metrics/activity');
  await page.locator('.flex-container-nav').getByRole('link', {name: 'Metrics'}).click();
  await expect(page).toHaveURL(/\/user2\/pull-metrics\/activity\/metrics$/);

  await expect(page.locator('[data-card="merged"] .value')).toHaveText('5');
  await expect(page.locator('[data-card="first-review"] .value')).not.toHaveText('n/a');
  await expect(page.locator('[data-card="commits"] .value')).toHaveText('3');
  await expect(page.locator('[data-table="weekly"] tbody tr')).toHaveCount(5);
  await expect(page.locator('[data-table="review-load"] tbody tr')).toHaveCount(2);
  await expect(page.getByRole('link', {name: 'Download CSV'})).toHaveAttribute('href', '/user2/pull-metrics/activity/metrics?period=30&format=csv');
  await screenshot(page);

  await page.locator('.ui.dropdown.jump').click();
  await page.locator('.ui.dropdown.jump .menu .item', {hasText: '7 days'}).click();
  await expect(page).toHaveURL(/period=7/);
  await expect(page.locator('[data-table="weekly"] tbody tr')).toHaveCount(1);
});

test('Organization pull request metrics', async ({page, isMobile}) => {
  await page.goto('/org/org3/metrics');
  // on small screens the tab moves into the overflow menu
  if (!isMobile) await expect(page.locator('.overflow-menu-items a.active[href="/org/org3/metrics"]')).toBeVisible();
  await expect(page.getByText('Download CSV')).toBeVisible();
  await screenshot(page);
});
