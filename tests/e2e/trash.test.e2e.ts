// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/trash.tmpl
// templates/admin/navbar.tmpl
// templates/repo/settings/trash_notice.tmpl
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user1'});

test('Admin trash page', async ({page}) => {
  const response = await page.goto('/admin/trash');
  expect(response?.status()).toBe(200);

  await expect(page.getByRole('heading', {name: /Trash/})).toBeVisible();
  await expect(page.getByText('The trash is empty.')).toBeVisible();
  await expect(page.locator('.admin-setting-content a.item.active, .menu a.item.active', {hasText: 'Trash'}).first()).toBeVisible();
  await screenshot(page);
});
