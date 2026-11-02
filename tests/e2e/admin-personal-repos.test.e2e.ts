// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/personal_repos.tmpl
// templates/admin/navbar.tmpl
// routers/web/admin/personal_repos.go
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';

test.use({user: 'user1'});

test('Personal repository policy', async ({page}) => {
  const response = await page.goto('/admin/personal-repos');
  expect(response?.status()).toBe(200);
  await expect(page.locator('#mode-allowed')).toBeChecked();
  await expect(page.locator('#personal-repo-violators')).toHaveCount(0);

  await page.locator('label[for="mode-private_only"]').click();
  await page.getByRole('button', {name: 'Save'}).click();
  await expect(page.locator('#flash-message')).toContainText('The personal repository policy has been saved.');
  await expect(page.locator('#mode-private_only')).toBeChecked();
  // user2 owns public repositories
  await expect(page.locator('#personal-repo-violators')).toContainText('user2');

  // the other specs run with the default again
  await page.locator('label[for="mode-allowed"]').click();
  await page.getByRole('button', {name: 'Save'}).click();
  await expect(page.locator('#mode-allowed')).toBeChecked();
  await expect(page.locator('#personal-repo-violators')).toHaveCount(0);
});
