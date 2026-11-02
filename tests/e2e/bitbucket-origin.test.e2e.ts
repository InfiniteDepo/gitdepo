// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/home.tmpl
// templates/repo/bitbucket_origin_command.tmpl
// web_src/js/features/repo-common.js
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';

test.use({user: 'user2'});

test('Bitbucket migration banner is dismissed for 90 days', async ({page}) => {
  const response = await page.goto('/user2/bitbucket-migrated');
  expect(response?.status()).toBe(200);
  await expect(page.getByText('Migrated from Bitbucket')).toBeVisible();

  const banner = page.locator('#bitbucket-origin-banner');
  await expect(banner).toBeVisible();
  await expect(banner).toContainText('git remote set-url origin');

  await banner.getByRole('button', {name: 'Dismiss'}).click();
  await expect(banner).toBeHidden();
  await page.reload();
  await expect(page.getByText('Migrated from Bitbucket')).toBeVisible();
  await expect(banner).toBeHidden();

  // a dismissal older than 90 days no longer hides it
  await page.evaluate(() => {
    const key = Object.keys(localStorage).find((k) => k.startsWith('bitbucket-origin-banner-'));
    localStorage.setItem(key, String(Date.now() - 91 * 24 * 60 * 60 * 1000));
  });
  await page.reload();
  await expect(banner).toBeVisible();
});
