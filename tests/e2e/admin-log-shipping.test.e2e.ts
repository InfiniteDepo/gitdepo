// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/log_shipping.tmpl
// web_src/js/features/admin/**
// routers/web/admin/log_shipping.go
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';

test.use({user: 'user1'});

test('Log shipping destination form', async ({page}) => {
  const response = await page.goto('/admin/log-shipping');
  expect(response?.status()).toBe(200);
  await expect(page.locator('#log-shipping-list')).toContainText('No destinations yet.');

  // the fields follow the type
  await expect(page.locator('#key')).toBeVisible();
  await expect(page.locator('#headers')).toBeHidden();
  await page.locator('#type').selectOption('http');
  await expect(page.locator('#key')).toBeHidden();
  await expect(page.locator('#headers')).toBeVisible();
  await page.locator('#type').selectOption('newrelic');

  // create one with a key; the host is a name, which is only checked when it is dialled
  await page.locator('#name').fill('e2e-nr');
  await page.locator('#endpoint').fill('https://log-api.newrelic.com/log/v1');
  await page.locator('#key').fill('NRAK-E2EKEY0123456789');
  await page.locator('#log-type-access').check();
  await page.getByRole('button', {name: 'Save'}).click();

  // the key is masked and never comes back
  await expect(page.locator('#flash-message')).toContainText('The destination was saved.');
  await expect(page.locator('#key')).toHaveValue('');
  await expect(page.locator('#key')).toHaveAttribute('placeholder', /set/);
  await expect(page.locator('body')).not.toContainText('NRAK-E2EKEY0123456789');
  await expect(page.locator('#log-type-access')).toBeChecked();
  await expect(page.locator('#type')).toBeDisabled();
  await expect(page.locator('#log-shipping-list')).toContainText('e2e-nr');
  await expect(page.locator('#log-shipping-test')).toBeVisible();

  // delete it again
  await page.locator('#log-shipping-delete').click();
  await expect(page.locator('#log-shipping-list')).toContainText('No destinations yet.');
});
