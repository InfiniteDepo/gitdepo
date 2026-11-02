// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/settings/deploy_keys.tmpl
// templates/org/settings/deploy_key_scope.tmpl
// templates/org/settings/navbar.tmpl
// templates/repo/settings/deploy_keys.tmpl
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

// an ed25519 public key in OpenSSH format; any 32 bytes parse as one
function newPublicKey(): string {
  const field = (b: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    return Buffer.concat([len, b]);
  };
  return `ssh-ed25519 ${Buffer.concat([field(Buffer.from('ssh-ed25519')), field(randomBytes(32))]).toString('base64')}`;
}

test('org deploy key with selected repositories', async ({page}) => {
  const name = `e2e-org-key-${randomBytes(4).toString('hex')}`;
  const response = await page.goto('/org/org3/settings/keys');
  expect(response?.status()).toBe(200);

  await page.locator('.org-setting-content > h4').getByRole('button', {name: 'Add deploy key'}).click();
  const form = page.locator('#add-deploy-key-panel form');
  await form.locator('input[name="title"]').fill(name);
  await form.locator('textarea[name="content"]').fill(newPublicKey());
  await form.locator('input[name="scope"][value="selected"]').check();
  const picker = form.locator('.ui.dropdown');
  await picker.click();
  await picker.locator('.menu .item', {hasText: /^repo3$/}).click();
  await expect(picker.locator('input[name="repo_ids"]')).toHaveValue('3');
  // a multiple selection stays open; with more repositories in org3 its menu covers the button
  await page.keyboard.press('Escape');
  await expect(picker.locator('.menu')).toBeHidden();
  await screenshot(page);
  await form.getByRole('button', {name: 'Add deploy key'}).click();

  const item = page.locator('.flex-item', {hasText: name});
  await expect(item).toBeVisible();
  await expect(item).toContainText('repo3');

  // the repository lists it, read-only
  await page.goto('/org3/repo3/settings/keys');
  await expect(page.locator('#org-deploy-keys')).toContainText(name);
  await screenshot(page);

  // clean up
  await page.goto('/org/org3/settings/keys');
  await item.locator('.delete-button').click();
  await page.locator('#delete-deploy-key').getByRole('button', {name: 'Yes'}).click();
  await expect(item).toHaveCount(0);
});
