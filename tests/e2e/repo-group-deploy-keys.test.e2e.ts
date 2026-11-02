// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/repo_group/settings.tmpl
// templates/org/settings/deploy_keys.tmpl
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

test('add a project deploy key, see it in the list, and delete it', async ({page}) => {
  const project = `e2e-keys-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);

  await page.goto(`/org3/${project}/-/settings`);
  await page.getByRole('link', {name: 'Keys and tokens'}).click();
  await expect(page).toHaveURL(`/org3/${project}/-/settings/keys`);

  await page.locator('.org-setting-content > h4').getByRole('button', {name: 'Add deploy key'}).click();
  const form = page.locator('#add-deploy-key-panel form');
  await form.locator('#ssh-key-title').fill('project ci');
  await form.locator('#ssh-key-content').fill(newPublicKey());
  await expect(form.locator('input[name="scope"]')).toHaveCount(0);
  await screenshot(page);
  await form.getByRole('button', {name: 'Add deploy key'}).click();

  await expect(page.locator('.flash-success')).toBeVisible();
  const item = page.locator('.flex-item', {hasText: 'project ci'});
  await expect(item).toBeVisible();

  await item.locator('.delete-button').click();
  await page.locator('#delete-deploy-key').getByRole('button', {name: 'Yes'}).click();
  await expect(page.locator('.flex-item', {hasText: 'project ci'})).toHaveCount(0);
});
