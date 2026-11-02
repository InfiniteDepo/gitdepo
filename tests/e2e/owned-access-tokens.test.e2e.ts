// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/shared/owned_tokens.tmpl
// templates/org/settings/deploy_keys.tmpl
// templates/repo/settings/deploy_keys.tmpl
// routers/web/shared/user/owned_token.go
// templates/repo/settings/allowlist_tokens.tmpl
// templates/repo/settings/protected_branch.tmpl
// @watch end

import {randomBytes} from 'node:crypto';
import {expect, test as base, type Page} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

async function shot(page: Page, name: string) {
  if (process.env.OWNED_TOKEN_SHOTS) await page.screenshot({path: `${process.env.OWNED_TOKEN_SHOTS}/${base.info().project.name}-${name}.png`, fullPage: true});
}

test('create a repository token, see its value once, and revoke it', async ({page}) => {
  const name = `ci-${randomBytes(4).toString('hex')}`;
  await page.goto('/user2/repo1/settings/keys');
  await expect(page.locator('#access-tokens')).toContainText('Access tokens (HTTPS and API)');
  await shot(page, '1-repo-page');

  await page.locator('#access-tokens').getByRole('button', {name: 'Add access token'}).click();
  const form = page.locator('#add-access-token-panel form');
  await expect(form.getByLabel('Read: clone, download and read through the API')).toBeChecked();
  await expect(form.locator('#access-token-coverage')).toHaveText('This repository only');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('Write: also push, and change issues, pull requests and packages').check();
  await shot(page, '2-repo-form');
  await screenshot(page);

  await form.getByRole('button', {name: 'Create token'}).click();
  const created = page.locator('#new-access-token');
  await expect(created).toContainText(name);
  await expect(page.locator('#new-access-token-value')).toHaveText(/^[0-9a-f]{40}$/);
  await shot(page, '3-repo-created');

  // a name that is taken keeps the form and what was entered
  await page.locator('#access-tokens').getByRole('button', {name: 'Add access token'}).click();
  await form.getByLabel('Name').fill(name);
  await form.getByRole('button', {name: 'Create token'}).click();
  await expect(page.locator('#access-token-error')).toContainText(`A token named ${name} already exists here.`);
  await expect(form.getByLabel('Name')).toHaveValue(name);
  await shot(page, '4-repo-refused');

  await page.goto('/user2/repo1/settings/keys');
  const item = page.locator('#access-token-list .flex-item', {hasText: name});
  await expect(item).toContainText('Write');
  await item.getByRole('button', {name: 'Revoke'}).click();
  const modal = page.locator('#revoke-access-token');
  await expect(modal).toContainText(`Revoke ${name}? Anything using it loses access immediately.`);
  await shot(page, '5-repo-revoke');
  await modal.getByRole('button', {name: 'Revoke'}).click();
  await expect(page.locator('.flash-success')).toHaveText('Token revoked');
  await expect(page.locator('#access-token-list .flex-item', {hasText: name})).toHaveCount(0);
});

test('organization token for selected repositories', async ({page}) => {
  const name = `release-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/settings/keys');
  await page.locator('#access-tokens').getByRole('button', {name: 'Add access token'}).click();
  const form = page.locator('#add-access-token-panel form');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('Selected repositories').check();
  await form.locator('.ui.dropdown').click();
  await form.locator('.ui.dropdown .item', {hasText: 'repo3'}).click();
  await page.keyboard.press('Escape');
  await shot(page, '6-org-form');
  await form.getByRole('button', {name: 'Create token'}).click();
  await expect(page.locator('#new-access-token')).toContainText(name);
  await expect(page.locator('#access-token-list .flex-item', {hasText: name})).toContainText('org3/repo3');
  await shot(page, '7-org-created');

  await page.goto('/org3/repo3/settings/keys');
  await expect(page.locator('#covering-access-tokens')).toContainText(name);
  await shot(page, '8-repo-covering');
});

async function createRepoToken(page: Page, name: string, permission: string): Promise<string> {
  await page.goto('/user2/repo1/settings/keys');
  await page.locator('#access-tokens').getByRole('button', {name: 'Add access token'}).click();
  const form = page.locator('#add-access-token-panel form');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel(permission).check();
  await form.getByRole('button', {name: 'Create token'}).click();
  await expect(page.locator('#new-access-token')).toContainText(name);
  return (await page.locator('#new-access-token-value').textContent())!.trim();
}

async function revokeRepoToken(page: Page, name: string) {
  await page.goto('/user2/repo1/settings/keys');
  await page.locator('#access-token-list .flex-item', {hasText: name}).getByRole('button', {name: 'Revoke'}).click();
  await page.locator('#revoke-access-token').getByRole('button', {name: 'Revoke'}).click();
  await expect(page.locator('.flash-success')).toHaveText('Token revoked');
}

test('rotate a token: the new secret shows once and the old one stops working', async ({page, request}) => {
  const name = `rotate-${randomBytes(4).toString('hex')}`;
  const oldSecret = await createRepoToken(page, name, 'Write: also push, and change issues, pull requests and packages');
  const status = async (secret: string) => (await request.get('/api/v1/repos/user2/repo1', {headers: {Authorization: `token ${secret}`}})).status();
  expect(await status(oldSecret)).toBe(200);

  await page.goto('/user2/repo1/settings/keys');
  const item = page.locator('#access-token-list .flex-item', {hasText: name});
  await item.getByRole('button', {name: 'Rotate'}).click();
  const dialog = page.locator('#rotate-access-token');
  await expect(dialog).toContainText(`Rotate ${name}? The current secret stops working immediately.`);
  await dialog.getByRole('button', {name: 'Rotate'}).click();

  const created = page.locator('#new-access-token');
  await expect(created).toContainText(`Token ${name} rotated.`);
  const newSecret = (await page.locator('#new-access-token-value').textContent())!.trim();
  expect(newSecret).toMatch(/^[0-9a-f]{40}$/);
  expect(newSecret).not.toBe(oldSecret);
  expect(await status(oldSecret)).toBe(401);
  expect(await status(newSecret)).toBe(200);
  await shot(page, '9-repo-rotated');

  // the secret was shown once: a reload shows none, and rotates nothing
  await page.reload();
  await expect(page.locator('#new-access-token-value')).toHaveCount(0);
  await expect(page.locator('#access-token-list .flex-item', {hasText: name}).locator('.last-rotated')).toContainText('user2');
  expect(await status(newSecret)).toBe(200);

  await revokeRepoToken(page, name);
  expect(await status(newSecret)).toBe(401);
});

test('a token without a scope is refused and nothing is created', async ({page}) => {
  const name = `no-scope-${randomBytes(4).toString('hex')}`;
  await page.goto('/user2/repo1/settings/keys');
  await page.locator('#access-tokens').getByRole('button', {name: 'Add access token'}).click();
  const form = page.locator('#add-access-token-panel form');
  await form.getByLabel('Name').fill(name);
  await form.locator('#access-token-scope-repository').selectOption('');
  await form.getByRole('button', {name: 'Create token'}).click();

  await expect(page.locator('#access-token-scopes-error')).toHaveText('Choose at least one scope.');
  await expect(page.locator('#new-access-token')).toHaveCount(0);
  await expect(form.getByLabel('Name')).toHaveValue(name);
  await shot(page, '10-repo-no-scope');

  await page.goto('/user2/repo1/settings/keys');
  await expect(page.locator('#access-token-list .flex-item', {hasText: name})).toHaveCount(0);
});

test('a write token can be added to a branch protection rule', async ({page}) => {
  const name = `protect-${randomBytes(4).toString('hex')}`;
  const ruleName = `token-rule-${randomBytes(4).toString('hex')}`;
  await createRepoToken(page, name, 'Write: also push, and change issues, pull requests and packages');
  const readName = `protect-read-${randomBytes(4).toString('hex')}`;
  await createRepoToken(page, readName, 'Read: clone, download and read through the API');

  await page.goto('/user2/repo1/settings/branches/edit');
  await page.locator('input[name="rule_name"]').fill(ruleName);
  await page.locator('input[name="enable_push"][value="whitelist"]').click();
  const picker = page.locator('#whitelist_deploy_key_ids');
  await picker.click();
  // only write tokens are offered
  await expect(picker.locator('.menu .item', {hasText: readName})).toHaveCount(0);
  await picker.locator('.menu .item', {hasText: name}).click();
  await expect(picker.locator('input[name="whitelist_deploy_key_ids"]')).toHaveValue(/^-\d+$/);
  await shot(page, '11-rule-picker');
  await page.locator('button:text("Save rule")').click();
  await page.waitForLoadState('domcontentloaded');

  await page.goto(`/user2/repo1/settings/branches/edit?rule_name=${ruleName}`);
  await expect(picker.locator('input[name="whitelist_deploy_key_ids"]')).toHaveValue(/^-\d+$/);
  await expect(picker.locator('a.label', {hasText: name})).toBeVisible();

  // clean up
  await page.goto('/user2/repo1/settings/branches/');
  const deleteButton = page.locator('.flex-item', {hasText: ruleName}).locator('.delete-button');
  await deleteButton.click();
  await page.locator('#delete-protected-branch .actions .ok').click();
  await expect(deleteButton).toHaveCount(0);
  await revokeRepoToken(page, name);
  await revokeRepoToken(page, readName);
});
