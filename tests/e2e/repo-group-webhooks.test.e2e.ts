// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/repo_group/settings.tmpl
// templates/org/repo_group/hooks.tmpl
// templates/org/repo_group/hook_new.tmpl
// templates/repo/settings/webhook/**
// templates/webhook/**
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

test('add a project webhook, see it in the list, and delete it', async ({page}) => {
  const project = `e2e-hooks-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);

  await page.goto(`/org3/${project}/-/settings`);
  await page.getByRole('link', {name: 'Webhooks'}).click();
  await expect(page).toHaveURL(`/org3/${project}/-/settings/hooks`);
  await page.locator('.ui.jump.dropdown').click();
  await page.locator(`.ui.jump.dropdown a.item[href$="/-/settings/hooks/forgejo/new"]`).click();
  await page.locator('#payload_url').fill('https://example.com/project-hook');
  await screenshot(page);
  await page.locator('form').getByRole('button', {name: 'Add webhook'}).click();
  await expect(page).toHaveURL(`/org3/${project}/-/settings/hooks`);
  await expect(page.locator('.flash-success')).toBeVisible();
  const row = page.locator('.item', {hasText: 'https://example.com/project-hook'});
  await expect(row).toBeVisible();

  await row.locator('.delete-button').click();
  await page.locator('#delete-webhook').getByRole('button', {name: 'Yes'}).click();
  await expect(page.locator('.item', {hasText: 'https://example.com/project-hook'})).toHaveCount(0);
});
