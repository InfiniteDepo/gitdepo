// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/repo_group/settings.tmpl
// templates/org/team/repositories.tmpl
// templates/repo/settings/collaboration.tmpl
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {accessibilityCheck} from './shared/accessibility.ts';

test.use({user: 'user2'});

test('link a team to a project, and unlink it after confirming', async ({page}) => {
  const project = `e2e-teams-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);

  await page.goto(`/org3/${project}/-/settings`);
  await page.getByLabel('Select a team').selectOption({label: 'team1'});
  await page.getByRole('button', {name: 'Link team'}).click();
  await expect(page.locator('.flash-success')).toBeVisible();
  const row = page.locator('.flex-item', {hasText: 'team1'});
  await expect(row.getByRole('link', {name: 'team1'})).toBeVisible();
  // the h4 headers are the layout of every settings page
  await accessibilityCheck({page}, ['.page-content'], [], ['heading-order']);
  await screenshot(page);

  // unlinking asks first: cancelling keeps the link
  await row.getByRole('button', {name: 'Unlink'}).click();
  await page.locator('#unlink-team').getByRole('button', {name: 'No'}).click();
  await expect(row).toHaveCount(1);
  await row.getByRole('button', {name: 'Unlink'}).click();
  await page.locator('#unlink-team').getByRole('button', {name: 'Yes'}).click();
  await expect(page.locator('.flash-success')).toBeVisible();
  await expect(page.locator('.flex-item', {hasText: 'team1'})).toHaveCount(0);
});
