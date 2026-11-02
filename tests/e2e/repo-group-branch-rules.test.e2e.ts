// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/repo_group/settings.tmpl
// templates/repo/settings/protected_branch.tmpl
// templates/repo/settings/branches.tmpl
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {accessibilityCheck} from './shared/accessibility.ts';

test.use({user: 'user2'});

test('add a project branch rule, see it in a repository, and delete it after confirming', async ({page}) => {
  const project = `e2e-rules-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);
  await page.locator('.page-content').getByRole('link', {name: 'New repository'}).click();
  await page.locator('input[name="repo_name"]').fill('svc');
  await page.locator('input[name="auto_init"]').check();
  await page.getByRole('button', {name: 'Create repository'}).click();
  await expect(page).toHaveURL(`/org3/${project}/svc`);

  // the form has no repository selection: a project rule covers the whole project
  await page.goto(`/org3/${project}/-/settings`);
  await page.getByRole('link', {name: 'Add new rule'}).click();
  await expect(page.locator('input[name="apply_to_selected_repos"]')).toHaveCount(0);
  // the form's scripts run on the project page too
  await expect(page.getByRole('button', {name: 'Add approval rule'})).toBeVisible();
  await page.locator('input[name="rule_name"]').fill('main');
  await page.getByRole('button', {name: 'Save rule'}).click();
  await expect(page).toHaveURL(`/org3/${project}/-/settings`);
  await expect(page.locator('.flash-success')).toBeVisible();
  const row = page.locator('.flex-item', {hasText: 'main'});
  await expect(row.getByRole('link', {name: 'Edit'})).toBeVisible();
  // the h4 headers are the layout of every settings page
  await accessibilityCheck({page}, ['.page-content'], [], ['heading-order']);
  await screenshot(page);

  await page.goto(`/org3/${project}/svc/settings/branches`);
  await expect(page.locator('.org-protected-branches')).toContainText(`Project ${project}`);
  await screenshot(page);

  // deleting asks first: cancelling keeps the rule
  await page.goto(`/org3/${project}/-/settings`);
  await row.getByRole('button', {name: 'Delete rule'}).click();
  await page.locator('#delete-protected-branch').getByRole('button', {name: 'No'}).click();
  await expect(row).toHaveCount(1);
  await row.getByRole('button', {name: 'Delete rule'}).click();
  await page.locator('#delete-protected-branch').getByRole('button', {name: 'Yes'}).click();
  await expect(page.locator('.flash-success')).toBeVisible();
  await expect(page.locator('.flex-item', {hasText: 'main'})).toHaveCount(0);
});
