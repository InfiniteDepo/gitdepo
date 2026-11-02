// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/repo_group/settings.tmpl
// templates/org/repo_group/actions.tmpl
// templates/shared/actions/secrets_list.tmpl
// templates/shared/actions/variables_list.tmpl
// web_src/js/features/**
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

test('add a project secret and variable, see them in the lists, and delete them', async ({page}) => {
  const project = `e2e-actions-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);

  await page.goto(`/org3/${project}/-/settings`);
  await page.getByRole('link', {name: 'Actions secrets', exact: true}).click();
  await expect(page).toHaveURL(`/org3/${project}/-/settings/secrets`);
  await page.getByRole('button', {name: 'Add secret'}).click();
  await page.locator('#secret-name').fill('PROJECT_TOKEN');
  await page.locator('#secret-data').fill('project-secret-value');
  await screenshot(page);
  await page.locator('#add-secret-modal').getByText('Confirm').click();
  const secret = page.locator('.flex-item', {hasText: 'PROJECT_TOKEN'});
  await expect(secret).toBeVisible();
  await expect(page.getByText('project-secret-value')).toHaveCount(0);
  await secret.locator('.link-action').click();
  await page.locator('#delete-secret').getByText('Confirm').click();
  await expect(page.locator('.flex-item', {hasText: 'PROJECT_TOKEN'})).toHaveCount(0);

  await page.goto(`/org3/${project}/-/settings/variables`);
  await page.getByRole('button', {name: 'Add variable'}).click();
  await page.locator('#dialog-variable-name').fill('PROJECT_MODE');
  await page.locator('#dialog-variable-data').fill('fast');
  await page.locator('#edit-variable-modal').getByText('Confirm').click();
  const variable = page.locator('.flex-item', {hasText: 'PROJECT_MODE'});
  await expect(variable).toBeVisible();
  await expect(variable).toContainText('fast');
  await variable.locator('.link-action').click();
  await page.locator('#delete-variable').getByText('Confirm').click();
  await expect(page.locator('.flex-item', {hasText: 'PROJECT_MODE'})).toHaveCount(0);
});
