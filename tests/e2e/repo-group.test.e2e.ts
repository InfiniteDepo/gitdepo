// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/repo_group/**
// templates/explore/repo_groups.tmpl
// templates/org/menu.tmpl
// templates/repo/create_basic.tmpl
// templates/repo/header.tmpl
// web_src/js/features/repo-template.js
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {validate_form} from './shared/forms.ts';
import {accessibilityCheck} from './shared/accessibility.ts';

test.use({user: 'user2'});

test('create a project and a repository in it', async ({page}) => {
  const name = `e2e-project-${randomBytes(4).toString('hex')}`;
  const response = await page.goto('/org/org3/groups');
  expect(response?.status()).toBe(200);
  await page.getByRole('link', {name: 'New project'}).click();
  await page.getByLabel('Project name').fill(name);
  await page.getByLabel('Description').fill('Payment services');
  await validate_form({page});
  await page.getByRole('button', {name: 'Create project'}).click();

  // the empty project
  await expect(page).toHaveURL(`/org3/${name}`);
  await expect(page.getByText('This project has no repositories yet')).toBeVisible();
  await expect(page.getByText('Payment services')).toBeVisible();
  await accessibilityCheck({page}, ['.page-content'], ['span[data-tooltip-content'], []);
  await screenshot(page);

  // New repository preselects the project
  await page.locator('.page-content').getByRole('link', {name: 'New repository'}).click();
  await expect(page.locator('#repo_group')).toHaveValue(/^[1-9]\d*$/);
  await expect(page.locator('#repo_group option:checked')).toHaveText(name);
  await page.locator('input[name="repo_name"]').fill('api');
  await page.getByRole('button', {name: 'Create repository'}).click();

  await expect(page).toHaveURL(`/org3/${name}/api`);
  const header = page.locator('.repo-header .flex-item-title');
  await expect(header).toHaveText(`org3/${name}/api`);
  await header.getByRole('link', {name}).click();
  await expect(page).toHaveURL(`/org3/${name}`);
  await expect(page.locator('.flex-list').getByRole('link', {name: 'api'})).toBeVisible();
  await screenshot(page);

  // the Projects tab and Explore list it
  await page.goto('/org/org3/groups');
  await expect(page.getByRole('link', {name, exact: true})).toBeVisible();
  await accessibilityCheck({page}, ['.page-content'], ['span[data-tooltip-content'], []);
  await page.goto(`/explore/groups?q=${name}`);
  await expect(page.locator('.flex-list').getByRole('link', {name, exact: true})).toBeVisible();
});

test('the project select follows the owner', async ({page}) => {
  const response = await page.goto('/repo/create');
  expect(response?.status()).toBe(200);
  // user2 owns no projects: no select until an organization with projects is chosen
  await expect(page.locator('#repo_group_label')).toBeHidden();
});

test('rename and delete a project', async ({page}) => {
  const name = `e2e-project-${randomBytes(4).toString('hex')}`;
  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(name);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${name}`);

  await page.getByRole('link', {name: 'Project settings'}).click();
  await expect(page).toHaveURL(`/org3/${name}/-/settings`);
  await validate_form({page});
  await screenshot(page);
  await page.getByLabel('Project name').fill(`${name}-x`);
  await page.getByRole('button', {name: 'Update project'}).click();
  await expect(page).toHaveURL(`/org3/${name}-x/-/settings`);
  await expect(page.getByText('The project has been updated.')).toBeVisible();

  await page.getByLabel(`Type org3/${name}-x to confirm`).fill(`org3/${name}-x`);
  await page.getByRole('button', {name: 'Delete project'}).click();
  await expect(page).toHaveURL('/org/org3/groups');
  await expect(page.getByText(`The project ${name}-x has been deleted.`)).toBeVisible();
  await expect(page.getByRole('link', {name: `${name}-x`, exact: true})).toHaveCount(0);
});
