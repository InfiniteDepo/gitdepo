// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/settings/options.tmpl
// templates/org/settings/redirects.tmpl
// templates/org/settings/navbar.tmpl
// @watch end

import {randomBytes} from 'node:crypto';
import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {accessibilityCheck} from './shared/accessibility.ts';

test.use({user: 'user2'});

test('move a repository into a project, and remove the redirect of its old path', async ({page}) => {
  const suffix = randomBytes(4).toString('hex');
  const project = `e2e-move-${suffix}`;
  const repo = `e2e-moved-${suffix}`;

  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);

  await page.goto('/repo/create?org=3');
  await page.locator('input[name="repo_name"]').fill(repo);
  await page.getByRole('button', {name: 'Create repository'}).click();
  await expect(page).toHaveURL(`/org3/${repo}`);

  // the danger zone of the settings
  await page.goto(`/org3/${repo}/settings`);
  await page.getByRole('button', {name: 'Move', exact: true}).click();
  const modal = page.locator('#move-repo-modal');
  await expect(modal).toBeVisible();
  // a wrong confirmation names the expected full name and moves nothing
  await modal.locator('input[name="repo_name"]').fill('org3/other');
  await modal.getByLabel('Move to').selectOption({label: project});
  await modal.getByRole('button', {name: 'Move repository'}).click();
  await expect(page.locator('.flash-error')).toContainText(`Enter the full name of the repository: org3/${repo}`);
  await screenshot(page);

  // blanks around the name and its case don't matter
  await page.getByRole('button', {name: 'Move', exact: true}).click();
  await expect(modal).toBeVisible();
  await modal.locator('input[name="repo_name"]').fill(`  ORG3/${repo} `);
  await modal.getByLabel('Move to').selectOption({label: project});
  await accessibilityCheck({page}, ['#move-repo-modal'], [], []);
  await screenshot(page);
  await modal.getByRole('button', {name: 'Move repository'}).click();

  await expect(page).toHaveURL(`/org3/${project}/${repo}/settings`);
  await expect(page.locator('.flash-success')).toContainText(`org3/${project}/${repo}`);

  // the old path redirects
  await page.goto(`/org3/${repo}`);
  await expect(page).toHaveURL(`/org3/${project}/${repo}`);

  // the organization's redirects
  await page.goto('/org/org3/settings/redirects');
  const row = page.locator('.flex-item', {hasText: `org3/${repo}`});
  await expect(row.getByRole('link', {name: `org3/${project}/${repo}`})).toBeVisible();
  // the h4 header is the layout of every settings page
  await accessibilityCheck({page}, ['.org-setting-content'], [], ['heading-order']);
  await screenshot(page);
  await row.getByRole('button', {name: 'Remove'}).click();
  await expect(page.locator('.flash-success')).toBeVisible();
  await expect(page.locator('.flex-item', {hasText: `org3/${repo}`})).toHaveCount(0);
});

// a mobile keyboard appends a blank, copying the label can bring a non-breaking space
test('the move confirmation ignores a trailing blank and a trailing non-breaking space', async ({page}) => {
  const suffix = randomBytes(4).toString('hex');
  const project = `e2e-blank-${suffix}`;
  const repo = `e2e-blank-repo-${suffix}`;

  await page.goto('/org/org3/groups/new');
  await page.getByLabel('Project name').fill(project);
  await page.getByRole('button', {name: 'Create project'}).click();
  await expect(page).toHaveURL(`/org3/${project}`);
  await page.goto('/repo/create?org=3');
  await page.locator('input[name="repo_name"]').fill(repo);
  await page.getByRole('button', {name: 'Create repository'}).click();
  await expect(page).toHaveURL(`/org3/${repo}`);

  await page.goto(`/org3/${repo}/settings`);
  await page.getByRole('button', {name: 'Move', exact: true}).click();
  const modal = page.locator('#move-repo-modal');
  await modal.locator('input[name="repo_name"]').fill(`org3/${repo} `);
  await modal.getByLabel('Move to').selectOption({label: project});
  await modal.getByRole('button', {name: 'Move repository'}).click();
  await expect(page).toHaveURL(`/org3/${project}/${repo}/settings`);

  await page.getByRole('button', {name: 'Move', exact: true}).click();
  await expect(modal).toBeVisible();
  await modal.locator('input[name="repo_name"]').fill(`org3/${project}/${repo}\u00a0`);
  await modal.getByLabel('Move to').selectOption({index: 1});
  await modal.getByRole('button', {name: 'Move repository'}).click();
  await expect(page).toHaveURL(`/org3/${repo}/settings`);
});
