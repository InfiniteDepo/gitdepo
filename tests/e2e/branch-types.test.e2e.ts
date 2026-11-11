// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/branch/{list,create_dialog}.tmpl
// templates/repo/issue/view_content/sidebar/development.tmpl
// web_src/js/features/repo-branch.ts
// @watch end

import {expect} from '@playwright/test';
import {dynamic_id, test} from './utils_e2e.ts';
import {adminAuth} from './shared/fake-data.ts';

test.use({user: 'user2'});

const model = '/api/v1/repos/user2/repo1/branching-model';
const types = [
  {name: 'Feature', prefix: 'feature/', base: 'development'},
  {name: 'Bugfix', prefix: 'bugfix/', base: 'development'},
];

test('Create branch dialog: type, preview, creation and a refusal', async ({page, request}) => {
  const put = async (naming: object) => {
    const res = await request.put(model, {headers: adminAuth(), data: {development_branch: 'master', types, branch_naming: naming}});
    expect(res.ok()).toBeTruthy();
  };
  try {
    await put({require_branch_type: false});
    await page.goto('/user2/repo1/branches');
    await page.getByRole('button', {name: 'Create new branch from "branch2"'}).click();
    await expect(page.locator('#create-branch-modal')).toBeVisible();

    // the type picker is a labelled group, with Other selected
    const picker = page.getByRole('group', {name: 'Branch type'});
    await expect(picker.getByRole('radio', {name: 'Other'})).toBeChecked();
    await picker.getByRole('radio', {name: 'Bugfix'}).check();
    const name = dynamic_id();
    await page.locator('#branch_name_part').fill(`my ${name}`);
    await expect(page.locator('#branch-name-preview')).toHaveText(`bugfix/my-${name}`);
    await page.getByRole('button', {name: 'Confirm'}).click();
    expect((await page.goto(`/user2/repo1/src/branch/bugfix/my-${name}`))?.status()).toBe(200);

    // the model changes after the dialog was opened: the server refuses and names the allowed prefixes
    await page.goto('/user2/repo1/branches');
    await page.getByRole('button', {name: 'Create new branch from "branch2"'}).click();
    await put({require_branch_type: true});
    const refused = dynamic_id();
    await page.locator('#branch_name_part').fill(`spike/${refused}`);
    await page.getByRole('button', {name: 'Confirm'}).click();
    await expect(page.locator('.flash-error')).toContainText('feature/');
    expect((await page.goto(`/user2/repo1/src/branch/spike/${refused}`))?.status()).toBe(404);
  } finally {
    await request.put(model, {headers: adminAuth(), data: {inherit: true}});
  }
});
