// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/branch/list.tmpl
// web_src/js/features/repo-branch.ts
// web_src/css/repo.css
// @watch end

import {expect} from '@playwright/test';
import {dynamic_id, test} from './utils_e2e.ts';
import {adminAuth} from './shared/fake-data.ts';

test.use({user: 'user2'});

test('Branches page: selection banner, confirm list and typed confirmation', async ({page, request}) => {
  const prefix = `e2ebulk-${dynamic_id()}-`;
  const names = Array.from({length: 12}, (_, i) => `${prefix}${String(i).padStart(2, '0')}`);
  for (const name of names) {
    const res = await request.post('/api/v1/repos/user2/repo1/branches', {headers: adminAuth(), data: {new_branch_name: name, old_branch_name: 'master'}});
    expect(res.ok()).toBeTruthy();
  }
  try {
    await page.goto(`/user2/repo1/branches?q=${prefix}&state=merged`);
    const boxes = page.locator('input.branch-select');
    await expect(boxes).toHaveCount(12);
    const count = page.locator('#branch-selected-count');
    const selectAll = page.locator('#branch-select-all');
    const clear = page.locator('#branch-clear-selection');

    // nothing selected: no way to delete, and every box has a name
    await expect(page.locator('#branch-delete-selected')).toBeDisabled();
    await expect(page.getByRole('checkbox', {name: `Select ${names[0]}`})).toBeVisible();

    // the page's boxes, then "all matching" (the banner, as in an issue list)
    await page.locator('#branch-select-page').check();
    await expect(count).toHaveText('12 selected');
    await expect(selectAll).toBeHidden(); // all 12 matching are already selected
    await boxes.first().uncheck();
    await expect(count).toHaveText('11 selected');
    await expect(page.locator('#branch-select-page')).toHaveJSProperty('indeterminate', true);
    await expect(page.locator('#branch-filter-stale')).toHaveCSS('border-top-width', '1px'); // filter inputs are styled
    await expect(selectAll).toHaveText('Select all 12 matching');
    await selectAll.click();
    await expect(count).toHaveText('All 12 matching branches selected');
    await expect(page.getByRole('button', {name: 'Delete selected (12)'})).toBeEnabled();

    // the dialog lists exactly what will go; above ten it asks for the name of the repository
    await page.getByRole('button', {name: 'Delete selected (12)'}).click();
    const modal = page.locator('#delete-selected-modal');
    await expect(modal).toBeVisible();
    await expect(modal.locator('#delete-selected-title')).toHaveText('Delete 12 branches?');
    await expect(modal.locator('#delete-selected-list li')).toHaveCount(12);
    await expect(modal.locator('#delete-selected-cap')).toBeHidden();
    await expect(modal.locator('form #delete-selected-cap')).toHaveCount(0); // Fomantic hides a warning message inside a form
    const ok = modal.locator('#delete-selected-ok');
    await expect(ok).toHaveText('Delete 12 branches');
    await expect(ok).toBeDisabled();
    await modal.getByLabel('Type user2/repo1 to confirm').fill('user2/other');
    await expect(ok).toBeDisabled();
    await modal.getByLabel('Type user2/repo1 to confirm').fill('user2/repo1');
    await expect(ok).toBeEnabled();
    await modal.getByRole('button', {name: 'Cancel'}).click();
    await expect(modal).toBeHidden();

    // clearing the selection, then two rows: no typed name below eleven
    await clear.click();
    await expect(count).toHaveText('');
    await boxes.nth(0).check();
    await boxes.nth(1).check();
    await expect(count).toHaveText('2 selected');
    await page.getByRole('button', {name: 'Delete selected (2)'}).click();
    await expect(modal.locator('#delete-selected-title')).toHaveText('Delete 2 branches?');
    await expect(modal.locator('#delete-selected-list li')).toHaveCount(2);
    await expect(modal.locator('#delete-selected-confirm')).toBeHidden();
    await expect(ok).toBeEnabled();
    await ok.click();

    await expect(page.locator('.flash-success')).toContainText('2 branches deleted (');
    await expect(page.locator('.flash-success').getByRole('link', {name: 'Show deleted branches'})).toBeVisible();
    await page.goto(`/user2/repo1/branches?q=${prefix}&state=merged`);
    await expect(page.locator('input.branch-select')).toHaveCount(10);
  } finally {
    for (const name of names) await request.delete(`/api/v1/repos/user2/repo1/branches/${name}`, {headers: adminAuth()});
  }
});
