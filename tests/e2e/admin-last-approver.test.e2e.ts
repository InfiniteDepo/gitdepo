// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/user/edit.tmpl
// routers/web/admin/users.go
// services/user/last_approver.go
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {FakeData, adminAuth} from './shared/fake-data.ts';

test.use({user: 'user1'});

test('Admin: deactivating the only approver shows a warning and still saves', async ({page, request}) => {
  const data = new FakeData(request);
  try {
    const approver = await data.createUser();
    const org = await data.createOrg();
    const repo = await data.createRepo(org);
    const api = `/api/v1/repos/${org}/${repo}`;
    for (const res of [
      await request.put(`${api}/collaborators/${approver.username}`, {headers: adminAuth(), data: {permission: 'write'}}),
      await request.post(`${api}/branch_protections`, {
        headers: adminAuth(),
        data: {rule_name: 'main', approval_rules: [{name: 'Leads', required_count: 1, usernames: [approver.username]}]},
      }),
    ]) expect(res.ok(), await res.text()).toBeTruthy();

    const user = await (await request.get(`/api/v1/users/${approver.username}`, {headers: adminAuth()})).json();
    await page.goto(`/admin/users/${user.id}/edit`);
    const warning = page.locator('.last-approver-warnings');
    await expect(warning).toBeVisible();
    await expect(warning.getByRole('link', {name: `Approval rule Leads of branch rule main in ${org}/${repo}`})).toHaveAttribute('href', `/${org}/${repo}/settings/branches/edit?rule_name=main`);

    // the save is not blocked: it deactivates the account and says what it broke
    await page.locator('.ui.checkbox', {has: page.locator('input[name="active"]')}).click();
    await page.getByRole('button', {name: 'Update user account'}).click();
    await expect(page.locator('.flash-success')).toBeVisible();
    await expect(page.locator('.flash-warning').getByRole('link', {name: `Approval rule Leads of branch rule main in ${org}/${repo}`})).toBeVisible();
  } finally {
    await data.cleanup();
  }
});
