// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/issue/view_content/update_branch_by_merge.tmpl
// templates/repo/issue/view_content/approval_rules.tmpl
// templates/repo/issue/view_content/pusher_notes.tmpl
// templates/repo/settings/protected_branch.tmpl
// web_src/js/features/repo-issue.js
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {adminAuth} from './shared/fake-data.ts';

test.use({user: 'user2'});

test('Pusher approvals: updating the branch asks first, then the approval stops counting', async ({page, request}) => {
  const api = '/api/v1/repos/user2/repo1';
  const id = Date.now();
  const base = `pusher-base-${id}`;
  const head = `pusher-head-${id}`;
  const ok = async (res) => expect(res.ok(), await res.text()).toBeTruthy();
  const file = async (branch: string, name: string, from?: string) => ok(await request.post(`${api}/contents/${name}`, {
    headers: adminAuth(),
    data: {content: btoa(name), branch: from ?? branch, new_branch: from ? branch : undefined},
  }));

  // user1 opens the pull request, user2 approves it, and the base moves on so that the head is behind
  await ok(await request.post(`${api}/branches`, {headers: adminAuth(), data: {new_branch_name: base, old_branch_name: 'master'}}));
  await file(head, `${head}.txt`, base);
  const pr = await request.post(`${api}/pulls`, {headers: adminAuth(), data: {head, base, title: `Pusher ${id}`}});
  await ok(pr);
  const number = (await pr.json()).number as number;
  await file(base, `${base}.txt`);
  await ok(await request.post(`${api}/branch_protections`, {
    headers: adminAuth(),
    data: {rule_name: base, required_approvals: 1, ignore_pusher_approvals: true, apply_to_admins: true},
  }));
  await ok(await request.post(`${api}/pulls/${number}/reviews?sudo=user2`, {headers: adminAuth(), data: {event: 'APPROVED'}}));

  await page.goto(`/user2/repo1/pulls/${number}`);
  await expect(page.locator('.pusher-approval')).toHaveCount(0);
  const update = page.locator('.update-button > button, form.update-branch-form button').first();
  const warning = "Updating the branch counts as a push: your approval will no longer count toward this branch's approval requirements.";

  // cancelling the confirmation changes nothing
  const modal = page.locator('#update-branch-confirm');
  await expect(modal).toBeHidden();
  await update.click();
  await expect(modal).toBeVisible();
  await expect(modal.locator('.content')).toHaveText(warning);
  await modal.locator('.cancel').click();
  await expect(modal).toBeHidden();
  await page.reload();
  await expect(update).toBeVisible();
  await expect(page.locator('.pusher-approval')).toHaveCount(0);

  // confirming updates the branch, and the merge box says why the approval no longer counts
  await update.click();
  await modal.locator('.ok').click();
  await expect(page.locator('.pusher-approval')).toHaveText(/The approval of user2 does not count: they pushed to this pull request\./);
  await expect(page.getByText('0 of 1 approvals granted')).toBeVisible();
  await expect(update).toHaveCount(0); // the head is up to date now
});

test('CODEOWNERS section lines sit under the rule row and fit a phone', async ({page, request}) => {
  const api = '/api/v1/repos/user2/repo1';
  const id = Date.now();
  const base = `owners-base-${id}`;
  const head = `owners-head-${id}`;
  const ok = async (res) => expect(res.ok(), await res.text()).toBeTruthy();
  const file = async (branch: string, name: string, content: string, from?: string) => ok(await request.post(`${api}/contents/${name}`, {
    headers: adminAuth(),
    data: {content: btoa(content), branch: from ?? branch, new_branch: from ? branch : undefined},
  }));

  // a section that needs two approvals, with two owners, one approving
  await ok(await request.post(`${api}/branches`, {headers: adminAuth(), data: {new_branch_name: base, old_branch_name: 'master'}}));
  await file(base, 'CODEOWNERS', '[Docs][2]\ndocs/.* @user2 @user4\n');
  await file(head, 'docs/a.md', 'a', base);
  const pr = await request.post(`${api}/pulls`, {headers: adminAuth(), data: {head, base, title: `Owners ${id}`}});
  await ok(pr);
  const number = (await pr.json()).number as number;
  await ok(await request.post(`${api}/branch_protections`, {
    headers: adminAuth(),
    data: {rule_name: base, apply_to_admins: true, approval_rules: [{name: 'Owners', required_count: 1, require_code_owners: true}]},
  }));
  await ok(await request.post(`${api}/pulls/${number}/reviews?sudo=user2`, {headers: adminAuth(), data: {event: 'APPROVED'}}));

  await page.setViewportSize({width: 390, height: 800});
  await page.goto(`/user2/repo1/pulls/${number}`);
  const row = page.locator('li', {hasText: 'Owners: 1/1'}).locator('.flex-text-block').first();
  const line = page.locator('.codeowners-shortfall');
  await expect(line).toHaveText(/CODEOWNERS section Docs needs 2 approvals, only 1 can approve/);
  const [rowBox, lineBox] = [await row.boundingBox(), await line.boundingBox()];
  expect(lineBox.y).toBeGreaterThanOrEqual(rowBox.y + rowBox.height - 1); // its own line, under the rule row
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
});
