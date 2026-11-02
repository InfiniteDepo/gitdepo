// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/issue/view_content/context_menu.tmpl
// templates/repo/issue/view_content/sidebar/pull_tasks.tmpl
// templates/repo/issue/view_content/sidebar/pull_attention.tmpl
// templates/shared/issuelist.tmpl
// routers/web/repo/pull_task.go
// routers/web/repo/pull_attention.go
// web_src/js/features/repo-diff.js
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

test('PR: Create a task from a review comment and complete it', async ({page}) => {
  const suffix = `${Date.now()}`;
  const commentText = `Review comment ${suffix}`;
  const taskText = `Add a test ${suffix}`;

  // a single review comment on the diff
  const response = await page.goto('/user2/repo1/pulls/5/files');
  expect(response?.status()).toBe(200);
  await page.locator('button.add-code-comment').first().click();
  const codeComment = page.locator('.comment-code-cloud form textarea.markdown-text-editor');
  await expect(codeComment).toBeVisible();
  await codeComment.fill(commentText);
  await page.locator('.comment-code-cloud form button.btn-add-single').click();
  await expect(page.locator('.comment-code-cloud .comment .render-content').getByText(commentText)).toBeVisible();

  // turn it into a task from its context menu
  await page.goto('/user2/repo1/pulls/5');
  const conversation = page.locator('.conversation-holder').filter({hasText: commentText});
  await conversation.locator('.comment-header-right.actions .dialog-dropdown .opener').click();
  const taskInput = conversation.locator('.create-pull-task input[name="content"]');
  await expect(taskInput).toBeVisible();
  await taskInput.fill(taskText);
  await taskInput.press('Enter');

  const task = page.locator('#pull-tasks .pull-task').filter({hasText: taskText});
  await expect(task).toBeVisible();
  await expect(task).not.toHaveClass(/done/);
  await expect(task.locator('a[href*="#issuecomment-"]')).toHaveCount(1);
  await expect(page.locator('.issue-title-meta .pull-tasks-progress')).toHaveText(/Tasks: \d+ of \d+ done/);
  await screenshot(page);

  // complete it
  await task.getByRole('button', {name: 'Mark done'}).click();
  await expect(page.locator('#pull-tasks .pull-task').filter({hasText: taskText})).toHaveClass(/done/);
  await expect(page.locator('.timeline-item .pull-task-content').filter({hasText: taskText})).toHaveCount(2);
  await screenshot(page);

  // clean up, so that the diff line can take a new comment on the next run
  await page.locator('#pull-tasks .pull-task').filter({hasText: taskText}).getByRole('button', {name: 'Delete task'}).click();
  await expect(page.locator('#pull-tasks .pull-task').filter({hasText: taskText})).toHaveCount(0);
  page.on('dialog', (dialog) => dialog.accept());
  await conversation.locator('.comment-header-right.actions .dialog-dropdown .opener').click();
  await conversation.locator('.comment-header-right.actions .dialog-dropdown dialog .delete-comment').click();
  await expect(page.locator('.conversation-holder').filter({hasText: commentText})).toHaveCount(0);
});

test('PR: Add a user to the attention set and remove them', async ({page}) => {
  const response = await page.goto('/user2/repo1/pulls/5');
  expect(response?.status()).toBe(200);
  const attention = page.locator('#pull-attention');
  await attention.getByRole('combobox', {name: 'Choose a person'}).selectOption('user4');
  await attention.getByRole('textbox', {name: 'Reason (optional)'}).fill('Please check the docs');
  await attention.getByRole('button', {name: 'Add'}).click();

  const member = page.locator('#pull-attention li').filter({hasText: 'user4'});
  await expect(member).toBeVisible();
  await expect(member.locator('[data-tooltip-content]').first()).toHaveAttribute('data-tooltip-content', 'Added by user2: Please check the docs');
  await screenshot(page);

  // the pull request list marks it
  await page.goto('/user2/repo1/pulls');
  const marker = page.locator('#issue-list .flex-item').filter({hasText: 'pull5'}).locator('.pull-attention-marker');
  await expect(marker).toBeVisible();
  await expect(marker).toHaveAttribute('data-tooltip-content', /^Waiting on: .*user4/);

  // clean up
  await page.goto('/user2/repo1/pulls/5');
  await member.getByRole('button', {name: 'Remove from attention'}).click();
  await expect(page.locator('#pull-attention li').filter({hasText: 'user4'})).toHaveCount(0);
});
