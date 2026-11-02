// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// web_src/js/features/repo-issue.js
// web_src/js/markup/mermaid.js
// web_src/js/markup/math.js
// templates/repo/issue/view_content/comments.tmpl
// templates/repo/issue/view_content/conversation.tmpl
// @watch end

import {expect, type Locator, type Page} from '@playwright/test';
import {test} from './utils_e2e.ts';

test.use({user: 'user2'});
test.setTimeout(180000);

const PR = '/user2/permalink-test/pulls/1';

// Comment IDs are not known up front: read the ID from a plain load, then open the permalink in a fresh load.
async function commentID(page: Page, text: string) {
  await page.goto(PR, {waitUntil: 'domcontentloaded', timeout: 60000});
  const id = await page.locator('[id^="issuecomment-"]', {hasText: text}).last().getAttribute('id');
  await page.goto('about:blank');
  return id!.match(/^issuecomment-\d+/)![0];
}

// The fixture has 90 images, 90 math and 90 mermaid blocks before the target.
async function expectLayoutSettled(page: Page) {
  // images are lazy-loaded, so not all of them ever load; their shifts are caught by the position check
  await expect(page.locator('.markup .katex')).toHaveCount(90, {timeout: 60000});
  await expect(page.locator('.markup .mermaid-block:not(.is-loading)')).toHaveCount(90, {timeout: 60000});
}

// Samples the position once per animation frame and needs 10 identical samples in a row, then re-checks the viewport.
async function expectStableInViewport(target: Locator) {
  let last = NaN;
  let same = 0;
  await expect.poll(async () => {
    const top = await target.evaluate((el) => new Promise<number>((resolve) => requestAnimationFrame(() => resolve(el.getBoundingClientRect().top))));
    same = top === last ? same + 1 : 0;
    last = top;
    return same;
  }, {timeout: 30000, intervals: [100]}).toBeGreaterThanOrEqual(10);
  await expect(target).toBeInViewport({ratio: 0.5});
}

test('permalink to a deep comment stays in view while content loads', async ({page}) => {
  const id = await commentID(page, 'PERMALINK-TARGET');
  const response = await page.goto(`${PR}#${id}`, {waitUntil: 'domcontentloaded', timeout: 60000});
  expect(response?.status()).toBe(200);

  const target = page.locator(`#${id}`);
  await expectLayoutSettled(page);
  // no scrollIntoView here: the page itself must have brought the comment into view
  await expectStableInViewport(target);
});

test('permalink to a comment in an outdated code comment group expands it', async ({page}) => {
  const id = await commentID(page, 'OUTDATED-TARGET');
  await page.goto(`${PR}#${id}`, {waitUntil: 'domcontentloaded', timeout: 60000});

  const target = page.locator(`#${id}`);
  await expectLayoutSettled(page);
  await expect(target).toBeVisible();
  await expectStableInViewport(target);
  await expect(page.locator(`.conversation-holder:has(#${id}) .hide-outdated`).first()).toBeVisible();
});
