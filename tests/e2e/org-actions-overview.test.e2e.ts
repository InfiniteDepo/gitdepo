// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/org/actions/overview.tmpl
// routers/web/org/actions.go
// services/actions/org_overview.go
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user2'});

const cards = ['runs-24h', 'runs-7d', 'failure-rate', 'running', 'queued', 'avg-queue'];

for (const width of [1280, 390]) {
  test(`Org Actions overview cards are styled at ${width}px`, async ({page}) => {
    await page.setViewportSize({width, height: 900});
    await page.goto('/org/org3/actions/overview');

    // an org without runs: no failure rate and no queue sample
    await expect(page.locator('.org-overview-cards [data-card]')).toHaveCount(cards.length);
    await expect(page.locator('[data-card="failure-rate"] .value')).toHaveText('n/a');
    await expect(page.locator('[data-card="avg-queue"] .value')).toHaveText('n/a');

    const tops = new Set<number>();
    for (const card of cards) {
      const el = page.locator(`[data-card="${card}"]`);
      await expect(el).toBeVisible();
      await expect(el).toHaveCSS('border-top-width', '1px');
      tops.add(Math.round((await el.boundingBox())!.y));
    }
    // two cards per row on a phone
    if (width === 390) expect(tops.size).toBe(3);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await screenshot(page);
  });
}
