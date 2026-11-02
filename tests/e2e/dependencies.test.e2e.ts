// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/dependencies.tmpl
// templates/repo/navbar.tmpl
// routers/web/repo/dependency.go
// web_src/css/repo/dependencies.css
// @watch end

import {expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

test.use({user: 'user11'});

test('list, filter and page of the dependencies', async ({page}) => {
  await page.goto('/user11/dependencies-test/activity');
  await page.locator('.flex-container-nav').getByRole('link', {name: 'Dependencies', exact: true}).click();
  await expect(page).toHaveURL(/\/user11\/dependencies-test\/activity\/dependencies$/);
  await expect(page.getByRole('heading', {name: 'Dependencies'})).toBeVisible();
  await expect(page.getByText('4 packages from 3 manifests')).toBeVisible();

  const rows = page.locator('.repo-dependencies-row:not(.repo-dependencies-head)');
  await expect(rows).toHaveCount(4);
  await expect(rows.filter({hasText: 'requests'}).getByText('Unknown')).toBeVisible();
  await screenshot(page);

  await page.getByRole('searchbox', {name: 'Search packages'}).fill('expr');
  await page.getByRole('button', {name: 'Filter'}).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('express');

  await page.goto('/user11/dependencies-test/activity/dependencies');
  await page.getByLabel('Relationship').selectOption('transitive'); // a select applies at once, without the button
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('body-parser');
  await expect(page.locator('#dependencies-matches')).toContainText('1 of 4 packages match.');
  await page.getByRole('link', {name: 'Clear filters'}).click();
  await expect(rows).toHaveCount(4);
  await expect(page.locator('#dependencies-matches')).toHaveCount(0);

  await page.goto('/user11/dependencies-test/activity/dependencies');
  await page.getByLabel('Ecosystem').selectOption('Go');
  await expect(rows).toHaveCount(1);
  await page.getByLabel('Manifest').selectOption('go.mod');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('golang.org/x/net');
  await expect(rows.first().getByRole('link', {name: 'go.mod'})).toHaveAttribute('href', /\/src\/commit\/[0-9a-f]{40}\/go\.mod$/);
});

test('download both SBOM formats', async ({page}) => {
  await page.goto('/user11/dependencies-test/activity/dependencies');
  const exportMenu = page.locator('#dependencies-export');

  await exportMenu.click();
  await expect(exportMenu).toContainText('user11-dependencies-test.spdx.json');
  const spdxDownload = page.waitForEvent('download');
  await exportMenu.locator('a.item', {hasText: 'SPDX 2.3'}).click();
  const spdx = await spdxDownload;
  expect(spdx.suggestedFilename()).toBe('user11-dependencies-test.spdx.json');
  const spdxDoc = JSON.parse(readFileSync(await spdx.path(), 'utf8'));
  expect(spdxDoc.spdxVersion).toBe('SPDX-2.3');
  expect(spdxDoc.name).toBe('user11/dependencies-test');
  expect(spdxDoc.packages).toHaveLength(5);

  await exportMenu.click();
  const cdxDownload = page.waitForEvent('download');
  await exportMenu.locator('a.item', {hasText: 'CycloneDX 1.6'}).click();
  const cdx = await cdxDownload;
  expect(cdx.suggestedFilename()).toBe('user11-dependencies-test.cdx.json');
  const cdxDoc = JSON.parse(readFileSync(await cdx.path(), 'utf8'));
  expect(cdxDoc.bomFormat).toBe('CycloneDX');
  expect(cdxDoc.metadata.component.name).toBe('user11/dependencies-test');
  expect(cdxDoc.components).toHaveLength(4);
});

test('a manifest without a lock file', async ({page}) => {
  for (const width of [1280, 390]) {
    await page.setViewportSize({width, height: 900});
    await page.goto('/user11/dependencies-unpinned/activity/dependencies');
    const hint = page.locator('.repo-dependencies-hint');
    await expect(hint).toHaveCount(1);
    await expect(hint.locator('.header')).toContainText('1 manifest has no lock file');
    await expect(hint.locator('li')).toHaveText(['web/package.json']);
    await expect(hint).toContainText('Commit package-lock.json, yarn.lock or pnpm-lock.yaml for exact versions and transitive packages.');
    const express = page.locator('.repo-dependencies-row', {hasText: 'express'});
    await expect(express).toContainText('^4.18.0');
    await expect(express.locator('.repo-dependencies-not-pinned')).toHaveText('not pinned');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await screenshot(page);
  }
  // a pinned row has no label
  await page.goto('/user11/dependencies-test/activity/dependencies');
  await expect(page.locator('.repo-dependencies-not-pinned')).toHaveCount(0);
  await expect(page.locator('.repo-dependencies-hint')).toHaveCount(0);
});

test('a reader without access to the code gets nothing', async ({page}) => {
  const response = await page.goto('/user11/dependencies-no-code/activity/dependencies');
  expect(response?.status()).toBe(404);
  const sbom = await page.goto('/user11/dependencies-no-code/activity/dependencies/sbom');
  expect(sbom?.status()).toBe(404);
  await page.goto('/user11/dependencies-no-code/activity');
  await expect(page.getByRole('link', {name: 'Dependencies', exact: true})).toBeHidden();
});

test('phone width stacks the rows into cards', async ({page}) => {
  await page.setViewportSize({width: 390, height: 800});
  await page.goto('/user11/dependencies-test/activity/dependencies');
  await expect(page.locator('.repo-dependencies-head')).toBeHidden();
  const row = page.locator('.repo-dependencies-row:not(.repo-dependencies-head)').first();
  await expect(row).toBeVisible();
  const box = await row.boundingBox();
  expect(box!.width).toBeLessThanOrEqual(390);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await screenshot(page);
});

test('the filter bar fits the screen and has big enough controls', async ({page}) => {
  for (const [width, minHeight] of [[390, 44], [1280, 30]]) {
    await page.setViewportSize({width, height: 900});
    await page.goto('/user11/dependencies-test/activity/dependencies');
    const controls = page.locator('.repo-dependencies-filters').locator('input[type=search], select, button');
    await expect(controls).toHaveCount(5);
    for (const control of await controls.all()) {
      const box = await control.boundingBox();
      expect(box!.height).toBeGreaterThanOrEqual(minHeight);
      expect(box!.x + box!.width).toBeLessThanOrEqual(width);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  }
});
