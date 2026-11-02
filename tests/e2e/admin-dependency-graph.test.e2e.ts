// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/dependency_graph.tmpl
// templates/admin/dependency_graph_limit.tmpl
// templates/admin/dependency_graph_source_default.tmpl
// routers/web/admin/dependency_graph.go
// web_src/js/features/admin/dependency-graph.js
// web_src/css/repo/dependencies.css
// web_src/css/form.css
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {FakeData, fakeName, loginAs, adminAuth} from './shared/fake-data.ts';

test.describe('as the site admin', () => {
  test.use({user: 'user1'});

  // the source the instance starts with: restored after each test, which also drops every saved limit
  let source = '';

  test.beforeEach(async ({page}) => {
    await page.goto('/admin/config/dependency-graph');
    source = await page.locator('input[name="source"]:checked').inputValue();
  });

  test.afterEach(async ({page}) => {
    const resp = await page.request.post('/admin/config/dependency-graph/settings', {form: {source}, maxRedirects: 0});
    expect(resp.status()).toBe(303);
  });

  test('Dependency graph settings are saved on the page', async ({page}) => {
    const response = await page.goto('/admin/config/dependency-graph');
    expect(response?.status()).toBe(200);
    const scans = page.locator('#dg-max_concurrent_scans');
    await expect(scans).toHaveValue('1');

    // the mirror fields show only with the mirror source
    await page.locator('label[for="dg-source-mirror"]').click();
    await expect(page.locator('#dg-mirror_url')).toBeVisible();
    await page.locator('label[for="dg-source-public"]').click();
    await expect(page.locator('#dg-mirror_url')).toBeHidden();

    // the test uses the saved settings: not while the form has unsaved changes
    await scans.fill('2');
    await expect(page.locator('#dependency-graph-test')).toBeDisabled();
    await expect(page.locator('#dg-test-hint')).toHaveText('Save first to test the new settings.');
    await page.locator('#dependency-graph-save').click();
    await expect(page.locator('#flash-message')).toContainText('The dependency graph settings were saved.');
    await expect(scans).toHaveValue('2');
    await expect(page.locator('#dependency-graph-test')).toBeEnabled();
    await expect(page.locator('#dg-max_concurrent_scans').locator('xpath=../..').locator('.dg-app-default')).toContainText('app.ini: 1.');

    // back to the app.ini value: no hint
    await scans.fill('1');
    await page.locator('#dependency-graph-save').click();
    await expect(page.locator('#flash-message')).toContainText('The dependency graph settings were saved.');
    await expect(scans).toHaveValue('1');
    await expect(page.locator('#dg-max_concurrent_scans').locator('xpath=../..').locator('.dg-app-default')).toHaveCount(0);
  });

  test('A refused save shows the form again at the refused field', async ({page}) => {
    await page.goto('/admin/config/dependency-graph');
    // a field in a closed fold: the browser doesn't block the save, the server refuses it and opens the fold
    await page.locator('#dg-download-limits summary').click();
    await page.locator('#dg-osv_max_entry_size').fill('2000');
    await page.locator('#dg-download-limits summary').click();
    await page.locator('#dependency-graph-save').click();
    await expect(page.locator('#dg-form-error')).toContainText('Largest advisory must be more than 0 and at most 1024 MiB.');
    await expect(page.locator('#dg-save-error')).toContainText('Largest advisory must be more than 0 and at most 1024 MiB.');
    await expect(page.locator('#dg-download-limits')).toHaveAttribute('open', '');
    const field = page.locator('#dg-osv_max_entry_size');
    await expect(field).toHaveValue('2000');
    await expect(field).toHaveAttribute('aria-invalid', 'true');
    await expect(field).toBeFocused();
    await expect(page.locator('#dependency-graph-test')).toBeDisabled();
  });

  test('A refused field stays shown whatever the source', async ({page}) => {
    await page.goto('/admin/config/dependency-graph');
    await page.locator('#dg-allowed_hosts').fill('private');
    await page.locator('label[for="dg-source-none"]').click();
    await page.locator('#dependency-graph-save').click();
    const field = page.locator('#dg-allowed_hosts');
    await expect(field).toHaveAttribute('aria-invalid', 'true');
    await expect(field).toBeVisible();
    await expect(field).toBeFocused();
    await expect(page.locator('#dg-update_interval')).toBeVisible();
    await expect(page.locator('#dependency-graph-test')).toBeHidden();
    await expect(page.locator('#dg-test-hint')).toBeHidden();
  });

  test('A save over someone else\'s change is refused with a message that takes the focus', async ({page}) => {
    await page.goto('/admin/config/dependency-graph');
    const revision = await page.locator('input[name="revision"]').inputValue();
    // another admin saves after the page was shown
    const other = await page.request.post('/admin/config/dependency-graph/settings', {form: {source, max_concurrent_scans: '3', revision}, maxRedirects: 0});
    expect(other.status()).toBe(303);
    await page.locator('#dg-max_concurrent_scans').fill('2');
    await page.locator('#dependency-graph-save').click();
    const message = page.locator('#dg-form-error');
    await expect(message).toContainText('Someone else changed these settings; review and save again.');
    await expect(message).toBeFocused();
    await expect(message).toBeInViewport();
    await expect(page.locator('#dg-max_concurrent_scans')).toHaveValue('2');
  });

  test('The None source hides what it does not use', async ({page}) => {
    await page.goto('/admin/config/dependency-graph');
    await page.locator('label[for="dg-source-none"]').click();
    await expect(page.locator('label[for="dg-source-none"]')).toContainText('advisories already downloaded are kept');
    await expect(page.locator('#dg-allowed_hosts')).toBeHidden();
    await expect(page.locator('#dg-update_interval')).toBeHidden();
    await expect(page.locator('#dg-download-limits')).toBeHidden();
    await expect(page.locator('#dependency-graph-test')).toBeHidden();
    await expect(page.locator('#dg-test-hint')).toBeHidden();
    await expect(page.locator('#advisory-mirror-table')).toBeVisible();
  });
});

test.describe('as an auditor', () => {
  test.use({user: null, storageState: {cookies: [], origins: []}});

  let data: FakeData;

  test.beforeEach(({request}) => {
    data = new FakeData(request);
  });

  test.afterEach(async () => {
    await data.cleanup();
  });

  test('The auditor reads the dependency graph settings and can not save them', async ({browser, request}) => {
    const auditor = await data.createUser();
    const group = fakeName('group');
    expect((await request.post('/api/v1/admin/groups', {headers: adminAuth(), data: {name: group, grants_auditor: true}})).status()).toBe(201);
    data.trackGroup(group);
    expect((await request.put(`/api/v1/admin/groups/${group}/members/${auditor.username}`, {headers: adminAuth()})).status()).toBe(204);

    const page = await (await loginAs(browser, auditor.username, auditor.password)).newPage();
    const response = await page.goto('/admin/config/dependency-graph');
    expect(response?.status()).toBe(200);
    await expect(page.locator('#dg-max_concurrent_scans')).toBeDisabled();
    await expect(page.locator('#dg-read-only')).toContainText('Read-only: only site administrators can change these settings');
    await expect(page.locator('#dg-source-summary')).toBeVisible();
    await expect(page.locator('input[name="source"]')).toHaveCount(0);
    await expect(page.locator('#dependency-graph-save')).toHaveCount(0);
    await expect(page.locator('#dependency-graph-test')).toHaveCount(0);
    const post = await page.request.post('/admin/config/dependency-graph/settings', {form: {source: 'public', max_concurrent_scans: '5'}, maxRedirects: 0});
    expect(post.status()).toBe(403);
  });
});
