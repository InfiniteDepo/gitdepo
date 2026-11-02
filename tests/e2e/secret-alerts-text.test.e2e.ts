// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/security/**
// templates/shared/secret_alerts.tmpl
// routers/web/repo/secret_alerts.go
// models/secretscan/**
// services/secretscan/**
// @watch end

import {expect, type Page} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

const rows = (page: Page) => page.locator('.repo-security-row:not(.repo-security-head)');

async function fitsTheScreen(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
}

test.describe('the owner of a repository whose issues and pull requests they read', () => {
  test.use({user: 'user11'});

  test('sees where a secret is in text, and who wrote it', async ({page}) => {
    await page.goto('/user11/secret-text-test/security/secrets');
    await expect(rows(page)).toHaveCount(3);
    await expect(rows(page).filter({hasText: 'GitHub token'})).toContainText('Issue #1 · description');
    await expect(rows(page).filter({hasText: 'AWS access key ID'})).toContainText('Pull request #2 · title');
    await expect(rows(page).filter({hasText: 'Slack token'})).toContainText('config/prod.env:1');
    await expect(rows(page).filter({hasText: 'GitHub token'}).getByRole('link', {name: 'Issue #1'})).toHaveAttribute('href', /\/user11\/secret-text-test\/issues\/1$/);
    await expect(rows(page).filter({hasText: 'AWS access key ID'}).getByRole('link', {name: 'Pull request #2'})).toHaveAttribute('href', /\/user11\/secret-text-test\/pulls\/2$/);
    await fitsTheScreen(page);
    await screenshot(page);

    // the facet: where the secret was found
    await page.locator('select[name="found"]').selectOption('code');
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText('Slack token');
    await page.locator('select[name="found"]').selectOption('text');
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(rows(page)).toHaveCount(3);

    await page.goto('/user11/secret-text-test/security/secrets');
    await rows(page).filter({hasText: 'GitHub token'}).getByRole('link', {name: 'GitHub token'}).click();
    const places = page.locator('.secret-locations');
    await expect(places).toContainText('Issue #1');
    await expect(places).toContainText('description, line 4');
    await expect(places).toContainText('user2');
    await expect(places).toContainText('Removed from the text');
    await expect(places.getByRole('link', {name: 'Issue #1'}).first()).toHaveAttribute('href', /\/user11\/secret-text-test\/issues\/1$/);
    await expect(places).not.toContainText('Details hidden');
    await fitsTheScreen(page);
    await screenshot(page);
  });
});

test.describe('the owner of a repository whose issues and pull requests are off', () => {
  test.use({user: 'user11'});

  test('is told only that the secret is in an issue or a comment', async ({page}) => {
    await page.goto('/user11/secret-text-hidden/security/secrets');
    await expect(rows(page)).toHaveCount(3);
    await expect(rows(page).filter({hasText: 'GitHub token'})).toContainText('In an issue');
    await expect(rows(page).filter({hasText: 'GitHub token'})).not.toContainText('#1');
    await expect(rows(page).filter({hasText: 'Slack token'})).toContainText('config/prod.env:1');
    await fitsTheScreen(page);
    await screenshot(page);

    await rows(page).filter({hasText: 'GitHub token'}).getByRole('link', {name: 'GitHub token'}).click();
    const places = page.locator('.secret-locations');
    await expect(places).toContainText('In an issue');
    await expect(places).toContainText('In a comment');
    await expect(places.getByText("Details hidden: you don't have access to issues or pull requests here")).toHaveCount(2);
    for (const hidden of ['#1', 'user2', 'description', 'Removed from the text']) {
      await expect(places).not.toContainText(hidden);
    }
    await expect(places.getByRole('link')).toHaveCount(0);
    await fitsTheScreen(page);
    await screenshot(page);
  });
});
