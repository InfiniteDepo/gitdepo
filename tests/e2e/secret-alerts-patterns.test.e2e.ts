// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/shared/secret_patterns.tmpl
// templates/org/security_patterns.tmpl
// templates/org/settings/code_security.tmpl
// templates/admin/secret_patterns.tmpl
// routers/web/shared/security/patterns.go
// routers/web/org/setting/code_security.go
// routers/web/admin/secret_patterns.go
// services/secretscan/patterns.go
// web_src/js/features/secret-alerts.js
// @watch end

import {expect, type Page} from '@playwright/test';
import {test, login_user} from './utils_e2e.ts';

const rows = (page: Page) => page.locator('table.secret-patterns-table tbody tr');

// a secret of the test rule, built from parts so that no source line holds one
const sample = `K=acme-${'key-'}${'a1'.repeat(10)}`;

async function fitsTheScreen(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
}

async function fill(page: Page, name: string, keywords = 'acme-key') {
  await page.locator('#secret-pattern-name').fill(name);
  await page.locator('#secret-pattern-pattern').fill('acme-key-[a-z0-9]{20}');
  await page.locator('#secret-pattern-keywords').fill(keywords);
  await page.locator('#secret-pattern-sample').fill(sample);
}

test.describe('an organization owner', () => {
  test.use({user: 'user2'});

  test('tests, adds, renames, turns off and deletes a custom pattern', async ({page, isMobile}) => {
    const name = isMobile ? 'Acme key (phone)' : 'Acme key (desktop)';
    await page.goto('/org/org3/settings/code_security');
    await expect(page.locator('#secret-patterns-none')).toContainText('No custom patterns yet.');
    await expect(rows(page)).toHaveCount(0);

    // Test shows what the pattern found, never the test string, and stores nothing
    await fill(page, name);
    await page.locator('#secret-pattern-test').click();
    const result = page.locator('#secret-pattern-result');
    await expect(result).toContainText('Match found');
    await expect(result).toContainText('29 characters');
    await expect(result).not.toContainText('a1a1a1');
    await expect(rows(page)).toHaveCount(0);

    // a refused rule says why, next to the field, keeps what was typed and not the test string
    await page.locator('#secret-pattern-keywords').fill('zzz-key');
    await expect(result).toBeEmpty(); // an edit clears the old answer
    await page.locator('#secret-pattern-test').click();
    await expect(result).toContainText('A keyword must appear in the match');
    await expect(page.locator('#secret-pattern-keywords')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.locator('#secret-pattern-keywords')).toHaveAttribute('aria-describedby', 'secret-pattern-error');
    await page.locator('#secret-pattern-add').click();
    await expect(page).toHaveURL(/#secret-pattern-form$/);
    await expect(page.locator('#secret-pattern-error')).toContainText('A keyword must appear in the match');
    await expect(page.locator('#secret-pattern-error')).toBeInViewport();
    await expect(page.locator('#secret-pattern-keywords')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.locator('#secret-pattern-name')).toHaveValue(name);
    await expect(page.locator('#secret-pattern-keywords')).toHaveValue('zzz-key');
    await expect(page.locator('#secret-pattern-sample')).toHaveValue('');
    await fitsTheScreen(page);

    // add
    await fill(page, name);
    await page.locator('#secret-pattern-add').click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText(name);
    await expect(rows(page).first()).toContainText('acme-key-[a-z0-9]{20}');
    await expect(rows(page).first()).toContainText('On');
    await expect(page.locator('#secret-patterns-count')).toContainText('1 of 50 patterns are on, including the site\'s.');
    await fitsTheScreen(page);

    // the type filter of the list offers it
    await page.goto('/org/org3/security/secrets');
    await expect(page.locator('select[name="type"] option', {hasText: name})).toHaveCount(1);
    await page.goto('/org/org3/settings/code_security');

    // disable asks, and says what happens; Cancel closes the dialog
    await rows(page).first().getByRole('button', {name: 'Disable'}).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', {name: 'Cancel'}).click();
    await expect(dialog).toHaveCount(0);
    await rows(page).first().getByRole('button', {name: 'Disable'}).click();
    await expect(dialog).toContainText(`Disable pattern ${name}?`);
    await expect(dialog).toContainText('It has no open alerts.');
    await dialog.getByRole('button', {name: 'Disable pattern'}).click();
    await expect(rows(page).first()).toContainText('Off');
    await rows(page).first().getByRole('button', {name: 'Enable'}).click();
    await expect(rows(page).first()).toContainText('On');

    // rename: the only edit
    await rows(page).first().getByRole('button', {name: 'Rename'}).click();
    await page.getByRole('dialog').getByRole('textbox', {name: 'Name'}).fill(`${name} 2`);
    await page.getByRole('dialog').getByRole('button', {name: 'Rename'}).click();
    await expect(rows(page).first()).toContainText(`${name} 2`);

    // delete asks for the name
    await rows(page).first().getByRole('button', {name: 'Delete'}).click();
    const confirm = page.getByRole('dialog');
    await expect(confirm).toContainText(`Delete pattern ${name} 2?`);
    const ok = confirm.getByRole('button', {name: 'Delete pattern'});
    await expect(ok).toBeDisabled();
    await confirm.getByRole('textbox', {name: `Type ${name} 2 to confirm`}).fill('something else');
    await expect(ok).toBeDisabled();
    await confirm.getByRole('textbox', {name: `Type ${name} 2 to confirm`}).fill(`${name} 2`);
    await expect(ok).toBeEnabled();
    await ok.click();
    await expect(rows(page)).toHaveCount(0);
    await expect(page.locator('#secret-patterns-none')).toBeVisible();
  });

  test('reads the patterns in the Security area', async ({page}) => {
    await page.goto('/org/org3/security/secrets/patterns');
    await expect(page.locator('.repo-security-tabs a[aria-current="page"]')).toHaveText('Custom patterns');
    await expect(page.locator('#secret-pattern-form')).toHaveCount(0);
    await expect(page.locator('#secret-patterns-manage')).toBeVisible();
    await fitsTheScreen(page);
  });
});

test.describe('an organization member', () => {
  test.use({user: null, storageState: {cookies: [], origins: []}});

  test('reads names and keywords, never the rule', async ({browser}, workerInfo) => {
    const page = await (await login_user(browser, workerInfo, 'user4')).newPage();
    await page.goto('/org/org3/security/secrets/patterns');
    await expect(page.locator('#secret-patterns-intro')).toContainText('Patterns the organization and the site scan for');
    await expect(page.locator('#secret-pattern-form')).toHaveCount(0);
    await expect(page.locator('#secret-patterns-manage')).toHaveCount(0);
    await fitsTheScreen(page);
  });
});

test.describe('the site admin', () => {
  test.use({user: 'user1'});

  test('manages the site patterns', async ({page, isMobile}) => {
    const name = isMobile ? 'Site key (phone)' : 'Site key (desktop)';
    await page.goto('/admin/security/patterns');
    await expect(page.getByRole('link', {name: 'Custom patterns', exact: true})).toBeVisible();
    await fill(page, name);
    await page.locator('#secret-pattern-add').click();
    await expect(rows(page).filter({hasText: name})).toHaveCount(1);
    await expect(rows(page).filter({hasText: name})).toContainText('acme-key-[a-z0-9]{20}');
    await fitsTheScreen(page);
    // an organization lists it as a site pattern, with no buttons
    await page.goto('/org/org3/settings/code_security');
    const site = rows(page).filter({hasText: name});
    await expect(site).toContainText('Site');
    await expect(site.getByRole('button')).toHaveCount(0);
    await page.goto('/admin/security/patterns');
    const row = rows(page).filter({hasText: name});
    await row.getByRole('button', {name: 'Delete'}).click();
    const confirm = page.getByRole('dialog');
    await confirm.getByRole('textbox', {name: `Type ${name} to confirm`}).fill(name);
    await confirm.getByRole('button', {name: 'Delete pattern'}).click();
    await expect(rows(page).filter({hasText: name})).toHaveCount(0);
  });
});

test.describe('someone outside', () => {
  test.use({user: 'user12'});

  test('finds no pattern page', async ({page}) => {
    expect((await page.goto('/org/org3/settings/code_security'))?.status()).toBe(404);
    expect((await page.goto('/org/org3/security/secrets/patterns'))?.status()).toBe(404);
    expect((await page.goto('/admin/security/patterns'))?.status()).toBe(403);
  });
});
