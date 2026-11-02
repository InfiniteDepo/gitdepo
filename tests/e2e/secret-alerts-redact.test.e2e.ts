// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/security/secret.tmpl
// routers/web/repo/secret_alerts.go
// services/secretscan/redact.go
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';

// each browser project has its own issue and alert (see seedSecretRedact): a redaction can't be undone
const alertOf: Record<string, number> = {'chromium': 1, 'firefox': 2, 'Mobile Chrome': 3};

test.describe('the owner of a repository', () => {
  test.use({user: 'user11'});

  test('removes a secret from the text of an issue', async ({page}, testInfo) => {
    const n = alertOf[testInfo.project.name];
    await page.goto(`/user11/secret-redact-test/security/secrets/${n}`);
    const places = page.locator('.secret-locations');
    await expect(places.locator('button.secret-redact')).toHaveCount(2);
    const body = places.getByRole('button', {name: `Redact the secret from Issue #${n} · description`, exact: true});
    const comment = places.getByRole('button', {name: `Redact the secret from Issue #${n} · comment`, exact: true});
    await expect(body).toHaveText('Redact…');

    // the dialog says what happens, and Cancel leaves everything as it is
    const dialog = page.locator('#secret-redact-modal');
    await body.click();
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('header')).toHaveText('Redact the secret');
    await expect(dialog.locator('#secret-redact-where')).toHaveText(`Issue #${n} · description`);
    await expect(dialog).toContainText('[secret removed]');
    await expect(dialog).toContainText('edit history');
    await expect(dialog).toContainText("can't be undone");
    await expect(dialog).toContainText('The credential still works until you revoke it');
    await expect(dialog).toContainText('webhook deliveries');
    await screenshot(page);
    await dialog.getByRole('button', {name: 'Cancel', exact: true}).click();
    await expect(dialog).toBeHidden();

    // confirmed: the text is redacted and the place is marked; the button stays, for the history
    await body.click();
    await dialog.getByRole('button', {name: 'Redact', exact: true}).click();
    await expect(page.locator('.flash-success')).toContainText('Revoke it, then close the alert.');
    await expect(places).toContainText('Removed from the text');
    await expect(page.locator('#secret-activity')).toContainText('removed the secret from an issue or pull request text');
    await screenshot(page);

    // the comment no longer holds the secret, its edit history does: that is erased
    await comment.click();
    await expect(dialog.locator('#secret-redact-where')).toHaveText(`Issue #${n} · comment`);
    await dialog.getByRole('button', {name: 'Redact', exact: true}).click();
    await expect(page.locator('.flash-success')).toContainText('The secret was already gone from the text. Its earlier versions were deleted from the edit history.');
    await expect(page.locator('#secret-activity')).toContainText('cleaned up an issue or pull request text the secret was already gone from');
    await screenshot(page);

    // then nothing is left to remove
    await comment.click();
    await dialog.getByRole('button', {name: 'Redact', exact: true}).click();
    await expect(page.locator('.flash-info')).toContainText('Nothing left to remove');
    await screenshot(page);

    await page.goto(`/user11/secret-redact-test/issues/${n}`);
    await expect(page.locator('.comment-list .render-content').first()).toContainText('[secret removed]');
    await expect(page.locator('.comment-list').first()).not.toContainText('ghp_');

    // the body's "edited" menu: the emptied first version shows as deleted, the redaction as user11's edit
    await page.locator('.timeline-item.comment.first .content-history-menu').click();
    const versions = page.locator('.timeline-item.comment.first .content-history-menu .menu .item');
    await expect(versions).toHaveCount(2);
    await expect(versions.locator('[data-history-is-deleted="1"]')).toHaveCount(1);
  });
});
