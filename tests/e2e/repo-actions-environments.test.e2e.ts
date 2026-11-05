// @watch start
// templates/repo/settings/environment*.tmpl
// templates/repo/settings/navbar.tmpl
// templates/shared/actions/secrets_list.tmpl
// templates/shared/actions/variables_list.tmpl
// routers/web/repo/setting/environments.go
// web_src/js/features/repo-settings-environments.js
// @watch end

import {expect} from '@playwright/test';
import {test, dynamic_id} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {basicAuth} from './shared/fake-data.ts';

test.use({user: 'user2'});

const list = '/user2/repo1/settings/actions/environments';

test('create, edit, give secrets to and delete an environment', async ({page}) => {
  const name = `prod-${dynamic_id()}`;
  await page.goto(list);
  await page.getByRole('link', {name: 'New environment', exact: true}).first().click();
  await page.locator('#environment-name').fill(name);

  // required reviewers and patterns
  await page.locator('#environment-reviewers input.search').click();
  await page.locator('#environment-reviewers .menu .item[data-value="user:2"]').click();
  await expect(page.locator('#environment-reviewers-count')).toHaveText('1 of 6 reviewers.');
  await page.locator('label[for="environment-prevent-self-review"]').click();
  await page.locator('#environment-wait-timer').fill('10');
  await page.locator('label[for="environment-ref-patterns"]').click();
  const rows = page.locator('#environment-pattern-rows .environment-pattern');
  await expect(rows).toHaveCount(1);
  await rows.nth(0).locator('input[name="pattern"]').fill('main');
  await page.locator('#environment-pattern-add').click();
  await rows.nth(1).locator('select[name="pattern_type"]').selectOption('tag');
  await rows.nth(1).locator('input[name="pattern"]').fill('v*');
  await page.locator('#environment-runner-labels').fill('prod');
  await screenshot(page, page.locator('.repo-setting-content'), 8);
  await page.locator('#environment-save').click();
  await expect(page.getByText(`The rules of environment "${name}" have been saved.`)).toBeVisible();
  await expect(page.locator('.repo-setting-content h4').first()).toHaveText(`Environment: ${name}`);

  await page.goto(list);
  const row = page.locator('#environment-list .flex-item').filter({hasText: name});
  await expect(row).toContainText('1 reviewer · Prevent self-review · main, v* · 10 min wait · runners: prod');
  await expect(row).toContainText('0 secrets · 0 variables');

  // edit: a pattern that doesn't compile is named and nothing is saved
  await row.getByRole('link', {name, exact: true}).click();
  await rows.nth(1).locator('input[name="pattern"]').fill('v[');
  await page.locator('#environment-save').click();
  await expect(page.getByText('The pattern "v[" is not valid.')).toBeVisible();
  await rows.nth(1).locator('input[name="pattern"]').fill('v*');
  await rows.nth(0).locator('.environment-pattern-remove').click();
  await page.locator('#environment-save').click();
  await expect(page.getByText(`The rules of environment "${name}" have been saved.`)).toBeVisible();
  await expect(rows).toHaveCount(1);

  // a secret of the environment: its value is never shown
  const secrets = page.locator('#environment-secrets');
  await secrets.getByRole('button', {name: 'Add secret'}).click();
  await page.locator('#secret-name').fill('DEPLOY_TOKEN');
  await page.locator('#secret-data').fill('do-not-show-this-value');
  await page.locator('#add-secret-modal button.ok').click();
  await expect(secrets.locator('.flex-item-title')).toContainText('DEPLOY_TOKEN');
  await expect(page.locator('body')).not.toContainText('do-not-show-this-value');

  // delete needs the typed name
  await page.getByRole('button', {name: 'Delete environment'}).click();
  const dialog = page.locator('#delete-environment-modal');
  await expect(dialog).toContainText(`The next deployment to ${name} will run without approval`);
  await expect(dialog).toContainText('Last deployment: none yet');
  const confirm = dialog.locator('#environment-delete-button');
  await expect(confirm).toBeDisabled();
  await dialog.locator('#environment-delete-confirm').fill(name.toUpperCase());
  await expect(confirm).toBeDisabled();
  await dialog.locator('#environment-delete-confirm').fill(name);
  await expect(confirm).toBeEnabled();
  await screenshot(page, dialog);
  await confirm.click();
  await expect(page.getByText(`The environment "${name}" has been deleted.`)).toBeVisible();
  await expect(page.locator('.repo-setting-content')).not.toContainText(name);
});

test('warning when nobody listed can approve', async ({page, request}) => {
  const name = `locked-${dynamic_id()}`;
  // user9 is deactivated: listed, but can't approve
  const response = await request.put(`/api/v1/repos/user2/repo1/actions/environments/${name}`, {
    headers: basicAuth('user2', 'password'),
    data: {reviewers: [{type: 'user', id: 9}]},
  });
  expect(response.status()).toBe(201);
  const warning = 'Nobody listed can approve a deployment right now';

  await page.goto(list);
  await expect(page.locator('#environment-list .flex-item').filter({hasText: name})).toContainText(warning);
  await page.locator('#environment-list').getByRole('link', {name, exact: true}).click();
  await expect(page.locator('#environment-no-reviewer')).toContainText(warning);
  await expect(page.locator('#environment-reviewers')).toContainText("can't sign in");
  await screenshot(page, page.locator('.repo-setting-content'), 8);

  // listing an approver lifts it
  await page.locator('#environment-reviewers input.search').click();
  await page.locator('#environment-reviewers .menu .item[data-value="user:2"]').click();
  await page.locator('#environment-save').click();
  await expect(page.locator('#environment-no-reviewer')).toHaveCount(0);

  const deleted = await request.delete(`/api/v1/repos/user2/repo1/actions/environments/${name}`, {
    headers: basicAuth('user2', 'password'),
  });
  expect(deleted.status()).toBe(204);
});
