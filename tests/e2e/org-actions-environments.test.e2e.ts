// @watch start
// templates/repo/settings/environment*.tmpl
// templates/org/settings/navbar.tmpl
// routers/web/repo/setting/environments.go
// web_src/js/features/repo-settings-environments.js
// @watch end

import {expect} from '@playwright/test';
import {test, dynamic_id} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {basicAuth} from './shared/fake-data.ts';

test.use({user: 'user2'});

const orgList = '/org/org3/settings/actions/environments';

test('an organization environment is inherited by its repositories', async ({page, request}) => {
  const id = dynamic_id();
  const name = `org-prod-${id}`;
  const repo = `oenv-${id}`;
  const created = await request.post('/api/v1/orgs/org3/repos', {headers: basicAuth('user2', 'password'), data: {name: repo, auto_init: true}});
  expect(created.status()).toBe(201);

  // the organization's settings: the last item of the Actions menu
  await page.goto('/org/org3/settings');
  const nav = page.locator('.flex-container-nav');
  await nav.locator('summary', {hasText: 'Actions'}).click();
  await nav.getByRole('link', {name: 'Environments', exact: true}).click();
  await expect(page).toHaveURL(orgList);
  await expect(page.locator('#environment-org-note')).toContainText('Organization environments are never created by workflows.');
  await page.getByRole('link', {name: 'New environment', exact: true}).first().click();
  await page.locator('#environment-name').fill(name);
  await page.locator('#environment-reviewers input.search').click();
  await page.locator('#environment-reviewers .menu .item[data-value="user:2"]').click();
  await page.locator('#environment-wait-timer').fill('5');
  await screenshot(page, page.locator('.org-setting-content'), 8);
  await page.locator('#environment-save').click();
  await expect(page.getByText(`The rules of environment "${name}" have been saved.`)).toBeVisible();

  await page.goto(orgList);
  await expect(page.locator('#environment-list .flex-item').filter({hasText: name})).toContainText('1 reviewer · 5 min wait');

  // the repository shows it read-only, with a link to edit it in the organization
  const repoList = `/org3/${repo}/settings/actions/environments`;
  await page.goto(repoList);
  const inherited = page.locator('#environment-inherited-list .flex-item').filter({hasText: name});
  await expect(inherited).toContainText('From organization org3');
  await expect(inherited).toContainText('1 reviewer · 5 min wait');
  await screenshot(page, page.locator('.repo-setting-content'), 8);

  // and refuses a repository environment of the same name
  await page.getByRole('link', {name: 'New environment', exact: true}).first().click();
  await page.locator('#environment-name').fill(name.toUpperCase());
  await page.locator('#environment-save').click();
  await expect(page.getByText('This name is taken by an environment of the organization org3')).toBeVisible();

  await page.goto(repoList);
  await inherited.getByRole('link', {name: 'Edit in org3'}).click();
  await expect(page.locator('.org-setting-content h4').first()).toHaveText(`Environment: ${name}`);

  const deleted = await request.delete(`/api/v1/orgs/org3/actions/environments/${name}`, {headers: basicAuth('user2', 'password')});
  expect(deleted.status()).toBe(204);
  const removed = await request.delete(`/api/v1/repos/org3/${repo}`, {headers: basicAuth('user2', 'password')});
  expect(removed.status()).toBe(204);
});
