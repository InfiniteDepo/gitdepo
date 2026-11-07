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
  // a new organization environment applies to no repository until some are chosen
  await expect(page.locator('#deploy-key-scope-selected-environment')).toBeChecked();
  await page.locator('label[for="deploy-key-scope-all-environment"]').click();
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

test('a run waits for an organization environment and its reviewer approves it', async ({page, request}) => {
  const id = dynamic_id();
  const name = `org-review-${id}`;
  const repo = `oenv-run-${id}`;
  const headers = basicAuth('user2', 'password');
  let response = await request.post('/api/v1/orgs/org3/repos', {headers, data: {name: repo, auto_init: true, default_branch: 'main'}});
  expect(response.ok(), await response.text()).toBeTruthy();
  response = await request.put(`/api/v1/orgs/org3/actions/environments/${name}`, {headers, data: {
    ref_policy: 'any', ref_patterns: [], wait_timer: 0, prevent_self_review: false, reviewers: [{type: 'user', id: 2}],
    runner_labels: [], allowed_workflows: [], repository_selection: 'selected', repositories: [repo],
  }});
  expect(response.ok(), await response.text()).toBeTruthy();
  const workflow = `on: workflow_dispatch\njobs:\n  release:\n    runs-on: e2e-no-runner\n    environment: ${name}\n    steps:\n      - run: echo deploy\n`;
  response = await request.post(`/api/v1/repos/org3/${repo}/contents/.gitea/workflows/deploy.yml`, {headers, data: {
    message: 'add deploy', branch: 'main', content: Buffer.from(workflow).toString('base64'),
  }});
  expect(response.ok(), await response.text()).toBeTruthy();
  response = await request.post(`/api/v1/repos/org3/${repo}/actions/workflows/deploy.yml/dispatches`, {headers, data: {ref: 'main', return_run_info: true}});
  expect(response.ok(), await response.text()).toBeTruthy();
  const run = await response.json();

  await page.goto(`/org3/${repo}/actions/runs/${run.run_number}`);
  await expect(page.locator('.job-info-header-detail')).toHaveText(`Waiting for approval to deploy to ${name}`);
  await page.locator('#review-deployments').click();
  const dialog = page.locator('#review-deployments-modal');
  await expect(dialog).toContainText(name);
  await screenshot(page, dialog);
  await dialog.getByRole('button', {name: 'Approve and deploy', exact: true}).dispatchEvent('click');
  await expect(page.getByText('1 deployment was approved.')).toBeVisible();
  await expect(page.locator('.deployments-panel')).toContainText('Approved by user2');

  expect((await request.delete(`/api/v1/repos/org3/${repo}`, {headers})).status()).toBe(204);
  expect((await request.delete(`/api/v1/orgs/org3/actions/environments/${name}`, {headers})).status()).toBe(204);
});
