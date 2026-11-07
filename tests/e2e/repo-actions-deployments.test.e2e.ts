// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/repo/actions/**
// web_src/js/components/RepoActionView.vue
// routers/web/repo/actions/deployments.go
// routers/web/repo/actions/view.go
// @watch end

import {expect, type APIRequestContext} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {basicAuth, fakeName} from './shared/fake-data.ts';

const owner = basicAuth('user2', 'password');

// newDeployment creates a public repository of user2 with an environment that user2 must approve and a workflow that
// deploys to it, and starts a run of it: the run waits for the review. It returns the run page and the repository.
async function newDeployment(request: APIRequestContext) {
  const repo = fakeName('deploy');
  let response = await request.post('/api/v1/user/repos', {headers: owner, data: {name: repo, auto_init: true, default_branch: 'main'}});
  expect(response.ok(), await response.text()).toBeTruthy();
  response = await request.put(`/api/v1/repos/user2/${repo}/actions/environments/prod`, {headers: owner, data: {
    ref_policy: 'any', ref_patterns: [], wait_timer: 0, prevent_self_review: false,
    reviewers: [{type: 'user', id: 2}], runner_labels: [], allowed_workflows: [],
  }});
  expect(response.ok(), await response.text()).toBeTruthy();
  const workflow = 'on: workflow_dispatch\njobs:\n  release:\n    runs-on: e2e-no-runner\n    environment: prod\n    steps:\n      - run: echo deploy\n';
  response = await request.post(`/api/v1/repos/user2/${repo}/contents/.gitea/workflows/deploy.yml`, {headers: owner, data: {
    message: 'add deploy', branch: 'main', content: Buffer.from(workflow).toString('base64'),
  }});
  expect(response.ok(), await response.text()).toBeTruthy();
  response = await request.post(`/api/v1/repos/user2/${repo}/actions/workflows/deploy.yml/dispatches`, {headers: owner, data: {ref: 'main', return_run_info: true}});
  expect(response.ok(), await response.text()).toBeTruthy();
  const run = await response.json();
  return {repo, runLink: `/user2/${repo}/actions/runs/${run.run_number}`};
}

test.describe('as the reviewer', () => {
  test.use({user: 'user2'});

  test('review a waiting deployment from the run page', async ({page, request}) => {
    const {repo, runLink} = await newDeployment(request);
    await page.goto(runLink);
    const panel = page.locator('.deployments-panel');
    await expect(panel).toHaveClass(/waiting/);
    await expect(panel).toContainText('1 deployment is waiting for approval');
    await expect(panel).toContainText('Waiting for approval');
    await expect(page.locator('.job-deployment-gate')).toContainText('Waiting for approval');
    await expect(page.locator('.job-info-header-detail')).toHaveText('Waiting for approval to deploy to prod');
    await screenshot(page, panel, 8);

    // a rejection needs a comment
    await page.locator('#review-deployments').click();
    const dialog = page.locator('#review-deployments-modal');
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('input[name="job_ids"]')).toBeChecked();
    await dialog.getByRole('button', {name: 'Reject', exact: true}).dispatchEvent('click');
    await expect(dialog).toContainText('A comment is required to reject.');
    await expect(dialog.locator('#review-comment')).toBeFocused();
    await expect(dialog.locator('#review-comment')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByRole('dialog', {name: 'Review pending deployments'})).toBeVisible();
    await screenshot(page, dialog);
    await dialog.locator('#review-comment').fill('Not <b>today</b>');
    await dialog.getByRole('button', {name: 'Reject', exact: true}).dispatchEvent('click');

    await expect(page.getByText('1 deployment was rejected.')).toBeVisible();
    await expect(panel).toHaveClass(/failed/);
    await expect(panel).toContainText('Deployment rejected');
    await expect(panel).toContainText('Rejected by user2');
    await expect(panel.locator('.deployment-comment')).toHaveText('Not <b>today</b>');
    await expect(page.locator('#review-deployments')).toHaveCount(0);
    await screenshot(page, panel, 8);

    // the deployments view of the Actions tab
    await page.goto(`/user2/${repo}/actions`);
    await page.locator('#deployments-menu').getByRole('link', {name: 'prod', exact: true}).click();
    await expect(page).toHaveURL(`/user2/${repo}/actions/deployments?environment=prod`);
    const item = page.locator('#deployment-list .deployment-item');
    await expect(item).toHaveCount(1);
    await expect(item).toContainText('Rejected by user2');
    await expect(item.locator('.deployment-comment')).toHaveText('Comment: Not <b>today</b>');
    await page.locator('#deployment-status').selectOption('released');
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(page.locator('#deployments-empty')).toContainText('No deployments match the filter.');
    await page.getByRole('link', {name: 'Clear filters', exact: true}).click();
    await expect(item).toHaveCount(1);
    await screenshot(page);
  });

  test('approve a waiting deployment', async ({page, request}) => {
    const {runLink} = await newDeployment(request);
    await page.goto(runLink);
    await page.locator('#review-deployments').click();
    await page.locator('#review-deployments-modal').getByRole('button', {name: 'Approve and deploy', exact: true}).dispatchEvent('click');
    await expect(page.getByText('1 deployment was approved.')).toBeVisible();
    await expect(page.locator('.deployments-panel')).toContainText('Approved by user2');
    await expect(page.locator('#review-deployments')).toHaveCount(0);
  });
});

test.describe('as another user', () => {
  test.use({user: 'user4'});

  test('a user who may not review sees that it waits, no reviewer and no button', async ({page, request}) => {
    const {runLink} = await newDeployment(request);
    await page.goto(runLink);
    const panel = page.locator('.deployments-panel');
    await expect(panel).toContainText('Waiting for review');
    await expect(panel).not.toContainText('Waiting for a reviewer');
    await expect(page.locator('#review-deployments')).toHaveCount(0);
    await expect(page.locator('#review-deployments-modal')).toHaveCount(0);
  });
});
