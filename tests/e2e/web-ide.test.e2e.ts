// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// routers/web/repo/ide.go
// templates/repo/ide.tmpl
// templates/repo/view_file.tmpl
// templates/repo/issue/view_title.tmpl
// web_src/ide/**
// web_src/js/features/repo-code.ts
// @watch end

import {expect, type APIRequestContext, type Page} from '@playwright/test';
import {test, create_temp_user, dynamic_id} from './utils_e2e.ts';

// The workbench is a desktop UI; its keyboard shortcuts are the Linux/Windows ones.
test.skip(({isMobile}) => isMobile, 'the Web IDE is a desktop UI');

const files = ['alpha.txt', 'beta.txt', 'gamma.txt', 'delta.txt'];

async function setupRepo(request: APIRequestContext, username: string) {
  const auth = {Authorization: `Basic ${btoa(`${username}:password`)}`, 'Content-Type': 'application/json'};
  const repo = dynamic_id();
  const api = `/api/v1/repos/${username}/${repo}`;
  expect((await request.post('/api/v1/user/repos', {headers: auth, data: {name: repo, auto_init: true, default_branch: 'main'}})).ok()).toBeTruthy();
  const created = await request.post(`${api}/contents`, {headers: auth, data: {
    branch: 'main',
    message: 'add files',
    files: files.map((path) => ({operation: 'create', path, content: btoa(`${path}\n`)})),
  }});
  expect(created.ok()).toBeTruthy();
  return {repo, api, auth, link: `/${username}/${repo}`};
}

async function openIDE(page: Page, link: string) {
  await page.goto(link);
  await expect(page.locator('#ide[data-ready="true"]')).toBeAttached({timeout: 30000});
}

const explorerRow = (page: Page, name: string) => page.locator('.explorer-folders-view .monaco-list-row', {hasText: name});

async function editFile(page: Page, name: string, text: string) {
  await explorerRow(page, name).dblclick();
  const editor = page.locator('.editor-instance .monaco-editor').filter({visible: true}).first();
  await expect(editor).toContainText(name);
  await editor.locator('.view-lines').click();
  await page.keyboard.press('Control+End');
  await page.keyboard.type(text);
  await page.keyboard.press('Control+s');
}

async function commit(page: Page, message: string, choice: RegExp) {
  await page.keyboard.press('Control+Shift+G');
  await page.locator('.scm-editor .monaco-editor').first().click();
  await page.keyboard.type(message);
  await page.keyboard.press('Control+Enter');
  await page.locator('.monaco-dialog-box .monaco-button', {hasText: choice}).click();
}

const toast = (page: Page) => page.locator('.notifications-toasts');

test('open from the file view and with "."', async ({browser, request}, workerInfo) => {
  const {context, username} = await create_temp_user(browser, workerInfo, request);
  const page = await context.newPage();
  const {link} = await setupRepo(request, username);

  await page.goto(`${link}/src/branch/main/alpha.txt`);
  await page.locator('a[data-ide-link]').click();
  await expect(page).toHaveURL(`${link}/-/ide/branch/main/alpha.txt`);
  await expect(page.locator('#ide[data-ready="true"]')).toBeAttached({timeout: 30000});
  await expect(page.locator('.tab.active')).toContainText('alpha.txt');

  await page.goto(`${link}/src/branch/main`);
  await page.locator('#repo-files-table').waitFor();
  await page.keyboard.press('.');
  await expect(page).toHaveURL(`${link}/-/ide/branch/main`);
});

test('edit, delete and rename in one commit', async ({browser, request}, workerInfo) => {
  const {context, username} = await create_temp_user(browser, workerInfo, request);
  const page = await context.newPage();
  const {api, auth, link} = await setupRepo(request, username);
  await openIDE(page, `${link}/-/ide/branch/main`);

  await editFile(page, 'alpha.txt', 'edited\n');
  await editFile(page, 'beta.txt', 'edited\n');
  await explorerRow(page, 'gamma.txt').click();
  await page.keyboard.press('Delete');
  await page.locator('.monaco-dialog-box').getByRole('button', {name: 'Delete', exact: true}).click();
  await explorerRow(page, 'delta.txt').click();
  await page.keyboard.press('F2');
  await page.keyboard.press('Control+a');
  await page.keyboard.type('epsilon.txt');
  await page.keyboard.press('Enter');
  await expect(explorerRow(page, 'epsilon.txt')).toBeVisible();

  await commit(page, 'IDE commit', /^Commit to main/);
  await expect(toast(page)).toContainText('Committed to main');

  const head = await (await request.get(`${api}/git/commits/main`, {headers: auth})).json();
  expect(head.commit.message.trim()).toBe('IDE commit');
  expect(head.files.map((f) => `${f.status} ${f.filename}`).sort()).toEqual([
    'added epsilon.txt',
    'modified alpha.txt',
    'modified beta.txt',
    'removed delta.txt',
    'removed gamma.txt',
  ]);
});

test('commit to a new branch and open a pull request', async ({browser, request}, workerInfo) => {
  const {context, username} = await create_temp_user(browser, workerInfo, request);
  const page = await context.newPage();
  const {api, auth, link} = await setupRepo(request, username);
  await openIDE(page, `${link}/-/ide/branch/main/alpha.txt`);

  await editFile(page, 'alpha.txt', 'feature\n');
  await commit(page, 'Feature from the IDE', /^New branch \+ PR$/);
  await page.keyboard.press('Control+a');
  await page.keyboard.type('ide-feature');
  await page.keyboard.press('Enter');
  await expect(toast(page)).toContainText('The pull request is open');
  await expect(page.locator('.statusbar')).toContainText('ide-feature');

  const pulls = await (await request.get(`${api}/pulls`, {headers: auth})).json();
  expect(pulls.map((p) => [p.title, p.head.ref, p.base.ref])).toEqual([['Feature from the IDE', 'ide-feature', 'main']]);

  // the pull request page links back to the IDE on its branch
  await page.goto(pulls[0].html_url);
  await expect(page.locator('a[data-ide-link]')).toHaveAttribute('href', `${link}/-/ide/branch/ide-feature`);
});

test('a protected branch only offers a new branch', async ({browser, request}, workerInfo) => {
  const {context, username} = await create_temp_user(browser, workerInfo, request);
  const page = await context.newPage();
  const {api, auth, link} = await setupRepo(request, username);
  expect((await request.post(`${api}/branch_protections`, {headers: auth, data: {rule_name: 'main', enable_push: false}})).ok()).toBeTruthy();
  await openIDE(page, `${link}/-/ide/branch/main`);

  await editFile(page, 'alpha.txt', 'x\n');
  await commit(page, 'Protected', /^New branch$/);
  await expect(page.locator('.monaco-dialog-box .monaco-button', {hasText: /^Commit to main/})).toHaveCount(0);
  await page.keyboard.press('Control+a');
  await page.keyboard.type('from-protected');
  await page.keyboard.press('Enter');
  await expect(toast(page)).toContainText('Committed to from-protected');
});

test('a branch with new commits offers a new branch', async ({browser, request}, workerInfo) => {
  const {context, username} = await create_temp_user(browser, workerInfo, request);
  const page = await context.newPage();
  const {api, auth, link} = await setupRepo(request, username);
  await openIDE(page, `${link}/-/ide/branch/main`);

  // someone else pushes while the IDE is open
  expect((await request.post(`${api}/contents/other.txt`, {headers: auth, data: {branch: 'main', message: 'other', content: btoa('other')}})).ok()).toBeTruthy();

  await editFile(page, 'alpha.txt', 'stale\n');
  await commit(page, 'Stale', /^Commit to main/);
  await expect(toast(page)).toContainText('main has new commits');
  await toast(page).getByRole('button', {name: 'Commit to a new branch'}).click();
  await page.locator('.monaco-dialog-box .monaco-button', {hasText: /^New branch$/}).click();
  await page.keyboard.press('Control+a');
  await page.keyboard.type('stale-branch');
  await page.keyboard.press('Enter');
  await expect(toast(page)).toContainText('Committed to stale-branch');
});

test('someone without write access can read but not commit', async ({browser, request}, workerInfo) => {
  const {username} = await create_temp_user(browser, workerInfo, request);
  const {link} = await setupRepo(request, username);
  const {context} = await create_temp_user(browser, workerInfo, request);
  const page = await context.newPage();

  await openIDE(page, `${link}/-/ide/branch/main/alpha.txt`);
  await expect(page.locator('.statusbar')).toContainText('Read-only');
  await expect(page.locator('.tab.active')).toContainText('alpha.txt');
  await page.keyboard.press('Control+Shift+G');
  await expect(page.locator('.scm-view .monaco-button', {hasText: 'Commit'})).toBeDisabled();
});
