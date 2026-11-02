// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Creates throwaway users, organizations, repositories and teams through the
// API, authenticated as a site administrator, so a test does not depend on
// the fixture data and can run against any Forgejo instance.
//
// The administrator account comes from the environment:
//   E2E_ADMIN_USERNAME (default: user1, the administrator of the test fixtures)
//   E2E_ADMIN_PASSWORD (default: password)
// and the instance from GITEA_URL (see playwright.config.ts).

import {Buffer} from 'node:buffer';
import {expect, type APIRequestContext, type Browser, type BrowserContext} from '@playwright/test';
import {test_context} from '../utils_e2e.ts';

export const ADMIN_USERNAME = process.env.E2E_ADMIN_USERNAME || 'user1';
export const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'password';

// Credentials are encoded as UTF-8, like the sign-in form sends them: btoa()
// only handles Latin-1 and would break on passwords such as "pässwörd€".
export function basicAuth(username: string, password: string) {
  return {Authorization: `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`};
}

export const adminAuth = () => basicAuth(ADMIN_USERNAME, ADMIN_PASSWORD);

// a short random name that is valid for users, organizations, teams, repositories and user groups
export function fakeName(prefix: string) {
  return `${prefix}-${globalThis.crypto.randomUUID().slice(0, 8)}`;
}

export type FakeUser = {username: string, password: string};
export type FakeTeam = {id: number, name: string, org: string};

async function ok(response: Awaited<ReturnType<APIRequestContext['get']>>, what: string) {
  expect(response.ok(), `${what}: ${response.status()} ${await response.text()}`).toBeTruthy();
  return response.status() === 204 ? null : response.json();
}

// Tracks what a test created, so that it can be removed afterwards.
export class FakeData {
  private users: string[] = [];
  private orgs: string[] = [];
  private repos: string[] = [];
  private groups: string[] = [];
  private announcements: number[] = [];

  constructor(private request: APIRequestContext) {}

  async createUser(): Promise<FakeUser> {
    // non-ASCII characters so that every login and API call checks they are encoded correctly
    const user = {username: fakeName('user'), password: `pässwörd€-${globalThis.crypto.randomUUID()}`};
    await ok(await this.request.post('/api/v1/admin/users', {
      headers: adminAuth(),
      data: {
        username: user.username,
        email: `${user.username}@example.invalid`,
        password: user.password,
        must_change_password: false,
      },
    }), `create user ${user.username}`);
    this.users.push(user.username);
    return user;
  }

  // Creates an organization owned by `owner`, or by the administrator when no owner is given.
  async createOrg(owner?: FakeUser): Promise<string> {
    const name = fakeName('org');
    const url = owner ? `/api/v1/admin/users/${owner.username}/orgs` : '/api/v1/orgs';
    await ok(await this.request.post(url, {
      headers: adminAuth(),
      data: {username: name, visibility: 'private'},
    }), `create organization ${name}`);
    this.orgs.push(name);
    return name;
  }

  async createRepo(org: string): Promise<string> {
    const name = fakeName('repo');
    await ok(await this.request.post(`/api/v1/orgs/${org}/repos`, {
      headers: adminAuth(),
      data: {name, private: true, auto_init: true},
    }), `create repository ${org}/${name}`);
    this.repos.push(`${org}/${name}`);
    return name;
  }

  // Creates a team. Without `repos`, the team covers all repositories of the organization.
  async createTeam(org: string, permission: 'read' | 'write' | 'admin', repos?: string[]): Promise<FakeTeam> {
    const name = fakeName('team');
    const units = ['repo.code', 'repo.issues', 'repo.pulls', 'repo.releases', 'repo.wiki'];
    const team = await ok(await this.request.post(`/api/v1/orgs/${org}/teams`, {
      headers: adminAuth(),
      data: {
        name,
        permission,
        includes_all_repositories: !repos,
        units_map: Object.fromEntries(units.map((unit) => [unit, permission])),
      },
    }), `create team ${org}/${name}`);
    for (const repo of repos ?? []) {
      await ok(await this.request.put(`/api/v1/teams/${team.id}/repos/${org}/${repo}`, {headers: adminAuth()}),
        `add ${org}/${repo} to team ${name}`);
    }
    return {id: team.id, name, org};
  }

  // Remembers a user group created by the test through the UI, so that it is deleted afterwards.
  trackGroup(name: string) {
    this.groups.push(name);
  }

  // Remembers an announcement created by the test through the UI, so that it is deleted afterwards.
  trackAnnouncement(id: number) {
    this.announcements.push(id);
  }

  async cleanup() {
    const headers = adminAuth();
    for (const id of this.announcements) await this.request.delete(`/api/v1/admin/announcements/${id}`, {headers});
    for (const group of this.groups) await this.request.delete(`/api/v1/admin/groups/${group}`, {headers});
    for (const repo of this.repos) await this.request.delete(`/api/v1/repos/${repo}`, {headers});
    for (const org of this.orgs) await this.request.delete(`/api/v1/orgs/${org}`, {headers});
    for (const user of this.users) await this.request.delete(`/api/v1/admin/users/${user}?purge=true`, {headers});
  }
}

// Logs in through the sign-in form and returns the browser context of the session.
export async function loginAs(browser: Browser, username: string, password: string): Promise<BrowserContext> {
  const context = await test_context(browser);
  const page = await context.newPage();
  await page.goto('/user/login');
  await page.fill('input[name=user_name]', username);
  await page.fill('input[name=password]', password);
  await page.click('form button.ui.primary.button:visible');
  await expect(page.locator('.flash-error')).toHaveCount(0);
  await expect(page).not.toHaveURL(/\/user\/login/);
  await page.close();
  return context;
}

export const loginAsAdmin = (browser: Browser) => loginAs(browser, ADMIN_USERNAME, ADMIN_PASSWORD);

// The permissions a user has on a repository, as seen through the API. A
// repository the user cannot see returns null.
export async function repoPermissions(request: APIRequestContext, user: FakeUser, org: string, repo: string) {
  const response = await request.get(`/api/v1/repos/${org}/${repo}`, {headers: basicAuth(user.username, user.password)});
  if (response.status() === 404) return null;
  expect(response.ok(), `get ${org}/${repo} as ${user.username}: ${response.status()}`).toBeTruthy();
  return (await response.json()).permissions as {admin: boolean, push: boolean, pull: boolean};
}
