// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// templates/admin/user_group/**
// templates/admin/navbar.tmpl
// templates/org/team/members.tmpl
// templates/org/team/membership_origin.tmpl
// templates/org/team/navbar.tmpl
// templates/org/team/teams.tmpl
// routers/web/admin/user_groups.go
// routers/web/org/teams.go
// services/usergroup/**
// models/organization/user_group.go
// web_src/js/features/org-team.js
// tests/e2e/shared/fake-data.ts
// @watch end

// Everything here is created from scratch by the administrator configured in
// E2E_ADMIN_USERNAME / E2E_ADMIN_PASSWORD (see shared/fake-data.ts), so the
// tests do not depend on the fixture data.

import {expect, type Page} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {FakeData, fakeName, loginAs, loginAsAdmin, repoPermissions, adminAuth, type FakeTeam} from './shared/fake-data.ts';

const teamURL = (team: FakeTeam) => `/org/${team.org}/teams/${team.name}`;

async function linkGroup(page: Page, team: FakeTeam, group: string) {
  await page.goto(teamURL(team));
  // type part of the name and pick the group from the suggestions
  await page.getByPlaceholder('User group name').fill(group.slice(0, -2));
  await page.locator('#search-user-group-box .results .result', {hasText: group}).click();
  await expect(page.getByPlaceholder('User group name')).toHaveValue(group);
  await page.getByRole('button', {name: 'Link user group'}).click();
  await expect(page.locator('#team-user-groups + .segment + .segment')).toContainText(group);
}

let data: FakeData;

test.beforeEach(({request}) => {
  data = new FakeData(request);
});

test.afterEach(async () => {
  await data.cleanup();
});

test('One user group grants access to teams of several organizations', async ({browser, request}) => {
  test.setTimeout(180000);

  // two users, and two private organizations with a read-only team on every
  // repository of the first and a write team on one repository of the second
  const alice = await data.createUser();
  const bob = await data.createUser();
  const orgA = await data.createOrg();
  const repoA = await data.createRepo(orgA);
  const orgB = await data.createOrg();
  const repoB1 = await data.createRepo(orgB);
  const repoB2 = await data.createRepo(orgB);
  const readers = await data.createTeam(orgA, 'read');
  const writers = await data.createTeam(orgB, 'write', [repoB1]);

  for (const user of [alice, bob]) {
    expect(await repoPermissions(request, user, orgA, repoA)).toBeNull();
    expect(await repoPermissions(request, user, orgB, repoB1)).toBeNull();
  }

  const admin = await (await loginAsAdmin(browser)).newPage();
  const group = fakeName('group');
  data.trackGroup(group);

  await test.step('create the user group', async () => {
    await admin.goto('/admin/groups');
    await admin.getByRole('link', {name: 'Create user group'}).click();
    await admin.getByLabel('Group name').fill(group);
    await admin.getByLabel('Description').fill('Created by the end-to-end tests');
    await admin.getByRole('button', {name: 'Create user group'}).click();
    await expect(admin.locator('.flash-success')).toContainText(`User group "${group}" has been created.`);
  });

  const groupURL = admin.url();

  await test.step('group names are unique', async () => {
    await admin.goto('/admin/groups/new');
    await admin.getByLabel('Group name').fill(group.toUpperCase());
    await admin.getByRole('button', {name: 'Create user group'}).click();
    await expect(admin.getByText('A user group with this name already exists.')).toBeVisible();
  });

  await test.step('add the users to the group', async () => {
    await admin.goto(groupURL);
    for (const user of [alice, bob]) {
      await admin.getByPlaceholder('Search users…').fill(user.username);
      await admin.getByRole('button', {name: 'Add member'}).click();
      await expect(admin.locator('.flash-success')).toContainText(`${user.username} has been added to the group.`);
    }
    await admin.getByPlaceholder('Search users…').fill(orgA);
    await admin.getByRole('button', {name: 'Add member'}).click();
    await expect(admin.locator('.flash-error')).toContainText('An organization cannot be a member of a user group.');

    const members = admin.locator('#user-group-members + .segment + .segment');
    await expect(members).toContainText(alice.username);
    await expect(members).toContainText(bob.username);
    await expect(members).not.toContainText(orgA);
  });

  await test.step('link the group to a team in each organization', async () => {
    for (const team of [readers, writers]) {
      await linkGroup(admin, team, group);
      await expect(admin.locator('#team-user-groups + .segment + .segment .flex-item', {hasText: group})).toContainText(`${group} · 2 members`);
      await expect(admin.locator('.org-team-navbar')).toContainText('1 user group');
      for (const user of [alice, bob]) {
        const row = admin.locator('.flex-item', {hasText: user.username});
        await expect(row).toContainText(`joined via ${group} on`);
        // site admins get a link to the group
        await expect(row.getByRole('link', {name: group})).toHaveAttribute('href', new URL(groupURL).pathname);
        // a member coming from a group can only be removed through the group
        await expect(row.getByRole('button', {name: 'Remove'})).toHaveCount(0);
      }
    }

    await admin.goto(`/org/${readers.org}/teams`);
    await expect(admin.locator('.team-meta', {has: admin.locator(`a[href$="/teams/${readers.name}"]`)})).toContainText('· 1 user group');

    await admin.goto(groupURL);
    const linkedTeams = admin.locator('#user-group-teams + .segment');
    await expect(linkedTeams.getByRole('link', {name: readers.name})).toBeVisible();
    await expect(linkedTeams.getByRole('link', {name: writers.name})).toBeVisible();
  });

  await test.step('members get exactly the access of the linked teams', async () => {
    for (const user of [alice, bob]) {
      expect(await repoPermissions(request, user, orgA, repoA)).toMatchObject({pull: true, push: false});
      expect(await repoPermissions(request, user, orgB, repoB1)).toMatchObject({pull: true, push: true});
      expect(await repoPermissions(request, user, orgB, repoB2)).toBeNull();
    }

    const alicePage = await (await loginAs(browser, alice.username, alice.password)).newPage();
    expect((await alicePage.goto(`/${orgA}/${repoA}`))?.status()).toBe(200);
    expect((await alicePage.goto(`/${orgB}/${repoB1}`))?.status()).toBe(200);
    expect((await alicePage.goto(`/${orgB}/${repoB2}`))?.status()).toBe(404);
    await alicePage.context().close();
  });

  await test.step('removing a member from the group revokes their access everywhere', async () => {
    await admin.goto(groupURL);
    await admin.locator('.flex-item', {hasText: bob.username}).getByRole('button', {name: 'Remove'}).click();
    await expect(admin.locator('.flash-success')).toContainText('The member has been removed from the group.');

    expect(await repoPermissions(request, bob, orgA, repoA)).toBeNull();
    expect(await repoPermissions(request, bob, orgB, repoB1)).toBeNull();
    expect(await repoPermissions(request, alice, orgA, repoA)).not.toBeNull();
  });

  await test.step('unlinking the group from a team revokes the access of that team only', async () => {
    await admin.goto(teamURL(readers));
    await admin.locator('#team-user-groups + .segment + .segment .flex-item', {hasText: group}).getByRole('button', {name: 'Unlink'}).click();
    await expect(admin.locator('#team-user-groups + .segment + .segment')).toContainText('No user groups are linked to this team.');
    await expect(admin.locator('.flex-item', {hasText: alice.username})).toHaveCount(0);

    expect(await repoPermissions(request, alice, orgA, repoA)).toBeNull();
    expect(await repoPermissions(request, alice, orgB, repoB1)).toMatchObject({pull: true, push: true});
  });

  const renamed = fakeName('group');

  await test.step('rename the group', async () => {
    await admin.goto(groupURL);
    await admin.getByLabel('Group name').fill(renamed);
    await admin.getByRole('button', {name: 'Update user group'}).click();
    await expect(admin.locator('.flash-success')).toContainText('User group has been updated.');
    data.trackGroup(renamed);

    await admin.goto(teamURL(writers));
    await expect(admin.locator('#team-user-groups + .segment + .segment')).toContainText(renamed);
  });

  await test.step('deleting the group revokes the remaining access', async () => {
    await admin.goto(groupURL);
    await admin.getByRole('button', {name: 'Delete user group'}).click();
    await admin.locator('#delete-user-group').getByRole('button', {name: 'Yes'}).click();
    await expect(admin).toHaveURL(/\/admin\/groups$/);
    await expect(admin.locator('.flash-success')).toContainText(`User group "${renamed}" has been deleted.`);

    expect(await repoPermissions(request, alice, orgB, repoB1)).toBeNull();
    await admin.goto(teamURL(writers));
    await expect(admin.locator('.flex-item', {hasText: alice.username})).toHaveCount(0);
  });
});

test('Only site administrators manage user groups and only owners link them', async ({browser, request}) => {
  test.setTimeout(120000);

  // carol is a direct member of a team, but neither a site administrator nor an organization owner
  const carol = await data.createUser();
  const org = await data.createOrg();
  const team = await data.createTeam(org, 'read');
  const added = await request.put(`/api/v1/teams/${team.id}/members/${carol.username}`, {headers: adminAuth()});
  expect(added.status()).toBe(204);

  const group = fakeName('group');
  const created = await request.post('/api/v1/admin/groups', {headers: adminAuth(), data: {name: group}});
  expect(created.status()).toBe(201);
  data.trackGroup(group);
  const linked = await request.put(`/api/v1/teams/${team.id}/groups/${group}`, {headers: adminAuth()});
  expect(linked.status()).toBe(204);

  const page = await (await loginAs(browser, carol.username, carol.password)).newPage();

  // the administration pages are refused
  for (const url of ['/admin/groups', '/admin/groups/new']) {
    expect((await page.goto(url))?.status(), url).toBe(403);
  }

  // the team page lists the linked group, without the controls to change it
  expect((await page.goto(teamURL(team)))?.status()).toBe(200);
  await expect(page.locator('#team-user-groups + .segment')).toContainText(group);
  await expect(page.getByPlaceholder('User group name')).toHaveCount(0);
  await expect(page.getByRole('button', {name: 'Link user group'})).toHaveCount(0);
  await expect(page.getByRole('button', {name: 'Unlink'})).toHaveCount(0);

  // and the group search used by the link form is refused
  expect((await page.goto(`${teamURL(team)}/groups/search?q=${group}`))?.status()).toBe(404);
});

test('Switching off a role a group grants asks first', async ({browser, request}) => {
  const erin = await data.createUser();
  const group = fakeName('group');
  const created = await request.post('/api/v1/admin/groups', {headers: adminAuth(), data: {name: group, grants_site_admin: true}});
  expect(created.status()).toBe(201);
  data.trackGroup(group);
  expect((await request.put(`/api/v1/admin/groups/${group}/members/${erin.username}`, {headers: adminAuth()})).status()).toBe(204);

  const admin = await (await loginAsAdmin(browser)).newPage();
  await admin.goto('/admin/groups');
  await admin.getByRole('link', {name: group}).click();
  await admin.getByText('Members are site administrators', {exact: true}).click();
  await expect(admin.locator('input[name="grants_site_admin"]')).not.toBeChecked();
  await admin.getByRole('button', {name: 'Update user group'}).click();

  const warning = admin.locator('.user-group-role-loss');
  await expect(warning).toBeVisible();
  await expect(warning).toContainText('1 member will lose site administrator rights');
  await admin.getByRole('link', {name: 'Cancel'}).click();
  await expect(admin.locator('input[name="grants_site_admin"]')).toBeChecked();
  await expect(warning).toHaveCount(0);
});

test('Switching off the auditor grant asks first', async ({browser, request}) => {
  const erin = await data.createUser();
  const group = fakeName('group');
  const created = await request.post('/api/v1/admin/groups', {headers: adminAuth(), data: {name: group, grants_auditor: true}});
  expect(created.status()).toBe(201);
  data.trackGroup(group);
  expect((await request.put(`/api/v1/admin/groups/${group}/members/${erin.username}`, {headers: adminAuth()})).status()).toBe(204);

  const admin = await (await loginAsAdmin(browser)).newPage();
  await admin.goto('/admin/groups');
  await admin.getByRole('link', {name: group}).click();
  const auditor = admin.locator('input[name="grants_auditor"]');
  await expect(auditor).toBeChecked();

  // the delete modal names what deleting the group takes away
  await admin.locator('button.delete-button').click();
  const modal = admin.locator('#delete-user-group');
  await expect(modal).toContainText('1 member will lose auditor access.');
  await modal.getByRole('button', {name: 'No'}).click();
  await expect(modal).toBeHidden();

  await admin.getByText('Members are auditors (read all)', {exact: true}).click();
  await expect(auditor).not.toBeChecked();
  await admin.getByRole('button', {name: 'Update user group'}).click();

  const warning = admin.locator('.user-group-role-loss');
  await expect(warning).toBeVisible();
  await expect(warning).toContainText('1 member will lose auditor access.');
  await admin.getByRole('link', {name: 'Cancel'}).click();
  await expect(auditor).toBeChecked();
  await expect(warning).toHaveCount(0);

  // confirming turns the grant off
  await admin.getByText('Members are auditors (read all)', {exact: true}).click();
  await admin.getByRole('button', {name: 'Update user group'}).click();
  await expect(warning).toBeVisible();
  await admin.getByRole('button', {name: 'Update anyway'}).click();
  await expect(admin.locator('input[name="grants_auditor"]')).not.toBeChecked();
  await expect(warning).toHaveCount(0);
});
