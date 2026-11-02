// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// @watch start
// routers/api/v1/admin/user_group.go
// routers/api/v1/org/team_user_group.go
// routers/api/v1/org/team.go
// services/usergroup/**
// services/convert/user_group.go
// models/organization/user_group.go
// tests/e2e/shared/fake-data.ts
// @watch end

// Drives user groups through the REST API only. Everything is created from
// scratch by the administrator configured in E2E_ADMIN_USERNAME /
// E2E_ADMIN_PASSWORD (see shared/fake-data.ts).

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {FakeData, fakeName, repoPermissions, adminAuth, basicAuth} from './shared/fake-data.ts';

let data: FakeData;

test.beforeEach(({request}) => {
  data = new FakeData(request);
});

test.afterEach(async () => {
  await data.cleanup();
});

test('User groups through the API', async ({request}) => {
  test.setTimeout(120000);
  const admin = adminAuth();

  // dave owns an organization with two private repositories and a write team on one of them
  const dave = await data.createUser();
  const erin = await data.createUser();
  const frank = await data.createUser();
  const org = await data.createOrg(dave);
  const repo = await data.createRepo(org);
  const otherRepo = await data.createRepo(org);
  const team = await data.createTeam(org, 'write', [repo]);
  const daveAuth = basicAuth(dave.username, dave.password);
  const erinAuth = basicAuth(erin.username, erin.password);

  const group = fakeName('group');
  const groupURL = `/api/v1/admin/groups/${group}`;
  data.trackGroup(group);

  await test.step('create, find and edit the group', async () => {
    let response = await request.post('/api/v1/admin/groups', {headers: admin, data: {name: group, description: 'API group'}});
    expect(response.status()).toBe(201);
    expect(await response.json()).toMatchObject({name: group, description: 'API group', members_count: 0, teams_count: 0});

    response = await request.post('/api/v1/admin/groups', {headers: admin, data: {name: group.toUpperCase()}});
    expect(response.status()).toBe(409);
    response = await request.post('/api/v1/admin/groups', {headers: admin, data: {name: 'not valid!'}});
    expect(response.status()).toBe(422);

    response = await request.get(`/api/v1/admin/groups?q=${group}`, {headers: admin});
    expect(response.status()).toBe(200);
    expect((await response.json()).map((g: {name: string}) => g.name)).toEqual([group]);
    expect(response.headers()['x-total-count']).toBe('1');

    response = await request.patch(groupURL, {headers: admin, data: {description: 'Edited through the API'}});
    expect(response.status()).toBe(200);
    expect((await response.json()).description).toBe('Edited through the API');
  });

  await test.step('only site administrators manage groups', async () => {
    expect((await request.get('/api/v1/admin/groups', {headers: daveAuth})).status()).toBe(403);
    expect((await request.post('/api/v1/admin/groups', {headers: daveAuth, data: {name: fakeName('group')}})).status()).toBe(403);
    expect((await request.put(`${groupURL}/members/${dave.username}`, {headers: daveAuth})).status()).toBe(403);
  });

  await test.step('add members', async () => {
    for (const user of [erin, frank]) {
      expect((await request.put(`${groupURL}/members/${user.username}`, {headers: admin})).status()).toBe(204);
    }
    // adding again is a no-op, organizations and unknown users are refused
    expect((await request.put(`${groupURL}/members/${erin.username}`, {headers: admin})).status()).toBe(204);
    expect((await request.put(`${groupURL}/members/${org}`, {headers: admin})).status()).toBe(422);
    expect((await request.put(`${groupURL}/members/${fakeName('nobody')}`, {headers: admin})).status()).toBe(404);

    const response = await request.get(`${groupURL}/members`, {headers: admin});
    const members = (await response.json()).map((u: {login: string}) => u.login).sort();
    expect(members).toEqual([erin.username, frank.username].sort());
    expect(response.headers()['x-total-count']).toBe('2');
  });

  await test.step('the organization owner links the group to a team', async () => {
    // erin is in the group but not an owner: she cannot link it
    expect((await request.put(`/api/v1/teams/${team.id}/groups/${group}`, {headers: erinAuth})).status()).toBe(404);
    expect((await request.put(`/api/v1/teams/${team.id}/groups/${fakeName('missing')}`, {headers: daveAuth})).status()).toBe(404);

    expect((await request.put(`/api/v1/teams/${team.id}/groups/${group}`, {headers: daveAuth})).status()).toBe(204);
    expect((await request.put(`/api/v1/teams/${team.id}/groups/${group}`, {headers: daveAuth})).status()).toBe(204);

    const linked = await (await request.get(`/api/v1/teams/${team.id}/groups`, {headers: daveAuth})).json();
    expect(linked).toHaveLength(1);
    expect(linked[0]).toMatchObject({name: group, members_count: 2, teams_count: 1});

    const teams = await (await request.get(`${groupURL}/teams`, {headers: admin})).json();
    expect(teams).toHaveLength(1);
    expect(teams[0].name).toBe(team.name);
    expect(teams[0].organization.username).toBe(org);
  });

  await test.step('members get the access of the team', async () => {
    for (const user of [erin, frank]) {
      expect(await repoPermissions(request, user, org, repo)).toMatchObject({pull: true, push: true});
      expect(await repoPermissions(request, user, org, otherRepo)).toBeNull();
    }
    const members = await (await request.get(`/api/v1/teams/${team.id}/members`, {headers: daveAuth})).json();
    expect(members.map((u: {login: string}) => u.login)).toEqual(expect.arrayContaining([erin.username, frank.username]));
  });

  await test.step('a member coming from the group cannot be removed from the team directly', async () => {
    const response = await request.delete(`/api/v1/teams/${team.id}/members/${erin.username}`, {headers: daveAuth});
    expect(response.status()).toBe(422);
    expect(await repoPermissions(request, erin, org, repo)).not.toBeNull();
  });

  await test.step('removing a member from the group revokes their access', async () => {
    expect((await request.delete(`${groupURL}/members/${frank.username}`, {headers: admin})).status()).toBe(204);
    expect((await request.delete(`${groupURL}/members/${frank.username}`, {headers: admin})).status()).toBe(404);
    expect(await repoPermissions(request, frank, org, repo)).toBeNull();
    expect(await repoPermissions(request, erin, org, repo)).not.toBeNull();
  });

  await test.step('unlinking the group revokes the access of its members', async () => {
    expect((await request.delete(`/api/v1/teams/${team.id}/groups/${group}`, {headers: erinAuth})).status()).toBe(404);
    expect((await request.delete(`/api/v1/teams/${team.id}/groups/${group}`, {headers: daveAuth})).status()).toBe(204);
    expect((await request.delete(`/api/v1/teams/${team.id}/groups/${group}`, {headers: daveAuth})).status()).toBe(404);
    expect(await repoPermissions(request, erin, org, repo)).toBeNull();
  });

  await test.step('delete the group', async () => {
    expect((await request.delete(groupURL, {headers: admin})).status()).toBe(204);
    expect((await request.get(groupURL, {headers: admin})).status()).toBe(404);
  });
});
