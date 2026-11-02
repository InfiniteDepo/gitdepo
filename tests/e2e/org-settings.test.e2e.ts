// @watch start
// templates/org/settings/options.tmpl
// templates/org/team/new.tmpl
// templates/org/settings/repos.tmpl
// templates/org/settings/verified_domains.tmpl
// templates/org/header.tmpl
// web_src/css/form.css
// web_src/js/features/org-team.js
// web_src/js/features/tablesort.js
// @watch end

import {expect} from '@playwright/test';
import {test} from './utils_e2e.ts';
import {screenshot} from './shared/screenshots.ts';
import {validate_form} from './shared/forms.ts';
import {FakeData, loginAs, loginAsAdmin} from './shared/fake-data.ts';

test.use({user: 'user2'});

test('org team settings', async ({page}) => {
  const response = await page.goto('/org/org3/teams/team1/edit');
  expect(response?.status()).toBe(200);

  await page.locator('input[name="permission"][value="admin"]').click();
  await expect(page.locator('.hide-unless-checked')).toBeHidden();
  await screenshot(page);

  await page.locator('input[name="permission"][value="read"]').click();
  await expect(page.locator('.hide-unless-checked')).toBeVisible();
  await screenshot(page);

  // we are validating the form here to include the part that could be hidden
  await validate_form({page});
});

test('org add and remove team repositories', async ({page}) => {
  const response = await page.goto('/org/org3/teams/team1/repositories');
  expect(response?.status()).toBe(200);

  // As this is a shared state between multiple runs, always add repo3 to have some initial state.
  await page.getByPlaceholder('Search repos…').fill('repo3');
  await page.getByRole('button', {name: 'Add', exact: true}).click();
  await expect(page.getByText('org3/repo3')).toBeVisible();

  // Open remove all dialog.
  await page.getByRole('button', {name: 'Remove all'}).click();
  await expect(page.locator('#removeall-repos-modal')).toBeVisible();
  await screenshot(page, page.locator('#removeall-repos-modal'));
  // Remove all repositories.
  await page.getByRole('button', {name: 'Yes'}).click();

  // Check that all repositories are removed.
  await expect(page.getByText('No repositories could be accessed by this team.')).toBeVisible();

  // Open add all dialog.
  await page.getByRole('button', {name: 'Add all'}).click();
  await expect(page.locator('#addall-repos-modal')).toBeVisible();
  await screenshot(page, page.locator('#addall-repos-modal'));
  // Add all repositories.
  await page.getByRole('button', {name: 'Yes'}).click();

  // Check that there are three repositories.
  await expect(page.getByText('No repositories could be accessed by this team.')).toBeHidden();
  await expect(page.getByText('org3/repo3')).toBeVisible();
  await expect(page.getByText('org3/repo21')).toBeVisible();
  await expect(page.getByText('org3/repo5')).toBeVisible();
});

test('org settings repositories list sorting', async ({page}) => {
  const response = await page.goto('/org/org3/settings/repos');
  expect(response?.status()).toBe(200);

  // other specs seed more repositories in org3 (secret-lists-*), so only the fixture repositories are compared
  const names = page.locator('table tbody tr td:first-child a', {hasText: /^repo\d+$/});
  await expect(names).toHaveCount(3);

  // Clicking the name header sorts ascending, a second click reverses the order.
  await page.locator('th[data-sortt-asc="alphabetically"]').click();
  await page.waitForURL(/sort=alphabetically/);
  await expect(names).toHaveText(['repo21', 'repo3', 'repo5']);
  await screenshot(page);

  await page.locator('th[data-sortt-asc="alphabetically"]').click();
  await page.waitForURL(/sort=reversealphabetically/);
  await expect(names).toHaveText(['repo5', 'repo3', 'repo21']);

  // The size columns cannot change the order of the all-zero-sized fixture
  // repositories, but clicking them must still update the sort parameter.
  await page.locator('th[data-sortt-asc="gitsize"]').click();
  await page.waitForURL(/sort=gitsize/);
  await page.locator('th[data-sortt-asc="gitsize"]').click();
  await page.waitForURL(/sort=reversegitsize/);

  await page.locator('th[data-sortt-asc="lfssize"]').click();
  await page.waitForURL(/sort=lfssize/);
  await page.locator('th[data-sortt-asc="lfssize"]').click();
  await page.waitForURL(/sort=reverselfssize/);
  await expect(names).toHaveCount(3);
});

test('org requires two-factor authentication only from an owner who has it', async ({page}) => {
  const response = await page.goto('/org/org3/settings');
  expect(response?.status()).toBe(200);

  const checkbox = page.locator('input[name="require_two_factor"]');
  await expect(checkbox).not.toBeChecked();
  await checkbox.check();
  await page.getByRole('button', {name: 'Update settings'}).click();

  // user2 has no two-factor authentication: nothing is saved, the form keeps the choice
  await expect(page.locator('.flash-error')).toContainText('you must enable two-factor authentication');
  await expect(page.locator('input[name="require_two_factor"]')).toBeChecked();
  await screenshot(page);
  await page.goto('/org/org3/settings');
  await expect(page.locator('input[name="require_two_factor"]')).not.toBeChecked();
});

test.describe('as fake users', () => {
  // a clean state, so that loginAs doesn't inherit user2's session
  test.use({user: null, storageState: {cookies: [], origins: []}});

  test('org repository policies persist', async ({browser, request}) => {
    const data = new FakeData(request);
    try {
      const owner = await data.createUser();
      const org = await data.createOrg(owner);
      const page = await (await loginAs(browser, owner.username, owner.password)).newPage();
      await page.goto(`/org/${org}/settings`);

      const visibility = page.locator('input[name="restrict_repo_visibility_change"]');
      const forks = page.locator('select[name="private_fork_policy"]');
      await expect(visibility).not.toBeChecked();
      await expect(forks).toHaveValue('0');
      await expect(page.locator('#repo_policies_box')).toContainText('Only organization owners can delete or transfer repositories.');
      await visibility.check();
      await forks.selectOption('2');
      await page.getByRole('button', {name: 'Update settings'}).click();
      await expect(page.locator('.flash-success')).toBeVisible();

      await page.goto(`/org/${org}/settings`);
      await expect(visibility).toBeChecked();
      await expect(forks).toHaveValue('2');
      await screenshot(page);
    } finally {
      await data.cleanup();
    }
  });

  test('org verified domain', async ({browser, request}) => {
    const data = new FakeData(request);
    try {
      const owner = await data.createUser();
      const org = await data.createOrg(owner);
      const domain = `${org.toLowerCase()}.example`;
      const page = await (await loginAs(browser, owner.username, owner.password)).newPage();
      await page.goto(`/org/${org}/settings/verified_domains`);
      await expect(page.getByText('No verified domains yet.')).toBeVisible();
      await expect(page.locator('#require-verified-domain')).toBeDisabled();
      await screenshot(page);

      // adding a domain shows the DNS record to publish
      await page.getByRole('textbox', {name: 'Domain'}).fill(domain.toUpperCase());
      await page.getByRole('button', {name: 'Add domain'}).click();
      const pending = page.locator('#verified-domain-pending');
      await expect(pending).toContainText(`_gitdepo-verify.${domain}`);
      await expect(pending).toContainText('gitdepo-verification=');
      await expect(pending.getByRole('button', {name: 'Verify without DNS'})).toHaveCount(0);
      await screenshot(page);

      // a site administrator verifies it without DNS
      const admin = await (await loginAsAdmin(browser)).newPage();
      await admin.goto(`/org/${org}/settings/verified_domains?domain=${domain}`);
      await admin.getByRole('button', {name: 'Verify without DNS'}).click();
      await expect(admin.locator('.flash-success')).toContainText(`The domain ${domain} is verified.`);
      await expect(admin.locator('.flex-list')).toContainText('by a site administrator');

      await page.goto(`/org/${org}/settings/verified_domains`);
      await expect(page.locator('.flex-list')).toContainText(domain);
      await screenshot(page);

      await page.goto(`/${org}`);
      await expect(page.locator('.org-verified-domain')).toHaveText(`Verified: ${domain}`);
      await screenshot(page, page.locator('#org-info'));
    } finally {
      await data.cleanup();
    }
  });
});
