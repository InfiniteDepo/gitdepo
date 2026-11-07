// Copyright 2024 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT
import {flushPromises, mount} from '@vue/test-utils';
import PullRequestMergeForm from './PullRequestMergeForm.vue';

async function renderMergeForm(branchName, extra = {}) {
  window.config.pageData.pullRequestMergeForm = {
    textDeleteBranch: `Delete branch "${branchName}"`,
    textDoMerge: 'Merge',
    defaultMergeStyle: 'merge',
    isPullBranchDeletable: true,
    canMergeNow: true,
    mergeStyles: [{
      'name': 'merge',
      'allowed': true,
      'textDoMerge': 'Merge',
      'mergeTitleFieldText': 'Merge PR',
      'mergeMessageFieldText': 'Description',
      'hideAutoMerge': 'Hide this message',
    }],
    ...extra,
  };
  const mergeform = mount(PullRequestMergeForm);
  mergeform.get('.merge-button').trigger('click');
  await flushPromises();
  return mergeform;
}

test('renders escaped branch name', async () => {
  let mergeform = await renderMergeForm('<b>evil</b>');
  expect(mergeform.get('label[for="delete-branch-after-merge"]').text()).toBe('Delete branch "<b>evil</b>"');

  mergeform = await renderMergeForm('<script class="evil">alert("evil message");</script>');
  expect(mergeform.get('label[for="delete-branch-after-merge"]').text()).toBe('Delete branch "<script class="evil">alert("evil message");</script>"');
});

test('delete branch checkbox follows the configured default', async () => {
  let mergeform = await renderMergeForm('feature', {defaultDeleteBranchAfterMerge: false});
  expect(mergeform.get('#delete-branch-after-merge').element.checked).toBe(false);
  expect(mergeform.get('#delete-branch-after-merge').element.disabled).toBe(false);

  mergeform = await renderMergeForm('feature', {defaultDeleteBranchAfterMerge: true});
  expect(mergeform.get('#delete-branch-after-merge').element.checked).toBe(true);
  expect(mergeform.get('#delete-branch-after-merge').element.disabled).toBe(false);
  await mergeform.get('#delete-branch-after-merge').setValue(false);
  expect(mergeform.get('#delete-branch-after-merge').element.checked).toBe(false);
});

test('delete branch checkbox is ticked and disabled with an explanation when forced', async () => {
  const mergeform = await renderMergeForm('feature', {
    defaultDeleteBranchAfterMerge: true,
    deleteBranchForced: true,
    textDeleteBranchForced: 'Set by organization org3',
  });
  const checkbox = mergeform.get('#delete-branch-after-merge');
  expect(checkbox.element.checked).toBe(true);
  expect(checkbox.element.disabled).toBe(true);
  expect(mergeform.get('.delete-branch-forced').text()).toBe('Set by organization org3');
});

test('hides merge controls when no merge style is allowed', () => {
  window.config.pageData.pullRequestMergeForm = {
    textDeleteBranch: 'Delete branch',
    textAutoMergeButtonWhenSucceed: 'when checks succeed',
    textAutoMergeWhenSucceed: 'Auto merge when checks succeed',
    textAutoMergeCancelSchedule: 'Cancel schedule',
    textCancel: 'Cancel',
    defaultDeleteBranchAfterMerge: false,
    defaultMergeMessage: '',
    defaultMergeStyle: 'merge',
    emptyCommit: false,
    hasPendingPullRequestMerge: false,
    hasPendingPullRequestMergeTip: '',
    isPullBranchDeletable: false,
    canMergeNow: true,
    allOverridableChecksOk: true,
    pullHeadCommitID: 'abc123',
    mergeStyles: [{
      name: 'merge',
      allowed: false,
      textDoMerge: 'Merge',
      mergeTitleFieldText: '',
      mergeMessageFieldText: '',
      hideAutoMerge: false,
    }],
  };

  const mergeform = mount(PullRequestMergeForm);
  expect(mergeform.find('.merge-button').exists()).toBe(false);
  expect(mergeform.find('form.form-fetch-action').exists()).toBe(false);
});

test('shows merge styles dropdown when multiple merge styles are allowed', async () => {
  window.config.pageData.pullRequestMergeForm = {
    textAutoMergeButtonWhenSucceed: '(When checks succeed)',
    textAutoMergeWhenSucceed: 'Auto merge when all checks succeed',
    textAutoMergeCancelSchedule: 'Cancel auto merge',
    canMergeNow: true,
    defaultMergeStyle: 'merge',
    hasPendingPullRequestMerge: false,
    mergeStyles: [
      {
        name: 'merge',
        allowed: true,
        textDoMerge: 'Create merge commit',
        mergeTitleFieldText: '',
        mergeMessageFieldText: '',
        hideAutoMerge: false,
      },
      {
        name: 'rebase',
        allowed: true,
        textDoMerge: 'Rebase then fast-forward',
        mergeTitleFieldText: '',
        mergeMessageFieldText: '',
        hideAutoMerge: false,
      },
    ],
  };

  const mergeform = mount(PullRequestMergeForm);
  await flushPromises();
  const mergeBtn = '.merge-button .ui.button .button-text';
  expect(mergeform.find(mergeBtn).exists()).toBe(true);
  expect(mergeform.find(mergeBtn).text()).toBe('Create merge commit');
  expect(mergeform.find('.merge-button .single-merge-strategy-auto-merge-btn').exists()).toBe(false);
  expect(mergeform.find('.merge-button .ui.dropdown .menu').exists()).toBe(true);
  expect(mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(1)').exists()).toBe(true);
  expect(mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(1) .action-text').text()).toBe('Create merge commit');
  expect(mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(1) .auto-merge-small').text()).toBe('Auto merge when all checks succeed');
  expect(mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(2)').exists()).toBe(true);
  expect(mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(2) .action-text').text()).toBe('Rebase then fast-forward');
  expect(mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(2) .auto-merge-small').text()).toBe('Auto merge when all checks succeed');

  await mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(2)').trigger('click');
  expect(mergeform.find(mergeBtn).text()).toBe('Rebase then fast-forward');

  await mergeform.find('.merge-button .ui.dropdown .menu .item:nth-of-type(1) .auto-merge-small').trigger('click');
  expect(mergeform.find(mergeBtn).text()).toBe('Create merge commit (When checks succeed)');
});

test('shows auto merge button when a single merge style is allowed', async () => {
  window.config.pageData.pullRequestMergeForm = {
    textAutoMergeButtonWhenSucceed: '(When checks succeed)',
    textAutoMergeWhenSucceed: 'Auto merge when all checks succeed',
    textAutoMergeCancelSchedule: 'Cancel auto merge',
    canMergeNow: true,
    defaultMergeStyle: 'merge',
    hasPendingPullRequestMerge: false,
    mergeStyles: [
      {
        name: 'merge',
        allowed: true,
        textDoMerge: 'Create merge commit',
        mergeTitleFieldText: '',
        mergeMessageFieldText: '',
        hideAutoMerge: false,
      },
    ],
  };

  const mergeform = mount(PullRequestMergeForm);
  await flushPromises();
  const mergeBtn = '.merge-button .ui.button .button-text';
  expect(mergeform.find(mergeBtn).exists()).toBe(true);
  expect(mergeform.find(mergeBtn).text()).toBe('Create merge commit');
  expect(mergeform.find('.merge-button .ui.dropdown .menu').exists()).toBe(false);
  const autoMergeBtn = '.merge-button .single-merge-strategy-auto-merge-btn';
  expect(mergeform.find(autoMergeBtn).exists()).toBe(true);
  const tooltip = '.merge-button .single-merge-strategy-auto-merge-btn .single-merge-strategy-auto-merge-tooltip';
  expect(mergeform.find(tooltip).exists()).toBe(true);
  expect(mergeform.find(tooltip).text()).toBe('Auto merge when all checks succeed');

  await mergeform.find(autoMergeBtn).trigger('click');
  expect(mergeform.find(mergeBtn).text()).toBe('Create merge commit (When checks succeed)');
  expect(mergeform.find(tooltip).text()).toBe('Cancel auto merge');

  await mergeform.find(autoMergeBtn).trigger('click');
  expect(mergeform.find(mergeBtn).text()).toBe('Create merge commit');
  expect(mergeform.find(tooltip).text()).toBe('Auto merge when all checks succeed');
});

test('schedule picker reads the time in the time zone setting and shows the zone', async () => {
  const mergeform = await renderMergeForm('feature', {timeZone: 'Asia/Kolkata'});
  await mergeform.get('#scheduled-after').setValue('2026-07-01T12:00');
  expect(mergeform.get('input[name="scheduled_after"]').element.value).toBe('2026-07-01T06:30:00.000Z');
  expect(mergeform.get('.time-zone-label').text()).toContain('Asia/Kolkata (UTC+05:30)');
});

test('schedule picker uses the browser time zone without the setting', async () => {
  const mergeform = await renderMergeForm('feature', {timeZone: ''});
  await mergeform.get('#scheduled-after').setValue('2026-07-01T12:00');
  expect(mergeform.get('input[name="scheduled_after"]').element.value).toBe(new Date('2026-07-01T12:00').toISOString());
});

test('change time control posts the new time of a pending schedule', async () => {
  const mergeform = await renderMergeForm('feature', {
    timeZone: 'UTC', baseLink: '/o/r/pulls/1', hasPendingPullRequestMerge: true, textChangeTime: 'Change time', textChangeTimeSave: 'Save',
  });
  await mergeform.get('.merge-cancel').trigger('click');
  await mergeform.get('.change-time-button').trigger('click');
  const form = mergeform.get('form.change-time-form');
  expect(form.attributes('action')).toBe('/o/r/pulls/1/change_auto_merge_time');
  await mergeform.get('#change-scheduled-after').setValue('2026-07-01T12:00');
  expect(form.get('input[name="scheduled_after"]').element.value).toBe('2026-07-01T12:00:00.000Z');
});

test('delete branch checkbox is unchecked and disabled with the reason when the branch will be kept', async () => {
  const mergeform = await renderMergeForm('develop', {
    defaultDeleteBranchAfterMerge: true,
    deleteBranchForced: true,
    textDeleteBranchKept: 'develop will be kept: it is the development branch.',
  });
  expect(mergeform.get('#delete-branch-after-merge').element.checked).toBe(false);
  expect(mergeform.get('#delete-branch-after-merge').element.disabled).toBe(true);
  expect(mergeform.get('.delete-branch-kept').text()).toBe('develop will be kept: it is the development branch.');
  expect(mergeform.find('.delete-branch-forced').exists()).toBe(false);
  expect(mergeform.get('#delete-branch-after-merge').attributes('aria-describedby')).toBe('delete-branch-kept-reason');
  expect(mergeform.get('#delete-branch-kept-reason').text()).toContain('will be kept');
});
