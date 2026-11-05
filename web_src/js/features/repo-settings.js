import $ from 'jquery';
import {minimatch} from 'minimatch';
import {onInputDebounce, toggleElem} from '../utils/dom.js';
import {POST} from '../modules/fetch.js';
import {createCodemirror} from './codemirror.ts';

const {appSubUrl, i18n} = window.config;

export function initRepoSettingsCollaboration() {
  // Change collaborator access mode
  for (const dropdownEl of document.querySelectorAll('.page-content.repository .dialog-dropdown.access-mode')) {
    const url = dropdownEl.getAttribute('data-url');
    const uid = dropdownEl.getAttribute('data-uid');
    const textEl = dropdownEl.querySelector('.text');
    for (const buttonEl of dropdownEl.querySelectorAll('button[data-mode]')) {
      const mode = buttonEl.getAttribute('data-mode');
      buttonEl.addEventListener('click', async () => {
        dropdownEl.classList.add('is-loading');
        dropdownEl.removeAttribute('open');

        const data = new FormData();
        data.append('uid', uid);
        data.append('mode', mode);

        try {
          await POST(url, {data});
          textEl.textContent = buttonEl.textContent;
        } catch {
          showErrorToast(i18n.network_error);
        }
        dropdownEl.classList.remove('is-loading');
      }, {passive: true});
    }
  }
}

export function initRepoSettingSearchTeamBox() {
  const searchTeamBox = document.getElementById('search-team-box');
  if (!searchTeamBox) return;

  $(searchTeamBox).search({
    minCharacters: 2,
    apiSettings: {
      url: `${appSubUrl}/org/${searchTeamBox.getAttribute('data-org-name')}/teams/-/search?q={query}`,
      onResponse(response) {
        const items = [];
        for (const item of response.data) {
          items.push({
            title: item.name,
            description: `${item.permission} access`, // TODO: translate this string
          });
        }
        return {results: items};
      },
    },
    searchFields: ['name', 'description'],
    showNoResults: false,
  });
}

export function initRepoSettingGitHook() {
  if (!$('.edit.githook').length) return;
  const filename = document.querySelector('.hook-filename').textContent;
  const _promise = createCodemirror($('#content')[0], filename, {language: 'shell'});
}

export function initRepoSettingBranches() {
  if (!document.querySelector('.repository.settings.branches')) return;

  for (const el of document.getElementsByClassName('toggle-target-enabled')) {
    el.addEventListener('change', function () {
      const target = document.querySelector(this.getAttribute('data-target'));
      target?.classList.toggle('disabled', !this.checked);
    });
  }

  for (const el of document.getElementsByClassName('toggle-target-disabled')) {
    el.addEventListener('change', function () {
      const target = document.querySelector(this.getAttribute('data-target'));
      if (this.checked) target?.classList.add('disabled'); // only disable, do not auto enable
    });
  }

  document.getElementById('dismiss_stale_approvals')?.addEventListener('change', function () {
    document.getElementById('ignore_stale_approvals_box')?.classList.toggle('disabled', this.checked);
  });

  // show the `Matched` mark for the status checks that match the pattern
  const markMatchedStatusChecks = () => {
    const patterns = (document.getElementById('status_check_contexts').value || '').split(/[\r\n]+/);
    const validPatterns = patterns.map((item) => item.trim()).filter(Boolean);
    const marks = document.getElementsByClassName('status-check-matched-mark');

    for (const el of marks) {
      let matched = false;
      const statusCheck = el.getAttribute('data-status-check');
      for (const pattern of validPatterns) {
        if (minimatch(statusCheck, pattern)) {
          matched = true;
          break;
        }
      }
      toggleElem(el, matched);
    }
  };
  markMatchedStatusChecks();
  document.getElementById('status_check_contexts').addEventListener('input', onInputDebounce(markMatchedStatusChecks));

  initApprovalRules();
}

const showJsOnly = (root) => {
  for (const el of root.querySelectorAll('[data-js-only]')) toggleElem(el, true);
};

const setTitle = (card) => {
  const title = card.querySelector('.approval-rule-title');
  title.textContent = card.querySelector('[name="approval_rule_name"]').value.trim() || title.getAttribute('data-default');
};

// the limits of ValidateGlobPattern in models/git: at most 255 bytes, 6 wildcards, 3 alternations, none nested
function globsWithinLimits(pattern) {
  const p = pattern.trim();
  let depth = 0;
  let braces = 0;
  for (const c of p) {
    if (c === '{') {
      braces++;
      if (++depth > 1) return false;
    } else if (c === '}') {
      if (--depth < 0) return false;
    }
  }
  return new TextEncoder().encode(p).length <= 255 && (p.match(/[*?]/g) ?? []).length <= 6 && braces <= 3;
}

const ruleValue = (card, name) => card.querySelector(`[name="${name}"]`)?.value.trim() ?? '';

// Cards of approval rules: add, remove and validate in the browser. Without JS the existing cards still save as before.
function initApprovalRules() {
  const rules = document.querySelector('.approval-rules');
  if (!rules) return;
  const list = rules.querySelector('.approval-rule-cards');
  const addButton = rules.querySelector('.approval-rule-add');
  const cards = () => list.querySelectorAll('.approval-rule-card');
  const update = () => {
    const full = cards().length >= Number(rules.getAttribute('data-max'));
    addButton.disabled = full;
  };

  showJsOnly(rules);
  update();

  addButton.addEventListener('click', () => {
    const card = rules.querySelector('template').content.firstElementChild.cloneNode(true);
    showJsOnly(card);
    list.append(card);
    $(card).find('.ui.dropdown').dropdown();
    update();
  });
  list.addEventListener('click', (e) => {
    e.target.closest('.approval-rule-remove')?.closest('.approval-rule-card').remove();
    update();
  });
  list.addEventListener('input', (e) => {
    if (e.target.name === 'approval_rule_name') setTitle(e.target.closest('.approval-rule-card'));
  });
  // the source branch only matters when reviews are requested; the field stays in the form (hidden, not disabled) so the rows keep their order
  list.addEventListener('change', (e) => {
    if (e.target.name === 'approval_rule_request_reviews') {
      const card = e.target.closest('.approval-rule-card');
      toggleElem(card.querySelector('.approval-rule-source'), e.target.value === 'true');
      // the count error depends on the option: let the next save check again
      if (e.target.value === 'true') {
        toggleElem(card.querySelector('.approval-rule-error[data-error="count"]'), false);
        card.querySelector('[name="approval_rule_count"]').closest('.field').classList.remove('error');
      }
    }
  });

  // drop empty cards; refuse invalid ones with the checks of the model, the server still reports the rest (path globs, unknown names)
  rules.closest('form').addEventListener('submit', (e) => {
    const seen = new Set();
    let firstBad;
    for (const card of cards()) {
      const value = (name) => ruleValue(card, name);
      const name = value('approval_rule_name');
      const hasApprovers = value('approval_rule_users') || value('approval_rule_teams') || value('approval_rule_code_owners') === 'true';
      if (!name && !hasApprovers && !value('approval_rule_paths') && value('approval_rule_count') === '1') {
        card.remove();
        continue;
      }
      let error;
      let invalid = [];
      if (!name || new TextEncoder().encode(name).length > 255) [error, invalid] = ['name', ['approval_rule_name']];
      else if (seen.has(name)) [error, invalid] = ['duplicate', ['approval_rule_name']];
      else if (!(value('approval_rule_count') !== '' && Number.isInteger(Number(value('approval_rule_count'))) && Number(value('approval_rule_count')) >= (value('approval_rule_request_reviews') === 'true' ? 0 : 1))) [error, invalid] = ['count', ['approval_rule_count']];
      else if (Number(value('approval_rule_count')) === 0 && value('approval_rule_code_owners') === 'true') [error, invalid] = ['codeowners0', ['approval_rule_count', 'approval_rule_code_owners']];
      else if (!hasApprovers) [error, invalid] = ['approvers', ['approval_rule_users', 'approval_rule_teams']];
      else if (!globsWithinLimits(value('approval_rule_source_branch')) || value('approval_rule_paths').split(';').some((p) => !globsWithinLimits(p))) [error, invalid] = ['pattern', ['approval_rule_source_branch', 'approval_rule_paths']];
      seen.add(name);
      for (const el of card.querySelectorAll('.field')) el.classList.remove('error');
      for (const el of card.querySelectorAll('.approval-rule-error')) toggleElem(el, el.getAttribute('data-error') === error);
      for (const n of invalid) card.querySelector(`[name="${n}"]`)?.closest('.field').classList.add('error');
      if (error) firstBad ??= card;
    }
    update();
    if (firstBad) {
      e.preventDefault();
      firstBad.scrollIntoView({block: 'center'});
    }
  });
}
