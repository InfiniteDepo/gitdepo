import $ from 'jquery';
import {toggleElem} from '../utils/dom.js';

// The new/edit page of an Actions environment (templates/repo/settings/environment.tmpl).
export function initRepoSettingsEnvironment() {
  const form = document.querySelector('#environment-form');
  if (form) {
    initReviewers();
    initPatterns(form);
  }
  const confirm = document.querySelector('#environment-delete-confirm');
  if (confirm) {
    const button = document.querySelector('#environment-delete-button');
    confirm.addEventListener('input', () => {
      button.disabled = confirm.value.trim() !== confirm.getAttribute('data-name');
    });
  }
}

function initReviewers() {
  const dropdown = document.querySelector('#environment-reviewers');
  const input = document.querySelector('#environment-reviewers-input');
  const count = document.querySelector('#environment-reviewers-count');
  const max = Number(dropdown.getAttribute('data-max'));
  const update = () => {
    const n = input.value ? input.value.split(',').length : 0;
    const text = count.getAttribute(n >= max ? 'data-full' : 'data-text');
    count.textContent = text.replace('%d', String(n)).replace('%d', String(max));
    dropdown.querySelector('input.search')?.toggleAttribute('disabled', n >= max);
  };
  $(dropdown).dropdown({maxSelections: max, fullTextSearch: true, onChange: update});
  update();
}

function initPatterns(form) {
  const box = document.querySelector('#environment-patterns');
  const rows = document.querySelector('#environment-pattern-rows');
  const template = document.querySelector('#environment-pattern-row');
  const addRow = () => rows.append(template.content.cloneNode(true));
  for (const radio of form.querySelectorAll('input[name="ref_policy"]')) {
    radio.addEventListener('change', () => {
      const selected = form.querySelector('input[name="ref_policy"]:checked').value === '2';
      toggleElem(box, selected);
      if (selected && !rows.children.length) addRow();
    });
  }
  document.querySelector('#environment-pattern-add').addEventListener('click', addRow);
  rows.addEventListener('click', (e) => {
    e.target.closest('.environment-pattern-remove')?.closest('.environment-pattern').remove();
  });
}
