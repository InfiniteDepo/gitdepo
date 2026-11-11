// Copyright 2025 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

import {toggleElem} from '../utils/dom.js';
import {showModal} from '../modules/modal.ts';

// the part of a name the user types: whitespace and characters git refuses become one dash, case is kept
export function normalizeBranchName(name: string): string {
  return name.trim().replace(/[\s~^:?*[\\]+/g, '-');
}

function initCreateBranchDialog(modal: HTMLElement) {
  const form = modal.querySelector('form');
  const choices = Array.from(form.querySelectorAll<HTMLInputElement>('.branch-type-choice'));
  const nameInput = form.querySelector<HTMLInputElement>('#branch_name_part');
  const fullInput = form.querySelector<HTMLInputElement>('#new_branch_name');
  const preview = form.querySelector('#branch-name-preview');
  const base = form.querySelector<HTMLInputElement>('#branch_base');
  const note = form.querySelector('#branch-base-note');
  let typeBase = '';
  let notice = '';

  const update = () => {
    const prefix = choices.find((c) => c.checked)?.dataset.prefix ?? '';
    fullInput.value = prefix + normalizeBranchName(nameInput.value);
    preview.textContent = fullInput.value;
    form.action = form.getAttribute('data-base-action') + encodeURIComponent(base.value);
    const lines = [form.getAttribute('data-text-from').replace('%s', base.value), notice];
    const missing = choices.find((c) => c.checked)?.dataset.missing;
    if (missing) lines.push(form.getAttribute('data-text-missing').replace('%s', missing));
    if (typeBase && base.value !== typeBase) lines.push(form.getAttribute('data-text-changed').replace('%s', typeBase));
    note.textContent = lines.filter(Boolean).join(' ');
  };
  const pick = (choice: HTMLInputElement, resetBase: boolean) => {
    choice.checked = true;
    typeBase = choice.dataset.base ?? '';
    if (resetBase) base.value = typeBase;
  };
  form.addEventListener('change', (e) => {
    const target = e.target as HTMLInputElement;
    if (target.classList.contains('branch-type-choice')) {
      notice = '';
      pick(target, base.dataset.touched !== 'true');
    }
    update();
  });
  nameInput.addEventListener('input', () => {
    // a known prefix typed under "Other" switches the type and leaves the rest as the name
    const other = choices.find((c) => c.checked && c.dataset.prefix === '');
    if (other) {
      const match = choices.filter((c) => c.dataset.prefix && nameInput.value.startsWith(c.dataset.prefix)).sort((a, b) => b.dataset.prefix.length - a.dataset.prefix.length)[0];
      if (match) {
        nameInput.value = nameInput.value.slice(match.dataset.prefix.length);
        pick(match, base.dataset.touched !== 'true');
        notice = form.getAttribute('data-text-switched').replace('%s', match.value);
      }
    }
    update();
  });
  base.addEventListener('input', () => {
    base.dataset.touched = 'true';
    update();
  });

  for (const el of document.querySelectorAll('.show-create-branch-modal')) {
    el.addEventListener('click', () => {
      // the branch the user clicked is the base; the type's own base is only a hint
      base.value = el.getAttribute('data-branch-from');
      base.dataset.touched = 'true';
      notice = '';
      const wanted = choices.find((c) => c.value === el.getAttribute('data-suggest-type')) ?? choices.find((c) => c.checked) ?? choices[0];
      if (wanted) pick(wanted, false);
      nameInput.value = el.getAttribute('data-suggest-name') ?? '';
      update();
      showModal('create-branch-modal', undefined);
    });
  }
}

export function initRepoBranchGroups() {
  const toggle = document.querySelector<HTMLButtonElement>('#branch-group-toggle');
  if (!toggle) return;
  const tbody = document.querySelector('#branch-list-body');
  const rows = Array.from(tbody.querySelectorAll<HTMLElement>('tr[data-order]'));
  const headers = Array.from(tbody.querySelectorAll<HTMLElement>('tr.branch-group-header'));
  const byOrder = (a: HTMLElement, b: HTMLElement) => Number(a.dataset.order) - Number(b.dataset.order);
  const apply = (grouped: boolean) => {
    for (const header of headers) toggleElem(header, grouped);
    if (grouped) {
      for (const header of headers) tbody.append(header, ...rows.filter((r) => r.dataset.group === header.dataset.group).sort(byOrder));
    } else {
      tbody.append(...rows.sort(byOrder));
    }
    toggle.textContent = toggle.getAttribute(grouped ? 'data-text-none' : 'data-text-type'); // the button names what a click does
  };
  let grouped = true;
  try {
    grouped = localStorage.getItem('branch-list-group') !== 'none';
  } catch {}
  apply(grouped);
  toggle.addEventListener('click', () => {
    grouped = !grouped;
    try {
      localStorage.setItem('branch-list-group', grouped ? 'type' : 'none');
    } catch {}
    apply(grouped);
  });
}

export function initRepoBranchButton() {
  const createBranchModal = document.querySelector<HTMLElement>('#create-branch-modal');
  if (createBranchModal?.querySelector('#branch_name_part')) initCreateBranchDialog(createBranchModal);

  const renameBranchModel = document.querySelector('#rename-branch-modal');
  for (const el of document.querySelectorAll('.show-rename-branch-modal')) {
    el.addEventListener('click', () => {
      const oldBranchName = el.getAttribute('data-old-branch-name');
      (renameBranchModel.querySelector('input[name="from"]') as HTMLInputElement).value = oldBranchName;

      const branchToEl = renameBranchModel.querySelector('.label-branch-from');
      branchToEl.textContent = branchToEl.getAttribute('data-locale').replace('%s', oldBranchName);

      toggleElem(renameBranchModel.querySelector('.default-branch-warning'), el.getAttribute('data-is-default-branch') === 'true');

      showModal('rename-branch-modal', undefined);
    });
  }
}
