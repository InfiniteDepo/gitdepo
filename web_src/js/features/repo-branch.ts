// Copyright 2025 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

import {toggleElem} from '../utils/dom.js';
import {showModal} from '../modules/modal.ts';
import {GET} from '../modules/fetch.js';

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

type BulkBranch = {name: string, commit: string};

function fill(text: string, ...values: Array<number | string>): string {
  for (const v of values) text = text.replace('%s', String(v));
  return text;
}

// The checkboxes of the Branches page, the "select all matching" banner state and the confirm dialog. The dialog
// lists exactly what the form posts: the ticked rows, or what the server says "all matching" deletes now.
export function initRepoBranchBulk() {
  const bar = document.querySelector<HTMLElement>('#branch-bulk-bar');
  if (!bar) return;
  const text = (key: string) => bar.getAttribute(`data-${key}`);
  const total = Number(bar.getAttribute('data-total'));
  const deletedMode = bar.getAttribute('data-deleted') === 'true';
  const boxes = () => Array.from(document.querySelectorAll<HTMLInputElement>('input.branch-select:not(:disabled)'));
  const ticked = () => boxes().filter((box) => box.checked);
  const count = bar.querySelector('#branch-selected-count');
  const master = bar.querySelector<HTMLInputElement>('#branch-select-page');
  const selectAll = bar.querySelector<HTMLButtonElement>('#branch-select-all');
  const clear = bar.querySelector<HTMLButtonElement>('#branch-clear-selection');
  const action = bar.querySelector<HTMLButtonElement>(deletedMode ? '#branch-restore-selected' : '#branch-delete-selected');
  let allMatching = false; // changing a filter reloads the page, which clears it

  const update = () => {
    const n = allMatching ? total : ticked().length;
    count.textContent = allMatching ? fill(text('text-all-selected'), total) : (n ? fill(text('text-selected'), n) : '');
    toggleElem(selectAll, !deletedMode && !allMatching && n > 0 && total > n);
    selectAll.textContent = fill(text('text-select-all'), total);
    toggleElem(clear, n > 0);
    if (action) {
      action.textContent = fill(text(deletedMode ? 'text-restore' : 'text-delete'), n);
      action.disabled = n === 0;
    }
    const all = boxes();
    master.checked = all.length > 0 && all.every((box) => box.checked);
  };
  const setAll = (checked: boolean) => {
    for (const box of boxes()) box.checked = checked;
    if (!checked) allMatching = false;
    update();
  };
  master.addEventListener('change', () => setAll(master.checked));
  clear.addEventListener('click', () => setAll(false));
  selectAll.addEventListener('click', () => {
    for (const box of boxes()) box.checked = true;
    allMatching = true;
    update();
  });
  document.addEventListener('change', (e) => {
    if (!(e.target as HTMLElement).classList?.contains('branch-select')) return;
    if (allMatching && !(e.target as HTMLInputElement).checked) allMatching = false;
    update();
  });
  update();
  if (deletedMode) return;

  const modal = document.querySelector<HTMLDialogElement>('#delete-selected-modal');
  const form = modal.querySelector<HTMLFormElement>('#delete-selected-form');
  const list = modal.querySelector('#delete-selected-list');
  const ok = modal.querySelector<HTMLButtonElement>('#delete-selected-ok');
  const nameInput = modal.querySelector<HTMLInputElement>('#delete-selected-name');
  const notes = {
    cap: modal.querySelector<HTMLElement>('#delete-selected-cap'),
    kept: modal.querySelector<HTMLElement>('#delete-selected-kept'),
    confirm: modal.querySelector<HTMLElement>('#delete-selected-confirm'),
    error: modal.querySelector<HTMLElement>('#delete-selected-error'),
  };
  const confirmAbove = Number(text('confirm-above'));
  let needConfirm = false;
  let listed = 0;
  const refreshOk = () => {
    ok.disabled = listed === 0 || (needConfirm && nameInput.value.trim().toLowerCase() !== text('confirm-name').toLowerCase());
  };
  nameInput.addEventListener('input', refreshOk);

  bar.querySelector('#branch-delete-selected').addEventListener('click', async () => {
    let items: BulkBranch[];
    let deletable = 0;
    let kept = 0;
    let failed = false;
    if (allMatching) {
      // the server decides what "all matching" is, under the filters of this page
      const params = new URLSearchParams(window.location.search);
      for (const key of ['page', 'selected', 'deleted']) params.delete(key);
      try {
        const res = await GET(`${text('preview-url')}?${params}`);
        if (!res.ok) throw new Error(String(res.status));
        const data = await res.json();
        items = data.branches;
        deletable = data.total;
        kept = data.kept;
      } catch {
        failed = true;
      }
    } else {
      items = ticked().map((box) => ({name: box.getAttribute('data-name'), commit: box.value.split(':')[0]}));
      deletable = items.length;
    }
    items ??= [];
    listed = items.length;
    for (const input of form.querySelectorAll('input[name="branch"]')) input.remove();
    list.textContent = '';
    for (const item of items) {
      const li = document.createElement('li');
      li.textContent = item.name;
      list.append(li);
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'branch';
      input.value = `${item.commit}:${item.name}`;
      form.append(input);
    }
    const plural = items.length === 1 ? 'one' : 'other';
    modal.querySelector('#delete-selected-title').textContent = fill(text(`title-${plural}`), items.length);
    ok.textContent = fill(text(`ok-${plural}`), items.length);
    toggleElem(notes.cap, deletable > items.length);
    notes.cap.textContent = fill(text('text-cap'), items.length, deletable);
    toggleElem(notes.kept, kept > 0);
    notes.kept.textContent = fill(text('text-kept'), kept);
    needConfirm = items.length > confirmAbove;
    toggleElem(notes.confirm, needConfirm);
    nameInput.value = '';
    toggleElem(notes.error, failed || items.length === 0);
    notes.error.textContent = failed ? text('text-error') : text('text-none');
    refreshOk();
    showModal('delete-selected-modal', undefined);
  });
}
