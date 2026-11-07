import {toggleElem} from '../utils/dom.js';

// the types "Start from Git flow" offers; nothing is saved until the form is saved
const gitFlow = [
  {name: 'Feature', prefix: 'feature/', base: 'development'},
  {name: 'Bugfix', prefix: 'bugfix/', base: 'development'},
  {name: 'Hotfix', prefix: 'hotfix/', base: 'production'},
];

// the checkboxes hold the index of their row, so the server knows which rows are on
function renumber(table) {
  for (const [i, row] of Array.from(table.querySelectorAll('tbody tr.branch-type-row')).entries()) {
    row.querySelector('input[name="type_on"]').value = String(i);
  }
}

function showBranchInput(row) {
  toggleElem(row.querySelector('input[name="type_branch"]'), row.querySelector('select[name="type_base"]').value === 'branch');
}

function addRow(table, {name, prefix, base}) {
  const row = table.querySelector('template').content.firstElementChild.cloneNode(true);
  row.querySelector('input[name="type_name"]').value = name;
  row.querySelector('input[name="type_prefix"]').value = prefix;
  row.querySelector('select[name="type_base"]').value = base;
  row.querySelector('input[name="type_on"]').checked = true;
  showBranchInput(row);
  table.querySelector('tbody').append(row);
  renumber(table);
}

export function initBranchingModel() {
  const table = document.querySelector('#branch-types');
  if (!table) return;
  for (const row of table.querySelectorAll('tr.branch-type-row')) showBranchInput(row);
  table.addEventListener('change', (e) => {
    if (e.target.matches('select[name="type_base"]')) showBranchInput(e.target.closest('tr'));
  });
  table.addEventListener('click', (e) => {
    const remove = e.target.closest('.remove-branch-type');
    if (!remove) return;
    remove.closest('tr').remove();
    renumber(table);
  });
  document.querySelector('#add-branch-type')?.addEventListener('click', () => addRow(table, {name: '', prefix: '', base: 'development'}));
  document.querySelector('#git-flow-branch-types')?.addEventListener('click', () => {
    const form = table.closest('form');
    for (const [field, value] of [['development_branch', 'develop'], ['production_branch', 'main'], ['release_prefixes', 'release/']]) {
      const input = form.querySelector(`input[name="${field}"]`);
      if (input && !input.value) input.value = value;
    }
    const have = new Set(Array.from(table.querySelectorAll('input[name="type_prefix"]'), (i) => i.value));
    for (const type of gitFlow) {
      if (!have.has(type.prefix)) addRow(table, type);
    }
  });
  table.closest('form').addEventListener('submit', () => renumber(table));
}
