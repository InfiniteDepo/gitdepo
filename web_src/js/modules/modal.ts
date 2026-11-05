// Copyright 2025 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// showModal will show the given modal and run `onApprove` if the approve/ok/yes
// button is pressed.
// The approve handler of each modal, so that showing it again (after Esc or a click outside) replaces it.
const approveHandlers = new WeakMap<HTMLDialogElement, () => void>();

export function showModal(modalID: string | HTMLDialogElement, onApprove: () => void) {
  let modal: HTMLDialogElement;
  if (typeof modalID === 'string') {
    modal = document.getElementById(modalID) as HTMLDialogElement;
  } else {
    modal = modalID;
  }

  // Move the modal to `<body>`, to avoid inheriting any bad CSS or if the
  // parent becomes `display: hidden`.
  document.body.append(modal);

  // Close the modal if the cancel button is pressed.
  modal.querySelector('.cancel')?.addEventListener('click', () => {
    modal.close();
    modal.querySelector('.ok')?.removeEventListener('click', onApprove);
  }, {once: true, passive: true});
  const ok = modal.querySelector('.ok');
  const previous = approveHandlers.get(modal);
  if (previous) ok?.removeEventListener('click', previous);
  approveHandlers.set(modal, onApprove);
  ok?.addEventListener('click', onApprove, {passive: true});

  // The modal is ready to be shown.
  modal.showModal();
}

// NOTE: Can be replaced in late 2026 with `closedBy` attribute on `<dialog>` element.
export function initModalClose() {
  document.addEventListener('click', (event) => {
    const dialog = document.querySelector<HTMLDialogElement>('dialog.modal[open]');
    // No open dialogs on page, nothing to do.
    if (dialog === null) return;

    const target = event.target as HTMLElement;
    // User clicked dialog itself (not it's content), likely ::backdrop, so close it.
    if (dialog === target) dialog.close();
  });
}
