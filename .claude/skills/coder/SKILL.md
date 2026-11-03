---
name: coder
description: Pick the next open gitdepo issue and take it to a mergeable pull request (choose, claim, design, test, code, CI, review). Use when someone asks to "work on the next issue", "pick an issue", "fix issue #N" or "open a PR for #N" in this repository.
---

# Coder

You work with the person who started you. They decide; you do the work and ask when a choice is theirs. Read `CLAUDE.md` and `CONTRIBUTING.md` first, then follow these steps in order. Keep messages short.

## 1. Pick the issue

If the person named an issue, use it. Otherwise list open issues and pick one that is:

- not assigned, and not already linked to an open pull request;
- not labelled `no-agent`, `wontfix`, `duplicate`, `invalid` or `question`, and not marked "Parked until …" in a comment;
- first by kind: bugs, regressions and `flaky` before features;
- then by size: the `P0`…`P4` labels are effort (P0 = least). Prefer `good first issue` for a first contribution.

Show the person your choice in one line (number, title, why) plus one alternative, and wait for their go. Read the whole issue and its comments: comments by maintainers are requirements.

## 2. Claim it

Comment on the issue that you are working on it, so nobody duplicates the work. Branch from the latest `develop`: `git fetch origin develop && git checkout -b <type>/<short-name> origin/develop`.

## 3. Design before code

For anything beyond a small fix, write a short plan: what changes (files, functions, migration, API, UI), what stays out of scope, and the tests that prove each requirement. Find existing helpers first (`tools/codemap.sh query`, then grep) and reuse them; use the `ponytail` skill: smallest correct diff, no unrequested abstractions. Show the plan to the person and post it on the issue. Ask before anything that changes an API, a database schema, permissions or a default.

## 4. Tests, then code

- Write the tests for each requirement, see them fail, then make them pass.
- Follow the conventions in `CONTRIBUTING.md` and `CLAUDE.md` (migrations, locale strings, swagger, license headers, lowercase "gitdepo"). Read the `CLAUDE.md` Learnings that touch your area: they record mistakes already made once.
- Never remove or skip existing tests, checks or validation to make something pass.
- Permissions: every new route, API endpoint or query that returns data checks who may see it, and a hidden thing answers like a missing one.

## 5. Check locally

Run what `CONTRIBUTING.md` lists for your change (`make fmt`, the lints, unit tests of the changed packages and their neighbours, the migration test if you added one, the e2e specs that cover your files). Run the integration suite for backend changes. Before calling a failure unrelated, run it on `origin/develop`; the environmental failures already known are listed in `CLAUDE.md`. Re-read your own diff as a reviewer would. Then use the other skills:

- `tester` on your head: the full local checks, other databases and performance, with every failure classified.
- `security-review` on your diff when it touches sign-in, permissions, roles, tokens, keys or secrets, input that reaches HTML, SQL, git or a shell, uploads, redirects, webhooks or outbound requests. Fix what it finds before opening the pull request.
- `screenshots` when the interface changes, and fix what it reports.

If the change adds or changes a user-visible feature, update the feature list in `docs/features.md` and any page under `docs/` it affects, in the same pull request.

## 6. Commit and open the pull request

- `git commit -s` (DCO sign-off on every commit). Stage files by name, never `git add -A`; keep `package-lock.json` out unless you changed packages.
- Open the pull request against `develop` and fill in `.github/pull_request_template.md`: summary with `Fixes #N`, the tests you added and ran, the checklist. Say that AI helped.
- For a change to the interface, attach before/after screenshots.

## 7. CI and review

CI runs on every push and sets the **CI success** status. When it fails, read the log in the pull request's checks, reproduce the failure locally, fix the cause and push once. "Flaky" is not a cause. Answer every review comment: fix it, or explain why not. If `develop` moves on, merge it into your branch with a merge commit (never rebase or force-push a pushed branch). The pull request is done when CI success is green on its head, it contains the latest `develop`, and every review thread is answered. Maintainers merge it.

## Never

- Never put a security problem, secret, credential, internal host name or log with tokens in an issue, pull request, commit or comment. If you find a vulnerability, stop and tell the person; it is reported privately as `SECURITY.md` describes.
- Never push to `develop` directly, rebase or force-push a pushed branch, or merge your own pull request.
- Never change repository settings or CI files (`.github/ci/*`) in a feature pull request.
