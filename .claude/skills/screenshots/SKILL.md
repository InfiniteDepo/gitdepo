---
name: screenshots
description: Start a fresh local gitdepo instance from a branch or PR head and screenshot the pages a change touches (desktop and mobile, light and dark), then review them. Use when asked for "screenshots", "show me the UI", "check how this looks" or before merging a pull request that changes the interface.
---

# Screenshots

You look at the interface as a user would. You don't change product code. Read `CLAUDE.md` ("Environment") first.

## 1. Build a clean instance

- Use a separate worktree with a short path (`git worktree add ../wt-<n> <sha>`): very long paths break the unix sockets.
- `make frontend` and `make backend` (or `make build`) in the worktree.
- Start from an empty data directory every time, never a shared one: write a minimal `custom/conf/app.ini` in the worktree with `WORK_PATH`, `[database] DB_TYPE = sqlite3` and a path inside the worktree, `INSTALL_LOCK = true`, a fresh `SECRET_KEY`/`INTERNAL_TOKEN`, and `HTTP_PORT` on a free port. A fresh install is the point: it catches pages that only work on a database someone already used.
- Run it in the background: `./gitea web --config custom/conf/app.ini`. Only if you run as root (containers), set `GITEA_I_AM_BEING_UNSAFE_RUNNING_AS_ROOT=true`.
- Create an admin with `./gitea admin user create --admin --config …` and the data the pages need (an org, a repository, a few rows) through the CLI or the API, never by editing the database.

## 2. Capture

- Use Playwright with Chromium. On your own machine `npx playwright install chromium` is fine; in a container with a preinstalled browser, don't install, pass its `executablePath` instead (see `CLAUDE.md`).
- For each page the change touches, plus its empty state and its error states: desktop (1280 px) and mobile (390 px), light and dark theme. Full-page screenshots, named `NN-<page>-<variant>.png`.
- Also capture the same pages on `origin/develop` when the change alters an existing page, so before and after can be compared.

## 3. Review

For every screenshot check: nothing overlaps or overflows at 390 px, no raw locale keys (`admin.something.title`) or `%!(EXTRA …)`, the product name is lowercase "gitdepo", buttons and messages say what they do, empty and error states read well, dark mode has readable contrast, and the page shows nothing the viewer shouldn't see. Note the browser console errors.

Accessibility, on each changed page: every control can be reached and used with the keyboard alone (Tab, Enter, Escape closes dialogs) with a visible focus ring; inputs have labels and icon-only buttons an `aria-label`; errors are announced in text, not by color alone; headings are in order. A quick automated pass (`@axe-core/playwright`) helps, but doesn't replace the keyboard check.

## 4. Report

A verdict, GO or NO-GO, then one line per page and variant (OK, or the problem and where). Give the person the image files. GitHub's tools can't attach images, so a pull request gets a text note of what was checked and the result. Stop the server and remove the worktree when done.
