# Web IDE

The Web IDE is the VS Code workbench running in the browser, on a repository's files. It is built from the MIT-licensed `@codingame/monaco-vscode-api` packages (VS Code 1.138) and talks only to gitdepo's own web routes, with the signed-in session.

## Opening it

- **File and folder views**: the "Open in Web IDE" button next to the edit button, or the `.` key anywhere on a file or folder page.
- **Pull requests**: the "Open in Web IDE" button in the header of an open pull request, shown only when you can push to its head branch (including "Allow edits from maintainers"). AGit pull requests have no head branch and get no button.
- **URL**: `/{owner}/{repo}/-/ide/{branch|tag|commit}/{ref}/{path}`.

Signing in is required. Anyone who can read the code can open it; on a tag, a commit, or a branch they can't push to, it is read-only.

## What it does

- Explorer, tabs, quick open (`Ctrl+P`) and search across the repository (`Ctrl+Shift+F`, server-side `git grep` at the opened commit, plus the files changed in the browser).
- Source control view (`Ctrl+Shift+G`) with the changes, their diffs, discard and "view all changes".
- Commit (`Ctrl+Enter` in the message box): all changes go into one commit, to the branch, to a new branch, or to a new branch with a pull request. Edits, new files, deletes and renames (kept as renames) are supported.
- If the branch got new commits since the IDE opened, committing to it is refused and the IDE offers a new branch instead. A branch you can't push to (protected) only offers a new branch.
- Files larger than `MAX_FILE_SIZE`, submodules and Git LFS files open read-only with a placeholder, and symbolic links are read-only. Other binary files get VS Code's binary-file notice. Images open in a preview; Markdown has a preview rendered by gitdepo's markup renderer in a sandboxed frame (no scripts).
- Uncommitted changes are kept in the browser (IndexedDB) and come back after a reload. If the branch moved meanwhile, they come back on the commit they were made on and must go to a new branch.

Commits go through the same code as the web editor (`ChangeRepoFiles`), so branch protection, push rules, pre-receive hooks, quota, the personal repository size lock and the audit log apply.

## Settings

```ini
[ide]
; Turn the Web IDE off. The routes then answer 404 and the buttons are hidden.
ENABLED = true
; Larger files open read-only. Defaults to [ui] MAX_DISPLAY_FILE_SIZE.
MAX_FILE_SIZE = 8388608
; Where the built IDE is. Defaults to <STATIC_ROOT_PATH>/public/assets/ide.
ASSETS_PATH =
```

## Building and deploying

The IDE is about 17 MB of JavaScript, CSS and fonts. It is **not embedded in the binary**, so the `gitea` binary that git hooks and SSH run stays the same size: it is built into `public/assets/ide` and served from disk at `/assets/ide/`.

- `make frontend` builds it (`make ide` builds only it, with vite, `web_src/ide/vite.config.js`). `make frontend SKIP_IDE=1` skips it.
- The Docker images copy it to `/app/gitea/public/assets/ide`.
- For other deployments, copy `public/assets/ide` next to the binary (or set `ASSETS_PATH`).
- When `ide.js` is missing from `ASSETS_PATH`, the IDE is off: no buttons, and the routes answer 404.

## Content Security Policy

The IDE page sends its own policy:

```
default-src 'self'; script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:;
worker-src 'self' blob:; connect-src 'self'; frame-src 'self'; object-src 'none';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

With `STATIC_URL_PREFIX` on another origin, that origin is added to the style, image and font sources. There is no `unsafe-eval`: VS Code extensions that need it (such as the built-in Git extension) are not included. `wasm-unsafe-eval` is for the TextMate grammar engine (oniguruma). VS Code webviews are off (there is no webview origin); the previews are plain editor panes instead.

## Licences

VS Code's MIT licence and the licences of the `@codingame` packages are in `/assets/licenses.txt`. `jschardet` (LGPL), which VS Code uses to guess file encodings, is replaced by a stub and not shipped: the IDE reads and writes UTF-8.
