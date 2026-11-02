// The built-in extension of the Web IDE: the repository as a file system, its changes as source control, and the
// commit, all through spoved's web routes.
import type * as vscode from 'vscode';
import type {IExtensionManifest} from '@codingame/monaco-vscode-api/extensions';
import {minimatch} from 'minimatch';
import * as api from './api.ts';
import {loadChanges, saveChanges} from './storage.ts';
import {ExistsError, NotFoundError, Workspace, type Change, type TreeEntry} from './workspace.ts';
import {BASE_SCHEME, repoPathOf, rootPath, SCHEME} from './paths.ts';
import {markdownExtensions, PREVIEW_EDITOR} from './preview.ts';

type VSCode = typeof vscode;

const LFS_POINTER = 'version https://git-lfs.github.com/spec/v1';

export function manifestFor(config: api.IDEConfig): IExtensionManifest {
  const s = config.strings;
  const isSpoved = `scmProvider == ${SCHEME}`;
  return {
    name: 'spoved-fs',
    publisher: 'spoved',
    version: '1.0.0',
    engines: {vscode: '*'},
    enabledApiProposals: ['fileSearchProvider', 'textSearchProvider', 'scmActionButton'],
    contributes: {
      commands: [
        {command: 'spoved.commit', title: s.commit, icon: '$(check)'},
        {command: 'spoved.viewChanges', title: s.viewChanges, icon: '$(diff-multiple)'},
        {command: 'spoved.discard', title: s.discard, icon: '$(discard)'},
        {command: 'spoved.discardAll', title: s.discardAll, icon: '$(discard)'},
        {command: 'spoved.preview', title: s.preview, icon: '$(open-preview)'},
        {command: 'spoved.openInRepository', title: s.openInRepository},
      ],
      menus: {
        'scm/title': [
          {command: 'spoved.commit', group: 'navigation', when: isSpoved},
          {command: 'spoved.viewChanges', group: 'navigation', when: isSpoved},
        ],
        'scm/resourceState/context': [{command: 'spoved.discard', group: 'inline', when: isSpoved}],
        'scm/resourceGroup/context': [{command: 'spoved.discardAll', group: 'inline', when: isSpoved}],
        'editor/title': [{
          command: 'spoved.preview',
          group: 'navigation',
          when: `resourceScheme == ${SCHEME} && resourceExtname =~ /^\\.(${markdownExtensions.join('|')})$/i`,
        }],
      },
      configuration: {
        title: 'gitdepo',
        properties: {
          'spoved.commit.signoff': {type: 'boolean', default: false, description: s.signoff},
        },
      },
    },
  };
}

// a working-tree file that can't be edited here shows this text instead of its content
function placeholder(config: api.IDEConfig, entry: TreeEntry, content?: Uint8Array): string | undefined {
  const s = config.strings;
  if (entry.type === 'commit') return s.submodule.replace('%s', entry.sha);
  if (entry.size > config.maxFileSize) return s.tooLarge;
  if (content && content.length < 1024 && new TextDecoder().decode(content).startsWith(LFS_POINTER)) return s.lfs;
  return undefined;
}

export async function activate(vscode: VSCode, config: api.IDEConfig) {
  const s = config.strings;
  const root = rootPath(config);
  const uriOf = (path: string, scheme = SCHEME) => vscode.Uri.from({scheme, path: path ? `${root}/${path}` : root});
  const pathOf = (uri: vscode.Uri) => repoPathOf(config, uri.path);
  const canEdit = config.canCommit || config.canCreateBranch;
  const storageKey = `${config.repoLink}#${config.refName}`;

  // changes saved by an earlier session of this branch keep the commit they were made on
  const saved = config.refType === 'branch' && canEdit ? await loadChanges(storageKey) : undefined;
  let entries: TreeEntry[] = [];
  let commitID = config.commitID;
  if (saved && saved.commitID !== config.commitID) {
    try {
      entries = await api.fetchTree(config.repoLink, saved.commitID);
      commitID = saved.commitID;
    } catch {
      await saveChanges(storageKey, undefined);
    }
  }
  if (commitID === config.commitID) entries = await api.fetchTree(config.repoLink, commitID);
  const ws = new Workspace(commitID, entries, (entry) => api.fetchBlob(config.repoLink, entry.sha));
  if (saved && saved.commitID === commitID) ws.restore(saved);

  const fileChanged = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
  const mtimes = new Map<string, number>();
  const readonlyPaths = new Set<string>();

  const fsError = (err: unknown, uri: vscode.Uri) => {
    if (err instanceof NotFoundError) return vscode.FileSystemError.FileNotFound(uri);
    if (err instanceof ExistsError) return vscode.FileSystemError.FileExists(uri);
    return err;
  };
  const isReadonly = (path: string) => {
    const entry = ws.entry(path);
    return readonlyPaths.has(path) || (entry && (entry.type === 'commit' || entry.mode === '120000' || placeholder(config, entry) !== undefined));
  };

  let saveTimer: ReturnType<typeof setTimeout>;
  const changed = (events: vscode.FileChangeEvent[]) => {
    for (const {uri} of events) mtimes.set(pathOf(uri), Date.now());
    fileChanged.fire(events);
    refreshSCM();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => saveChanges(storageKey, ws.changes().length ? ws.save() : undefined), 300);
  };

  vscode.workspace.registerFileSystemProvider(SCHEME, {
    onDidChangeFile: fileChanged.event,
    watch: () => new vscode.Disposable(() => {}),
    stat(uri) {
      const path = pathOf(uri);
      if (ws.isFile(path)) {
        return {
          type: vscode.FileType.File,
          ctime: 0,
          mtime: mtimes.get(path) ?? 0,
          size: ws.size(path),
          permissions: isReadonly(path) ? vscode.FilePermission.Readonly : undefined,
        };
      }
      if (ws.isDirectory(path)) return {type: vscode.FileType.Directory, ctime: 0, mtime: 0, size: 0};
      throw vscode.FileSystemError.FileNotFound(uri);
    },
    readDirectory(uri) {
      try {
        return ws.readDirectory(pathOf(uri)).map(([name, type]) => [name, type === 'file' ? vscode.FileType.File : vscode.FileType.Directory]);
      } catch (err) {
        throw fsError(err, uri);
      }
    },
    async readFile(uri) {
      const path = pathOf(uri);
      const entry = ws.entry(path);
      try {
        const early = entry && placeholder(config, entry);
        if (early) return new TextEncoder().encode(early);
        const content = await ws.readFile(path);
        const late = entry && placeholder(config, entry, content);
        if (late) {
          readonlyPaths.add(path);
          return new TextEncoder().encode(late);
        }
        return content;
      } catch (err) {
        throw fsError(err, uri);
      }
    },
    async writeFile(uri, content, options) {
      const path = pathOf(uri);
      if (isReadonly(path)) throw vscode.FileSystemError.NoPermissions(uri);
      const existed = ws.isFile(path);
      try {
        await ws.writeFile(path, content, options);
      } catch (err) {
        throw fsError(err, uri);
      }
      changed([{type: existed ? vscode.FileChangeType.Changed : vscode.FileChangeType.Created, uri}]);
    },
    createDirectory(uri) {
      try {
        ws.createDirectory(pathOf(uri));
      } catch (err) {
        throw fsError(err, uri);
      }
      changed([{type: vscode.FileChangeType.Created, uri}]);
    },
    delete(uri) {
      try {
        ws.delete(pathOf(uri));
      } catch (err) {
        throw fsError(err, uri);
      }
      changed([{type: vscode.FileChangeType.Deleted, uri}]);
    },
    async rename(from, to, options) {
      try {
        await ws.rename(pathOf(from), pathOf(to), options.overwrite);
      } catch (err) {
        throw fsError(err, from);
      }
      changed([{type: vscode.FileChangeType.Deleted, uri: from}, {type: vscode.FileChangeType.Created, uri: to}]);
    },
  }, {isCaseSensitive: true, isReadonly: canEdit ? false : new vscode.MarkdownString(s.readOnly)});

  // the committed files, which the source control view and the editor gutter compare with
  const baseChanged = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
  vscode.workspace.registerFileSystemProvider(BASE_SCHEME, {
    onDidChangeFile: baseChanged.event,
    watch: () => new vscode.Disposable(() => {}),
    stat(uri) {
      const entry = ws.base.get(pathOf(uri));
      if (!entry) throw vscode.FileSystemError.FileNotFound(uri);
      return {type: entry.type === 'tree' ? vscode.FileType.Directory : vscode.FileType.File, ctime: 0, mtime: 0, size: entry.size};
    },
    readDirectory: () => [],
    async readFile(uri) {
      const entry = ws.base.get(pathOf(uri));
      if (!entry || entry.type === 'tree') throw vscode.FileSystemError.FileNotFound(uri);
      const early = placeholder(config, entry);
      return early ? new TextEncoder().encode(early) : ws.readBase(entry);
    },
    writeFile: (uri) => {
      throw vscode.FileSystemError.NoPermissions(uri);
    },
    createDirectory: (uri) => {
      throw vscode.FileSystemError.NoPermissions(uri);
    },
    delete: (uri) => {
      throw vscode.FileSystemError.NoPermissions(uri);
    },
    rename: (uri) => {
      throw vscode.FileSystemError.NoPermissions(uri);
    },
  }, {isCaseSensitive: true, isReadonly: true});

  const included = (path: string, options: vscode.SearchOptions) =>
    (!options.includes.length || options.includes.some((g) => minimatch(path, g, {dot: true, matchBase: true}))) &&
    !options.excludes.some((g) => minimatch(path, g, {dot: true, matchBase: true}));

  // quick open (Ctrl+P) and search across the repository
  vscode.workspace.registerFileSearchProvider(SCHEME, {
    provideFileSearchResults(query, options) {
      const pattern = query.pattern.toLowerCase().replaceAll(/\s/g, '');
      const matches: vscode.Uri[] = [];
      for (const path of ws.files()) {
        let i = 0;
        for (const c of path.toLowerCase()) {
          if (c === pattern[i]) i++;
        }
        if (i === pattern.length && included(path, options)) matches.push(uriOf(path));
        if (options.maxResults && matches.length >= options.maxResults) break;
      }
      return matches;
    },
  });
  vscode.workspace.registerTextSearchProvider(SCHEME, {
    async provideTextSearchResults(query, options, progress, token) {
      let re: RegExp;
      try {
        const source = query.isRegExp ? query.pattern : query.pattern.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
        re = new RegExp(query.isWordMatch ? `\\b(?:${source})\\b` : source, query.isCaseSensitive ? 'g' : 'gi');
      } catch {
        return {limitHit: false};
      }
      let count = 0;
      const report = (path: string, line: number, text: string) => {
        const ranges = Array.from(text.matchAll(re)).filter((m) => m[0].length).map((m) => new vscode.Range(line, m.index, line, m.index + m[0].length));
        if (!ranges.length || count >= options.maxResults) return;
        count++;
        progress.report({uri: uriOf(path), ranges, preview: {text, matches: ranges.map((r) => new vscode.Range(0, r.start.character, 0, r.end.character))}});
      };
      // files changed here are searched here, the rest by the server at the commit
      const local = new Set([...ws.modified.keys(), ...ws.deleted]);
      for (const [path, content] of ws.modified) {
        if (!included(path, options) || content.includes(0)) continue;
        for (const [i, text] of new TextDecoder().decode(content).split('\n').entries()) report(path, i, text);
      }
      let matches: api.SearchMatch[] = [];
      try {
        matches = await api.search(config.repoLink, ws.commitID, query.pattern, Boolean(query.isRegExp));
      } catch (err) {
        return {limitHit: false, message: {text: err.message, type: 2}};
      }
      for (const match of matches) {
        if (token.isCancellationRequested) break;
        if (local.has(match.path) || !included(match.path, options)) continue;
        for (const [i, line] of match.lines.entries()) report(match.path, line - 1, match.codes[i]);
      }
      return {limitHit: count >= options.maxResults};
    },
  });
  // source control: the changes, their diffs and the commit
  const scm = vscode.scm.createSourceControl(SCHEME, config.repoName, uriOf(''));
  scm.quickDiffProvider = {
    provideOriginalResource: (uri) => {
      const path = pathOf(uri);
      const from = ws.renamedFrom.get(path) ?? path;
      return ws.base.get(from)?.type === 'blob' ? uriOf(from, BASE_SCHEME) : undefined;
    },
  };
  scm.inputBox.placeholder = s.commitMessagePlaceholder;
  scm.acceptInputCommand = {command: 'spoved.commit', title: s.commit};
  const group = scm.createResourceGroup('changes', s.changes);
  const label = {added: s.added, modified: s.modified, deleted: s.deleted, renamed: s.renamed};
  const openChange = (change: Change): vscode.Command => {
    const name = change.path.slice(change.path.lastIndexOf('/') + 1);
    switch (change.kind) {
      case 'added':
        return {command: 'vscode.open', title: s.open, arguments: [uriOf(change.path)]};
      case 'deleted':
        return {command: 'vscode.open', title: s.open, arguments: [uriOf(change.path, BASE_SCHEME)]};
      default:
        return {command: 'vscode.diff', title: s.open, arguments: [uriOf(change.from ?? change.path, BASE_SCHEME), uriOf(change.path), `${name} (${label[change.kind]})`]};
    }
  };
  const decorationsChanged = new vscode.EventEmitter<undefined>();
  function refreshSCM() {
    const changes = ws.changes();
    group.resourceStates = changes.map((change) => ({
      resourceUri: uriOf(change.path),
      command: openChange(change),
      decorations: {
        strikeThrough: change.kind === 'deleted',
        tooltip: change.from ? `${label[change.kind]}: ${change.from} → ${change.path}` : label[change.kind],
      },
    }));
    scm.count = changes.length;
    scm.actionButton = {command: {command: 'spoved.commit', title: s.commit}, enabled: canEdit && changes.length > 0};
    decorationsChanged.fire(undefined);
  }

  // the explorer shows the changes too
  const badges = {added: 'A', modified: 'M', deleted: 'D', renamed: 'R'};
  const colors = {added: 'charts.green', modified: 'charts.yellow', deleted: 'charts.red', renamed: 'charts.blue'};
  vscode.window.registerFileDecorationProvider({
    onDidChangeFileDecorations: decorationsChanged.event,
    provideFileDecoration(uri) {
      if (uri.scheme !== SCHEME) return undefined;
      const change = ws.changes().find((c) => c.path === pathOf(uri));
      return change && new vscode.FileDecoration(badges[change.kind], label[change.kind], new vscode.ThemeColor(colors[change.kind]));
    },
  });

  const fireAll = (paths: string[]) => fileChanged.fire(paths.map((path) => ({type: vscode.FileChangeType.Changed, uri: uriOf(path)})));
  vscode.commands.registerCommand('spoved.discard', (...states: vscode.SourceControlResourceState[]) => {
    const paths = states.map((state) => pathOf(state.resourceUri));
    for (const path of paths) ws.revert(path);
    changed(paths.map((path) => ({type: vscode.FileChangeType.Changed, uri: uriOf(path)})));
  });
  vscode.commands.registerCommand('spoved.discardAll', async () => {
    if (await vscode.window.showWarningMessage(s.discardAllConfirm, {modal: true}, s.discardAll) !== s.discardAll) return;
    const paths = ws.changes().flatMap((c) => c.from ? [c.path, c.from] : [c.path]);
    ws.clear();
    changed(paths.map((path) => ({type: vscode.FileChangeType.Changed, uri: uriOf(path)})));
  });
  vscode.commands.registerCommand('spoved.viewChanges', () => vscode.commands.executeCommand('_workbench.openMultiDiffEditor', {
    multiDiffSourceUri: vscode.Uri.from({scheme: 'spoved-changes', path: root}),
    title: s.changes,
    resources: ws.changes().map((c) => ({
      originalUri: c.kind === 'added' ? undefined : uriOf(c.from ?? c.path, BASE_SCHEME),
      modifiedUri: c.kind === 'deleted' ? undefined : uriOf(c.path),
    })),
  }));
  vscode.commands.registerCommand('spoved.preview', (uri?: vscode.Uri) => {
    const target = uri ?? vscode.window.activeTextEditor?.document.uri;
    if (target) vscode.commands.executeCommand('vscode.openWith', target, PREVIEW_EDITOR, vscode.ViewColumn.Beside);
  });

  const branchItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  branchItem.text = `$(${config.refType === 'branch' ? 'git-branch' : config.refType === 'tag' ? 'tag' : 'git-commit'}) ${config.refName}`;
  branchItem.tooltip = s.openInRepository;
  branchItem.command = 'spoved.openInRepository';
  branchItem.show();

  // after a commit, the IDE continues on the commit's branch with no changes left
  async function moveTo(branch: string, commit: string) {
    const paths = ws.changes().flatMap((c) => c.from ? [c.path, c.from] : [c.path]);
    await saveChanges(storageKey, undefined);
    config.refName = branch;
    const next = await api.fetchTree(config.repoLink, commit);
    ws.base.clear();
    for (const entry of next) ws.base.set(entry.path, entry);
    ws.commitID = commit;
    ws.clear();
    readonlyPaths.clear();
    window.history.replaceState(null, '', `${config.repoLink}/-/ide/branch/${api.escapePath(branch)}`);
    branchItem.text = `$(git-branch) ${branch}`;
    fireAll(paths);
    baseChanged.fire(paths.map((path) => ({type: vscode.FileChangeType.Changed, uri: uriOf(path, BASE_SCHEME)})));
    refreshSCM();
  }

  // A text prompt with a tappable confirm button. A mobile soft keyboard's Enter
  // key often never reaches the quick input, so Enter can't be the only way to
  // accept; the button in the title bar lets a touch user confirm with a tap.
  function promptText(opts: {prompt: string; placeHolder?: string; value?: string; required?: boolean}): Promise<string | undefined> {
    return new Promise((resolve) => {
      const input = vscode.window.createInputBox();
      input.title = s.commit;
      input.prompt = opts.prompt;
      if (opts.placeHolder) input.placeholder = opts.placeHolder;
      if (opts.value) input.value = opts.value;
      input.ignoreFocusOut = true;
      const ok: vscode.QuickInputButton = {iconPath: new vscode.ThemeIcon('check'), tooltip: s.commit};
      input.buttons = [ok];
      let done = false;
      const finish = (value?: string) => {
        if (done) return;
        done = true;
        input.hide();
        resolve(value);
      };
      const accept = () => {
        const value = input.value.trim();
        if (opts.required && !value) {
          input.validationMessage = opts.prompt;
          return;
        }
        finish(value);
      };
      input.onDidAccept(accept);
      input.onDidTriggerButton((b) => { if (b === ok) accept(); });
      input.onDidHide(() => finish(undefined));
      input.show();
    });
  }

  let committing = false;
  vscode.commands.registerCommand('spoved.commit', async (forceNewBranch?: boolean) => {
    if (committing) return;
    const files = ws.operations();
    if (!files.length) {
      vscode.window.showInformationMessage(s.nothingToCommit);
      return;
    }
    let message = scm.inputBox.value.trim();
    if (!message) message = (await promptText({prompt: s.commitMessage, placeHolder: s.commitMessagePlaceholder, required: true}))?.trim();
    if (!message) return;

    const onBranch = config.refType === 'branch' && config.canCommit && ws.commitID === config.commitID && forceNewBranch !== true;
    // Short labels: a modal's button row doesn't wrap, so long labels overflow a phone screen.
    const choices = [
      ...(onBranch ? [{label: s.commitToBranch.replace('%s', config.refName), id: 'branch'}] : []),
      ...(config.canCreateBranch ? [{label: s.targetNewBranch, id: 'new'}] : []),
      ...(config.canCreatePull ? [{label: s.targetNewBranchPull, id: 'pull'}] : []),
    ];
    if (!choices.length) {
      vscode.window.showErrorMessage(s.readOnly);
      return;
    }
    // A modal dialog's buttons are plain tappable buttons; a quick-pick list's row
    // selection and filter box are unreliable under a mobile soft keyboard.
    let choice: string | undefined;
    if (choices.length === 1) {
      choice = choices[0].id;
    } else {
      const picked = await vscode.window.showInformationMessage(s.commit, {modal: true}, ...choices.map((c) => c.label));
      choice = choices.find((c) => c.label === picked)?.id;
    }
    if (!choice) return;
    let newBranch: string;
    if (choice !== 'branch') {
      newBranch = (await promptText({
        prompt: s.newBranchName,
        value: `${config.refName}-ide-${new Date().toISOString().slice(0, 10)}`,
        required: true,
      }))?.trim();
      if (!newBranch) return;
    }

    committing = true;
    try {
      const res = await vscode.window.withProgress({location: vscode.ProgressLocation.SourceControl}, () => api.commit(config.repoLink, config.refName, {
        last_commit: ws.commitID,
        new_branch: newBranch,
        message,
        signoff: vscode.workspace.getConfiguration('spoved.commit').get('signoff', false),
        files,
      }));
      const base = config.refName;
      scm.inputBox.value = '';
      config.commitID = res.commit;
      config.canCommit ||= Boolean(newBranch);
      await moveTo(res.branch, res.commit);
      if (choice === 'pull') {
        const [title, ...body] = message.split('\n');
        const link = await api.createPull(config.repoLink, base, res.branch, title, body.join('\n').trim());
        if (await vscode.window.showInformationMessage(s.pullCreated, s.openPull) === s.openPull) window.open(link, '_blank', 'noopener');
      } else {
        vscode.window.showInformationMessage(s.committed.replace('%s', res.branch));
      }
    } catch (err) {
      if (err instanceof api.RequestError && err.code === 'branch_moved' && config.canCreateBranch) {
        if (await vscode.window.showWarningMessage(err.message, s.commitToNewBranch) === s.commitToNewBranch) {
          committing = false;
          await vscode.commands.executeCommand('spoved.commit', true);
        }
      } else {
        vscode.window.showErrorMessage(err.message);
      }
    } finally {
      committing = false;
    }
  });

  vscode.commands.registerCommand('spoved.openInRepository', () => {
    const editor = vscode.window.activeTextEditor?.document.uri;
    const path = editor?.scheme === SCHEME && ws.entry(pathOf(editor)) ? pathOf(editor) : '';
    window.open(`${config.repoLink}/src/${config.refType}/${api.escapePath(config.refName)}${path ? `/${api.escapePath(path)}` : ''}`, '_blank', 'noopener');
  });

  if (!canEdit) {
    const readonlyItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 99);
    readonlyItem.text = `$(lock) ${s.readOnlyShort}`;
    readonlyItem.tooltip = s.readOnly;
    readonlyItem.show();
  }

  refreshSCM();
  if (ws.commitID !== config.commitID) vscode.window.showWarningMessage(s.restoredOnOlderCommit);
  if (config.treePath && ws.isFile(config.treePath)) {
    vscode.commands.executeCommand('vscode.open', uriOf(config.treePath));
  } else if (config.treePath && ws.isDirectory(config.treePath)) {
    vscode.commands.executeCommand('revealInExplorer', uriOf(config.treePath));
  }
  document.querySelector('#ide').setAttribute('data-ready', 'true');
}
