// The Web IDE: the VS Code workbench (MIT, built from microsoft/vscode by @codingame/monaco-vscode-api) with a
// built-in extension that reads and writes the repository through gitdepo's web routes.
import {IFileService, initialize, LogLevel, withReadyServices} from '@codingame/monaco-vscode-api';
import {URI} from '@codingame/monaco-vscode-api/vscode/vs/base/common/uri';
import {ExtensionHostKind, registerExtension} from '@codingame/monaco-vscode-api/extensions';
import getWorkbenchServiceOverride from '@codingame/monaco-vscode-workbench-service-override';
import getQuickAccessServiceOverride from '@codingame/monaco-vscode-quickaccess-service-override';
import getConfigurationServiceOverride from '@codingame/monaco-vscode-configuration-service-override';
import getKeybindingsServiceOverride from '@codingame/monaco-vscode-keybindings-service-override';
import getModelServiceOverride from '@codingame/monaco-vscode-model-service-override';
import getNotificationServiceOverride from '@codingame/monaco-vscode-notifications-service-override';
import getDialogsServiceOverride from '@codingame/monaco-vscode-dialogs-service-override';
import getTextmateServiceOverride from '@codingame/monaco-vscode-textmate-service-override';
import getThemeServiceOverride from '@codingame/monaco-vscode-theme-service-override';
import getLanguagesServiceOverride from '@codingame/monaco-vscode-languages-service-override';
import getStorageServiceOverride from '@codingame/monaco-vscode-storage-service-override';
import getLifecycleServiceOverride from '@codingame/monaco-vscode-lifecycle-service-override';
import getExplorerServiceOverride from '@codingame/monaco-vscode-explorer-service-override';
import getScmServiceOverride from '@codingame/monaco-vscode-scm-service-override';
import getSearchServiceOverride from '@codingame/monaco-vscode-search-service-override';
import getLogServiceOverride from '@codingame/monaco-vscode-log-service-override';
import getExtensionServiceOverride from '@codingame/monaco-vscode-extensions-service-override';
import getStatusBarServiceOverride from '@codingame/monaco-vscode-view-status-bar-service-override';
import getPreferencesServiceOverride from '@codingame/monaco-vscode-preferences-service-override';
import getWorkingCopyServiceOverride from '@codingame/monaco-vscode-working-copy-service-override';
import getEnvironmentServiceOverride from '@codingame/monaco-vscode-environment-service-override';
import getMultiDiffEditorServiceOverride from '@codingame/monaco-vscode-multi-diff-editor-service-override';
import {createIndexedDBProviders} from '@codingame/monaco-vscode-files-service-override';
import '@codingame/monaco-vscode-extension-api/localExtensionHost';
import './languages.ts';
import editorWorker from '@codingame/monaco-vscode-api/workers/editor.worker?worker&url';
import textMateWorker from '@codingame/monaco-vscode-textmate-service-override/worker?worker&url';
import searchWorker from '@codingame/monaco-vscode-search-service-override/worker?worker&url';
import {activate, manifestFor} from './extension.ts';
import {BASE_SCHEME, rootPath, SCHEME} from './paths.ts';
import {registerPreview} from './preview.ts';
import type {IDEConfig} from './api.ts';

const workers: Record<string, string> = {
  editorWorkerService: editorWorker,
  TextMateWorker: textMateWorker,
  LocalFileSearchWorker: searchWorker,
};
window.MonacoEnvironment = {
  getWorkerUrl: (_moduleId: string, label: string) => workers[label],
  getWorkerOptions: () => ({type: 'module'}),
};

const themes = {
  light: 'Default Light Modern',
  dark: 'Default Dark Modern',
  'high-contrast': 'Default High Contrast',
};

const container = document.querySelector<HTMLElement>('#ide');
const config: IDEConfig = JSON.parse(container.getAttribute('data-config'));
container.textContent = '';

// On a narrow (phone) screen a modal dialog's button row doesn't wrap, so three or
// more options run off the edge. Stack the buttons vertically there so each stays
// fully visible and tappable; wide screens keep the default horizontal row.
const narrowDialogStyle = document.createElement('style');
narrowDialogStyle.textContent = `@media (max-width: 600px) {
  .monaco-dialog-box:not(.align-vertical) > .dialog-buttons-row { overflow: visible !important; }
  .monaco-dialog-box:not(.align-vertical) > .dialog-buttons-row > .dialog-buttons {
    flex-direction: column !important;
    align-items: stretch !important;
    justify-content: flex-start !important;
    overflow: visible !important;
    margin-left: 5px !important;
    margin-right: 5px !important;
  }
  .monaco-dialog-box:not(.align-vertical) > .dialog-buttons-row > .dialog-buttons > .monaco-button {
    width: auto !important;
    margin: 4px 0 !important;
  }
}`;
document.head.append(narrowDialogStyle);

// the workbench resolves the repository's folder before the extension below registers its file systems: make it
// wait for them, or the explorer marks the folder as unresolvable for good
let providersReady: () => void;
const ready = new Promise<void>((resolve) => providersReady = resolve);
withReadyServices((services) => services.get(IFileService).onWillActivateFileSystemProvider((e) => {
  if (e.scheme === SCHEME || e.scheme === BASE_SCHEME) e.join(ready);
}));

// user settings and keybindings stay in this browser
await createIndexedDBProviders();

await initialize({
  ...getLogServiceOverride(),
  ...getExtensionServiceOverride(),
  ...getModelServiceOverride(),
  ...getNotificationServiceOverride(),
  ...getDialogsServiceOverride(),
  ...getConfigurationServiceOverride(),
  ...getKeybindingsServiceOverride(),
  ...getTextmateServiceOverride(),
  ...getThemeServiceOverride(),
  ...getLanguagesServiceOverride(),
  ...getStorageServiceOverride(),
  ...getLifecycleServiceOverride(),
  ...getEnvironmentServiceOverride(),
  ...getWorkingCopyServiceOverride(),
  ...getPreferencesServiceOverride(),
  ...getStatusBarServiceOverride(),
  ...getExplorerServiceOverride(),
  ...getScmServiceOverride(),
  ...getSearchServiceOverride(),
  ...getMultiDiffEditorServiceOverride(),
  ...getWorkbenchServiceOverride(),
  ...getQuickAccessServiceOverride({isKeybindingConfigurationVisible: () => true, shouldUseGlobalPicker: () => true}),
}, container, {
  workspaceProvider: {
    trusted: true,
    open: async () => false,
    workspace: {folderUri: URI.from({scheme: SCHEME, path: rootPath(config)})},
  },
  developmentOptions: {logLevel: LogLevel.Warning},
  productConfiguration: {nameShort: 'gitdepo Web IDE', nameLong: 'gitdepo Web IDE'},
  configurationDefaults: {
    'workbench.colorTheme': themes[config.theme] ?? themes.light,
    'window.autoDetectColorScheme': config.theme === 'auto',
    'workbench.preferredLightColorTheme': themes.light,
    'workbench.preferredDarkColorTheme': themes.dark,
    'workbench.startupEditor': 'none',
    'files.autoSave': 'afterDelay',
    'window.title': `\${dirty}\${activeEditorShort}\${separator}${config.repoName}`,
  },
});

registerPreview(config);
const extension = registerExtension(manifestFor(config), ExtensionHostKind.LocalProcess, {system: true});
try {
  await activate(await extension.getApi(), config);
} finally {
  providersReady();
}
