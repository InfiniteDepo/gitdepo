// Markdown and image preview without VS Code webviews: images are shown from the file's bytes, Markdown is rendered
// by gitdepo's own markup renderer (sanitized on the server) inside a sandboxed iframe that can't run scripts.
import {getService, IFileService, type IEditorGroup} from '@codingame/monaco-vscode-api';
import type {URI} from '@codingame/monaco-vscode-api/vscode/vs/base/common/uri';
import {
  registerEditor,
  registerEditorPane,
  RegisteredEditorPriority,
  SimpleEditorInput,
  SimpleEditorPane,
} from '@codingame/monaco-vscode-workbench-service-override';
import {POST} from '../js/modules/fetch.js';
import {escapePath, type IDEConfig} from './api.ts';
import {repoPathOf} from './paths.ts';

export const PREVIEW_EDITOR = 'gitdepo.preview';
export const imageExtensions = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp', 'ico', 'svg'];
export const markdownExtensions = ['md', 'markdown'];

const imageTypes: Record<string, string> = {svg: 'image/svg+xml', jpg: 'image/jpeg', ico: 'image/x-icon'};
const extensionOf = (path: string) => path.slice(path.lastIndexOf('.') + 1).toLowerCase();

export function registerPreview(config: IDEConfig) {
  const markdownHTML = async (path: string, text: string) => {
    const dir = path.includes('/') ? `/${escapePath(path.slice(0, path.lastIndexOf('/')))}` : '';
    const form = new FormData();
    form.set('mode', 'file');
    form.set('context', `${config.repoLink}${dir}`);
    form.set('branch_path', `${config.refType}/${escapePath(config.refName)}`);
    form.set('file_path', path);
    form.set('text', text);
    const resp = await POST(`${config.repoLink}/markup`, {data: form});
    return resp.ok ? resp.text() : '';
  };

  class PreviewPane extends SimpleEditorPane {
    static readonly ID = PREVIEW_EDITOR;

    constructor(group: IEditorGroup) {
      super(PreviewPane.ID, group);
    }

    initialize(): HTMLElement {
      const container = document.createElement('div');
      container.style.height = '100%';
      return container;
    }

    async renderInput(input: PreviewInput) {
      const fileService = await getService(IFileService);
      let url = '';
      const render = async () => {
        const content = (await fileService.readFile(input.resource)).value.buffer;
        const path = repoPathOf(config, input.resource.path);
        const extension = extensionOf(path);
        if (imageExtensions.includes(extension)) {
          URL.revokeObjectURL(url);
          url = URL.createObjectURL(new Blob([content as Uint8Array<ArrayBuffer>], {type: imageTypes[extension] ?? `image/${extension}`}));
          const img = document.createElement('img');
          img.src = url;
          img.alt = path;
          img.style.cssText = 'max-width: 100%; display: block; margin: 16px auto;';
          this.container.replaceChildren(img);
          return;
        }
        const frame = document.createElement('iframe');
        frame.sandbox.value = ''; // no scripts, no same-origin access
        frame.style.cssText = 'width: 100%; height: 100%; border: 0; background: var(--vscode-editor-background);';
        frame.srcdoc = `<!DOCTYPE html><html data-theme="${config.themeName}"><head><meta charset="utf-8">
<link rel="stylesheet" href="${config.assetUrlPrefix}/css/index.css"><link rel="stylesheet" href="${config.assetUrlPrefix}/css/theme-${config.themeName}.css">
</head><body><div class="markup tw-p-4">${await markdownHTML(path, new TextDecoder().decode(content))}</div></body></html>`;
        this.container.replaceChildren(frame);
      };
      await render();
      const changes = fileService.onDidFilesChange(async (e) => {
        // a deleted file has nothing left to show
        if (e.contains(input.resource) && await fileService.exists(input.resource)) await render();
      });
      return {dispose: () => {
        changes.dispose();
        URL.revokeObjectURL(url);
      }};
    }
  }

  class PreviewInput extends SimpleEditorInput {
    constructor(resource: URI) {
      super(resource);
      this.setName(`${config.strings.preview}: ${resource.path.slice(resource.path.lastIndexOf('/') + 1)}`);
    }

    get typeId(): string {
      return PreviewPane.ID;
    }
  }

  registerEditorPane(PREVIEW_EDITOR, config.strings.preview, PreviewPane, [PreviewInput]);
  const factory = {createEditorInput: ({resource}) => ({editor: new PreviewInput(resource)})};
  registerEditor(`*.{${imageExtensions.join(',')}}`, {
    id: PREVIEW_EDITOR,
    label: config.strings.preview,
    priority: {editor: RegisteredEditorPriority.default, diff: RegisteredEditorPriority.option, merge: RegisteredEditorPriority.option},
  }, {singlePerResource: true}, factory);
  registerEditor(`*.{${markdownExtensions.join(',')}}`, {
    id: PREVIEW_EDITOR,
    label: config.strings.preview,
    priority: {editor: RegisteredEditorPriority.option, diff: RegisteredEditorPriority.option, merge: RegisteredEditorPriority.option},
  }, {singlePerResource: true}, factory);
}
