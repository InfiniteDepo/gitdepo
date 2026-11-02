import type {IDEConfig} from './api.ts';

// the working tree, and the committed files the changes are compared with
export const SCHEME = 'gitdepo';
export const BASE_SCHEME = 'gitdepo-base';

// the workspace folder is named after the repository, so each repository keeps its own open editors
export const rootPath = (config: IDEConfig) => `/${config.repoName}`;

export function repoPathOf(config: IDEConfig, uriPath: string): string {
  const root = rootPath(config);
  return uriPath === root ? '' : uriPath.slice(root.length + 1);
}
