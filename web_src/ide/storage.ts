// Uncommitted changes stay in this browser's IndexedDB until they are committed or discarded.
import type {SavedChanges} from './workspace.ts';

function store(mode: IDBTransactionMode): Promise<IDBObjectStore> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('gitdepo-ide', 1);
    open.addEventListener('upgradeneeded', () => open.result.createObjectStore('changes'));
    open.addEventListener('success', () => resolve(open.result.transaction('changes', mode).objectStore('changes')));
    open.addEventListener('error', () => reject(open.error));
  });
}

function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.addEventListener('success', () => resolve(req.result));
    req.addEventListener('error', () => reject(req.error));
  });
}

export async function loadChanges(key: string): Promise<SavedChanges | undefined> {
  try {
    return await done((await store('readonly')).get(key));
  } catch {
    return undefined; // a private window may have no IndexedDB
  }
}

export async function saveChanges(key: string, changes: SavedChanges | undefined) {
  try {
    const changesStore = await store('readwrite');
    await done(changes ? changesStore.put(changes, key) : changesStore.delete(key));
  } catch {
    // the changes then only live in this page
  }
}
