import { AIDError } from '../core/errors.js';
import type { AIDStorage } from '../core/types.js';

export class MemoryStorage implements AIDStorage {
  private readonly map = new Map<string, string>();
  get(key: string): string | null {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  set(key: string, value: string): void {
    this.map.set(key, value);
  }
  remove(key: string): void {
    this.map.delete(key);
  }
}

class WebStorageAdapter implements AIDStorage {
  constructor(private readonly backing: Storage) {}
  get(key: string): string | null {
    return this.backing.getItem(key);
  }
  set(key: string, value: string): void {
    this.backing.setItem(key, value);
  }
  remove(key: string): void {
    this.backing.removeItem(key);
  }
}

/**
 * Default storage for the browser SDK.
 * The OAuth redirect navigates away from the app; an in-memory map cannot
 * survive that, so sessionStorage is the correct default.
 */
export class SessionStorage implements AIDStorage {
  private readonly impl: WebStorageAdapter;
  constructor() {
    if (typeof globalThis.sessionStorage === 'undefined') {
      throw new AIDError('STORAGE_ERROR', 'sessionStorage is not available in this environment');
    }
    this.impl = new WebStorageAdapter(globalThis.sessionStorage);
  }
  get(key: string): string | null {
    return this.impl.get(key);
  }
  set(key: string, value: string): void {
    this.impl.set(key, value);
  }
  remove(key: string): void {
    this.impl.remove(key);
  }
}

export class LocalStorage implements AIDStorage {
  private readonly impl: WebStorageAdapter;
  constructor() {
    if (typeof globalThis.localStorage === 'undefined') {
      throw new AIDError('STORAGE_ERROR', 'localStorage is not available in this environment');
    }
    this.impl = new WebStorageAdapter(globalThis.localStorage);
  }
  get(key: string): string | null {
    return this.impl.get(key);
  }
  set(key: string, value: string): void {
    this.impl.set(key, value);
  }
  remove(key: string): void {
    this.impl.remove(key);
  }
}