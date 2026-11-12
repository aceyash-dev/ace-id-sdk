/**
 * Collapse concurrent callers into one in-flight operation.
 *
 * Discovery, JWKS fetches, token refreshes and profile requests all benefit from
 * the same guarantee: if five callers need the same network operation, they must
 * share one request rather than start five. Duplicated refreshes are not merely
 * wasteful — with rotating refresh tokens a second concurrent refresh can
 * invalidate the first one's result.
 *
 * The map is keyed by an arbitrary string so a single helper serves every call
 * site. Entries are always removed, including on failure, so a transient error
 * cannot poison the key permanently.
 */
export class SingleFlight {
  private readonly inFlight = new Map<string, Promise<unknown>>();

  /** Number of operations currently in flight (diagnostics and tests). */
  get size(): number {
    return this.inFlight.size;
  }

  has(key: string): boolean {
    return this.inFlight.has(key);
  }

  run<T>(key: string, operation: () => Promise<T>): Promise<T> {
    const existing = this.inFlight.get(key);
    if (existing) return existing as Promise<T>;

    const started = operation();
    // Register before any await so a synchronous throw cannot leave a gap.
    const settled: Promise<T> = started.finally(() => {
      // Only delete our own entry: a nested operation may have replaced it.
      if (this.inFlight.get(key) === settled) this.inFlight.delete(key);
    });
    this.inFlight.set(key, settled);
    return settled;
  }

  clear(): void {
    this.inFlight.clear();
  }
}

/** Shared helper for one-off call sites that do not own a {@link SingleFlight}. */
const sharedFlights = new SingleFlight();

export function singleFlight<T>(key: string, operation: () => Promise<T>): Promise<T> {
  return sharedFlights.run(key, operation);
}

/** Forget every shared in-flight operation (tests, or after a hard reset). */
export function clearSingleFlight(): void {
  sharedFlights.clear();
}
