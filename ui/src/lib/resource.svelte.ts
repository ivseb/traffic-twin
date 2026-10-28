// Tiny async data helper. Re-runs when reactive values read synchronously by
// `fetcher` change, or when `reload()` is called. Keeps the previous data while
// reloading so lists do not flash.

export interface Resource<T> {
  readonly data: T | undefined;
  readonly error: Error | undefined;
  readonly loading: boolean;
  /** Epoch ms of the last successful load. */
  readonly updatedAt: number | undefined;
  reload(): void;
}

export function resource<T>(fetcher: () => Promise<T>): Resource<T> {
  let data = $state<T | undefined>(undefined);
  let error = $state<Error | undefined>(undefined);
  let loading = $state(true);
  let updatedAt = $state<number | undefined>(undefined);
  let tick = $state(0);

  $effect(() => {
    void tick;
    let cancelled = false;
    loading = true;
    fetcher().then(
      (v) => {
        if (cancelled) return;
        data = v;
        updatedAt = Date.now();
        error = undefined;
        loading = false;
      },
      (e) => {
        if (cancelled) return;
        error = e instanceof Error ? e : new Error(String(e));
        loading = false;
      },
    );
    return () => {
      cancelled = true;
    };
  });

  return {
    get data() {
      return data;
    },
    get error() {
      return error;
    },
    get loading() {
      return loading;
    },
    get updatedAt() {
      return updatedAt;
    },
    reload() {
      tick++;
    },
  };
}
