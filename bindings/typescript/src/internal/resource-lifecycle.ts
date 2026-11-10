import { AuthsWorkflowError } from "./operation-errors.js";

/** Per-caller cancellation is separate from ownership of an asynchronous task. */
export interface LifecycleWaitOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export type CleanupRetry = "idempotent" | "unsafe";

interface Completion<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function completion<T>(): Completion<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  // An owner survives its last waiter. Retaining its outcome must not raise an
  // unhandled rejection when all waiters detached or closing invalidated opening.
  void promise.catch(() => {});
  return { promise, resolve, reject };
}

function disposed(): AuthsWorkflowError {
  return new AuthsWorkflowError("disposed", "Auths resource is disposed or not open");
}

function incomplete(): AuthsWorkflowError {
  return new AuthsWorkflowError("signer-failed", "Auths cleanup is incomplete", {
    causeChain: ["cleanup-incomplete"], effect: "possible", retry: "conditional",
  });
}

function cleanupFailed(): AuthsWorkflowError {
  return new AuthsWorkflowError("signer-failed", "Auths owned resource cleanup failed", {
    causeChain: ["cleanup-failed"], effect: "possible", retry: "conditional",
  });
}

export interface LifecycleTiming {
  now(): number;
  schedule(callback: () => void, delayMs: number): () => void;
}
const systemTiming: LifecycleTiming = {
  now: () => performance.now(),
  schedule(callback, delayMs) { const timer = setTimeout(callback, delayMs); return () => clearTimeout(timer); },
};

interface Wait {
  readonly signal: AbortSignal | undefined;
  readonly deadline: number | undefined;
}

function captureWait(options: LifecycleWaitOptions, timing: LifecycleTiming): Wait {
  const { signal, timeoutMs } = options;
  if (signal?.aborted) throw new AuthsWorkflowError("disposed", "Auths wait cancelled", { causeChain: ["cancelled"] });
  if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs <= 0)) throw new TypeError("timeoutMs must be finite and positive");
  return { signal, deadline: timeoutMs === undefined ? undefined : timing.now() + timeoutMs };
}

function waitError(cause: "cancelled" | "timeout"): AuthsWorkflowError {
  return new AuthsWorkflowError("disposed", `Auths wait ${cause}`, {
    causeChain: [cause], effect: "possible", retry: "conditional",
  });
}

/** Bounded timer observations avoid platform overflow on a long explicit deadline. */
function deadlineTimer(deadline: number | undefined, expired: () => void, timing: LifecycleTiming): () => void {
  if (deadline === undefined) return () => {};
  let cancel = () => {};
  const observe = () => {
    const remaining = deadline - timing.now();
    if (remaining <= 0) expired();
    else cancel = timing.schedule(observe, Math.min(remaining, 2147483647));
  };
  observe();
  return () => cancel();
}

function waitFor<T>(task: Promise<T>, wait: Wait, timing: LifecycleTiming, detached: () => void = () => {}): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let state: "waiting" | "settled" = "waiting";
    let cancelTimer = () => {};
    const finish = (action: () => void) => {
      if (state !== "waiting") return;
      state = "settled";
      cancelTimer();
      wait.signal?.removeEventListener("abort", aborted);
      action();
    };
    const aborted = () => finish(() => { detached(); reject(waitError("cancelled")); });
    wait.signal?.addEventListener("abort", aborted, { once: true });
    if (wait.signal?.aborted) aborted();
    if (state === "waiting") cancelTimer = deadlineTimer(wait.deadline, () => finish(() => { detached(); reject(waitError("timeout")); }), timing);
    task.then((value) => finish(() => resolve(value)), (error: unknown) => finish(() => reject(error)));
  });
}

interface CleanupAction {
  readonly run: (retry: boolean) => Promise<void>;
  readonly retry: CleanupRetry;
  readonly order: number;
}

type Obligation =
  | { readonly kind: "pending"; readonly action: CleanupAction }
  | { readonly kind: "failed"; readonly action: CleanupAction };

type CloseReason = { readonly kind: "closed" } | { readonly kind: "open-failed"; readonly result: Completion<void> };

interface Generation {
  readonly result: Completion<void>;
  readonly deadline: number | undefined;
  readonly reason: CloseReason;
}

type State =
  | { readonly kind: "new" }
  | { readonly kind: "opening"; readonly result: Completion<void> }
  | { readonly kind: "open" }
  | { readonly kind: "closing"; readonly generation: Generation }
  | { readonly kind: "closing-overdue"; readonly generation: Generation }
  | { readonly kind: "cleanup-failed"; readonly failure: AuthsWorkflowError; readonly reason: CloseReason }
  | { readonly kind: "closed"; readonly reason: CloseReason };

/**
 * Local resource ownership only: this class grants no authorization or provider
 * entry. Work tokens delay destruction; cleanup generations retain their own
 * result independently from waiters and from later explicit cleanup retries.
 */
export class ResourceLifecycle {
  #state: State;
  readonly #active = new Set<Promise<void>>();
  readonly #obligations = new Map<object, Obligation>();
  readonly #invalidations = new Set<() => void>();
  readonly #timing: LifecycleTiming;

  constructor(initial: "new" | "open" = "open", timing: LifecycleTiming = systemTiming) { this.#state = { kind: initial }; this.#timing = timing; }

  get state(): State["kind"] { return this.#state.kind; }
  get isOpen(): boolean { return this.#state.kind === "open"; }

  assertOpen(): void { if (!this.isOpen) throw disposed(); }

  /** Register one owned destructor. Borrowed resources are never registered. */
  own(key: object, run: (retry: boolean) => Promise<void>, retry: CleanupRetry = "unsafe", order = 0): void {
    if (this.#state.kind === "closed") throw disposed();
    if (!this.#obligations.has(key)) this.#obligations.set(key, { kind: "pending", action: { run, retry, order } });
  }

  /** Call only after another owner registered the exact cleanup obligation. */
  transfer(key: object): void { this.#obligations.delete(key); }

  async disposeOwned(key: object): Promise<void> {
    const obligation = this.#obligations.get(key);
    if (obligation !== undefined && obligation.kind === "pending") await this.#attempt(key, obligation);
  }

  #work<T>(operation: () => Promise<T>): Promise<T> {
    const done = completion<void>();
    this.#active.add(done.promise);
    let task: Promise<T>;
    try { task = Promise.resolve(operation()); } catch (error) { task = Promise.reject(error); }
    return task.finally(() => {
      this.#active.delete(done.promise);
      done.resolve(undefined);
    });
  }

  /** One opening task per instance; detaching a waiter never cancels that task. */
  open(initialize: () => Promise<void>, options: LifecycleWaitOptions = {}, opened: () => void = () => {}): Promise<void> {
    const wait = captureWait(options, this.#timing);
    if (this.#state.kind === "open") return Promise.resolve();
    if (this.#state.kind === "opening") return waitFor(this.#state.result.promise, wait, this.#timing);
    if (this.#state.kind !== "new") return Promise.reject(disposed());
    const result = completion<void>();
    this.#state = { kind: "opening", result };
    void this.#work(initialize).then(() => {
      if (this.#state.kind !== "opening" || this.#state.result !== result) return;
      this.#state = { kind: "open" };
      try {
        opened();
        if (this.isOpen) result.resolve(undefined);
        else result.reject(disposed());
      } catch (error) {
        result.reject(error);
        this.#startClose(undefined, false, { kind: "open-failed", result });
      }
    }, (error: unknown) => {
      result.reject(error);
      if (this.#state.kind === "opening" && this.#state.result === result) this.#startClose(undefined, false, { kind: "open-failed", result });
    });
    return waitFor(result.promise, wait, this.#timing);
  }

  /** Existing work drains while shutdown waits for its ownership token. */
  run<T>(operation: () => Promise<T>, options: LifecycleWaitOptions = {}): Promise<T> {
    const wait = captureWait(options, this.#timing);
    this.assertOpen();
    return waitFor(this.#work(operation), wait, this.#timing);
  }

  /** A late attachment cannot be published; its result remains an owned cleanup obligation. */
  publish<T extends object>(
    create: () => Promise<T>, destroy: (value: T, retry: boolean) => Promise<void>,
    options: LifecycleWaitOptions = {}, retry: CleanupRetry = "unsafe",
  ): Promise<T> {
    const wait = captureWait(options, this.#timing);
    this.assertOpen();
    let publication: "waiting" | "abandoned" | "published" = "waiting";
    const done = completion<void>();
    const invalidated = completion<T>();
    this.#active.add(done.promise);
    const invalidate = () => { publication = "abandoned"; invalidated.reject(disposed()); };
    this.#invalidations.add(invalidate);
    let created: Promise<T>;
    try { created = Promise.resolve(create()); } catch (error) { created = Promise.reject(error); }
    const owned = created.then((value) => {
      this.own(value, (attempt) => destroy(value, attempt), retry);
      return value;
    });
    return waitFor(Promise.race([owned, invalidated.promise]), wait, this.#timing, () => { publication = "abandoned"; }).then((value) => {
      if (!this.isOpen || publication !== "waiting" || wait.signal?.aborted ||
          (wait.deadline !== undefined && this.#timing.now() >= wait.deadline)) throw disposed();
      publication = "published";
      return value;
    }).finally(() => {
      this.#invalidations.delete(invalidate);
      // A cancelled waiter releases neither its creation task nor its late result.
      void owned.then(async (value) => {
        if (publication !== "published") {
          const obligation = this.#obligations.get(value);
          if (obligation !== undefined) await this.#attempt(value, obligation);
        }
      }, () => {}).finally(() => { this.#active.delete(done.promise); done.resolve(undefined); });
    });
  }

  close(options: LifecycleWaitOptions = {}): Promise<void> {
    const wait = captureWait(options, this.#timing);
    switch (this.#state.kind) {
      case "closed": return Promise.resolve();
      case "cleanup-failed": return Promise.reject(this.#state.failure);
      case "closing-overdue": return Promise.reject(incomplete());
      case "closing": return waitFor(this.#state.generation.result.promise, wait, this.#timing);
      default: return waitFor(this.#startClose(wait.deadline, false).result.promise, { signal: wait.signal, deadline: undefined }, this.#timing);
    }
  }

  retryCleanup(options: LifecycleWaitOptions = {}): Promise<void> {
    const wait = captureWait(options, this.#timing);
    switch (this.#state.kind) {
      case "closed": return Promise.resolve();
      case "closing": return waitFor(this.#state.generation.result.promise, wait, this.#timing);
      case "closing-overdue": return Promise.reject(incomplete());
      case "cleanup-failed":
        if (![...this.#obligations.values()].some((obligation) => obligation.action.retry === "idempotent")) return Promise.reject(this.#state.failure);
        return waitFor(this.#startClose(wait.deadline, true, this.#state.reason).result.promise, { signal: wait.signal, deadline: undefined }, this.#timing);
      default: return Promise.reject(disposed());
    }
  }

  #startClose(deadline: number | undefined, retry: boolean, reason: CloseReason = { kind: "closed" }): Generation {
    if (this.#state.kind === "opening") this.#state.result.reject(disposed());
    for (const invalidate of this.#invalidations) invalidate();
    const generation: Generation = { result: completion<void>(), deadline, reason };
    this.#state = { kind: "closing", generation };
    const cancelDeadline = deadlineTimer(deadline, () => {
      if (this.#state.kind === "closing" && this.#state.generation === generation) {
        this.#state = { kind: "closing-overdue", generation };
        generation.result.reject(incomplete());
      }
    }, this.#timing);
    void Promise.resolve().then(async () => {
      await Promise.all([...this.#active]);
      for (const [key, obligation] of [...this.#obligations].sort((left, right) => left[1].action.order - right[1].action.order)) {
        if (obligation.kind === "pending" || (retry && obligation.action.retry === "idempotent")) await this.#attempt(key, obligation, retry);
      }
      cancelDeadline();
      if (this.#obligations.size === 0) {
        this.#state = { kind: "closed", reason: generation.reason };
        generation.result.resolve(undefined);
      } else {
        const failure = cleanupFailed();
        this.#state = { kind: "cleanup-failed", failure, reason: generation.reason };
        generation.result.reject(failure);
      }
    }).catch(() => {
      cancelDeadline();
      const failure = cleanupFailed();
      this.#state = { kind: "cleanup-failed", failure, reason: generation.reason };
      generation.result.reject(failure);
    });
    return generation;
  }

  async #attempt(key: object, obligation: Obligation, retry = false): Promise<void> {
    try {
      await obligation.action.run(retry);
      this.#obligations.delete(key);
    } catch {
      this.#obligations.set(key, { kind: "failed", action: obligation.action });
    }
  }
}

// Retain factory owners after every waiter leaves, including settled cleanup
// failures. A successful publication transfers reachability to the returned owner.
const retainedFactories = new Set<ResourceLifecycle>();
export function openResource<T>(
  initialize: (owner: ResourceLifecycle) => Promise<T>, options: LifecycleWaitOptions = {},
): Promise<T> {
  const owner = new ResourceLifecycle("new");
  // Validate before creating work, including an already aborted caller.
  const wait = captureWait(options, systemTiming);
  retainedFactories.add(owner);
  let value: T;
  const opening = owner.open(async () => { value = await initialize(owner); });
  const closeAbandoned = () => {
    void owner.close().then(() => retainedFactories.delete(owner), () => {});
  };
  return waitFor(opening, wait, systemTiming, closeAbandoned).then(() => {
    retainedFactories.delete(owner);
    return value!;
  }, (error: unknown) => { closeAbandoned(); throw error; });
}
