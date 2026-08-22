import { AuthsError, parseAuthsErrorEnvelope } from "../product-errors.js";

/**
 * The WASM boundary guard.
 *
 * Rust hands JavaScript a real `Error` whose own properties are an
 * `auths.error/1` envelope. That envelope is the Rust-owned error model; this
 * module is the single place where it becomes the public {@link AuthsError}, so
 * no caller of any entry point ever has to know that a failure originated
 * across an ABI.
 *
 * The guard wraps the packaged module once, at load, rather than asking every
 * call site to remember a `try`/`catch`. A call site that forgets is a silent
 * hole in the effect axis; there is no call site to forget here.
 */

const wrappers = new WeakMap<object, unknown>();

/**
 * Rehydrates one thrown value into the public error type.
 *
 * A value that is not a Rust error envelope is returned untouched: a
 * programmer error or a contract violation raised by TypeScript itself must
 * never be relabelled as an authorization outcome (contract 5.7).
 */
export function boundaryError(thrown: unknown): unknown {
  if (thrown instanceof AuthsError) return thrown;
  if (typeof thrown !== "object" || thrown === null) return thrown;
  if ((thrown as { readonly schema?: unknown }).schema !== "auths.error/1") return thrown;
  return parseAuthsErrorEnvelope(thrown);
}

/**
 * Wraps the packaged WASM namespace so every failure it raises — from a
 * top-level call, a constructor, or a method on an object it returned —
 * reaches the caller as an {@link AuthsError}.
 */
export function guardWasmBoundary<T extends object>(module: T): T {
  return guardObject(module) as T;
}

function guardObject<T extends object>(value: T): T {
  const existing = wrappers.get(value);
  if (existing !== undefined) return existing as T;
  const proxy = new Proxy(value, {
    get(target, property, receiver) {
      const member: unknown = Reflect.get(target, property, receiver);
      return typeof member === "function" ? guardFunction(member as CallableFunction) : member;
    },
  });
  wrappers.set(value, proxy);
  return proxy as T;
}

/**
 * Guards one boundary-crossing call.
 *
 * The value a guarded call RETURNS is handed back untouched, including a
 * `wasm-bindgen` handle. Wrapping a handle is not safe: `wasm-bindgen` tracks
 * ownership and finalization by object identity, so a proxy makes
 * `FinalizationRegistry.unregister` miss and lets a live borrow be freed —
 * observed as "attempted to take ownership of Rust value while it was
 * borrowed". Handles therefore stay raw, and the methods that own them are
 * guarded where the SDK holds them, never by re-wrapping the handle.
 */
function guardFunction(value: CallableFunction): CallableFunction {
  const existing = wrappers.get(value);
  if (existing !== undefined) return existing as CallableFunction;
  const proxy = new Proxy(value, {
    apply(target, thisArg, argumentsList) {
      try {
        return Reflect.apply(target as (...args: unknown[]) => unknown, thisArg, argumentsList);
      } catch (error) {
        throw boundaryError(error);
      }
    },
    construct(target, argumentsList, newTarget) {
      try {
        return Reflect.construct(target as unknown as new (...args: unknown[]) => object, argumentsList, newTarget);
      } catch (error) {
        throw boundaryError(error);
      }
    },
  });
  wrappers.set(value, proxy);
  return proxy;
}
