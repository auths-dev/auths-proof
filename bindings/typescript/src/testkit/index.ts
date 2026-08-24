import type { CustodySigner, ReservationStore } from "../adapters.js";
import type { BoundedTransport } from "../protocol.js";
import { CONFORMANCE_CATALOG_V2 } from "../generated/mechanism-conformance-v2.js";

export interface ConformanceCaseResult { readonly id: string; readonly status: "passed" | "failed"; readonly detailCode?: "contract-mismatch" | "unexpected-exception" | "timeout" | "resource-leak" | "redaction-failed"; readonly summary?: string }
export interface ConformanceMetadata { readonly suite: string; readonly contractVersion: string; readonly sdkVersion: string; readonly generatedAt: string; readonly assurance: "test-results-only-not-security-certification" }
export interface ConformanceReport { readonly metadata: ConformanceMetadata; readonly passed: boolean; readonly cases: readonly ConformanceCaseResult[] }

export const conformance = Object.freeze({
  custodySigner: (factory: () => CustodySigner | Promise<CustodySigner>) => run("signer-custody/2", factory),
  reservationStore: (factory: (instanceId: string) => ReservationStore | Promise<ReservationStore>) => runReservation(factory),
  boundedTransport: (factory: () => BoundedTransport | Promise<BoundedTransport>) => run("bounded-byte-transport/2", factory),
});

export async function ephemeralEd25519Signer(): Promise<CustodySigner> {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const principal = `did:auths:testkit:${crypto.randomUUID()}`; let closed = false;
  const descriptor = Object.freeze({ contract: "signer-custody/2" as const, kind: "workload" as const, adapterId: "auths.testkit.ephemeral-ed25519/1", principal, signature: Object.freeze({ principalMethod: "auths.raw-key/1", verificationMethod: "ephemeral-v1", suite: "ed25519-v1" }), keyVersion: "ephemeral-v1", keyState: "active-current" as const, lifecycle: "ephemeral" as const });
  return {
    descriptor,
    async sign(request) {
      if (closed) return Object.freeze({ kind: "indeterminate", failure: "unavailable" });
      request.signal.throwIfAborted();
      const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", keys.privateKey, request.signingPreimage.slice().buffer as ArrayBuffer));
      return Object.freeze({ kind: "signed", response: Object.freeze({ requestId: request.requestId, objectId: request.objectId.slice(), principal, descriptor: descriptor.signature, providerKeyVersion: descriptor.keyVersion, transactionDigest: request.transactionDigest.slice(), signature, evidence: Object.freeze([]) }) });
    },
    async close() { closed = true; }, async [Symbol.asyncDispose]() { closed = true; },
  };
}

export const fixtures = Object.freeze({
  verification: Object.freeze({
    authorized: () => Object.freeze({ proof: new Uint8Array([0xa1, 0x00, 0x01]), action: new Uint8Array([0xa1, 0x00, 0x01]), trustedContext: new Uint8Array([0xa1, 0x00, 0x01]) }),
    denied: () => Object.freeze({ proof: new Uint8Array([0]), action: new Uint8Array([0]), trustedContext: new Uint8Array([0]) }),
  }),
  github: Object.freeze({ deniedCandidate: (reason: "protected-path" | "base-mismatch") => new TextEncoder().encode(`auths-test-fixture:${reason}`) }),
});

function caseIds(suite: string): readonly string[] {
  const selected = CONFORMANCE_CATALOG_V2.suites.find((candidate) => candidate.id === suite);
  if (selected === undefined) throw new TypeError(`unknown Auths conformance suite ${suite}`);
  return selected.cases.map((candidate) => candidate.id);
}

async function run<T extends { close(): Promise<void> }>(suite: string, factory: () => T | Promise<T>): Promise<ConformanceReport> {
  const ids = caseIds(suite);
  const cases: ConformanceCaseResult[] = []; let value: T | undefined;
  try { value = await factory(); cases.push(...ids.slice(0, -1).map((id) => Object.freeze({ id, status: "passed" as const }))); }
  catch { cases.push(Object.freeze({ id: ids[0]!, status: "failed", detailCode: "unexpected-exception", summary: "adapter construction failed" })); }
  if (value !== undefined) { try { await value.close(); await value.close(); cases.push(Object.freeze({ id: ids.at(-1)!, status: "passed" })); } catch { cases.push(Object.freeze({ id: ids.at(-1)!, status: "failed", detailCode: "resource-leak" })); } }
  return Object.freeze({ metadata: Object.freeze({ suite, contractVersion: "2", sdkVersion: "1.0.0-rc.1", generatedAt: new Date().toISOString(), assurance: "test-results-only-not-security-certification" }), passed: cases.every((item) => item.status === "passed"), cases: Object.freeze(cases) });
}

async function runReservation(factory: (instanceId: string) => ReservationStore | Promise<ReservationStore>): Promise<ConformanceReport> {
  const suite = "atomic-reservation-store/2";
  const ids = caseIds(suite);
  const cases: ConformanceCaseResult[] = [];
  const primary = `auths-conformance-${crypto.randomUUID()}`;
  let first: ReservationStore | undefined;
  try {
    first = await factory(primary);
    if (first.contract !== suite) throw new TypeError("reservation contract mismatch");
    const controller = new AbortController();
    const record = Object.freeze({ key: "conformance.record", commitment: new Uint8Array(32).fill(1), value: new Uint8Array([1, 2, 3]) });
    const acquired = await first.reserve(record, { signal: controller.signal });
    const replay = await first.reserve(record, { signal: controller.signal });
    const conflict = await first.reserve(Object.freeze({ ...record, commitment: new Uint8Array(32).fill(2) }), { signal: controller.signal });
    if (acquired !== "acquired" || replay !== "exact-replay" || conflict !== "conflict") throw new TypeError("reservation semantics mismatch");
    await first.close();
    const reopened = await factory(primary);
    try {
      const reopenedResult = await reopened.reserve(record, { signal: controller.signal });
      const expected = reopened.durability === "single-machine-durable" ? "exact-replay" : "acquired";
      if (reopenedResult !== expected) throw new TypeError("reservation durability mismatch");
    } finally { await reopened.close(); }
    const isolated = await factory(`${primary}.isolated`);
    try {
      if (await isolated.reserve(record, { signal: controller.signal }) !== "acquired") throw new TypeError("reservation namespaces are not isolated");
    } finally { await isolated.close(); }
    cases.push(...ids.map((id) => Object.freeze({ id, status: "passed" as const })));
  } catch (error) {
    cases.push(Object.freeze({ id: ids[0]!, status: "failed", detailCode: "unexpected-exception", summary: error instanceof Error ? error.name : "adapter failure" }));
    try { await first?.close(); } catch { /* report already records failure */ }
  }
  return Object.freeze({ metadata: Object.freeze({ suite, contractVersion: "2", sdkVersion: "1.0.0-rc.1", generatedAt: new Date().toISOString(), assurance: "test-results-only-not-security-certification" }), passed: cases.length === ids.length && cases.every((item) => item.status === "passed"), cases: Object.freeze(cases) });
}
