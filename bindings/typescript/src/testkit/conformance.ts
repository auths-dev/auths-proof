import type { Signer } from "../custody.js";
import { development } from "../integrations.js";
import {
  mcp,
  type McpClosedProvider,
  type McpHandlerOutcome,
  type McpToolContext,
} from "../mcp.js";
import { CONFORMANCE_CATALOG } from "../generated/mechanism-conformance.js";
import { custodyConformance } from "./custody-conformance.js";

export interface ConformanceMetadata {
  readonly implementation: string;
  readonly version: string;
  readonly runtime?: string;
  readonly capabilities?: readonly string[];
}

export interface ConformanceCaseResult {
  readonly id: string;
  readonly classification: "deterministic";
  readonly passed: boolean;
}

export interface ConformanceReport {
  readonly schema: "auths.conformance-report/1";
  readonly suite: string;
  readonly suiteVersion: 1;
  readonly semanticSubject: "auths.mechanism-profile-conformance/1";
  readonly implementation: string;
  readonly implementationVersion: string;
  readonly runtime: string;
  readonly capabilities: readonly string[];
  readonly results: readonly ConformanceCaseResult[];
  readonly passed: boolean;
  readonly claim: "test-results-only-not-security-certification";
}

export interface AtomicReservationRecord {
  readonly key: string;
  readonly commitment: Uint8Array;
  readonly value: Uint8Array;
}

export interface AtomicReservationStoreCandidate {
  reserve(record: AtomicReservationRecord): Promise<"acquired" | "exact-replay" | "conflict">;
  reopen?(): AtomicReservationStoreCandidate | Promise<AtomicReservationStoreCandidate>;
  close?(): void | Promise<void>;
}

export interface ByteTransportCandidate {
  exchange(
    packet: Uint8Array,
    options: Readonly<{ maximumBytes: number; signal: AbortSignal }>,
  ): Promise<Uint8Array>;
  close?(): void | Promise<void>;
}

export type ByteTransportFactory = (
  deliver: (packet: Uint8Array) => Uint8Array | Promise<Uint8Array>,
) => ByteTransportCandidate | Promise<ByteTransportCandidate>;

export type McpProviderFactory = (options: Readonly<{
  service?: string;
  tools: Readonly<Record<string, (
    argumentsValue: Readonly<Record<string, unknown>>,
    context: McpToolContext,
  ) => unknown | Promise<unknown>>>;
  reconcile?: (executionId: string, service: string) => McpHandlerOutcome<unknown> | Promise<McpHandlerOutcome<unknown>>;
}>) => McpClosedProvider;

export async function certifySigner(
  factory: () => Signer | Promise<Signer>,
  metadata: ConformanceMetadata,
): Promise<ConformanceReport> {
  const observed = await custodyConformance({ create: async () => factory() });
  return report(
    "signer-custody/1",
    metadata,
    observed.results.map((result) => [`signer/${result.name}`, result.passed] as const),
  );
}

export async function certifyAtomicStore(
  factory: () => AtomicReservationStoreCandidate | Promise<AtomicReservationStoreCandidate>,
  metadata: ConformanceMetadata,
): Promise<ConformanceReport> {
  const record = reservation("case", 1, new Uint8Array([3]));
  const outcomes: Array<readonly [string, boolean]> = [];
  outcomes.push(["atomic-store/acquire", await atomicCase(factory, async (store) =>
    await store.reserve(record) === "acquired")]);
  outcomes.push(["atomic-store/exact-replay", await atomicCase(factory, async (store) =>
    await store.reserve(record) === "acquired" && await store.reserve(record) === "exact-replay")]);
  outcomes.push(["atomic-store/conflict", await atomicCase(factory, async (store) =>
    await store.reserve(record) === "acquired"
      && await store.reserve(reservation("case", 2, new Uint8Array([4]))) === "conflict")]);
  outcomes.push(["atomic-store/concurrent-single-winner", await atomicCase(factory, async (store) => {
    const values = await Promise.all(Array.from({ length: 8 }, () => store.reserve(record)));
    return values.filter((value) => value === "acquired").length === 1
      && values.filter((value) => value === "exact-replay").length === 7;
  })]);
  outcomes.push(["atomic-store/bounded-record", await atomicCase(factory, async (store) => {
    try {
      await store.reserve(reservation("oversized", 1, new Uint8Array(262_145)));
      return false;
    } catch {
      return true;
    }
  })]);
  const first = await factory();
  const second = await factory();
  try {
  outcomes.push(["atomic-store/isolated-instances",
      await first.reserve(record) === "acquired" && await second.reserve(record) === "acquired"]);
  } catch {
    outcomes.push(["atomic-store/isolated-instances", false]);
  } finally {
    await first.close?.();
    await second.close?.();
  }
  outcomes.push(["atomic-store/reopen-durability-claim", await durabilityCase(factory, record, metadata)]);
  return report("atomic-reservation-store/1", metadata, outcomes);
}

export async function certifyByteTransport(
  factory: ByteTransportFactory,
  metadata: ConformanceMetadata,
): Promise<ConformanceReport> {
  const outcomes: Array<readonly [string, boolean]> = [];
  outcomes.push(["byte-transport/exact-bytes", await transportCase(factory, (packet) => packet, async (transport) => {
    const value = new Uint8Array([1, 2, 3]);
    return equalBytes(await transport.exchange(value, transportOptions(16)), value);
  })]);
  outcomes.push(["byte-transport/bounded-input", await transportCase(factory, (packet) => packet, async (transport) => {
    try {
      await transport.exchange(new Uint8Array(17), transportOptions(16));
      return false;
    } catch {
      return true;
    }
  })]);
  outcomes.push(["byte-transport/bounded-output", await transportCase(factory, () => new Uint8Array(17), async (transport) => {
    try {
      await transport.exchange(new Uint8Array([1]), transportOptions(16));
      return false;
    } catch {
      return true;
    }
  })]);
  outcomes.push(["byte-transport/cancellation", await transportCase(factory, (packet) => packet, async (transport) => {
    const controller = new AbortController();
    controller.abort();
    try {
      await transport.exchange(new Uint8Array([1]), { maximumBytes: 16, signal: controller.signal });
      return false;
    } catch {
      return true;
    }
  })]);
  outcomes.push(["byte-transport/disposal", await transportCase(factory, (packet) => packet, async (transport) => {
    if (transport.close === undefined) return false;
    await transport.close();
    try {
      await transport.exchange(new Uint8Array([1]), transportOptions(16));
      return false;
    } catch {
      return true;
    }
  }, false)]);
  return report("bounded-byte-transport/1", metadata, outcomes);
}

export async function certifyMcpProvider(
  factory: McpProviderFactory,
  metadata: ConformanceMetadata,
): Promise<ConformanceReport> {
  const outcomes: Array<readonly [string, boolean]> = [];
  let calls = 0;
  let requestBound = false;
  const exact = factory({ tools: { async publish_report(argumentsValue, context) {
    calls += 1;
    requestBound = argumentsValue.report === "weekly"
      && context.service === "development"
      && context.tool === "publish_report";
    return { ok: true };
  } } });
  const auths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
  try {
    const action = mcp.callTool({ name: "publish_report", arguments: { report: "weekly" } });
    const completed = await auths.execute({ action, provider: exact, requestId: "conformance-exact" });
    outcomes.push(["mcp/exact-call", completed.kind === "completed" && calls === 1 && requestBound]);
    const denied = await auths.execute({
      action: mcp.callTool({ name: "delete_report", arguments: {} }),
      provider: exact,
      requestId: "conformance-denied",
    });
    outcomes.push(["mcp/deny-before-entry", denied.kind === "denied" && calls === 1]);
    const concurrent = await Promise.all([
      auths.execute({ action, provider: exact, requestId: "conformance-concurrent" }),
      auths.execute({ action, provider: exact, requestId: "conformance-concurrent" }),
    ]);
    outcomes.push(["mcp/concurrent-single-entry",
      concurrent.map((value) => value.kind).sort().join(",") === "completed,exact-replay" && calls === 2]);
  } catch {
    outcomes.push(["mcp/exact-call", false], ["mcp/deny-before-entry", false], ["mcp/concurrent-single-entry", false]);
  } finally {
    await auths.close();
  }

  let ambiguousCalls = 0;
  const recoveryAuths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
  try {
    const pending = await recoveryAuths.execute({
      action: mcp.callTool({ name: "publish_report", arguments: {} }),
      provider: factory({ tools: { async publish_report() {
        ambiguousCalls += 1;
        return { effect: "possible", cause: "unknown" };
      } } }),
      requestId: "conformance-recovery",
    });
    outcomes.push(["mcp/ambiguous-no-blind-retry", pending.kind === "recoverable" && ambiguousCalls === 1]);
    const resumed = pending.kind === "recoverable" && pending.reference !== undefined
      ? await recoveryAuths.resume({
        reference: pending.reference,
        provider: factory({
          tools: { async publish_report() { ambiguousCalls += 100; } },
          async reconcile() { return { effect: "applied", result: { ok: true } }; },
        }),
      })
      : undefined;
    outcomes.push(["mcp/reconcile-without-reentry", resumed?.kind === "completed" && ambiguousCalls === 1]);
  } catch {
    outcomes.push(["mcp/ambiguous-no-blind-retry", false], ["mcp/reconcile-without-reentry", false]);
  } finally {
    await recoveryAuths.close();
  }

  const serviceAuths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
  try {
    await serviceAuths.execute({
      action: mcp.callTool({ name: "publish_report", arguments: {} }),
      provider: factory({ service: "other", tools: { async publish_report() {} } }),
    });
    outcomes.push(["mcp/service-binding", false]);
  } catch {
    outcomes.push(["mcp/service-binding", true]);
  } finally {
    await serviceAuths.close();
  }

  const boundedAuths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
  try {
    const bounded = await boundedAuths.execute({
      action: mcp.callTool({ name: "publish_report", arguments: {} }),
      provider: factory({ tools: { async publish_report() { return "x".repeat(1_048_577); } } }),
    });
    outcomes.push(["mcp/bounded-output", bounded.kind !== "completed"]);
  } catch {
    outcomes.push(["mcp/bounded-output", true]);
  } finally {
    await boundedAuths.close();
  }
  return report("auths.mcp/1/provider/1", metadata, outcomes);
}

export { CONFORMANCE_CATALOG };

async function atomicCase(
  factory: () => AtomicReservationStoreCandidate | Promise<AtomicReservationStoreCandidate>,
  exercise: (store: AtomicReservationStoreCandidate) => Promise<boolean>,
): Promise<boolean> {
  const store = await factory();
  try {
    return await exercise(store);
  } catch {
    return false;
  } finally {
    await store.close?.();
  }
}

async function durabilityCase(
  factory: () => AtomicReservationStoreCandidate | Promise<AtomicReservationStoreCandidate>,
  record: AtomicReservationRecord,
  metadata: ConformanceMetadata,
): Promise<boolean> {
  if (!(metadata.capabilities ?? []).includes("durable-reopen")) return true;
  const first = await factory();
  let second: AtomicReservationStoreCandidate | undefined;
  try {
    if (await first.reserve(record) !== "acquired" || first.reopen === undefined) return false;
    second = await first.reopen();
    return await second.reserve(record) === "exact-replay";
  } catch {
    return false;
  } finally {
    await second?.close?.();
    await first.close?.();
  }
}

async function transportCase(
  factory: ByteTransportFactory,
  deliver: (packet: Uint8Array) => Uint8Array | Promise<Uint8Array>,
  exercise: (transport: ByteTransportCandidate) => Promise<boolean>,
  close = true,
): Promise<boolean> {
  const transport = await factory(deliver);
  try {
    return await exercise(transport);
  } catch {
    return false;
  } finally {
    if (close) await transport.close?.();
  }
}

function report(
  suite: string,
  metadata: ConformanceMetadata,
  outcomes: readonly (readonly [string, boolean])[],
): ConformanceReport {
  const expected = CONFORMANCE_CATALOG.suites.find((candidate) => candidate.id === suite);
  if (expected === undefined) throw new TypeError("unknown Auths conformance suite");
  const supplied = new Map(outcomes);
  const results = expected.cases.map((candidate) => Object.freeze({
    id: candidate.id,
    classification: candidate.classification,
    passed: supplied.get(candidate.id) === true,
  }));
  const implementation = bounded(metadata.implementation, "implementation");
  const version = bounded(metadata.version, "implementation version");
  const runtime = bounded(metadata.runtime ?? "javascript", "runtime");
  const capabilities = Object.freeze((metadata.capabilities ?? []).map((value) => bounded(value, "capability")));
  return Object.freeze({
    schema: "auths.conformance-report/1",
    suite,
    suiteVersion: 1,
    semanticSubject: "auths.mechanism-profile-conformance/1",
    implementation,
    implementationVersion: version,
    runtime,
    capabilities,
    results: Object.freeze(results),
    passed: results.every((result) => result.passed),
    claim: "test-results-only-not-security-certification",
  });
}

function reservation(key: string, byte: number, value: Uint8Array): AtomicReservationRecord {
  return Object.freeze({ key, commitment: new Uint8Array(32).fill(byte), value });
}

function transportOptions(maximumBytes: number): Readonly<{ maximumBytes: number; signal: AbortSignal }> {
  return Object.freeze({ maximumBytes, signal: new AbortController().signal });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function bounded(value: string, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || /[\r\n]/u.test(value)) {
    throw new TypeError(`invalid conformance ${name}`);
  }
  return value;
}
