export type AdapterKind =
  | "signer"
  | "approval"
  | "identity-method"
  | "signature-suite"
  | "resolver"
  | "status"
  | "clock"
  | "store"
  | "telemetry"
  | "transport"
  | "gateway";

export interface AdapterMetadata {
  readonly implementationId: string;
  readonly implementationVersion: string;
  readonly contract: Readonly<{ readonly kind: AdapterKind; readonly version: "1" }>;
  readonly runtimes: readonly string[];
  readonly supportOwner: string;
  readonly securityClaims: readonly string[];
}

export interface AdapterConformanceCase {
  readonly id: string;
  run(): void | Promise<void>;
}

export interface AdapterConformanceOptions {
  readonly metadata: AdapterMetadata;
  readonly cases: readonly AdapterConformanceCase[];
}

export interface AdapterConformanceReport {
  readonly metadata: AdapterMetadata;
  readonly passed: readonly string[];
  readonly certifiedAt: string;
}

const REQUIRED_CASES: Readonly<Record<AdapterKind, readonly string[]>> = Object.freeze({
  signer: ["exact-request", "mismatch", "rejection", "cancellation", "timeout", "disposal"],
  approval: ["exact-request", "mismatch", "rejection", "cancellation", "timeout", "duplicate"],
  "identity-method": ["exact-method", "wrong-method", "purpose", "rotation", "downgrade"],
  "signature-suite": ["exact-suite", "wrong-suite", "changed-message", "purpose", "downgrade"],
  resolver: ["provenance", "freshness", "size", "redirect", "ssrf", "cancellation", "timeout"],
  status: ["missing", "stale", "conflict", "unavailable", "provenance"],
  clock: ["boundary", "monotonic", "unavailable"],
  store: ["reserve", "duplicate", "compare-and-set", "concurrency", "reopen", "unavailable"],
  telemetry: ["redaction", "bounded", "exporter-failure"],
  transport: ["bounded", "cancellation", "timeout", "substitution"],
  gateway: ["forgery", "mismatch", "idempotency", "failure", "outcome-unknown", "reconciliation"],
});

/** Runs the mandatory contract cases and returns publishable certification metadata. */
export async function adapterConformance(
  options: AdapterConformanceOptions,
): Promise<AdapterConformanceReport> {
  const metadata = parseMetadata(options.metadata);
  const cases = new Map<string, AdapterConformanceCase>();
  for (const candidate of options.cases) {
    if (candidate.id.length === 0 || cases.has(candidate.id)) {
      throw new TypeError(`duplicate or empty adapter conformance case: ${candidate.id}`);
    }
    cases.set(candidate.id, candidate);
  }
  const required = REQUIRED_CASES[metadata.contract.kind];
  const missing = required.filter((id) => !cases.has(id));
  if (missing.length > 0) throw new TypeError(`missing adapter conformance cases: ${missing.join(", ")}`);
  for (const id of required) await cases.get(id)?.run();
  return Object.freeze({
    metadata,
    passed: Object.freeze([...required]),
    certifiedAt: new Date().toISOString(),
  });
}

function parseMetadata(metadata: AdapterMetadata): AdapterMetadata {
  const texts = [
    metadata.implementationId,
    metadata.implementationVersion,
    metadata.supportOwner,
    ...metadata.runtimes,
    ...metadata.securityClaims,
  ];
  if (metadata.contract.version !== "1" || texts.some((value) =>
    typeof value !== "string" || value.length === 0 || value.length > 256
  ) || metadata.runtimes.length === 0) {
    throw new TypeError("adapter certification metadata is invalid");
  }
  return Object.freeze({
    ...metadata,
    contract: Object.freeze({ ...metadata.contract }),
    runtimes: Object.freeze([...metadata.runtimes]),
    securityClaims: Object.freeze([...metadata.securityClaims]),
  });
}
