export interface ProductWaistConformanceCase {
  readonly id: string;
  run(expected: ProductWaistExpected): void | Promise<void>;
}

export interface ProductWaistExpected {
  readonly boundary: string;
  readonly code: string;
}

export interface ProductWaistConformanceReport {
  readonly schema: "auths.simplified-product-waist-conformance-result/1";
  readonly manifestSchema: "auths.simplified-product-waist-conformance/1";
  readonly fixtureProjection: string;
  readonly passed: readonly string[];
}

interface ManifestCase extends ProductWaistExpected {
  readonly id: string;
}

interface ProductWaistManifest {
  readonly schema: "auths.simplified-product-waist-conformance/1";
  readonly semanticOwner: "Rust";
  readonly fixtureProjection: string;
  readonly cases: readonly ManifestCase[];
}

export async function productWaistConformance(
  manifestInput: unknown,
  cases: readonly ProductWaistConformanceCase[],
): Promise<ProductWaistConformanceReport> {
  const manifest = parseManifest(manifestInput);
  const implementations = new Map<string, ProductWaistConformanceCase>();
  for (const candidate of cases) {
    if (!validIdentifier(candidate.id) || implementations.has(candidate.id)) {
      throw new TypeError(`invalid or duplicate product-waist case: ${candidate.id}`);
    }
    implementations.set(candidate.id, candidate);
  }
  const required = manifest.cases.map((candidate) => candidate.id);
  const missing = required.filter((id) => !implementations.has(id));
  const unexpected = [...implementations.keys()].filter((id) => !required.includes(id));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new TypeError(
      `product-waist case mismatch; missing=${missing.join(",")}; unexpected=${unexpected.join(",")}`,
    );
  }
  for (const expected of manifest.cases) {
    await implementations.get(expected.id)?.run(Object.freeze({
      boundary: expected.boundary,
      code: expected.code,
    }));
  }
  return Object.freeze({
    schema: "auths.simplified-product-waist-conformance-result/1",
    manifestSchema: manifest.schema,
    fixtureProjection: manifest.fixtureProjection,
    passed: Object.freeze(required),
  });
}

function parseManifest(input: unknown): ProductWaistManifest {
  if (!isRecord(input)) throw new TypeError("product-waist manifest must be an object");
  const schema = text(input.schema, "schema");
  const semanticOwner = text(input.semanticOwner, "semanticOwner");
  const fixtureProjection = text(input.fixtureProjection, "fixtureProjection");
  if (
    schema !== "auths.simplified-product-waist-conformance/1" ||
    semanticOwner !== "Rust" ||
    !Array.isArray(input.cases)
  ) {
    throw new TypeError("unsupported product-waist manifest");
  }
  const seen = new Set<string>();
  const cases = input.cases.map((value): ManifestCase => {
    if (!isRecord(value)) throw new TypeError("product-waist case must be an object");
    const id = text(value.id, "case id");
    const boundary = text(value.boundary, "case boundary");
    const code = text(value.expected, "case expected code");
    if (!validIdentifier(id) || seen.has(id)) {
      throw new TypeError(`invalid or duplicate product-waist case: ${id}`);
    }
    seen.add(id);
    return Object.freeze({ id, boundary, code });
  });
  return Object.freeze({
    schema,
    semanticOwner,
    fixtureProjection,
    cases: Object.freeze(cases),
  });
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) {
    throw new TypeError(`product-waist ${name} is invalid`);
  }
  return value;
}

function validIdentifier(value: string): boolean {
  return /^[a-z0-9-]+\/[a-z0-9-]+$/.test(value);
}
