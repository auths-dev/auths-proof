import {
  X509Certificate,
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const MAX_DEPTH = 64;
const MAX_ITEMS = 1_000_000;

type V = {
  major: number;
  uint: bigint;
  bytes?: Uint8Array;
  text?: string;
  array?: V[];
  pairs?: Array<[V, V]>;
  raw: Uint8Array;
};

class Decoder {
  private offset = 0;
  private items = 0;
  private readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  complete(): V {
    const value = this.item(1);
    if (this.offset !== this.data.length) throw new Error("trailing CBOR bytes");
    return value;
  }

  private item(depth: number): V {
    if (depth > MAX_DEPTH || this.items >= MAX_ITEMS || this.offset >= this.data.length) {
      throw new Error("CBOR resource limit or truncation");
    }
    this.items += 1;
    const start = this.offset;
    const initial = this.data[this.offset++]!;
    const major = initial >>> 5;
    const additional = initial & 31;
    const argument = this.argument(additional);
    const value: V = { major, uint: argument, raw: new Uint8Array() };
    if (major === 2 || major === 3) {
      const length = this.length(argument, this.data.length - this.offset);
      const body = this.data.slice(this.offset, this.offset + length);
      this.offset += length;
      if (major === 2) value.bytes = body;
      else value.text = new TextDecoder("utf-8", { fatal: true }).decode(body);
    } else if (major === 4) {
      const length = this.length(argument, MAX_ITEMS - this.items);
      value.array = [];
      for (let index = 0; index < length; index += 1) value.array.push(this.item(depth + 1));
    } else if (major === 5) {
      const length = this.length(argument, Math.floor((MAX_ITEMS - this.items) / 2));
      value.pairs = [];
      let previous: Uint8Array | undefined;
      for (let index = 0; index < length; index += 1) {
        const key = this.item(depth + 1);
        if (previous !== undefined) {
          const order = compareCanonical(previous, key.raw);
          if (order === 0) throw new Error("duplicate CBOR map key");
          if (order > 0) throw new Error("non-canonical CBOR map key order");
        }
        previous = key.raw.slice();
        value.pairs.push([key, this.item(depth + 1)]);
      }
    } else if (major === 7) {
      if (![20, 21, 22].includes(additional)) {
        throw new Error("unsupported CBOR simple or floating value");
      }
    } else if (major !== 0 && major !== 1) {
      throw new Error("CBOR tags are not admitted");
    }
    value.raw = this.data.slice(start, this.offset);
    return value;
  }

  private argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (width === 0) throw new Error("indefinite or reserved CBOR argument");
    if (this.offset + width > this.data.length) throw new Error("truncated CBOR argument");
    let value = 0n;
    for (const octet of this.data.slice(this.offset, this.offset + width)) {
      value = (value << 8n) | BigInt(octet);
    }
    this.offset += width;
    if (
      (width === 1 && value < 24n) ||
      (width === 2 && value <= 0xffn) ||
      (width === 4 && value <= 0xffffn) ||
      (width === 8 && value <= 0xffffffffn)
    ) throw new Error("non-minimal CBOR argument");
    return value;
  }

  private length(value: bigint, maximum: number): number {
    if (value > BigInt(maximum)) throw new Error("CBOR length exceeds bound");
    return Number(value);
  }
}

function compareCanonical(left: Uint8Array, right: Uint8Array): number {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return Buffer.compare(left, right);
}

function exactMap(value: V, entries: number): void {
  if (value.major !== 5 || value.pairs?.length !== entries) {
    throw new Error(`expected CBOR map with ${entries} entries`);
  }
  value.pairs.forEach(([key], index) => {
    if (key.major !== 0 || key.uint !== BigInt(index)) throw new Error("unexpected CBOR map key");
  });
}

function mapAt(value: V, key: number): V {
  if (value.major !== 5) throw new Error("expected CBOR map");
  const pair = value.pairs?.find(([candidate]) => candidate.major === 0 && candidate.uint === BigInt(key));
  if (!pair) throw new Error(`missing CBOR map key ${key}`);
  return pair[1];
}

function text(value: V): string {
  if (value.major !== 3 || value.text === undefined) throw new Error("expected CBOR text");
  return value.text;
}

function bytes(value: V, length = -1): Uint8Array {
  if (value.major !== 2 || value.bytes === undefined || (length >= 0 && value.bytes.length !== length)) {
    throw new Error("unexpected CBOR byte string");
  }
  return value.bytes.slice();
}

function uint(value: V): bigint {
  if (value.major !== 0) throw new Error("expected CBOR unsigned integer");
  return value.uint;
}

function array(value: V): V[] {
  if (value.major !== 4 || value.array === undefined) throw new Error("expected CBOR array");
  return value.array;
}

function optionalBytes(value: V): Uint8Array | undefined {
  return value.major === 7 && value.uint === 22n ? undefined : bytes(value, 32);
}

type Profile = { id: string; version: bigint };
type Permission = { capability: string; resource: string };
type Budget = { algebra: string; value: bigint };
type StatusPolicy = { kind: bigint; method?: string; maxAge?: bigint };
type Constraint = { kind: bigint; digests: Uint8Array[] };
type Descriptor = { method: string; verificationMethod: string; suite: string; raw: Uint8Array };
type Signature = { descriptor: Descriptor; signature: Uint8Array };
type Extension = { id: string; bytes: Uint8Array };

type Grant = {
  statement: V;
  issuer: string;
  subject: string;
  profile: Profile;
  permissions: Permission[];
  notBefore: bigint;
  expiresAt: bigint;
  audiences: string[];
  constraint: Constraint;
  budget?: Budget;
  remainingDepth: bigint;
  parent?: Uint8Array;
  status: StatusPolicy;
  assurance: string;
  extensions: Extension[];
  signature: Signature;
  id: Uint8Array;
};

type Action = {
  envelope: V;
  profile: Profile;
  mediaType: string;
  bodyDigest: Uint8Array;
  permission: Permission;
  budget?: Budget;
  audience: string;
  challenge: Uint8Array;
  notBefore: bigint;
  expiresAt: bigint;
  actor: string;
  terminalGrant?: Uint8Array;
  planID: Uint8Array;
  channel: string;
  proofRef: Uint8Array;
  attachments: V[];
  extensions: Extension[];
  signature: Signature;
  id: Uint8Array;
};

type Plan = { kind: bigint; k: bigint; proofRef?: Uint8Array; children: Plan[]; raw: Uint8Array };
type Evidence = { id: Uint8Array; kind: string; mediaType: string; body: Uint8Array };
type StatementRef = { kind: bigint; id: Uint8Array };
type Binding = { statement: StatementRef; evidence: Uint8Array[] };
type PrincipalStatus = {
  statement: V; method: string; principal: string; state: bigint; sequence: bigint;
  observedAt: bigint; validUntil: bigint; issuer: string; signature: Signature; id: Uint8Array;
};
type GrantStatus = {
  statement: V; method: string; grantID: Uint8Array; state: bigint; sequence: bigint;
  observedAt: bigint; validUntil: bigint; issuer: string; signature: Signature; id: Uint8Array;
};
type StatusTrust = { method: string; issuer: string; minimumSequence: bigint };
type Snapshot<T> = {
  observedAt: bigint;
  validUntil: bigint;
  statements: T[];
  checkpoints: Uint8Array[];
  trust: StatusTrust[];
};
type Anchor = {
  principal: string; methods: string[]; profiles: Profile[]; permissions: Permission[];
  namespaces: string[]; audiences: string[]; notBefore: bigint; expiresAt: bigint;
  budget?: Budget; maxDepth: bigint;
  assurance: string; status: StatusPolicy;
};
type AssuranceRequirement = {
  role: bigint; claim: string; maximumAge?: bigint; quantifier: bigint;
};
type CompositionRequirement = {
  expectedPlan?: Uint8Array;
  minimumAuthorizedBranches: bigint;
  minimumDistinctActors: bigint;
  minimumDistinctRoots: bigint;
};
type Context = {
  raw: Uint8Array; configuration: Uint8Array; composition: CompositionRequirement;
  anchors: Anchor[]; principalMethods: string[]; signatureSuites: string[];
  registryManifest: Uint8Array;
  evidenceTypes: string[]; principalStatuses: string[]; grantStatuses: string[];
  assuranceClaims: string[]; budgetAlgebras: string[];
  resourceMatchers: string[]; extensions: string[]; profiles: Profile[]; profilePolicies: string[];
  // Profiles whose canonical actions cannot express a requested budget.
  budgetFreeProfiles: Profile[];
  expectedAudience: string; expectedChallenge: Uint8Array;
  evaluationTime: bigint; assuranceID: string; assurance: AssuranceRequirement[];
  principalSnapshot: Snapshot<PrincipalStatus>; grantSnapshot: Snapshot<GrantStatus>;
  resourceMatcher: string; profilePolicy: string; channelPolicy: string; limits: bigint[];
  observerAnchors: ObserverAnchor[];
};
type Bundle = {
  raw: Uint8Array; grants: Grant[]; actions: Action[]; plan: Plan; evidence: Evidence[];
  bindings: Binding[]; principalStatus: PrincipalStatus[]; grantStatus: GrantStatus[];
  attachments: V[]; canonicalBody?: Uint8Array;
};

function profile(value: V): Profile {
  exactMap(value, 2);
  const version = uint(mapAt(value, 1));
  if (version === 0n || version > 65535n) throw new Error("invalid profile");
  return { id: text(mapAt(value, 0)), version };
}

function permission(value: V): Permission {
  exactMap(value, 2);
  return { capability: text(mapAt(value, 0)), resource: text(mapAt(value, 1)) };
}

function budget(value: V): Budget | undefined {
  if (value.major === 7 && value.uint === 22n) return undefined;
  exactMap(value, 2);
  return { algebra: text(mapAt(value, 0)), value: uint(mapAt(value, 1)) };
}

function statusPolicy(value: V): StatusPolicy {
  const kind = uint(mapAt(value, 0));
  if (kind === 0n && value.pairs?.length === 1) return { kind };
  if (kind !== 1n || value.pairs?.length !== 3) throw new Error("invalid status policy");
  return { kind, method: text(mapAt(value, 1)), maxAge: uint(mapAt(value, 2)) };
}

function constraint(value: V): Constraint {
  const kind = uint(mapAt(value, 0));
  if (kind === 0n && value.pairs?.length === 1) return { kind, digests: [] };
  if (kind === 1n && value.pairs?.length === 2) {
    return { kind, digests: [bytes(mapAt(value, 1), 32)] };
  }
  if (kind === 2n && value.pairs?.length === 2) {
    return { kind, digests: array(mapAt(value, 1)).map((entry) => bytes(entry, 32)) };
  }
  throw new Error("invalid action constraint");
}

function textArray(value: V): string[] {
  return array(value).map(text);
}

function permissionArray(value: V): Permission[] {
  return array(value).map(permission);
}

function extensions(value: V): Extension[] {
  return array(value).map((entry) => {
    exactMap(entry, 2);
    return { id: text(mapAt(entry, 0)), bytes: bytes(mapAt(entry, 1)) };
  });
}

function signature(value: V): Signature {
  exactMap(value, 2);
  const descriptor = mapAt(value, 0);
  exactMap(descriptor, 3);
  return {
    descriptor: {
      method: text(mapAt(descriptor, 0)),
      verificationMethod: text(mapAt(descriptor, 1)),
      suite: text(mapAt(descriptor, 2)),
      raw: descriptor.raw.slice(),
    },
    signature: bytes(mapAt(value, 1)),
  };
}

function grant(value: V): Grant {
  exactMap(value, 2);
  const statement = mapAt(value, 0);
  exactMap(statement, 16);
  if (uint(mapAt(statement, 0)) !== 1n) throw new Error("unsupported grant protocol");
  const notBefore = uint(mapAt(statement, 6));
  const expiresAt = uint(mapAt(statement, 7));
  if (notBefore > expiresAt) throw new Error("invalid grant validity");
  return {
    statement,
    issuer: text(mapAt(statement, 1)),
    subject: text(mapAt(statement, 2)),
    profile: { id: text(mapAt(statement, 3)), version: uint(mapAt(statement, 4)) },
    permissions: permissionArray(mapAt(statement, 5)),
    notBefore,
    expiresAt,
    audiences: textArray(mapAt(statement, 8)),
    constraint: constraint(mapAt(statement, 9)),
    budget: budget(mapAt(statement, 10)),
    remainingDepth: uint(mapAt(statement, 11)),
    parent: optionalBytes(mapAt(statement, 12)),
    status: statusPolicy(mapAt(statement, 13)),
    assurance: text(mapAt(statement, 14)),
    extensions: extensions(mapAt(statement, 15)),
    signature: signature(mapAt(value, 1)),
    id: domainHash(1, statement.raw),
  };
}

function action(value: V): Action {
  exactMap(value, 2);
  const envelope = mapAt(value, 0);
  exactMap(envelope, 19);
  if (uint(mapAt(envelope, 0)) !== 1n) throw new Error("unsupported action protocol");
  const notBefore = uint(mapAt(envelope, 10));
  const expiresAt = uint(mapAt(envelope, 11));
  if (notBefore > expiresAt) throw new Error("invalid action validity");
  return {
    envelope,
    profile: { id: text(mapAt(envelope, 1)), version: uint(mapAt(envelope, 2)) },
    mediaType: text(mapAt(envelope, 3)),
    bodyDigest: bytes(mapAt(envelope, 4), 32),
    permission: { capability: text(mapAt(envelope, 5)), resource: text(mapAt(envelope, 6)) },
    budget: budget(mapAt(envelope, 7)),
    audience: text(mapAt(envelope, 8)),
    challenge: bytes(mapAt(envelope, 9), 32),
    notBefore,
    expiresAt,
    actor: text(mapAt(envelope, 12)),
    terminalGrant: optionalBytes(mapAt(envelope, 13)),
    planID: bytes(mapAt(envelope, 14), 32),
    channel: text(mapAt(envelope, 15)),
    proofRef: bytes(mapAt(envelope, 16), 32),
    attachments: array(mapAt(envelope, 17)),
    extensions: extensions(mapAt(envelope, 18)),
    signature: signature(mapAt(value, 1)),
    id: domainHash(2, envelope.raw),
  };
}

class Failure extends Error {
  readonly decision: "denied" | "indeterminate";
  readonly code: string;

  constructor(decision: "denied" | "indeterminate", code: string) {
    super(`${decision}:${code}`);
    this.decision = decision;
    this.code = code;
  }
}
const denied = (code: string): Failure => new Failure("denied", code);
const indeterminate = (code: string): Failure => new Failure("indeterminate", code);

function plan(value: V, depth: number, limits: bigint[]): Plan {
  if (BigInt(depth) > limits[6]!) throw denied("resource-limit-exceeded");
  const kind = uint(mapAt(value, 0));
  if (kind === 0n && value.pairs?.length === 2) {
    return { kind, k: 0n, proofRef: bytes(mapAt(value, 1), 32), children: [], raw: value.raw };
  }
  const childrenValue = mapAt(value, kind === 3n ? 2 : 1);
  const childValues = array(childrenValue);
  if (childValues.length === 0 || BigInt(childValues.length) > limits[7]!) {
    throw denied("resource-limit-exceeded");
  }
  if (kind === 1n || kind === 2n) {
    return { kind, k: 0n, children: childValues.map((child) => plan(child, depth + 1, limits)), raw: value.raw };
  }
  if (kind === 3n) {
    const k = uint(mapAt(value, 1));
    if (k === 0n || k > BigInt(childValues.length)) throw denied("resource-limit-exceeded");
    return { kind, k, children: childValues.map((child) => plan(child, depth + 1, limits)), raw: value.raw };
  }
  throw new Error("invalid authorization plan");
}

function evidence(value: V, maximum: bigint): Evidence {
  exactMap(value, 4);
  const result = {
    id: bytes(mapAt(value, 0), 32),
    kind: text(mapAt(value, 1)),
    mediaType: text(mapAt(value, 2)),
    body: bytes(mapAt(value, 3)),
  };
  if (result.body.length === 0 || BigInt(result.body.length) > maximum) {
    throw denied("resource-limit-exceeded");
  }
  if (!equal(result.id, domainHash(4, evidenceContent(result)))) throw denied("digest-mismatch");
  return result;
}

function statementRef(value: V): StatementRef {
  exactMap(value, 2);
  const kind = uint(mapAt(value, 0));
  if (kind > 3n) throw new Error("invalid statement reference");
  return { kind, id: bytes(mapAt(value, 1), 32) };
}

function binding(value: V, maximum: bigint): Binding {
  exactMap(value, 2);
  const ids = array(mapAt(value, 1)).map((entry) => bytes(entry, 32));
  if (ids.length === 0 || BigInt(ids.length) > maximum) throw denied("resource-limit-exceeded");
  return { statement: statementRef(mapAt(value, 0)), evidence: ids };
}

function principalStatus(value: V): PrincipalStatus {
  exactMap(value, 2);
  const statement = mapAt(value, 0);
  exactMap(statement, 9);
  const observedAt = uint(mapAt(statement, 5));
  const validUntil = uint(mapAt(statement, 6));
  return {
    statement,
    method: text(mapAt(statement, 1)),
    principal: text(mapAt(statement, 2)),
    state: uint(mapAt(statement, 3)),
    sequence: uint(mapAt(statement, 4)),
    observedAt,
    validUntil,
    issuer: text(mapAt(statement, 7)),
    signature: signature(mapAt(value, 1)),
    id: domainHash(5, statement.raw),
  };
}

function grantStatus(value: V): GrantStatus {
  exactMap(value, 2);
  const statement = mapAt(value, 0);
  exactMap(statement, 9);
  return {
    statement,
    method: text(mapAt(statement, 1)),
    grantID: bytes(mapAt(statement, 2), 32),
    state: uint(mapAt(statement, 3)),
    sequence: uint(mapAt(statement, 4)),
    observedAt: uint(mapAt(statement, 5)),
    validUntil: uint(mapAt(statement, 6)),
    issuer: text(mapAt(statement, 7)),
    signature: signature(mapAt(value, 1)),
    id: domainHash(6, statement.raw),
  };
}

function snapshot<T>(value: V, decode: (entry: V) => T): Snapshot<T> {
  exactMap(value, 6);
  const trust = array(mapAt(value, 5)).map((rule) => {
    exactMap(rule, 3);
    return {
      method: text(mapAt(rule, 0)),
      issuer: text(mapAt(rule, 1)),
      minimumSequence: uint(mapAt(rule, 2)),
    };
  });
  return {
    observedAt: uint(mapAt(value, 1)),
    validUntil: uint(mapAt(value, 2)),
    statements: array(mapAt(value, 3)).map(decode),
    checkpoints: array(mapAt(value, 4)).map((entry) => bytes(entry, 32)),
    trust,
  };
}

function context(data: Uint8Array): Context {
  const root = new Decoder(data).complete();
  exactMap(root, 15);
  const limitMap = mapAt(root, 0);
  exactMap(limitMap, 27);
  const compositionValue = mapAt(root, 2);
  exactMap(compositionValue, 4);
  const expectedPlan = mapAt(compositionValue, 0);
  const composition: CompositionRequirement = {
    expectedPlan: expectedPlan.major === 7 && expectedPlan.uint === 22n
      ? undefined
      : bytes(expectedPlan, 32),
    minimumAuthorizedBranches: uint(mapAt(compositionValue, 1)),
    minimumDistinctActors: uint(mapAt(compositionValue, 2)),
    minimumDistinctRoots: uint(mapAt(compositionValue, 3)),
  };
  if (
    composition.minimumAuthorizedBranches === 0n ||
    composition.minimumDistinctActors === 0n ||
    composition.minimumDistinctRoots === 0n ||
    composition.minimumDistinctActors > composition.minimumAuthorizedBranches ||
    composition.minimumDistinctRoots > composition.minimumAuthorizedBranches
  ) throw new Error("invalid composition requirement");
  const registries = mapAt(root, 4);
  exactMap(registries, 14);
  const assurance = mapAt(root, 8);
  exactMap(assurance, 2);
  const result: Context = {
    raw: data,
    configuration: bytes(mapAt(root, 1), 32),
    composition,
    anchors: array(mapAt(root, 3)).map((value) => {
      exactMap(value, 13);
      return {
        principal: text(mapAt(value, 1)),
        methods: textArray(mapAt(value, 2)),
        profiles: array(mapAt(value, 3)).map(profile),
        permissions: permissionArray(mapAt(value, 4)),
        namespaces: textArray(mapAt(value, 5)),
        audiences: textArray(mapAt(value, 6)),
        notBefore: uint(mapAt(value, 7)),
        expiresAt: uint(mapAt(value, 8)),
        budget: budget(mapAt(value, 9)),
        maxDepth: uint(mapAt(value, 10)),
        assurance: text(mapAt(value, 11)),
        status: statusPolicy(mapAt(value, 12)),
      };
    }),
    registryManifest: bytes(mapAt(registries, 0), 32),
    principalMethods: textArray(mapAt(registries, 1)),
    signatureSuites: textArray(mapAt(registries, 2)),
    evidenceTypes: textArray(mapAt(registries, 3)),
    principalStatuses: textArray(mapAt(registries, 4)),
    grantStatuses: textArray(mapAt(registries, 5)),
    assuranceClaims: textArray(mapAt(registries, 6)),
    resourceMatchers: textArray(mapAt(registries, 8)),
    budgetAlgebras: textArray(mapAt(registries, 9)),
    extensions: textArray(mapAt(registries, 10)),
    profiles: array(mapAt(registries, 11)).map(profile),
    profilePolicies: textArray(mapAt(registries, 12)),
    budgetFreeProfiles: array(mapAt(registries, 13)).map(profile),
    expectedAudience: text(mapAt(root, 5)),
    expectedChallenge: bytes(mapAt(root, 6), 32),
    evaluationTime: uint(mapAt(root, 7)),
    assuranceID: text(mapAt(assurance, 0)),
    assurance: array(mapAt(assurance, 1)).map((entry) => {
      exactMap(entry, 8);
      const maximum = mapAt(entry, 6);
      const quantifier = uint(mapAt(entry, 7));
      if (quantifier > 1n) throw new Error("invalid assurance quantifier");
      return {
        role: uint(mapAt(entry, 0)),
        claim: text(mapAt(entry, 1)),
        maximumAge: maximum.major === 7 && maximum.uint === 22n ? undefined : uint(maximum),
        quantifier,
      };
    }),
    principalSnapshot: snapshot(mapAt(root, 9), principalStatus),
    grantSnapshot: snapshot(mapAt(root, 10), grantStatus),
    resourceMatcher: text(mapAt(root, 11)),
    profilePolicy: text(mapAt(root, 12)),
    channelPolicy: text(mapAt(root, 13)),
    limits: Array.from({ length: 27 }, (_, index) => uint(mapAt(limitMap, index))),
    observerAnchors: observerAnchors(mapAt(root, 14)),
  };
  return result;
}

function bundle(data: Uint8Array, limits: bigint[]): Bundle {
  if (BigInt(data.length) > limits[0]!) throw denied("resource-limit-exceeded");
  let root: V;
  try {
    root = new Decoder(data).complete();
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (detail.includes("non-minimal") || detail.includes("non-canonical")) {
      throw denied("non-canonical-proof");
    }
    throw denied("malformed-proof");
  }
  exactMap(root, 10);
  const header = mapAt(root, 0);
  exactMap(header, 2);
  const version = uint(mapAt(header, 0));
  const flags = uint(mapAt(header, 1));
  if (flags !== 0n) throw denied("malformed-proof");
  if (version !== 1n) throw indeterminate("unsupported-protocol");
  const grants = array(mapAt(root, 1)).map(grant);
  const actions = array(mapAt(root, 2)).map(action);
  const evidenceValues = array(mapAt(root, 4));
  const bindingValues = array(mapAt(root, 5));
  const principalValues = array(mapAt(root, 6));
  const grantValues = array(mapAt(root, 7));
  if (
    BigInt(grants.length) > limits[3]! ||
    BigInt(actions.length) > limits[4]! ||
    BigInt(evidenceValues.length) > limits[8]! ||
    BigInt(bindingValues.length) > limits[10]! ||
    BigInt(principalValues.length) > limits[11]! ||
    BigInt(grantValues.length) > limits[12]!
  ) throw denied("resource-limit-exceeded");
  const decodedPlan = plan(mapAt(root, 3), 1, limits);
  if (BigInt(collectLeaves(decodedPlan).length) > limits[5]!) {
    throw denied("resource-limit-exceeded");
  }
  const attachments = array(mapAt(root, 8));
  if (BigInt(attachments.length) > limits[13]!) throw denied("resource-limit-exceeded");
  const body = mapAt(root, 9);
  const canonicalBody = body.major === 7 && body.uint === 22n ? undefined : bytes(body);
  if (canonicalBody !== undefined && BigInt(canonicalBody.length) > limits[23]!) {
    throw denied("resource-limit-exceeded");
  }
  return {
    raw: data,
    grants,
    actions,
    plan: decodedPlan,
    evidence: evidenceValues.map((entry) => evidence(entry, limits[9]!)),
    bindings: bindingValues.map((entry) => binding(entry, limits[22]!)),
    principalStatus: principalValues.map(principalStatus),
    grantStatus: grantValues.map(grantStatus),
    attachments,
    canonicalBody,
  };
}

function sha256(value: Uint8Array): Uint8Array {
  return createHash("sha256").update(value).digest();
}

function domainHash(kind: number, canonical: Uint8Array): Uint8Array {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(1, 0);
  header.writeUInt16BE(kind, 2);
  header.writeBigUInt64BE(BigInt(canonical.length), 4);
  return createHash("sha256").update("AUTHS-ID").update(header).update(canonical).digest();
}

function signingPreimage(kind: number, profileValue: Profile, object: Uint8Array, descriptor: Uint8Array): Uint8Array {
  const signingObject = Buffer.concat([Buffer.from([0xa2, 0x00]), object, Buffer.from([0x01]), descriptor]);
  const profileBytes = Buffer.from(profileValue.id);
  const header = Buffer.alloc(16);
  header.writeUInt16BE(1, 0);
  header.writeUInt16BE(kind, 2);
  header.writeUInt16BE(profileBytes.length, 4);
  header.writeUInt16BE(Number(profileValue.version), 6);
  header.writeBigUInt64BE(BigInt(signingObject.length), 8);
  return Buffer.concat([
    Buffer.from("AUTHS"),
    header.subarray(0, 6),
    profileBytes,
    header.subarray(6),
    signingObject,
  ]);
}

function cborHead(major: number, value: number): Uint8Array {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value <= 0xff) return Uint8Array.of((major << 5) | 24, value);
  if (value <= 0xffff) return Uint8Array.of((major << 5) | 25, value >>> 8, value & 0xff);
  throw new Error("conformance CBOR helper length exceeded");
}
function cborText(value: string): Uint8Array {
  return Buffer.concat([cborHead(3, Buffer.byteLength(value)), Buffer.from(value)]);
}
function cborBytes(value: Uint8Array): Uint8Array {
  return Buffer.concat([cborHead(2, value.length), value]);
}
function evidenceContent(value: Evidence): Uint8Array {
  return Buffer.concat([
    Buffer.from([0xa3, 0x00]), cborText(value.kind),
    Buffer.from([0x01]), cborText(value.mediaType),
    Buffer.from([0x02]), cborBytes(value.body),
  ]);
}

function equal(left: Uint8Array | undefined, right: Uint8Array | undefined): boolean {
  if (left === undefined || right === undefined) return left === undefined && right === undefined;
  return Buffer.compare(left, right) === 0;
}
const keyOf = (value: Uint8Array): string => Buffer.from(value).toString("hex");
const refKey = (value: StatementRef): string => `${value.kind}:${keyOf(value.id)}`;
const contains = <T>(values: T[], expected: T): boolean => values.includes(expected);
const sameProfile = (left: Profile, right: Profile): boolean => left.id === right.id && left.version === right.version;
const samePermission = (left: Permission, right: Permission): boolean => left.capability === right.capability && left.resource === right.resource;
const sameBudget = (left?: Budget, right?: Budget): boolean =>
  left === undefined || right === undefined
    ? left === undefined && right === undefined
    : left.algebra === right.algebra && left.value === right.value;

type Claim = { kind: string; observedAt?: bigint };
type Control = {
  key: Uint8Array;
  signatureMessage?: Uint8Array;
  claims: Claim[];
  consumed: Uint8Array[];
  adapter: string;
  work: bigint;
};
type VerifiedControl = Control & {
  statement: StatementRef;
  principal: string;
  error?: Failure;
};

class Reader {
  private offset = 0;
  private readonly body: Uint8Array;

  constructor(body: Uint8Array) {
    this.body = body;
  }
  take(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.body.length) throw new Error("truncated evidence");
    const value = this.body.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
  u8(): number { return this.take(1)[0]!; }
  u16(): number { return Buffer.from(this.take(2)).readUInt16BE(); }
  u32(): number { return Buffer.from(this.take(4)).readUInt32BE(); }
  text8(): string { return new TextDecoder().decode(this.take(this.u8())); }
  get complete(): boolean { return this.offset === this.body.length; }
}

function expectDomain(reader: Reader, expected: string): void {
  const encoded = Buffer.from(expected, "binary");
  if (Buffer.compare(reader.take(encoded.length), encoded) !== 0) {
    throw denied("principal-method-mismatch");
  }
}

function selectEvidence(kind: string, mediaType: string, values: Evidence[]): Evidence {
  const selected = values.filter((value) => value.kind === kind);
  if (selected.length === 0) throw indeterminate("missing-principal-evidence");
  if (selected.length !== 1 || selected[0]!.mediaType !== mediaType) throw denied("principal-method-mismatch");
  return selected[0]!;
}

function base58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let number = 0n;
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base58");
    number = number * 58n + BigInt(index);
  }
  const octets: number[] = [];
  while (number > 0n) {
    octets.push(Number(number & 0xffn));
    number >>= 8n;
  }
  octets.reverse();
  for (let index = 0; index < value.length && value[index] === "1"; index += 1) octets.unshift(0);
  return Uint8Array.from(octets);
}

function multikey(encoded: string): { key: Uint8Array; suite: string } {
  if (!encoded.startsWith("z")) throw new Error("unsupported multibase");
  const decoded = base58(encoded.slice(1));
  if (decoded[0] === 0xed && decoded[1] === 0x01 && decoded.length === 34) {
    return { key: decoded.slice(2), suite: "ed25519-v1" };
  }
  if (decoded[0] === 0x80 && decoded[1] === 0x24 && decoded.length === 35) {
    return { key: decoded.slice(2), suite: "p256-sha256-v1" };
  }
  throw new Error("unsupported multicodec");
}

function rawKeyControl(principal: string, descriptor: Descriptor, evidence: Evidence[]): Control {
  const object = selectEvidence("raw-key-v1", "application/vnd.auths.raw-key.v1", evidence);
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-RAW-KEY\0\u0001");
  const tag = reader.u8();
  const length = reader.u16();
  const key = reader.take(length);
  if (!reader.complete) throw denied("principal-method-mismatch");
  const suite = tag === 1 ? "ed25519-v1" : tag === 2 ? "p256-sha256-v1" : "";
  if (!suite || (tag === 1 && length !== 32) || (tag === 2 && length !== 33)) {
    throw denied("principal-method-mismatch");
  }
  if (descriptor.suite !== suite) throw denied("signature-suite-mismatch");
  const expected = `key:sha256:${Buffer.from(sha256(object.body)).toString("base64url")}`;
  if (principal !== expected) throw denied("principal-method-mismatch");
  if (descriptor.verificationMethod !== principal) throw denied("verification-method-mismatch");
  return {
    key, claims: [{ kind: "self-certifying-identifier" }, { kind: "offline-verifiable" }],
    consumed: [object.id], adapter: "raw-key-v1", work: 10n,
  };
}

function didKeyControl(principal: string, descriptor: Descriptor, evidence: Evidence[]): Control {
  const object = selectEvidence("did-key-v1", "application/vnd.auths.did-key.v1", evidence);
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-DID-KEY\0\u0001");
  const encoded = new TextDecoder().decode(reader.take(reader.u16()));
  if (!reader.complete) throw denied("principal-method-mismatch");
  const parsed = multikey(encoded);
  const expected = `did:key:${encoded}`;
  if (principal !== expected) throw denied("principal-method-mismatch");
  if (descriptor.verificationMethod !== `${expected}#${encoded}`) throw denied("verification-method-mismatch");
  if (descriptor.suite !== parsed.suite) throw denied("signature-suite-mismatch");
  return {
    key: parsed.key,
    claims: [{ kind: "self-certifying-identifier" }, { kind: "offline-verifiable" }],
    consumed: [object.id], adapter: "did-key-v1", work: 20n,
  };
}

function didWebControl(
  principal: string,
  descriptor: Descriptor,
  purpose: bigint,
  signingTime: bigint,
  preimage: Uint8Array,
  evidence: Evidence[],
  evaluationTime: bigint,
  records: any[],
): Control {
  const object = selectEvidence(
    "did-web-bundled-v1", "application/vnd.auths.did-web-bundle.v1", evidence,
  );
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-DID-WEB\0\u0001");
  const embeddedPrincipal = new TextDecoder().decode(reader.take(reader.u16()));
  const document = reader.take(reader.u32());
  if (!reader.complete || embeddedPrincipal !== principal) throw denied("principal-method-mismatch");
  const did = JSON.parse(new TextDecoder().decode(document)) as any;
  if (did.id !== principal || !Array.isArray(did.verificationMethod)) throw denied("principal-method-mismatch");
  const relationship =
    purpose === 0n ? did.capabilityDelegation :
    purpose === 1n ? did.capabilityInvocation :
    did.assertionMethod;
  if (!Array.isArray(relationship) || !relationship.includes(descriptor.verificationMethod)) {
    throw denied("verification-method-mismatch");
  }
  const method = did.verificationMethod.find((candidate: any) =>
    candidate.id === descriptor.verificationMethod &&
    candidate.type === "Multikey" &&
    candidate.controller === principal
  );
  if (!method) throw denied("verification-method-mismatch");
  const parsed = multikey(method.publicKeyMultibase);
  if (descriptor.suite !== parsed.suite) throw denied("signature-suite-mismatch");
  const documentDigest = sha256(document);
  let trustClaims: Claim[] | undefined;
  let matchingDocument = false;
  for (const record of records) {
    if (record.principal !== principal ||
        Buffer.from(record.document_digest, "hex").compare(documentDigest) !== 0) continue;
    matchingDocument = true;
    if (
      record.kind === "current" &&
      BigInt(record.observed_at) <= evaluationTime &&
      evaluationTime <= BigInt(record.valid_until)
    ) {
      trustClaims = [
        { kind: "controller-state-current-at", observedAt: BigInt(record.observed_at) },
        { kind: "revocation-checked-at", observedAt: BigInt(record.observed_at) },
      ];
      break;
    }
    if (
      record.kind === "historical" &&
      BigInt(record.valid_from) <= signingTime &&
      signingTime <= BigInt(record.valid_until)
    ) {
      trustClaims = [{ kind: "historical-at", observedAt: signingTime }];
      if (
        record.statement &&
        Buffer.from(record.statement.signing_preimage_digest, "hex").compare(sha256(preimage)) === 0 &&
        BigInt(record.statement.existed_at) >= signingTime &&
        BigInt(record.statement.existed_at) <= BigInt(record.valid_until)
      ) {
        trustClaims.push({
          kind: "statement-existence-proven-at",
          observedAt: BigInt(record.statement.existed_at),
        });
      }
      break;
    }
  }
  if (!trustClaims) {
    throw indeterminate(
      matchingDocument ? "historical-state-unavailable" : "external-fact-unavailable",
    );
  }
  return {
    key: parsed.key,
    claims: [...trustClaims, { kind: "offline-verifiable" }, { kind: "rotation-aware" }],
    consumed: [object.id], adapter: "did-web-bundled-v1", work: 45n,
  };
}

function keriKey(encoded: string): { key: Uint8Array; suite: string } {
  if ((encoded.startsWith("D") || encoded.startsWith("B")) && encoded.length === 44) {
    const decoded = Buffer.from(`A${encoded.slice(1)}`, "base64url");
    if (decoded.length !== 33 || decoded[0] !== 0) throw new Error("invalid KERI key");
    return { key: decoded.slice(1), suite: "ed25519-v1" };
  }
  if ((encoded.startsWith("1AAJ") || encoded.startsWith("1AAI")) && encoded.length === 48) {
    const decoded = Buffer.from(encoded.slice(4), "base64url");
    if (decoded.length !== 33) throw new Error("invalid KERI key");
    return { key: decoded, suite: "p256-sha256-v1" };
  }
  throw new Error("unsupported KERI key");
}

function didKeriControl(principal: string, descriptor: Descriptor, evidence: Evidence[]): Control {
  const object = selectEvidence(
    "did-keri-v1", "application/vnd.auths.did-keri-kel.v1", evidence,
  );
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-DID-KERI\0\u0001");
  const count = reader.u16();
  if (count === 0 || count > 64) throw denied("principal-method-mismatch");
  let inception = "";
  let establishment = 0;
  let keys: string[] = [];
  let next: unknown[] = [];
  for (let index = 0; index < count; index += 1) {
    const event = JSON.parse(new TextDecoder().decode(reader.take(reader.u32()))) as any;
    reader.take(reader.u32());
    const sequence = Number.parseInt(event.s, 16);
    if (sequence !== index) throw denied("principal-method-mismatch");
    if (index === 0) {
      inception = event.i;
      if (event.t !== "icp" || event.d !== inception) throw denied("principal-method-mismatch");
    }
    if (event.t === "icp" || event.t === "rot") {
      if (!Array.isArray(event.k) || event.k.length === 0) throw denied("principal-method-mismatch");
      keys = event.k;
      next = Array.isArray(event.n) ? event.n : [];
      establishment = sequence;
    }
  }
  if (!reader.complete || principal !== `did:keri:${inception}`) throw denied("principal-method-mismatch");
  const prefix = `${principal}#key-${establishment.toString(16)}-`;
  if (!descriptor.verificationMethod.startsWith(prefix)) throw denied("verification-method-mismatch");
  const index = Number.parseInt(descriptor.verificationMethod.slice(prefix.length), 10);
  if (!Number.isSafeInteger(index) || index < 0 || index >= keys.length) {
    throw denied("verification-method-mismatch");
  }
  const parsed = keriKey(keys[index]!);
  if (descriptor.suite !== parsed.suite) throw denied("signature-suite-mismatch");
  const claims: Claim[] = [
    { kind: "self-certifying-identifier" },
    { kind: "offline-verifiable" },
  ];
  if (next.length > 0) claims.push({ kind: "rotation-aware" });
  return {
    key: parsed.key, claims, consumed: [object.id],
    adapter: "did-keri-v1", work: 60n + BigInt(count) * 40n,
  };
}

function webauthnControl(
  principal: string,
  descriptor: Descriptor,
  preimage: Uint8Array,
  evidence: Evidence[],
  evaluationTime: bigint,
  records: any[],
): Control {
  if (descriptor.suite !== "p256-sha256-v1") throw denied("signature-suite-mismatch");
  const record = records.find((candidate) => candidate.principal === principal);
  if (!record) throw indeterminate("external-fact-unavailable");
  if (descriptor.verificationMethod !== record.verification_method) throw denied("verification-method-mismatch");
  if (evaluationTime < BigInt(record.observed_at) || evaluationTime > BigInt(record.valid_until)) {
    throw indeterminate("external-fact-unavailable");
  }
  const object = selectEvidence(
    "webauthn-v1", "application/vnd.auths.webauthn-assertion.v1", evidence,
  );
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-WEBAUTHN\0\u0001");
  const credentialID = reader.take(reader.u16());
  const authenticator = reader.take(reader.u16());
  const clientData = reader.take(reader.u32());
  if (
    !reader.complete ||
    Buffer.from(credentialID).compare(Buffer.from(record.credential_id, "hex")) !== 0 ||
    authenticator.length < 37
  ) throw denied("principal-method-mismatch");
  const flags = authenticator[32]!;
  const rpDigest = sha256(Buffer.from(record.rp_id));
  const counter = Buffer.from(authenticator.slice(33, 37)).readUInt32BE();
  if (
    Buffer.from(authenticator.slice(0, 32)).compare(rpDigest) !== 0 ||
    (flags & 1) === 0 ||
    (record.user_verification === "Required" && (flags & 4) === 0) ||
    (record.counter_policy.kind === "greater-than" &&
      (counter === 0 || counter <= record.counter_policy.value))
  ) throw denied("principal-method-mismatch");
  const client = JSON.parse(new TextDecoder().decode(clientData));
  if (
    client.type !== "webauthn.get" ||
    Buffer.from(client.challenge, "base64url").compare(sha256(preimage)) !== 0 ||
    !record.origins.includes(client.origin)
  ) throw denied("principal-method-mismatch");
  const claims: Claim[] = [
    { kind: "origin-bound", observedAt: BigInt(record.observed_at) },
    { kind: "controller-state-current-at", observedAt: BigInt(record.observed_at) },
    { kind: "revocation-checked-at", observedAt: BigInt(record.observed_at) },
  ];
  if ((flags & 4) !== 0) claims.push({ kind: "user-verified", observedAt: evaluationTime });
  if (record.attestation_level) {
    claims.push({ kind: "hardware-attested", observedAt: BigInt(record.observed_at) });
  }
  return {
    key: Buffer.from(record.public_key, "hex"),
    signatureMessage: Buffer.concat([authenticator, sha256(clientData)]),
    claims, consumed: [object.id], adapter: "webauthn-v1", work: 75n,
  };
}

function hsmControl(
  principal: string,
  descriptor: Descriptor,
  preimage: Uint8Array,
  evidence: Evidence[],
  evaluationTime: bigint,
  records: any[],
): Control {
  const record = records.find((candidate) => candidate.principal === principal);
  if (!record) throw indeterminate("external-fact-unavailable");
  if (descriptor.verificationMethod !== record.verification_method) throw denied("verification-method-mismatch");
  if (descriptor.suite !== record.suite) throw denied("signature-suite-mismatch");
  if (evaluationTime < BigInt(record.observed_at) || evaluationTime > BigInt(record.valid_until)) {
    throw indeterminate("external-fact-unavailable");
  }
  const object = selectEvidence(
    "hsm-attested-v1", "application/vnd.auths.hsm-attested.v1", evidence,
  );
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-HSM-ATTESTED\0\u0001");
  const evidenceProfile = reader.text8();
  const provider = reader.text8();
  const level = reader.text8();
  const handle = reader.take(32);
  const device = reader.take(32);
  const nonExportable = reader.u8();
  const transaction = reader.take(32);
  if (
    !reader.complete ||
    evidenceProfile !== record.profile || provider !== record.provider ||
    level !== record.protection_level ||
    Buffer.from(handle).compare(Buffer.from(record.key_handle_digest, "hex")) !== 0 ||
    Buffer.from(device).compare(Buffer.from(record.device_chain_digest, "hex")) !== 0 ||
    (nonExportable === 1) !== (record.exportability === "NonExportable") ||
    Buffer.from(transaction).compare(sha256(preimage)) !== 0
  ) throw denied("principal-method-mismatch");
  const observedAt = BigInt(record.observed_at);
  return {
    key: Buffer.from(record.public_key, "hex"),
    claims: [
      { kind: "hardware-attested", observedAt },
      { kind: "controller-state-current-at", observedAt },
      { kind: "revocation-checked-at", observedAt },
      { kind: "offline-verifiable" },
    ],
    consumed: [object.id], adapter: "hsm-attested-v1", work: 55n,
  };
}

function spiffeControl(
  principal: string,
  descriptor: Descriptor,
  evidence: Evidence[],
  evaluationTime: bigint,
  config: any,
): Control {
  const uri = new URL(principal);
  if (uri.protocol !== "spiffe:") throw denied("principal-method-mismatch");
  const trust = config.trust_domains.find((candidate: any) => candidate.name === uri.hostname);
  if (!trust) throw indeterminate("external-fact-unavailable");
  const object = selectEvidence(
    "spiffe-x509-v1", "application/vnd.auths.spiffe-x509-svid.v1", evidence,
  );
  const reader = new Reader(object.body);
  expectDomain(reader, "AUTHS-SPIFFE-X509\0\u0001");
  const count = reader.u16();
  const certificates: X509Certificate[] = [];
  const raw: Uint8Array[] = [];
  for (let index = 0; index < count; index += 1) {
    const der = reader.take(reader.u32());
    raw.push(der);
    certificates.push(new X509Certificate(der));
  }
  if (!reader.complete || certificates.length === 0) throw denied("principal-method-mismatch");
  const root = new X509Certificate(Buffer.from(trust.roots[0], "hex"));
  const issuer = certificates.length > 1 ? certificates[1]! : root;
  if (!certificates[0]!.verify(issuer.publicKey)) throw denied("principal-method-mismatch");
  if (certificates.length > 1 && !certificates.at(-1)!.verify(root.publicKey)) {
    throw denied("principal-method-mismatch");
  }
  const san = certificates[0]!.subjectAltName;
  if (!san.includes(principal)) throw denied("principal-method-mismatch");
  if (descriptor.suite !== "ed25519-v1") throw denied("signature-suite-mismatch");
  const leafDigest = sha256(raw[0]!);
  const expectedMethod = `${principal}#svid-${Buffer.from(leafDigest).toString("base64url").slice(0, 16)}`;
  if (descriptor.verificationMethod !== expectedMethod) throw denied("verification-method-mismatch");
  const status = config.status.find((candidate: any) =>
    Buffer.from(candidate.leaf_digest, "hex").compare(leafDigest) === 0 &&
    BigInt(candidate.observed_at) <= evaluationTime &&
    evaluationTime <= BigInt(candidate.valid_until)
  );
  if (status && status.status !== "Active") throw denied("principal-revoked");
  if (trust.status_requirement === "Required" && !status) {
    throw indeterminate("external-fact-unavailable");
  }
  const claims: Claim[] = [
    { kind: "pki-chain-validated", observedAt: evaluationTime },
    { kind: "workload-attested", observedAt: evaluationTime },
  ];
  if (status) {
    claims.push(
      { kind: "controller-state-current-at", observedAt: BigInt(status.observed_at) },
      { kind: "revocation-checked-at", observedAt: BigInt(status.observed_at) },
    );
  }
  const spki = certificates[0]!.publicKey.export({ type: "spki", format: "der" });
  const key = spki.subarray(spki.length - 32);
  return {
    key, claims, consumed: [object.id],
    adapter: "spiffe-x509-v1", work: 120n + BigInt(count) * 35n,
  };
}

function control(
  method: string,
  principal: string,
  descriptor: Descriptor,
  purpose: bigint,
  signingTime: bigint,
  preimage: Uint8Array,
  evidence: Evidence[],
  contextValue: Context,
  adapters: any,
): Control {
  if (!contains(contextValue.principalMethods, method)) throw indeterminate("unsupported-principal-method");
  if (!contains(contextValue.signatureSuites, descriptor.suite)) throw indeterminate("unsupported-signature-suite");
  if (evidence.some((value) => !contains(contextValue.evidenceTypes, value.kind))) {
    throw indeterminate("unsupported-evidence-type");
  }
  switch (method) {
    case "raw-key-v1": return rawKeyControl(principal, descriptor, evidence);
    case "did-key-v1": return didKeyControl(principal, descriptor, evidence);
    case "did-web-bundled-v1":
      return didWebControl(
        principal, descriptor, purpose, signingTime, preimage, evidence,
        contextValue.evaluationTime, adapters.did_web,
      );
    case "did-keri-v1": return didKeriControl(principal, descriptor, evidence);
    case "webauthn-v1":
      return webauthnControl(
        principal, descriptor, preimage, evidence, contextValue.evaluationTime, adapters.webauthn,
      );
    case "hsm-attested-v1":
      return hsmControl(
        principal, descriptor, preimage, evidence, contextValue.evaluationTime, adapters.hsm,
      );
    case "spiffe-x509-v1":
      return spiffeControl(principal, descriptor, evidence, contextValue.evaluationTime, adapters.spiffe);
    default: throw indeterminate("unsupported-principal-method");
  }
}

function publicKey(suite: string, raw: Uint8Array) {
  if (suite === "ed25519-v1") {
    return createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
      format: "der",
      type: "spki",
    });
  }
  if (suite === "p256-sha256-v1") {
    return createPublicKey({
      key: Buffer.concat([
        Buffer.from("3039301306072a8648ce3d020106082a8648ce3d030107032200", "hex"),
        raw,
      ]),
      format: "der",
      type: "spki",
    });
  }
  throw new Error("unsupported signature suite");
}

function verifySignature(suite: string, key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (suite === "ed25519-v1") {
    return signature.length === 64 && cryptoVerify(null, message, publicKey(suite, key), signature);
  }
  if (suite === "p256-sha256-v1") {
    if (signature.length !== 64) return false;
    const s = BigInt(`0x${Buffer.from(signature.slice(32)).toString("hex")}`);
    const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    if (s > order / 2n) return false;
    return cryptoVerify(
      "sha256",
      message,
      { key: publicKey(suite, key), dsaEncoding: "ieee-p1363" },
      signature,
    );
  }
  return false;
}

type Participant = { principal: string; role: bigint; claims: Claim[]; adapter: string };
type DetachedAttachment = { digest: Uint8Array; bytes: Uint8Array };
type CanonicalAction = {
  body: Uint8Array; profile: Profile; mediaType: string; permission: Permission; budget?: Budget;
  detached: DetachedAttachment[];
};
type SemanticResult = {
  name: string; decision: string; code: string;
  proof: Uint8Array; context: Uint8Array; action: Uint8Array; plan: Uint8Array;
  actionIDs: Uint8Array[]; branches: Uint8Array[]; assurance: Participant[];
};
type Artifact = {
  path: string; sha256: string; profile: string; profile_version: number;
  media_type: string; capability: string; resource: string;
  requested_budget?: { algebra: string; value: number };
};
type Fixture = {
  name: string; proof: Artifact; context: Artifact; canonical_action: Artifact;
  canonical_body: Artifact; expected_result: Artifact;
  expected_decision: string; expected_code: string;
};
type SemanticManifest = {
  protocol_major: number; adapter_context: any; fixtures: Fixture[];
};

function fail(error: unknown): never {
  if (error instanceof Failure) throw error;
  throw denied("malformed-proof");
}

function collectLeaves(value: Plan): Uint8Array[] {
  return value.kind === 0n
    ? [value.proofRef!]
    : value.children.flatMap(collectLeaves);
}

/**
 * Rejects a proof-carried status statement that the snapshot supersedes or
 * does not hold. Rollback is keyed on the statement's subject alone, the
 * principal or the grant, as status selection is.
 */
function validateCarriedStatus(value: Bundle, contextValue: Context): void {
  for (const carried of value.principalStatus) {
    if (contextValue.principalSnapshot.statements.some((current) =>
      carried.principal === current.principal && current.sequence > carried.sequence
    )) throw denied("status-sequence-rollback");
    if (!contextValue.principalSnapshot.statements.some((current) =>
      equal(carried.statement.raw, current.statement.raw) &&
      equal(carried.signature.signature, current.signature.signature)
    )) throw denied("digest-mismatch");
  }
  for (const carried of value.grantStatus) {
    if (contextValue.grantSnapshot.statements.some((current) =>
      equal(carried.grantID, current.grantID) && current.sequence > carried.sequence
    )) throw denied("status-sequence-rollback");
    if (!contextValue.grantSnapshot.statements.some((current) =>
      equal(carried.statement.raw, current.statement.raw) &&
      equal(carried.signature.signature, current.signature.signature)
    )) throw denied("digest-mismatch");
  }
}

function resolveAndVerifyControl(
  value: Bundle,
  contextValue: Context,
  adapters: any,
): VerifiedControl[] {
  const planID = domainHash(3, value.plan.raw);
  const grants = new Map<string, Grant>();
  for (const grantValue of value.grants) {
    if (grants.has(keyOf(grantValue.id))) throw denied("duplicate-object");
    grants.set(keyOf(grantValue.id), grantValue);
  }
  const actionsByID = new Map<string, Action>();
  const actionsByRef = new Map<string, Action>();
  for (const actionValue of value.actions) {
    if (!equal(actionValue.planID, planID)) throw denied("plan-action-mismatch");
    if (actionsByID.has(keyOf(actionValue.id)) || actionsByRef.has(keyOf(actionValue.proofRef))) {
      throw denied("duplicate-object");
    }
    actionsByID.set(keyOf(actionValue.id), actionValue);
    actionsByRef.set(keyOf(actionValue.proofRef), actionValue);
  }
  const leaves = collectLeaves(value.plan);
  if (leaves.length !== value.actions.length ||
      leaves.some((leaf) => !actionsByRef.has(keyOf(leaf)))) {
    throw denied("missing-reference");
  }
  const evidenceByID = new Map<string, Evidence>();
  for (const object of value.evidence) {
    if (evidenceByID.has(keyOf(object.id))) throw denied("duplicate-object");
    evidenceByID.set(keyOf(object.id), object);
  }
  const principalByID = new Map<string, PrincipalStatus>();
  for (const status of contextValue.principalSnapshot.statements) {
    if (principalByID.has(keyOf(status.id))) throw denied("duplicate-object");
    principalByID.set(keyOf(status.id), status);
  }
  const grantStatusByID = new Map<string, GrantStatus>();
  for (const status of contextValue.grantSnapshot.statements) {
    if (grantStatusByID.has(keyOf(status.id))) throw denied("duplicate-object");
    grantStatusByID.set(keyOf(status.id), status);
  }
  const bindings = new Map<string, Binding>();
  for (const item of value.bindings) {
    const key = refKey(item.statement);
    if (bindings.has(key)) throw denied("duplicate-object");
    const exists =
      (item.statement.kind === 0n && grants.has(keyOf(item.statement.id))) ||
      (item.statement.kind === 1n && actionsByID.has(keyOf(item.statement.id))) ||
      (item.statement.kind === 2n && principalByID.has(keyOf(item.statement.id))) ||
      (item.statement.kind === 3n && grantStatusByID.has(keyOf(item.statement.id)));
    if (!exists || item.evidence.some((id) => !evidenceByID.has(keyOf(id)))) {
      throw denied("missing-reference");
    }
    bindings.set(key, item);
  }
  const usedGrants = new Set<string>();
  for (const actionValue of value.actions) {
    const seen = new Set<string>();
    let cursor = actionValue.terminalGrant;
    while (cursor !== undefined) {
      const key = keyOf(cursor);
      if (seen.has(key)) throw denied("reference-cycle");
      seen.add(key);
      const grantValue = grants.get(key);
      if (!grantValue) throw denied("missing-reference");
      usedGrants.add(key);
      cursor = grantValue.parent;
    }
  }
  if (usedGrants.size !== grants.size) throw denied("unused-critical-evidence");
  const attachmentDigests = new Set<string>();
  for (const attachment of value.attachments) {
    const key = keyOf(bytes(mapAt(attachment, 0), 32));
    if (attachmentDigests.has(key)) throw denied("duplicate-attachment");
    attachmentDigests.add(key);
  }
  validateCarriedStatus(value, contextValue);

  // Principal control starts by requiring the executable registry and
  // configuration, after every reference has resolved.
  if (!equal(contextValue.registryManifest, new Uint8Array(32).fill(0x36))) {
    throw denied("registry-manifest-mismatch");
  }
  const localConfiguration = typeof adapters.configuration === "string"
    ? Buffer.from(adapters.configuration, "hex")
    : new Uint8Array();
  if (localConfiguration.length !== 32 ||
      !equal(contextValue.configuration, localConfiguration)) {
    throw denied("verifier-configuration-mismatch");
  }

  type SignedInput = {
    statement: StatementRef; principal: string; signature: Signature; profile: Profile;
    object: Uint8Array; kind: number; purpose: bigint; signingTime: bigint;
  };
  const inputs: SignedInput[] = [];
  for (const grantValue of [...value.grants].sort((a, b) => Buffer.compare(a.id, b.id))) {
    inputs.push({
      statement: { kind: 0n, id: grantValue.id }, principal: grantValue.issuer,
      signature: grantValue.signature, profile: grantValue.profile,
      object: grantValue.statement.raw, kind: 1, purpose: 0n, signingTime: grantValue.notBefore,
    });
  }
  for (const actionValue of [...value.actions].sort((a, b) => Buffer.compare(a.id, b.id))) {
    inputs.push({
      statement: { kind: 1n, id: actionValue.id }, principal: actionValue.actor,
      signature: actionValue.signature, profile: actionValue.profile,
      object: actionValue.envelope.raw, kind: 2, purpose: 1n, signingTime: actionValue.notBefore,
    });
  }
  for (const status of contextValue.principalSnapshot.statements) {
    inputs.push({
      statement: { kind: 2n, id: status.id }, principal: status.issuer,
      signature: status.signature, profile: { id: "", version: 0n },
      object: status.statement.raw, kind: 3, purpose: 2n, signingTime: status.observedAt,
    });
  }
  for (const status of contextValue.grantSnapshot.statements) {
    inputs.push({
      statement: { kind: 3n, id: status.id }, principal: status.issuer,
      signature: status.signature, profile: { id: "", version: 0n },
      object: status.statement.raw, kind: 4, purpose: 2n, signingTime: status.observedAt,
    });
  }
  const controls: VerifiedControl[] = [];
  const consumed = new Set<string>();
  let work = 0n;
  for (const input of inputs) {
    const bound = bindings.get(refKey(input.statement));
    if (!bound) {
      controls.push({
        statement: input.statement,
        principal: input.principal,
        key: new Uint8Array(),
        claims: [],
        consumed: [],
        adapter: "",
        work: 0n,
        error: indeterminate("missing-principal-evidence"),
      });
      continue;
    }
    const evidenceValues = bound.evidence.map((id) => evidenceByID.get(keyOf(id))!);
    bound.evidence.forEach((id) => consumed.add(keyOf(id)));
    const preimage = signingPreimage(input.kind, input.profile, input.object, input.signature.descriptor.raw);
    let result: Control;
    try {
      result = control(
        input.signature.descriptor.method, input.principal, input.signature.descriptor,
        input.purpose, input.signingTime, preimage, evidenceValues, contextValue, adapters,
      );
    } catch (error) {
      controls.push({
        statement: input.statement,
        principal: input.principal,
        key: new Uint8Array(),
        claims: [],
        consumed: [],
        adapter: "",
        work: 0n,
        error: error instanceof Failure ? error : denied("principal-method-mismatch"),
      });
      continue;
    }
    const message = result.signatureMessage ?? preimage;
    if (!verifySignature(
      input.signature.descriptor.suite, result.key, message, input.signature.signature,
    )) {
      controls.push({
        ...result,
        statement: input.statement,
        principal: input.principal,
        error: denied("invalid-signature"),
      });
      continue;
    }
    const suiteWork = input.signature.descriptor.suite === "p256-sha256-v1" ? 250n : 100n;
    work += result.work;
    if (work > contextValue.limits[26]!) throw denied("resource-limit-exceeded");
    work += suiteWork;
    if (work > contextValue.limits[26]!) throw denied("resource-limit-exceeded");
    result.consumed.forEach((id) => consumed.add(keyOf(id)));
    controls.push({ ...result, statement: input.statement, principal: input.principal });
  }
  contextValue.principalSnapshot.checkpoints.forEach((id) => consumed.add(keyOf(id)));
  contextValue.grantSnapshot.checkpoints.forEach((id) => consumed.add(keyOf(id)));
  if (value.evidence.some((object) => !consumed.has(keyOf(object.id)))) {
    throw denied("unused-critical-evidence");
  }
  return controls;
}

function permissionSubset(child: Permission[], parent: Permission[]): boolean {
  return child.every((item) => parent.some((candidate) => samePermission(item, candidate)));
}
function profileContains(values: Profile[], expected: Profile): boolean {
  return values.some((value) => sameProfile(value, expected));
}
function constraintAttenuates(child: Constraint, parent: Constraint): boolean {
  if (parent.kind === 0n) return true;
  if (child.kind === 0n) return false;
  return child.digests.every((digest) => parent.digests.some((allowed) => equal(digest, allowed)));
}
function constraintAllows(value: Constraint, digest: Uint8Array): boolean {
  return value.kind === 0n || value.digests.some((allowed) => equal(digest, allowed));
}
function budgetAttenuates(child?: Budget, parent?: Budget): boolean {
  return parent === undefined ||
    (child !== undefined && child.algebra === parent.algebra && child.value <= parent.value);
}
// An unbounded ceiling covers everything.
//
// An absent request means two different things. When the action's profile is
// able to state a budget (budgetFree false) an absent request states no bound at
// all, so a bounded ceiling does NOT vacuously cover it. When the profile's
// canonical body has no budget field (budgetFree true) the action provably
// spends zero and every ceiling covers it. The denying reading is the default
// for any profile the trusted registry selection does not declare budget-free.
function budgetCovers(ceiling: Budget | undefined, requested: Budget | undefined,
                      budgetFree: boolean): boolean {
  if (ceiling === undefined) return true;
  if (requested === undefined) return budgetFree;
  return ceiling.algebra === requested.algebra && requested.value <= ceiling.value;
}
function requireBudgetAlgebra(value: Budget | undefined, contextValue: Context): void {
  if (value === undefined) return;
  if (
    !contains(contextValue.budgetAlgebras, value.algebra) ||
    value.algebra !== "numeric-ceiling-v1"
  ) throw indeterminate("unsupported-budget-algebra");
}
// Compares every bounded ceiling before the delegation walk: each grant under
// a bounded parent, then the action's request under a bounded terminal
// ceiling. An algebra is resolved only where a bounded ceiling is compared,
// and the parent's algebra rejects a value in any other algebra as invalid
// input, which is local-policy-denied.
function validateBudgetChain(
  anchor: Anchor, chain: Grant[], actionValue: Action, contextValue: Context,
): void {
  let parent = anchor.budget;
  for (const grantValue of chain) {
    const child = grantValue.budget;
    if (parent !== undefined) {
      if (child === undefined) throw denied("delegation-expanded");
      requireBudgetAlgebra(parent, contextValue);
      if (child.algebra !== parent.algebra) throw denied("local-policy-denied");
      if (child.value > parent.value) throw denied("delegation-expanded");
    }
    parent = child;
  }
  if (parent === undefined) return;
  if (actionValue.budget === undefined) {
    if (profileContains(contextValue.budgetFreeProfiles, actionValue.profile)) return;
    throw denied("budget-ceiling-exceeded");
  }
  requireBudgetAlgebra(parent, contextValue);
  if (actionValue.budget.algebra !== parent.algebra) throw denied("local-policy-denied");
  if (actionValue.budget.value > parent.value) throw denied("budget-ceiling-exceeded");
}
function statusAttenuates(child: StatusPolicy, parent: StatusPolicy): boolean {
  return parent.kind === 0n ||
    (child.kind === 1n && child.method === parent.method && child.maxAge! <= parent.maxAge!);
}

type Authority = {
  subject: string; allowedProfiles: Profile[]; selectedProfile?: Profile;
  permissions: Permission[]; notBefore: bigint; expiresAt: bigint; audiences: string[];
  constraint: Constraint; budget?: Budget; remainingDepth: bigint; lastGrant?: Uint8Array;
  assurance: string; status: StatusPolicy;
  extensions?: Extension[];
};

/**
 * The attenuation law of one critical-extension identifier; `undefined` is an
 * absent extension. An identifier the context does not accept, or without a
 * handler, has no law.
 */
function extensionLaw(
  id: string, child: Extension | undefined, parent: Extension | undefined, accepted: string[],
): boolean {
  if (child === undefined || !contains(accepted, id)) return false;
  if (id === "exact-marker-v1") return parent !== undefined && equal(child.bytes, parent.bytes);
  if (id === BOUNDED_POLICY_EXTENSION) return boundedPolicyLaw(child, parent);
  if (id !== OBSERVATION_EXTENSION) return false;
  try {
    const childRequirements = observationRequirements(child.bytes);
    if (parent === undefined) return true;
    return requirementsAttenuate(childRequirements, observationRequirements(parent.bytes));
  } catch {
    return false;
  }
}

/**
 * Every parent identifier is present in the child and its law accepts the
 * pair; an identifier only the child carries is accepted only when its law
 * accepts adding it.
 */
function extensionsAttenuate(child: Extension[], parent: Extension[], accepted: string[]): boolean {
  const find = (values: Extension[], id: string) => values.find((value) => value.id === id);
  return parent.every((value) => extensionLaw(value.id, find(child, value.id), value, accepted)) &&
    child.every((value) =>
      find(parent, value.id) !== undefined || extensionLaw(value.id, value, undefined, accepted));
}

function delegate(authority: Authority, grantValue: Grant, accepted: string[]): void {
  // Linkage is judged before any attenuation dimension: a grant issued by
  // anyone but the current subject breaks the chain rather than widening it.
  if (grantValue.issuer !== authority.subject || !equal(grantValue.parent, authority.lastGrant)) {
    throw denied("broken-grant-chain");
  }
  const profileAllowed = authority.selectedProfile === undefined
    ? profileContains(authority.allowedProfiles, grantValue.profile)
    : sameProfile(authority.selectedProfile, grantValue.profile);
  if (
    authority.remainingDepth === 0n ||
    grantValue.remainingDepth >= authority.remainingDepth ||
    !profileAllowed ||
    !permissionSubset(grantValue.permissions, authority.permissions) ||
    grantValue.notBefore < authority.notBefore ||
    grantValue.expiresAt > authority.expiresAt ||
    !grantValue.audiences.every((audience) => contains(authority.audiences, audience)) ||
    !constraintAttenuates(grantValue.constraint, authority.constraint) ||
    !budgetAttenuates(grantValue.budget, authority.budget) ||
    !statusAttenuates(grantValue.status, authority.status) ||
    grantValue.assurance !== authority.assurance ||
    (authority.extensions !== undefined &&
      !extensionsAttenuate(grantValue.extensions, authority.extensions, accepted))
  ) throw denied("delegation-expanded");
  authority.subject = grantValue.subject;
  authority.selectedProfile = grantValue.profile;
  authority.permissions = grantValue.permissions;
  authority.notBefore = grantValue.notBefore;
  authority.expiresAt = grantValue.expiresAt;
  authority.audiences = grantValue.audiences;
  authority.constraint = grantValue.constraint;
  authority.budget = grantValue.budget;
  authority.remainingDepth = grantValue.remainingDepth;
  authority.lastGrant = grantValue.id;
  authority.status = grantValue.status;
  authority.extensions = grantValue.extensions;
}

function authorize(authority: Authority, actionValue: Action, budgetFree: boolean): void {
  if (actionValue.actor !== authority.subject ||
      !equal(actionValue.terminalGrant, authority.lastGrant)) {
    throw denied("broken-grant-chain");
  }
  const profileAllowed = authority.selectedProfile === undefined
    ? profileContains(authority.allowedProfiles, actionValue.profile)
    : sameProfile(authority.selectedProfile, actionValue.profile);
  if (!profileAllowed) throw denied("broken-grant-chain");
  if (!permissionSubset([actionValue.permission], authority.permissions)) {
    throw denied("permission-not-granted");
  }
  if (actionValue.notBefore < authority.notBefore || actionValue.expiresAt > authority.expiresAt) {
    throw denied("action-outside-validity");
  }
  if (!contains(authority.audiences, actionValue.audience)) throw denied("audience-mismatch");
  if (!constraintAllows(authority.constraint, actionValue.bodyDigest)) {
    throw denied("action-constraint-mismatch");
  }
  if (!budgetCovers(authority.budget, actionValue.budget, budgetFree)) {
    throw denied("budget-ceiling-exceeded");
  }
}

/** What an absent status statement means for a subject. */
type StatusListing = "required" | "revocation-list";

type StatusEntry = {
  method: string; issuer: string; state: bigint; sequence: bigint;
  observedAt: bigint; validUntil: bigint;
};

function statusControl(controls: Map<string, VerifiedControl>, kind: bigint, id: Uint8Array): void {
  const verified = controls.get(refKey({ kind, id }));
  if (!verified) throw indeterminate("missing-principal-evidence");
  if (verified.error) throw verified.error;
}

/**
 * Follows the native exact status method: a trusted statement below its
 * issuer's sequence floor is a rollback, and freshness and state are judged
 * across every trusted statement at the greatest sequence.
 */
function selectStatus(
  candidates: StatusEntry[],
  policy: StatusPolicy,
  trust: StatusTrust[],
  evaluationTime: bigint,
  revoked: string,
): void {
  if (!candidates.some((item) => item.method === policy.method)) {
    throw denied("status-method-mismatch");
  }
  const trusted: StatusEntry[] = [];
  for (const item of candidates) {
    if (item.method !== policy.method) continue;
    const rule = trust.find((candidate) =>
      candidate.method === policy.method && candidate.issuer === item.issuer);
    if (!rule) continue;
    if (item.sequence < rule.minimumSequence) throw denied("status-sequence-rollback");
    trusted.push(item);
  }
  if (trusted.length === 0) throw denied("status-issuer-untrusted");
  const maximum = trusted.reduce(
    (current, item) => item.sequence > current ? item.sequence : current,
    trusted[0]!.sequence,
  );
  const latest = trusted.filter((item) => item.sequence === maximum);
  if (latest.some((item) =>
    item.observedAt > evaluationTime || item.validUntil < evaluationTime ||
    evaluationTime - item.observedAt > policy.maxAge!)) {
    throw indeterminate("stale-status");
  }
  if (latest.some((item) => item.state !== 0n)) throw denied(revoked);
}

function checkPrincipalStatus(
  policy: StatusPolicy,
  principal: string,
  listing: StatusListing,
  contextValue: Context,
  controls: Map<string, VerifiedControl>,
): void {
  if (policy.kind === 0n) return;
  if (!contains(contextValue.principalStatuses, policy.method!)) {
    throw indeterminate("unsupported-status-method");
  }
  const snapshotValue = contextValue.principalSnapshot;
  const candidates: StatusEntry[] = [];
  for (const item of snapshotValue.statements) {
    if (item.principal !== principal) continue;
    statusControl(controls, 2n, item.id);
    candidates.push(item);
  }
  if (snapshotValue.observedAt > contextValue.evaluationTime ||
      snapshotValue.validUntil < contextValue.evaluationTime) {
    throw indeterminate("stale-status");
  }
  if (candidates.length === 0) {
    if (listing === "revocation-list") return;
    throw indeterminate("missing-principal-status");
  }
  selectStatus(
    candidates, policy, snapshotValue.trust, contextValue.evaluationTime, "principal-revoked",
  );
}

function checkGrantStatus(
  policy: StatusPolicy,
  grantID: Uint8Array,
  contextValue: Context,
  controls: Map<string, VerifiedControl>,
): void {
  if (policy.kind === 0n) return;
  if (!contains(contextValue.grantStatuses, policy.method!)) {
    throw indeterminate("unsupported-status-method");
  }
  const snapshotValue = contextValue.grantSnapshot;
  const candidates: StatusEntry[] = [];
  for (const item of snapshotValue.statements) {
    if (!equal(item.grantID, grantID)) continue;
    statusControl(controls, 3n, item.id);
    candidates.push(item);
  }
  if (snapshotValue.observedAt > contextValue.evaluationTime ||
      snapshotValue.validUntil < contextValue.evaluationTime) {
    throw indeterminate("stale-status");
  }
  if (candidates.length === 0) throw indeterminate("missing-grant-status");
  selectStatus(
    candidates, policy, snapshotValue.trust, contextValue.evaluationTime, "grant-revoked",
  );
}

function report(value: VerifiedControl, role: bigint): Participant {
  if (value.error) throw value.error;
  return { principal: value.principal, role, claims: value.claims, adapter: value.adapter };
}

function assuranceSatisfied(
  requirements: AssuranceRequirement[],
  reports: Participant[],
  evaluationTime: bigint,
): boolean {
  return requirements.every((requirement) => {
    const selected = reports.filter((participant) => participant.role === requirement.role);
    if (selected.length === 0) return false;
    const matches = (participant: Participant): boolean =>
      participant.claims.some((claim) =>
      claim.kind === requirement.claim &&
      (requirement.maximumAge === undefined ||
        (claim.observedAt !== undefined &&
          claim.observedAt <= evaluationTime &&
          evaluationTime - claim.observedAt <= requirement.maximumAge))
      );
    return requirement.quantifier === 0n
      ? selected.some(matches)
      : selected.every(matches);
  });
}

function verifyFromAnchor(
  actionValue: Action,
  chain: Grant[],
  rootControl: VerifiedControl,
  anchor: Anchor,
  contextValue: Context,
  controls: Map<string, VerifiedControl>,
): Participant[] {
  const method = chain.length === 0
    ? actionValue.signature.descriptor.method
    : chain[0]!.signature.descriptor.method;
  if (!contains(anchor.methods, method) || anchor.assurance !== contextValue.assuranceID) {
    throw denied("untrusted-root");
  }
  if (rootControl.error) throw rootControl.error;
  // Status runs before resource and attenuation checks. Every grant subject is
  // checked under the anchor's policy: by chain linkage the subjects are every
  // issuer after the root and the actor.
  checkPrincipalStatus(anchor.status, anchor.principal, "required", contextValue, controls);
  for (const grantValue of chain) {
    checkGrantStatus(grantValue.status, grantValue.id, contextValue, controls);
    checkPrincipalStatus(
      anchor.status, grantValue.subject, "revocation-list", contextValue, controls,
    );
  }
  if (
    !contains(contextValue.resourceMatchers, contextValue.resourceMatcher) ||
    contextValue.resourceMatcher !== "uri-namespace-v1"
  ) throw indeterminate("unsupported-resource-matcher");
  // Every grant permission, root to terminal, and then the action's
  // permission must name a resource inside one of the anchor's namespaces.
  const insideAnchor = (resource: string): boolean =>
    anchor.namespaces.some((namespace) => namespaceMatches(namespace, resource));
  for (const grantValue of chain) {
    if (!grantValue.permissions.every((granted) => insideAnchor(granted.resource))) {
      throw denied("resource-namespace-mismatch");
    }
  }
  if (!insideAnchor(actionValue.permission.resource)) {
    throw denied("resource-namespace-mismatch");
  }
  validateBudgetChain(anchor, chain, actionValue, contextValue);
  const authority: Authority = {
    subject: anchor.principal, allowedProfiles: anchor.profiles,
    permissions: anchor.permissions, notBefore: anchor.notBefore, expiresAt: anchor.expiresAt,
    audiences: anchor.audiences, constraint: { kind: 0n, digests: [] },
    budget: anchor.budget, remainingDepth: anchor.maxDepth,
    assurance: anchor.assurance, status: anchor.status,
  };
  const reports: Participant[] = [];
  if (chain.length === 0) reports.push(report(rootControl, 0n));
  chain.forEach((grantValue, index) => {
    if (index > 0) requireParentRequirements(chain[index - 1]!, grantValue);
    delegate(authority, grantValue, contextValue.extensions);
    const verified = controls.get(refKey({ kind: 0n, id: grantValue.id }));
    if (!verified) throw indeterminate("missing-principal-evidence");
    if (verified.error) throw verified.error;
    reports.push(report(verified, index === 0 ? 0n : 1n));
    evaluateCriticalExtensions(grantValue.extensions, contextValue.extensions);
  });
  authorize(authority, actionValue, profileContains(contextValue.budgetFreeProfiles, actionValue.profile));
  const actionControl = controls.get(refKey({ kind: 1n, id: actionValue.id }));
  if (!actionControl) throw indeterminate("missing-principal-evidence");
  if (actionControl.error) throw actionControl.error;
  reports.push(report(actionControl, 2n));
  for (const participant of reports) {
    for (const claim of participant.claims) {
      if (!contains(contextValue.assuranceClaims, claim.kind)) {
        throw indeterminate("unsupported-assurance-claim");
      }
    }
  }
  if (!assuranceSatisfied(contextValue.assurance, reports, contextValue.evaluationTime)) {
    throw indeterminate("assurance-requirement-not-met");
  }
  return reports;
}

type BranchResult = { actionID?: Uint8Array; reports?: Participant[]; error?: Failure };

function evaluatePlan(
  planValue: Plan,
  branch: (reference: Uint8Array) => BranchResult,
  branches: Uint8Array[],
  actionIDs: Uint8Array[],
  reports: Participant[],
): BranchResult {
  if (planValue.kind === 0n) {
    const result = branch(planValue.proofRef!);
    if (!result.error) {
      branches.push(planValue.proofRef!);
      actionIDs.push(result.actionID!);
      reports.push(...result.reports!);
    }
    return result;
  }
  const results = planValue.children.map((child) =>
    evaluatePlan(child, branch, branches, actionIDs, reports));
  const failure = (
    decision: Failure["decision"],
  ): BranchResult | undefined => results
    .filter((result) => result.error?.decision === decision)
    .sort((left, right) => left.error!.code.localeCompare(right.error!.code))[0];
  if (planValue.kind === 1n) {
    const deniedResult = failure("denied");
    if (deniedResult) return deniedResult;
    return failure("indeterminate") ?? {};
  }
  if (planValue.kind === 2n) {
    if (results.some((result) => !result.error)) return {};
    return failure("indeterminate") ?? failure("denied")!;
  }
  if (planValue.kind === 3n) {
    const authorized = results.filter((result) => !result.error).length;
    const unavailable = results.filter((result) => result.error?.decision === "indeterminate").length;
    if (BigInt(authorized) >= planValue.k) return {};
    if (BigInt(authorized + unavailable) >= planValue.k) {
      return failure("indeterminate") ??
        { error: indeterminate("external-fact-unavailable") };
    }
    return failure("denied") ??
      { error: denied("authorization-plan-invalid") };
  }
  return { error: denied("authorization-plan-invalid") };
}

function boolean(value: V): boolean {
  if (value.major !== 7 || (value.uint !== 20n && value.uint !== 21n)) {
    throw denied("malformed-proof");
  }
  return value.uint === 21n;
}

function validateAttachments(
  value: Bundle,
  canonical: CanonicalAction,
  contextValue: Context,
): void {
  const descriptors = value.actions[0]!.attachments;
  if (
    descriptors.length !== value.attachments.length ||
    descriptors.some((descriptor, index) =>
      !equal(descriptor.raw, value.attachments[index]!.raw))
  ) throw denied("unused-critical-attachment");
  const descriptorIDs = new Set<string>();
  for (const descriptor of descriptors) {
    exactMap(descriptor, 7);
    const key = keyOf(bytes(mapAt(descriptor, 0), 32));
    if (descriptorIDs.has(key)) throw denied("duplicate-attachment");
    descriptorIDs.add(key);
  }
  const detached = new Map<string, DetachedAttachment>();
  let total = 0n;
  for (const attachment of canonical.detached) {
    const key = keyOf(attachment.digest);
    if (detached.has(key)) throw denied("duplicate-attachment");
    detached.set(key, attachment);
    total += BigInt(attachment.bytes.length);
  }
  if (total > contextValue.limits[14]!) throw denied("resource-limit-exceeded");
  for (const descriptor of descriptors) {
    const digest = bytes(mapAt(descriptor, 0), 32);
    const attachment = detached.get(keyOf(digest));
    const required = boolean(mapAt(descriptor, 5));
    if (!attachment) {
      if (required) throw denied("attachment-missing");
      continue;
    }
    if (BigInt(attachment.bytes.length) !== uint(mapAt(descriptor, 2))) {
      throw denied("attachment-length-mismatch");
    }
    if (!equal(sha256(attachment.bytes), digest)) throw denied("attachment-digest-mismatch");
    if (boolean(mapAt(descriptor, 4)) && !boolean(mapAt(descriptor, 6))) {
      throw denied("opaque-attachment-not-allowed");
    }
  }
  if ([...detached.keys()].some((key) => !descriptorIDs.has(key))) {
    throw denied("unused-critical-attachment");
  }
}

function sharedAction(left: Action, right: Action): boolean {
  return sameProfile(left.profile, right.profile) &&
    left.mediaType === right.mediaType &&
    equal(left.bodyDigest, right.bodyDigest) &&
    samePermission(left.permission, right.permission) &&
    sameBudget(left.budget, right.budget) &&
    left.audience === right.audience &&
    equal(left.challenge, right.challenge) &&
    left.notBefore === right.notBefore &&
    left.expiresAt === right.expiresAt &&
    equal(left.planID, right.planID) &&
    left.channel === right.channel &&
    left.attachments.length === right.attachments.length &&
    left.attachments.every((value, index) => equal(value.raw, right.attachments[index]!.raw)) &&
    left.extensions.length === right.extensions.length &&
    left.extensions.every((value, index) =>
      value.id === right.extensions[index]!.id &&
      equal(value.bytes, right.extensions[index]!.bytes));
}

function evaluateCriticalExtensions(values: Extension[], accepted: string[]): void {
  for (const value of values) {
    if (!contains(accepted, value.id)) throw denied("critical-extension-unknown");
    if (value.id === OBSERVATION_EXTENSION) {
      evaluateObservationExtension(value);
      continue;
    }
    if (value.id === BOUNDED_POLICY_EXTENSION) {
      evaluateBoundedPolicyExtension(value);
      continue;
    }
    if (value.id !== "exact-marker-v1") throw indeterminate("unsupported-critical-extension");
    if (!equal(value.bytes, Uint8Array.of(1))) throw denied("local-policy-denied");
  }
}

function uniqueDigests(values: Uint8Array[]): Uint8Array[] {
  return values
    .sort((a, b) => Buffer.compare(a, b))
    .filter((value, index, all) => index === 0 || !equal(value, all[index - 1]));
}
function claimsEqual(left: Claim[], right: Claim[]): boolean {
  return left.length === right.length &&
    left.every((claim, index) =>
      claim.kind === right[index]!.kind && claim.observedAt === right[index]!.observedAt);
}
function uniqueReports(values: Participant[]): Participant[] {
  values.sort((a, b) => a.role === b.role
    ? Buffer.compare(Buffer.from(a.principal), Buffer.from(b.principal))
    : a.role < b.role ? -1 : 1);
  return values.filter((value, index, all) => !all.slice(0, index).some((candidate) =>
    value.principal === candidate.principal &&
    value.role === candidate.role &&
    value.adapter === candidate.adapter &&
    claimsEqual(value.claims, candidate.claims)));
}

function verifyAuthority(
  value: Bundle,
  controls: VerifiedControl[],
  contextValue: Context,
  canonical: CanonicalAction,
  adapters: any,
): { actionIDs: Uint8Array[]; branches: Uint8Array[]; assurance: Participant[] } {
  // Action binding runs once, before any branch: the carried body, each
  // signed action in proof order, the attachments, then the profile policy.
  if (value.canonicalBody !== undefined && !equal(value.canonicalBody, canonical.body)) {
    throw denied("action-body-mismatch");
  }
  const expectedBody = sha256(canonical.body);
  const first = value.actions[0]!;
  for (const actionValue of value.actions) {
    if (!sameProfile(actionValue.profile, canonical.profile) ||
        actionValue.mediaType !== canonical.mediaType ||
        !equal(actionValue.bodyDigest, expectedBody) ||
        !samePermission(actionValue.permission, canonical.permission) ||
        !sameBudget(actionValue.budget, canonical.budget)) {
      throw denied("action-body-mismatch");
    }
    if (!profileContains(contextValue.profiles, actionValue.profile)) {
      throw indeterminate("unsupported-profile");
    }
    if (actionValue.audience !== contextValue.expectedAudience) throw denied("audience-mismatch");
    if (!equal(actionValue.challenge, contextValue.expectedChallenge)) throw denied("challenge-mismatch");
    if (contextValue.evaluationTime < actionValue.notBefore ||
        contextValue.evaluationTime > actionValue.expiresAt) {
      throw denied("action-outside-validity");
    }
    if (actionValue.channel !== contextValue.channelPolicy) throw denied("local-policy-denied");
    if (!sharedAction(first, actionValue)) throw denied("plan-action-mismatch");
    evaluateCriticalExtensions(actionValue.extensions, contextValue.extensions);
    validateObservationAttachments(actionValue);
  }
  validateAttachments(value, canonical, contextValue);
  if (
    !contains(contextValue.profilePolicies, contextValue.profilePolicy) ||
    contextValue.profilePolicy !== "exact-v1"
  ) throw indeterminate("unsupported-profile-policy");
  const actionByRef = new Map(value.actions.map((item) => [keyOf(item.proofRef), item]));
  const grantByID = new Map(value.grants.map((item) => [keyOf(item.id), item]));
  const controlByStatement = new Map(controls.map((item) => [refKey(item.statement), item]));
  const branches: Uint8Array[] = [];
  const actionIDs: Uint8Array[] = [];
  const reports: Participant[] = [];
  const branch = (reference: Uint8Array): BranchResult => {
    const actionValue = actionByRef.get(keyOf(reference));
    if (!actionValue) return { error: denied("missing-reference") };
    const chain: Grant[] = [];
    let cursor = actionValue.terminalGrant;
    while (cursor !== undefined) {
      const grantValue = grantByID.get(keyOf(cursor));
      if (!grantValue) return { error: denied("missing-reference") };
      chain.push(grantValue);
      cursor = grantValue.parent;
    }
    chain.reverse();
    const root = chain.length === 0 ? actionValue.actor : chain[0]!.issuer;
    const rootReference = chain.length === 0
      ? { kind: 1n, id: actionValue.id }
      : { kind: 0n, id: chain[0]!.id };
    const rootControl = controlByStatement.get(refKey(rootReference));
    if (!rootControl) return { error: indeterminate("missing-principal-evidence") };
    if (rootControl.error) return { error: rootControl.error };
    let firstFailure: Failure | undefined;
    for (const anchor of contextValue.anchors) {
      if (anchor.principal !== root) continue;
      try {
        const branchReports = verifyFromAnchor(
          actionValue, chain, rootControl, anchor, contextValue, controlByStatement,
        );
        evaluateObservations(chain, anchor.principal, actionValue, canonical, contextValue, adapters);
        return { actionID: actionValue.id, reports: branchReports };
      } catch (error) {
        if (error instanceof Failure && firstFailure === undefined) firstFailure = error;
        else if (!(error instanceof Failure)) return { error: denied("malformed-proof") };
      }
    }
    return { error: firstFailure ?? denied("untrusted-root") };
  };
  const outcome = evaluatePlan(value.plan, branch, branches, actionIDs, reports);
  if (outcome.error) throw outcome.error;
  const uniqueBranches = uniqueDigests(branches);
  const uniqueAssurance = uniqueReports(reports);
  const actors = new Set(
    uniqueAssurance.filter((participant) => participant.role === 2n)
      .map((participant) => participant.principal),
  );
  const roots = new Set(
    uniqueAssurance.filter((participant) => participant.role === 0n)
      .map((participant) => participant.principal),
  );
  if (
    BigInt(uniqueBranches.length) < contextValue.composition.minimumAuthorizedBranches ||
    BigInt(actors.size) < contextValue.composition.minimumDistinctActors ||
    BigInt(roots.size) < contextValue.composition.minimumDistinctRoots
  ) throw denied("composition-requirement-not-met");
  return {
    actionIDs: uniqueDigests(actionIDs),
    branches: uniqueBranches,
    assurance: uniqueAssurance,
  };
}

function verifySemantic(
  name: string,
  proofBytes: Uint8Array,
  contextBytes: Uint8Array,
  actionBytes: Uint8Array,
  adapters: any,
): SemanticResult {
  const result: SemanticResult = {
    name, decision: "", code: "",
    proof: sha256(proofBytes), context: domainHash(9, contextBytes), action: sha256(actionBytes),
    plan: new Uint8Array(), actionIDs: [], branches: [], assurance: [],
  };
  try {
    const contextValue = context(contextBytes);
    // The canonical action is bounded and decoded before the proof is read,
    // so a rejected action leaves no plan digest.
    const canonical = boundedCanonicalAction(actionBytes, contextValue.limits);
    const proof = bundle(proofBytes, contextValue.limits);
    result.plan = domainHash(3, proof.plan.raw);
    if (contextValue.composition.expectedPlan !== undefined &&
        !equal(contextValue.composition.expectedPlan, result.plan)) {
      throw denied("composition-requirement-not-met");
    }
    const controls = resolveAndVerifyControl(proof, contextValue, adapters);
    const authority = verifyAuthority(proof, controls, contextValue, canonical, adapters);
    result.decision = "authorized";
    result.code = "authorized";
    result.actionIDs = authority.actionIDs;
    result.branches = authority.branches;
    result.assurance = authority.assurance;
  } catch (error) {
    if (error instanceof Failure) {
      result.decision = error.decision;
      result.code = error.code;
    } else {
      result.decision = "denied";
      result.code = "malformed-proof";
    }
  }
  return result;
}

function writeField(summary: ReturnType<typeof createHash>, value: string): void {
  summary.update(value);
  summary.update(Uint8Array.of(0));
}

function writeResult(summary: ReturnType<typeof createHash>, result: SemanticResult): void {
  const writeBytes = (value: Uint8Array) => writeField(summary, keyOf(value));
  writeField(summary, result.name);
  writeField(summary, result.decision);
  writeField(summary, result.code);
  writeBytes(result.proof);
  writeBytes(result.context);
  writeBytes(result.action);
  writeBytes(result.plan);
  result.actionIDs.forEach(writeBytes);
  writeField(summary, "|");
  result.branches.forEach(writeBytes);
  writeField(summary, "|");
  for (const participant of result.assurance) {
    writeField(summary, participant.principal);
    writeField(summary, participant.role.toString());
    writeField(summary, participant.adapter);
    const claims = [...participant.claims].sort((left, right) => {
      const kind = Buffer.compare(Buffer.from(left.kind), Buffer.from(right.kind));
      if (kind !== 0) return kind;
      if (left.observedAt === undefined || right.observedAt === undefined) {
        return left.observedAt === undefined ? -1 : 1;
      }
      return left.observedAt < right.observedAt ? -1 : left.observedAt > right.observedAt ? 1 : 0;
    });
    for (const claim of claims) {
      writeField(summary, claim.kind);
      writeField(summary, claim.observedAt?.toString() ?? "-");
    }
    writeField(summary, ";");
  }
  writeField(summary, "\n");
}

function decodeCanonicalAction(data: Uint8Array): CanonicalAction {
  const root = new Decoder(data).complete();
  exactMap(root, 6);
  const detached = array(mapAt(root, 5)).map((value) => {
    exactMap(value, 2);
    return {
      digest: bytes(mapAt(value, 0), 32),
      bytes: bytes(mapAt(value, 1)),
    };
  });
  return {
    profile: profile(mapAt(root, 0)),
    mediaType: text(mapAt(root, 1)),
    body: bytes(mapAt(root, 2)),
    permission: permission(mapAt(root, 3)),
    budget: budget(mapAt(root, 4)),
    detached,
  };
}

// The canonical-action input is decoded under the trusted context's
// deployment limits, before the proof is read. The input length is bounded
// before any byte is read; fields are read in key order, each bound checked
// as its field is read; and the unique canonical encoding is required only
// after the whole input has been read, so a shortest-form violation never
// hides a structural or bound failure that follows it.
class ActionReader {
  private at = 0;
  private readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  get complete(): boolean {
    return this.at === this.data.length;
  }

  nextIsNull(): boolean {
    if (this.data[this.at] !== 0xf6) return false;
    this.at += 1;
    return true;
  }

  // The argument need not use the shortest encoding; the final canonical
  // comparison rejects that.
  head(): [number, bigint] {
    if (this.at >= this.data.length) throw denied("malformed-proof");
    const initial = this.data[this.at++]!;
    const major = initial >>> 5;
    const additional = initial & 31;
    if (additional < 24) return [major, BigInt(additional)];
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    // Indefinite lengths and reserved values are unreadable here.
    if (width === 0 || this.data.length - this.at < width) throw denied("malformed-proof");
    let value = 0n;
    for (const octet of this.data.subarray(this.at, this.at + width)) {
      value = (value << 8n) | BigInt(octet);
    }
    this.at += width;
    return [major, value];
  }

  mapOf(entries: number): void {
    const [major, value] = this.head();
    if (major !== 5 || value !== BigInt(entries)) throw denied("malformed-proof");
  }

  // A key that is not a small unsigned integer is unreadable; a readable key
  // other than the next expected one is a non-canonical key order.
  key(expected: number): void {
    const [major, value] = this.head();
    if (major !== 0 || value > 0xffn) throw denied("malformed-proof");
    if (value !== BigInt(expected)) throw denied("non-canonical-proof");
  }

  unsigned(maximum: bigint): bigint {
    const [major, value] = this.head();
    if (major !== 0 || value > maximum) throw denied("malformed-proof");
    return value;
  }

  private span(expectedMajor: number): Uint8Array {
    const [major, length] = this.head();
    if (major !== expectedMajor || length > BigInt(this.data.length - this.at)) {
      throw denied("malformed-proof");
    }
    const value = this.data.slice(this.at, this.at + Number(length));
    this.at += Number(length);
    return value;
  }

  byteString(): Uint8Array {
    return this.span(2);
  }

  // A bounded protocol identifier: non-empty, at most `maximum` bytes,
  // without whitespace or control characters.
  identifier(maximum: number): string {
    const raw = this.span(3);
    let value: string;
    try {
      value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
    } catch {
      throw denied("malformed-proof");
    }
    if (raw.length === 0 || raw.length > maximum || /[\p{Cc}\p{White_Space}]/u.test(value)) {
      throw denied("malformed-proof");
    }
    return value;
  }
}

function actionHead(major: number, value: bigint): Uint8Array {
  if (value < 24n) return Uint8Array.of((major << 5) | Number(value));
  const [marker, width] = value <= 0xffn ? [24, 1] : value <= 0xffffn ? [25, 2] :
    value <= 0xffffffffn ? [26, 4] : [27, 8];
  const output = new Uint8Array(1 + width);
  output[0] = (major << 5) | marker;
  let remaining = value;
  for (let index = width; index > 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function actionText(value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  return Buffer.concat([actionHead(3, BigInt(encoded.length)), encoded]);
}

function actionByteString(value: Uint8Array): Uint8Array {
  return Buffer.concat([actionHead(2, BigInt(value.length)), value]);
}

// The unique canonical encoding of a decoded canonical action, with detached
// attachments in digest order.
function encodeCanonicalAction(value: CanonicalAction): Uint8Array {
  const key = (index: number) => Uint8Array.of(index);
  const parts: Uint8Array[] = [
    actionHead(5, 6n),
    key(0), actionHead(5, 2n), key(0), actionText(value.profile.id),
    key(1), actionHead(0, value.profile.version),
    key(1), actionText(value.mediaType),
    key(2), actionByteString(value.body),
    key(3), actionHead(5, 2n), key(0), actionText(value.permission.capability),
    key(1), actionText(value.permission.resource),
    key(4),
  ];
  if (value.budget === undefined) {
    parts.push(Uint8Array.of(0xf6));
  } else {
    parts.push(
      actionHead(5, 2n), key(0), actionText(value.budget.algebra),
      key(1), actionHead(0, value.budget.value),
    );
  }
  parts.push(key(5), actionHead(4, BigInt(value.detached.length)));
  for (const attachment of value.detached) {
    parts.push(
      actionHead(5, 2n), key(0), actionByteString(attachment.digest),
      key(1), actionByteString(attachment.bytes),
    );
  }
  return Buffer.concat(parts);
}

// Decodes the canonical-action input under the context's limits: input bytes
// (limit 1), body bytes (limit 23), detached attachment count (limit 13), and
// each and all detached attachment bytes (limit 14), with the native stable
// code for every failure.
function boundedCanonicalAction(data: Uint8Array, limits: bigint[]): CanonicalAction {
  if (BigInt(data.length) > limits[1]!) throw denied("resource-limit-exceeded");
  const reader = new ActionReader(data);
  reader.mapOf(6);
  reader.key(0);
  reader.mapOf(2);
  reader.key(0);
  const profileID = reader.identifier(128);
  reader.key(1);
  const version = reader.unsigned(0xffffn);
  if (version === 0n) throw denied("malformed-proof");
  reader.key(1);
  const mediaType = reader.identifier(128);
  reader.key(2);
  const body = reader.byteString();
  if (body.length === 0 || BigInt(body.length) > limits[23]!) {
    throw denied("resource-limit-exceeded");
  }
  reader.key(3);
  reader.mapOf(2);
  reader.key(0);
  const capability = reader.identifier(128);
  reader.key(1);
  const resource = reader.identifier(1024);
  reader.key(4);
  let requested: Budget | undefined;
  if (!reader.nextIsNull()) {
    reader.mapOf(2);
    reader.key(0);
    const algebra = reader.identifier(128);
    reader.key(1);
    requested = { algebra, value: reader.unsigned(0xffffffffffffffffn) };
  }
  reader.key(5);
  const [major, count] = reader.head();
  if (major !== 4) throw denied("malformed-proof");
  if (count > limits[13]!) throw denied("resource-limit-exceeded");
  const detached: DetachedAttachment[] = [];
  let total = 0n;
  for (let index = 0n; index < count; index += 1n) {
    reader.mapOf(2);
    reader.key(0);
    const digest = reader.byteString();
    if (digest.length !== 32) throw denied("malformed-proof");
    reader.key(1);
    const content = reader.byteString();
    const size = BigInt(content.length);
    if (size === 0n || size > limits[14]!) throw denied("resource-limit-exceeded");
    total += size;
    if (total > limits[14]!) throw denied("resource-limit-exceeded");
    detached.push({ digest, bytes: content });
  }
  const sorted = [...detached].sort((left, right) => Buffer.compare(left.digest, right.digest));
  if (sorted.some((value, index) => index > 0 && equal(value.digest, sorted[index - 1]!.digest))) {
    throw denied("malformed-proof");
  }
  if (!reader.complete) throw denied("malformed-proof");
  const action: CanonicalAction = {
    body, profile: { id: profileID, version }, mediaType,
    permission: { capability, resource }, budget: requested, detached: sorted,
  };
  if (!equal(encodeCanonicalAction(action), data)) throw denied("non-canonical-proof");
  return action;
}

export function semanticAudit(manifestPath: string): string {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as SemanticManifest;
  if (manifest.protocol_major !== 1 || manifest.fixtures.length === 0) {
    throw new Error("unsupported or empty Auths corpus");
  }
  const root = dirname(manifestPath);
  const summary = createHash("sha256");
  for (const fixture of manifest.fixtures) {
    const proofBytes = readFileSync(join(root, fixture.proof.path));
    const contextBytes = readFileSync(join(root, fixture.context.path));
    const actionBytes = readFileSync(join(root, fixture.canonical_action.path));
    const bodyBytes = readFileSync(join(root, fixture.canonical_body.path));
    const canonical = decodeCanonicalAction(actionBytes);
    if (!equal(canonical.body, bodyBytes)) {
      throw new Error(`${fixture.name} canonical action/body mismatch`);
    }
    const result = verifySemantic(
      fixture.name, proofBytes, contextBytes, actionBytes, manifest.adapter_context,
    );
    if (result.decision !== fixture.expected_decision || result.code !== fixture.expected_code) {
      throw new Error(
        `${fixture.name} independently derived ${result.decision}/${result.code}, ` +
        `manifest requires ${fixture.expected_decision}/${fixture.expected_code}`,
      );
    }
    writeResult(summary, result);
  }
  return `${manifest.fixtures.length}:${summary.digest("hex")}`;
}

// Evidence-conditioned authority: observation requirements carried by
// grants, signed observations attached to the action, and the per-branch
// observation stage. Written from the V1 specification, not from the Rust
// verifier.

const OBSERVATION_EXTENSION = "observation-requirement-v1";
const OBSERVATION_MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor";

class ObservationLimit extends Error {}

type FactValue = { kind: "uint"; uint: bigint } | { kind: "bytes"; bytes: Uint8Array } |
  { kind: "text"; text: string };
type ObservationCondition = {
  name: string; tag: bigint; literal?: FactValue; action?: string; lo?: bigint; hi?: bigint;
  members?: FactValue[];
};
type ObservationRequirement = {
  raw: Uint8Array; anchor: string; schema: string; subjectKind: bigint; subject: string;
  maxAge: bigint; conditions: ObservationCondition[];
};
type ObserverAnchor = {
  id: string; principal: string; methods: string[]; schemas: string[]; namespaces: string[];
  notBefore: bigint; expiresAt: bigint;
};
type SignedObservation = {
  digest: Uint8Array; observer: string; schema: string; subject: string; observedAt: bigint;
  facts: Array<{ name: string; value: FactValue }>; statementRaw: Uint8Array;
  signature: Signature; evidence: Evidence[]; authentic?: boolean;
};

function sameFact(left: FactValue, right: FactValue): boolean {
  if (left.kind === "uint" && right.kind === "uint") return left.uint === right.uint;
  if (left.kind === "bytes" && right.kind === "bytes") return equal(left.bytes, right.bytes);
  if (left.kind === "text" && right.kind === "text") return left.text === right.text;
  return false;
}

function boundedIdentifier(value: V, maximum: number): string {
  const result = text(value);
  if (result.length === 0 || Buffer.byteLength(result) > maximum || /[\s\p{Cc}]/u.test(result)) {
    throw new Error("invalid bounded identifier");
  }
  return result;
}

function factValue(value: V): FactValue {
  if (value.major === 0) return { kind: "uint", uint: value.uint };
  if (value.major === 2) {
    if (value.bytes!.length > 64) throw new ObservationLimit();
    return { kind: "bytes", bytes: value.bytes! };
  }
  if (value.major === 3) {
    if (Buffer.byteLength(value.text!) > 256) throw new ObservationLimit();
    return { kind: "text", text: value.text! };
  }
  throw new Error("invalid fact value");
}

function boundedArray(value: V, minimum: number, maximum: number): V[] {
  const items = array(value);
  if (items.length > maximum) throw new ObservationLimit();
  if (items.length < minimum) throw new Error("array below its minimum");
  return items;
}

function observationCondition(value: V): ObservationCondition {
  const tag = uint(mapAt(value, 0));
  exactMap(value, tag === 2n ? 4 : 3);
  const name = boundedIdentifier(mapAt(value, 1), 128);
  const operand = mapAt(value, 2);
  if (tag === 0n) return { name, tag, literal: factValue(operand) };
  if (tag === 1n) return { name, tag, action: boundedIdentifier(operand, 128) };
  if (tag === 2n) {
    const lo = uint(operand);
    const hi = uint(mapAt(value, 3));
    if (lo > hi) throw new Error("inverted range");
    return { name, tag, lo, hi };
  }
  if (tag === 3n) {
    const members: FactValue[] = [];
    for (const item of boundedArray(operand, 1, 16)) {
      const member = factValue(item);
      if (members.some((previous) => sameFact(previous, member))) {
        throw new Error("duplicate member value");
      }
      members.push(member);
    }
    return { name, tag, members };
  }
  throw new Error("unknown condition atom");
}

function observationRequirement(value: V): ObservationRequirement {
  exactMap(value, 5);
  const subject = mapAt(value, 2);
  exactMap(subject, 2);
  const subjectKind = uint(mapAt(subject, 0));
  if (subjectKind > 1n) throw new Error("unknown subject kind");
  const result: ObservationRequirement = {
    raw: value.raw,
    anchor: boundedIdentifier(mapAt(value, 0), 128),
    schema: boundedIdentifier(mapAt(value, 1), 128),
    subjectKind,
    subject: boundedIdentifier(mapAt(subject, 1), subjectKind === 0n ? 1024 : 128),
    maxAge: uint(mapAt(value, 3)),
    conditions: boundedArray(mapAt(value, 4), 1, 16).map(observationCondition),
  };
  if (result.maxAge === 0n || result.maxAge > 86400n) throw new Error("maximum age out of range");
  return result;
}

function observationRequirements(data: Uint8Array): ObservationRequirement[] {
  const requirements: ObservationRequirement[] = [];
  for (const node of boundedArray(new Decoder(data).complete(), 1, 8)) {
    const requirement = observationRequirement(node);
    if (requirements.some((previous) => equal(previous.raw, requirement.raw))) {
      throw new Error("duplicate observation requirement");
    }
    requirements.push(requirement);
  }
  return requirements;
}

function requirementFailure(error: unknown): Failure {
  return error instanceof ObservationLimit
    ? denied("resource-limit-exceeded")
    : denied("local-policy-denied");
}

function evaluateObservationExtension(value: Extension): void {
  try {
    observationRequirements(value.bytes);
  } catch (error) {
    throw requirementFailure(error);
  }
}

function observerAnchors(value: V): ObserverAnchor[] {
  const nodes = array(value);
  if (nodes.length > 32) throw denied("resource-limit-exceeded");
  const anchors: ObserverAnchor[] = [];
  for (const node of nodes) {
    exactMap(node, 7);
    const anchor: ObserverAnchor = {
      id: text(mapAt(node, 0)),
      principal: text(mapAt(node, 1)),
      methods: textArray(mapAt(node, 2)),
      schemas: textArray(mapAt(node, 3)),
      namespaces: textArray(mapAt(node, 4)),
      notBefore: uint(mapAt(node, 5)),
      expiresAt: uint(mapAt(node, 6)),
    };
    if (anchor.methods.length === 0 || anchor.schemas.length === 0 ||
        anchor.namespaces.length === 0 || anchor.notBefore > anchor.expiresAt) {
      throw new Error("invalid observer anchor");
    }
    const previous = anchors[anchors.length - 1];
    if (previous !== undefined && Buffer.compare(Buffer.from(previous.id), Buffer.from(anchor.id)) >= 0) {
      throw new Error("observer anchors are not strictly ordered");
    }
    anchors.push(anchor);
  }
  return anchors;
}

function signedObservation(data: Uint8Array, digest: Uint8Array, limits: bigint[]): SignedObservation {
  if (data.length > 4096) throw new ObservationLimit();
  const root = new Decoder(data).complete();
  exactMap(root, 3);
  const statement = mapAt(root, 0);
  exactMap(statement, 6);
  if (uint(mapAt(statement, 0)) !== 1n) throw new Error("unsupported observation version");
  const facts: Array<{ name: string; value: FactValue }> = [];
  for (const node of boundedArray(mapAt(statement, 5), 1, 16)) {
    exactMap(node, 2);
    const name = boundedIdentifier(mapAt(node, 0), 128);
    const previous = facts[facts.length - 1];
    if (previous !== undefined && Buffer.compare(Buffer.from(previous.name), Buffer.from(name)) >= 0) {
      throw new Error("observation facts are not strictly ordered");
    }
    facts.push({ name, value: factValue(mapAt(node, 1)) });
  }
  const signatureValue = signature(mapAt(root, 1));
  if (BigInt(signatureValue.signature.length) > limits[16]!) throw new ObservationLimit();
  const evidenceValues: Evidence[] = [];
  for (const node of boundedArray(mapAt(root, 2), 0, 4)) {
    const object = evidence(node, limits[9]!);
    const previous = evidenceValues[evidenceValues.length - 1];
    if (previous !== undefined && Buffer.compare(previous.id, object.id) >= 0) {
      throw new Error("observation evidence is not strictly ordered");
    }
    evidenceValues.push(object);
  }
  return {
    digest,
    observer: text(mapAt(statement, 1)),
    schema: boundedIdentifier(mapAt(statement, 2), 128),
    subject: boundedIdentifier(mapAt(statement, 3), 1024),
    observedAt: uint(mapAt(statement, 4)),
    facts,
    statementRaw: statement.raw,
    signature: signatureValue,
    evidence: evidenceValues,
  };
}

function validateObservationAttachments(actionValue: Action): void {
  let count = 0;
  for (const descriptor of actionValue.attachments) {
    if (text(mapAt(descriptor, 1)) !== OBSERVATION_MEDIA_TYPE) continue;
    count += 1;
    if (count > 32 || uint(mapAt(descriptor, 2)) > 4096n) throw denied("resource-limit-exceeded");
  }
}

function chainRequirements(chain: Grant[]): ObservationRequirement[] {
  const requirements: ObservationRequirement[] = [];
  for (const grantValue of chain) {
    for (const extension of grantValue.extensions) {
      if (extension.id !== OBSERVATION_EXTENSION) continue;
      let decoded: ObservationRequirement[];
      try {
        decoded = observationRequirements(extension.bytes);
      } catch (error) {
        throw requirementFailure(error);
      }
      for (const requirement of decoded) {
        if (!requirements.some((existing) => equal(existing.raw, requirement.raw))) {
          requirements.push(requirement);
        }
      }
    }
  }
  if (requirements.length > 32) throw denied("resource-limit-exceeded");
  return requirements;
}

/**
 * Denies a child grant that drops a parent's observation requirement: no
 * child requirement addresses it with the same schema and subject. A child
 * requirement that addresses it without keeping or narrowing it is left to the
 * delegation relation, which denies it as expanded.
 */
function requireParentRequirements(parent: Grant, child: Grant): void {
  const parentRequirements = chainRequirements([parent]);
  let childRequirements: ObservationRequirement[] = [];
  try {
    childRequirements = chainRequirements([child]);
  } catch {
    childRequirements = [];
  }
  for (const requirement of parentRequirements) {
    if (!childRequirements.some((candidate) =>
      candidate.schema === requirement.schema &&
      candidate.subjectKind === requirement.subjectKind &&
      candidate.subject === requirement.subject)) {
      throw denied("observation-requirement-dropped");
    }
  }
}

function sameCondition(left: ObservationCondition, right: ObservationCondition): boolean {
  if (left.name !== right.name || left.tag !== right.tag) return false;
  if (left.tag === 0n) return sameFact(left.literal!, right.literal!);
  if (left.tag === 1n) return left.action === right.action;
  if (left.tag === 2n) return left.lo === right.lo && left.hi === right.hi;
  return left.members!.length === right.members!.length &&
    left.members!.every((member, index) => sameFact(member, right.members![index]!));
}

/** Every atom of `wider` occurs in `narrower`. */
function conditionsInclude(narrower: ObservationCondition[], wider: ObservationCondition[]): boolean {
  return wider.every((condition) =>
    narrower.some((candidate) => sameCondition(candidate, condition)));
}

/**
 * The child keeps the parent byte-identical or strictly narrows it: the same
 * observer, schema, and subject; a maximum age no larger; a superset of
 * condition atoms; and the age or the atom set strictly narrower.
 */
function requirementCovers(child: ObservationRequirement, parent: ObservationRequirement): boolean {
  if (equal(child.raw, parent.raw)) return true;
  if (child.anchor !== parent.anchor || child.schema !== parent.schema ||
      child.subjectKind !== parent.subjectKind || child.subject !== parent.subject ||
      child.maxAge > parent.maxAge || !conditionsInclude(child.conditions, parent.conditions)) {
    return false;
  }
  return child.maxAge < parent.maxAge || !conditionsInclude(parent.conditions, child.conditions);
}

/** Every parent requirement is covered by some child requirement. */
function requirementsAttenuate(
  child: ObservationRequirement[], parent: ObservationRequirement[],
): boolean {
  return parent.every((requirement) =>
    child.some((candidate) => requirementCovers(candidate, requirement)));
}

function namespaceMatches(namespace: string, resource: string): boolean {
  return resource === namespace || (
    resource.startsWith(namespace) &&
    (namespace.endsWith("/") ||
      ["/", "?", "#"].includes(resource.slice(namespace.length, namespace.length + 1)))
  );
}

function observationConditionsHold(
  conditions: ObservationCondition[],
  facts: Array<{ name: string; value: FactValue }>,
): boolean {
  return conditions.every((condition) => {
    const observed = facts.find((fact) => fact.name === condition.name)?.value;
    if (observed === undefined) return false;
    if (condition.tag === 0n) return sameFact(observed, condition.literal!);
    if (condition.tag === 2n) {
      return observed.kind === "uint" && observed.uint >= condition.lo! && observed.uint <= condition.hi!;
    }
    if (condition.tag === 3n) return condition.members!.some((member) => sameFact(observed, member));
    return false;
  });
}

function observationAuthentic(
  candidate: SignedObservation,
  contextValue: Context,
  adapters: any,
): boolean {
  const descriptor = candidate.signature.descriptor;
  const preimage = signingPreimage(9, { id: "", version: 0n }, candidate.statementRaw, descriptor.raw);
  let verified: Control;
  try {
    verified = control(
      descriptor.method, candidate.observer, descriptor, 2n, candidate.observedAt,
      preimage, candidate.evidence, contextValue, adapters,
    );
  } catch {
    return false;
  }
  const consumed = verified.consumed.map((id) => keyOf(id)).sort();
  const supplied = candidate.evidence.map((object) => keyOf(object.id)).sort();
  if (consumed.length !== supplied.length || consumed.some((id, index) => id !== supplied[index])) {
    return false;
  }
  return verifySignature(
    descriptor.suite, verified.key, verified.signatureMessage ?? preimage,
    candidate.signature.signature,
  );
}

function observationEligible(
  requirement: ObservationRequirement,
  anchor: ObserverAnchor,
  candidate: SignedObservation,
  contextValue: Context,
  adapters: any,
): boolean {
  const now = contextValue.evaluationTime;
  if (candidate.observer !== anchor.principal || candidate.schema !== requirement.schema ||
      !contains(anchor.schemas, requirement.schema) || candidate.subject !== requirement.subject ||
      candidate.observedAt > now || now - candidate.observedAt > requirement.maxAge ||
      candidate.observedAt < anchor.notBefore || candidate.observedAt > anchor.expiresAt ||
      !contains(anchor.methods, candidate.signature.descriptor.method) ||
      !anchor.namespaces.some((namespace) => namespaceMatches(namespace, candidate.subject))) {
    return false;
  }
  candidate.authentic ??= observationAuthentic(candidate, contextValue, adapters);
  return candidate.authentic;
}

// The core registry's exact-v1 profile policy, the only one this verifier
// implements, defines no action facts.
function evaluateRequirement(
  requirement: ObservationRequirement,
  anchor: ObserverAnchor | undefined,
  candidates: SignedObservation[],
  contextValue: Context,
  adapters: any,
): Failure | undefined {
  if (anchor === undefined) return indeterminate("observation-missing");
  if (requirement.subjectKind === 1n || requirement.conditions.some((condition) => condition.tag === 1n)) {
    return indeterminate("observation-action-fact-unavailable");
  }
  let anyEligible = false;
  for (const candidate of candidates) {
    if (!observationEligible(requirement, anchor, candidate, contextValue, adapters)) continue;
    anyEligible = true;
    if (observationConditionsHold(requirement.conditions, candidate.facts)) return undefined;
  }
  return anyEligible
    ? denied("observation-condition-false")
    : indeterminate("observation-missing");
}

function observationCandidates(
  actionValue: Action,
  canonical: CanonicalAction,
  contextValue: Context,
): SignedObservation[] {
  const candidates: SignedObservation[] = [];
  for (const descriptor of actionValue.attachments) {
    if (text(mapAt(descriptor, 1)) !== OBSERVATION_MEDIA_TYPE) continue;
    const digest = bytes(mapAt(descriptor, 0), 32);
    const detached = canonical.detached.find((attachment) => equal(attachment.digest, digest));
    if (detached === undefined) continue;
    try {
      candidates.push(signedObservation(detached.bytes, digest, contextValue.limits));
    } catch (error) {
      if (error instanceof ObservationLimit) throw denied("resource-limit-exceeded");
      if (error instanceof Failure) throw error;
      throw denied("malformed-proof");
    }
  }
  return candidates.sort((left, right) => Buffer.compare(left.digest, right.digest));
}

function evaluateObservations(
  chain: Grant[],
  root: string,
  actionValue: Action,
  canonical: CanonicalAction,
  contextValue: Context,
  adapters: any,
): void {
  const requirements = chainRequirements(chain);
  if (requirements.length === 0) return;
  const authorities = new Set([root, actionValue.actor]);
  for (const grantValue of chain) {
    authorities.add(grantValue.issuer);
    authorities.add(grantValue.subject);
  }
  const anchors = requirements.map((requirement) =>
    contextValue.observerAnchors.find((anchor) => anchor.id === requirement.anchor));
  if (anchors.some((anchor) => anchor !== undefined && authorities.has(anchor.principal))) {
    throw denied("observer-in-authority-chain");
  }
  const candidates = observationCandidates(actionValue, canonical, contextValue);
  let unavailable: Failure | undefined;
  requirements.forEach((requirement, index) => {
    const failure = evaluateRequirement(requirement, anchors[index], candidates, contextValue, adapters);
    if (failure?.decision === "denied") throw failure;
    unavailable ??= failure;
  });
  if (unavailable !== undefined) throw unavailable;
}

// Bounded-policy commitments: the core shape of the
// bounded-policy-commitment-v1 grant critical extension and its link law.

const BOUNDED_POLICY_EXTENSION = "bounded-policy-commitment-v1";

class BoundedPolicyLimit extends Error {}

/** SHA-256 over the commitment prefix, protocol, framed domain, and framed payload. */
function domainCommitment(domain: string, payload: Uint8Array): Uint8Array {
  const domainBytes = Buffer.from(domain);
  const head = Buffer.alloc(4);
  head.writeUInt16BE(1, 0);
  head.writeUInt16BE(domainBytes.length, 2);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(payload.length));
  return createHash("sha256").update("AUTHS-COMMITMENT").update(head).update(domainBytes)
    .update(length).update(payload).digest();
}

function policyIdentifier(value: V, maximum: number): void {
  const result = text(value);
  if (result.length === 0 || Buffer.byteLength(result) > maximum || !/^[A-Za-z0-9./:_-]+$/.test(result)) {
    throw new Error("invalid policy identifier");
  }
}

/** Returns the parent link, or throws `BoundedPolicyLimit` for a size bound. */
function boundedPolicy(data: Uint8Array): { parent?: Uint8Array } {
  if (data.length > 65536) throw new BoundedPolicyLimit();
  const root = new Decoder(data).complete();
  exactMap(root, 3);
  const commitment = mapAt(root, 0);
  exactMap(commitment, 5);
  policyIdentifier(mapAt(commitment, 0), 128);
  const version = uint(mapAt(commitment, 1));
  if (version === 0n || version > 0xffffn) throw new Error("invalid policy version");
  policyIdentifier(mapAt(commitment, 2), 64);
  const digest = bytes(mapAt(commitment, 3), 32);
  policyIdentifier(mapAt(commitment, 4), 128);
  const policy = bytes(mapAt(root, 1));
  if (policy.length > 4096) throw new BoundedPolicyLimit();
  if (policy.length === 0) throw new Error("empty policy");
  const parent = optionalBytes(mapAt(root, 2));
  if (!equal(domainCommitment("auths.bounded-policy.v1", policy), digest)) {
    throw new Error("policy bytes do not open the commitment");
  }
  return { parent };
}

function evaluateBoundedPolicyExtension(value: Extension): void {
  try {
    boundedPolicy(value.bytes);
  } catch (error) {
    throw error instanceof BoundedPolicyLimit
      ? denied("resource-limit-exceeded")
      : denied("local-policy-denied");
  }
}

/**
 * A child keeps a bound only by linking the digest of the parent's exact
 * extension bytes, and adds one to an unbounded parent only without a link.
 */
function boundedPolicyLaw(child: Extension, parent: Extension | undefined): boolean {
  try {
    const decoded = boundedPolicy(child.bytes);
    if (parent === undefined) return decoded.parent === undefined;
    boundedPolicy(parent.bytes);
    return decoded.parent !== undefined &&
      equal(decoded.parent, domainCommitment("auths.bounded-policy-commitment.v1", parent.bytes));
  } catch {
    return false;
  }
}
