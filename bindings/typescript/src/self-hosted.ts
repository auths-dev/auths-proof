/** Exact application-owned MCP actions. Provider execution is not qualified. */

import { createVerifier, type VerificationResult } from "./verify.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";
import type { CustodySigner, PublicControlEvidence } from "./adapters.js";

export interface StringField {
  readonly kind: "string";
  readonly minBytes: number;
  readonly maxBytes: number;
}

export interface OptionalStringField {
  readonly kind: "optional-string";
  readonly minBytes: number;
  readonly maxBytes: number;
}

export interface IntegerField {
  readonly kind: "integer";
  readonly minimum: number;
  readonly maximum: number;
}

export interface BooleanField { readonly kind: "boolean" }

export type ScalarField = StringField | IntegerField | BooleanField;
export interface OptionalField<Inner extends ScalarField = ScalarField> {
  readonly kind: "optional";
  readonly inner: Inner;
}

export type Field = ScalarField | OptionalStringField | OptionalField;
export type FieldMap = Readonly<Record<string, Field>>;
export type ValueOf<Definition extends Field> =
  Definition extends OptionalField<infer Inner> ? ValueOf<Inner> | null
  : Definition extends OptionalStringField ? string | null
  : Definition extends IntegerField ? number
  : Definition extends BooleanField ? boolean
  : string;
export type CommandOf<Fields extends FieldMap> = Readonly<{
  [Key in keyof Fields]: ValueOf<Fields[Key]>;
}>;

export function stringField(bounds: Readonly<{ minBytes?: number; maxBytes: number }>): StringField {
  return stringFieldValue("string", bounds) as StringField;
}

export function optionalStringField(bounds: Readonly<{ minBytes?: number; maxBytes: number }>): OptionalStringField {
  return stringFieldValue("optional-string", bounds) as OptionalStringField;
}

function stringFieldValue(kind: "string" | "optional-string", bounds: Readonly<{ minBytes?: number; maxBytes: number }>): StringField | OptionalStringField {
  const minBytes = bounds.minBytes ?? 0;
  const maxBytes = bounds.maxBytes;
  if (!Number.isSafeInteger(minBytes) || !Number.isSafeInteger(maxBytes) ||
      minBytes < 0 || minBytes > maxBytes || maxBytes > 4096) {
    throw new RangeError("string field bounds are invalid");
  }
  return Object.freeze({ kind, minBytes, maxBytes });
}

export function integerField(bounds: Readonly<{ minimum: number; maximum: number }>): IntegerField {
  if (!Number.isSafeInteger(bounds.minimum) || !Number.isSafeInteger(bounds.maximum) ||
      bounds.minimum > bounds.maximum) {
    throw new RangeError("integer field bounds are invalid");
  }
  return Object.freeze({ kind: "integer", minimum: bounds.minimum, maximum: bounds.maximum });
}

export function booleanField(): BooleanField {
  return Object.freeze({ kind: "boolean" });
}

export function optionalField<Inner extends ScalarField>(inner: Inner): OptionalField<Inner> {
  return Object.freeze({ kind: "optional", inner: normalizeScalarField(inner) as Inner });
}

export interface PreparedMcpAction<Command> {
  readonly command: Command;
  readonly action: Uint8Array;
  readonly actionEnvelope: Uint8Array;
  readonly argumentsJson: Uint8Array;
  readonly actionCommitment: Uint8Array;
  readonly audience: string;
  readonly resource: string;
  readonly displayDigestHex: string;
}

export class ExactMcpTool<Fields extends FieldMap> {
  readonly service: string;
  readonly name: string;
  readonly #fields: Fields;

  constructor(config: Readonly<{ service: string; name: string; fields: Fields }>) {
    if (!/^[a-z0-9._-]{1,64}$/.test(config.service) ||
        !/^[A-Za-z0-9._-]{1,128}$/.test(config.name)) {
      throw new TypeError("invalid exact MCP service or tool");
    }
    const entries = Object.entries(config.fields);
    if (entries.length === 0 || entries.length > 32 ||
        entries.some(([name, value]) => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name) ||
          ["__proto__", "prototype", "constructor"].includes(name) ||
          value === null || typeof value !== "object" ||
          !["string", "optional-string", "integer", "boolean", "optional"].includes(value.kind))) {
      throw new TypeError("invalid closed command schema");
    }
    this.service = config.service;
    this.name = config.name;
    this.#fields = Object.freeze(Object.fromEntries(entries.map(([name, value]) => [
      name, normalizeField(value),
    ]))) as Fields;
    Object.freeze(this);
  }

  decode(value: unknown): CommandOf<Fields> {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError("MCP arguments must be a closed object");
    }
    const raw = value as Record<string, unknown>;
    const keys = Object.keys(raw);
    if (keys.length !== Object.keys(this.#fields).length ||
        keys.some((key) => !Object.hasOwn(this.#fields, key)) ||
        Object.getOwnPropertySymbols(raw).length !== 0) {
      throw new TypeError("MCP arguments do not match the closed schema");
    }
    const checked: Record<string, string | number | boolean | null> = {};
    const encoder = new TextEncoder();
    for (const [name, definition] of Object.entries(this.#fields)) {
      const descriptor = Object.getOwnPropertyDescriptor(raw, name);
      if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) {
        throw new TypeError("MCP argument accessors are not allowed");
      }
      const item = descriptor.value as unknown;
      if (item === null && (definition.kind === "optional-string" || definition.kind === "optional")) {
        checked[name] = null;
        continue;
      }
      const required = definition.kind === "optional" ? definition.inner : definition;
      if (required.kind === "integer") {
        if (typeof item !== "number" || !Number.isSafeInteger(item) ||
            Object.is(item, -0) || item < required.minimum || item > required.maximum) {
          throw new RangeError("MCP integer exceeds its safe bounds");
        }
        checked[name] = item;
      } else if (required.kind === "boolean") {
        if (typeof item !== "boolean") throw new TypeError("MCP argument must be a boolean");
        checked[name] = item;
      } else {
        if (typeof item !== "string") throw new TypeError("MCP argument must be a string");
        assertValidUnicode(item);
        const size = encoder.encode(item).length;
        if (size < required.minBytes || size > required.maxBytes) {
          throw new RangeError("MCP argument exceeds its byte bounds");
        }
        checked[name] = item;
      }
    }
    return Object.freeze(checked) as CommandOf<Fields>;
  }

  async prepare(command: CommandOf<Fields>, options: Readonly<{
    actor: string;
    terminalGrant: Uint8Array;
    challenge: Uint8Array;
    evaluationTime: bigint;
  }>): Promise<PreparedMcpAction<CommandOf<Fields>>> {
    const checked = this.decode(command);
    const engine = await loadPackagedWorkflowEngine();
    const prepared = engine.prepareMcpActionV1(
      this.service, this.name, checked, options.actor, options.terminalGrant,
      options.challenge, options.evaluationTime,
    );
    try {
      const action = prepared.canonicalActionCbor.slice();
      return Object.freeze({
        command: checked,
        action,
        actionEnvelope: prepared.actionEnvelopeCbor.slice(),
        argumentsJson: prepared.argumentsJson.slice(),
        actionCommitment: engine.commitCanonicalV1("auths.canonical-action.v1", action),
        audience: prepared.audience,
        resource: prepared.resource,
        displayDigestHex: prepared.displayDigestHex,
      });
    } finally {
      prepared.free?.();
    }
  }
}

export function exactMcpTool<Fields extends FieldMap>(config: Readonly<{
  service: string;
  name: string;
  fields: Fields;
}>): ExactMcpTool<Fields> {
  return new ExactMcpTool(config);
}

const authorizedCommandBrand: unique symbol = Symbol("auths-authorized-command");

export interface AuthorizedCommand<Command> {
  readonly kind: "authorized";
  readonly command: Command;
  readonly actionCommitment: Uint8Array;
  readonly decision: VerificationResult;
  readonly [authorizedCommandBrand]: true;
}

export type CommandResult<Command> =
  | AuthorizedCommand<Command>
  | Readonly<{
      kind: "denied" | "indeterminate";
      code: string;
      source: "auths-verifier" | "developer-contract";
      decision: VerificationResult;
    }>;

/** One-use persistence is application-owned; verification alone is reusable. */
export type AttemptState = "attempting" | "confirmed" | "rejected" | "unknown";
export interface AttemptRecord {
  readonly actionCommitment: Uint8Array;
  readonly operationKey: string;
  readonly state: AttemptState;
}
export interface AttemptStore {
  claimOnce(actionCommitment: Uint8Array, operationKey: string): Promise<boolean>;
  read(actionCommitment: Uint8Array): Promise<AttemptRecord | undefined>;
  finish(
    actionCommitment: Uint8Array,
    state: Exclude<AttemptState, "attempting">,
  ): Promise<AttemptRecord>;
}

export async function verifyCommand<Fields extends FieldMap>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  proof: Uint8Array;
  action: Uint8Array;
  trustedContext: Uint8Array;
}>): Promise<CommandResult<CommandOf<Fields>>> {
  const decision = (await createVerifier()).verify(input);
  if (decision.kind !== "authorized") {
    return Object.freeze({
      kind: decision.kind, code: decision.code, source: "auths-verifier", decision,
    });
  }
  const engine = await loadPackagedWorkflowEngine();
  const argumentsJson = engine.verifyExactMcpArgumentsV1(
    input.proof, input.action, input.trustedContext,
    input.contract.service, input.contract.name,
  );
  if (argumentsJson === undefined) {
    return Object.freeze({
      kind: "denied", code: "self-hosted.contract-mismatch",
      source: "developer-contract", decision,
    });
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(argumentsJson));
    const command = input.contract.decode(parsed);
    return Object.freeze({
      kind: "authorized", command,
      actionCommitment: engine.commitCanonicalV1("auths.canonical-action.v1", input.action),
      decision,
      [authorizedCommandBrand]: true,
    }) as AuthorizedCommand<CommandOf<Fields>>;
  } catch {
    return Object.freeze({
      kind: "denied", code: "self-hosted.contract-mismatch",
      source: "developer-contract", decision,
    });
  }
}

export interface GrantEvidence {
  readonly signedGrant: Uint8Array;
  readonly evidence: readonly PublicControlEvidence[];
}

export interface AuthoredMcpProof<Command> {
  readonly command: Command;
  readonly proof: Uint8Array;
  readonly action: Uint8Array;
  readonly trustedContext: Uint8Array;
  readonly actionCommitment: Uint8Array;
}

export class AuthoringUnsuccessful extends Error {
  readonly kind: "rejected" | "indeterminate";
  readonly code: string;

  constructor(kind: "rejected" | "indeterminate", code: string) {
    super(`proof authoring ${kind}: ${code}`);
    this.name = "AuthoringUnsuccessful";
    this.kind = kind;
    this.code = code;
  }
}

/** The signer, existing grants, and independent trust template are explicit. */
export async function authorMcpProof<Fields extends FieldMap>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  command: CommandOf<Fields>;
  grants: readonly GrantEvidence[];
  trustedContextTemplate: Uint8Array;
  signer: CustodySigner;
  challenge: Uint8Array;
  evaluationTime: bigint;
  signal?: AbortSignal;
}>): Promise<AuthoredMcpProof<CommandOf<Fields>>> {
  if (input.grants.length < 1 || input.grants.length > 16) {
    throw new RangeError("grant chain count is outside bounds");
  }
  if (input.challenge.length !== 32 || input.evaluationTime < 0n ||
      input.evaluationTime >= (1n << 64n) - 300n) {
    throw new RangeError("challenge or evaluation time is outside bounds");
  }
  const descriptor = input.signer.descriptor;
  if (descriptor.contract !== "signer-custody/2") {
    throw new TypeError("signer does not implement the custody contract");
  }
  for (const grant of input.grants) {
    if (grant.signedGrant.length < 1 || grant.signedGrant.length > 262_144 ||
        grant.evidence.length < 1 || grant.evidence.length > 32) {
      throw new RangeError("grant or its control evidence is outside bounds");
    }
  }
  const engine = await loadPackagedWorkflowEngine();
  const prepared = await input.contract.prepare(input.command, {
    actor: descriptor.principal,
    terminalGrant: input.grants[input.grants.length - 1]!.signedGrant,
    challenge: input.challenge,
    evaluationTime: input.evaluationTime,
  });
  const context = engine.bindTrustedContextRequestV1(
    input.trustedContextTemplate, prepared.audience,
    input.challenge, input.evaluationTime,
  );
  const signature = descriptor.signature;
  const request = engine.prepareActionSigningV1(
    prepared.actionEnvelope, signature.principalMethod,
    signature.verificationMethod, signature.suite,
  );
  const requestId = request.requestId;
  const objectId = request.objectId.slice();
  const transactionDigest = request.transactionDigest.slice();
  let outcome: Awaited<ReturnType<CustodySigner["sign"]>>;
  try {
    outcome = await input.signer.sign({
      requestId,
      objectKind: "action",
      objectId: objectId.slice(),
      descriptor,
      transactionDigest: transactionDigest.slice(),
      signingPreimage: request.signingPreimage.slice(),
      expiresAtUnixSeconds: input.evaluationTime + 300n,
      display: Object.freeze([
        { label: "service", value: input.contract.service },
        { label: "tool", value: input.contract.name },
        { label: "arguments", value: new TextDecoder("utf-8", { fatal: true }).decode(prepared.argumentsJson) },
        { label: "action digest", value: prepared.displayDigestHex },
      ]),
      signal: input.signal ?? new AbortController().signal,
    });
  } finally {
    request.free?.();
  }
  if (outcome.kind !== "signed") {
    throw new AuthoringUnsuccessful(
      outcome.kind === "rejected" ? "rejected" : "indeterminate", outcome.failure,
    );
  }
  const response = outcome.response;
  if (response.requestId !== requestId ||
      !bytesEqual(response.objectId, objectId) ||
      !bytesEqual(response.transactionDigest, transactionDigest) ||
      response.principal !== descriptor.principal ||
      response.providerKeyVersion !== descriptor.keyVersion ||
      response.descriptor.principalMethod !== signature.principalMethod ||
      response.descriptor.verificationMethod !== signature.verificationMethod ||
      response.descriptor.suite !== signature.suite ||
      response.evidence.length < 1 || response.evidence.length > 32) {
    throw new TypeError("custody response does not bind the exact signing request");
  }
  const signedAction = engine.completeActionSigningV1(
    prepared.actionEnvelope, signature.principalMethod,
    signature.verificationMethod, signature.suite, response.signature,
  );
  const builder = new engine.WorkflowProofBuilderV1();
  let artifacts;
  try {
    for (const grant of input.grants) {
      const index = builder.pushGrant(grant.signedGrant);
      for (const evidence of grant.evidence) {
        builder.bindGrantEvidence(index, evidence.type, evidence.mediaType, evidence.bytes);
      }
    }
    for (const evidence of response.evidence) {
      builder.bindActionEvidence(evidence.type, evidence.mediaType, evidence.bytes);
    }
    artifacts = builder.finish(signedAction, prepared.action, context);
  } finally {
    builder.free?.();
  }
  try {
    const proof = artifacts.proofCbor.slice();
    const trustedContext = artifacts.trustedContextCbor.slice();
    const decision = await verifyCommand({
      contract: input.contract, proof, action: prepared.action, trustedContext,
    });
    if (decision.kind !== "authorized") {
      throw new AuthoringUnsuccessful(
        decision.kind === "denied" ? "rejected" : "indeterminate", decision.code,
      );
    }
    return Object.freeze({
      command: decision.command, proof, action: prepared.action.slice(),
      trustedContext, actionCommitment: decision.actionCommitment,
    });
  } finally {
    artifacts.free?.();
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function assertValidUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("invalid Unicode surrogate in MCP argument");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError("invalid Unicode surrogate in MCP argument");
    }
  }
}

function normalizeField(value: Field): Field {
  switch (value.kind) {
    case "string": return stringField({ minBytes: value.minBytes, maxBytes: value.maxBytes });
    case "optional-string": return optionalStringField({ minBytes: value.minBytes, maxBytes: value.maxBytes });
    case "integer": return integerField({ minimum: value.minimum, maximum: value.maximum });
    case "boolean": return booleanField();
    case "optional": return optionalField(value.inner);
  }
}

function normalizeScalarField(value: ScalarField): ScalarField {
  switch (value.kind) {
    case "string": return stringField({ minBytes: value.minBytes, maxBytes: value.maxBytes });
    case "integer": return integerField({ minimum: value.minimum, maximum: value.maximum });
    case "boolean": return booleanField();
  }
}
