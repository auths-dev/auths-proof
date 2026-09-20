/** Exact application-owned MCP actions. Provider execution is not qualified. */

import { createVerifier, type VerificationResult } from "./verify.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";
import type { CustodySigner, PublicControlEvidence } from "./adapters.js";

export interface StringField {
  readonly kind: "string";
  readonly minBytes: number;
  readonly maxBytes: number;
}

interface OptionalStringField {
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

export interface BytesField {
  readonly kind: "bytes";
  readonly minBytes: number;
  readonly maxBytes: number;
}

type ScalarField = StringField | IntegerField | BooleanField | BytesField;
export interface OptionalField<Inner extends Field = Field> {
  readonly kind: "optional";
  readonly inner: Inner;
}

export interface ArrayField<Item extends Field = Field> {
  readonly kind: "array";
  readonly inner: Item;
  readonly minItems: number;
  readonly maxItems: number;
}

export interface ObjectField<Fields extends FieldMap = FieldMap> {
  readonly kind: "object";
  readonly fields: Fields;
}

export type Field = ScalarField | OptionalStringField | OptionalField | ArrayField | ObjectField;
export type FieldMap = Readonly<Record<string, Field>>;
type ValueOf<Definition extends Field> =
  Definition extends OptionalField<infer Inner> ? ValueOf<Inner> | null
  : Definition extends OptionalStringField ? string | null
  : Definition extends ArrayField<infer Item> ? readonly ValueOf<Item>[]
  : Definition extends ObjectField<infer Fields> ? CommandOf<Fields>
  : Definition extends BytesField ? Uint8Array
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

export function bytesField(bounds: Readonly<{ minBytes?: number; maxBytes: number }>): BytesField {
  const minBytes = bounds.minBytes ?? 0;
  if (!Number.isSafeInteger(minBytes) || !Number.isSafeInteger(bounds.maxBytes) ||
      minBytes < 0 || minBytes > bounds.maxBytes || bounds.maxBytes > 3072) {
    throw new RangeError("bytes field bounds are invalid");
  }
  return Object.freeze({ kind: "bytes", minBytes, maxBytes: bounds.maxBytes });
}

export function arrayField<Item extends Field>(inner: Item, bounds: Readonly<{
  minItems?: number; maxItems: number;
}>): ArrayField<Item> {
  const minItems = bounds.minItems ?? 0;
  if (!Number.isSafeInteger(minItems) || !Number.isSafeInteger(bounds.maxItems) ||
      minItems < 0 || minItems > bounds.maxItems || bounds.maxItems > 32 ||
      inner.kind === "optional" || inner.kind === "optional-string") {
    throw new RangeError("array item schema or bounds are invalid");
  }
  return Object.freeze({ kind: "array", inner: normalizeField(inner) as Item,
    minItems, maxItems: bounds.maxItems });
}

export function objectField<Fields extends FieldMap>(fields: Fields): ObjectField<Fields> {
  return Object.freeze({ kind: "object", fields: normalizeFields(fields) as Fields });
}

export function optionalField<Inner extends Field>(inner: Inner): OptionalField<Inner> {
  if (inner.kind === "optional" || inner.kind === "optional-string") {
    throw new TypeError("nested nullable fields are unsupported");
  }
  return Object.freeze({ kind: "optional", inner: normalizeField(inner) as Inner });
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
    const fields = normalizeFields(config.fields);
    if (schemaFieldCount(fields) > 32 || schemaDepth(fields) > 4) {
      throw new TypeError("command schema exceeds field or depth bounds");
    }
    this.service = config.service;
    this.name = config.name;
    this.#fields = fields as Fields;
    Object.freeze(this);
  }

  decode(value: unknown): CommandOf<Fields> {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError("MCP arguments must be a closed object");
    }
    return projectObject(this.#fields, value, true) as CommandOf<Fields>;
  }

  encode(command: CommandOf<Fields>): Readonly<Record<string, unknown>> {
    return projectObject(this.#fields, command, false) as Readonly<Record<string, unknown>>;
  }

  async prepare(command: CommandOf<Fields>, options: Readonly<{
    actor: string;
    terminalGrant: Uint8Array;
    challenge: Uint8Array;
    evaluationTime: bigint;
  }>): Promise<PreparedMcpAction<CommandOf<Fields>>> {
    const encoded = this.encode(command);
    const engine = await loadPackagedWorkflowEngine();
    const prepared = engine.prepareMcpActionV1(
      this.service, this.name, encoded, options.actor, options.terminalGrant,
      options.challenge, options.evaluationTime,
    );
    try {
      if (prepared.argumentsJson.length > 4096) {
        throw new RangeError("MCP arguments exceed the self-hosted bound");
      }
      const action = prepared.canonicalActionCbor.slice();
      return Object.freeze({
        command: this.decode(encoded),
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

export type Observation = "observed" | "not_observed" | "unavailable";
export type ProviderOutcome<Result> =
  | Readonly<{ kind: "accepted"; value: Result }>
  | Readonly<{ kind: "rejected"; code: string }>
  | Readonly<{ kind: "unknown"; code: string }>;

/** The app owns exact request mapping, token custody, and observation. */
export interface SelfHostedProviderAdapter<Command, Credential, Result> {
  credential(): Credential | Promise<Credential>;
  invoke(command: Command, credential: Credential): Promise<ProviderOutcome<Result>>;
  observe(command: Command): Promise<Observation>;
}

export type RunResult<Command, Result> =
  | Readonly<{ kind: "denied" | "indeterminate" | "replay" | "pre-entry-failed"; code: string }>
  | Readonly<{
      kind: "attempted";
      authorization: AuthorizedCommand<Command>;
      provider: ProviderOutcome<Result>;
      observation?: Observation;
    }>;

/** Verify/project, atomically claim, then access the credential and provider. */
export async function runOnce<Fields extends FieldMap, Credential, Result>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  proof: Uint8Array;
  action: Uint8Array;
  trustedContext: Uint8Array;
  attempts: AttemptStore;
  operationKey: string;
  adapter: SelfHostedProviderAdapter<CommandOf<Fields>, Credential, Result>;
  expectedCommand?: CommandOf<Fields>;
}>): Promise<RunResult<CommandOf<Fields>, Result>> {
  const authorization = await verifyCommand(input);
  if (authorization.kind !== "authorized") {
    return Object.freeze({ kind: authorization.kind, code: authorization.code });
  }
  if (input.expectedCommand !== undefined) {
    const expected: Readonly<Record<string, unknown>> = input.expectedCommand;
    if (Object.keys(expected).length !== Object.keys(authorization.command).length ||
        Object.entries(authorization.command).some(([name, value]) =>
          !Object.hasOwn(expected, name) || expected[name] !== value)) {
      return Object.freeze({ kind: "denied", code: "self-hosted.expected-command-mismatch" });
    }
  }
  const commitment = authorization.actionCommitment;
  if (!await input.attempts.claimOnce(commitment, input.operationKey)) {
    return Object.freeze({ kind: "replay", code: "self-hosted.attempt-already-claimed" });
  }
  let credential: Credential;
  try {
    credential = await input.adapter.credential();
  } catch {
    await input.attempts.finish(commitment, "rejected");
    return Object.freeze({ kind: "pre-entry-failed", code: "self-hosted.credential-unavailable" });
  }
  let provider: ProviderOutcome<Result>;
  try {
    provider = await input.adapter.invoke(authorization.command, credential);
  } catch (error) {
    await input.attempts.finish(commitment, "unknown");
    throw error;
  }
  if (provider?.kind === "accepted") {
    await input.attempts.finish(commitment, "confirmed");
  } else if (provider?.kind === "rejected") {
    await input.attempts.finish(commitment, "rejected");
  } else if (provider?.kind === "unknown") {
    await input.attempts.finish(commitment, "unknown");
  } else {
    await input.attempts.finish(commitment, "unknown");
    throw new TypeError("provider adapter returned an invalid outcome");
  }
  if (provider.kind !== "accepted") {
    return Object.freeze({ kind: "attempted", authorization, provider });
  }
  let observation: Observation;
  try {
    const value = await input.adapter.observe(authorization.command);
    observation = ["observed", "not_observed", "unavailable"].includes(value) ? value : "unavailable";
  } catch {
    observation = "unavailable";
  }
  return Object.freeze({ kind: "attempted", authorization, provider, observation });
}

/** Read only. An unknown provider effect must never be retried by this API. */
export async function reconcileReadOnly<Command, Credential, Result>(input: Readonly<{
  authorization: AuthorizedCommand<Command>;
  adapter: SelfHostedProviderAdapter<Command, Credential, Result>;
}>): Promise<Observation> {
  try {
    const value = await input.adapter.observe(input.authorization.command);
    return ["observed", "not_observed", "unavailable"].includes(value) ? value : "unavailable";
  } catch {
    return "unavailable";
  }
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

/** Structural production inputs; provenance of trust is an operator duty. */
export interface ProductionAuthoringInputs {
  readonly grants: readonly GrantEvidence[];
  readonly trustedContextTemplate: Uint8Array;
  readonly signer: CustodySigner;
  readonly challenge: Uint8Array;
  readonly evaluationTime: bigint;
  readonly signal?: AbortSignal;
}

/** Reject missing or development-only custody before requesting a signature. */
export async function authorProductionMcpProof<Fields extends FieldMap>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  command: CommandOf<Fields>;
  inputs: ProductionAuthoringInputs;
}>): Promise<AuthoredMcpProof<CommandOf<Fields>>> {
  const production = input.inputs;
  if (production.signer.descriptor.contract !== "signer-custody/2" ||
      production.signer.descriptor.lifecycle !== "durable" ||
      production.signer.descriptor.keyState !== "active-current") {
    throw new TypeError("production signer needs active-current durable custody");
  }
  if (production.trustedContextTemplate.length < 1 ||
      production.trustedContextTemplate.length > 262_144) {
    throw new RangeError("production trusted context size is outside bounds");
  }
  return authorMcpProof({
    contract: input.contract,
    command: input.command,
    grants: production.grants,
    trustedContextTemplate: production.trustedContextTemplate,
    signer: production.signer,
    challenge: production.challenge,
    evaluationTime: production.evaluationTime,
    ...(production.signal === undefined ? {} : { signal: production.signal }),
  });
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
    case "bytes": return bytesField({ minBytes: value.minBytes, maxBytes: value.maxBytes });
    case "array": return arrayField(value.inner, { minItems: value.minItems, maxItems: value.maxItems });
    case "object": return objectField(value.fields);
    case "optional": return optionalField(value.inner);
  }
}

function normalizeFields(fields: FieldMap): FieldMap {
  if (fields === null || typeof fields !== "object" || Array.isArray(fields) ||
      Object.getPrototypeOf(fields) !== Object.prototype ||
      Object.getOwnPropertySymbols(fields).length !== 0) {
    throw new TypeError("command fields must be a closed object");
  }
  const entries = Object.entries(fields);
  if (entries.length === 0 || entries.length > 32) {
    throw new RangeError("command field count is outside bounds");
  }
  return Object.freeze(Object.fromEntries(entries.map(([name, value]) => {
    const descriptor = Object.getOwnPropertyDescriptor(fields, name);
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name) ||
        ["__proto__", "prototype", "constructor"].includes(name) ||
        descriptor === undefined || !Object.hasOwn(descriptor, "value") ||
        value === null || typeof value !== "object") {
      throw new TypeError("invalid command field");
    }
    return [name, normalizeField(value)];
  })));
}

function schemaFieldCount(fields: FieldMap): number {
  return Object.values(fields).reduce((count, field) => count + fieldCount(field), 0);
}

function fieldCount(field: Field): number {
  switch (field.kind) {
    case "optional": return fieldCount(field.inner);
    case "array": return fieldCount(field.inner);
    case "object": return schemaFieldCount(field.fields);
    default: return 1;
  }
}

function schemaDepth(fields: FieldMap): number {
  return 1 + Math.max(...Object.values(fields).map(fieldDepth));
}

function fieldDepth(field: Field): number {
  switch (field.kind) {
    case "optional": return fieldDepth(field.inner);
    case "array": return 1 + fieldDepth(field.inner);
    case "object": return schemaDepth(field.fields);
    default: return 0;
  }
}

function projectObject(fields: FieldMap, value: unknown, wire: boolean): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError("MCP arguments must be a closed object");
  }
  const source = value as Record<string, unknown>;
  const names = Object.keys(source);
  if (names.length !== Object.keys(fields).length ||
      names.some(name => !Object.hasOwn(fields, name))) {
    throw new TypeError("MCP arguments do not match the closed schema");
  }
  const checked: Record<string, unknown> = {};
  for (const [name, field] of Object.entries(fields)) {
    const descriptor = Object.getOwnPropertyDescriptor(source, name);
    if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) {
      throw new TypeError("MCP argument accessors are not allowed");
    }
    checked[name] = projectField(field, descriptor.value, wire);
  }
  return Object.freeze(checked);
}

function projectField(field: Field, value: unknown, wire: boolean): unknown {
  if (field.kind === "optional" || field.kind === "optional-string") {
    if (value === null) return null;
    if (field.kind === "optional") return projectField(field.inner, value, wire);
  }
  switch (field.kind) {
    case "string":
    case "optional-string": {
      if (typeof value !== "string") throw new TypeError("MCP argument must be a string");
      assertValidUnicode(value);
      const size = new TextEncoder().encode(value).length;
      if (size < field.minBytes || size > field.maxBytes) {
        throw new RangeError("MCP string exceeds its byte bounds");
      }
      return value;
    }
    case "integer":
      if (typeof value !== "number" || !Number.isSafeInteger(value) ||
          Object.is(value, -0) || value < field.minimum || value > field.maximum) {
        throw new RangeError("MCP integer exceeds its safe bounds");
      }
      return value;
    case "boolean":
      if (typeof value !== "boolean") throw new TypeError("MCP argument must be a boolean");
      return value;
    case "bytes": {
      let bytes: Uint8Array;
      if (wire) {
        if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
          throw new TypeError("MCP bytes need unpadded base64url");
        }
        try {
          const text = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
          bytes = Uint8Array.from(text, char => char.charCodeAt(0));
        } catch {
          throw new TypeError("MCP bytes are malformed");
        }
        if (base64url(bytes) !== value) throw new TypeError("MCP bytes are noncanonical");
      } else {
        if (!(value instanceof Uint8Array)) throw new TypeError("MCP argument must be bytes");
        bytes = value.slice();
      }
      if (bytes.length < field.minBytes || bytes.length > field.maxBytes) {
        throw new RangeError("MCP bytes exceed their bounds");
      }
      return wire ? bytes : base64url(bytes);
    }
    case "array": {
      if (!Array.isArray(value) || value.length < field.minItems || value.length > field.maxItems) {
        throw new RangeError("MCP array item count is outside bounds");
      }
      return Object.freeze(value.map(item => projectField(field.inner, item, wire)));
    }
    case "object": return projectObject(field.fields, value, wire);
    case "optional": throw new TypeError("unexpected nullable field");
  }
}

function base64url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
