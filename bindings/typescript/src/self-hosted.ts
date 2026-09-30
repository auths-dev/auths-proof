/** Exact application-owned MCP actions. Provider execution is not qualified. */

import { createVerifier, type VerificationResult } from "./verify.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";
import { checkedValidity } from "./internal/action-validity.js";
import type { CustodySigner, PublicControlEvidence, ReviewField, SigningRequest } from "./adapters.js";

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

export interface EnumField<Variants extends readonly string[] = readonly string[]> {
  readonly kind: "enum";
  readonly variants: Variants;
}

class UnknownEnumVariant extends TypeError {
  readonly code = "self-hosted.enum-variant-undeclared";
  readonly stage = "contract";
  constructor() { super("unknown enum variant"); }
}

export interface BytesField {
  readonly kind: "bytes";
  readonly minBytes: number;
  readonly maxBytes: number;
}

type ScalarField = StringField | IntegerField | BooleanField | BytesField | EnumField;
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
type ValueOf<Definition extends Field, Depth extends readonly unknown[] = []> =
  Depth["length"] extends 6 ? never
  : Definition extends OptionalField<infer Inner> ? ValueOf<Inner, [0, ...Depth]> | null
  : Definition extends OptionalStringField ? string | null
  : Definition extends EnumField<infer Variants> ? Variants[number]
  : Definition extends ArrayField<infer Item> ? readonly ValueOf<Item, [0, ...Depth]>[]
  : Definition extends ObjectField<infer Fields> ? CommandOf<Fields, [0, ...Depth]>
  : Definition extends BytesField ? Uint8Array
  : Definition extends IntegerField ? number
  : Definition extends BooleanField ? boolean
  : string;
export type CommandOf<Fields extends FieldMap, Depth extends readonly unknown[] = []> = Readonly<{
  [Key in keyof Fields]: ValueOf<Fields[Key], Depth>;
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

export function enumField<const Variants extends readonly [string, ...string[]]>(variants: Variants): EnumField<Variants> {
  if (!Array.isArray(variants) || Object.getPrototypeOf(variants) !== Array.prototype ||
      variants.length < 1 || variants.length > 32 ||
      variants.some(item => typeof item !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(item)) ||
      new Set(variants).size !== variants.length) {
    throw new TypeError("enum variants must be unique bounded ASCII names");
  }
  return Object.freeze({ kind: "enum", variants: Object.freeze([...variants]) }) as EnumField<Variants>;
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

  /**
   * Prepares the unsigned exact action, valid from `evaluationTime` for `validitySeconds`
   * (the native default when omitted, bounded natively) and cut to the terminal grant's
   * expiry, so a verifier with its own later clock, such as a gateway, accepts it inside
   * that window. The window is not a replay defence, and it never extends an observation's
   * maximum age, which is judged at the verifier's evaluation time.
   */
  async prepare(command: CommandOf<Fields>, options: Readonly<{
    actor: string;
    terminalGrant: Uint8Array;
    challenge: Uint8Array;
    evaluationTime: bigint;
    validitySeconds?: number;
  }>): Promise<PreparedMcpAction<CommandOf<Fields>>> {
    const encoded = this.encode(command);
    const validitySeconds = checkedValidity(options.validitySeconds);
    const engine = await loadPackagedWorkflowEngine();
    const prepared = engine.prepareMcpActionV1(
      this.service, this.name, encoded, options.actor, options.terminalGrant,
      options.challenge, options.evaluationTime, validitySeconds,
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

/**
 * One signed observation to carry with an action. A gateway `GatewaySignedObservation`
 * satisfies this shape: `observation` is the exact signed bytes and `mediaType` their
 * declared media type.
 */
export interface SignedObservationAttachment {
  readonly mediaType: string;
  readonly observation: Uint8Array;
}

/**
 * Returns `prepared` carrying each observation as a detached attachment whose descriptor
 * the unsigned action statement binds, so sign the returned action, not the original.
 * Native code checks only media type, size, count, and distinctness; whether an
 * observation is authentic, fresh, about the right subject, and satisfies a grant's
 * conditions is decided by the verifier. Attach at most once.
 */
export async function attachObservations<Command>(
  prepared: PreparedMcpAction<Command>,
  observations: readonly SignedObservationAttachment[],
): Promise<PreparedMcpAction<Command>> {
  if (!Array.isArray(observations)) {
    throw new TypeError("observations must be an array");
  }
  const offered = observations.map((item) => {
    if (item === null || typeof item !== "object" || typeof item.mediaType !== "string" ||
        !(item.observation instanceof Uint8Array)) {
      throw new TypeError("each observation needs a media type and signed bytes");
    }
    return Object.freeze({ mediaType: item.mediaType, observation: item.observation.slice() });
  });
  const engine = await loadPackagedWorkflowEngine();
  const attached = engine.attachObservationsV1(prepared.action, prepared.actionEnvelope, offered);
  try {
    const action = attached.canonicalActionCbor.slice();
    return Object.freeze({
      ...prepared,
      action,
      actionEnvelope: attached.actionEnvelopeCbor.slice(),
      actionCommitment: engine.commitCanonicalV1("auths.canonical-action.v1", action),
    });
  } finally {
    attached.free?.();
  }
}

export function exactMcpTool<Fields extends FieldMap>(config: Readonly<{
  service: string;
  name: string;
  fields: Fields;
}>): ExactMcpTool<Fields> {
  return new ExactMcpTool<Fields>(config);
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
    try {
      const expected = input.contract.encode(input.expectedCommand);
      const actual = input.contract.encode(authorization.command);
      if (!sameEncodedValue(expected, actual)) {
        return Object.freeze({ kind: "denied", code: "self-hosted.expected-command-mismatch" });
      }
    } catch {
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

/** Application guard over already schema-validated values, not a wire codec. */
function sameEncodedValue(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((item, index) => sameEncodedValue(item, right[index]));
  }
  const leftFields = Object.keys(left);
  const rightFields = Object.keys(right);
  return leftFields.length === rightFields.length && leftFields.every(key =>
    Object.hasOwn(right, key) && sameEncodedValue(
      (left as Record<string, unknown>)[key], (right as Record<string, unknown>)[key],
    ));
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
  } catch (error) {
    return Object.freeze({
      kind: "denied", code: error instanceof UnknownEnumVariant
        ? error.code : "self-hosted.contract-mismatch",
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
  observations?: readonly SignedObservationAttachment[];
  validitySeconds?: number;
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
    ...(input.observations === undefined ? {} : { observations: input.observations }),
    ...(input.validitySeconds === undefined ? {} : { validitySeconds: input.validitySeconds }),
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
  observations?: readonly SignedObservationAttachment[];
  validitySeconds?: number;
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
  const unattached = await input.contract.prepare(input.command, {
    actor: descriptor.principal,
    terminalGrant: input.grants[input.grants.length - 1]!.signedGrant,
    challenge: input.challenge,
    evaluationTime: input.evaluationTime,
    ...(input.validitySeconds === undefined ? {} : { validitySeconds: input.validitySeconds }),
  });
  const prepared = input.observations === undefined || input.observations.length === 0
    ? unattached
    : await attachObservations(unattached, input.observations);
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

/**
 * Projection of the native approval requirement every approval binds: any
 * `required` of the listed `approvers`, whoever responds. The verifier's
 * trusted context must carry the same requirement; a proof never sets its
 * own threshold.
 */
export interface QuorumRequirement {
  readonly required: number;
  /** The listed approvers in ascending order. */
  readonly approvers: readonly string[];
  readonly requirementId: Uint8Array;
  /** The action and every approval are valid from `validFrom` through `validUntil` inclusive. */
  readonly validFrom: bigint;
  readonly validUntil: bigint;
}

export interface AuthoredMcpQuorumProof<Command> extends AuthoredMcpProof<Command> {
  readonly requirement: QuorumRequirement;
}

const MAX_QUORUM_APPROVERS = 16;
const MAX_APPROVAL_EVIDENCE = 4;

type Engine = Awaited<ReturnType<typeof loadPackagedWorkflowEngine>>;
type NativeQuorum = ReturnType<Engine["prepareMcpQuorumV1"]>;
type SigningSource = Readonly<{
  objectKind: string;
  requestId: string;
  objectId: Uint8Array;
  transactionDigest: Uint8Array;
  signingPreimage: Uint8Array;
}>;

interface QuorumInputs {
  readonly service: string;
  readonly name: string;
  readonly encoded: unknown;
  readonly approvers: readonly string[];
  readonly required: number;
  readonly actor: string;
  readonly actorGrant: Uint8Array | undefined;
  readonly challenge: Uint8Array;
  readonly evaluationTime: bigint;
  readonly validitySeconds: number | undefined;
}

function checkedQuorum(approvers: unknown, required: unknown): readonly string[] {
  if (!Array.isArray(approvers) || approvers.length < 1 || approvers.length > MAX_QUORUM_APPROVERS) {
    throw new RangeError("approval requirement lists 1 to 16 approvers");
  }
  if (typeof required !== "number" || !Number.isInteger(required) || required < 1 ||
      required > approvers.length) {
    throw new RangeError("approval threshold is outside 1 to the approver count");
  }
  return Object.freeze(approvers.map((approver) => checkedText(approver, "approver")));
}

function checkedRequest(challenge: unknown, evaluationTime: unknown): void {
  if (!(challenge instanceof Uint8Array) || challenge.length !== 32 ||
      typeof evaluationTime !== "bigint" || evaluationTime < 0n || evaluationTime > MAX_UINT64) {
    throw new RangeError("challenge or evaluation time is outside bounds");
  }
}

function checkedGrants(grants: readonly GrantEvidence[]): readonly GrantEvidence[] {
  if (!Array.isArray(grants) || grants.length > 16) {
    throw new RangeError("actor grant chain is outside bounds");
  }
  for (const grant of grants) {
    if (!(grant?.signedGrant instanceof Uint8Array) || grant.signedGrant.length < 1 ||
        grant.signedGrant.length > 262_144 || !Array.isArray(grant.evidence) ||
        grant.evidence.length < 1 || grant.evidence.length > 32) {
      throw new RangeError("grant or its control evidence is outside bounds");
    }
  }
  return grants;
}

function custodyOf(signer: CustodySigner): CustodySigner["descriptor"] {
  const descriptor = signer?.descriptor;
  if (descriptor?.contract !== "signer-custody/2") {
    throw new TypeError("signer does not implement the custody contract");
  }
  return descriptor;
}

function prepareQuorum(engine: Engine, inputs: QuorumInputs): NativeQuorum {
  return engine.prepareMcpQuorumV1(
    inputs.service, inputs.name, inputs.encoded, inputs.required, inputs.approvers,
    inputs.actor, inputs.actorGrant, inputs.challenge, inputs.evaluationTime,
    inputs.validitySeconds,
  );
}

function withQuorum<T>(engine: Engine, inputs: QuorumInputs, use: (quorum: NativeQuorum) => T): T {
  const quorum = prepareQuorum(engine, inputs);
  try {
    return use(quorum);
  } finally {
    quorum.free?.();
  }
}

function requirementOf(quorum: NativeQuorum): QuorumRequirement {
  const validity = quorum.validity;
  if (validity.length !== 2) throw new TypeError("native quorum validity is inconsistent");
  return Object.freeze({
    required: quorum.required,
    approvers: Object.freeze([...quorum.approvers]),
    requirementId: quorum.requirementId.slice(),
    validFrom: validity[0]!,
    validUntil: validity[1]!,
  });
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function quorumDisplay(service: string, name: string, quorum: NativeQuorum): readonly ReviewField[] {
  return Object.freeze([
    { label: "service", value: service },
    { label: "tool", value: name },
    { label: "arguments", value: new TextDecoder("utf-8", { fatal: true }).decode(quorum.argumentsJson) },
    { label: "action digest", value: quorum.displayDigestHex },
    { label: "actor", value: quorum.actor },
    { label: "approvals required", value: `any ${quorum.required} of ${quorum.approvers.length}` },
    { label: "approval requirement", value: hex(quorum.requirementId) },
  ].map((field) => Object.freeze(field)));
}

/**
 * Sends one exact native signing request to custody and returns the
 * signature and its evidence once the response binds that request.
 */
async function signExactly(
  signer: CustodySigner,
  native: SigningSource,
  objectKind: SigningRequest["objectKind"],
  expiresAtUnixSeconds: bigint,
  display: readonly ReviewField[],
  signal: AbortSignal,
  maximumEvidence: number,
): Promise<Readonly<{ signature: Uint8Array; evidence: readonly PublicControlEvidence[] }>> {
  const descriptor = signer.descriptor;
  const signature = descriptor.signature;
  const requestId = native.requestId;
  const objectId = native.objectId.slice();
  const transactionDigest = native.transactionDigest.slice();
  if (native.objectKind !== objectKind) throw new TypeError("native signing request kind is inconsistent");
  const outcome = await signer.sign({
    requestId, objectKind, objectId: objectId.slice(), descriptor,
    transactionDigest: transactionDigest.slice(),
    signingPreimage: native.signingPreimage.slice(),
    expiresAtUnixSeconds, display, signal,
  });
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
      response.evidence.length < 1 || response.evidence.length > maximumEvidence) {
    throw new TypeError("custody response does not bind the exact signing request");
  }
  return Object.freeze({ signature: response.signature.slice(), evidence: response.evidence });
}

/**
 * The actor's signed envelope with its grant chain (root first; empty when
 * the actor is a trust anchor) and the public evidence controlling its
 * signature, as `signApprovalAction` returns it.
 */
export interface ApprovalAction {
  readonly signedAction: Uint8Array;
  readonly grants: readonly GrantEvidence[];
  readonly evidence: readonly PublicControlEvidence[];
}

type NativeAction = InstanceType<Engine["McpQuorumActionV1"]>;

function nativeAction(engine: Engine, action: ApprovalAction): NativeAction {
  if (!(action?.signedAction instanceof Uint8Array) || action.signedAction.length < 1 ||
      action.signedAction.length > 262_144 || !Array.isArray(action.evidence) ||
      action.evidence.length < 1 || action.evidence.length > 32) {
    throw new RangeError("signed action or its control evidence is outside bounds");
  }
  const grants = checkedGrants(action.grants);
  const native = new engine.McpQuorumActionV1(action.signedAction);
  try {
    for (const grant of grants) {
      const index = native.pushGrant(grant.signedGrant);
      for (const evidence of grant.evidence) {
        native.bindGrantEvidence(index, evidence.type, evidence.mediaType, evidence.bytes);
      }
    }
    for (const evidence of action.evidence) {
      native.bindActionEvidence(evidence.type, evidence.mediaType, evidence.bytes);
    }
    return native;
  } catch (error) {
    native.free?.();
    throw error;
  }
}

/**
 * Author one exact action approved by any `required` of the listed
 * `approvers`. `actor` signs one action envelope under its own grant chain
 * `grants`, root first (omitted when the actor is itself a trust anchor);
 * each of `signers` signs one approval statement bound to the action, the
 * audience and challenge, and the approval requirement. `signers` are the
 * custody signers of the approvers who approve: each a distinct listed
 * approver, at least `required` of them. The actor is never an approver.
 * The actor and the approvers are asked concurrently; no signer is closed. Approvers carry no
 * grants: the verifier's trusted context names them with approver anchors
 * and carries the requirement, so the threshold never comes from the proof.
 * The action and every approval are valid from `evaluationTime` for
 * `validitySeconds` (the native quorum default when omitted, bounded
 * natively), cut to the actor's terminal-grant expiry; each custody request
 * stays valid for the whole window. The assembled proof is verified locally
 * against `trustedContextTemplate`; a denial raises `AuthoringUnsuccessful`
 * with the verifier's code. A declining signer raises `AuthoringUnsuccessful`;
 * malformed input raises `TypeError` or `RangeError` before any signature is
 * requested.
 */
export async function authorMcpQuorumProof<Fields extends FieldMap>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  command: CommandOf<Fields>;
  actor: CustodySigner;
  grants?: readonly GrantEvidence[];
  required: number;
  approvers: readonly string[];
  signers: readonly CustodySigner[];
  trustedContextTemplate: Uint8Array;
  challenge: Uint8Array;
  evaluationTime: bigint;
  validitySeconds?: number;
  signal?: AbortSignal;
}>): Promise<AuthoredMcpQuorumProof<CommandOf<Fields>>> {
  const approvers = checkedQuorum(input.approvers, input.required);
  checkedRequest(input.challenge, input.evaluationTime);
  const actor = custodyOf(input.actor);
  const grants = checkedGrants(input.grants ?? []);
  const signers = input.signers;
  if (!Array.isArray(signers) || signers.length < input.required || signers.length > approvers.length) {
    throw new RangeError("signers must be at least the required number of listed approvers");
  }
  const approving = new Set<string>();
  for (const signer of signers) {
    const principal = custodyOf(signer).principal;
    if (!approvers.includes(principal)) throw new TypeError("a signer is not a listed approver");
    if (approving.has(principal)) throw new TypeError("an approver appears twice among the signers");
    approving.add(principal);
  }
  const validitySeconds = checkedValidity(input.validitySeconds);
  const engine = await loadPackagedWorkflowEngine();
  const quorum = prepareQuorum(engine, {
    service: input.contract.service,
    name: input.contract.name,
    encoded: input.contract.encode(input.command),
    approvers,
    required: input.required,
    actor: actor.principal,
    actorGrant: grants.at(-1)?.signedGrant,
    challenge: input.challenge,
    evaluationTime: input.evaluationTime,
    validitySeconds,
  });
  try {
    const action = quorum.canonicalActionCbor.slice();
    const requirement = requirementOf(quorum);
    const context = engine.bindTrustedContextRequestV1(
      input.trustedContextTemplate, quorum.audience, input.challenge, input.evaluationTime,
    );
    const display = quorumDisplay(input.contract.service, input.contract.name, quorum);
    const signal = input.signal ?? new AbortController().signal;
    const envelope = quorum.actionEnvelopeCbor.slice();
    const signature = actor.signature;
    const actorRequest = engine.prepareActionSigningV1(
      envelope, signature.principalMethod, signature.verificationMethod, signature.suite,
    );
    const approvalRequests = signers.map((signer) => {
      const method = signer.descriptor.signature;
      return quorum.prepareApprovalSigning(
        signer.descriptor.principal, method.principalMethod, method.verificationMethod, method.suite,
      );
    });
    let signedAction: Readonly<{ signature: Uint8Array; evidence: readonly PublicControlEvidence[] }>;
    let signedApprovals: Readonly<{ signature: Uint8Array; evidence: readonly PublicControlEvidence[] }>[];
    try {
      [signedAction, signedApprovals] = await Promise.all([
        signExactly(input.actor, actorRequest, "action", requirement.validUntil, display, signal, 32),
        Promise.all(signers.map((signer, index) => signExactly(
          signer, approvalRequests[index]!, "approval", requirement.validUntil, display, signal,
          MAX_APPROVAL_EVIDENCE,
        ))),
      ]);
    } finally {
      actorRequest.free?.();
      for (const request of approvalRequests) request.free?.();
    }
    const native = nativeAction(engine, {
      signedAction: engine.completeActionSigningV1(
        envelope, signature.principalMethod, signature.verificationMethod, signature.suite,
        signedAction.signature,
      ),
      grants,
      evidence: signedAction.evidence,
    });
    const builder = new engine.McpQuorumProofBuilderV1();
    let proof: Uint8Array;
    try {
      signers.forEach((signer, index) => {
        const method = signer.descriptor.signature;
        const approval = signedApprovals[index]!;
        const slot = builder.addApproval(
          signer.descriptor.principal, method.principalMethod, method.verificationMethod,
          method.suite, approval.signature,
        );
        for (const evidence of approval.evidence) {
          builder.bindApprovalEvidence(slot, evidence.type, evidence.mediaType, evidence.bytes);
        }
      });
      proof = builder.finish(quorum, native).slice();
    } finally {
      builder.free?.();
      native.free?.();
    }
    const decision = await verifyCommand({
      contract: input.contract, proof, action, trustedContext: context,
    });
    if (decision.kind !== "authorized") {
      throw new AuthoringUnsuccessful(
        decision.kind === "denied" ? "rejected" : "indeterminate", decision.code,
      );
    }
    return Object.freeze({
      command: decision.command, proof, action, trustedContext: context.slice(),
      actionCommitment: decision.actionCommitment, requirement,
    });
  } finally {
    quorum.free?.();
  }
}

/** A remote approval operation refused its input with a stable `approval.*` code. */
export class ApprovalRefused extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "ApprovalRefused";
    this.code = code;
  }
}

function refusals<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (error instanceof Error && error.name === "ApprovalRefused") {
      throw new ApprovalRefused(String((error as Error & { code?: unknown }).code));
    }
    throw error;
  }
}

/**
 * One exact action and its approval requirement, built for approvers on
 * their own devices. `action` is the canonical action the assembled proof
 * carries; `actor` signs it with `signApprovalAction`.
 */
export interface ApprovalProposal<Command> {
  readonly command: Command;
  readonly action: Uint8Array;
  readonly actor: string;
  readonly requirement: QuorumRequirement;
}

/** One request, addressed to one approver, as bytes and printable text. */
export interface ApprovalRequest {
  readonly approver: string;
  readonly data: Uint8Array;
  readonly text: string;
  readonly requestId: Uint8Array;
}

/**
 * A request that passed every native check. `title`, `fields`, and
 * `displayDigestHex` are the profile's review of the exact canonical action;
 * render them and nothing else. `requester` is the actor.
 */
export interface ApprovalReview {
  readonly title: string;
  readonly fields: readonly (readonly [string, string])[];
  readonly displayDigestHex: string;
  readonly requester: string;
  readonly approvers: readonly string[];
  readonly required: number;
  readonly approver: string;
  readonly validFrom: bigint;
  readonly validUntil: bigint;
  readonly requestId: Uint8Array;
}

/** One approver's signed answer, as bytes and printable text. */
export interface ApprovalResponse {
  readonly decision: "approve" | "decline";
  readonly data: Uint8Array;
  readonly text: string;
}

export interface ApproverStatus {
  readonly approver: string;
  readonly status: "pending" | "approved" | "declined" | "rejected";
  readonly code?: string;
  readonly decidedAt?: bigint;
}

/**
 * Where each listed approver stands, in ascending approver order.
 * `unattributed` lists responses matched to no approver, by input index.
 * `approved` counts the listed approvers whose approvals match.
 */
export interface ApprovalCollection {
  readonly statuses: readonly ApproverStatus[];
  readonly unattributed: readonly (readonly [number, string])[];
  readonly approved: number;
  readonly required: number;
  readonly isComplete: boolean;
  /**
   * The proof from the actor's signed action and every matching approval;
   * throws `ApprovalRefused` with `approval.incomplete` while fewer than
   * `required` listed approvers have approved, `approval.action-mismatch`
   * for another action, and `approval.oversized` for material outside bounds.
   */
  assemble(action: ApprovalAction): Uint8Array;
}

const proposals = new WeakMap<object, QuorumInputs>();
const reviews = new WeakMap<object, Readonly<{ data: Uint8Array; now: bigint }>>();

function proposalInputs(proposal: object): QuorumInputs {
  const inputs = proposals.get(proposal);
  if (inputs === undefined) throw new TypeError("approval proposal was not built by proposeMcpApproval");
  return inputs;
}

function message(data: Uint8Array | string): Uint8Array {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (!(data instanceof Uint8Array)) throw new TypeError("approval message must be bytes or text");
  return data.slice();
}

function unixNow(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

/**
 * Build a proposal for any `required` of the listed `approvers`, approving on
 * their own devices. `actor` is the principal that will sign the action with
 * `signApprovalAction`; `actorGrant` is the canonical terminal grant its
 * authority descends from, omitted when the actor is a trust anchor. The
 * actor is never an approver. The window follows `authorMcpQuorumProof`.
 */
export async function proposeMcpApproval<Fields extends FieldMap>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  command: CommandOf<Fields>;
  required: number;
  approvers: readonly string[];
  actor: string;
  actorGrant?: Uint8Array;
  challenge: Uint8Array;
  evaluationTime: bigint;
  validitySeconds?: number;
}>): Promise<ApprovalProposal<CommandOf<Fields>>> {
  const approvers = checkedQuorum(input.approvers, input.required);
  checkedRequest(input.challenge, input.evaluationTime);
  if (input.actorGrant !== undefined && (!(input.actorGrant instanceof Uint8Array) ||
      input.actorGrant.length < 1 || input.actorGrant.length > 262_144)) {
    throw new RangeError("actor grant is outside bounds");
  }
  const engine = await loadPackagedWorkflowEngine();
  const inputs: QuorumInputs = Object.freeze({
    service: input.contract.service,
    name: input.contract.name,
    encoded: input.contract.encode(input.command),
    approvers,
    required: input.required,
    actor: checkedText(input.actor, "actor"),
    actorGrant: input.actorGrant?.slice(),
    challenge: input.challenge.slice(),
    evaluationTime: input.evaluationTime,
    validitySeconds: checkedValidity(input.validitySeconds),
  });
  const proposal = withQuorum(engine, inputs, (quorum) => Object.freeze({
    command: input.command,
    action: quorum.canonicalActionCbor.slice(),
    actor: quorum.actor,
    requirement: requirementOf(quorum),
  }));
  proposals.set(proposal, inputs);
  return proposal;
}

/** One request per listed approver, in ascending approver order. */
export async function approvalRequests<Command>(
  proposal: ApprovalProposal<Command>,
): Promise<readonly ApprovalRequest[]> {
  const engine = await loadPackagedWorkflowEngine();
  return withQuorum(engine, proposalInputs(proposal), (quorum) => {
    const issued = refusals(() => engine.approvalRequestsV1(quorum));
    try {
      return Object.freeze(Array.from({ length: issued.count }, (_, index) => Object.freeze({
        approver: issued.approver(index),
        data: issued.data(index).slice(),
        text: issued.text(index),
        requestId: issued.requestId(index).slice(),
      })));
    } finally {
      issued.free?.();
    }
  });
}

/**
 * The actor signs the proposal's action envelope with `signer`, whose
 * custody request shows the action and the requirement and expires at the
 * window's end. `grants` is the actor's chain, root first; it must end in the
 * proposal's `actorGrant` and is empty when the actor is a trust anchor. The
 * signer is not closed.
 */
export async function signApprovalAction<Command>(
  proposal: ApprovalProposal<Command>,
  signer: CustodySigner,
  options: Readonly<{ grants?: readonly GrantEvidence[]; signal?: AbortSignal }> = {},
): Promise<ApprovalAction> {
  const inputs = proposalInputs(proposal);
  const descriptor = custodyOf(signer);
  if (descriptor.principal !== inputs.actor) throw new TypeError("signer is not the proposal's actor");
  const grants = checkedGrants(options.grants ?? []);
  const terminal = grants.at(-1)?.signedGrant;
  if ((terminal === undefined) !== (inputs.actorGrant === undefined) ||
      (terminal !== undefined && !bytesEqual(terminal, inputs.actorGrant!))) {
    throw new TypeError("grant chain does not end in the proposal's actor grant");
  }
  const engine = await loadPackagedWorkflowEngine();
  const signature = descriptor.signature;
  const { envelope, display, validUntil } = withQuorum(engine, inputs, (quorum) => ({
    envelope: quorum.actionEnvelopeCbor.slice(),
    display: quorumDisplay(inputs.service, inputs.name, quorum),
    validUntil: requirementOf(quorum).validUntil,
  }));
  const request = engine.prepareActionSigningV1(
    envelope, signature.principalMethod, signature.verificationMethod, signature.suite,
  );
  let signed: Readonly<{ signature: Uint8Array; evidence: readonly PublicControlEvidence[] }>;
  try {
    signed = await signExactly(
      signer, request, "action", validUntil, display,
      options.signal ?? new AbortController().signal, 32,
    );
  } finally {
    request.free?.();
  }
  return Object.freeze({
    signedAction: engine.completeActionSigningV1(
      envelope, signature.principalMethod, signature.verificationMethod, signature.suite,
      signed.signature,
    ).slice(),
    grants: Object.freeze(grants.map((grant) => Object.freeze({
      signedGrant: grant.signedGrant.slice(),
      evidence: Object.freeze(grant.evidence.map((item) => Object.freeze({
        type: item.type, mediaType: item.mediaType, bytes: item.bytes.slice(),
      }))),
    }))),
    evidence: Object.freeze(signed.evidence.map((item) => Object.freeze({
      type: item.type, mediaType: item.mediaType, bytes: item.bytes.slice(),
    }))),
  });
}

/**
 * Check one request natively and return the review to show. Throws
 * `ApprovalRefused` with the first failing check's code.
 */
export async function openApprovalRequest(
  data: Uint8Array | string,
  options: Readonly<{ now?: bigint }> = {},
): Promise<ApprovalReview> {
  const engine = await loadPackagedWorkflowEngine();
  const bytes = message(data);
  const now = options.now ?? unixNow();
  const reviewed = refusals(() => engine.openApprovalRequestV1(bytes, now));
  try {
    const window = reviewed.window;
    const value: ApprovalReview = Object.freeze({
      title: reviewed.title,
      fields: Object.freeze(reviewed.fields.map(([label, text]) => Object.freeze([label, text] as const))),
      displayDigestHex: reviewed.displayDigestHex,
      requester: reviewed.requester,
      approvers: Object.freeze([...reviewed.approvers]),
      required: reviewed.required,
      approver: reviewed.approver,
      validFrom: window[0]!,
      validUntil: window[1]!,
      requestId: reviewed.requestId.slice(),
    });
    reviews.set(value, Object.freeze({ data: bytes, now }));
    return value;
  } finally {
    reviewed.free?.();
  }
}

type NativePending = ReturnType<ReturnType<Engine["openApprovalRequestV1"]>["prepareApproval"]>;

async function answer(
  pending: NativePending,
  signer: CustodySigner,
  signal: AbortSignal,
): Promise<ApprovalResponse> {
  const decision = pending.decision;
  const signed = await signExactly(
    signer, pending, pending.objectKind as SigningRequest["objectKind"], pending.expiresAt,
    Object.freeze(pending.display.map(([label, value]) => Object.freeze({ label, value }))),
    signal, MAX_APPROVAL_EVIDENCE,
  );
  for (const evidence of signed.evidence) {
    refusals(() => pending.bindEvidence(evidence.type, evidence.mediaType, evidence.bytes));
  }
  const completed = refusals(() => pending.complete(signed.signature));
  try {
    return Object.freeze({ decision, data: completed.data.slice(), text: completed.text });
  } finally {
    completed.free?.();
  }
}

async function respond(
  reviewed: ApprovalReview,
  signer: CustodySigner,
  signal: AbortSignal,
  prepare: (native: ReturnType<Engine["openApprovalRequestV1"]>) => NativePending,
): Promise<ApprovalResponse> {
  custodyOf(signer);
  const opened = reviews.get(reviewed);
  if (opened === undefined) throw new TypeError("request was not opened by openApprovalRequest");
  const engine = await loadPackagedWorkflowEngine();
  const native = refusals(() => engine.openApprovalRequestV1(opened.data, opened.now));
  let pending: NativePending | undefined;
  try {
    pending = refusals(() => prepare(native));
    return await answer(pending, signer, signal);
  } finally {
    pending?.free?.();
    native.free?.();
  }
}

/**
 * Sign the reviewed approval statement with `signer`, whose custody request
 * shows the same review and expires at the window's end. An approver carries
 * no grants. The signer is not closed.
 */
export async function approve(
  reviewed: ApprovalReview,
  signer: CustodySigner,
  options: Readonly<{ signal?: AbortSignal }> = {},
): Promise<ApprovalResponse> {
  const signature = signer?.descriptor?.signature;
  return respond(
    reviewed, signer, options.signal ?? new AbortController().signal,
    (native) => native.prepareApproval(
      signer.descriptor.principal, signature.principalMethod,
      signature.verificationMethod, signature.suite,
    ),
  );
}

/**
 * Sign a refusal at `now`. A decline carries no authority; it records who
 * refused.
 */
export async function decline(
  reviewed: ApprovalReview,
  signer: CustodySigner,
  options: Readonly<{ now?: bigint; signal?: AbortSignal }> = {},
): Promise<ApprovalResponse> {
  const signature = signer?.descriptor?.signature;
  const now = options.now ?? unixNow();
  return respond(
    reviewed, signer, options.signal ?? new AbortController().signal,
    (native) => native.prepareDecline(
      signer.descriptor.principal, signature.principalMethod,
      signature.verificationMethod, signature.suite, now,
    ),
  );
}

/**
 * Match responses to the proposal's requests. Signatures are checked by the
 * verifier when the assembled proof is used.
 */
export async function collectApprovals<Command>(
  proposal: ApprovalProposal<Command>,
  responses: readonly (Uint8Array | string)[],
): Promise<ApprovalCollection> {
  const inputs = proposalInputs(proposal);
  if (!Array.isArray(responses) || responses.length > 4 * MAX_QUORUM_APPROVERS) {
    throw new RangeError("too many approval responses");
  }
  const received = Object.freeze(responses.map(message));
  const engine = await loadPackagedWorkflowEngine();
  const collector = (): InstanceType<Engine["ApprovalCollectorV1"]> => {
    const value = new engine.ApprovalCollectorV1();
    try {
      for (const response of received) value.add(response);
      return value;
    } catch (error) {
      value.free?.();
      throw error;
    }
  };
  return withQuorum(engine, inputs, (quorum) => {
    const gathered = collector();
    let native: ReturnType<typeof gathered.collect> | undefined;
    try {
      native = refusals(() => gathered.collect(quorum));
      const collection = native;
      const statuses = Object.freeze(Array.from({ length: collection.count }, (_, index) => {
        const status = collection.status(index) as ApproverStatus["status"];
        return Object.freeze({
          approver: collection.approver(index),
          status,
          ...(status === "rejected" ? { code: collection.code(index) } : {}),
          ...(status === "declined" ? { decidedAt: collection.decidedAt(index) } : {}),
        });
      }));
      const unattributed = Object.freeze(Array.from(
        { length: collection.unattributedCount },
        (_, index) => Object.freeze([collection.unattributedIndex(index), collection.unattributedCode(index)] as const),
      ));
      return Object.freeze({
        statuses,
        unattributed,
        approved: collection.approved,
        required: collection.required,
        isComplete: collection.isComplete,
        assemble(action: ApprovalAction): Uint8Array {
          return withQuorum(engine, inputs, (current) => {
            const answers = collector();
            let staged: NativeAction | undefined;
            try {
              staged = nativeAction(engine, action);
              const signedAction = staged;
              return refusals(() => answers.assemble(current, signedAction)).slice();
            } finally {
              staged?.free?.();
              answers.free?.();
            }
          });
        },
      });
    } finally {
      native?.free?.();
      gathered.free?.();
    }
  });
}

/**
 * One root the operator trusts and the most authority it may exercise or
 * delegate. `maxDelegationDepth` counts the delegations allowed below the
 * anchor: 0 means the anchor may only act, 1 lets it grant once. Anchors use
 * expiry-only status.
 */
export interface TrustAnchor {
  readonly id: string;
  readonly principal: string;
  readonly acceptedMethods: readonly string[];
  readonly profiles: readonly Readonly<{ id: string; version: number }>[];
  readonly permissions: readonly Readonly<{ capability: string; resource: string }>[];
  readonly resourceNamespaces: readonly string[];
  readonly audiences: readonly string[];
  readonly notBefore: bigint;
  readonly expiresAt: bigint;
  readonly maxDelegationDepth: number;
  readonly assurancePolicy: string;
}

/**
 * One principal the operator lets approve, and how the verifier checks its
 * signatures. An approver anchor is not a trust anchor: it grants no
 * authority and carries no grant chain. Approver anchors use expiry-only
 * status.
 */
export interface ApproverAnchor {
  readonly principal: string;
  readonly acceptedMethods: readonly string[];
  readonly notBefore: bigint;
  readonly expiresAt: bigint;
}

/**
 * Approvals every verified action needs: any `threshold` distinct principals
 * of `approvers`, whoever responds. An actor's own approval never counts.
 */
export interface ApprovalRequirement {
  readonly approvers: readonly string[];
  readonly threshold: number;
}

/** Assurance claims the verifier requires of each participant role. */
export interface AssurancePolicy {
  readonly id: string;
  readonly requirements: readonly Readonly<{
    role: "root" | "intermediate" | "actor" | "external-issuer";
    quantifier: "any" | "every";
    claim: string;
    maximumAge?: bigint;
  }>[];
}

const MAX_UINT64 = (1n << 64n) - 1n;

/**
 * Compiles an operator's trusted context the way the Rust SDK's trusted-context
 * builder does for the Python binding, so equal inputs give equal bytes in
 * both SDKs. `configuration` is the 32-byte verifier configuration the
 * context pins: pass the one `auths-gateway review` prints to install trust in
 * that gateway, or omit it to pin this package's own verifier, which the local
 * check in `authorMcpProof` and `authorMcpQuorumProof` uses. The composition
 * minimums default to 1. `approverAnchors` and `approvalRequirements` install
 * native K-of-N approvals: each requirement must be met by approvals from
 * listed approvers that the anchors name. With `request`, the context is bound to one audience,
 * challenge, and evaluation time, as a gateway installation needs; without it
 * the unbound template is returned. Throws `TypeError` or `RangeError` for
 * malformed or unbounded input before native code runs, and the native error
 * for input the Rust model rejects.
 */
export async function compileTrustedContext(input: Readonly<{
  anchors: readonly TrustAnchor[];
  assurance: AssurancePolicy;
  configuration?: Uint8Array;
  minimumAuthorizedBranches?: number;
  minimumDistinctActors?: number;
  minimumDistinctRoots?: number;
  evidenceTypes?: readonly string[];
  criticalExtensions?: readonly string[];
  channelPolicy?: string;
  approverAnchors?: readonly ApproverAnchor[];
  approvalRequirements?: readonly ApprovalRequirement[];
  request?: Readonly<{ audience: string; challenge: Uint8Array; evaluationTime: bigint }>;
}>): Promise<Uint8Array> {
  if (!Array.isArray(input.anchors) || input.anchors.length < 1 || input.anchors.length > 32) {
    throw new RangeError("trusted context needs 1 to 32 trust anchors");
  }
  if (input.configuration !== undefined &&
      (!(input.configuration instanceof Uint8Array) || input.configuration.length !== 32)) {
    throw new TypeError("verifier configuration must contain 32 bytes");
  }
  const assurance = input.assurance;
  if (assurance === null || typeof assurance !== "object" || !Array.isArray(assurance.requirements) ||
      assurance.requirements.length > 32) {
    throw new TypeError("assurance policy must list at most 32 requirements");
  }
  const request = input.request;
  if (request !== undefined && (!(request.challenge instanceof Uint8Array) ||
      request.challenge.length !== 32)) {
    throw new TypeError("request challenge must contain 32 bytes");
  }
  const composition = {
    expectedPlan: null,
    minimumAuthorizedBranches: checkedU16(input.minimumAuthorizedBranches ?? 1, "authorized branches"),
    minimumDistinctActors: checkedU16(input.minimumDistinctActors ?? 1, "distinct actors"),
    minimumDistinctRoots: checkedU16(input.minimumDistinctRoots ?? 1, "distinct roots"),
  };
  const anchors = input.anchors.map((anchor) => ({
    id: checkedText(anchor.id, "anchor ID"),
    principal: checkedText(anchor.principal, "anchor principal"),
    acceptedMethods: checkedTexts(anchor.acceptedMethods, "accepted methods", 16),
    profiles: checkedProfiles(anchor.profiles),
    permissions: checkedPermissions(anchor.permissions),
    resourceNamespaces: checkedTexts(anchor.resourceNamespaces, "resource namespaces", 64),
    audiences: checkedTexts(anchor.audiences, "audiences", 32),
    notBefore: checkedU64(anchor.notBefore, "anchor validity"),
    expiresAt: checkedU64(anchor.expiresAt, "anchor validity"),
    budget: null,
    maxDelegationDepth: checkedU16(anchor.maxDelegationDepth, "delegation depth"),
    assurancePolicy: checkedText(anchor.assurancePolicy, "anchor assurance policy"),
    statusPolicy: { mode: "expiry-only" },
  }));
  const policy = {
    id: checkedText(assurance.id, "assurance policy"),
    requirements: assurance.requirements.map((requirement) => ({
      role: checkedText(requirement.role, "assurance role"),
      quantifier: checkedText(requirement.quantifier, "assurance quantifier"),
      claimKind: checkedText(requirement.claim, "assurance claim"),
      maximumAge: requirement.maximumAge === undefined
        ? null : checkedU64(requirement.maximumAge, "assurance maximum age"),
    })),
  };
  const channelPolicy = input.channelPolicy === undefined
    ? undefined : checkedText(input.channelPolicy, "channel policy");
  const evidenceTypes = checkedTexts(input.evidenceTypes ?? [], "evidence types", 64);
  const criticalExtensions = checkedTexts(input.criticalExtensions ?? [], "critical extensions", 64);
  const approverAnchors = input.approverAnchors ?? [];
  if (!Array.isArray(approverAnchors) || approverAnchors.length > 64) {
    throw new RangeError("approver anchors must be a list of at most 64 entries");
  }
  const approvalRequirements = input.approvalRequirements ?? [];
  if (!Array.isArray(approvalRequirements) || approvalRequirements.length > 64) {
    throw new RangeError("approval requirements must be a list of at most 64 entries");
  }
  const approvers = approverAnchors.map((anchor) => ({
    principal: checkedText(anchor?.principal, "approver principal"),
    acceptedMethods: checkedTexts(anchor.acceptedMethods, "approver accepted methods", 16),
    notBefore: checkedU64(anchor.notBefore, "approver validity"),
    expiresAt: checkedU64(anchor.expiresAt, "approver validity"),
    statusPolicy: { mode: "expiry-only" },
  }));
  const requirements = approvalRequirements.map((requirement) => ({
    approvers: checkedTexts(requirement?.approvers, "requirement approvers", 16),
    threshold: checkedU16(requirement.threshold, "approval threshold"),
  }));
  const engine = await loadPackagedWorkflowEngine();
  const compiled = engine.buildTrustedContextTemplateV1(
    input.configuration?.slice(), composition, anchors, policy, channelPolicy,
    evidenceTypes, criticalExtensions, approvers, requirements,
  ).slice();
  if (request === undefined) return compiled;
  return engine.bindTrustedContextRequestV1(
    compiled, checkedText(request.audience, "request audience"), request.challenge.slice(),
    checkedU64(request.evaluationTime, "evaluation time"),
  ).slice();
}

/**
 * Asks a trust anchor's custody signer to issue one parentless grant to
 * `subject` and returns it with the anchor's control evidence, ready to be the
 * first `GrantEvidence` of the subject's chain. The grant permits any body of
 * `profile` under `permissions` and `audiences` from `notBefore` through
 * `expiresAt`, carries no budget ceiling, uses expiry-only status, and carries
 * each critical extension exactly as given, such as the bounded-policy
 * commitment a gateway enforces. `remainingDepth` counts the delegations the
 * subject may make. The custody request expires 300 seconds after
 * `requestedAt`. A declining signer raises `AuthoringUnsuccessful`; malformed
 * input raises `TypeError` or `RangeError` before any signature is requested,
 * and a custody response that does not bind the exact request raises
 * `TypeError`.
 */
export async function authorRootGrant(input: Readonly<{
  signer: CustodySigner;
  subject: string;
  profile: Readonly<{ id: string; version: number }>;
  permissions: readonly Readonly<{ capability: string; resource: string }>[];
  audiences: readonly string[];
  notBefore: bigint;
  expiresAt: bigint;
  remainingDepth: number;
  assuranceFloor: string;
  criticalExtensions?: readonly Readonly<{ id: string; bytes: Uint8Array }>[];
  requestedAt: bigint;
  signal?: AbortSignal;
}>): Promise<GrantEvidence> {
  const descriptor = input.signer?.descriptor;
  if (descriptor?.contract !== "signer-custody/2") {
    throw new TypeError("signer does not implement the custody contract");
  }
  const extensions = input.criticalExtensions ?? [];
  if (!Array.isArray(extensions) || extensions.length > 8 ||
      extensions.some((extension) => !(extension?.bytes instanceof Uint8Array) ||
        extension.bytes.length > 16_384)) {
    throw new RangeError("a grant carries at most 8 critical extensions of at most 16 KiB each");
  }
  const requestedAt = checkedU64(input.requestedAt, "request time");
  if (requestedAt > MAX_UINT64 - 300n) throw new RangeError("request time is outside bounds");
  const profile = checkedProfiles([input.profile])[0]!;
  const fields = {
    subject: checkedText(input.subject, "grant subject"),
    profile,
    permissions: checkedPermissions(input.permissions),
    notBefore: checkedU64(input.notBefore, "grant validity"),
    expiresAt: checkedU64(input.expiresAt, "grant validity"),
    audiences: checkedTexts(input.audiences, "audiences", 32),
    remainingDepth: checkedU16(input.remainingDepth, "delegation depth"),
    assuranceFloor: checkedText(input.assuranceFloor, "assurance floor"),
    criticalExtensions: extensions.map((extension) => ({
      id: checkedText(extension.id, "critical extension"),
      bytes: extension.bytes.slice(),
    })),
  };
  const engine = await loadPackagedWorkflowEngine();
  const statement = engine.rootGrantStatementV1(
    descriptor.principal, fields.subject, profile.id, profile.version,
    fields.permissions.map((item) => item.capability),
    fields.permissions.map((item) => item.resource),
    fields.notBefore, fields.expiresAt, fields.audiences, fields.remainingDepth,
    fields.assuranceFloor, fields.criticalExtensions,
  ).slice();
  const signature = descriptor.signature;
  const request = engine.prepareGrantSigningV1(
    statement, signature.principalMethod, signature.verificationMethod, signature.suite,
  );
  const requestId = request.requestId;
  const objectId = request.objectId.slice();
  const transactionDigest = request.transactionDigest.slice();
  let outcome: Awaited<ReturnType<CustodySigner["sign"]>>;
  try {
    outcome = await input.signer.sign({
      requestId,
      objectKind: "grant",
      objectId: objectId.slice(),
      descriptor,
      transactionDigest: transactionDigest.slice(),
      signingPreimage: request.signingPreimage.slice(),
      expiresAtUnixSeconds: requestedAt + 300n,
      display: Object.freeze([
        { label: "grant subject", value: fields.subject },
        { label: "profile", value: `${fields.profile.id}/${fields.profile.version}` },
        { label: "permissions", value: fields.permissions.map((item) => `${item.capability} ${item.resource}`).join(", ") },
        { label: "audiences", value: fields.audiences.join(", ") },
        { label: "valid", value: `${fields.notBefore} to ${fields.expiresAt}` },
        { label: "further delegations", value: String(fields.remainingDepth) },
        { label: "critical extensions", value: fields.criticalExtensions.length === 0 ? "none"
          : fields.criticalExtensions.map((item) => `${item.id} (${item.bytes.length} bytes)`).join(", ") },
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
  const signedGrant = engine.completeGrantSigningV1(
    statement, signature.principalMethod, signature.verificationMethod, signature.suite,
    response.signature,
  ).slice();
  engine.validateRootAuthorityV1(
    signedGrant, descriptor.principal, fields.subject, fields.profile.id, fields.profile.version,
  ).free?.();
  return Object.freeze({
    signedGrant,
    evidence: Object.freeze(response.evidence.map((evidence) => Object.freeze({
      type: evidence.type, mediaType: evidence.mediaType, bytes: evidence.bytes.slice(),
    }))),
  });
}

function checkedText(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024) {
    throw new TypeError(`${label} must be a non-empty bounded string`);
  }
  return value;
}

function checkedTexts(values: unknown, label: string, maximum: number): string[] {
  if (!Array.isArray(values) || values.length > maximum) {
    throw new RangeError(`${label} must be a list of at most ${maximum} entries`);
  }
  return values.map((value) => checkedText(value, label));
}

function checkedU16(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`${label} must be a whole number from 0 to 65535`);
  }
  return value;
}

function checkedU64(value: unknown, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_UINT64) {
    throw new RangeError(`${label} must be an unsigned 64-bit bigint`);
  }
  return value;
}

function checkedProfiles(values: unknown): Readonly<{ id: string; version: number }>[] {
  if (!Array.isArray(values) || values.length > 16) {
    throw new RangeError("profiles must be a list of at most 16 entries");
  }
  return values.map((value: Readonly<{ id?: unknown; version?: unknown }> | null) => ({
    id: checkedText(value?.id, "profile ID"),
    version: checkedU16(value?.version, "profile version"),
  }));
}

function checkedPermissions(values: unknown): Readonly<{ capability: string; resource: string }>[] {
  if (!Array.isArray(values) || values.length > 64) {
    throw new RangeError("permissions must be a list of at most 64 entries");
  }
  return values.map((value: Readonly<{ capability?: unknown; resource?: unknown }> | null) => ({
    capability: checkedText(value?.capability, "permission capability"),
    resource: checkedText(value?.resource, "permission resource"),
  }));
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
    case "enum": return enumField(value.variants as readonly [string, ...string[]]);
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
    case "enum":
      if (typeof value !== "string" || !field.variants.includes(value)) {
        throw new UnknownEnumVariant();
      }
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
  }
}

function base64url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
