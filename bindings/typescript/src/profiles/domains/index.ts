import { AuthsWorkflowError, type WorkflowDomainActionFields } from "../../workflow.js";
import { loadPackagedWorkflowEngine } from "../../verifier/wasm.js";
import {
  type ApplicationAction,
  type ApplicationCommand,
  type ApplicationGateway,
  type ApplicationProfile,
  type CanonicalProfileAction,
  defineProfile,
} from "../application/index.js";

export interface DomainProfileOptions {
  readonly audience: string;
  readonly resourceNamespace?: string;
}

export interface HttpActionInput {
  readonly method: "DELETE" | "GET" | "HEAD" | "PATCH" | "POST" | "PUT";
  readonly scheme: "http" | "https";
  readonly authority: string;
  readonly path: string;
  readonly query?: Readonly<Record<string, readonly string[]>>;
  readonly headers?: Readonly<Record<string, string>>;
  readonly contentType?: string;
  readonly bodyDigest?: string;
}

export interface GitActionInput {
  readonly repository: string;
  readonly operation: "create-ref" | "delete-ref" | "merge" | "push" | "tag";
  readonly reference: string;
  readonly objectId: string;
}

export interface DeploymentActionInput {
  readonly environment: string;
  readonly region: string;
  readonly operation: "activate" | "deploy" | "rollback";
  readonly artifactDigest: string;
  readonly provenanceDigest: string;
  readonly configurationDigest: string;
  readonly strategy: "blue-green" | "canary" | "immediate" | "rolling";
  readonly rolloutNotBefore: bigint;
  readonly rolloutExpiresAt: bigint;
  readonly blastRadius: bigint;
}

export interface SupplyChainActionInput {
  readonly operation: "approve" | "attest" | "publish" | "release";
  readonly subjectDigest: string;
  readonly predicateType: string;
  readonly builder: string;
}

export interface EdgeActionInput {
  readonly fleet: string;
  readonly device: string;
  readonly command: "activate-firmware" | "apply-config" | "execute" | "restart";
  readonly sequence: bigint;
  readonly stateDigest?: string;
}

export interface DomainAuthority<ProfileId extends string> {
  readonly profile: ProfileId;
  readonly capability: string;
  readonly resource: string;
  readonly audience: string;
  readonly budget?: Readonly<{ readonly algebra: string; readonly value: bigint }>;
}

export interface DomainReceipt<ProfileId extends string, Result> {
  readonly profile: ProfileId;
  readonly idempotencyKey: string;
  readonly outcome: "executed" | "failed" | "outcome-unknown";
  readonly result?: Result;
}

export interface DomainGatewayError<ProfileId extends string> {
  readonly profile: ProfileId;
  readonly code: string;
  readonly retry: "never" | "safe" | "conditional" | "unknown";
  readonly effect: "not-applied" | "applied" | "unknown";
}

export type HttpAction = ApplicationAction<HttpActionInput>;
export type HttpCommand = ApplicationCommand<HttpActionInput>;
export type HttpGateway<Result> = ApplicationGateway<HttpActionInput, Result>;
export type HttpProfile = ApplicationProfile<HttpActionInput, HttpActionInput>;
export type HttpAuthority = DomainAuthority<"auths.http">;
export type HttpReceipt<Result> = DomainReceipt<"auths.http", Result>;
export type HttpGatewayError = DomainGatewayError<"auths.http">;
export type GitAction = ApplicationAction<GitActionInput>;
export type GitCommand = ApplicationCommand<GitActionInput>;
export type GitGateway<Result> = ApplicationGateway<GitActionInput, Result>;
export type GitProfile = ApplicationProfile<GitActionInput, GitActionInput>;
export type GitAuthority = DomainAuthority<"auths.git">;
export type GitReceipt<Result> = DomainReceipt<"auths.git", Result>;
export type GitGatewayError = DomainGatewayError<"auths.git">;
export type DeploymentAction = ApplicationAction<DeploymentActionInput>;
export type DeploymentCommand = ApplicationCommand<DeploymentActionInput>;
export type DeploymentGateway<Result> = ApplicationGateway<DeploymentActionInput, Result>;
export type DeploymentProfile = ApplicationProfile<DeploymentActionInput, DeploymentActionInput>;
export type DeploymentAuthority = DomainAuthority<"auths.deploy">;
export type DeploymentReceipt<Result> = DomainReceipt<"auths.deploy", Result>;
export type DeploymentGatewayError = DomainGatewayError<"auths.deploy">;
export type SupplyChainAction = ApplicationAction<SupplyChainActionInput>;
export type SupplyChainCommand = ApplicationCommand<SupplyChainActionInput>;
export type SupplyChainGateway<Result> = ApplicationGateway<SupplyChainActionInput, Result>;
export type SupplyChainProfile = ApplicationProfile<SupplyChainActionInput, SupplyChainActionInput>;
export type SupplyChainAuthority = DomainAuthority<"auths.supply-chain">;
export type SupplyChainReceipt<Result> = DomainReceipt<"auths.supply-chain", Result>;
export type SupplyChainGatewayError = DomainGatewayError<"auths.supply-chain">;
export type EdgeAction = ApplicationAction<EdgeActionInput>;
export type EdgeCommand = ApplicationCommand<EdgeActionInput>;
export type EdgeGateway<Result> = ApplicationGateway<EdgeActionInput, Result>;
export type EdgeProfile = ApplicationProfile<EdgeActionInput, EdgeActionInput>;
export type EdgeAuthority = DomainAuthority<"auths.edge">;
export type EdgeReceipt<Result> = DomainReceipt<"auths.edge", Result>;
export type EdgeGatewayError = DomainGatewayError<"auths.edge">;

type NativeParser<Input> = (input: Input) => WorkflowDomainActionFields;
type CanonicalParser<Input> = (value: unknown) => Input;
interface DomainParser<Input> {
  readonly input: NativeParser<Input>;
  readonly canonical: (body: Uint8Array) => WorkflowDomainActionFields;
}

export interface DomainProfiles {
  http(options: DomainProfileOptions): HttpProfile;
  git(options: DomainProfileOptions): GitProfile;
  deployment(options: DomainProfileOptions): DeploymentProfile;
  supplyChain(options: DomainProfileOptions): SupplyChainProfile;
  edge(options: DomainProfileOptions): EdgeProfile;
}

export async function loadDomainProfiles(): Promise<DomainProfiles> {
  const engine = await loadPackagedWorkflowEngine();
  const http: DomainParser<HttpActionInput> = {
      input: (value) => engine.parseHttpActionV1(httpNative(value)),
      canonical: (body) => engine.parseCanonicalHttpActionV1(body),
  };
  const git: DomainParser<GitActionInput> = {
      input: (value) => engine.parseGitActionV1(gitNative(value)),
      canonical: (body) => engine.parseCanonicalGitActionV1(body),
  };
  const deployment: DomainParser<DeploymentActionInput> = {
      input: (value) => engine.parseDeploymentActionV1(deploymentNative(value)),
      canonical: (body) => engine.parseCanonicalDeploymentActionV1(body),
  };
  const supplyChain: DomainParser<SupplyChainActionInput> = {
      input: (value) => engine.parseSupplyChainActionV1(supplyChainNative(value)),
      canonical: (body) => engine.parseCanonicalSupplyChainActionV1(body),
  };
  const edge: DomainParser<EdgeActionInput> = {
      input: (value) => engine.parseEdgeActionV1(edgeNative(value)),
      canonical: (body) => engine.parseCanonicalEdgeActionV1(body),
  };
  return Object.freeze({
    http: (options: DomainProfileOptions) => domainProfile("auths.http", options, http, parseHttp),
    git: (options: DomainProfileOptions) => domainProfile("auths.git", options, git, parseGit),
    deployment: (options: DomainProfileOptions) => domainProfile(
      "auths.deploy", options, deployment, parseDeployment,
    ),
    supplyChain: (options: DomainProfileOptions) => domainProfile(
      "auths.supply-chain", options, supplyChain, parseSupplyChain,
    ),
    edge: (options: DomainProfileOptions) => domainProfile("auths.edge", options, edge, parseEdge),
  });
}

function domainProfile<Input>(
  id: string,
  options: DomainProfileOptions,
  parser: DomainParser<Input>,
  parseCanonical: CanonicalParser<Input>,
): ApplicationProfile<Input, Input> {
  const audience = boundedText(options.audience, "audience");
  const namespace = options.resourceNamespace === undefined
    ? undefined
    : boundedText(options.resourceNamespace, "resource namespace");
  return defineProfile({
    id,
    version: 1,
    canonicalize(input) {
      const parsed = parser.input(input);
      try {
        const labels = [...parsed.reviewLabels];
        const values = [...parsed.reviewValues];
        if (labels.length !== values.length) {
          throw new AuthsWorkflowError("invalid-profile", "native review fields are inconsistent");
        }
        return {
          mediaType: parsed.mediaType,
          body: new Uint8Array(parsed.body),
          permission: { capability: parsed.capability, resource: parsed.resource },
          resourceNamespace: namespace ?? parsed.resource,
          ...(parsed.hasBudget
            ? { budget: { algebra: parsed.budgetAlgebra, value: BigInt(parsed.budgetValue) } }
            : {}),
          audience,
          display: [
            { label: "Action", value: parsed.reviewTitle },
            ...labels.map((label, index) => ({ label, value: values[index] ?? "" })),
          ],
        } satisfies CanonicalProfileAction;
      } finally {
        parsed.free?.();
      }
    },
    decodeVerified(canonical) {
      const parsed = parser.canonical(canonical.body);
      try {
        return parseCanonical(parsed.normalized);
      } finally {
        parsed.free?.();
      }
    },
  });
}

function httpNative(input: HttpActionInput): unknown {
  return {
    method: input.method,
    scheme: input.scheme,
    authority: input.authority,
    path: input.path,
    query: input.query ?? {},
    headers: input.headers ?? {},
    ...(input.contentType === undefined ? {} : { content_type: input.contentType }),
    ...(input.bodyDigest === undefined ? {} : { body_digest: input.bodyDigest }),
  };
}

function gitNative(input: GitActionInput): unknown {
  return {
    repository: input.repository,
    operation: input.operation,
    reference: input.reference,
    object_id: input.objectId,
  };
}

function deploymentNative(input: DeploymentActionInput): unknown {
  return {
    environment: input.environment,
    region: input.region,
    operation: input.operation,
    artifact_digest: input.artifactDigest,
    provenance_digest: input.provenanceDigest,
    configuration_digest: input.configurationDigest,
    strategy: input.strategy,
    rollout_not_before: input.rolloutNotBefore,
    rollout_expires_at: input.rolloutExpiresAt,
    blast_radius: input.blastRadius,
  };
}

function supplyChainNative(input: SupplyChainActionInput): unknown {
  return {
    operation: input.operation,
    subject_digest: input.subjectDigest,
    predicate_type: input.predicateType,
    builder: input.builder,
  };
}

function edgeNative(input: EdgeActionInput): unknown {
  return {
    fleet: input.fleet,
    device: input.device,
    command: input.command,
    sequence: input.sequence,
    ...(input.stateDigest === undefined ? {} : { state_digest: input.stateDigest }),
  };
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AuthsWorkflowError("invalid-profile", "native profile returned a non-object action");
  }
  return value as Readonly<Record<string, unknown>>;
}

function textField(value: Readonly<Record<string, unknown>>, key: string): string {
  const field = value[key];
  if (typeof field !== "string") {
    throw new AuthsWorkflowError("invalid-profile", `native profile omitted ${key}`);
  }
  return field;
}

function integerField(value: Readonly<Record<string, unknown>>, key: string): bigint {
  const field = value[key];
  if (typeof field === "bigint" && field >= 0n) return field;
  if (typeof field === "number" && Number.isSafeInteger(field) && field >= 0) {
    return BigInt(field);
  }
  throw new AuthsWorkflowError("invalid-profile", `native profile returned invalid ${key}`);
}

function parseHttp(value: unknown): HttpActionInput {
  const fields = record(value);
  return Object.freeze({
    method: textField(fields, "method") as HttpActionInput["method"],
    scheme: textField(fields, "scheme") as HttpActionInput["scheme"],
    authority: textField(fields, "authority"),
    path: textField(fields, "path"),
    query: parseStringLists(fields.query),
    headers: parseStrings(fields.headers),
    ...(typeof fields.content_type === "string" ? { contentType: fields.content_type } : {}),
    ...(typeof fields.body_digest === "string" ? { bodyDigest: fields.body_digest } : {}),
  });
}

function parseGit(value: unknown): GitActionInput {
  const fields = record(value);
  return Object.freeze({
    repository: textField(fields, "repository"),
    operation: textField(fields, "operation") as GitActionInput["operation"],
    reference: textField(fields, "reference"),
    objectId: textField(fields, "object_id"),
  });
}

function parseDeployment(value: unknown): DeploymentActionInput {
  const fields = record(value);
  return Object.freeze({
    environment: textField(fields, "environment"),
    region: textField(fields, "region"),
    operation: textField(fields, "operation") as DeploymentActionInput["operation"],
    artifactDigest: textField(fields, "artifact_digest"),
    provenanceDigest: textField(fields, "provenance_digest"),
    configurationDigest: textField(fields, "configuration_digest"),
    strategy: textField(fields, "strategy") as DeploymentActionInput["strategy"],
    rolloutNotBefore: integerField(fields, "rollout_not_before"),
    rolloutExpiresAt: integerField(fields, "rollout_expires_at"),
    blastRadius: integerField(fields, "blast_radius"),
  });
}

function parseSupplyChain(value: unknown): SupplyChainActionInput {
  const fields = record(value);
  return Object.freeze({
    operation: textField(fields, "operation") as SupplyChainActionInput["operation"],
    subjectDigest: textField(fields, "subject_digest"),
    predicateType: textField(fields, "predicate_type"),
    builder: textField(fields, "builder"),
  });
}

function parseEdge(value: unknown): EdgeActionInput {
  const fields = record(value);
  return Object.freeze({
    fleet: textField(fields, "fleet"),
    device: textField(fields, "device"),
    command: textField(fields, "command") as EdgeActionInput["command"],
    sequence: integerField(fields, "sequence"),
    ...(typeof fields.state_digest === "string" ? { stateDigest: fields.state_digest } : {}),
  });
}

function parseStrings(value: unknown): Readonly<Record<string, string>> {
  const fields = record(value);
  return Object.freeze(Object.fromEntries(
    Object.entries(fields).map(([key, item]) => {
      if (typeof item !== "string") {
        throw new AuthsWorkflowError("invalid-profile", "native map value is not text");
      }
      return [key, item];
    }),
  ));
}

function parseStringLists(value: unknown): Readonly<Record<string, readonly string[]>> {
  const fields = record(value);
  return Object.freeze(Object.fromEntries(
    Object.entries(fields).map(([key, item]) => {
      if (!Array.isArray(item) || item.some((member) => typeof member !== "string")) {
        throw new AuthsWorkflowError("invalid-profile", "native query value is not a text list");
      }
      return [key, Object.freeze([...item])];
    }),
  ));
}

function boundedText(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw new AuthsWorkflowError("invalid-profile", `${label} is outside bounds`);
  }
  return value;
}
