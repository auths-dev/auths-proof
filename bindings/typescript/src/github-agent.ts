/**
 * Typed client for the launch GitHub issue-agent vertical.
 *
 * The server owns GitHub canonicalization, inspection, authorization,
 * lifecycle state, credentials, writes, and receipts. This module only turns
 * developer-shaped values into the closed demo API and projects its outcomes.
 */

const SCHEMA = "auths-github-agent/v1";
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_CANDIDATE_BYTES = 2 * 1_048_576;
const DEFAULT_TIMEOUT_MS = 120_000;
const sessionIds = new WeakMap<GitHubAgentSession, string>();

export interface GitHubAgentBoundary {
  readonly repository: string;
  readonly issueNumber: number;
  readonly baseRef: string;
  readonly baseRevision: string;
  readonly allowedPaths: readonly string[];
  readonly protectedPaths: readonly string[];
  readonly minimumExpirySeconds: number;
  readonly maximumExpirySeconds: number;
  readonly branchBudget: 1;
  readonly draftPullRequestBudget: 1;
  readonly agentCredentialPresent: false;
}

export interface GitHubAgentTask {
  readonly repository: string;
  readonly issueNumber: number;
  readonly baseRef: string;
  readonly baseRevision: string;
  readonly allowedPaths: readonly string[];
  readonly protectedPaths: readonly string[];
  readonly expiresInSeconds: number;
  readonly branchBudget: 1;
  readonly draftPullRequestBudget: 1;
  readonly agentLabel: string;
}

export interface GitHubCandidateFile {
  readonly path: string | URL;
  readonly baseRevision: string;
  readonly candidateRevision: string;
}

export type GitHubDenialFixture =
  | "prohibited-path"
  | "candidate-changed"
  | "repository-changed"
  | "issue-changed"
  | "base-advanced"
  | "malformed-bundle";

export interface GitHubAgentSession {
  readonly kind: "github-agent-session";
  readonly workflowId: string;
  readonly expiresAt: number;
  readonly targetRef: string;
  readonly agentPrincipal: string;
  readonly requiredConfiguration: string;
  readonly executedConfiguration: string;
  toJSON(): never;
}

class GitHubAgentSessionValue implements GitHubAgentSession {
  readonly kind = "github-agent-session" as const;

  constructor(
    id: string,
    readonly workflowId: string,
    readonly expiresAt: number,
    readonly targetRef: string,
    readonly agentPrincipal: string,
    readonly requiredConfiguration: string,
    readonly executedConfiguration: string,
  ) {
    sessionIds.set(this, id);
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths GitHub agent sessions are opaque");
  }
}

export interface GitHubCandidateInspection {
  readonly kind: "inspected" | "denied";
  readonly candidateRevision?: string;
  readonly changedPaths: readonly string[];
  readonly directPush: "refused-without-credential" | "not-attempted" | "unexpectedly-accepted";
  readonly decisionCode: string;
  readonly credentialWouldBeRequested: boolean;
}

export interface GitHubAgentOutcome {
  readonly kind: "completed" | "denied" | "indeterminate" | "replayed" | "reconciled";
  readonly code: string;
  readonly credentialRequests: number | "unknown";
  readonly mutations: number | "unknown";
  readonly next: "none" | "reconcile";
  readonly branchRef?: string;
  readonly pullRequestNumber?: number;
  readonly pullRequestUrl?: string;
}

export interface GitHubVerifiedReceipts {
  readonly kind: "verified";
  readonly workflowId: string;
  readonly count: number;
}

export interface GitHubAgentClientOptions {
  readonly endpoint: string | URL;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
}

export interface GitHubAgentClient {
  boundary(): Promise<GitHubAgentBoundary>;
  delegate(task: GitHubAgentTask): Promise<GitHubAgentSession>;
  inspectCandidate(session: GitHubAgentSession, candidate: GitHubCandidateFile): Promise<GitHubCandidateInspection>;
  inspectFixture(session: GitHubAgentSession, fixture: "exact" | GitHubDenialFixture): Promise<GitHubCandidateInspection>;
  execute(session: GitHubAgentSession): Promise<GitHubAgentOutcome>;
  replay(session: GitHubAgentSession): Promise<GitHubAgentOutcome>;
  reconcile(session: GitHubAgentSession): Promise<GitHubAgentOutcome>;
  verifyReceipts(session: GitHubAgentSession): Promise<GitHubVerifiedReceipts>;
}

/** Opens the typed GitHub issue-agent launch client. */
export function createGitHubAgentClient(options: GitHubAgentClientOptions): GitHubAgentClient {
  const endpoint = parseEndpoint(options.endpoint);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw new TypeError("Auths GitHub agent timeout is outside bounds");
  }
  const send = options.fetch ?? globalThis.fetch;
  if (typeof send !== "function") throw new TypeError("Auths GitHub agent fetch is unavailable");

  const call = async (path: string, init?: RequestInit): Promise<Record<string, unknown>> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await send(new URL(path, endpoint), {
        ...init,
        signal: controller.signal,
        headers: { "content-type": "application/json", ...init?.headers },
      });
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.length === 0 || bytes.length > MAX_RESPONSE_BYTES) {
        throw new TypeError("Auths GitHub agent response is outside bounds");
      }
      const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      const object = record(value, "Auths GitHub agent response");
      if (!response.ok) {
        const code = optionalString(object.code) ?? `http-${response.status}`;
        const detail = optionalString(object.detail) ?? "GitHub agent request failed";
        throw new GitHubAgentError(code, detail, response.status);
      }
      if (object.schema !== SCHEMA) throw new TypeError("Auths GitHub agent schema mismatch");
      return object;
    } finally {
      clearTimeout(timer);
    }
  };

  const operate = async (
    session: GitHubAgentSession,
    operation: "execute" | "replay" | "reconcile",
  ): Promise<GitHubAgentOutcome> => {
    const id = readSession(session);
    try {
      return projectOutcome(await call(`/v1/demo/sessions/${id}/${operation}`, { method: "POST" }));
    } catch {
      return Object.freeze({
        kind: "indeterminate" as const,
        code: "transport-uncertain",
        credentialRequests: "unknown" as const,
        mutations: "unknown" as const,
        next: "reconcile" as const,
      });
    }
  };

  return Object.freeze({
    async boundary() {
      return projectBoundary(await call("/v1/demo/scenario"));
    },
    async delegate(task: GitHubAgentTask) {
      validateTask(task);
      const value = await call("/v1/demo/sessions", {
        method: "POST",
        body: JSON.stringify(task),
      });
      const requiredConfiguration = requiredString(value.required_configuration, "required configuration");
      const executedConfiguration = requiredString(value.executed_configuration, "executed configuration");
      if (requiredConfiguration !== executedConfiguration) {
        throw new TypeError("Auths GitHub agent verifier configuration mismatch");
      }
      return new GitHubAgentSessionValue(
        requiredString(value.session_id, "session id"),
        requiredString(value.workflow_id, "workflow id"),
        requiredInteger(value.expires_at, "expiry"),
        requiredString(value.target_ref, "target ref"),
        requiredString(value.agent_principal, "agent principal"),
        requiredConfiguration,
        executedConfiguration,
      );
    },
    async inspectCandidate(session: GitHubAgentSession, candidate: GitHubCandidateFile) {
      validateCandidate(candidate);
      const { readFile, stat } = await import("node:fs/promises");
      const metadata = await stat(candidate.path);
      if (!metadata.isFile() || metadata.size === 0 || metadata.size > MAX_CANDIDATE_BYTES) {
        throw new TypeError("Auths GitHub candidate file is outside bounds");
      }
      const bundle = await readFile(candidate.path);
      if (bundle.length === 0 || bundle.length > MAX_CANDIDATE_BYTES) {
        throw new TypeError("Auths GitHub candidate file changed outside bounds");
      }
      const value = await call(`/v1/demo/sessions/${readSession(session)}/candidate`, {
        method: "POST",
        body: JSON.stringify({
          kind: "bundle",
          bundleBase64url: base64Url(bundle),
          baseRevision: candidate.baseRevision,
          candidateRevision: candidate.candidateRevision,
        }),
      });
      return projectInspection(value);
    },
    async inspectFixture(session: GitHubAgentSession, fixture: "exact" | GitHubDenialFixture) {
      const value = await call(`/v1/demo/sessions/${readSession(session)}/candidate`, {
        method: "POST",
        body: JSON.stringify({ kind: "fixture", experiment: fixture }),
      });
      return projectInspection(value);
    },
    execute: (session: GitHubAgentSession) => operate(session, "execute"),
    replay: (session: GitHubAgentSession) => operate(session, "replay"),
    reconcile: (session: GitHubAgentSession) => operate(session, "reconcile"),
    async verifyReceipts(session: GitHubAgentSession) {
      const id = readSession(session);
      const value = await call(`/v1/demo/receipts/demo-${id}`);
      const receipts = array(value.receipts, "receipts");
      const workflowId = requiredString(value.workflow_id, "workflow id");
      if (receipts.length === 0 || workflowId !== session.workflowId) {
        throw new TypeError("Auths GitHub agent receipt timeline is not bound to the session");
      }
      return Object.freeze({
        kind: "verified" as const,
        workflowId,
        count: receipts.length,
      });
    },
  });
}

export class GitHubAgentError extends Error {
  constructor(readonly code: string, message: string, readonly status: number) {
    super(message);
    this.name = "GitHubAgentError";
  }
}

function projectBoundary(value: Record<string, unknown>): GitHubAgentBoundary {
  const budgets = record(value.budgets, "budgets");
  const expiry = record(value.expiry, "expiry");
  if (budgets.branches !== 1 || budgets.draft_pull_requests !== 1 || value.agent_credential_present !== false) {
    throw new TypeError("Auths GitHub agent boundary is unsafe");
  }
  return Object.freeze({
    repository: requiredString(value.repository, "repository"),
    issueNumber: requiredInteger(value.issue_number, "issue number"),
    baseRef: requiredString(value.base_ref, "base ref"),
    baseRevision: requiredString(value.base_revision, "base revision"),
    allowedPaths: Object.freeze(strings(value.allowed_paths, "allowed paths")),
    protectedPaths: Object.freeze(strings(value.denied_paths, "protected paths")),
    minimumExpirySeconds: requiredInteger(expiry.minimum_seconds, "minimum expiry"),
    maximumExpirySeconds: requiredInteger(expiry.maximum_seconds, "maximum expiry"),
    branchBudget: 1,
    draftPullRequestBudget: 1,
    agentCredentialPresent: false,
  });
}

function projectInspection(value: Record<string, unknown>): GitHubCandidateInspection {
  const candidate = record(value.candidate, "candidate");
  const preview = record(candidate.preview, "candidate preview");
  const direct = record(candidate.direct_push, "direct push");
  const changed = Array.isArray(candidate.changed_paths)
    ? candidate.changed_paths.map((entry) => requiredString(record(entry, "changed path").path, "changed path"))
    : [];
  const status = requiredString(candidate.status, "candidate status");
  if (status !== "inspected" && status !== "denied") throw new TypeError("invalid candidate status");
  const directPush = requiredString(direct.result, "direct push result");
  if (!["refused-without-credential", "not-attempted", "unexpectedly-accepted"].includes(directPush)) {
    throw new TypeError("invalid direct-push result");
  }
  if (status === "inspected" && directPush !== "refused-without-credential") {
    throw new TypeError("inspected candidate did not prove credential isolation");
  }
  return Object.freeze({
    kind: status,
    ...(typeof candidate.candidate_revision === "string" ? { candidateRevision: candidate.candidate_revision } : {}),
    changedPaths: Object.freeze(changed),
    directPush: directPush as GitHubCandidateInspection["directPush"],
    decisionCode: requiredString(preview.code, "decision code"),
    credentialWouldBeRequested: requiredBoolean(preview.credential_would_be_requested, "credential projection"),
  });
}

function projectOutcome(value: Record<string, unknown>): GitHubAgentOutcome {
  const decision = record(value.decision, "decision");
  const execution = record(value.execution, "execution");
  const code = requiredString(decision.code, "decision code");
  const className = requiredString(decision.class, "decision class");
  if (!["authorized", "denied", "indeterminate"].includes(className)) {
    throw new TypeError("invalid GitHub agent decision class");
  }
  const status = optionalString(execution.status);
  const replay = optionalString(execution.replay);
  const kind: GitHubAgentOutcome["kind"] = replay === "original-receipt-returned"
    ? "replayed"
    : status?.startsWith("reconciled") === true
      ? "reconciled"
      : className === "denied"
        ? "denied"
        : className === "indeterminate"
          ? "indeterminate"
          : "completed";
  return Object.freeze({
    kind,
    code,
    credentialRequests: className === "indeterminate"
      ? optionalInteger(value.credential_requests) ?? "unknown"
      : requiredInteger(value.credential_requests, "credential requests"),
    mutations: className === "indeterminate"
      ? optionalInteger(value.mutations) ?? "unknown"
      : requiredInteger(value.mutations, "mutation count"),
    next: className === "indeterminate" ? "reconcile" : "none",
    ...(typeof execution.branch_ref === "string" ? { branchRef: execution.branch_ref } : {}),
    ...(typeof execution.pull_request_number === "number" ? { pullRequestNumber: execution.pull_request_number } : {}),
    ...(typeof execution.pull_request_url === "string" ? { pullRequestUrl: execution.pull_request_url } : {}),
  });
}

function validateTask(task: GitHubAgentTask): void {
  if (!Number.isSafeInteger(task.issueNumber) || task.issueNumber < 1
      || !Number.isSafeInteger(task.expiresInSeconds) || task.expiresInSeconds < 1
      || task.branchBudget !== 1 || task.draftPullRequestBudget !== 1) {
    throw new TypeError("Auths GitHub agent task is outside bounds");
  }
  for (const value of [task.repository, task.baseRef, task.baseRevision, task.agentLabel, ...task.allowedPaths, ...task.protectedPaths]) {
    if (typeof value !== "string" || value.length === 0 || value.length > 1_024) {
      throw new TypeError("Auths GitHub agent task contains an invalid string");
    }
  }
}

function validateCandidate(candidate: GitHubCandidateFile): void {
  if ((typeof candidate.path !== "string" && !(candidate.path instanceof URL))
      || typeof candidate.baseRevision !== "string" || typeof candidate.candidateRevision !== "string") {
    throw new TypeError("Auths GitHub candidate file is invalid");
  }
}

function readSession(session: GitHubAgentSession): string {
  const id = sessionIds.get(session);
  if (id === undefined) throw new TypeError("forged Auths GitHub agent session");
  return id;
}

function parseEndpoint(value: string | URL): URL {
  const endpoint = new URL(value);
  const local = endpoint.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname);
  if ((endpoint.protocol !== "https:" && !local) || endpoint.username !== "" || endpoint.password !== ""
      || endpoint.pathname !== "/" || endpoint.search !== "" || endpoint.hash !== "") {
    throw new TypeError("Auths GitHub agent endpoint must be HTTPS or loopback HTTP");
  }
  return endpoint;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.length)));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${label} is malformed`);
  return value as Record<string, unknown>;
}

function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} is malformed`);
  return value;
}

function strings(value: unknown, label: string): string[] {
  const values = array(value, label);
  if (!values.every((entry) => typeof entry === "string")) throw new TypeError(`${label} is malformed`);
  return values as string[];
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} is malformed`);
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function requiredInteger(value: unknown, label: string): number {
  const integer = optionalInteger(value);
  if (integer === undefined) throw new TypeError(`${label} is malformed`);
  return integer;
}

function optionalInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function requiredBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new TypeError(`${label} is malformed`);
  return value;
}
