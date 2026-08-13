import { approvalPolicy, noApproval } from "./approvals.js";
import { DevelopmentEd25519Signer, DevelopmentReceiptAttestor } from "./internal/development.js";
import {
  createAuths,
  createAuthsConfiguration,
  type Auths,
  type AuthsConfiguration,
  type AuthsResources,
} from "./product.js";
import {
  resourcesForMcpAuthority,
  type McpExecutionState,
  type McpRecoveryCheckpoint,
  type McpReceiptSink,
  type McpToolAuthority,
} from "./profiles/mcp/index.js";
import { prepareRawKeyAuthority } from "./verifier/authority.js";
import { loadAuths } from "./workflow-client.js";
import type { ApprovalConfiguration } from "./workflow.js";

const DEVELOPMENT_DIAGNOSTICS = Object.freeze([
  "mode=development",
  "signer=ephemeral-ed25519",
  "trust=local-raw-key",
  "approval=none",
  "state=in-memory-not-production-durable",
  "receipts=memory-not-production-durable",
]);

export interface DevelopmentAuthsOptions {
  readonly authority: McpToolAuthority;
  readonly approval?: ApprovalConfiguration;
}

export interface RecoverableDevelopmentAuthsOptions extends DevelopmentAuthsOptions {
  readonly directory: string;
}

class InMemoryMcpResources implements McpExecutionState, McpReceiptSink {
  readonly #executions = new Map<string, { stage: "reserved" | "provider" | "completed"; recovery?: McpRecoveryCheckpoint }>();
  readonly #receipts = new Map<string, Uint8Array>();

  async reserve(executionId: string, recovery: McpRecoveryCheckpoint): Promise<"acquired" | "exact-replay" | "conflict"> {
    if (this.#executions.has(executionId)) return "exact-replay";
    this.#executions.set(executionId, { stage: "reserved", recovery: copyRecovery(recovery) });
    return "acquired";
  }

  async markProviderEntry(executionId: string, recovery: McpRecoveryCheckpoint): Promise<void> {
    const execution = this.#executions.get(executionId);
    if (execution?.stage !== "reserved" || recovery.executionId !== executionId) {
      throw new TypeError("invalid development provider-entry transition");
    }
    this.#executions.set(executionId, { stage: "provider", recovery: copyRecovery(recovery) });
  }

  async saveRecovery(recovery: McpRecoveryCheckpoint): Promise<void> {
    const execution = this.#executions.get(recovery.executionId);
    if (execution === undefined || execution.stage === "completed") {
      throw new TypeError("invalid development recovery transition");
    }
    this.#executions.set(recovery.executionId, { stage: execution.stage, recovery: copyRecovery(recovery) });
  }

  async loadRecovery(reference: string): Promise<Uint8Array | undefined> {
    for (const execution of this.#executions.values()) {
      if (execution.stage !== "completed" && execution.recovery?.reference === reference) {
        return execution.recovery.recordJson.slice();
      }
    }
    return undefined;
  }

  async loadPending(executionId: string): Promise<McpRecoveryCheckpoint | undefined> {
    const execution = this.#executions.get(executionId);
    return execution?.stage === "completed" || execution?.recovery === undefined
      ? undefined
      : copyRecovery(execution.recovery);
  }

  async clearPending(executionId: string): Promise<void> {
    const execution = this.#executions.get(executionId);
    if (execution === undefined) throw new TypeError("invalid development completion transition");
    this.#executions.set(executionId, { stage: "completed" });
  }

  async persist(executionId: string, receiptJson: Uint8Array): Promise<void> {
    const execution = this.#executions.get(executionId);
    if (execution?.stage !== "provider") {
      throw new TypeError("invalid development receipt transition");
    }
    const existing = this.#receipts.get(executionId);
    if (existing !== undefined) {
      if (!equalBytes(existing, receiptJson)) throw new TypeError("development receipt conflicts with persisted bytes");
      return;
    }
    this.#receipts.set(executionId, receiptJson.slice());
  }
}

function copyRecovery(recovery: McpRecoveryCheckpoint): McpRecoveryCheckpoint {
  return Object.freeze({
    executionId: recovery.executionId,
    reference: recovery.reference,
    recordJson: recovery.recordJson.slice(),
  });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export const development = Object.freeze({
  async createAuths(options: DevelopmentAuthsOptions): Promise<Auths> {
    return createAuths(developmentConfiguration(options, new InMemoryMcpResources(), crypto.getRandomValues(new Uint8Array(32))));
  },

  async createRecoverableAuths(options: RecoverableDevelopmentAuthsOptions): Promise<Auths> {
    if (typeof options.directory !== "string" || options.directory.length === 0) {
      throw new TypeError("recoverable development directory is required");
    }
    const { openRecoverableDevelopmentResources } = await import("./internal/development-store-node.js");
    const opened = await openRecoverableDevelopmentResources(options.directory);
    return createAuths(developmentConfiguration(
      options,
      opened.resources,
      opened.sessionKey,
      RECOVERABLE_DEVELOPMENT_DIAGNOSTICS,
      opened.authorityNotBefore,
    ));
  },
});

export const production = Object.freeze({
  async createAuths(configuration: AuthsConfiguration): Promise<Auths> {
    if (configuration.mode !== "production") {
      throw new TypeError("production composition rejects development capabilities");
    }
    return createAuths(configuration);
  },
});

function developmentConfiguration(
  options: DevelopmentAuthsOptions,
  state: McpExecutionState & McpReceiptSink,
  sessionKey: Uint8Array,
  diagnostics: readonly string[] = DEVELOPMENT_DIAGNOSTICS,
  authorityNotBefore?: bigint,
): AuthsConfiguration {
  const authority = resourcesForMcpAuthority(options.authority);
  let opened = false;
  let childIndex = 0;
  return createAuthsConfiguration("development", diagnostics, async (): Promise<AuthsResources> => {
    if (opened) throw new TypeError("development Auths configuration is single-use");
    opened = true;
    const rootSigner = await DevelopmentEd25519Signer.fromSeed(await developmentSeed(sessionKey, "root"));
    const actorSigner = await DevelopmentEd25519Signer.fromSeed(await developmentSeed(sessionKey, "actor"));
    const receiptAttestor = await DevelopmentReceiptAttestor.fromSeed(await developmentSeed(sessionKey, "receipts"));
    let client;
    try {
      const approval = options.approval ?? Object.freeze({
        policy: await approvalPolicy.none({ policyId: "approval.development.none" }),
        provider: noApproval,
      });
      const actor = await actorSigner.publicIdentity();
      const now = authorityNotBefore ?? BigInt(Math.floor(Date.now() / 1000));
      const prepared = await prepareRawKeyAuthority({
        authorityId: "development.local",
        rootSigner,
        subjectPrincipal: actor.principal,
        profile: authority.profile,
        permissions: authority.permissions,
        resourceNamespaces: authority.resourceNamespaces,
        validity: { notBefore: now, expiresAt: now + 86_400n },
        audiences: authority.audiences,
        remainingDepth: 4,
        approval,
      });
      client = await loadAuths({ signer: actorSigner, trustedAuthority: prepared.trustedAuthority });
      const agent = await client.attachAgent({
        name: "development-agent",
        profile: authority.profile,
        authority: prepared.authority,
        approval,
      });
      await rootSigner.dispose();
      return {
        agent,
        authority: options.authority,
        state,
        receipts: state,
        receiptAttestor,
        sessionKey: sessionKey.slice(),
        childSigner: async () => DevelopmentEd25519Signer.fromSeed(
          await developmentSeed(sessionKey, `child:${childIndex++}`),
        ),
        dispose: async () => {
          receiptAttestor.dispose();
          await client!.dispose();
        },
      };
    } catch (error) {
      await rootSigner.dispose().catch(() => undefined);
      if (client !== undefined) await client.dispose().catch(() => undefined);
      else await actorSigner.dispose().catch(() => undefined);
      receiptAttestor.dispose();
      throw error;
    }
  });
}

const RECOVERABLE_DEVELOPMENT_DIAGNOSTICS = Object.freeze(
  DEVELOPMENT_DIAGNOSTICS.map((value) => {
    if (value.startsWith("state=")) return "state=file-backed-single-machine-not-production-durable";
    if (value.startsWith("receipts=")) return "receipts=file-backed-single-machine-not-production-durable";
    return value;
  }),
);

async function developmentSeed(sessionKey: Uint8Array, role: string): Promise<Uint8Array> {
  const roleBytes = new TextEncoder().encode(role);
  const input = new Uint8Array(32 + 8 + roleBytes.length);
  input.set(sessionKey);
  new DataView(input.buffer).setBigUint64(32, BigInt(roleBytes.length));
  input.set(roleBytes, 40);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}
