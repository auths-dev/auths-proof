/** Synthetic conformance for application-owned adapters; not provider qualification. */

import {
  exactMcpTool, reconcileReadOnly, runOnce,
  type AttemptRecord, type AttemptStore, type ExactMcpTool,
  type FieldMap, type CommandOf, type Observation, type ProviderOutcome,
  type RunResult, type SelfHostedProviderAdapter,
} from "../self-hosted.js";
import type { ConformanceReport, ConformanceCaseResult } from "./index.js";

export type SelfHostedScenario =
  | "accepted" | "rejected" | "unknown" | "timeout" | "observation-unavailable";

/** The consumer connects its provider-specific fake port to this script. */
export class ScriptedProvider {
  readonly scenario: SelfHostedScenario;
  readonly trace: string[];
  writes = 0;
  reads = 0;

  constructor(scenario: SelfHostedScenario, trace: string[]) {
    this.scenario = scenario;
    this.trace = trace;
  }

  async write(request: unknown, credential: unknown): Promise<ProviderOutcome<string>> {
    void request; void credential;
    this.trace.push("provider-write");
    this.writes += 1;
    if (this.scenario === "timeout") throw new Error("synthetic provider timeout");
    if (this.scenario === "unknown") return { kind: "unknown", code: "synthetic-outcome-unknown" };
    if (this.scenario === "rejected") return { kind: "rejected", code: "synthetic-definite-no-effect" };
    return { kind: "accepted", value: "synthetic-accepted" };
  }

  async read(request: unknown): Promise<Observation> {
    void request;
    this.trace.push("provider-read");
    this.reads += 1;
    return this.scenario === "observation-unavailable" ? "unavailable" : "observed";
  }
}

class MemoryAttempts implements AttemptStore {
  readonly trace: string[];
  readonly records = new Map<string, AttemptRecord>();
  readonly keys = new Set<string>();

  constructor(trace: string[]) { this.trace = trace; }

  async claimOnce(actionCommitment: Uint8Array, operationKey: string): Promise<boolean> {
    this.trace.push("claim");
    const identity = hex(actionCommitment);
    if (this.records.has(identity) || this.keys.has(operationKey)) return false;
    this.keys.add(operationKey);
    this.records.set(identity, { actionCommitment: actionCommitment.slice(), operationKey, state: "attempting" });
    return true;
  }

  async read(actionCommitment: Uint8Array): Promise<AttemptRecord | undefined> {
    return this.records.get(hex(actionCommitment));
  }

  async finish(actionCommitment: Uint8Array, state: "confirmed" | "rejected" | "unknown"): Promise<AttemptRecord> {
    const identity = hex(actionCommitment);
    const previous = this.records.get(identity);
    if (!previous || previous.state !== "attempting") throw new Error("attempt already finished");
    const record = { ...previous, state };
    this.records.set(identity, record);
    return record;
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, item => item.toString(16).padStart(2, "0")).join("");
}

/** Run mandatory local ordering and uncertain-effect cases against an adapter factory. */
export async function runSelfHostedAdapterConformance<
  Fields extends FieldMap, Credential, Result,
>(input: Readonly<{
  contract: ExactMcpTool<Fields>;
  command: CommandOf<Fields>;
  artifacts: Readonly<{ proof: Uint8Array; action: Uint8Array; trustedContext: Uint8Array }>;
  adapterFactory: (provider: ScriptedProvider) => SelfHostedProviderAdapter<CommandOf<Fields>, Credential, Result>;
}>): Promise<ConformanceReport> {
  const cases: ConformanceCaseResult[] = [];
  async function exercise(scenario: SelfHostedScenario, id: string): Promise<void> {
    const trace: string[] = [];
    const provider = new ScriptedProvider(scenario, trace);
    const actual = input.adapterFactory(provider);
    const adapter: SelfHostedProviderAdapter<CommandOf<Fields>, Credential, Result> = {
      async credential() { trace.push("credential"); return actual.credential(); },
      async invoke(command, credential) { trace.push("invoke"); return actual.invoke(command, credential); },
      async observe(command) { trace.push("observe"); return actual.observe(command); },
    };
    const attempts = new MemoryAttempts(trace);
    const base = {
      contract: input.contract, proof: input.artifacts.proof,
      action: input.artifacts.action, trustedContext: input.artifacts.trustedContext,
      attempts, operationKey: "synthetic-operation", adapter,
      expectedCommand: input.command,
    };
    try {
      if (id === "denied-before-credential") {
        const wrong = exactMcpTool({ service: input.contract.service, name: "auths_test_wrong_tool",
          fields: { value: { kind: "boolean" } } });
        const result = await runOnce({ ...base, contract: wrong, expectedCommand: { value: false },
          adapter: { credential: adapter.credential, invoke: async () => ({ kind: "unknown", code: "wrong" }),
            observe: async () => "unavailable" } });
        if (result.kind !== "denied" || provider.writes || trace.includes("claim") || trace.includes("credential")) {
          throw new Error("denial reached claim or provider");
        }
      } else if (id === "mutated-action-before-credential") {
        const changed = input.artifacts.action.slice();
        changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
        try {
          const result = await runOnce({ ...base, action: changed });
          if (result.kind === "attempted") throw new Error("mutated action produced an attempt");
        } catch { /* malformed transport is also a pre-entry failure */ }
        if (provider.writes || trace.includes("claim") || trace.includes("credential")) {
          throw new Error("mutated action reached claim or provider");
        }
      } else if (id === "invalid-trust-before-credential") {
        try {
          const result = await runOnce({ ...base, trustedContext: new Uint8Array([0]) });
          if (result.kind === "attempted") throw new Error("invalid trust produced an attempt");
        } catch { /* malformed trust may fail before a verdict */ }
        if (provider.writes || trace.includes("claim") || trace.includes("credential")) {
          throw new Error("invalid trust reached claim or provider");
        }
      } else if (id === "credential-unavailable-before-provider") {
        const unavailable: SelfHostedProviderAdapter<CommandOf<Fields>, Credential, Result> = {
          credential() { trace.push("credential"); throw new Error("synthetic credential unavailable"); },
          async invoke() { throw new Error("provider must not be entered"); },
          async observe() { throw new Error("observation must not be entered"); },
        };
        const result = await runOnce({ ...base, adapter: unavailable });
        const record = [...attempts.records.values()][0];
        if (result.kind !== "pre-entry-failed" || record?.state !== "rejected" || provider.writes) {
          throw new Error("credential failure crossed provider boundary");
        }
      } else if (id === "competing-claim") {
        const results = await Promise.all([runOnce(base), runOnce(base)]);
        if (provider.writes !== 1 || results.filter(result => result.kind === "attempted").length !== 1) {
          throw new Error("competing calls entered provider more than once");
        }
      } else {
        let result: RunResult<CommandOf<Fields>, Result> | undefined;
        try { result = await runOnce(base); }
        catch (error) { if (scenario !== "timeout") throw error; }
        const record = [...attempts.records.values()][0];
        if (provider.writes !== 1 || !record) throw new Error("adapter did not use scripted provider once");
        if (scenario === "accepted") {
          if (result?.kind !== "attempted" || result.provider.kind !== "accepted" || result.observation !== "observed" ||
              trace.indexOf("claim") > trace.indexOf("credential") ||
              trace.indexOf("credential") > trace.indexOf("provider-write")) {
            throw new Error("accepted result or execution order is incorrect");
          }
          const replay = await runOnce(base);
          if (replay.kind !== "replay" || provider.writes !== 1) throw new Error("replay entered provider");
        } else if (scenario === "rejected") {
          if (result?.kind !== "attempted" || !(
            (result.provider.kind === "rejected" && record.state === "rejected") ||
            (result.provider.kind === "unknown" && record.state === "unknown")
          )) {
            throw new Error("synthetic no-effect result was overstated");
          }
        } else if (scenario === "unknown" || scenario === "timeout") {
          if (record.state !== "unknown" ||
              (result !== undefined && (result.kind !== "attempted" || result.provider.kind !== "unknown"))) {
            throw new Error("possible effect was not retained as unknown");
          }
          const replay = await runOnce(base);
          if (replay.kind !== "replay" || provider.writes !== 1) throw new Error("unknown effect was retried");
          if (result?.kind === "attempted") {
            const before = provider.writes;
            await reconcileReadOnly({ authorization: result.authorization, adapter });
            if (provider.writes !== before) throw new Error("reconciliation repeated a write");
          }
        } else if (result?.kind !== "attempted" || result.observation === "observed") {
          throw new Error("unavailable observation was overstated");
        }
      }
      cases.push({ id, status: "passed" });
    } catch (error) {
      cases.push({ id, status: "failed", detailCode: "contract-mismatch",
        summary: error instanceof Error ? error.name.slice(0, 128) : "adapter failure" });
    }
  }
  for (const [scenario, id] of [
    ["accepted", "authorized-one-write-and-replay"],
    ["accepted", "denied-before-credential"],
    ["accepted", "mutated-action-before-credential"],
    ["accepted", "invalid-trust-before-credential"],
    ["accepted", "credential-unavailable-before-provider"],
    ["accepted", "competing-claim"],
    ["rejected", "definite-no-effect-rejection"],
    ["unknown", "unknown-no-blind-retry"],
    ["timeout", "timeout-no-blind-retry"],
    ["observation-unavailable", "unavailable-observation"],
  ] as const) await exercise(scenario, id);
  return Object.freeze({
    metadata: Object.freeze({ suite: "self-hosted-provider-adapter/1", contractVersion: "1",
      sdkVersion: "1.0.0-rc.1", generatedAt: new Date().toISOString(),
      assurance: "test-results-only-not-security-certification" }),
    passed: cases.every(item => item.status === "passed"), cases: Object.freeze(cases),
  });
}
