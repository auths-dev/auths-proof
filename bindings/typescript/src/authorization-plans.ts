import { AuthsWorkflowError, type WorkflowAuthorizationPlanBuilder } from "./workflow.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

const PLAN_TOKEN = Symbol("auths-authorization-plan");
const BUILDER_TOKEN = Symbol("auths-authorization-plan-builder");
const REFERENCE_TOKEN = Symbol("auths-proof-reference");

export type AuthorizationPlanKind = "proof" | "all-of" | "any-of" | "threshold";

interface PlanState {
  readonly builder: AuthorizationPlanBuilder;
  readonly handle: number;
}

const planStates = new WeakMap<AuthorizationPlan, PlanState>();
const proofReferences = new WeakMap<ProofReference, Uint8Array>();

export class ProofReference {
  declare private readonly __reference: void;

  private constructor(token: typeof REFERENCE_TOKEN, bytes: Uint8Array) {
    if (token !== REFERENCE_TOKEN) throw new TypeError("sealed Auths proof reference");
    proofReferences.set(this, bytes);
    Object.freeze(this);
  }

  static create(token: typeof REFERENCE_TOKEN, bytes: Uint8Array): ProofReference {
    return new ProofReference(token, bytes);
  }
}

export function proofReference(value: string): ProofReference {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new AuthsWorkflowError("invalid-authority", "proof reference must be 64 lowercase hex characters");
  }
  return ProofReference.create(REFERENCE_TOKEN, Uint8Array.from(
    { length: 32 },
    (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  ));
}

export class AuthorizationPlan {
  declare private readonly __plan: void;
  readonly kind: AuthorizationPlanKind;

  private constructor(
    token: typeof PLAN_TOKEN,
    kind: AuthorizationPlanKind,
    builder: AuthorizationPlanBuilder,
    handle: number,
  ) {
    if (token !== PLAN_TOKEN) throw new TypeError("sealed Auths authorization plan");
    this.kind = kind;
    planStates.set(this, { builder, handle });
    Object.freeze(this);
  }

  static create(
    token: typeof PLAN_TOKEN,
    kind: AuthorizationPlanKind,
    builder: AuthorizationPlanBuilder,
    handle: number,
  ): AuthorizationPlan {
    if (token !== PLAN_TOKEN) throw new TypeError("sealed Auths authorization plan");
    return new AuthorizationPlan(token, kind, builder, handle);
  }
}

export interface AuthorizationPlanSummary {
  readonly planId: Uint8Array;
  readonly canonicalPlan: Uint8Array;
  readonly proofReferences: readonly ProofReference[];
  readonly leafCount: number;
  readonly maximumDepth: number;
}

export class AuthorizationPlanBuilder {
  readonly #native: WorkflowAuthorizationPlanBuilder;
  #active = true;

  private constructor(
    token: typeof BUILDER_TOKEN,
    native: WorkflowAuthorizationPlanBuilder,
  ) {
    if (token !== BUILDER_TOKEN) throw new TypeError("sealed Auths authorization plan builder");
    this.#native = native;
  }

  static create(
    token: typeof BUILDER_TOKEN,
    native: WorkflowAuthorizationPlanBuilder,
  ): AuthorizationPlanBuilder {
    if (token !== BUILDER_TOKEN) throw new TypeError("sealed Auths authorization plan builder");
    return new AuthorizationPlanBuilder(token, native);
  }

  proof(reference: ProofReference): AuthorizationPlan {
    this.#assertActive();
    const bytes = proofReferences.get(reference);
    if (bytes === undefined) {
      throw new AuthsWorkflowError("invalid-authority", "proof reference is forged");
    }
    return AuthorizationPlan.create(PLAN_TOKEN, "proof", this, this.#native.proof(bytes.slice()));
  }

  allOf(members: readonly AuthorizationPlan[]): AuthorizationPlan {
    return this.#compound("all-of", members, (handles) => this.#native.allOf(handles));
  }

  anyOf(members: readonly AuthorizationPlan[]): AuthorizationPlan {
    return this.#compound("any-of", members, (handles) => this.#native.anyOf(handles));
  }

  threshold(required: number, members: readonly AuthorizationPlan[]): AuthorizationPlan {
    return this.#compound(
      "threshold",
      members,
      (handles) => this.#native.threshold(required, handles),
    );
  }

  summarize(plan: AuthorizationPlan): AuthorizationPlanSummary {
    this.#assertActive();
    const handle = this.#handle(plan);
    const summary = this.#native.summarize(handle);
    try {
      const references = new Uint8Array(summary.proofReferences);
      if (references.length !== summary.leafCount * 32) {
        throw new AuthsWorkflowError("invalid-authority", "native plan summary is inconsistent");
      }
      return Object.freeze({
        planId: new Uint8Array(summary.planId),
        canonicalPlan: new Uint8Array(summary.planCbor),
        proofReferences: Object.freeze(Array.from(
          { length: summary.leafCount },
          (_, index) => ProofReference.create(
            REFERENCE_TOKEN,
            references.slice(index * 32, (index + 1) * 32),
          ),
        )),
        leafCount: summary.leafCount,
        maximumDepth: summary.maximumDepth,
      });
    } finally {
      summary.free?.();
    }
  }

  dispose(): void {
    if (!this.#active) return;
    this.#active = false;
    this.#native.free?.();
  }

  #compound(
    kind: AuthorizationPlanKind,
    members: readonly AuthorizationPlan[],
    compose: (handles: Uint32Array) => number,
  ): AuthorizationPlan {
    this.#assertActive();
    const handles = Uint32Array.from(members, (member) => this.#handle(member));
    return AuthorizationPlan.create(PLAN_TOKEN, kind, this, compose(handles));
  }

  #handle(plan: AuthorizationPlan): number {
    const state = planStates.get(plan);
    if (state === undefined || state.builder !== this) {
      throw new AuthsWorkflowError("invalid-authority", "authorization plan belongs to another builder");
    }
    return state.handle;
  }

  #assertActive(): void {
    if (!this.#active) {
      throw new AuthsWorkflowError("disposed", "authorization plan builder is disposed");
    }
  }
}

export async function loadAuthorizationPlanBuilder(): Promise<AuthorizationPlanBuilder> {
  const engine = await loadPackagedWorkflowEngine();
  return AuthorizationPlanBuilder.create(BUILDER_TOKEN, new engine.AuthorizationPlanBuilderV1());
}
