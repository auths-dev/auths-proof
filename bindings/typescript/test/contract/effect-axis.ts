/**
 * WAVE ACCEPTANCE TEST (compile-time half) — the frozen effect vocabulary.
 *
 * EXPECTED TO BE RED until the Surface lane lands. `npm run test:contract`
 * type-checks this file; every error below is a finding.
 *
 * `EffectState` and `RetryClass` are erased at runtime, so their shape cannot
 * be asserted by a node:test file. This is where contract 4.1 is enforced:
 *
 *   EffectState = "not-applied" | "possible" | "applied"      exactly three
 *   RetryClass  = "never" | "safe" | "conditional" | "unknown" — "may I retry"
 *   NextCall    = "never" | "backoff" | "resume" | "reconcile" — "what next"
 *
 * The last two are DIFFERENT QUESTIONS and must never share an identifier.
 * `@auths-dev/sdk` used to export the NextCall set under the name `RetryClass`
 * and export no `EffectState` at all. It now exports `EffectState` and the
 * `RetryClass` question; `NextCall` belongs to `@auths-dev/sdk/service`.
 */

import type {
  AuthsErrorDetails,
  EffectState,
  RecommendedAction,
  RetryClass,
} from "../../src/index.js";
// `NextCall` answers "what should I call next", which only the remote client
// can answer, so it is exported from the subpath that publishes that client
// (contract 4.4). Importing both here is the point: they must not unify.
import type { NextCall } from "../../src/service.js";

// --- EffectState: exactly three members, no fourth ------------------------

const everyEffectState: readonly EffectState[] = ["not-applied", "possible", "applied"];
void everyEffectState;

// @ts-expect-error "unknown" is not a fourth effect state; unrecognized codes map to "possible"
const fourthEffectState: EffectState = "unknown";
void fourthEffectState;

// @ts-expect-error the workflow-local vocabulary (none|possible|occurred) is deleted
const workflowEffectState: EffectState = "occurred";
void workflowEffectState;

// A total switch proves the union is closed at exactly three.
export function describeEffect(effect: EffectState): string {
  switch (effect) {
    case "not-applied": return "the real-world effect did not happen";
    case "possible": return "we do not know whether the real-world effect happened";
    case "applied": return "the real-world effect happened";
    default: {
      const exhaustive: never = effect;
      return exhaustive;
    }
  }
}

// --- RetryClass: the "may I retry" question -------------------------------

const everyRetryClass: readonly RetryClass[] = ["never", "safe", "conditional", "unknown"];
void everyRetryClass;

// @ts-expect-error "backoff" belongs to NextCall, not to the retry question
const nextCallAsRetry: RetryClass = "backoff";
void nextCallAsRetry;

// --- NextCall: the "what should I call next" question ---------------------

const everyNextCall: readonly NextCall[] = ["never", "backoff", "resume", "reconcile"];
void everyNextCall;

// @ts-expect-error "safe" belongs to RetryClass, not to the next-call question
const retryAsNextCall: NextCall = "safe";
void retryAsNextCall;

// --- The axis is reachable and typed on the public error details ----------

export function readAxis(details: AuthsErrorDetails): {
  readonly code: string;
  readonly effect: EffectState;
  readonly retry: RetryClass;
  readonly recommendedAction: RecommendedAction;
} {
  return {
    code: details.code,
    effect: details.effect,
    retry: details.retry,
    recommendedAction: details.recommendedAction,
  };
}
