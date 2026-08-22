import type { AuthsIssue, EffectState, RecommendedAction, RetryClass } from "../../src/index.js";

const everyEffect: readonly EffectState[] = ["not-applied", "possible", "applied"];
const everyRetry: readonly RetryClass[] = ["never", "safe", "conditional", "unknown"];
void everyEffect; void everyRetry;

// @ts-expect-error the effect axis is closed
const invalidEffect: EffectState = "unknown";
// @ts-expect-error retry classification is distinct from next-call guidance
const invalidRetry: RetryClass = "resume";
void invalidEffect; void invalidRetry;

export function readAxis(issue: AuthsIssue): {
  readonly code: string;
  readonly effect: EffectState;
  readonly retry: RetryClass;
  readonly recommendedAction: RecommendedAction;
} {
  return { code: issue.code, effect: issue.effect, retry: issue.retry, recommendedAction: issue.recommendedAction };
}
