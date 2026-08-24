import type { AuthsIssue, KnownAuthsErrorCode } from "../product-errors.js";
import { ERROR_REGISTRY } from "../generated/error-registry.js";

const definitions = new Map(
  ERROR_REGISTRY.definitions.map((definition) => [definition.code, definition] as const),
);

/** Creates the immutable host projection of one Rust-generated registry row. */
export function issue(
  code: KnownAuthsErrorCode,
  options: Readonly<{
    correlationId?: string;
    summary?: string;
    executionReference?: string;
    decisionReference?: string;
    receiptReference?: string;
    causes?: AuthsIssue["causes"];
    entered?: Partial<AuthsIssue["enteredBoundaries"]>;
  }> = {},
): AuthsIssue {
  const definition = definitions.get(code);
  if (definition === undefined) throw new TypeError("unknown Auths issue code");
  const outcome = definition.outcomes[0];
  if (outcome === undefined) throw new TypeError("Auths issue code has no outcome");
  const entered = options.entered ?? {};
  return Object.freeze({
    schema: "auths.error/1",
    code,
    family: definition.family,
    operation: definition.operation,
    stage: definition.stages[0] ?? "internal",
    summary: options.summary ?? definition.title,
    correlationId: options.correlationId ?? nextCorrelationId(),
    effect: outcome.effect,
    retry: outcome.retry,
    recommendedAction: definition.recommendedAction,
    enteredBoundaries: Object.freeze({
      approval: entered.approval ?? false,
      signer: entered.signer ?? false,
      state: entered.state ?? false,
      credential: entered.credential ?? false,
      provider: entered.provider ?? outcome.effect !== "not-applied",
    }),
    ...(options.executionReference === undefined
      ? {}
      : { executionReference: options.executionReference }),
    ...(options.decisionReference === undefined
      ? {}
      : { decisionReference: options.decisionReference }),
    ...(options.receiptReference === undefined
      ? {}
      : { receiptReference: options.receiptReference }),
    causes: Object.freeze([...(options.causes ?? [])]),
  });
}

let correlationSequence = 0;

function nextCorrelationId(): string {
  correlationSequence = (correlationSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `auths-${Date.now().toString(36)}-${correlationSequence.toString(36)}`;
}
