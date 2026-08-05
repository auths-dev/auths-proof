import type { Explanation, VerdictKind } from "./result.js";

export function explain(kind: VerdictKind, code: string): Explanation {
  if (kind === "authorized") {
    return { code, message: "the proof establishes exact authority for this action", retryable: false };
  }
  if (kind === "indeterminate") {
    return { code, message: "a required trustworthy fact or implementation is unavailable", retryable: true };
  }
  return { code, message: "the supplied proof does not authorize this exact action", retryable: false };
}
