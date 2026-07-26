export function copyAndFlipLast(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new TypeError("expected non-empty bytes");
  }
  const changed = bytes.slice();
  changed[changed.length - 1] ^= 1;
  return changed;
}

export function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function short(value, width = 12) {
  if (typeof value !== "string") return "—";
  if (value.length <= width) return value;
  return `${value.slice(0, width)}…${value.slice(-4)}`;
}

export async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return hex(new Uint8Array(digest));
}

export function configurationState(required, executed) {
  if (required === undefined || required === null) return "unavailable";
  return required === executed ? "match" : "mismatch";
}

export function runtimeDisplay(variant, runtime, validSubmissions = 0) {
  if (runtime === undefined) {
    return {
      first: "READY",
      replay: "NOT RUN",
      executorInvocations: 0,
      receiptCount: "0 decision · 0 execution",
    };
  }
  if (variant !== "valid") {
    if (
      runtime.entered !== false ||
      runtime.executor_invocations !== 0 ||
      runtime.decision_receipts !== 0 ||
      runtime.execution_receipts !== 0
    ) {
      throw new Error("denied input crossed the native executor boundary");
    }
    return {
      first: "DENIED",
      replay: "NOT ENTERED",
      executorInvocations: 0,
      receiptCount: "0 decision · 0 execution",
    };
  }
  if (
    runtime.entered !== true ||
    runtime.executor_invocations !== 1 ||
    runtime.decision_receipts !== 1 ||
    runtime.execution_receipts !== 1
  ) {
    throw new Error("native execution counters violated the demo contract");
  }
  if (validSubmissions === 1 && runtime.response?.outcome === "completed") {
    return {
      first: "COMPLETED",
      replay: "READY",
      executorInvocations: 1,
      receiptCount: "1 decision · 1 execution",
    };
  }
  if (
    validSubmissions === 2 &&
    runtime.response?.outcome === "refused" &&
    runtime.response?.kind === "consumed-challenge"
  ) {
    return {
      first: "COMPLETED",
      replay: "CONSUMED-CHALLENGE",
      executorInvocations: 1,
      receiptCount: "1 decision · 1 execution",
    };
  }
  throw new Error("native replay transition violated the demo contract");
}

export function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(Number(value));
}
