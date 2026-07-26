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

export function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(Number(value));
}
