/** Default validity, in seconds, of an SDK-prepared action. */
export const DEFAULT_ACTION_VALIDITY_SECONDS = 30;
/** Largest validity, in seconds, the native authoring path accepts. */
export const MAX_ACTION_VALIDITY_SECONDS = 300;

/** Returns the requested action validity, or the default, inside the native bound. */
export function checkedValidity(value: number | undefined): number {
  const seconds = value ?? DEFAULT_ACTION_VALIDITY_SECONDS;
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > MAX_ACTION_VALIDITY_SECONDS) {
    throw new RangeError("action validity must be 1 to 300 seconds");
  }
  return seconds;
}
