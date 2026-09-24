/**
 * Type check only for a requested action validity. The default and the bounds
 * are native, so an omitted value stays omitted.
 */
export function checkedValidity(value: number | undefined): number | undefined {
  if (value !== undefined && (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff)) {
    throw new RangeError("action validity must be a whole number of seconds");
  }
  return value;
}
