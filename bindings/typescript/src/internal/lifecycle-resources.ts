import { AuthsWorkflowError } from "../workflow/errors.js";

const snapshots = new WeakMap<object, Uint8Array>();

export function registerStatusSnapshot(snapshot: object, cbor: Uint8Array): void {
  snapshots.set(snapshot, cbor.slice());
}

export function statusSnapshotBytes(snapshot: object): Uint8Array {
  const cbor = snapshots.get(snapshot);
  if (cbor === undefined) {
    throw new AuthsWorkflowError("invalid-authority", "status snapshot is forged");
  }
  return cbor.slice();
}
