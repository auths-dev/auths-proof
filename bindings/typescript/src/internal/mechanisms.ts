export interface AtomicReservationRecord {
  readonly key: string;
  readonly commitment: Uint8Array;
  readonly value: Uint8Array;
}

export interface AtomicReservationStore {
  reserve(record: AtomicReservationRecord): Promise<"acquired" | "exact-replay" | "conflict">;
  reopen?(): AtomicReservationStore | Promise<AtomicReservationStore>;
  close?(): void | Promise<void>;
}
