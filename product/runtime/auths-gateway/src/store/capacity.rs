//! Shared fixed-window slot mechanics. Protocol owners decide which capacity
//! to reserve; this module preserves the existing bounded arithmetic and rows.
use super::*;
use crate::bounds::{BoundAdmission, count_slot_key, sum_slot_key};

pub(super) struct CapacityCandidate<'a> {
    bound: &'a BoundAdmission,
    counts: Vec<u64>,
    sums: Vec<u64>,
    totals: Vec<u64>,
}

impl<'a> CapacityCandidate<'a> {
    pub(super) fn new(
        store: &dyn GatewayAttemptStore,
        bound: &'a BoundAdmission,
    ) -> Result<Self, GatewayAttemptError> {
        let counts = bound
            .counts
            .iter()
            .map(|counter| {
                frontier(
                    store,
                    GatewayRecordKind::CountSlot,
                    &counter.key,
                    counter.capacity,
                    count_slot_key,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sums = bound
            .sums
            .iter()
            .map(|counter| {
                frontier(
                    store,
                    GatewayRecordKind::SumSlot,
                    &counter.key,
                    counter.slots,
                    sum_slot_key,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let totals = sums
            .iter()
            .zip(&bound.sums)
            .map(|(slot, counter)| match slot.checked_sub(1) {
                None => Ok(0),
                Some(previous) => cumulative(store, &counter.key, previous),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            bound,
            counts,
            sums,
            totals,
        })
    }
    pub(super) fn refusal(&self) -> Option<&'static str> {
        use auths_bounded_policy::kernel::{chain_counts_admit, chain_sums_admit};
        let Self {
            bound,
            counts,
            sums,
            totals,
        } = self;
        let count_capacities: Vec<u64> = bound
            .counts
            .iter()
            .map(|counter| counter.capacity)
            .collect();
        let sum_capacities: Vec<u64> = bound.sums.iter().map(|counter| counter.capacity).collect();
        let sum_slots_left = sums
            .iter()
            .zip(&bound.sums)
            .all(|(slot, counter)| *slot < counter.slots);
        if !chain_counts_admit(counts, &count_capacities) || !sum_slots_left {
            return Some("gateway.policy.window-exhausted");
        }
        if !chain_sums_admit(totals, bound.argument, &sum_capacities) {
            return Some("gateway.policy.sum-exhausted");
        }
        None
    }
    pub(super) fn batch(
        &self,
        key: GatewayAttemptKey,
        namespace: &str,
        operation_id: &str,
    ) -> Result<(Vec<CounterWire>, Vec<GatewayRecordEntry>), GatewayAttemptError> {
        let Self {
            bound,
            counts,
            sums,
            totals,
        } = self;
        let mut counters: Vec<GatewayCounterEntry> = bound
            .counts
            .iter()
            .zip(counts)
            .map(|(counter, slot)| GatewayCounterEntry {
                kind: GatewayCounterKind::Count,
                counter: counter.key,
                slot: *slot,
            })
            .chain(
                bound
                    .sums
                    .iter()
                    .zip(sums)
                    .map(|(counter, slot)| GatewayCounterEntry {
                        kind: GatewayCounterKind::Sum,
                        counter: counter.key,
                        slot: *slot,
                    }),
            )
            .collect();
        counters.sort_unstable();
        let wires = counters
            .iter()
            .map(|entry| CounterWire {
                kind: entry.kind,
                counter: hex::encode(entry.counter),
                slot: entry.slot,
            })
            .collect();
        let claim = hex::encode(key.as_bytes());
        let mut entries = Vec::with_capacity(1 + counts.len() + sums.len());
        for (counter, slot) in bound.counts.iter().zip(counts) {
            let slot_record = CountSlotRecord {
                schema: COUNT_SLOT_SCHEMA.to_owned(),
                counter: hex::encode(counter.key),
                slot: *slot,
                window_seconds: bound.window_seconds,
                window_index: bound.window_index,
                window_end: bound.window_end,
                namespace: namespace.to_owned(),
                operation_id: operation_id.to_owned(),
                claim: claim.clone(),
            };
            entries.push(GatewayRecordEntry {
                kind: GatewayRecordKind::CountSlot,
                key: GatewayAttemptKey(count_slot_key(&counter.key, *slot)),
                record: canonical(&slot_record)?,
                expires_at: Some(bound.expires_at()),
            });
        }
        for ((counter, slot), total) in bound.sums.iter().zip(sums).zip(totals) {
            let slot_record = SumSlotRecord {
                schema: SUM_SLOT_SCHEMA.to_owned(),
                counter: hex::encode(counter.key),
                slot: *slot,
                amount: bound.argument,
                cumulative: total
                    .checked_add(bound.argument)
                    .ok_or(GatewayAttemptError::Corrupt)?,
                window_seconds: bound.window_seconds,
                window_index: bound.window_index,
                window_end: bound.window_end,
                namespace: namespace.to_owned(),
                operation_id: operation_id.to_owned(),
                claim: claim.clone(),
            };
            entries.push(GatewayRecordEntry {
                kind: GatewayRecordKind::SumSlot,
                key: GatewayAttemptKey(sum_slot_key(&counter.key, *slot)),
                record: canonical(&slot_record)?,
                expires_at: Some(bound.expires_at()),
            });
        }
        Ok((wires, entries))
    }
    pub(super) fn advance(
        &mut self,
        store: &dyn GatewayAttemptStore,
        index: usize,
    ) -> Result<(), GatewayAttemptError> {
        let Self {
            bound,
            counts,
            sums,
            totals,
        } = self;
        let position = index;
        if let Some(slot) = counts.get_mut(position) {
            *slot += 1;
        } else {
            let position = position - counts.len();
            let (Some(slot), Some(total), Some(counter)) = (
                sums.get_mut(position),
                totals.get_mut(position),
                bound.sums.get(position),
            ) else {
                return Err(GatewayAttemptError::Corrupt);
            };
            *total = cumulative(store, &counter.key, *slot)?;
            *slot += 1;
        }
        Ok(())
    }
}

pub(super) fn decode_counters(
    wires: &[CounterWire],
) -> Result<Vec<GatewayCounterEntry>, GatewayAttemptError> {
    if wires.len() > MAX_COUNTERS {
        return Err(GatewayAttemptError::Corrupt);
    }
    let counters = wires
        .iter()
        .map(|entry| {
            Ok(GatewayCounterEntry {
                kind: entry.kind,
                counter: digest_bytes(&entry.counter)?,
                slot: entry.slot,
            })
        })
        .collect::<Result<Vec<_>, GatewayAttemptError>>()?;
    if counters.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(counters)
}

pub(super) fn validate_reservations(
    namespace: &str,
    operation_id: &str,
    counters: &[CounterWire],
    key: GatewayAttemptKey,
    bound: Option<&crate::bounds::BoundAdmission>,
    snapshots: &[Option<Vec<u8>>],
    now: u64,
) -> Result<(), GatewayAttemptError> {
    let counters = decode_counters(counters)?;
    let Some(bound) = bound else {
        return if counters.is_empty() && snapshots.is_empty() {
            Ok(())
        } else {
            Err(GatewayAttemptError::Corrupt)
        };
    };
    if counters.len() != bound.counts.len() + bound.sums.len()
        || snapshots.len() != counters.len()
        || bound.window_seconds == 0
        || bound.counts.iter().any(|bound| {
            counters
                .iter()
                .filter(|counter| {
                    counter.kind == GatewayCounterKind::Count && counter.counter == bound.key
                })
                .count()
                != 1
        })
        || bound.sums.iter().any(|bound| {
            counters
                .iter()
                .filter(|counter| {
                    counter.kind == GatewayCounterKind::Sum && counter.counter == bound.key
                })
                .count()
                != 1
        })
        || now >= bound.window_end
        || now / bound.window_seconds != bound.window_index
    {
        return Err(GatewayAttemptError::InvalidTransition);
    }
    let claim = hex::encode(key.as_bytes());
    for (counter, bytes) in counters.iter().zip(snapshots) {
        let bytes = bytes.as_deref().ok_or(GatewayAttemptError::Corrupt)?;
        let valid = match counter.kind {
            GatewayCounterKind::Count => {
                let slot: CountSlotRecord =
                    serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
                let limit = bound
                    .counts
                    .iter()
                    .find(|candidate| candidate.key == counter.counter)
                    .ok_or(GatewayAttemptError::Corrupt)?;
                canonical(&slot)? == bytes
                    && slot.schema == COUNT_SLOT_SCHEMA
                    && slot.counter == hex::encode(counter.counter)
                    && slot.slot == counter.slot
                    && slot.slot < limit.capacity
                    && slot.namespace == namespace
                    && slot.operation_id == operation_id
                    && slot.claim == claim
                    && slot.window_seconds == bound.window_seconds
                    && slot.window_index == bound.window_index
                    && slot.window_end == bound.window_end
            }
            GatewayCounterKind::Sum => {
                let slot: SumSlotRecord =
                    serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
                let limit = bound
                    .sums
                    .iter()
                    .find(|candidate| candidate.key == counter.counter)
                    .ok_or(GatewayAttemptError::Corrupt)?;
                canonical(&slot)? == bytes
                    && slot.schema == SUM_SLOT_SCHEMA
                    && slot.counter == hex::encode(counter.counter)
                    && slot.slot == counter.slot
                    && slot.slot < limit.slots
                    && slot.namespace == namespace
                    && slot.operation_id == operation_id
                    && slot.claim == claim
                    && slot.window_seconds == bound.window_seconds
                    && slot.window_index == bound.window_index
                    && slot.window_end == bound.window_end
                    && slot.amount == bound.argument
                    && slot.amount <= slot.cumulative
                    && slot.cumulative <= limit.capacity
            }
        };
        if !valid {
            return Err(GatewayAttemptError::Corrupt);
        }
    }
    Ok(())
}

impl CapacityCandidate<'_> {
    pub(super) fn dependencies(&self) -> Vec<(GatewayRecordKind, GatewayAttemptKey)> {
        let Self { bound, sums, .. } = self;
        let mut dependencies = Vec::new();
        for (counter, slot) in bound.sums.iter().zip(sums) {
            if let Some(previous) = slot.checked_sub(1) {
                dependencies.push((
                    GatewayRecordKind::SumSlot,
                    GatewayAttemptKey(crate::bounds::sum_slot_key(&counter.key, previous)),
                ));
            }
        }
        dependencies
    }
    pub(super) fn validate_predecessors(
        &self,
        snapshots: &[Option<Vec<u8>>],
    ) -> Result<(), GatewayAttemptError> {
        let Self {
            bound,
            sums,
            totals,
            ..
        } = self;
        if snapshots.len() != self.dependencies().len() {
            return Err(GatewayAttemptError::Corrupt);
        }
        let mut predecessors = snapshots.iter();
        for ((counter, slot), total) in bound.sums.iter().zip(sums).zip(totals) {
            match slot.checked_sub(1) {
                None if *total != 0 => return Err(GatewayAttemptError::Corrupt),
                None => {}
                Some(previous) => {
                    let bytes = predecessors
                        .next()
                        .and_then(|bytes| bytes.as_deref())
                        .ok_or(GatewayAttemptError::Corrupt)?;
                    let row: SumSlotRecord =
                        serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
                    if canonical(&row)? != bytes
                        || row.schema != SUM_SLOT_SCHEMA
                        || row.counter != hex::encode(counter.key)
                        || row.slot != previous
                        || row.amount > row.cumulative
                        || row.cumulative != *total
                        || row.window_seconds != bound.window_seconds
                        || row.window_index != bound.window_index
                        || row.window_end != bound.window_end
                        || row.cumulative > counter.capacity
                    {
                        return Err(GatewayAttemptError::Corrupt);
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) fn dependencies(
    counters: &[CounterWire],
) -> Result<Vec<(GatewayRecordKind, GatewayAttemptKey)>, GatewayAttemptError> {
    Ok(decode_counters(counters)?
        .iter()
        .map(|counter| match counter.kind {
            GatewayCounterKind::Count => (
                GatewayRecordKind::CountSlot,
                GatewayAttemptKey(count_slot_key(&counter.counter, counter.slot)),
            ),
            GatewayCounterKind::Sum => (
                GatewayRecordKind::SumSlot,
                GatewayAttemptKey(sum_slot_key(&counter.counter, counter.slot)),
            ),
        })
        .collect())
}

/// One append-only slot charges one invocation and its declared byte amount.
/// Unit domains and source eligibility remain in the bound protocol owner.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceAllocation {
    schema: String,
    claim: String,
    source: String,
    count_key: String,
    bytes_key: String,
    slot: u64,
    calls: u64,
    bytes: u64,
}

impl SourceAllocation {
    pub(super) fn new(
        source: [u8; 32],
        capacity: &crate::effect::SourceCapacity,
        key: GatewayAttemptKey,
        slot: u64,
    ) -> Result<Self, GatewayAttemptError> {
        if slot >= capacity.attempts {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        Ok(Self {
            schema: "auths.effect-allocation/1".to_owned(),
            claim: hex::encode(key.as_bytes()),
            source: hex::encode(source),
            count_key: hex::encode(capacity.count_key),
            bytes_key: hex::encode(capacity.bytes_key),
            slot,
            calls: 1,
            bytes: capacity.maximum_bytes,
        })
    }

    /// A losing admission can advance only past a canonical slot for the exact
    /// same source and units. Another claim is expected; altered facts are not.
    pub(super) fn validate_occupied(
        &self,
        expected: &Self,
        bytes: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if canonical(self)? != bytes
            || digest_bytes(&self.claim).is_err()
            || self.schema != expected.schema
            || self.source != expected.source
            || self.count_key != expected.count_key
            || self.bytes_key != expected.bytes_key
            || self.slot != expected.slot
            || self.calls != 1
            || self.bytes != expected.bytes
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        Ok(())
    }
}

pub(super) fn allocation_key(
    capacity: &crate::effect::SourceCapacity,
    slot: u64,
) -> GatewayAttemptKey {
    GatewayAttemptKey(crate::bounds::count_slot_key(&capacity.count_key, slot))
}
