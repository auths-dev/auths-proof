//! Typed append-only ancestor reservations in the existing operation journal.
//! No task ledger, mutable usage total, provider outcome, or permit lives here.
use super::*;
use crate::effect::{EngagementReservation, Unit};

const ALLOCATION_SCHEMA: &str = "auths.engagement-allocation/1";

/// Immutable references in the common record header. The commitment catches
/// missing/replaced allocation bytes at entry; it is not a signature or permit.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AllocationRef {
    reservation: EngagementReservation,
    slot: u64,
    commitment: [u8; 32],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    schema: String,
    claim: [u8; 32],
    effect: [u8; 32],
    reservation: EngagementReservation,
    slot: u64,
    cumulative: u64,
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], GatewayAttemptError> {
    auths_codec::domain_commitment("auths.engagement-allocation-record/1", bytes)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| GatewayAttemptError::Corrupt)
}

pub(super) fn slot_key(counter: &[u8; 32], slot: u64) -> [u8; 32] {
    // Fixed-size typed preimage; the counter already commits authority,
    // partition/epoch, engagement, ancestor and unit. Recipe/worker are absent.
    let mut preimage = [0_u8; 40];
    preimage[..32].copy_from_slice(counter);
    preimage[32..].copy_from_slice(&slot.to_be_bytes());
    Sha256::new()
        .chain_update(b"auths.engagement-allocation-key/1\0")
        .chain_update(preimage)
        .finalize()
        .into()
}

fn slots(reservation: &EngagementReservation) -> Result<u64, GatewayAttemptError> {
    let (count, maximum) = match reservation.unit {
        Unit::MutationCount => (true, 32),
        Unit::AcquisitionCount | Unit::DisclosureCount => (true, 64),
        Unit::DisclosureBytes => (false, 16 * 1_048_576),
        Unit::MutationSum | Unit::ResponseBytes => return Err(GatewayAttemptError::Corrupt),
    };
    if reservation.amount > reservation.ceiling
        || reservation.ceiling > maximum
        || (count && (reservation.amount != 1 || reservation.ceiling == 0))
        || (!count && reservation.amount > 65_536)
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(if count { reservation.ceiling } else { 64 })
}

fn decode_allocation(
    bytes: &[u8],
    expected: &EngagementReservation,
    slot: u64,
) -> Result<Allocation, GatewayAttemptError> {
    let row: Allocation =
        serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
    let count = matches!(
        expected.unit,
        Unit::MutationCount | Unit::AcquisitionCount | Unit::DisclosureCount
    );
    if canonical(&row)? != bytes
        || row.schema != ALLOCATION_SCHEMA
        || row.slot != slot
        || row.reservation.key != expected.key
        || row.reservation.unit != expected.unit
        || row.reservation.ceiling != expected.ceiling
        || row.slot >= slots(&row.reservation)?
        || row.reservation.amount > row.cumulative
        || row.cumulative > expected.ceiling
        || (count && row.cumulative != slot + 1)
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(row)
}

struct Candidate {
    row: Allocation,
    bytes: Vec<u8>,
    predecessor: Option<(GatewayAttemptKey, Vec<u8>)>,
}

impl Candidate {
    fn new(
        store: &dyn GatewayAttemptStore,
        reservation: &EngagementReservation,
        key: GatewayAttemptKey,
        effect: [u8; 32],
    ) -> Result<Self, GatewayAttemptError> {
        let slot = frontier(
            store,
            GatewayRecordKind::EffectAllocation,
            &reservation.key,
            slots(reservation)?,
            slot_key,
        )?;
        if slot == slots(reservation)? {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let predecessor = slot
            .checked_sub(1)
            .map(|previous| {
                let key = GatewayAttemptKey(slot_key(&reservation.key, previous));
                let bytes = store
                    .load(GatewayRecordKind::EffectAllocation, &key)?
                    .ok_or(GatewayAttemptError::Corrupt)?;
                decode_allocation(&bytes, reservation, previous)?;
                Ok::<_, GatewayAttemptError>((key, bytes))
            })
            .transpose()?;
        let previous = predecessor
            .as_ref()
            .map(|(_, bytes)| {
                decode_allocation(bytes, reservation, slot - 1).map(|row| row.cumulative)
            })
            .transpose()?
            .unwrap_or(0);
        // The same translated sum guard already enforces ordinary gateway
        // budgets. Zero-byte reservations retain their existing exact meaning.
        if !auths_bounded_policy::kernel::chain_sums_admit(
            &[previous],
            reservation.amount,
            &[reservation.ceiling],
        ) {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let cumulative =
            auths_bounded_policy::kernel::checked_add_u64(previous, reservation.amount)
                .ok_or(GatewayAttemptError::InvalidTransition)?;
        let row = Allocation {
            schema: ALLOCATION_SCHEMA.to_owned(),
            claim: *key.as_bytes(),
            effect,
            reservation: reservation.clone(),
            slot,
            cumulative,
        };
        let bytes = canonical(&row)?;
        Ok(Self {
            row,
            bytes,
            predecessor,
        })
    }
    fn reference(&self) -> Result<AllocationRef, GatewayAttemptError> {
        Ok(AllocationRef {
            reservation: self.row.reservation.clone(),
            slot: self.row.slot,
            commitment: digest(&self.bytes)?,
        })
    }
    fn entry(&self) -> GatewayRecordEntry {
        GatewayRecordEntry {
            kind: GatewayRecordKind::EffectAllocation,
            key: GatewayAttemptKey(slot_key(&self.row.reservation.key, self.row.slot)),
            record: self.bytes.clone(),
            expires_at: None,
        }
    }
}

/// Metadata check also used on proposed, not-yet-persisted records. Completeness
/// belongs to `validate_record`; no decoder may accept a pending reservation.
pub(super) fn validate_partial(
    binding: &EffectBinding,
    references: &[AllocationRef],
) -> Result<(), GatewayAttemptError> {
    if references.is_empty() {
        return Ok(());
    }
    let actual: Vec<_> = references
        .iter()
        .map(|reference| reference.reservation.clone())
        .collect();
    // A common header can belong to its primary operation or an exact declared
    // prerequisite. The typed state owner below selects which one is legal.
    if !binding.matches_engagement_declarations(&actual) {
        return Err(GatewayAttemptError::Corrupt);
    }
    for reference in references {
        if reference.slot >= slots(&reference.reservation)? {
            return Err(GatewayAttemptError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn validate_record<S: JournalProtocol>(
    record: &Record<S>,
) -> Result<(), GatewayAttemptError> {
    let binding = record.validate_header()?;
    validate_partial(&binding, &record.engagement_allocations)?;
    let declarations = S::engagement_reservations(record)?;
    let actual: Vec<_> = record
        .engagement_allocations
        .iter()
        .map(|reference| reference.reservation.clone())
        .collect();
    if actual != declarations && !(actual.is_empty() && S::view(record)?.stage == Stage::NotEntered)
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(())
}

pub(super) fn dependencies(
    references: &[AllocationRef],
) -> Vec<(GatewayRecordKind, GatewayAttemptKey)> {
    references
        .iter()
        .map(|reference| {
            (
                GatewayRecordKind::EffectAllocation,
                GatewayAttemptKey(slot_key(&reference.reservation.key, reference.slot)),
            )
        })
        .collect()
}

pub(super) fn validate_entry<S: JournalProtocol>(
    record: &Record<S>,
    claim: GatewayAttemptKey,
    snapshots: &[Option<Vec<u8>>],
) -> Result<(), GatewayAttemptError> {
    validate_record(record)?;
    if snapshots.len() != record.engagement_allocations.len() {
        return Err(GatewayAttemptError::Corrupt);
    }
    let binding = record.validate_header()?;
    for (reference, bytes) in record.engagement_allocations.iter().zip(snapshots) {
        let bytes = bytes.as_deref().ok_or(GatewayAttemptError::Corrupt)?;
        let row = decode_allocation(bytes, &reference.reservation, reference.slot)?;
        if digest(bytes)? != reference.commitment
            || row.claim != *claim.as_bytes()
            || row.effect != *binding.id().as_bytes()
            || row.reservation != reference.reservation
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
    }
    Ok(())
}

type AdmissionDecision<'a, S> =
    dyn FnMut(&mut Record<S>, &[Option<Vec<u8>>]) -> Result<(), GatewayAttemptError> + 'a;

/// Common all-or-none admission over operation, existing protocol slots and all
/// ancestor slots. Only vacancy collisions retry; errors/ambiguous acknowledgements
/// return immediately. The original first-row native decision runs under the same
/// fence and returns no permit. Existing entry indices stay unchanged for callers.
pub(super) fn insert<S: JournalProtocol>(
    store: &dyn GatewayAttemptStore,
    record: &mut Record<S>,
    entries: &[GatewayRecordEntry],
    dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
    decision: &mut AdmissionDecision<'_, S>,
) -> Result<GatewayInsert, GatewayAttemptError> {
    let first = entries.first().ok_or(GatewayAttemptError::Corrupt)?;
    if first.kind != GatewayRecordKind::Attempt
        || first.expires_at.is_some()
        || record.revision != 1
        || record.entry.is_some()
        || !record.engagement_allocations.is_empty()
    {
        return Err(GatewayAttemptError::InvalidTransition);
    }
    let binding = record.validate_header()?;
    let declarations = if S::view(record)?.stage == Stage::NotEntered {
        Vec::new()
    } else {
        S::engagement_reservations(record)?
    };
    for _ in 0..MAX_CLAIM_ROUNDS {
        let candidates = declarations
            .iter()
            .map(|declaration| {
                Candidate::new(store, declaration, first.key, *binding.id().as_bytes())
            })
            .collect::<Result<Vec<_>, _>>();
        let candidates = match candidates {
            Ok(candidates) => candidates,
            Err(error) => {
                // A concurrent identical claim may have consumed the last
                // ancestor unit after the caller's initial history lookup.
                // Delegate that winner to the existing exact-binding replay
                // owner rather than reporting its own reservation as exhausted.
                if store
                    .load(GatewayRecordKind::Attempt, &first.key)?
                    .is_some()
                {
                    record.engagement_allocations.clear();
                    return Ok(GatewayInsert::Exists { index: 0 });
                }
                return Err(error);
            }
        };
        record.engagement_allocations = candidates
            .iter()
            .map(Candidate::reference)
            .collect::<Result<Vec<_>, _>>()?;
        let mut batch = entries.to_vec();
        batch.extend(candidates.iter().map(Candidate::entry));
        let mut keys = dependencies.to_vec();
        let predecessor_indices = candidates
            .iter()
            .map(|candidate| {
                candidate.predecessor.as_ref().map(|(key, _)| {
                    acquisition::append_dependencies(
                        &mut keys,
                        &[(GatewayRecordKind::EffectAllocation, *key)],
                    )[0]
                })
            })
            .collect::<Vec<_>>();
        let result = store.fenced_insert_all(&batch, &keys, &mut |snapshots| {
            if snapshots.len() != keys.len() {
                return Err(GatewayAttemptError::Corrupt);
            }
            for (candidate, index) in candidates.iter().zip(&predecessor_indices) {
                if let (Some((_, expected)), Some(index)) = (&candidate.predecessor, index)
                    && snapshots[*index].as_deref() != Some(expected.as_slice())
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
            }
            decision(record, &snapshots[..dependencies.len()])?;
            validate_record(record)?;
            encode(record)
        })?;
        match result {
            GatewayInsert::Inserted => return Ok(result),
            GatewayInsert::Exists { index } if index < entries.len() => {
                // No row was inserted. Restore proposal state for outer protocol
                // counter contention handling before returning its original index.
                record.engagement_allocations.clear();
                return Ok(result);
            }
            GatewayInsert::Exists { index } => {
                let candidate = candidates
                    .get(index - entries.len())
                    .ok_or(GatewayAttemptError::Corrupt)?;
                let bytes = store
                    .load(GatewayRecordKind::EffectAllocation, &candidate.entry().key)?
                    .ok_or(GatewayAttemptError::Corrupt)?;
                decode_allocation(&bytes, &candidate.row.reservation, candidate.row.slot)?;
                record.engagement_allocations.clear();
            }
        }
    }
    Err(GatewayAttemptError::Conflict)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Allocation representation/arithmetic only, not an authority test. Native
    /// scoped information compilation must independently produce these units.
    #[test]
    fn byte_allocation_prefix_counts_zero_bytes_and_refuses_exhaustion_or_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileGatewayAttemptStore::open(directory.path()).unwrap();
        let mut limit = EngagementReservation {
            key: [0x91; 32],
            unit: Unit::DisclosureBytes,
            amount: 0,
            ceiling: 2,
        };
        let first =
            Candidate::new(&store, &limit, GatewayAttemptKey([0x11; 32]), [0x12; 32]).unwrap();
        assert_eq!(first.row.slot, 0);
        assert_eq!(first.row.cumulative, 0);
        store.insert_all(&[first.entry()]).unwrap();
        limit.amount = 2;
        let second =
            Candidate::new(&store, &limit, GatewayAttemptKey([0x21; 32]), [0x22; 32]).unwrap();
        assert_eq!(second.row.slot, 1);
        assert_eq!(second.row.cumulative, 2);
        store.insert_all(&[second.entry()]).unwrap();
        limit.amount = 1;
        assert!(Candidate::new(&store, &limit, GatewayAttemptKey([0x31; 32]), [0x32; 32]).is_err());
        let mut row: serde_json::Value = serde_json::from_slice(&second.bytes).unwrap();
        row["reservation"]["unit"] = serde_json::json!("mutation-count");
        assert!(decode_allocation(&serde_json::to_vec(&row).unwrap(), &limit, 1).is_err());
        limit.ceiling = 0;
        limit.amount = 0;
        assert!(
            Candidate::new(&store, &limit, GatewayAttemptKey([0x31; 32]), [0x32; 32]).is_err(),
            "another ceiling cannot reuse this counter prefix"
        );
        limit.key = [0x92; 32];
        assert_eq!(
            Candidate::new(&store, &limit, GatewayAttemptKey([0x31; 32]), [0x32; 32])
                .unwrap()
                .row
                .cumulative,
            0
        );
    }
}
