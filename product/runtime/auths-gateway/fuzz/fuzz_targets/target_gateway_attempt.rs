//! Attempt records: decoding and snapshots never panic, and the store's
//! transition rule agrees with the record table on any two records: the
//! stage change is one the table lists, terminal stages never change, and
//! the fixed fields stay.
//!
//! Input: a four-byte big-endian length, the old record, then the new one.

#![no_main]

use auths_gateway::{GatewayAttemptStage as Stage, fuzzing};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fn split(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = usize::try_from(u32::from_be_bytes(data.get(..4)?.try_into().ok()?)).ok()?;
    let end = 4_usize.checked_add(length)?;
    Some((data.get(4..end)?, data.get(end..)?))
}

/// The record table's stage changes, ignoring the link condition on the
/// two `observed-by-provider` rows, which the kernel harness checks.
const fn listed(from: Stage, to: Stage) -> bool {
    matches!(
        (from, to),
        (
            Stage::Attempting,
            Stage::Attempting
                | Stage::NotEntered
                | Stage::Unknown
                | Stage::ResponseRecorded
                | Stage::ObservedByProvider
        ) | (Stage::Unknown, Stage::ObservedByProvider)
            | (
                Stage::ResponseRecorded,
                Stage::Observed | Stage::ObservedByProvider
            )
    )
}

const FIXED: [&str; 8] = [
    "schema",
    "namespace",
    "operation_id",
    "action_commitment",
    "recipe_digest",
    "nonce",
    "evaluated_at",
    "counters",
];

fuzz_target!(|data: &[u8]| {
    let Some((old, new)) = split(data) else {
        let _ = fuzzing::attempt_stage(data);
        return;
    };
    let old_stage = fuzzing::attempt_stage(old);
    let new_stage = fuzzing::attempt_stage(new);
    if fuzzing::attempt_transition(old, new) != Some(true) {
        return;
    }
    let (Some(from), Some(to)) = (old_stage, new_stage) else {
        panic!("a valid transition has two valid records");
    };
    assert!(listed(from, to), "{from:?} -> {to:?}");
    let (Ok(old), Ok(new)) = (
        serde_json::from_slice::<Value>(old),
        serde_json::from_slice::<Value>(new),
    ) else {
        panic!("valid records are JSON");
    };
    for field in FIXED {
        assert_eq!(old.get(field), new.get(field), "{field} changed");
    }
});
