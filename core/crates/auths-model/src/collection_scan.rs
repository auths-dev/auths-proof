//! Bounded collection-constructor scans with explicit indices and stop rules.
//!
//! Sorting stays with the pinned standard library. Adjacent scans are used
//! only after the caller's canonical sort; order-preserving collections use
//! the complete prefix scan instead. No scan allocates or changes its input.

use crate::{CriticalExtension, EvidenceObject, ObservationFact};

pub(crate) fn adjacent_equal<T: PartialEq>(values: &[T]) -> bool {
    let mut position = 1;
    let mut matched = false;
    while position < values.len() && !matched {
        matched = values[position - 1] == values[position];
        position += 1;
    }
    matched
}

pub(crate) fn prefix_contains<T: PartialEq>(values: &[T], target: &T, end: usize) -> bool {
    let stop = if end > values.len() {
        values.len()
    } else {
        end
    };
    let mut position = 0;
    let mut matched = false;
    while position < stop && !matched {
        matched = values[position] == *target;
        position += 1;
    }
    matched
}

pub(crate) fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    let mut position = 0;
    let mut matched = false;
    while position < values.len() && !matched {
        matched = prefix_contains(values, &values[position], position);
        position += 1;
    }
    matched
}

pub(crate) fn extension_ids_repeat(values: &[CriticalExtension]) -> bool {
    let mut position = 1;
    let mut matched = false;
    while position < values.len() && !matched {
        matched = values[position - 1].id() == values[position].id();
        position += 1;
    }
    matched
}

pub(crate) fn fact_names_repeat(values: &[ObservationFact]) -> bool {
    let mut position = 1;
    let mut matched = false;
    while position < values.len() && !matched {
        matched = values[position - 1].name() == values[position].name();
        position += 1;
    }
    matched
}

pub(crate) fn evidence_ids_repeat(values: &[EvidenceObject]) -> bool {
    let mut position = 1;
    let mut matched = false;
    while position < values.len() && !matched {
        matched = values[position - 1].id() == values[position].id();
        position += 1;
    }
    matched
}
