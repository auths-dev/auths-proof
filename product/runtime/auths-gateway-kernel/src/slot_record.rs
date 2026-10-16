//! Validation of the decoded sum-slot projection. JSON parsing remains at the
//! storage boundary; this function binds the decoded record to the exact slot.
use crate::construct::{field_name_equal, hex_lower};

/// Numeric fields of a decoded sum-slot record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SumValues {
    /// Slot number recorded in the payload.
    pub slot: u64,
    /// Delta recorded in this slot.
    pub amount: u64,
    /// Cumulative sum recorded after this delta.
    pub cumulative: u64,
}

/// Exact lowercase hexadecimal identity of a public 32-byte counter ID.
#[must_use]
pub fn counter_hex_matches(stored: &[u8], counter: &[u8; 32]) -> bool {
    if stored.len() != 64 {
        return false;
    }
    let mut index = 0;
    while index < 32 {
        let byte = counter[index];
        if stored[index * 2] != hex_lower(byte / 16)
            || stored[index * 2 + 1] != hex_lower(byte % 16)
        {
            return false;
        }
        index += 1;
    }
    true
}

/// Accepts only the exact sum-slot schema, lowercase counter ID, requested
/// slot and a cumulative value at least as large as its recorded delta.
/// This checks the decoded projection; storage integrity and JSON correctness
/// are separate boundaries.
#[must_use]
pub fn validate_cumulative(
    schema: &[u8],
    expected_schema: &[u8],
    counter_hex: &[u8],
    counter: &[u8; 32],
    expected_slot: u64,
    values: SumValues,
) -> Option<u64> {
    if !field_name_equal(schema, expected_schema)
        || !counter_hex_matches(counter_hex, counter)
        || values.slot != expected_slot
        || values.amount > values.cumulative
    {
        return None;
    }
    Some(values.cumulative)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(counter: &[u8; 32]) -> alloc::vec::Vec<u8> {
        use core::fmt::Write as _;
        let mut encoded = alloc::string::String::with_capacity(64);
        for byte in counter {
            write!(encoded, "{byte:02x}").expect("writing to a String");
        }
        encoded.into_bytes()
    }

    #[test]
    fn public_counter_binding_matches_canonical_hex_on_all_byte_values() {
        for value in 0..=u8::MAX {
            let counter = [value; 32];
            let canonical = encoded(&counter);
            assert!(counter_hex_matches(&canonical, &counter));
            assert!(!counter_hex_matches(&canonical[..63], &counter));
            let mut extended = canonical.clone();
            extended.push(b'0');
            assert!(!counter_hex_matches(&extended, &counter));
            for index in 0..64 {
                let mut changed = canonical.clone();
                changed[index] ^= 1;
                assert!(!counter_hex_matches(&changed, &counter));
            }
            let uppercase: alloc::vec::Vec<_> =
                canonical.iter().map(u8::to_ascii_uppercase).collect();
            assert_eq!(
                counter_hex_matches(&uppercase, &counter),
                uppercase == canonical
            );
        }
    }

    #[test]
    fn complete_decoded_gate_preserves_the_previous_acceptance_rule() {
        let counter = [42; 32];
        let canonical = encoded(&counter);
        let schema = b"auths.gateway-bounded-sum/1";
        for recorded_schema in [schema.as_slice(), b"wrong".as_slice()] {
            for stored_hex in [canonical.as_slice(), b"not-a-counter".as_slice()] {
                for stored_slot in [0, 1, u64::MAX] {
                    for expected_slot in [0, 1, u64::MAX] {
                        for amount in [0, 1, u64::MAX] {
                            for cumulative in [0, 1, u64::MAX] {
                                let expected = (recorded_schema == schema
                                    && stored_hex == canonical
                                    && stored_slot == expected_slot
                                    && amount <= cumulative)
                                    .then_some(cumulative);
                                assert_eq!(
                                    validate_cumulative(
                                        recorded_schema,
                                        schema,
                                        stored_hex,
                                        &counter,
                                        expected_slot,
                                        SumValues {
                                            slot: stored_slot,
                                            amount,
                                            cumulative
                                        }
                                    ),
                                    expected
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
