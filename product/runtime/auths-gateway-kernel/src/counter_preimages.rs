//! Exact bounded-counter and slot commitment preimages. Hashing is performed
//! by the runtime with its existing SHA-256 primitive.
use crate::construct::{append_bytes, copy_bytes};
use alloc::vec::Vec;

fn append_word(output: Vec<u8>, value: u64) -> Vec<u8> {
    append_bytes(output, &value.to_be_bytes())
}

fn append_component(output: Vec<u8>, value: &[u8]) -> Vec<u8> {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    let output = append_word(output, length);
    append_bytes(output, value)
}

fn append_coordinates(output: Vec<u8>, window: u64, index: u64) -> Vec<u8> {
    let output = append_word(output, window);
    append_word(output, index)
}

/// Exact count-counter framing: domain, length-prefixed namespace, subject
/// and evaluator, followed by the fixed-width window length and index.
/// The runtime supplies constructor-validated namespace/principal/evaluator
/// bytes. Input components are never normalized or treated as delimiters.
#[must_use]
pub fn count_counter_preimage(
    namespace: &[u8],
    subject: &[u8],
    evaluator: &[u8],
    window: u64,
    index: u64,
) -> Vec<u8> {
    let output = copy_bytes(b"auths.gateway-bounded-count/2\0");
    let output = append_component(output, namespace);
    let output = append_component(output, subject);
    let output = append_component(output, evaluator);
    append_coordinates(output, window, index)
}

/// Exact sum-counter framing, adding the length-prefixed partition after
/// the evaluator. An unpartitioned counter supplies an empty partition.
#[must_use]
pub fn sum_counter_preimage(
    namespace: &[u8],
    subject: &[u8],
    evaluator: &[u8],
    partition: &[u8],
    window: u64,
    index: u64,
) -> Vec<u8> {
    let output = copy_bytes(b"auths.gateway-bounded-sum/1\0");
    let output = append_component(output, namespace);
    let output = append_component(output, subject);
    let output = append_component(output, evaluator);
    let output = append_component(output, partition);
    append_coordinates(output, window, index)
}

fn slot_preimage(domain: &[u8], counter: &[u8; 32], slot: u64) -> Vec<u8> {
    let output = append_bytes(copy_bytes(domain), counter);
    append_word(output, slot)
}

/// Count-slot domain followed by the exact 32-byte counter ID and an
/// eight-byte big-endian slot number. No claim/actor/process input is added.
#[must_use]
pub fn count_slot_preimage(counter: &[u8; 32], slot: u64) -> Vec<u8> {
    slot_preimage(b"auths.gateway-bounded-count-slot/2\0", counter, slot)
}

/// Sum-slot domain followed by the exact 32-byte counter ID and an
/// eight-byte big-endian slot number. No claim/actor/process input is added.
#[must_use]
pub fn sum_slot_preimage(counter: &[u8; 32], slot: u64) -> Vec<u8> {
    slot_preimage(b"auths.gateway-bounded-sum-slot/1\0", counter, slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent frozen framing; deliberately uses the former iterator form.
    fn original_counter(domain: &[u8], components: &[&[u8]], window: u64, index: u64) -> Vec<u8> {
        let mut bytes = Vec::from(domain);
        for component in components {
            bytes.extend_from_slice(
                &u64::try_from(component.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(component);
        }
        bytes.extend_from_slice(&window.to_be_bytes());
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes
    }

    #[test]
    fn component_lengths_order_and_full_width_words_match_previous_framing() {
        let parts: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"bc",
            b"raw:subject",
            b"contains\0separator",
            "unicode-λ".as_bytes(),
        ];
        for namespace in parts {
            for subject in parts {
                for partition in parts {
                    for value in [0, 1, 255, 256, u64::MAX] {
                        let evaluator = b"auths.gateway.argument-ceiling-window-count/2";
                        assert_eq!(
                            count_counter_preimage(namespace, subject, evaluator, value, value),
                            original_counter(
                                b"auths.gateway-bounded-count/2\0",
                                &[namespace, subject, evaluator],
                                value,
                                value
                            )
                        );
                        assert_eq!(
                            sum_counter_preimage(
                                namespace, subject, evaluator, partition, value, value
                            ),
                            original_counter(
                                b"auths.gateway-bounded-sum/1\0",
                                &[namespace, subject, evaluator, partition],
                                value,
                                value
                            )
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn domain_and_component_boundaries_are_visible() {
        assert_ne!(
            count_counter_preimage(b"a", b"bc", b"e", 60, 1),
            count_counter_preimage(b"ab", b"c", b"e", 60, 1)
        );
        assert_ne!(
            count_counter_preimage(b"a", b"b", b"e", 60, 1),
            sum_counter_preimage(b"a", b"b", b"e", b"", 60, 1)
        );
        for counter in [[0; 32], [255; 32]] {
            for slot in [0, 1, 255, 256, u64::MAX] {
                for (prefix, output) in [
                    (
                        b"auths.gateway-bounded-count-slot/2\0".as_slice(),
                        count_slot_preimage(&counter, slot),
                    ),
                    (
                        b"auths.gateway-bounded-sum-slot/1\0".as_slice(),
                        sum_slot_preimage(&counter, slot),
                    ),
                ] {
                    let mut original = Vec::from(prefix);
                    original.extend_from_slice(&counter);
                    original.extend_from_slice(&slot.to_be_bytes());
                    assert_eq!(output, original);
                }
            }
        }
    }
}
