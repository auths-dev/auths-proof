//! Independent pre-refactor sorting/validation oracle; test-only.
use super::*;
use alloc::format;

fn reference(mut anchors: Vec<TrustAnchorId>) -> Result<Vec<TrustAnchorId>, ModelError> {
    anchors.sort();
    if anchors.is_empty()
        || anchors.len() > HARD_MAX_TRUST_ANCHORS
        || anchors.windows(2).any(|window| window[0] == window[1])
    {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    Ok(anchors)
}

fn next_word(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn scope_constructor_matches_reference_for_validated_ids() {
    let mut admitted = 0;
    let mut refused = 0;
    for seed in [1_u64, 17, 42, 0x1234_5678] {
        let mut state = seed;
        for case in 0..1_500 {
            let length = match case % 149 {
                0 => HARD_MAX_TRUST_ANCHORS - 1,
                1 => HARD_MAX_TRUST_ANCHORS,
                2 => HARD_MAX_TRUST_ANCHORS + 1,
                3 => HARD_MAX_TRUST_ANCHORS * 2,
                _ => usize::try_from(next_word(&mut state) % 65).unwrap(),
            };
            let mut anchors: Vec<_> = (0..length)
                .map(|index| TrustAnchorId::parse(&format!("anchor:{index:04}")).unwrap())
                .collect();
            for index in (1..length).rev() {
                let selected =
                    usize::try_from(next_word(&mut state) % u64::try_from(index + 1).unwrap())
                        .unwrap();
                anchors.swap(index, selected);
            }
            if case % 4 == 0 && length > 1 {
                anchors[length - 1] = anchors[0].clone();
            }
            let expected = reference(anchors.clone());
            let actual = StatusScopeAnchors::new(anchors).map(|value| value.ids().to_vec());
            assert_eq!(
                actual, expected,
                "seed {seed}, case {case}, length {length}"
            );
            match actual {
                Ok(ids) => {
                    admitted += 1;
                    assert!(!ids.is_empty() && ids.len() <= HARD_MAX_TRUST_ANCHORS);
                    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
                }
                Err(ModelError::InvalidStatusSnapshot) => refused += 1,
                Err(other) => panic!("unexpected constructor result: {other:?}"),
            }
        }
    }
    assert!(admitted > 3_000 && refused > 1_000);
}
