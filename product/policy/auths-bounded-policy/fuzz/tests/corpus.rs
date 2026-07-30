use std::{fs, path::PathBuf};

#[test]
fn seventeen_byte_boundary_seed_is_pinned() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus/target_bounded_policy/17-byte-boundary-seed");
    let seed = fs::read(path).expect("the exact regression seed must remain in the corpus");
    assert_eq!(seed.len(), 17);
    assert!(seed.iter().any(|byte| *byte != 0));
}
