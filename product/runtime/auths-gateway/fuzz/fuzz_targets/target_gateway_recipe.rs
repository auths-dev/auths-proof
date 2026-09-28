//! Recipe compilation: `compile` never panics; an accepted source's digest
//! equals the digest of its canonical re-serialization; review and the
//! recovery capability are total.
//!
//! Input: a four-byte big-endian source length, the source, then the
//! profile lock.

#![no_main]

use auths_gateway::CompiledRecipe;
use libfuzzer_sys::fuzz_target;

const MAX_SOURCE_BYTES: usize = 65_536;

fn split(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = usize::try_from(u32::from_be_bytes(data.get(..4)?.try_into().ok()?)).ok()?;
    let end = 4_usize.checked_add(length)?;
    Some((data.get(4..end)?, data.get(end..)?))
}

fuzz_target!(|data: &[u8]| {
    let Some((source, lock)) = split(data) else {
        return;
    };
    let Ok(recipe) = CompiledRecipe::compile(source, lock) else {
        return;
    };
    let review = recipe.review();
    let _ = recipe.review_document();
    assert_eq!(review.recovery(), recipe.recovery());
    assert!(!recipe.recovery().write_is_conditional);
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(source) else {
        panic!("an accepted source is JSON");
    };
    let Ok(canonical) = serde_json_canonicalizer::to_vec(&value) else {
        panic!("accepted JSON has a canonical form");
    };
    if canonical.len() <= MAX_SOURCE_BYTES {
        let Ok(again) = CompiledRecipe::compile(&canonical, lock) else {
            panic!("the canonical form of an accepted source compiles");
        };
        assert_eq!(again.digest_hex(), recipe.digest_hex());
    }
});
