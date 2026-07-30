#![no_main]

use auths_bounded_policy::{
    BasisPoints, CanonicalizationId, PolicyTypeId, RoundingDirection, UnitId, checked_basis_points,
    kernel::{
        checked_add_u64, checked_div_u64, checked_mul_u64, checked_sub_u64,
        configuration_match_code,
    },
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let semantic = data.first().is_some_and(|byte| byte & 1 != 0);
    let canonicalization = data.get(1).is_some_and(|byte| byte & 1 != 0);
    let digest = data.get(2).is_some_and(|byte| byte & 1 != 0);
    let implementation = data.get(3).is_some_and(|byte| byte & 1 != 0);
    let _ = configuration_match_code(semantic, canonicalization, digest, implementation);

    let mut left_bytes = [0_u8; 8];
    let mut right_bytes = [0_u8; 8];
    let left_source = data.get(4..12).unwrap_or_default();
    let right_source = data.get(12..20).unwrap_or_default();
    left_bytes[..left_source.len()].copy_from_slice(left_source);
    right_bytes[..right_source.len()].copy_from_slice(right_source);
    let left = u64::from_le_bytes(left_bytes);
    let right = u64::from_le_bytes(right_bytes);
    let _ = checked_add_u64(left, right);
    let _ = checked_sub_u64(left, right);
    let _ = checked_mul_u64(left, right);
    let _ = checked_div_u64(left, right);
    let points = u16::from(data.get(20).copied().unwrap_or_default()) * 39;
    if let Ok(points) = BasisPoints::new(points) {
        let _ = checked_basis_points(left, points, RoundingDirection::Down);
        let _ = checked_basis_points(left, points, RoundingDirection::Up);
    }

    if let Ok(text) = core::str::from_utf8(data) {
        let _ = PolicyTypeId::parse(text);
        let _ = CanonicalizationId::parse(text);
        let _ = UnitId::parse(text);
    }
});
