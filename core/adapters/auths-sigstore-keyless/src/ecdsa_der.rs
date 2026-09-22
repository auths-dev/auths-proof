//! Encoding conversion for P-256 ECDSA signatures produced by Sigstore.
//!
//! Rekor signs its Signed Entry Timestamps and checkpoint notes, and records
//! artifact signatures, as DER `ECDSA-Sig-Value` structures whose `s` may lie
//! in either half of the group order. The bound signature suite accepts only
//! the fixed-width low-S form, so the adapter converts before calling it.
//!
//! This is encoding, not cryptography: nothing here verifies a signature.
//! The conversion is strict — exactly one DER encoding of each `(r, s)` is
//! accepted — and the only arithmetic is `s -> n - s` against the group
//! order, which maps a signature to the other member of its malleability
//! pair. Every converted signature is still verified by the suite.

/// Identifier of the kernel suite whose signatures need this conversion.
pub const P256_SHA256_SUITE: &str = "p256-sha256-v1";

/// Width of one P-256 scalar in bytes.
const SCALAR_BYTES: usize = 32;

/// The P-256 group order `n`, big-endian.
const ORDER: [u8; SCALAR_BYTES] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `floor(n / 2)`, big-endian: the largest low-S value.
const HALF_ORDER: [u8; SCALAR_BYTES] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Why a DER signature was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerSignatureError {
    /// The bytes are not exactly one canonical DER `ECDSA-Sig-Value`.
    Encoding,
    /// `r` or `s` is zero or not below the group order.
    Range,
}

/// Converts one strict-DER P-256 `ECDSA-Sig-Value` to fixed-width `r || s`
/// with `s` in the lower half of the group order.
///
/// # Errors
///
/// Returns [`DerSignatureError::Encoding`] for anything but the unique DER
/// encoding of two positive integers (BER lengths, leading zero padding,
/// negative values, trailing bytes), and [`DerSignatureError::Range`] when
/// either integer is zero or not below the group order.
pub fn low_s_fixed(der: &[u8]) -> Result<[u8; 64], DerSignatureError> {
    let content = element(der, 0x30)?;
    if content.len() + 2 != der.len() {
        return Err(DerSignatureError::Encoding);
    }
    let r_field = element(content, 0x02)?;
    let rest = &content[r_field.len() + 2..];
    let s_field = element(rest, 0x02)?;
    if s_field.len() + 2 != rest.len() {
        return Err(DerSignatureError::Encoding);
    }
    let r = scalar(r_field)?;
    let mut s = scalar(s_field)?;
    if greater(&s, &HALF_ORDER) {
        s = order_minus(&s);
    }
    let mut output = [0_u8; 64];
    output[..SCALAR_BYTES].copy_from_slice(&r);
    output[SCALAR_BYTES..].copy_from_slice(&s);
    Ok(output)
}

/// Returns the content of the short-form DER element at the start of
/// `bytes`. Every element here is below 128 bytes, so a long-form length is
/// a non-minimal encoding and is rejected.
fn element(bytes: &[u8], tag: u8) -> Result<&[u8], DerSignatureError> {
    match bytes {
        [found, length, rest @ ..] if *found == tag && *length < 0x80 => rest
            .get(..usize::from(*length))
            .ok_or(DerSignatureError::Encoding),
        _ => Err(DerSignatureError::Encoding),
    }
}

/// Decodes one minimal positive DER INTEGER into a scalar in `[1, n)`.
fn scalar(content: &[u8]) -> Result<[u8; SCALAR_BYTES], DerSignatureError> {
    let magnitude = match content {
        [] => return Err(DerSignatureError::Encoding),
        [first, ..] if first & 0x80 != 0 => return Err(DerSignatureError::Encoding),
        [0, next, ..] if next & 0x80 == 0 => return Err(DerSignatureError::Encoding),
        [0, rest @ ..] if !rest.is_empty() => rest,
        _ => content,
    };
    if magnitude.len() > SCALAR_BYTES {
        return Err(DerSignatureError::Range);
    }
    let mut value = [0_u8; SCALAR_BYTES];
    value[SCALAR_BYTES - magnitude.len()..].copy_from_slice(magnitude);
    if value.iter().all(|byte| *byte == 0) || !greater(&ORDER, &value) {
        return Err(DerSignatureError::Range);
    }
    Ok(value)
}

/// Whether `left > right` as big-endian unsigned integers.
fn greater(left: &[u8; SCALAR_BYTES], right: &[u8; SCALAR_BYTES]) -> bool {
    left > right
}

/// `n - value` for `0 < value < n`.
fn order_minus(value: &[u8; SCALAR_BYTES]) -> [u8; SCALAR_BYTES] {
    let mut output = [0_u8; SCALAR_BYTES];
    let mut borrow = 0_u16;
    for index in (0..SCALAR_BYTES).rev() {
        let minuend = u16::from(ORDER[index]);
        let subtrahend = u16::from(value[index]) + borrow;
        let (difference, next) = if minuend >= subtrahend {
            (minuend - subtrahend, 0)
        } else {
            (minuend + 0x100 - subtrahend, 1)
        };
        output[index] = u8::try_from(difference).unwrap_or(u8::MAX);
        borrow = next;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(r: &[u8], s: &[u8]) -> alloc::vec::Vec<u8> {
        let mut body = alloc::vec![0x02, u8::try_from(r.len()).unwrap()];
        body.extend_from_slice(r);
        body.extend_from_slice(&[0x02, u8::try_from(s.len()).unwrap()]);
        body.extend_from_slice(s);
        let mut out = alloc::vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend(body);
        out
    }

    #[test]
    fn low_s_values_pass_through_and_high_s_values_fold_to_their_pair() {
        let fixed = low_s_fixed(&der(&[1], &[2])).unwrap();
        assert_eq!(fixed[31], 1);
        assert_eq!(fixed[63], 2);
        let mut high = alloc::vec![0];
        high.extend_from_slice(&order_minus(&{
            let mut two = [0; 32];
            two[31] = 2;
            two
        }));
        let folded = low_s_fixed(&der(&[1], &high)).unwrap();
        assert_eq!(folded[63], 2);
        assert!(folded[32..63].iter().all(|b| *b == 0));
        let mut half = alloc::vec![];
        half.extend_from_slice(&HALF_ORDER);
        assert_eq!(&low_s_fixed(&der(&[1], &half)).unwrap()[32..], &HALF_ORDER);
    }

    #[test]
    fn only_the_unique_der_encoding_of_an_in_range_pair_is_accepted() {
        let mut order = alloc::vec![0];
        order.extend_from_slice(&ORDER);
        let rejected = [
            der(&[0], &[1]),
            der(&[1], &order),
            der(&[0, 1], &[1]),
            der(&[0x80], &[1]),
            der(&[], &[1]),
            alloc::vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            alloc::vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            alloc::vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            alloc::vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            alloc::vec![],
        ];
        for bytes in rejected {
            assert!(low_s_fixed(&bytes).is_err(), "accepted {bytes:02x?}");
        }
    }
}
