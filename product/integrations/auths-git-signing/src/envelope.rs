//! The armored envelope stored in a Git object's signature slot.
//!
//! ```text
//! -----BEGIN SIGNED MESSAGE-----
//! <standard padded base64 of the frame, 64 characters per line>
//! -----END SIGNED MESSAGE-----
//!
//! frame = "AUTHS-GIT-SIGNATURE/1\n"
//!         || u32be(len(proof)) || proof
//!         || u32be(len(action)) || action
//! ```
//!
//! The armor marker is the one Git associates with `gpg.format = x509`, so Git
//! routes the signature to the configured program. The frame carries explicit
//! lengths so splitting it never depends on decoding CBOR.
//!
//! Decoding accepts exactly one byte string per envelope: fixed line width,
//! `\n` line endings only, canonical base64, and no trailing data. Every bound
//! is checked before the next allocation.

use base64ct::{Base64, Encoding as _};
use thiserror::Error;

/// First armor line; the marker Git maps to the x509 signature format.
pub const ARMOR_BEGIN: &str = "-----BEGIN SIGNED MESSAGE-----";
/// Last armor line.
pub const ARMOR_END: &str = "-----END SIGNED MESSAGE-----";
/// Domain-separating prefix of the decoded frame.
pub const FRAME_MAGIC: &[u8] = b"AUTHS-GIT-SIGNATURE/1\n";
/// Maximum armored envelope size in bytes.
pub const MAX_ARMORED_BYTES: usize = 200 * 1024;
/// Maximum proof size in bytes.
pub const MAX_PROOF_BYTES: usize = 128 * 1024;
/// Maximum canonical action size in bytes.
pub const MAX_ACTION_BYTES: usize = 16 * 1024;
/// Base64 characters per armored line.
pub const LINE_WIDTH: usize = 64;

/// Proof and canonical action bytes carried by one Git signature.
///
/// Construction checks only the size bounds. Neither field has been verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSignatureEnvelope {
    proof: Vec<u8>,
    action: Vec<u8>,
}

/// Why envelope bytes were rejected. [`EnvelopeError::code`] returns the stable
/// result code.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnvelopeError {
    /// The armored input or a frame field exceeds its limit.
    #[error("git signature envelope exceeds its size limit")]
    TooLarge,
    /// The input is not armored as an Auths Git signature.
    #[error("signature is not an Auths git signature envelope")]
    NotAuthsEnvelope,
    /// The armor, base64, or frame is malformed or non-canonical.
    #[error("malformed git signature envelope")]
    Malformed,
}

impl EnvelopeError {
    /// Returns the stable result code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "git.envelope-too-large",
            Self::NotAuthsEnvelope => "git.not-auths-envelope",
            Self::Malformed => "git.envelope-malformed",
        }
    }
}

impl GitSignatureEnvelope {
    /// Wraps proof and canonical action bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::Malformed`] for an empty field and
    /// [`EnvelopeError::TooLarge`] when a field exceeds its limit.
    pub fn new(proof: Vec<u8>, action: Vec<u8>) -> Result<Self, EnvelopeError> {
        if proof.is_empty() || action.is_empty() {
            return Err(EnvelopeError::Malformed);
        }
        if proof.len() > MAX_PROOF_BYTES || action.len() > MAX_ACTION_BYTES {
            return Err(EnvelopeError::TooLarge);
        }
        Ok(Self { proof, action })
    }

    /// Returns the unverified proof bytes.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the unverified canonical action bytes.
    #[must_use]
    pub fn action(&self) -> &[u8] {
        &self.action
    }

    /// Encodes the canonical armored form, ending in one `\n`.
    #[must_use]
    pub fn to_armored(&self) -> String {
        let mut frame =
            Vec::with_capacity(FRAME_MAGIC.len() + 8 + self.proof.len() + self.action.len());
        frame.extend_from_slice(FRAME_MAGIC);
        push_field(&mut frame, &self.proof);
        push_field(&mut frame, &self.action);
        let encoded = Base64::encode_string(&frame);
        let mut armored = String::with_capacity(encoded.len() + encoded.len() / LINE_WIDTH + 64);
        armored.push_str(ARMOR_BEGIN);
        armored.push('\n');
        for line in encoded.as_bytes().chunks(LINE_WIDTH) {
            // INVARIANT: base64 output is ASCII, so every chunk is valid UTF-8.
            armored.extend(line.iter().map(|byte| char::from(*byte)));
            armored.push('\n');
        }
        armored.push_str(ARMOR_END);
        armored.push('\n');
        armored
    }

    /// Decodes an armored envelope, accepting only the canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::TooLarge`] before any decoding when the input
    /// exceeds [`MAX_ARMORED_BYTES`], [`EnvelopeError::NotAuthsEnvelope`] when
    /// the armor or frame prefix is absent, and [`EnvelopeError::Malformed`]
    /// for any other deviation from the canonical form.
    pub fn from_armored(input: &[u8]) -> Result<Self, EnvelopeError> {
        if input.len() > MAX_ARMORED_BYTES {
            return Err(EnvelopeError::TooLarge);
        }
        let body = input
            .strip_prefix(ARMOR_BEGIN.as_bytes())
            .and_then(|rest| rest.strip_prefix(b"\n"))
            .ok_or(EnvelopeError::NotAuthsEnvelope)?;
        let body = body
            .strip_suffix(b"\n")
            .and_then(|rest| rest.strip_suffix(ARMOR_END.as_bytes()))
            .and_then(|rest| rest.strip_suffix(b"\n"))
            .ok_or(EnvelopeError::Malformed)?;

        let lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').collect();
        let (last, full) = lines.split_last().ok_or(EnvelopeError::Malformed)?;
        if last.is_empty()
            || last.len() > LINE_WIDTH
            || full.iter().any(|line| line.len() != LINE_WIDTH)
        {
            return Err(EnvelopeError::Malformed);
        }
        let mut encoded = Vec::with_capacity(body.len());
        for line in &lines {
            encoded.extend_from_slice(line);
        }
        let frame = Base64::decode_vec(
            core::str::from_utf8(&encoded).map_err(|_| EnvelopeError::Malformed)?,
        )
        .map_err(|_| EnvelopeError::Malformed)?;
        if Base64::encode_string(&frame).as_bytes() != encoded.as_slice() {
            return Err(EnvelopeError::Malformed);
        }

        let rest = frame
            .strip_prefix(FRAME_MAGIC)
            .ok_or(EnvelopeError::NotAuthsEnvelope)?;
        let (proof, rest) = take_field(rest, MAX_PROOF_BYTES)?;
        let (action, rest) = take_field(rest, MAX_ACTION_BYTES)?;
        if !rest.is_empty() {
            return Err(EnvelopeError::Malformed);
        }
        Self::new(proof.to_vec(), action.to_vec())
    }
}

fn push_field(frame: &mut Vec<u8>, field: &[u8]) {
    // INVARIANT: `new` bounds every field far below `u32::MAX`.
    #[allow(clippy::cast_possible_truncation)]
    let length = field.len() as u32;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(field);
}

fn take_field(input: &[u8], limit: usize) -> Result<(&[u8], &[u8]), EnvelopeError> {
    let (length, rest) = input
        .split_first_chunk::<4>()
        .ok_or(EnvelopeError::Malformed)?;
    let length =
        usize::try_from(u32::from_be_bytes(*length)).map_err(|_| EnvelopeError::TooLarge)?;
    if length > limit {
        return Err(EnvelopeError::TooLarge);
    }
    if length > rest.len() {
        return Err(EnvelopeError::Malformed);
    }
    Ok(rest.split_at(length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> GitSignatureEnvelope {
        GitSignatureEnvelope::new(vec![0xa1; 150], vec![0xb2; 40]).expect("sample")
    }

    fn frame(proof: &[u8], action: &[u8]) -> Vec<u8> {
        let mut frame = FRAME_MAGIC.to_vec();
        push_field(&mut frame, proof);
        push_field(&mut frame, action);
        frame
    }

    fn armor_frame(frame: &[u8]) -> Vec<u8> {
        let encoded = Base64::encode_string(frame);
        let mut armored = format!("{ARMOR_BEGIN}\n");
        for line in encoded.as_bytes().chunks(LINE_WIDTH) {
            armored.push_str(core::str::from_utf8(line).expect("ascii"));
            armored.push('\n');
        }
        armored.push_str(ARMOR_END);
        armored.push('\n');
        armored.into_bytes()
    }

    #[test]
    fn envelope_round_trips_canonically() {
        let envelope = sample();
        let armored = envelope.to_armored();
        assert!(armored.starts_with("-----BEGIN SIGNED MESSAGE-----\n"));
        assert!(armored.ends_with("\n-----END SIGNED MESSAGE-----\n"));
        let decoded = GitSignatureEnvelope::from_armored(armored.as_bytes()).expect("decode");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.to_armored(), armored);
    }

    #[test]
    fn envelope_rejects_noncanonical_armor_with_stable_codes() {
        let armored = sample().to_armored();
        let cases: [(&str, Vec<u8>, &str); 9] = [
            (
                "crlf",
                armored.replace('\n', "\r\n").into_bytes(),
                "git.not-auths-envelope",
            ),
            (
                "pgp armor",
                armored
                    .replace("SIGNED MESSAGE", "PGP SIGNATURE")
                    .into_bytes(),
                "git.not-auths-envelope",
            ),
            (
                "missing final newline",
                armored.trim_end().as_bytes().to_vec(),
                "git.envelope-malformed",
            ),
            (
                "extra final newline",
                format!("{armored}\n").into_bytes(),
                "git.envelope-malformed",
            ),
            (
                "leading space",
                format!(" {armored}").into_bytes(),
                "git.not-auths-envelope",
            ),
            (
                "short interior line",
                armored
                    .replacen('\n', "\nA\n", 2)
                    .replacen("\nA\n", "\n", 1)
                    .into_bytes(),
                "git.envelope-malformed",
            ),
            (
                "indented line",
                armored
                    .replacen("\n", "\n ", 2)
                    .replacen("\n ", "\n", 1)
                    .into_bytes(),
                "git.envelope-malformed",
            ),
            (
                "trailing frame byte",
                armor_frame(&[frame(&[1], &[2]), vec![0]].concat()),
                "git.envelope-malformed",
            ),
            (
                "wrong magic",
                armor_frame(b"AUTHS-GIT-SIGNATURE/2\n\0\0\0\x01\x01\0\0\0\x01\x02"),
                "git.not-auths-envelope",
            ),
        ];
        for (name, input, code) in cases {
            let error = GitSignatureEnvelope::from_armored(&input).expect_err(name);
            assert_eq!(error.code(), code, "{name}");
        }
    }

    #[test]
    fn envelope_rejects_noncanonical_base64_padding_bits() {
        // "AQ==" is canonical for [0x01]; "AR==" decodes to the same byte in
        // lenient decoders and must be rejected.
        let input = format!("{ARMOR_BEGIN}\nAR==\n{ARMOR_END}\n");
        let error = GitSignatureEnvelope::from_armored(input.as_bytes()).expect_err("padding");
        assert_eq!(error.code(), "git.envelope-malformed");
    }

    #[test]
    fn envelope_rejects_empty_fields_and_truncated_lengths() {
        for input in [
            armor_frame(&frame(&[], &[2])),
            armor_frame(&frame(&[1], &[])),
            armor_frame(&[FRAME_MAGIC, &[0, 0, 0]].concat()),
            armor_frame(&[FRAME_MAGIC, &[0, 0, 0, 9, 1]].concat()),
        ] {
            let error = GitSignatureEnvelope::from_armored(&input).expect_err("frame");
            assert_eq!(error.code(), "git.envelope-malformed");
        }
    }

    #[test]
    fn envelope_limits_hold_at_exact_boundaries() {
        let at_limit =
            GitSignatureEnvelope::new(vec![7; MAX_PROOF_BYTES], vec![8; MAX_ACTION_BYTES])
                .expect("fields at limit");
        let armored = at_limit.to_armored();
        assert!(armored.len() <= MAX_ARMORED_BYTES);
        assert_eq!(
            GitSignatureEnvelope::from_armored(armored.as_bytes()).expect("decode"),
            at_limit
        );

        assert_eq!(
            GitSignatureEnvelope::new(vec![7; MAX_PROOF_BYTES + 1], vec![8]),
            Err(EnvelopeError::TooLarge)
        );
        assert_eq!(
            GitSignatureEnvelope::new(vec![7], vec![8; MAX_ACTION_BYTES + 1]),
            Err(EnvelopeError::TooLarge)
        );
        let oversized_field = armor_frame(&frame(&[7; MAX_PROOF_BYTES + 1], &[8]));
        assert_eq!(
            GitSignatureEnvelope::from_armored(&oversized_field)
                .expect_err("field")
                .code(),
            "git.envelope-too-large"
        );
        let oversized_input = vec![b'A'; MAX_ARMORED_BYTES + 1];
        assert_eq!(
            GitSignatureEnvelope::from_armored(&oversized_input)
                .expect_err("input")
                .code(),
            "git.envelope-too-large"
        );
    }

    proptest! {
        #[test]
        fn envelope_encoding_is_a_bijection(
            proof in proptest::collection::vec(any::<u8>(), 1..512),
            action in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            let envelope = GitSignatureEnvelope::new(proof, action).expect("bounded");
            let armored = envelope.to_armored();
            let decoded = GitSignatureEnvelope::from_armored(armored.as_bytes()).expect("decode");
            prop_assert_eq!(&decoded, &envelope);
            prop_assert_eq!(decoded.to_armored(), armored);
        }

        #[test]
        fn envelope_decoding_never_panics_and_accepts_only_canonical_bytes(
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            if let Ok(decoded) = GitSignatureEnvelope::from_armored(&input) {
                prop_assert_eq!(decoded.to_armored().into_bytes(), input);
            }
        }
    }
}
