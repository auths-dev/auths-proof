//! Bounded parsing of Git commit and tag objects around their signature.
//!
//! Git signs the *unsigned payload*: a commit without its signature header,
//! or a tag without its trailing signature block. The parser recovers that
//! payload from a signed object exactly as Git does, and rejects every object
//! whose split would be ambiguous instead of guessing:
//!
//! - A commit's signature is the header named for its object format:
//!   `gpgsig` for SHA-1 and `gpgsig-sha256` for SHA-256, with continuation
//!   lines that start with one space. Any other signature header, or a
//!   second one, makes the object ambiguous.
//! - A tag's signature starts at a line that opens a signature armor. Git
//!   splits at the last such line, so a tag with more than one is ambiguous.
//!
//! Only the structure needed for that split, the object format, and the tag
//! name is interpreted. Everything else is covered by the payload digest,
//! byte for byte.

use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum unsigned payload size in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum tag name length in bytes.
pub const MAX_TAG_NAME_BYTES: usize = 255;
/// Domain separator of the payload digest.
pub const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"auths.git-signature/1\0";

/// Lines at which Git considers a tag signature to begin.
const SIGNATURE_STARTS: [&[u8]; 4] = [
    b"-----BEGIN PGP SIGNATURE-----",
    b"-----BEGIN PGP MESSAGE-----",
    b"-----BEGIN SIGNED MESSAGE-----",
    b"-----BEGIN SSH SIGNATURE-----",
];

/// The kind of signed Git object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    /// A commit object.
    Commit,
    /// An annotated tag object.
    Tag,
}

impl ObjectKind {
    /// Returns the name bound into the payload digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }
}

/// The repository hash algorithm, read from the object's own identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectFormat {
    /// 40 hexadecimal digits.
    Sha1,
    /// 64 hexadecimal digits.
    Sha256,
}

impl ObjectFormat {
    /// Returns the canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    const fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    const fn commit_signature_header(self) -> &'static [u8] {
        match self {
            Self::Sha1 => b"gpgsig",
            Self::Sha256 => b"gpgsig-sha256",
        }
    }
}

/// Why an object or payload was rejected. [`ObjectError::code`] returns the
/// stable result code.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ObjectError {
    /// The payload exceeds [`MAX_PAYLOAD_BYTES`].
    #[error("git object payload exceeds its size limit")]
    PayloadTooLarge,
    /// The object carries no signature.
    #[error("git object is not signed")]
    Unsigned,
    /// The signature cannot be separated from the payload unambiguously.
    #[error("git object signature is ambiguous")]
    SignatureAmbiguous,
    /// The tag name is outside the accepted set.
    #[error("git tag name is not accepted")]
    TagNameInvalid,
    /// The object structure is malformed or outside the accepted subset.
    #[error("malformed git object")]
    Malformed,
}

impl ObjectError {
    /// Returns the stable result code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "git.payload-too-large",
            Self::Unsigned => "git.unsigned",
            Self::SignatureAmbiguous => "git.signature-ambiguous",
            Self::TagNameInvalid => "git.tag-name-invalid",
            Self::Malformed => "git.object-malformed",
        }
    }
}

/// A validated tag name.
///
/// Accepts 1–255 bytes of ASCII graphic characters other than
/// `~ ^ : ? * [ \`, with no `..`, `@{`, or `//`, no component that starts
/// with `.`, no leading `-` or `/`, and no trailing `/`, `.`, or `.lock`.
/// This is stricter than Git; a rejected name fails closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagName(String);

impl TagName {
    /// Parses a tag name.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::TagNameInvalid`] outside the accepted set.
    pub fn parse(value: &[u8]) -> Result<Self, ObjectError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_TAG_NAME_BYTES
            && value
                .iter()
                .all(|byte| byte.is_ascii_graphic() && !b"~^:?*[\\".contains(byte))
            && !contains(value, b"..")
            && !contains(value, b"@{")
            && !contains(value, b"//")
            && !value.starts_with(b"-")
            && !value.starts_with(b"/")
            && !value.ends_with(b"/")
            && !value.ends_with(b".")
            && !value.ends_with(b".lock")
            && value
                .split(|byte| *byte == b'/')
                .all(|component| !component.starts_with(b"."));
        if !valid {
            return Err(ObjectError::TagNameInvalid);
        }
        // INVARIANT: every accepted byte is ASCII.
        Ok(Self(value.iter().map(|byte| char::from(*byte)).collect()))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The exact bytes Git signs, with the facts read from them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedPayload {
    kind: ObjectKind,
    format: ObjectFormat,
    tag_name: Option<TagName>,
    bytes: Vec<u8>,
}

impl UnsignedPayload {
    /// Parses the payload Git passes to the signing program on stdin.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::PayloadTooLarge`] before parsing an oversized
    /// payload, [`ObjectError::SignatureAmbiguous`] when the payload already
    /// carries a signature header or armor line, and
    /// [`ObjectError::Malformed`] or [`ObjectError::TagNameInvalid`] for a
    /// structure outside the accepted subset.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ObjectError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ObjectError::PayloadTooLarge);
        }
        let kind = detect_kind(&bytes)?;
        let (headers, message) = split_headers(&bytes)?;
        let (format, tag_name) = match kind {
            ObjectKind::Commit => (commit_format(&headers)?, None),
            ObjectKind::Tag => {
                if message.split(|byte| *byte == b'\n').any(starts_signature) {
                    return Err(ObjectError::SignatureAmbiguous);
                }
                let (format, name) = tag_facts(&headers)?;
                (format, Some(name))
            }
        };
        if kind == ObjectKind::Commit
            && headers
                .iter()
                .any(|header| header.name.starts_with(b"gpgsig"))
        {
            return Err(ObjectError::SignatureAmbiguous);
        }
        Ok(Self {
            kind,
            format,
            tag_name,
            bytes,
        })
    }

    /// Returns the object kind.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Returns the object format.
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }

    /// Returns the tag name for a tag payload.
    #[must_use]
    pub fn tag_name(&self) -> Option<&TagName> {
        self.tag_name.as_ref()
    }

    /// Returns the exact payload bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns `SHA-256(domain || kind || 0x00 || payload)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PAYLOAD_DIGEST_DOMAIN);
        hasher.update(self.kind.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }
}

/// A signed object split into its unsigned payload and stored signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedObject {
    payload: UnsignedPayload,
    signature: Vec<u8>,
}

impl SignedObject {
    /// Splits a raw commit or tag object, as `git cat-file` prints it.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Unsigned`] when there is no signature,
    /// [`ObjectError::SignatureAmbiguous`] when the split is not unique, and
    /// the [`UnsignedPayload::parse`] errors for the recovered payload.
    pub fn parse(raw: &[u8]) -> Result<Self, ObjectError> {
        if raw.len() > MAX_PAYLOAD_BYTES.saturating_mul(2) {
            return Err(ObjectError::PayloadTooLarge);
        }
        let (payload, signature) = match detect_kind(raw)? {
            ObjectKind::Commit => split_commit(raw)?,
            ObjectKind::Tag => split_tag(raw)?,
        };
        Ok(Self {
            payload: UnsignedPayload::parse(payload)?,
            signature,
        })
    }

    /// Returns the unsigned payload.
    #[must_use]
    pub const fn payload(&self) -> &UnsignedPayload {
        &self.payload
    }

    /// Returns the stored signature bytes, not yet decoded.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

struct Header<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn starts_signature(line: &[u8]) -> bool {
    SIGNATURE_STARTS.iter().any(|start| line.starts_with(start))
}

fn detect_kind(bytes: &[u8]) -> Result<ObjectKind, ObjectError> {
    if bytes.starts_with(b"tree ") {
        Ok(ObjectKind::Commit)
    } else if bytes.starts_with(b"object ") {
        Ok(ObjectKind::Tag)
    } else {
        Err(ObjectError::Malformed)
    }
}

/// Splits `headers \n\n message`. Continuation lines (leading space) are
/// folded into the previous header's value. Headers may not contain NUL or
/// CR; the message may not contain NUL.
fn split_headers(bytes: &[u8]) -> Result<(Vec<Header<'_>>, &[u8]), ObjectError> {
    let boundary = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or(ObjectError::Malformed)?;
    let (head, rest) = bytes.split_at(boundary);
    let message = &rest[2..];
    if head.iter().any(|byte| matches!(byte, 0 | b'\r')) || message.contains(&0) {
        return Err(ObjectError::Malformed);
    }
    let mut headers: Vec<Header<'_>> = Vec::new();
    for line in head.split(|byte| *byte == b'\n') {
        if line.starts_with(b" ") {
            if headers.is_empty() {
                return Err(ObjectError::Malformed);
            }
            continue;
        }
        let space = line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(ObjectError::Malformed)?;
        let (name, value) = line.split_at(space);
        if name.is_empty() {
            return Err(ObjectError::Malformed);
        }
        headers.push(Header {
            name,
            value: &value[1..],
        });
    }
    Ok((headers, message))
}

fn object_id(value: &[u8], format: ObjectFormat) -> Result<(), ObjectError> {
    if value.len() == format.hex_len()
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Ok(())
    } else {
        Err(ObjectError::Malformed)
    }
}

fn format_of(value: &[u8]) -> Result<ObjectFormat, ObjectError> {
    let format = match value.len() {
        40 => ObjectFormat::Sha1,
        64 => ObjectFormat::Sha256,
        _ => return Err(ObjectError::Malformed),
    };
    object_id(value, format)?;
    Ok(format)
}

/// `tree`, then `parent`*, then `author`, then `committer`, then any other
/// headers. Only identifier syntax and order are interpreted.
fn commit_format(headers: &[Header<'_>]) -> Result<ObjectFormat, ObjectError> {
    let mut iter = headers.iter();
    let tree = iter
        .next()
        .filter(|header| header.name == b"tree")
        .ok_or(ObjectError::Malformed)?;
    let format = format_of(tree.value)?;
    let mut next = iter.next();
    while let Some(parent) = next.filter(|header| header.name == b"parent") {
        object_id(parent.value, format)?;
        next = iter.next();
    }
    let author = next.filter(|header| header.name == b"author");
    let committer = iter.next().filter(|header| header.name == b"committer");
    if author.is_none() || committer.is_none() {
        return Err(ObjectError::Malformed);
    }
    if iter.any(|header| matches!(header.name, b"tree" | b"parent" | b"author" | b"committer")) {
        return Err(ObjectError::Malformed);
    }
    Ok(format)
}

/// Exactly `object`, `type commit`, `tag`, `tagger`, in that order.
fn tag_facts(headers: &[Header<'_>]) -> Result<(ObjectFormat, TagName), ObjectError> {
    let [object, kind, tag, tagger] = headers else {
        return Err(ObjectError::Malformed);
    };
    if object.name != b"object"
        || kind.name != b"type"
        || kind.value != b"commit"
        || tag.name != b"tag"
        || tagger.name != b"tagger"
    {
        return Err(ObjectError::Malformed);
    }
    Ok((format_of(object.value)?, TagName::parse(tag.value)?))
}

fn split_commit(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ObjectError> {
    let boundary = raw
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or(ObjectError::Malformed)?;
    let (head, message) = raw.split_at(boundary + 1);
    let tree_line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let format = format_of(
        tree_line
            .strip_prefix(b"tree ")
            .ok_or(ObjectError::Malformed)?,
    )?;
    let wanted = format.commit_signature_header();

    let mut payload = Vec::with_capacity(raw.len());
    let mut signature = Vec::new();
    let mut found = 0_usize;
    let mut in_signature = false;
    // `head` ends in '\n'; the final empty split element is skipped.
    for line in head.split_inclusive(|byte| *byte == b'\n') {
        if let Some(continued) = line.strip_prefix(b" ")
            && in_signature
        {
            signature.extend_from_slice(continued);
            continue;
        }
        in_signature = false;
        let name = line.split(|byte| *byte == b' ').next().unwrap_or_default();
        if name.starts_with(b"gpgsig") {
            if name != wanted {
                return Err(ObjectError::SignatureAmbiguous);
            }
            found += 1;
            in_signature = true;
            signature.extend_from_slice(&line[wanted.len() + 1..]);
            continue;
        }
        payload.extend_from_slice(line);
    }
    match found {
        0 => Err(ObjectError::Unsigned),
        1 => {
            payload.extend_from_slice(message);
            Ok((payload, signature))
        }
        _ => Err(ObjectError::SignatureAmbiguous),
    }
}

fn split_tag(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ObjectError> {
    let mut starts = Vec::new();
    let mut offset = 0_usize;
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        if starts_signature(line) {
            starts.push(offset);
        }
        offset += line.len();
    }
    match starts.as_slice() {
        [] => Err(ObjectError::Unsigned),
        [start] => {
            let (payload, signature) = raw.split_at(*start);
            Ok((payload.to_vec(), signature.to_vec()))
        }
        _ => Err(ObjectError::SignatureAmbiguous),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::GitSignatureEnvelope;
    use base64ct::{Base64, Encoding as _};
    use serde_json::Value;

    const VECTORS: &[u8] = include_bytes!("../fixtures/objects.json");

    fn bytes(value: &Value, key: &str) -> Vec<u8> {
        Base64::decode_vec(value[key].as_str().expect(key)).expect("base64")
    }

    fn hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Runs one vector through the same steps the signer and verifier use.
    fn evaluate(case: &Value) -> Result<Value, &'static str> {
        let input = bytes(case, "input");
        match case["form"].as_str().expect("form") {
            "signed-object" => {
                let object = SignedObject::parse(&input).map_err(ObjectError::code)?;
                let envelope = GitSignatureEnvelope::from_armored(object.signature())
                    .map_err(crate::envelope::EnvelopeError::code)?;
                Ok(summary(
                    object.payload(),
                    Some((envelope.proof(), envelope.action())),
                ))
            }
            "unsigned-payload" => {
                let payload = UnsignedPayload::parse(input).map_err(ObjectError::code)?;
                Ok(summary(&payload, None))
            }
            other => panic!("unknown form {other}"),
        }
    }

    fn summary(payload: &UnsignedPayload, envelope: Option<(&[u8], &[u8])>) -> Value {
        let mut value = serde_json::json!({
            "kind": payload.kind().as_str(),
            "object_format": payload.format().as_str(),
            "tag_name": payload.tag_name().map(TagName::as_str),
            "payload": Base64::encode_string(payload.bytes()),
            "payload_digest": hex(&payload.digest()),
        });
        if let Some((proof, action)) = envelope {
            value["proof"] = Base64::encode_string(proof).into();
            value["action"] = Base64::encode_string(action).into();
        }
        value
    }

    #[test]
    fn object_vectors_match_the_independent_generator() {
        let corpus: Value = serde_json::from_slice(VECTORS).expect("vectors");
        assert_eq!(corpus["schema"], "auths.git-signing-object-vectors/1");
        let cases = corpus["cases"].as_array().expect("cases");
        assert!(cases.len() >= 30, "corpus shrank to {}", cases.len());
        for case in cases {
            let id = case["id"].as_str().expect("id");
            match (&case["expect"]["ok"], &case["expect"]["error"]) {
                (ok, Value::Null) => {
                    let mut actual = evaluate(case).unwrap_or_else(|code| panic!("{id}: {code}"));
                    if ok.get("proof").is_none() {
                        actual.as_object_mut().expect("object").remove("proof");
                        actual.as_object_mut().expect("object").remove("action");
                    }
                    assert_eq!(&actual, ok, "{id}");
                }
                (Value::Null, Value::String(code)) => {
                    assert_eq!(evaluate(case).err(), Some(code.as_str()), "{id}");
                }
                _ => panic!("{id}: expect needs exactly one of ok or error"),
            }
        }
    }

    #[test]
    fn payload_limit_holds_at_the_exact_boundary() {
        let header = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor a <a> 0 +0000\ncommitter a <a> 0 +0000\n\n";
        let mut at_limit = header.to_vec();
        at_limit.resize(MAX_PAYLOAD_BYTES, b'x');
        assert!(UnsignedPayload::parse(at_limit.clone()).is_ok());
        at_limit.push(b'x');
        assert_eq!(
            UnsignedPayload::parse(at_limit),
            Err(ObjectError::PayloadTooLarge)
        );
    }

    #[test]
    fn tag_names_are_closed() {
        for valid in ["v1", "v1.2.3", "release/2026-09", "a+b_c"] {
            assert!(TagName::parse(valid.as_bytes()).is_ok(), "{valid}");
        }
        for invalid in [
            "", "-v1", "/v1", "v1/", "v1.", "v1.lock", "a..b", "a//b", "a/.b", ".a", "a b", "a~1",
            "a^", "a:b", "a?", "a*", "a[", "a\\b", "a@{b",
        ] {
            assert_eq!(
                TagName::parse(invalid.as_bytes()),
                Err(ObjectError::TagNameInvalid),
                "{invalid}"
            );
        }
        let long = "a".repeat(MAX_TAG_NAME_BYTES + 1);
        assert!(TagName::parse(long.as_bytes()).is_err());
    }

    proptest::proptest! {
        #[test]
        fn object_parsing_never_panics(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let _ = SignedObject::parse(&input);
            let _ = UnsignedPayload::parse(input);
        }
    }
}
