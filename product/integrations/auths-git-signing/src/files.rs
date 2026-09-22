//! Files exchanged between the root, the agent, and verifiers.
//!
//! A delegation file carries a grant chain with each issuer's control
//! evidence, as JSON with base64 fields so it can be reviewed in a pull
//! request. Every field is re-validated on decode: grants through the
//! canonical codec, evidence by recomputing its content address.

use crate::sign::{Delegation, DelegationLink};
use auths_author::address_evidence;
use auths_codec::{decode_signed_grant, encode_signed_grant};
use auths_model::{EvidenceTypeId, MediaType, VerifierLimits};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema of a delegation file.
pub const DELEGATION_SCHEMA: &str = "auths.git-delegation/1";
/// Maximum delegation file size in bytes.
pub const MAX_DELEGATION_FILE_BYTES: usize = 256 * 1024;

/// Why a delegation file was rejected.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FileError {
    /// The file is too large, malformed, or not canonical.
    #[error("malformed delegation file")]
    Malformed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DelegationFile {
    schema: String,
    links: Vec<LinkFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinkFile {
    grant: String,
    issuer_evidence_type: String,
    issuer_evidence_media_type: String,
    issuer_evidence: String,
}

/// Encodes a delegation chain.
///
/// # Errors
///
/// Returns [`FileError::Malformed`] if a grant cannot be encoded.
pub fn encode_delegation(delegation: &Delegation) -> Result<Vec<u8>, FileError> {
    let links = delegation
        .links()
        .iter()
        .map(|link| {
            Ok(LinkFile {
                grant: Base64::encode_string(
                    &encode_signed_grant(link.grant()).map_err(|_| FileError::Malformed)?,
                ),
                issuer_evidence_type: link.issuer_evidence().evidence_type().as_str().to_owned(),
                issuer_evidence_media_type: link.issuer_evidence().media_type().as_str().to_owned(),
                issuer_evidence: Base64::encode_string(link.issuer_evidence().bytes()),
            })
        })
        .collect::<Result<Vec<_>, FileError>>()?;
    let mut bytes = serde_json_canonicalizer::to_vec(&DelegationFile {
        schema: DELEGATION_SCHEMA.to_owned(),
        links,
    })
    .map_err(|_| FileError::Malformed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decodes and re-validates a delegation chain.
///
/// # Errors
///
/// Returns [`FileError::Malformed`] for an oversized, unknown, or invalid
/// file, a grant that is not canonical, or evidence that does not address.
pub fn decode_delegation(bytes: &[u8]) -> Result<Delegation, FileError> {
    if bytes.len() > MAX_DELEGATION_FILE_BYTES {
        return Err(FileError::Malformed);
    }
    let file: DelegationFile = serde_json::from_slice(bytes).map_err(|_| FileError::Malformed)?;
    if file.schema != DELEGATION_SCHEMA {
        return Err(FileError::Malformed);
    }
    let limits = VerifierLimits::default();
    let links = file
        .links
        .into_iter()
        .map(|link| {
            let grant = decode_signed_grant(
                &Base64::decode_vec(&link.grant).map_err(|_| FileError::Malformed)?,
                &limits,
            )
            .map_err(|_| FileError::Malformed)?;
            let evidence = address_evidence(
                EvidenceTypeId::parse(&link.issuer_evidence_type)
                    .map_err(|_| FileError::Malformed)?,
                MediaType::parse(&link.issuer_evidence_media_type)
                    .map_err(|_| FileError::Malformed)?,
                Base64::decode_vec(&link.issuer_evidence).map_err(|_| FileError::Malformed)?,
            )
            .map_err(|_| FileError::Malformed)?;
            Ok(DelegationLink::new(grant, evidence))
        })
        .collect::<Result<Vec<_>, FileError>>()?;
    Delegation::new(links).map_err(|_| FileError::Malformed)
}
