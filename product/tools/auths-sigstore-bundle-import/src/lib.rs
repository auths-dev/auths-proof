use auths_model::Digest;
use auths_sigstore_keyless::{
    chain::CertificateChain,
    entry::{EntryFields, encode_entry},
};
use base64ct::{Base64, Encoding as _};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportError {
    Json,
    Shape,
    Encoding,
    UnsupportedDigest,
    Evidence,
}

/// Imports a Sigstore bundle into canonical chain and Rekor-entry evidence.
///
/// # Errors
///
/// Returns [`ImportError`] when JSON is malformed, the bundle shape or digest
/// algorithm is unsupported, encoded material is invalid, or canonical Auths
/// evidence cannot be constructed.
pub fn import_bundle(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ImportError> {
    let bundle: Value = serde_json::from_slice(bytes).map_err(|_| ImportError::Json)?;
    if bundle["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json" {
        return Err(ImportError::Shape);
    }
    let digest_algorithm = bundle
        .pointer("/messageSignature/messageDigest/algorithm")
        .and_then(Value::as_str)
        .ok_or(ImportError::Shape)?;
    if digest_algorithm != "SHA2_256" {
        return Err(ImportError::UnsupportedDigest);
    }
    let entries = bundle
        .pointer("/verificationMaterial/tlogEntries")
        .and_then(Value::as_array)
        .ok_or(ImportError::Shape)?;
    if entries.len() != 1 {
        return Err(ImportError::Shape);
    }
    let entry = &entries[0];
    let proof = entry.get("inclusionProof").ok_or(ImportError::Shape)?;
    let body = decode(value(entry, "canonicalizedBody")?)?;
    let set = decode(value(
        entry
            .pointer("/inclusionPromise")
            .ok_or(ImportError::Shape)?,
        "signedEntryTimestamp",
    )?)?;
    let checkpoint = value(
        proof.pointer("/checkpoint").ok_or(ImportError::Shape)?,
        "envelope",
    )?;
    let hashes = proof
        .get("hashes")
        .and_then(Value::as_array)
        .ok_or(ImportError::Shape)?
        .iter()
        .map(|value| {
            let bytes = decode(value.as_str().ok_or(ImportError::Shape)?)?;
            let array: [u8; 32] = bytes.try_into().map_err(|_| ImportError::Encoding)?;
            Ok(Digest::new(array))
        })
        .collect::<Result<Vec<_>, ImportError>>()?;
    let log_id: [u8; 32] = decode(
        entry
            .pointer("/logId/keyId")
            .and_then(Value::as_str)
            .ok_or(ImportError::Shape)?,
    )?
    .try_into()
    .map_err(|_| ImportError::Encoding)?;
    let entry_bytes = encode_entry(&EntryFields {
        body: &body,
        checkpoint,
        hashes: &hashes,
        integrated_time: integer(entry, "integratedTime")?,
        log_id: &log_id,
        log_index: integer(entry, "logIndex")?,
        proof_index: integer(proof, "logIndex")?,
        signed_entry_timestamp: &set,
        tree_size: integer(proof, "treeSize")?,
    })
    .map_err(|_| ImportError::Evidence)?;
    let material = bundle
        .get("verificationMaterial")
        .ok_or(ImportError::Shape)?;
    let certificates = if let Some(raw) = material
        .pointer("/certificate/rawBytes")
        .and_then(Value::as_str)
    {
        vec![decode(raw)?]
    } else {
        material
            .pointer("/x509CertificateChain/certificates")
            .and_then(Value::as_array)
            .ok_or(ImportError::Shape)?
            .iter()
            .map(|certificate| {
                decode(
                    certificate
                        .get("rawBytes")
                        .and_then(Value::as_str)
                        .ok_or(ImportError::Shape)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let chain = CertificateChain::encode(&certificates).map_err(|_| ImportError::Evidence)?;
    Ok((chain, entry_bytes))
}
/// Reads an unsigned integer that the bundle's JSON encoding may write as a
/// number or, for 64-bit fields, as a canonical decimal string.
fn integer(object: &Value, key: &str) -> Result<u64, ImportError> {
    match object.get(key).ok_or(ImportError::Shape)? {
        Value::Number(number) => number.as_u64().ok_or(ImportError::Shape),
        Value::String(text)
            if !text.is_empty()
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && (text == "0" || !text.starts_with('0')) =>
        {
            text.parse().map_err(|_| ImportError::Shape)
        }
        _ => Err(ImportError::Shape),
    }
}

fn value<'a>(object: &'a Value, key: &str) -> Result<&'a str, ImportError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ImportError::Shape)
}
fn decode(value: &str) -> Result<Vec<u8>, ImportError> {
    Base64::decode_vec(value).map_err(|_| ImportError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_wrong_media_type_and_tlog_cardinality() {
        assert_eq!(
            import_bundle(br#"{"mediaType":"wrong"}"#),
            Err(ImportError::Shape)
        );
        let empty=br#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","messageSignature":{"messageDigest":{"algorithm":"SHA2_256"}},"verificationMaterial":{"tlogEntries":[]}}"#;
        assert_eq!(import_bundle(empty), Err(ImportError::Shape));
    }
}
