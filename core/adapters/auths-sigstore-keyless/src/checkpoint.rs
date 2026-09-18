extern crate alloc;

use alloc::{string::String, vec::Vec};
use auths_model::Digest;
use base64ct::{Base64, Encoding as _};

use crate::CheckpointError;

pub const MAX_CHECKPOINT_BYTES: usize = 2048;
pub const MAX_NOTE_SIGNATURES: usize = 8;

macro_rules! note_text {
    ($name:ident, $maximum:expr) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: &str) -> Result<Self, CheckpointError> {
                if value.is_empty()
                    || value.len() > $maximum
                    || value.contains(['\n', '\r'])
                    || value.trim() != value
                {
                    return Err(CheckpointError::Syntax);
                }
                Ok(Self(value.into()))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
note_text!(CheckpointOrigin, 128);
note_text!(NoteName, 128);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteSignature {
    pub name: NoteName,
    pub hint: [u8; 4],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub origin: CheckpointOrigin,
    pub tree_size: u64,
    pub root: Digest,
    pub body: Vec<u8>,
    pub signatures: Vec<NoteSignature>,
}
impl Checkpoint {
    pub fn parse(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.is_empty()
            || bytes.len() > MAX_CHECKPOINT_BYTES
            || bytes.windows(2).any(|w| w == b"\r\n")
        {
            return Err(CheckpointError::Syntax);
        }
        let text = core::str::from_utf8(bytes).map_err(|_| CheckpointError::Syntax)?;
        let separator = text.find("\n\n").ok_or(CheckpointError::Syntax)?;
        let body = bytes[..separator + 1].to_vec();
        let mut lines = text[..separator].lines();
        let origin = CheckpointOrigin::parse(lines.next().ok_or(CheckpointError::Syntax)?)?;
        let tree_size = lines
            .next()
            .ok_or(CheckpointError::Syntax)?
            .parse()
            .map_err(|_| CheckpointError::Syntax)?;
        if tree_size == 0 {
            return Err(CheckpointError::Syntax);
        }
        let root_bytes = Base64::decode_vec(lines.next().ok_or(CheckpointError::Syntax)?)
            .map_err(|_| CheckpointError::Syntax)?;
        let root: [u8; 32] = root_bytes.try_into().map_err(|_| CheckpointError::Syntax)?;
        let signature_text = &text[separator + 2..];
        let mut signatures = Vec::new();
        for line in signature_text.lines() {
            let line = line.strip_prefix("— ").ok_or(CheckpointError::Syntax)?;
            let (name, encoded) = line.split_once(' ').ok_or(CheckpointError::Syntax)?;
            let decoded = Base64::decode_vec(encoded).map_err(|_| CheckpointError::Syntax)?;
            if decoded.len() <= 4 {
                return Err(CheckpointError::Syntax);
            }
            let hint = decoded[..4]
                .try_into()
                .map_err(|_| CheckpointError::Syntax)?;
            signatures.push(NoteSignature {
                name: NoteName::parse(name)?,
                hint,
                bytes: decoded[4..].to_vec(),
            });
        }
        if signatures.is_empty() || signatures.len() > MAX_NOTE_SIGNATURES {
            return Err(CheckpointError::Syntax);
        }
        Ok(Self {
            origin,
            tree_size,
            root: Digest::new(root),
            body,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_exact_signed_note_envelope() {
        let root = Base64::encode_string(&[7_u8; 32]);
        let mut signature = vec![1, 2, 3, 4];
        signature.extend_from_slice(&[9; 64]);
        let signature = Base64::encode_string(&signature);
        let envelope = alloc::format!("rekor.example\n1\n{root}\n\n— rekor {signature}\n");
        let parsed = Checkpoint::parse(envelope.as_bytes()).unwrap();
        assert_eq!(parsed.tree_size, 1);
        assert_eq!(parsed.signatures[0].hint, [1, 2, 3, 4]);
        assert!(Checkpoint::parse(envelope.replace('\n', "\r\n").as_bytes()).is_err());
    }
}
