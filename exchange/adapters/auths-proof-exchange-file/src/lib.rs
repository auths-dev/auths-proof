//! Deterministic offline file-envelope adapter.

#![forbid(unsafe_code)]

use auths_proof_exchange_codec::{
    decode_challenge, decode_request, decode_response, encode_challenge, encode_request,
    encode_response,
};
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, MAX_BODY_BYTES, MAX_PROOF_BYTES,
    MAX_RESULT_BYTES, PeerObservation,
};
use sha2::{Digest as _, Sha256};
use std::{fmt, io::Write as _, path::PathBuf};
use tokio::fs;

const MAX_CHALLENGE_BYTES: usize = 4 * 1024;
const MAX_SUBMISSION_BYTES: usize = MAX_BODY_BYTES as usize + MAX_PROOF_BYTES as usize + 4 * 1024;
const MAX_RESPONSE_BYTES: usize = MAX_RESULT_BYTES + 16 * 1024;
const ACK_DOMAIN: &[u8] = b"AUTHS-FILE-ACK\x00\x01";
const ACK_BYTES: usize = 16 + 8 + 32 + 32;

/// One exchange directory and monotonically increasing envelope sequence.
#[derive(Clone, Debug)]
pub struct FileExchange {
    directory: PathBuf,
    sequence: u64,
}

impl FileExchange {
    /// Selects one explicit exchange directory and sequence.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>, sequence: u64) -> Self {
        Self {
            directory: directory.into(),
            sequence,
        }
    }

    /// Writes a canonical challenge envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed file or codec failure.
    pub async fn write_challenge(
        &self,
        challenge: &ActionChallenge,
    ) -> Result<PeerObservation, FileExchangeError> {
        self.write(
            "challenge.cbor",
            &encode_challenge(challenge),
            MAX_CHALLENGE_BYTES,
        )
        .await
    }

    /// Reads a canonical challenge envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed file or codec failure.
    pub async fn read_challenge(&self) -> Result<ActionChallenge, FileExchangeError> {
        decode_challenge(&self.read("challenge.cbor", MAX_CHALLENGE_BYTES).await?)
            .map_err(|_| FileExchangeError::Codec)
    }

    /// Writes a submission that exactly matches `challenge`.
    ///
    /// # Errors
    ///
    /// Returns a typed file or codec failure.
    pub async fn write_submission(
        &self,
        submission: &ActionSubmission,
    ) -> Result<PeerObservation, FileExchangeError> {
        self.write(
            "submission.cbor",
            &encode_request(submission),
            MAX_SUBMISSION_BYTES,
        )
        .await
    }

    /// Reads and validates a submission against `challenge`.
    ///
    /// # Errors
    ///
    /// Returns a typed file or codec failure.
    pub async fn read_submission(
        &self,
        challenge: &ActionChallenge,
    ) -> Result<ActionSubmission, FileExchangeError> {
        decode_request(
            &self.read("submission.cbor", MAX_SUBMISSION_BYTES).await?,
            challenge,
        )
        .map_err(|_| FileExchangeError::Codec)
    }

    /// Writes a canonical response envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed file or codec failure.
    pub async fn write_response(
        &self,
        response: &ActionResponse,
    ) -> Result<PeerObservation, FileExchangeError> {
        self.write(
            "response.cbor",
            &encode_response(response),
            MAX_RESPONSE_BYTES,
        )
        .await
    }

    /// Reads a canonical response envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed file or codec failure.
    pub async fn read_response(&self) -> Result<ActionResponse, FileExchangeError> {
        decode_response(&self.read("response.cbor", MAX_RESPONSE_BYTES).await?)
            .map_err(|_| FileExchangeError::Codec)
    }

    /// Writes an immutable acknowledgment binding the submission and response.
    ///
    /// File exchange is not confidential by itself. Operators must place the
    /// directory on an encrypted medium or wrap it in an approved envelope.
    /// This acknowledgment provides integrity and retry correlation only.
    ///
    /// # Errors
    ///
    /// Returns a typed file failure if the immutable acknowledgment already
    /// exists or cannot be persisted.
    pub async fn write_acknowledgement(
        &self,
        submission: &ActionSubmission,
        response: &ActionResponse,
    ) -> Result<FileAcknowledgement, FileExchangeError> {
        let acknowledgement = FileAcknowledgement {
            sequence: self.sequence,
            submission_digest: Sha256::digest(encode_request(submission)).into(),
            response_digest: Sha256::digest(encode_response(response)).into(),
        };
        self.write("ack", &acknowledgement.encode(), ACK_BYTES)
            .await?;
        Ok(acknowledgement)
    }

    /// Reads and validates the immutable acknowledgment for exact messages.
    ///
    /// # Errors
    ///
    /// Returns a typed codec or integrity failure for malformed or mismatched
    /// acknowledgment bytes.
    pub async fn read_acknowledgement(
        &self,
        submission: &ActionSubmission,
        response: &ActionResponse,
    ) -> Result<FileAcknowledgement, FileExchangeError> {
        let acknowledgement = FileAcknowledgement::decode(&self.read("ack", ACK_BYTES).await?)?;
        let expected_submission: [u8; 32] = Sha256::digest(encode_request(submission)).into();
        let expected_response: [u8; 32] = Sha256::digest(encode_response(response)).into();
        if acknowledgement.sequence != self.sequence
            || acknowledgement.submission_digest != expected_submission
            || acknowledgement.response_digest != expected_response
        {
            return Err(FileExchangeError::Integrity);
        }
        Ok(acknowledgement)
    }

    async fn write(
        &self,
        name: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<PeerObservation, FileExchangeError> {
        if bytes.len() > maximum {
            return Err(FileExchangeError::Limit);
        }
        fs::create_dir_all(&self.directory)
            .await
            .map_err(|_| FileExchangeError::Io)?;
        let directory = self.directory.clone();
        let target = self.path(name);
        let owned = bytes.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut temporary =
                tempfile::NamedTempFile::new_in(directory).map_err(|_| FileExchangeError::Io)?;
            temporary
                .write_all(&owned)
                .map_err(|_| FileExchangeError::Io)?;
            temporary
                .as_file()
                .sync_all()
                .map_err(|_| FileExchangeError::Io)?;
            temporary.persist_noclobber(target).map_err(|error| {
                if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    FileExchangeError::AlreadyExists
                } else {
                    FileExchangeError::Io
                }
            })?;
            Ok::<(), FileExchangeError>(())
        })
        .await
        .map_err(|_| FileExchangeError::Io)??;
        Ok(observation(bytes, self.sequence))
    }

    async fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>, FileExchangeError> {
        let path = self.path(name);
        let metadata = fs::metadata(&path)
            .await
            .map_err(|_| FileExchangeError::Io)?;
        if metadata.len() > maximum as u64 {
            return Err(FileExchangeError::Limit);
        }
        let bytes = fs::read(path).await.map_err(|_| FileExchangeError::Io)?;
        if bytes.len() > maximum {
            return Err(FileExchangeError::Limit);
        }
        Ok(bytes)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(format!("{:020}-{name}", self.sequence))
    }
}

/// Integrity acknowledgment for one immutable file exchange sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileAcknowledgement {
    sequence: u64,
    submission_digest: [u8; 32],
    response_digest: [u8; 32],
}

impl FileAcknowledgement {
    /// Returns the exchange sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the canonical submission digest.
    #[must_use]
    pub const fn submission_digest(self) -> [u8; 32] {
        self.submission_digest
    }

    /// Returns the canonical response digest.
    #[must_use]
    pub const fn response_digest(self) -> [u8; 32] {
        self.response_digest
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ACK_BYTES);
        bytes.extend_from_slice(ACK_DOMAIN);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.submission_digest);
        bytes.extend_from_slice(&self.response_digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, FileExchangeError> {
        if bytes.len() != ACK_BYTES || &bytes[..ACK_DOMAIN.len()] != ACK_DOMAIN {
            return Err(FileExchangeError::Codec);
        }
        let sequence = u64::from_be_bytes(
            bytes[ACK_DOMAIN.len()..ACK_DOMAIN.len() + 8]
                .try_into()
                .map_err(|_| FileExchangeError::Codec)?,
        );
        let submission_start = ACK_DOMAIN.len() + 8;
        let submission_digest = bytes[submission_start..submission_start + 32]
            .try_into()
            .map_err(|_| FileExchangeError::Codec)?;
        let response_digest = bytes[submission_start + 32..]
            .try_into()
            .map_err(|_| FileExchangeError::Codec)?;
        Ok(Self {
            sequence,
            submission_digest,
            response_digest,
        })
    }
}

fn observation(bytes: &[u8], sequence: u64) -> PeerObservation {
    PeerObservation::FileEnvelope {
        digest: Sha256::digest(bytes).into(),
        sequence,
    }
}

/// Offline file-exchange failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileExchangeError {
    /// Filesystem operation failed.
    Io,
    /// Deterministic exchange codec rejected an envelope.
    Codec,
    /// Envelope exceeds its exact transport bound.
    Limit,
    /// An immutable envelope already exists at the target sequence.
    AlreadyExists,
    /// Acknowledgment does not bind the expected messages and sequence.
    Integrity,
}

impl fmt::Display for FileExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io => "file exchange I/O failed",
            Self::Codec => "invalid file exchange envelope",
            Self::Limit => "file exchange envelope limit exceeded",
            Self::AlreadyExists => "file exchange envelope already exists",
            Self::Integrity => "file exchange acknowledgment integrity mismatch",
        })
    }
}

impl std::error::Error for FileExchangeError {}
