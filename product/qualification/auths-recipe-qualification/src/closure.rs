//! The gateway semantic closure: the exact source files whose meaning a
//! gateway build carries, as one digest.

use crate::canonical::{self, Artifact, Canonical, Sealed};
use crate::{BoundedText, QualificationFormatError, Sha256Digest};
use serde::{Deserialize, Serialize};

/// The schema of a semantic closure.
pub const SEMANTIC_CLOSURE_SCHEMA: &str = "auths.gateway-semantic-closure/1";
/// The largest semantic closure accepted.
pub const MAX_SEMANTIC_CLOSURE_BYTES: usize = 1024 * 1024;
/// The most files a semantic closure lists.
pub const MAX_SEMANTIC_CLOSURE_FILES: usize = 4096;

/// One file of the closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticClosureFile {
    /// The file's path from the repository root, with `/` separators.
    pub path: BoundedText<160>,
    /// SHA-256 of the file's bytes.
    pub sha256: Sha256Digest,
}

/// The body of a semantic closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticClosureBody {
    /// Exactly [`SEMANTIC_CLOSURE_SCHEMA`].
    pub schema: String,
    /// The files, sorted by path and unique.
    pub files: Vec<SemanticClosureFile>,
}

impl Sealed for SemanticClosureBody {}

impl Artifact for SemanticClosureBody {
    const SCHEMA: &'static str = SEMANTIC_CLOSURE_SCHEMA;
    const MAX_BYTES: usize = MAX_SEMANTIC_CLOSURE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        if self.files.is_empty() || self.files.len() > MAX_SEMANTIC_CLOSURE_FILES {
            return Err(QualificationFormatError::ListBound);
        }
        let paths: Vec<&BoundedText<160>> = self.files.iter().map(|file| &file.path).collect();
        canonical::strictly_ascending(&paths)
    }
}

/// A decoded semantic closure. Its digest is the tuple member a
/// qualification binds: one changed, added, or removed file changes it.
pub type GatewaySemanticClosure = Canonical<SemanticClosureBody>;
