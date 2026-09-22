//! The external signing-program protocol Git uses for `gpg.format = x509`.
//!
//! Observed Git behavior, confirmed by `git_protocol_tests`:
//!
//! - Signing runs `<program> --status-fd=2 -bsau <user.signingkey>` with the
//!   exact unsigned payload on stdin. The program writes the armored
//!   signature to stdout. Git refuses to create the object unless stderr
//!   contains `\n[GNUPG:] SIG_CREATED `.
//! - Verifying runs `<program> --status-fd=1 --verify <signature-file> -` with
//!   the same payload on stdin. Git reports a good signature only when the
//!   program exits 0 **and** stdout contains `\n[GNUPG:] GOODSIG `, including
//!   the leading newline.
//!
//! Argument parsing is closed: any other argument vector is rejected, so a
//! future Git flag cannot silently change the meaning of a call.

use std::ffi::OsString;
use std::path::PathBuf;
use thiserror::Error;

/// Prefix of every accepted `user.signingkey` value.
pub const SIGNING_KEY_PREFIX: &str = "auths:";
/// Maximum length of the label after [`SIGNING_KEY_PREFIX`].
pub const MAX_SIGNING_KEY_LABEL: usize = 64;

/// A local signer label from `user.signingkey`, such as `auths:claude-release`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKeyRef(String);

impl SigningKeyRef {
    /// Parses `auths:<label>`, where the label is 1–64 bytes of lowercase ASCII
    /// letters, digits, and interior hyphens.
    ///
    /// # Errors
    ///
    /// Returns [`ProgramError::InvalidSigningKey`] for any other value.
    pub fn parse(value: &str) -> Result<Self, ProgramError> {
        let label = value
            .strip_prefix(SIGNING_KEY_PREFIX)
            .ok_or(ProgramError::InvalidSigningKey)?;
        let valid = !label.is_empty()
            && label.len() <= MAX_SIGNING_KEY_LABEL
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid {
            return Err(ProgramError::InvalidSigningKey);
        }
        Ok(Self(label.to_owned()))
    }

    /// Returns the label without the `auths:` prefix.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.0
    }
}

/// One call from Git, parsed from its exact argument vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramRequest {
    /// Sign the payload on stdin with the named local signer.
    Sign {
        /// The configured `user.signingkey`.
        key: SigningKeyRef,
    },
    /// Verify the signature in `signature` over the payload on stdin.
    Verify {
        /// The temporary file Git wrote the stored signature to.
        signature: PathBuf,
    },
}

/// Why a program invocation was rejected before any payload was read.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProgramError {
    /// The argument vector is not one of the two forms Git uses.
    #[error("unsupported git signing-program arguments")]
    UnsupportedArguments,
    /// `user.signingkey` is not an `auths:<label>` value.
    #[error("user.signingkey must be auths:<label>")]
    InvalidSigningKey,
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// Returns [`ProgramError::UnsupportedArguments`] unless the vector is exactly
/// `--status-fd=2 -bsau <key>` or `--status-fd=1 --verify <file> -`, and
/// [`ProgramError::InvalidSigningKey`] for a malformed key.
pub fn parse_arguments<I>(arguments: I) -> Result<ProgramRequest, ProgramError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments: Vec<OsString> = arguments.into_iter().take(5).collect();
    let text: Vec<Option<&str>> = arguments.iter().map(|value| value.to_str()).collect();
    match text.as_slice() {
        [Some("--status-fd=2"), Some("-bsau"), Some(key)] => Ok(ProgramRequest::Sign {
            key: SigningKeyRef::parse(key)?,
        }),
        [Some("--status-fd=1"), Some("--verify"), _, Some("-")] => Ok(ProgramRequest::Verify {
            signature: PathBuf::from(&arguments[2]),
        }),
        _ => Err(ProgramError::UnsupportedArguments),
    }
}

/// Status bytes written to stderr after a signature was produced.
#[must_use]
pub const fn sign_created_status() -> &'static [u8] {
    b"\n[GNUPG:] SIG_CREATED auths-git-signature/1\n"
}

/// The verification outcome reported to Git.
///
/// `Good` carries a [`VerifiedSigner`], which only this crate can construct.
/// Until the verifier exists, nothing outside the crate can make Git report a
/// good signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyStatus {
    /// A verified Auths signature.
    Good(VerifiedSigner),
    /// The signature was checked and denied, with a stable code.
    Bad(&'static str),
    /// No conclusion could be reached, with a stable code.
    Error(&'static str),
}

/// Display name of a verified signing principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSigner(String);

impl VerifiedSigner {
    /// Wraps a principal display string, replacing control characters so it
    /// cannot inject status lines.
    // Constructed only by the verifier in a later step, and by tests now.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(principal: &str) -> Self {
        Self(
            principal
                .chars()
                .map(|character| {
                    if character.is_control() {
                        '?'
                    } else {
                        character
                    }
                })
                .collect(),
        )
    }
}

impl VerifyStatus {
    /// Returns the stdout bytes for Git.
    #[must_use]
    pub fn status_lines(&self) -> Vec<u8> {
        let (kind, detail) = match self {
            Self::Good(signer) => ("GOODSIG", signer.0.as_str()),
            Self::Bad(code) => ("BADSIG", *code),
            Self::Error(code) => ("ERRSIG", *code),
        };
        format!("[GNUPG:] NEWSIG\n[GNUPG:] {kind} AUTHS {detail}\n").into_bytes()
    }

    /// Returns the process exit code for Git.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Good(_) => 0,
            Self::Bad(_) => 1,
            Self::Error(_) => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn program_arguments_accept_only_the_two_git_forms() {
        assert_eq!(
            parse_arguments(arguments(&[
                "--status-fd=2",
                "-bsau",
                "auths:claude-release"
            ])),
            Ok(ProgramRequest::Sign {
                key: SigningKeyRef("claude-release".into())
            })
        );
        assert_eq!(
            parse_arguments(arguments(&["--status-fd=1", "--verify", "/tmp/sig", "-"])),
            Ok(ProgramRequest::Verify {
                signature: PathBuf::from("/tmp/sig")
            })
        );
        for rejected in [
            &[][..],
            &["--status-fd=2", "-bsau"][..],
            &["--status-fd=2", "-bsau", "auths:a", "extra"][..],
            &["--status-fd=1", "-bsau", "auths:a"][..],
            &["--status-fd=2", "--verify", "/tmp/sig", "-"][..],
            &["--status-fd=1", "--verify", "/tmp/sig"][..],
            &["--status-fd=1", "--verify", "/tmp/sig", "-", "x"][..],
            &["-bsau", "auths:a", "--status-fd=2"][..],
        ] {
            assert_eq!(
                parse_arguments(arguments(rejected)),
                Err(ProgramError::UnsupportedArguments),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn signing_key_labels_are_closed() {
        for valid in ["auths:a", "auths:claude-release", "auths:agent-2"] {
            assert!(SigningKeyRef::parse(valid).is_ok(), "{valid}");
        }
        let long = format!("auths:{}", "a".repeat(MAX_SIGNING_KEY_LABEL + 1));
        for invalid in [
            "claude-release",
            "auths:",
            "auths:-a",
            "auths:a-",
            "auths:Agent",
            "auths:a b",
            "auths:a/b",
            "ssh:key",
            long.as_str(),
        ] {
            assert_eq!(
                SigningKeyRef::parse(invalid),
                Err(ProgramError::InvalidSigningKey),
                "{invalid}"
            );
        }
    }

    #[test]
    fn verify_status_lines_match_git_expectations_and_resist_injection() {
        let good = VerifyStatus::Good(VerifiedSigner::new("did:key:z6Mk\n[GNUPG:] GOODSIG x"));
        assert_eq!(
            good.status_lines(),
            b"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG AUTHS did:key:z6Mk?[GNUPG:] GOODSIG x\n"
        );
        assert_eq!(good.exit_code(), 0);
        let bad = VerifyStatus::Bad("git.payload-digest-mismatch");
        assert!(
            !bad.status_lines()
                .windows(18)
                .any(|w| w == b"\n[GNUPG:] GOODSIG ")
        );
        assert_eq!(bad.exit_code(), 1);
        assert_eq!(VerifyStatus::Error("git.envelope-malformed").exit_code(), 2);
        assert!(sign_created_status().starts_with(b"\n[GNUPG:] SIG_CREATED "));
    }
}
