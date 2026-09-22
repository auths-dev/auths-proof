//! The `auths.git-signature/1` profile: one typed action per object kind.
//!
//! A commit signature and a tag signature are separate actions with separate
//! permissions. Both bind the repository, the object format, and the digest
//! of the exact unsigned payload; a tag action also binds the tag name. The
//! body is RFC 8785 canonical JSON, and decoding accepts only the byte string
//! that re-encoding the decoded value produces.

use crate::object::{ObjectFormat, ObjectKind, TagName, UnsignedPayload};
use auths_model::{
    CanonicalAction, CapabilityId, MediaType, ModelError, Permission, ProfileId, ProfileRef,
    ResourceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Profile identifier.
pub const PROFILE_ID: &str = "auths.git-signature";
/// Profile version.
pub const PROFILE_VERSION: u16 = 1;
/// Media type of the canonical action body.
pub const MEDIA_TYPE: &str = "application/vnd.auths.git-signature.v1+json";
/// Capability for signing commits.
pub const SIGN_COMMIT: &str = "git/sign-commit";
/// Capability for signing tags.
pub const SIGN_TAG: &str = "git/sign-tag";
/// Maximum repository identifier length in bytes.
pub const MAX_REPOSITORY_BYTES: usize = 256;

/// A canonical repository identifier such as `github.com/acme/app`.
///
/// Two to eight `/`-separated segments of lowercase ASCII letters, digits,
/// `.`, `_`, and `-`; no segment is empty or starts with `.`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryId(String);

impl RepositoryId {
    /// Parses a canonical repository identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::InvalidRepository`] outside the accepted form.
    pub fn parse(value: &str) -> Result<Self, ActionError> {
        let segments: Vec<&str> = value.split('/').collect();
        let valid = value.len() <= MAX_REPOSITORY_BYTES
            && (2..=8).contains(&segments.len())
            && segments.iter().all(|segment| {
                !segment.is_empty()
                    && !segment.starts_with('.')
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(ActionError::InvalidRepository);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the audience a signature for this repository names:
    /// `git://<repository>`.
    #[must_use]
    pub fn audience(&self) -> String {
        format!("git://{}", self.0)
    }
}

/// Why an action could not be built or decoded. [`ActionError::code`] returns
/// the stable result code.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActionError {
    /// The repository identifier is outside the accepted form.
    #[error("invalid git repository identifier")]
    InvalidRepository,
    /// The body is not the canonical encoding of an action.
    #[error("malformed git signature action")]
    Malformed,
    /// The action is for a different object kind.
    #[error("git signature action is for a different object kind")]
    KindMismatch,
    /// The action names a different repository.
    #[error("git signature action names a different repository")]
    RepositoryMismatch,
    /// The action names a different object format.
    #[error("git signature action names a different object format")]
    ObjectFormatMismatch,
    /// The action commits to a different payload.
    #[error("git signature action commits to a different payload")]
    PayloadDigestMismatch,
    /// The action names a different tag.
    #[error("git signature action names a different tag")]
    TagNameMismatch,
    /// A model identifier was rejected.
    #[error("invalid git signature action identifier")]
    Model,
}

impl ActionError {
    /// Returns the stable result code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRepository => "git.repository-invalid",
            Self::Malformed | Self::Model => "git.action-malformed",
            Self::KindMismatch => "git.kind-mismatch",
            Self::RepositoryMismatch => "git.repository-mismatch",
            Self::ObjectFormatMismatch => "git.object-format-mismatch",
            Self::PayloadDigestMismatch => "git.payload-digest-mismatch",
            Self::TagNameMismatch => "git.tag-name-mismatch",
        }
    }
}

impl From<ModelError> for ActionError {
    fn from(_: ModelError) -> Self {
        Self::Model
    }
}

/// Authorization to sign one exact commit payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSignatureAction {
    repository: RepositoryId,
    object_format: ObjectFormat,
    payload_digest: [u8; 32],
}

/// Authorization to sign one exact tag payload with one tag name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagSignatureAction {
    repository: RepositoryId,
    object_format: ObjectFormat,
    payload_digest: [u8; 32],
    tag_name: TagName,
}

/// The action a payload requires, chosen by the payload's own object kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitSignatureAction {
    /// A commit signature.
    Commit(CommitSignatureAction),
    /// A tag signature.
    Tag(TagSignatureAction),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Body {
    kind: String,
    object_format: String,
    payload_digest: String,
    repository: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag_name: Option<String>,
}

impl GitSignatureAction {
    /// Builds the action that authorizes signing `payload` in `repository`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Malformed`] only if a tag payload has no tag
    /// name, which [`UnsignedPayload::parse`] never produces.
    pub fn for_payload(
        repository: &RepositoryId,
        payload: &UnsignedPayload,
    ) -> Result<Self, ActionError> {
        let repository = repository.clone();
        let object_format = payload.format();
        let payload_digest = payload.digest();
        Ok(match payload.kind() {
            ObjectKind::Commit => Self::Commit(CommitSignatureAction {
                repository,
                object_format,
                payload_digest,
            }),
            ObjectKind::Tag => Self::Tag(TagSignatureAction {
                repository,
                object_format,
                payload_digest,
                tag_name: payload.tag_name().cloned().ok_or(ActionError::Malformed)?,
            }),
        })
    }

    /// Returns the object kind.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        match self {
            Self::Commit(_) => ObjectKind::Commit,
            Self::Tag(_) => ObjectKind::Tag,
        }
    }

    /// Returns the permission the action exercises:
    /// `git/sign-commit` on `git://<repository>/commits`, or
    /// `git/sign-tag` on `git://<repository>/tags`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Model`] if an identifier exceeds a model bound.
    pub fn permission(&self) -> Result<Permission, ActionError> {
        let (capability, repository, collection) = match self {
            Self::Commit(action) => (SIGN_COMMIT, &action.repository, "commits"),
            Self::Tag(action) => (SIGN_TAG, &action.repository, "tags"),
        };
        Ok(Permission::new(
            CapabilityId::parse(capability)?,
            ResourceId::parse(&format!("git://{}/{collection}", repository.as_str()))?,
        ))
    }

    /// Returns the canonical JSON body.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Malformed`] if canonical encoding fails.
    pub fn body(&self) -> Result<Vec<u8>, ActionError> {
        let (repository, object_format, payload_digest, tag_name) = match self {
            Self::Commit(action) => (
                &action.repository,
                action.object_format,
                &action.payload_digest,
                None,
            ),
            Self::Tag(action) => (
                &action.repository,
                action.object_format,
                &action.payload_digest,
                Some(action.tag_name.as_str().to_owned()),
            ),
        };
        let body = Body {
            kind: self.kind().as_str().to_owned(),
            object_format: object_format.as_str().to_owned(),
            payload_digest: hex(payload_digest),
            repository: repository.as_str().to_owned(),
            tag_name,
        };
        serde_json_canonicalizer::to_vec(&body).map_err(|_| ActionError::Malformed)
    }

    /// Returns the kernel's canonical action for this profile action.
    ///
    /// # Errors
    ///
    /// Returns an [`ActionError`] if encoding or a model bound fails.
    pub fn canonical_action(&self) -> Result<CanonicalAction, ActionError> {
        Ok(CanonicalAction::new(
            ProfileRef::new(ProfileId::parse(PROFILE_ID)?, PROFILE_VERSION)?,
            MediaType::parse(MEDIA_TYPE)?,
            self.body()?,
            self.permission()?,
            None,
        )?)
    }

    /// Compares a signed canonical action body against this expected action
    /// and names the first field that differs.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Malformed`] for a non-canonical or unparseable
    /// body, and the matching mismatch error for the first differing field in
    /// the order kind, repository, object format, payload digest, tag name.
    pub fn check_signed_body(&self, signed: &[u8]) -> Result<(), ActionError> {
        let decoded: Body = serde_json::from_slice(signed).map_err(|_| ActionError::Malformed)?;
        if serde_json_canonicalizer::to_vec(&decoded).map_err(|_| ActionError::Malformed)? != signed
        {
            return Err(ActionError::Malformed);
        }
        let expected: Body =
            serde_json::from_slice(&self.body()?).map_err(|_| ActionError::Malformed)?;
        let checks = [
            (decoded.kind == expected.kind, ActionError::KindMismatch),
            (
                decoded.repository == expected.repository,
                ActionError::RepositoryMismatch,
            ),
            (
                decoded.object_format == expected.object_format,
                ActionError::ObjectFormatMismatch,
            ),
            (
                decoded.payload_digest == expected.payload_digest,
                ActionError::PayloadDigestMismatch,
            ),
            (
                decoded.tag_name == expected.tag_name,
                ActionError::TagNameMismatch,
            ),
        ];
        match checks.into_iter().find(|(equal, _)| !equal) {
            Some((_, error)) => Err(error),
            None => Ok(()),
        }
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nmessage\n";
    const TAG: &[u8] = b"object 1111111111111111111111111111111111111111\ntype commit\ntag v1.0.0\ntagger a <a> 0 +0000\n\nrelease\n";

    fn repository() -> RepositoryId {
        RepositoryId::parse("github.com/acme/app").expect("repository")
    }

    fn action(payload: &[u8]) -> GitSignatureAction {
        let payload = UnsignedPayload::parse(payload.to_vec()).expect("payload");
        GitSignatureAction::for_payload(&repository(), &payload).expect("action")
    }

    #[test]
    fn actions_bind_kind_repository_format_digest_and_tag() {
        let commit = action(COMMIT);
        let body = String::from_utf8(commit.body().expect("body")).expect("utf-8");
        assert!(body.starts_with(r#"{"kind":"commit","object_format":"sha1","payload_digest":""#));
        assert!(body.ends_with(r#"","repository":"github.com/acme/app"}"#));
        let permission = commit.permission().expect("permission");
        assert_eq!(permission.capability().as_str(), SIGN_COMMIT);
        assert_eq!(
            permission.resource().as_str(),
            "git://github.com/acme/app/commits"
        );

        let tag = action(TAG);
        let body = String::from_utf8(tag.body().expect("body")).expect("utf-8");
        assert!(body.ends_with(r#","repository":"github.com/acme/app","tag_name":"v1.0.0"}"#));
        let permission = tag.permission().expect("permission");
        assert_eq!(permission.capability().as_str(), SIGN_TAG);
        assert_eq!(
            permission.resource().as_str(),
            "git://github.com/acme/app/tags"
        );

        let canonical = tag.canonical_action().expect("canonical");
        assert_eq!(canonical.profile().id().as_str(), PROFILE_ID);
        assert_eq!(canonical.media_type().as_str(), MEDIA_TYPE);
    }

    #[test]
    fn signed_bodies_are_checked_field_by_field_with_stable_codes() {
        let commit = action(COMMIT);
        let tag = action(TAG);
        let other_repository = GitSignatureAction::for_payload(
            &RepositoryId::parse("github.com/acme/other").expect("repository"),
            &UnsignedPayload::parse(COMMIT.to_vec()).expect("payload"),
        )
        .expect("action");
        let mut other_message = COMMIT.to_vec();
        other_message.push(b'!');
        let other_digest = action(&other_message);

        assert_eq!(
            commit.check_signed_body(&commit.body().expect("body")),
            Ok(())
        );
        let cases = [
            (&tag, commit.body(), "git.kind-mismatch"),
            (&commit, other_repository.body(), "git.repository-mismatch"),
            (&commit, other_digest.body(), "git.payload-digest-mismatch"),
        ];
        for (expected, signed, code) in cases {
            let error = expected
                .check_signed_body(&signed.expect("body"))
                .expect_err(code);
            assert_eq!(error.code(), code);
        }
        let format = String::from_utf8(commit.body().expect("body"))
            .expect("utf-8")
            .replace("\"sha1\"", "\"sha256\"");
        assert_eq!(
            commit
                .check_signed_body(format.as_bytes())
                .map_err(ActionError::code),
            Err("git.object-format-mismatch")
        );
        let renamed = String::from_utf8(tag.body().expect("body"))
            .expect("utf-8")
            .replace("v1.0.0", "v1.0.1");
        assert_eq!(
            tag.check_signed_body(renamed.as_bytes())
                .map_err(ActionError::code),
            Err("git.tag-name-mismatch")
        );
    }

    #[test]
    fn signed_bodies_must_be_canonical_and_closed() {
        let commit = action(COMMIT);
        let body = String::from_utf8(commit.body().expect("body")).expect("utf-8");
        for malformed in [
            body.replacen('{', "{ ", 1),
            body.replacen("\"kind\":\"commit\",", "", 1),
            body.replacen('}', ",\"extra\":1}", 1),
            body.replacen(
                "\"kind\":\"commit\",\"object_format\":\"sha1\",",
                "\"object_format\":\"sha1\",\"kind\":\"commit\",",
                1,
            ),
            String::from("not json"),
        ] {
            assert_eq!(
                commit
                    .check_signed_body(malformed.as_bytes())
                    .map_err(ActionError::code),
                Err("git.action-malformed"),
                "{malformed}"
            );
        }
    }

    #[test]
    fn repository_identifiers_are_closed() {
        for valid in [
            "github.com/acme/app",
            "gitlab.com/group/sub/project",
            "host/repo",
        ] {
            assert!(RepositoryId::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "github.com",
            "github.com/Acme/app",
            "github.com//app",
            "github.com/acme/.app",
            "github.com/acme/app/",
            "https://github.com/acme/app",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert_eq!(
                RepositoryId::parse(invalid),
                Err(ActionError::InvalidRepository),
                "{invalid}"
            );
        }
    }
}
