//! Bounded-policy commitment corpus vectors.
//!
//! A root grants an intermediary a scope that may carry the
//! `bounded-policy-commitment-v1` critical extension, and the intermediary
//! delegates to the actor. Core validates the extension's shape and applies
//! its link law: a child keeps a bound only by linking the digest of its
//! parent's exact extension bytes, and may add a bound to an unbounded parent
//! only without a link. Whether the child's policy is tighter is the product
//! layer's decision and is not exercised here.
//!
//! Encodings a valid model cannot represent are derived from canonical
//! encodings by replacing exact byte runs, so every vector still comes from
//! this generator.

use super::*;
use auths_codec::{bounded_policy_digest, bounded_policy_link, encode_bounded_policy_commitment};
use auths_model::{
    BoundedPolicyCommitment, MAX_BOUNDED_POLICY_BYTES, PolicyCommitment, PolicyIdentifier,
};
use auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1;

const POLICY_TYPE: &str = "auths.test.bounded-policy/1";
const CANONICALIZATION: &str = "auths.test.canonical/1";
const EVALUATOR: &str = "auths.test.bounded-evaluate/1";

fn commitment(policy: &[u8]) -> PolicyCommitment {
    PolicyCommitment::new(
        PolicyIdentifier::parse(POLICY_TYPE, 128).expect("policy type"),
        1,
        PolicyIdentifier::parse(CANONICALIZATION, 64).expect("canonicalization"),
        bounded_policy_digest(policy).expect("policy digest"),
        PolicyIdentifier::parse(EVALUATOR, 128).expect("evaluator"),
    )
    .expect("commitment")
}

fn body(policy: &[u8], parent: Option<Digest>) -> Vec<u8> {
    encode_bounded_policy_commitment(
        &BoundedPolicyCommitment::new(commitment(policy), policy.to_vec(), parent)
            .expect("bounded body"),
    )
    .expect("canonical body")
}

fn link(parent: &[u8]) -> Digest {
    bounded_policy_link(parent).expect("link")
}

fn delegation(
    name: &'static str,
    parent: Option<Vec<u8>>,
    child: Option<Vec<u8>>,
    expected: Expected,
) -> CorpusFixture {
    extension_delegation(
        name,
        BOUNDED_POLICY_COMMITMENT_EXTENSION_V1,
        parent,
        child,
        expected,
    )
}

fn replace_once(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let position = bytes
        .windows(from.len())
        .position(|window| window == from)
        .expect("pattern present");
    assert_eq!(
        bytes
            .windows(from.len())
            .filter(|window| *window == from)
            .count(),
        1,
        "pattern is unique"
    );
    let mut replaced = bytes[..position].to_vec();
    replaced.extend_from_slice(to);
    replaced.extend_from_slice(&bytes[position + from.len()..]);
    replaced
}

/// A canonical body whose policy byte string is one byte past its bound. The
/// 4096-byte string header `59 10 00` becomes `59 10 01` and one byte is
/// appended to the string.
fn over_limit_policy() -> Vec<u8> {
    let policy = vec![0x5a; MAX_BOUNDED_POLICY_BYTES];
    let at_limit = body(&policy, None);
    let mut header_and_policy = vec![0x59, 0x10, 0x00];
    header_and_policy.extend_from_slice(&policy);
    let mut longer = vec![0x59, 0x10, 0x01];
    longer.extend_from_slice(&policy);
    longer.push(0x5a);
    replace_once(&at_limit, &header_and_policy, &longer)
}

/// Bounded-policy link-law and shape vectors, in corpus order.
pub(crate) fn bounded_policy_vectors() -> Vec<CorpusFixture> {
    let parent = body(b"parent-bound", None);
    let expanded = Expected::Denied(DenialReason::DelegationExpanded);
    let invalid = Expected::Denied(DenialReason::LocalPolicyDenied);
    let wrong_digest = {
        let mut commitment_bytes = body(b"parent-bound", None);
        let digest = bounded_policy_digest(b"parent-bound").expect("digest");
        let other = bounded_policy_digest(b"another-bound").expect("digest");
        commitment_bytes = replace_once(&commitment_bytes, digest.as_bytes(), other.as_bytes());
        commitment_bytes
    };
    vec![
        delegation(
            "bounded-policy-link-correct",
            Some(parent.clone()),
            Some(body(b"child-bound", Some(link(&parent)))),
            Expected::Authorized,
        ),
        delegation(
            "bounded-policy-link-wrong",
            Some(parent.clone()),
            Some(body(
                b"child-bound",
                Some(link(&body(b"another-bound", None))),
            )),
            expanded,
        ),
        delegation(
            "bounded-policy-link-missing",
            Some(parent.clone()),
            Some(body(b"child-bound", None)),
            expanded,
        ),
        delegation(
            "bounded-policy-dropped",
            Some(parent.clone()),
            None,
            expanded,
        ),
        delegation(
            "bounded-policy-added-to-unbounded",
            None,
            Some(body(b"child-bound", None)),
            Expected::Authorized,
        ),
        delegation(
            "bounded-policy-added-with-link",
            None,
            Some(body(b"child-bound", Some(link(&parent)))),
            expanded,
        ),
        delegation(
            "bounded-policy-digest-mismatch",
            Some(wrong_digest),
            None,
            invalid,
        ),
        delegation(
            "bounded-policy-identifier-invalid",
            Some(replace_once(
                &parent,
                POLICY_TYPE.as_bytes(),
                b"auths.test bounded-policy/1",
            )),
            None,
            invalid,
        ),
        delegation(
            "bounded-policy-at-limit",
            Some(body(&vec![0x5a; MAX_BOUNDED_POLICY_BYTES], None)),
            Some(body(
                b"child-bound",
                Some(link(&body(&vec![0x5a; MAX_BOUNDED_POLICY_BYTES], None))),
            )),
            Expected::Authorized,
        ),
        delegation(
            "bounded-policy-over-limit",
            Some(over_limit_policy()),
            None,
            Expected::Denied(DenialReason::ResourceLimitExceeded),
        ),
    ]
}
