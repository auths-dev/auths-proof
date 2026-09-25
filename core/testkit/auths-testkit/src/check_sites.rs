//! Inventory of the kernel's canonical-action input bounds and its
//! action-binding, validity, attenuation, and composition check sites, each
//! mapped to the corpus vectors that pin it.
//!
//! A result code can be shared by several sites (five binding clauses all
//! return `action-body-mismatch`), so coverage per code cannot show that a
//! particular check is wired in. Every site listed here names at least one
//! vector that violates exactly one fact, which this site is the first check
//! in verification order to reject; no vector is listed for two sites.
//! `cargo xtask spec-sync` checks each entry against the committed corpus
//! manifest.
//!
//! Sites are listed in the order the verifier evaluates them. A check that an
//! earlier check always decides first has no reachable vector and is not
//! listed: the delegation-edge budget dimension and the terminal budget
//! coverage inside the authority kernel, which the branch's budget chain
//! decides first, and duplicate attachment identifiers at binding, which
//! reference resolution and the canonical-action decoder reject first.

/// One check site and the vectors that pin it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckSite {
    /// Stable identifier, `<stage>.<check>`.
    pub site: &'static str,
    /// Stable result code the site returns.
    pub code: &'static str,
    /// Corpus vectors whose one violated fact this site rejects first.
    pub vectors: &'static [&'static str],
}

const fn site(
    site: &'static str,
    code: &'static str,
    vectors: &'static [&'static str],
) -> CheckSite {
    CheckSite {
        site,
        code,
        vectors,
    }
}

/// Every pinned site, in evaluation order.
pub const CHECK_SITES: &[CheckSite] = &[
    site(
        "decode.action-bytes",
        "resource-limit-exceeded",
        &["action-input-bytes-over-limit"],
    ),
    site(
        "decode.action-body-bytes",
        "resource-limit-exceeded",
        &["detached-body-bytes-over-limit"],
    ),
    site(
        "decode.attachment-bytes",
        "resource-limit-exceeded",
        &["attachment-bytes-over-limit"],
    ),
    site(
        "binding.embedded-body",
        "action-body-mismatch",
        &["embedded-body-differs"],
    ),
    site(
        "binding.profile",
        "action-body-mismatch",
        &["mismatched-profile-version"],
    ),
    site(
        "binding.media-type",
        "action-body-mismatch",
        &["action-media-type-substituted"],
    ),
    site(
        "binding.body-digest",
        "action-body-mismatch",
        &["embedded-body-swapped", "detached-body-swapped"],
    ),
    site(
        "binding.permission",
        "action-body-mismatch",
        &["action-permission-substituted"],
    ),
    site(
        "binding.requested-budget",
        "action-body-mismatch",
        &["action-budget-substituted"],
    ),
    site(
        "binding.profile-accepted",
        "unsupported-profile",
        &["unsupported-action-profile"],
    ),
    site("binding.audience", "audience-mismatch", &["wrong-audience"]),
    site(
        "binding.challenge",
        "challenge-mismatch",
        &["wrong-challenge"],
    ),
    site(
        "binding.evaluation-time",
        "action-outside-validity",
        &["evaluation-time-after-validity"],
    ),
    site(
        "binding.channel",
        "local-policy-denied",
        &["action-channel-mismatch"],
    ),
    site(
        "binding.shared-meaning",
        "plan-action-mismatch",
        &["plan-actions-differ"],
    ),
    site(
        "binding.action-extension-accepted",
        "critical-extension-unknown",
        &["unknown-action-extension"],
    ),
    site(
        "binding.action-extension-handler",
        "unsupported-critical-extension",
        &["accepted-extension-without-handler"],
    ),
    site(
        "binding.action-extension-evaluation",
        "local-policy-denied",
        &["exact-marker-extension-invalid"],
    ),
    site(
        "binding.observation-attachments",
        "resource-limit-exceeded",
        &[
            "observation-attachments-over-limit",
            "observation-bytes-over-limit",
        ],
    ),
    site(
        "binding.attachment-descriptors",
        "unused-critical-attachment",
        &["attachment-descriptor-set-mismatch"],
    ),
    site(
        "binding.attachment-missing",
        "attachment-missing",
        &["attachment-missing"],
    ),
    site(
        "binding.attachment-length",
        "attachment-length-mismatch",
        &["attachment-wrong-length"],
    ),
    site(
        "binding.attachment-digest",
        "attachment-digest-mismatch",
        &["attachment-wrong-digest"],
    ),
    site(
        "binding.attachment-opaque",
        "opaque-attachment-not-allowed",
        &["attachment-opaque-denied"],
    ),
    site(
        "binding.attachment-unused",
        "unused-critical-attachment",
        &["attachment-unused"],
    ),
    site(
        "binding.profile-policy",
        "unsupported-profile-policy",
        &["unsupported-profile-policy"],
    ),
    site(
        "branch.root-control",
        "invalid-signature",
        &["invalid-signature"],
    ),
    site(
        "branch.untrusted-root",
        "untrusted-root",
        &["untrusted-root"],
    ),
    site(
        "branch.anchor-principal-status",
        "principal-revoked",
        &["revoked-principal-status"],
    ),
    site(
        "branch.grant-status",
        "grant-revoked",
        &["revoked-grant-status"],
    ),
    site(
        "branch.subject-principal-status",
        "principal-revoked",
        &["revoked-delegate-principal-status"],
    ),
    site(
        "branch.resource-matcher",
        "unsupported-resource-matcher",
        &["unsupported-resource-matcher"],
    ),
    site(
        "branch.grant-namespace",
        "resource-namespace-mismatch",
        &["grant-permission-outside-namespace"],
    ),
    site(
        "branch.action-namespace",
        "resource-namespace-mismatch",
        &["action-resource-outside-namespace"],
    ),
    site(
        "branch.budget-edge-algebra",
        "unsupported-budget-algebra",
        &["budget-edge-algebra-unsupported"],
    ),
    site(
        "branch.budget-edge-mismatch",
        "local-policy-denied",
        &["budget-edge-algebra-mismatch"],
    ),
    site(
        "branch.budget-edge",
        "delegation-expanded",
        &["budget-widening"],
    ),
    site(
        "branch.budget-absent",
        "budget-ceiling-exceeded",
        &["action-budget-absent"],
    ),
    site(
        "branch.budget-algebra",
        "unsupported-budget-algebra",
        &["unsupported-budget-algebra"],
    ),
    site(
        "branch.budget-request-mismatch",
        "local-policy-denied",
        &["budget-request-algebra-mismatch"],
    ),
    site(
        "branch.budget-coverage",
        "budget-ceiling-exceeded",
        &["action-budget-exceeded"],
    ),
    site(
        "branch.requirement-dropped",
        "observation-requirement-dropped",
        &["observation-requirement-dropped"],
    ),
    site(
        "branch.delegation-linkage",
        "broken-grant-chain",
        &["delegation-issuer-not-subject"],
    ),
    site(
        "branch.delegation-depth",
        "delegation-expanded",
        &["depth-widening"],
    ),
    site(
        "branch.delegation-profile",
        "delegation-expanded",
        &["delegation-profile-changed"],
    ),
    site(
        "branch.delegation-permissions",
        "delegation-expanded",
        &["permission-widening"],
    ),
    site(
        "branch.delegation-validity",
        "delegation-expanded",
        &["validity-widening"],
    ),
    site(
        "branch.delegation-audiences",
        "delegation-expanded",
        &["audience-widening"],
    ),
    site(
        "branch.delegation-action-constraint",
        "delegation-expanded",
        &["delegation-action-constraint-relaxed"],
    ),
    site(
        "branch.delegation-status",
        "delegation-expanded",
        &["delegation-status-relaxed"],
    ),
    site(
        "branch.delegation-assurance",
        "delegation-expanded",
        &["assurance-policy-change"],
    ),
    site(
        "branch.delegation-extensions",
        "delegation-expanded",
        &["critical-extension-attenuation"],
    ),
    site(
        "branch.grant-extension",
        "local-policy-denied",
        &["bounded-policy-digest-mismatch"],
    ),
    site(
        "branch.coverage-linkage",
        "broken-grant-chain",
        &["action-actor-mismatch"],
    ),
    site(
        "branch.coverage-profile",
        "broken-grant-chain",
        &["action-profile-outside-grant"],
    ),
    site(
        "branch.coverage-permission",
        "permission-not-granted",
        &["action-permission-not-granted"],
    ),
    site(
        "branch.coverage-validity",
        "action-outside-validity",
        &["action-validity-expanded"],
    ),
    site(
        "branch.coverage-audience",
        "audience-mismatch",
        &["action-audience-outside-grant"],
    ),
    site(
        "branch.coverage-constraint",
        "action-constraint-mismatch",
        &["action-constraint-mismatch"],
    ),
    site(
        "branch.assurance-claim",
        "unsupported-assurance-claim",
        &["unsupported-assurance-claim"],
    ),
    site(
        "branch.assurance-requirement",
        "assurance-requirement-not-met",
        &["did-web-history-without-statement-existence"],
    ),
    site(
        "branch.observer-in-chain",
        "observer-in-authority-chain",
        &["observer-in-authority-chain"],
    ),
    site(
        "branch.observation-condition",
        "observation-condition-false",
        &["observation-condition-false"],
    ),
    site(
        "branch.observation-missing",
        "observation-missing",
        &["observation-missing"],
    ),
    site(
        "branch.observation-action-fact",
        "observation-action-fact-unavailable",
        &["observation-action-fact-unavailable"],
    ),
    site(
        "composition.authorized-branches",
        "composition-requirement-not-met",
        &["composition-branch-minimum"],
    ),
    site(
        "composition.distinct-actors",
        "composition-requirement-not-met",
        &["composition-same-actor"],
    ),
    site(
        "composition.distinct-roots",
        "composition-requirement-not-met",
        &["composition-shared-root"],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Expected, corpus};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn every_site_is_pinned_by_distinct_corpus_vectors_with_its_code() {
        let corpus: BTreeMap<_, _> = corpus()
            .into_iter()
            .map(|fixture| (fixture.name(), fixture.expected()))
            .collect();
        let mut sites = BTreeSet::new();
        let mut pinned = BTreeMap::new();
        for entry in CHECK_SITES {
            assert!(sites.insert(entry.site), "{} is listed twice", entry.site);
            assert!(!entry.vectors.is_empty(), "{} has no vector", entry.site);
            for vector in entry.vectors {
                if let Some(other) = pinned.insert(*vector, entry.site) {
                    panic!("{vector} pins both {other} and {}", entry.site);
                }
                let expected = corpus
                    .get(vector)
                    .unwrap_or_else(|| panic!("{} names absent vector {vector}", entry.site));
                let code = match expected {
                    Expected::Authorized => "authorized",
                    Expected::Denied(reason) => reason.code(),
                    Expected::Indeterminate(requirement) => requirement.code(),
                };
                assert_eq!(code, entry.code, "{vector} does not return {}", entry.site);
            }
        }
    }
}
