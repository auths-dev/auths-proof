//! Stages of a protected run that need no provider meaning: the
//! differential comparison of a family's oracle with a gateway, the
//! redaction scan, the freshness check of signed inputs, and signer
//! rotation.
//!
//! Each stage returns the cases it ran. A stage never decides what a
//! provider did: the oracle and the gateway are the caller's arguments, and
//! a scan compares bytes.

use crate::{
    CaseReport, CertificateRequest, IssuanceError, QualificationProposal, RecordDraft,
    ReleaseSigner, RootSigner, SigningSeed, evidence,
};
use auths_recipe_qualification::{
    CapabilityKind, EvidenceMemberKind, GitCommit, LiveEffects, QualificationFormatError,
    QualificationInputs, QualificationRefusal, QualificationReleaseIndex,
    QualificationRevocationList, QualificationRootId, QualificationSignerCertificate,
    QualificationSignerId, QualificationTrustRoot, QualificationTuple,
    RecipeQualificationAttestation, RecipeQualificationState, Scenario, VerifiedQualifications,
    VerifierState,
};
use base64ct::{Base64Unpadded, Base64UrlUnpadded, Encoding as _};

/// The shortest canary a redaction scan accepts. A shorter one would match
/// by chance.
pub const MIN_CANARY_BYTES: usize = 8;

/// Runs a family's corpus through its pure oracle and through a gateway and
/// reports, per corpus member, whether the two verdicts are equal.
///
/// `accepts` says whether a verdict is an acceptance, so each case is
/// recorded as an agreed acceptance or an agreed rejection: a corpus that
/// exercises only one of the two does not close the wall. The oracle is
/// test-only code the family owns. It is an argument here so that no
/// gateway build contains one.
///
/// # Errors
///
/// Returns [`IssuanceError::Format`] when a corpus member's identifier is
/// not bounded printable text.
pub fn differential<Member, Verdict: PartialEq>(
    corpus: &[Member],
    identifier: impl Fn(&Member) -> String,
    oracle: impl Fn(&Member) -> Verdict,
    gateway: impl Fn(&Member) -> Verdict,
    accepts: impl Fn(&Verdict) -> bool,
) -> Result<Vec<CaseReport>, IssuanceError> {
    corpus
        .iter()
        .map(|member| {
            let expected = oracle(member);
            let scenario = if accepts(&expected) {
                Scenario::OracleAccepts
            } else {
                Scenario::OracleRejects
            };
            CaseReport::new(&identifier(member), scenario, expected == gateway(member))
        })
        .collect()
}

/// What kind of output a scanned source is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    /// A log.
    Log,
    /// A trace.
    Trace,
    /// A metric export.
    Metric,
    /// A support bundle.
    SupportBundle,
    /// An evidence artifact.
    Evidence,
}

impl SourceKind {
    /// Parses the kind's token.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "log" => Some(Self::Log),
            "trace" => Some(Self::Trace),
            "metric" => Some(Self::Metric),
            "support-bundle" => Some(Self::SupportBundle),
            "evidence" => Some(Self::Evidence),
            _ => None,
        }
    }

    const fn scenario(self) -> Scenario {
        match self {
            Self::Log => Scenario::LogScan,
            Self::Trace => Scenario::TraceScan,
            Self::Metric => Scenario::MetricScan,
            Self::SupportBundle => Scenario::SupportBundleScan,
            Self::Evidence => Scenario::EvidenceScan,
        }
    }
}

/// One named byte source a redaction scan reads: a log, a trace, a metric
/// export, a support bundle, or an evidence artifact.
#[derive(Clone, Copy, Debug)]
pub struct ScanSource<'source> {
    /// What kind of output the source is.
    pub kind: SourceKind,
    /// The case identifier the source is reported under.
    pub name: &'source str,
    /// The source's bytes.
    pub bytes: &'source [u8],
}

/// Every spelling of `canary` a source must not contain: the bytes
/// themselves, both hexadecimal cases, and both base64 alphabets at each of
/// the three alignments an embedding can have.
fn spellings(canary: &[u8]) -> Vec<Vec<u8>> {
    let mut spellings = vec![
        canary.to_vec(),
        hex::encode(canary).into_bytes(),
        hex::encode_upper(canary).into_bytes(),
    ];
    for lead in 0..3_usize {
        let mut padded = vec![0_u8; lead];
        padded.extend_from_slice(canary);
        // Characters that depend only on the canary: skip those the lead
        // bytes reach, and drop a final character that later bytes share.
        let skipped = [0, 2, 3][lead];
        let whole = padded.len() * 8 / 6;
        for encoded in [
            Base64Unpadded::encode_string(&padded),
            Base64UrlUnpadded::encode_string(&padded),
        ] {
            if let Some(stable) = encoded.as_bytes().get(skipped..whole) {
                spellings.push(stable.to_vec());
            }
        }
    }
    spellings
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Scans every source for every planted canary, in each spelling a secret
/// commonly leaks in. A source passes when it contains none.
///
/// # Errors
///
/// Returns [`IssuanceError::CaseFailed`] when no canary or no source is
/// given, or a canary is shorter than [`MIN_CANARY_BYTES`]: a scan that
/// could not have found anything is not evidence. Returns
/// [`IssuanceError::Format`] when a source's name is not bounded printable
/// text.
pub fn redaction(
    canaries: &[&[u8]],
    sources: &[ScanSource<'_>],
) -> Result<Vec<CaseReport>, IssuanceError> {
    if canaries.is_empty()
        || sources.is_empty()
        || canaries
            .iter()
            .any(|canary| canary.len() < MIN_CANARY_BYTES)
    {
        return Err(IssuanceError::CaseFailed);
    }
    let forbidden: Vec<Vec<u8>> = canaries
        .iter()
        .flat_map(|canary| spellings(canary))
        .collect();
    sources
        .iter()
        .map(|source| {
            let clean = !forbidden
                .iter()
                .any(|spelling| contains(source.bytes, spelling));
            CaseReport::new(source.name, source.kind.scenario(), clean)
        })
        .collect()
}

fn expect(
    id: &str,
    verified: &VerifiedQualifications,
    deployment: &QualificationTuple,
    state: &VerifierState,
    (now, clock_trusted): (u64, bool),
    expected: Option<QualificationRefusal>,
) -> Result<CaseReport, IssuanceError> {
    let verdict = verified.evaluate(deployment, now, clock_trusted, state);
    let passed = verdict.refusal == expected && verdict.permits_lease() == expected.is_none();
    CaseReport::new(id, Scenario::Freshness, passed)
}

/// Checks that signed inputs which qualify `deployment` at `now` stop doing
/// so exactly where their signed time fields say: under an untrusted clock,
/// one second before the latest signed issue time, and one second after the
/// revocation list's next update.
///
/// # Errors
///
/// Returns [`IssuanceError::Format`] when an input does not decode.
pub fn freshness(
    root: &QualificationTrustRoot,
    inputs: &QualificationInputs<'_>,
    deployment: &QualificationTuple,
    state: &VerifierState,
    now: u64,
) -> Result<Vec<CaseReport>, IssuanceError> {
    let certificate =
        QualificationSignerCertificate::from_canonical_json(inputs.signer_certificate)?;
    let list = QualificationRevocationList::from_canonical_json(inputs.revocation_list)?;
    let index = QualificationReleaseIndex::from_canonical_json(inputs.release_index)?;
    let mut latest_issue = certificate
        .body()
        .statement
        .issued_at
        .max(list.body().statement.issued_at)
        .max(index.body().statement.issued_at);
    for attestation in inputs.attestations {
        let attestation = RecipeQualificationAttestation::from_canonical_json(attestation)?;
        latest_issue = latest_issue.max(attestation.body().statement.issued_at);
    }
    let behind = latest_issue
        .checked_sub(1)
        .ok_or(QualificationFormatError::InvalidTimeWindow)?;
    let past_update = list.body().statement.next_update + 1;
    let verified = VerifiedQualifications::verify(root, inputs);
    let case = |id, at, expected| expect(id, &verified, deployment, state, at, expected);
    Ok(vec![
        case("freshness-current-inputs-qualify", (now, true), None)?,
        case(
            "freshness-untrusted-clock-refuses",
            (now, false),
            Some(QualificationRefusal::ClockUntrusted),
        )?,
        case(
            "freshness-clock-behind-issue-refuses",
            (behind, true),
            Some(QualificationRefusal::ClockUntrusted),
        )?,
        case(
            "freshness-past-next-update-refuses",
            (past_update, true),
            Some(QualificationRefusal::RevocationStale),
        )?,
    ])
}

/// One signer's release, as the bytes a verifier reads.
struct Release {
    certificate: Vec<u8>,
    index: Vec<u8>,
    attestation: Vec<u8>,
}

impl Release {
    fn issue(
        signer: &ReleaseSigner,
        proposal: &QualificationProposal,
        now: u64,
    ) -> Result<Self, IssuanceError> {
        let record = proposal.record().body();
        let attestation = signer.attest(proposal, now, record.not_before, record.not_after)?;
        let index = signer.index(now, &[(proposal.record(), &attestation)])?;
        Ok(Self {
            certificate: signer.certificate().canonical_bytes().to_vec(),
            index: index.canonical_bytes().to_vec(),
            attestation: attestation.canonical_bytes().to_vec(),
        })
    }

    fn verified(
        &self,
        root: &QualificationTrustRoot,
        list: &QualificationRevocationList,
        proposal: &QualificationProposal,
    ) -> VerifiedQualifications {
        VerifiedQualifications::verify(
            root,
            &QualificationInputs {
                signer_certificate: &self.certificate,
                revocation_list: list.canonical_bytes(),
                release_index: &self.index,
                records: &[proposal.record().canonical_bytes()],
                attestations: &[&self.attestation],
            },
        )
    }
}

const HOUR: u64 = 60 * 60;

/// Rotates a release signer over `proposal` under a root made for this
/// stage and discarded with it, and reports whether each trust transition
/// held: the successor attests the record after its evidence closure is
/// re-verified, a revoked predecessor is refused and stays refused when a
/// later list omits it, the successor is unaffected, a record whose evidence
/// does not close is not re-signed, and a certificate a release signer
/// signed is not accepted.
///
/// No provider is called. The stage's keys never leave the call.
///
/// # Errors
///
/// Returns [`IssuanceError::Window`] when `now` is outside the record's
/// window, [`IssuanceError::Randomness`] when no key can be drawn, and
/// otherwise what issuing under the stage's root returns.
pub fn signer_rotation(
    proposal: &QualificationProposal,
    now: u64,
) -> Result<Vec<CaseReport>, IssuanceError> {
    let record = proposal.record().body();
    if now < record.not_before || now >= record.not_after {
        return Err(IssuanceError::Window);
    }
    let malformed = |_| QualificationFormatError::Malformed;
    let root = RootSigner::create(
        &SigningSeed::generate()?,
        QualificationRootId::parse("rotation-stage-root").map_err(malformed)?,
    )?;
    let certified = |authority: &RootSigner, name: &str| {
        let seed = SigningSeed::generate()?;
        let certificate = authority.certify(CertificateRequest {
            signer_id: QualificationSignerId::parse(name).map_err(malformed)?,
            public_key_b64: seed.public_key(),
            issued_at: record.not_before,
            not_before: record.not_before,
            not_after: record.not_after,
        })?;
        Ok::<_, IssuanceError>((seed, certificate))
    };
    let (predecessor_seed, predecessor_certificate) = certified(&root, "rotation-predecessor")?;
    let predecessor = ReleaseSigner::open(&predecessor_seed, predecessor_certificate)?;
    let (successor_seed, successor_certificate) = certified(&root, "rotation-successor")?;
    let successor = ReleaseSigner::open(&successor_seed, successor_certificate)?;
    let old = Release::issue(&predecessor, proposal, now)?;
    let new = Release::issue(&successor, proposal, now)?;
    let list = |sequence, revoked: &[&ReleaseSigner]| {
        root.revoke(
            sequence,
            now,
            now + HOUR,
            revoked
                .iter()
                .map(|signer| signer.certificate().body().statement.signer_id.clone())
                .collect(),
            Vec::new(),
        )
    };
    let pinned = root.trust_root();
    let deployment = &record.tuple;
    let mut state = VerifierState::default();
    let mut cases = Vec::new();
    let mut check =
        |id: &str, verified: &VerifiedQualifications, state: &mut VerifierState, expected| {
            verified.remember(state);
            let verdict = verified.evaluate(deployment, now, true, state);
            CaseReport::new(id, Scenario::SignerRotation, verdict.state == expected)
                .map(|case| cases.push(case))
        };
    let clean = list(1, &[])?;
    check(
        "rotation-predecessor-qualifies",
        &old.verified(pinned, &clean, proposal),
        &mut state,
        RecipeQualificationState::Qualified,
    )?;
    check(
        "rotation-successor-attests-closed-record",
        &new.verified(pinned, &clean, proposal),
        &mut state,
        RecipeQualificationState::Qualified,
    )?;
    let revoking = list(2, &[&predecessor])?;
    check(
        "rotation-revoked-predecessor-is-refused",
        &old.verified(pinned, &revoking, proposal),
        &mut state,
        RecipeQualificationState::Revoked,
    )?;
    check(
        "rotation-successor-survives-predecessor-revocation",
        &new.verified(pinned, &revoking, proposal),
        &mut state,
        RecipeQualificationState::Qualified,
    )?;
    let omitting = list(3, &[])?;
    check(
        "rotation-revocation-outlives-its-list",
        &old.verified(pinned, &omitting, proposal),
        &mut state,
        RecipeQualificationState::Revoked,
    )?;
    cases.push(self_certification(
        &predecessor_seed,
        pinned,
        &omitting,
        proposal,
        now,
    )?);
    cases.push(open_evidence(proposal)?);
    Ok(cases)
}

/// A release signer's key under the root's name is what a signer that tried
/// to certify its own successor would produce. Nothing it certifies
/// qualifies.
fn self_certification(
    signer_seed: &SigningSeed,
    pinned: &QualificationTrustRoot,
    list: &QualificationRevocationList,
    proposal: &QualificationProposal,
    now: u64,
) -> Result<CaseReport, IssuanceError> {
    let record = proposal.record().body();
    let impostor = RootSigner::create(signer_seed, pinned.body().root_id.clone())?;
    let seed = SigningSeed::generate()?;
    let certificate = impostor.certify(CertificateRequest {
        signer_id: QualificationSignerId::parse("rotation-self-certified")
            .map_err(|_| QualificationFormatError::Malformed)?,
        public_key_b64: seed.public_key(),
        issued_at: record.not_before,
        not_before: record.not_before,
        not_after: record.not_after,
    })?;
    let release = Release::issue(&ReleaseSigner::open(&seed, certificate)?, proposal, now)?;
    let verdict = release.verified(pinned, list, proposal).evaluate(
        &record.tuple,
        now,
        true,
        &VerifierState::default(),
    );
    CaseReport::new(
        "rotation-signer-cannot-certify",
        Scenario::SignerRotation,
        verdict.state == RecipeQualificationState::Unqualified,
    )
}

/// A record presented without all of its evidence is not a proposal, so no
/// signer can be asked to sign it again.
fn open_evidence(proposal: &QualificationProposal) -> Result<CaseReport, IssuanceError> {
    let evidence: Vec<&[u8]> = proposal
        .evidence()
        .iter()
        .skip(1)
        .map(auths_recipe_qualification::Canonical::canonical_bytes)
        .collect();
    let open = QualificationProposal::from_parts(proposal.record().canonical_bytes(), &evidence);
    CaseReport::new(
        "rotation-open-evidence-is-not-resigned",
        Scenario::SignerRotation,
        matches!(open, Err(IssuanceError::Closure(_))),
    )
}

/// The capabilities a placeholder candidate declares not applicable.
pub(crate) const PLACEHOLDER_ABSENT: [CapabilityKind; 2] = [
    CapabilityKind::AccountBinding,
    CapabilityKind::ObserverRotation,
];

/// One passing case per scenario of `member` that every record needs, and
/// one per capability the member shows. The cases stand for no run: they
/// fill a candidate whose only use is to exercise the release machinery.
///
/// # Panics
///
/// Never: the identifiers are fixed bounded text.
#[must_use]
pub fn placeholder_cases(member: EvidenceMemberKind) -> Vec<CaseReport> {
    let case = |name: String, scenario| {
        CaseReport::new(&name, scenario, true)
            .unwrap_or_else(|_| unreachable!("a fixed identifier is bounded text"))
    };
    let mut cases: Vec<CaseReport> = Scenario::ALL
        .into_iter()
        .filter(|scenario| scenario.member() == member && scenario.always_required())
        .map(|scenario| {
            let mut reported = case(format!("scenario-{scenario:?}"), scenario);
            if scenario == Scenario::ResponseLoss {
                reported.capabilities = vec![CapabilityKind::Recovery];
            }
            reported
        })
        .collect();
    if member == EvidenceMemberKind::Live {
        for capability in CapabilityKind::ALL {
            if Scenario::DeclaredCapability.may_show(capability)
                && !PLACEHOLDER_ABSENT.contains(&capability)
            {
                let mut reported = case(
                    format!("capability-{capability:?}"),
                    Scenario::DeclaredCapability,
                );
                reported.capabilities = vec![capability];
                cases.push(reported);
            }
        }
    }
    cases
}

/// A closed proposal for `tuple` whose evidence is placeholder cases, valid
/// for 90 days from two hours before `now`.
pub(crate) fn synthetic_proposal(
    index: u8,
    tuple: &QualificationTuple,
    now: u64,
) -> Result<QualificationProposal, IssuanceError> {
    const COMMIT: &str = "0000000000000000000000000000000000000000";
    let digest = |byte: &str| byte.repeat(32);
    let start = now
        .checked_sub(2 * HOUR)
        .ok_or(QualificationFormatError::InvalidTimeWindow)?;
    let draft: RecordDraft = serde_json::from_value(serde_json::json!({
        "qualification_id": format!("qlf_{}", hex::encode([index; 16])),
        "provider_kind": "placeholder",
        "tuple": tuple,
        "not_before": start,
        "not_after": start + 90 * 24 * HOUR,
        "provenance": {
            "repository": "placeholder",
            "commit": COMMIT,
            "workflow": "placeholder",
            "environment": "placeholder",
        },
        "source_closure_sha256": digest("00"),
        "generated_artifacts_sha256": digest("00"),
        "installed_packages": [
            {"name": "placeholder", "version": "0", "sha256": digest("00")},
        ],
        "recipe_decision_record_sha256": digest("00"),
        "corpus_manifest_sha256": digest("00"),
        "not_applicable": [
            {"capability": "account-binding", "reason": "a placeholder candidate"},
            {"capability": "observer-rotation", "reason": "a placeholder candidate"},
        ],
        "provider_resources": ["placeholder"],
        "custody_descriptor": "placeholder",
        "store_descriptor": "placeholder",
        "residual_assumptions": [],
        "excluded_claims": ["everything: this record stands for no run"],
    }))
    .map_err(|_| QualificationFormatError::Malformed)?;
    let commit = GitCommit::parse(COMMIT).map_err(|_| QualificationFormatError::Malformed)?;
    let artifacts = EvidenceMemberKind::ALL
        .into_iter()
        .map(|member| {
            let live = (member == EvidenceMemberKind::Live).then_some(LiveEffects {
                entered: 1,
                confirmed_by_read_back: 1,
            });
            evidence(member, &commit, tuple, placeholder_cases(member), live)
        })
        .collect::<Result<Vec<_>, _>>()?;
    QualificationProposal::assemble(draft, artifacts)
}

/// Runs the signer-rotation and freshness stages for `tuple` on the release
/// machinery of this build.
///
/// The stages need a closed record to sign and none exists before the
/// run's own record is assembled, so they use a placeholder candidate for
/// the same tuple under a root made for the stage. What they show is that
/// this build's issuance and verification keep every trust transition and
/// enforce every signed time bound; they show nothing about a provider.
///
/// # Errors
///
/// Returns what [`signer_rotation`] and [`freshness`] return.
pub fn trust_transitions(
    tuple: &QualificationTuple,
    now: u64,
) -> Result<Vec<CaseReport>, IssuanceError> {
    let candidate = synthetic_proposal(0, tuple, now)?;
    let mut cases = signer_rotation(&candidate, now)?;
    let record = candidate.record().body();
    let malformed = |_| QualificationFormatError::Malformed;
    let root = RootSigner::create(
        &SigningSeed::generate()?,
        QualificationRootId::parse("freshness-stage-root").map_err(malformed)?,
    )?;
    let seed = SigningSeed::generate()?;
    let certificate = root.certify(CertificateRequest {
        signer_id: QualificationSignerId::parse("freshness-stage-signer").map_err(malformed)?,
        public_key_b64: seed.public_key(),
        issued_at: record.not_before,
        not_before: record.not_before,
        not_after: record.not_after,
    })?;
    let signer = ReleaseSigner::open(&seed, certificate)?;
    // Everything is issued a minute before `now`, so the stage can also
    // step behind the issue time without leaving the record's window.
    let issued = now - 60;
    let release = Release::issue(&signer, &candidate, issued)?;
    let list = root.revoke(1, issued, now + HOUR, Vec::new(), Vec::new())?;
    cases.extend(freshness(
        root.trust_root(),
        &QualificationInputs {
            signer_certificate: &release.certificate,
            revocation_list: list.canonical_bytes(),
            release_index: &release.index,
            records: &[candidate.record().canonical_bytes()],
            attestations: &[&release.attestation],
        },
        tuple,
        &VerifierState::default(),
        now,
    )?);
    Ok(cases)
}
