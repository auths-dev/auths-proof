//! Stages of a protected run that need no provider meaning: the
//! differential comparison of a family's oracle with a gateway, the
//! redaction scan, the freshness check of signed inputs, and signer
//! rotation.
//!
//! Each stage returns the cases it ran. A stage never decides what a
//! provider did: the oracle and the gateway are the caller's arguments, and
//! a scan compares bytes.

use crate::{
    CaseReport, CertificateRequest, IssuanceError, QualificationProposal, ReleaseSigner,
    RootSigner, SigningSeed,
};
use auths_recipe_qualification::{
    QualificationFormatError, QualificationInputs, QualificationRefusal, QualificationReleaseIndex,
    QualificationRevocationList, QualificationRootId, QualificationSignerCertificate,
    QualificationSignerId, QualificationTrustRoot, QualificationTuple,
    RecipeQualificationAttestation, RecipeQualificationState, VerifiedQualifications,
    VerifierState, WallRow,
};
use base64ct::{Base64Unpadded, Base64UrlUnpadded, Encoding as _};

/// The shortest canary a redaction scan accepts. A shorter one would match
/// by chance.
pub const MIN_CANARY_BYTES: usize = 8;

/// Runs a family's corpus through its pure oracle and through a gateway and
/// reports, per corpus member, whether the two verdicts are equal.
///
/// The oracle is test-only code the family owns. It is an argument here so
/// that no gateway build contains one.
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
) -> Result<Vec<CaseReport>, IssuanceError> {
    corpus
        .iter()
        .map(|member| {
            CaseReport::new(
                &identifier(member),
                WallRow::OracleAgreement,
                oracle(member) == gateway(member),
            )
        })
        .collect()
}

/// One named byte source a redaction scan reads: a log, a trace, a metric
/// export, a support bundle, or an evidence artifact.
#[derive(Clone, Copy, Debug)]
pub struct ScanSource<'source> {
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
            CaseReport::new(source.name, WallRow::Redaction, clean)
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
    CaseReport::new(id, WallRow::Rotation, passed)
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
            CaseReport::new(id, WallRow::Rotation, verdict.state == expected)
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
        WallRow::Rotation,
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
        WallRow::Rotation,
        matches!(open, Err(IssuanceError::Closure(_))),
    )
}
