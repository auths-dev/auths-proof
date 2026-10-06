//! Inputs the release builder derives for the stable launch projection.

use crate::{GitCommit, QualificationTarget, Sha256Digest};

/// Exact candidate identity, derived by the release builder rather than a
/// qualification record. A caller must read the candidate's executable and
/// maintained semantic closure to supply these facts. This value contains no
/// readiness flag and cannot authorize a gateway credential lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchCandidate {
    /// The clean candidate source commit.
    pub commit: GitCommit,
    /// The candidate's maintained gateway semantic closure.
    pub gateway_semantic_closure_sha256: Sha256Digest,
    /// The exact production deployment and candidate executable digest.
    pub target: QualificationTarget,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::{
        Keys, NOW, attestation, attestation_statement, bounded, certificate, certificate_statement,
        digest_of, index, index_entry, index_statement, record, revocation, revocation_statement,
        text, trust_root, tuple,
    };
    use crate::{
        Canonical, CapabilityResult, EVIDENCE_SCHEMA, EvidenceBody, EvidenceCase, EvidenceMember,
        EvidenceMemberKind, EvidenceResult, QualificationEvidence, QualificationInputs,
        QualificationTrustRoot, RecipeFamilyId, RecipeQualificationRecord, RecordBody, Scenario,
        VerifiedQualifications, VerifierState,
    };
    use auths_connections::{CredentialStoreKind, ProviderKind};

    struct Fixture {
        records: Vec<RecordBody>,
        evidence: Vec<QualificationEvidence>,
        expired: Option<usize>,
        revoked: Option<usize>,
    }

    impl Fixture {
        fn new(claims: &[(&str, &str, &str)], readiness: bool) -> Self {
            let mut records = Vec::new();
            let mut evidence = Vec::new();
            for (index, (family, provider, contract)) in claims.iter().enumerate() {
                let mut deployment = tuple();
                deployment.recipe_family = RecipeFamilyId::parse(*family).expect("family");
                let mut declared = crate::vectors::contract();
                declared.api_release = bounded(contract);
                deployment.provider_contract_id =
                    crate::vectors::decoded_contract(&declared).contract_id();
                let mut body = record(
                    u8::try_from(index + 1).expect("bounded fixture"),
                    deployment,
                );
                body.provider_kind = ProviderKind::parse(*provider).expect("provider");
                body.provenance.environment =
                    bounded(&format!("recipe-qualification-live-{family}"));
                let artifacts = artifacts(&body, readiness);
                body.evidence = artifacts
                    .iter()
                    .map(|artifact| EvidenceMember {
                        member: artifact.body().member,
                        result: EvidenceResult::Passed,
                        evidence_sha256: artifact.digest(),
                        cases: u32::try_from(artifact.body().cases.len()).expect("bounded cases"),
                        unauthorized_provider_entries: 0,
                    })
                    .collect();
                records.push(body);
                evidence.extend(artifacts);
            }
            Self {
                records,
                evidence,
                expired: None,
                revoked: None,
            }
        }

        fn two() -> Self {
            Self::new(
                &[
                    ("refund-v1", "stripe", "stripe contract"),
                    ("record-update-v1", "airtable", "airtable contract"),
                ],
                true,
            )
        }

        fn candidate(&self) -> LaunchCandidate {
            let record = &self.records[0];
            LaunchCandidate {
                commit: record.provenance.commit.clone(),
                gateway_semantic_closure_sha256: record.tuple.gateway_semantic_closure_sha256,
                target: record.tuple.target.clone(),
            }
        }

        fn verified(&self, omit_record: bool) -> VerifiedQualifications {
            let keys = Keys::fixed();
            let root = QualificationTrustRoot::from_body(&trust_root(&keys)).expect("root");
            let certificate = text(&certificate(certificate_statement(&keys), &keys.root));
            let mut revoked = revocation_statement(NOW);
            if let Some(index) = self.revoked {
                revoked
                    .revoked_qualifications
                    .push(self.records[index].qualification_id.clone());
            }
            let revocations = text(&revocation(revoked, &keys.root));
            let records: Vec<String> = self.records.iter().map(text).collect();
            let attestations: Vec<String> = records
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    let mut statement =
                        attestation_statement(record, u8::try_from(index + 1).expect("id"));
                    if self.expired == Some(index) {
                        statement.not_after = NOW - 1;
                    }
                    text(&attestation(statement, &keys.signer))
                })
                .collect();
            let entries = records
                .iter()
                .zip(&attestations)
                .enumerate()
                .map(|(index, (record, attestation))| {
                    index_entry(u8::try_from(index + 1).expect("id"), record, attestation)
                })
                .collect();
            let index = text(&index(index_statement(entries), &keys.signer));
            let records: Vec<&[u8]> = records
                .iter()
                .take(if omit_record { 1 } else { records.len() })
                .map(String::as_bytes)
                .collect();
            let attestations: Vec<&[u8]> = attestations.iter().map(String::as_bytes).collect();
            VerifiedQualifications::verify(
                &root,
                &QualificationInputs {
                    signer_certificate: certificate.as_bytes(),
                    revocation_list: revocations.as_bytes(),
                    release_index: index.as_bytes(),
                    records: &records,
                    attestations: &attestations,
                },
            )
        }

        fn ready(&self) -> bool {
            self.verified(false).stable_launch_ready(
                &self.candidate(),
                &self.evidence,
                NOW,
                true,
                &VerifierState::default(),
            )
        }
    }

    fn artifacts(record: &RecordBody, readiness: bool) -> Vec<QualificationEvidence> {
        EvidenceMemberKind::ALL
            .into_iter()
            .map(|member| {
                let mut cases: Vec<EvidenceCase> = Scenario::ALL
                    .into_iter()
                    .filter(|scenario| {
                        scenario.member() == member
                            && (scenario.always_required()
                                || (readiness && *scenario == Scenario::ProductionReadiness))
                    })
                    .map(|scenario| EvidenceCase {
                        id: bounded(&format!("{scenario:?}")),
                        scenario,
                        capabilities: Vec::new(),
                        unauthorized_provider_entries: 0,
                    })
                    .collect();
                for capability in &record.capabilities {
                    if capability.result == CapabilityResult::Exercised
                        && capability.capability.member() == member
                    {
                        let scenario = match capability.capability {
                            crate::CapabilityKind::Recovery => Scenario::ResponseLoss,
                            crate::CapabilityKind::ObserverRotation => Scenario::ObserverRotation,
                            _ => Scenario::DeclaredCapability,
                        };
                        cases.push(EvidenceCase {
                            id: bounded(&format!("capability-{:?}", capability.capability)),
                            scenario,
                            capabilities: vec![capability.capability],
                            unauthorized_provider_entries: 0,
                        });
                    }
                }
                cases.sort_by(|left, right| left.id.cmp(&right.id));
                Canonical::from_body(&EvidenceBody {
                    schema: EVIDENCE_SCHEMA.to_owned(),
                    member,
                    commit: record.provenance.commit.clone(),
                    tuple_sha256: record.tuple.digest().expect("tuple"),
                    cases,
                    live_effects: (member == EvidenceMemberKind::Live)
                        .then_some(record.live_effects),
                })
                .expect("evidence")
            })
            .collect()
    }

    #[test]
    fn two_signed_independent_production_claims_with_closed_evidence_are_ready() {
        let fixture = Fixture::two();
        for record in &fixture.records {
            RecipeQualificationRecord::from_body(record).expect("closed record");
        }
        assert!(fixture.ready());
    }

    #[test]
    fn each_independence_dimension_is_required() {
        for claims in [
            [
                ("refund-v1", "stripe", "stripe contract"),
                ("refund-v1", "airtable", "airtable contract"),
            ],
            [
                ("refund-v1", "stripe", "shared contract"),
                ("record-update-v1", "airtable", "shared contract"),
            ],
            [
                ("refund-v1", "stripe", "one contract"),
                ("record-update-v1", "stripe", "another contract"),
            ],
        ] {
            assert!(!Fixture::new(&claims, true).ready());
        }
    }

    #[test]
    fn missing_or_tampered_evidence_and_missing_index_members_refuse() {
        let fixture = Fixture::two();
        let verified = fixture.verified(false);
        let candidate = fixture.candidate();
        let state = VerifierState::default();
        assert!(!verified.stable_launch_ready(
            &candidate,
            &fixture.evidence[1..],
            NOW,
            true,
            &state
        ));
        let mut changed = fixture.evidence.clone();
        let mut body = changed[0].body().clone();
        body.cases[0].id = bounded("substituted-case");
        body.cases.sort_by(|left, right| left.id.cmp(&right.id));
        changed[0] = QualificationEvidence::from_body(&body).expect("changed evidence");
        assert!(!verified.stable_launch_ready(&candidate, &changed, NOW, true, &state));
        assert!(!fixture.verified(true).stable_launch_ready(
            &candidate,
            &fixture.evidence,
            NOW,
            true,
            &state
        ));
        assert!(
            !Fixture::new(
                &[
                    ("refund-v1", "stripe", "one"),
                    ("update-v1", "airtable", "two")
                ],
                false
            )
            .ready()
        );
    }

    #[test]
    fn candidate_drift_development_custody_and_untrusted_time_refuse() {
        let fixture = Fixture::two();
        let verified = fixture.verified(false);
        let candidate = fixture.candidate();
        let state = VerifierState::default();
        for changed in [
            LaunchCandidate {
                commit: GitCommit::parse("abcdef0123456789abcdef0123456789abcdef01")
                    .expect("commit"),
                ..candidate.clone()
            },
            LaunchCandidate {
                gateway_semantic_closure_sha256: digest_of("changed closure"),
                ..candidate.clone()
            },
            LaunchCandidate {
                target: crate::QualificationTarget {
                    gateway_build_sha256: digest_of("changed binary"),
                    ..candidate.target.clone()
                },
                ..candidate.clone()
            },
            LaunchCandidate {
                target: crate::QualificationTarget {
                    store_kind: crate::LifecycleStoreKind::SharedFileV1,
                    ..candidate.target.clone()
                },
                ..candidate.clone()
            },
            LaunchCandidate {
                target: crate::QualificationTarget {
                    credential_store_kind: CredentialStoreKind::LocalFileV1,
                    ..candidate.target.clone()
                },
                ..candidate.clone()
            },
        ] {
            assert!(!verified.stable_launch_ready(&changed, &fixture.evidence, NOW, true, &state));
        }
        assert!(!verified.stable_launch_ready(&candidate, &fixture.evidence, NOW, false, &state));
        assert!(!verified.stable_launch_ready(
            &candidate,
            &fixture.evidence,
            NOW + crate::MAX_REVOCATION_SECONDS + 1,
            true,
            &state
        ));
    }

    #[test]
    fn a_valid_family_entry_cannot_hide_an_expired_or_revoked_duplicate() {
        for revoked in [false, true] {
            let mut fixture = Fixture::new(
                &[
                    ("refund-v1", "stripe", "stripe contract"),
                    ("record-update-v1", "airtable", "airtable contract"),
                    ("refund-v1", "stripe", "stripe contract"),
                ],
                true,
            );
            if revoked {
                fixture.revoked = Some(2);
            } else {
                fixture.expired = Some(2);
            }
            assert!(!fixture.ready());
        }
    }
}
