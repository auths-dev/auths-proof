//! Original native control inputs and historical replay. Stored contexts and
//! clock samples are evidence, not trust roots or new execution authority.
use super::{
    EngagementConfiguration, EngagementConfigurationError as Error,
    EngagementConfigurationSnapshot, EnrollmentInvocation, EnrollmentTree, ParentEnrollmentPins,
    ParticipantEnrollmentProofs, RootEnrollmentProofs, blob,
};
use crate::participant_enrollment::{
    EnrollmentResourceWitness, MAX_PARTICIPANTS, MAX_SCOPES, bounded_invocations,
};
use auths_model::TrustedContext;
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::{Zeroize as _, Zeroizing};

const INPUT_SCHEMA: &str = "auths.engagement-control-evidence/1";
const AUDIT_SCHEMA: &str = "auths.engagement-audit/1";
/// Maximum canonical private control evidence. Reserve 1 KiB before base64
/// expansion so every accepted input fits the existing 8 MiB app frame with
/// its fixed schema/envelope, without increasing the shared IPC limit.
pub const MAX_ENGAGEMENT_CONTROL_BYTES: usize = 6 * 1_048_576 - 1_024;
pub(super) const MAX_EVENTS: usize = MAX_PARTICIPANTS * 2;
const MAX_TOTAL_BYTES: usize = 256 * 1_048_576;
const MAX_EXPORT_BYTES: usize = MAX_TOTAL_BYTES * 3 / 2;

fn bounded_sequence<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const MAX: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> serde::de::Visitor<'de> for Visitor<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX} bounded audit items")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while result.len() < MAX {
                match seq.next_element()? {
                    Some(value) => result.push(value),
                    None => return Ok(result),
                }
            }
            // Do not materialize another private proof/blob beyond the bound.
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("audit item limit exceeded"));
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Visitor::<T, MAX>(std::marker::PhantomData))
}
fn deserialize_resources<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<Resource>, D::Error> {
    bounded_sequence::<D, Resource, MAX_SCOPES>(d)
}
pub(super) fn deserialize_events<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<Event>, D::Error> {
    bounded_sequence::<D, Event, MAX_EVENTS>(d)
}
fn deserialize_blobs<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<ExportBlob>, D::Error> {
    bounded_sequence::<D, ExportBlob, { MAX_EVENTS * 2 }>(d)
}

fn digest(domain: &str, bytes: &[u8]) -> Result<[u8; 32], Error> {
    auths_codec::domain_commitment(domain, bytes)
        .map(|d| *d.as_bytes())
        .map_err(|_| Error::Corrupt)
}
fn canonical<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, Error> {
    serde_json_canonicalizer::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| Error::Corrupt)
}
fn decode_b64(value: &str, maximum: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    if value.len() > maximum.div_ceil(3) * 4 {
        return Err(Error::EvidenceLimit);
    }
    let decoded = Zeroizing::new(Base64::decode_vec(value).map_err(|_| Error::Corrupt)?);
    if decoded.len() > maximum || Base64::encode_string(&decoded) != value {
        return Err(Error::Corrupt);
    }
    Ok(decoded)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    proof_b64: String,
    action_b64: String,
}
impl Drop for Invocation {
    fn drop(&mut self) {
        self.proof_b64.zeroize();
        self.action_b64.zeroize();
    }
}
impl Invocation {
    fn own(value: EnrollmentInvocation<'_>) -> Self {
        Self {
            proof_b64: Base64::encode_string(value.proof),
            action_b64: Base64::encode_string(value.action),
        }
    }
    fn decode(&self) -> Result<DecodedInvocation, Error> {
        Ok(DecodedInvocation {
            proof: decode_b64(&self.proof_b64, 4 * 1_048_576)?,
            action: decode_b64(&self.action_b64, 65_536)?,
        })
    }
}
struct DecodedInvocation {
    proof: Zeroizing<Vec<u8>>,
    action: Zeroizing<Vec<u8>>,
}
impl DecodedInvocation {
    fn borrowed(&self) -> EnrollmentInvocation<'_> {
        EnrollmentInvocation {
            proof: &self.proof,
            action: &self.action,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    scope: String,
    invocation: Invocation,
}
fn resources(values: &[EnrollmentResourceWitness<'_>]) -> Result<Vec<Resource>, Error> {
    if values.len() > MAX_SCOPES
        || values
            .iter()
            .any(|r| !crate::participant_enrollment::identifier(r.scope_id))
    {
        return Err(Error::EvidenceLimit);
    }
    Ok(values
        .iter()
        .map(|r| Resource {
            scope: r.scope_id.to_owned(),
            invocation: Invocation::own(r.invocation),
        })
        .collect())
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Control {
    Root {
        activation: Invocation,
        #[serde(deserialize_with = "deserialize_resources")]
        resources: Vec<Resource>,
    },
    Enroll {
        parent: [u8; 32],
        authorization: Invocation,
        acceptance: Invocation,
        #[serde(deserialize_with = "deserialize_resources")]
        resources: Vec<Resource>,
    },
    Revoke {
        authorization: Invocation,
    },
}

/// Owned original native control inputs. This is transport/audit data, never
/// authorization, trusted root pins, a current enrollment or an entry permit.
/// Private CBOR proof/action bytes are retained exactly inside one native codec.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementControlEvidence {
    schema: String,
    control: Control,
}
impl std::fmt::Debug for EngagementControlEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementControlEvidence { private: [redacted] }")
    }
}
impl EngagementControlEvidence {
    /// Copies bounded root activation and resource witnesses without verifying
    /// authority. Root installation remains an operator-only action.
    /// # Errors
    /// Refuses oversized or malformed input representations.
    pub fn root(proofs: &RootEnrollmentProofs<'_>) -> Result<Self, Error> {
        if proofs.resources.len() > MAX_SCOPES {
            return Err(Error::EvidenceLimit);
        }
        bounded_invocations(
            std::iter::once(proofs.activation).chain(proofs.resources.iter().map(|r| r.invocation)),
        )
        .map_err(|e| Error::Native(e.into()))?;
        Ok(Self {
            schema: INPUT_SCHEMA.into(),
            control: Control::Root {
                activation: Invocation::own(proofs.activation),
                resources: resources(proofs.resources)?,
            },
        })
    }
    /// Copies parent authorization, child acceptance and resource witnesses.
    /// `parent` is proposed data; the native owner resolves its current pins.
    /// # Errors
    /// Refuses oversized or malformed input representations.
    pub fn enroll(
        parent: [u8; 32],
        proofs: &ParticipantEnrollmentProofs<'_>,
    ) -> Result<Self, Error> {
        if proofs.resources.len() > MAX_SCOPES {
            return Err(Error::EvidenceLimit);
        }
        bounded_invocations(
            [proofs.parent, proofs.child]
                .into_iter()
                .chain(proofs.resources.iter().map(|r| r.invocation)),
        )
        .map_err(|e| Error::Native(e.into()))?;
        Ok(Self {
            schema: INPUT_SCHEMA.into(),
            control: Control::Enroll {
                parent,
                authorization: Invocation::own(proofs.parent),
                acceptance: Invocation::own(proofs.child),
                resources: resources(proofs.resources)?,
            },
        })
    }
    /// Copies a signed subtree withdrawal, without withdrawing anything.
    /// # Errors
    /// Refuses oversized or malformed input representations.
    pub fn revoke(value: EnrollmentInvocation<'_>) -> Result<Self, Error> {
        bounded_invocations([value]).map_err(|e| Error::Native(e.into()))?;
        Ok(Self {
            schema: INPUT_SCHEMA.into(),
            control: Control::Revoke {
                authorization: Invocation::own(value),
            },
        })
    }
    /// Decodes canonical private evidence without establishing authority.
    /// # Errors
    /// Refuses obsolete, noncanonical, oversized or malformed representations.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_ENGAGEMENT_CONTROL_BYTES {
            return Err(Error::EvidenceLimit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        if value.to_private_bytes()?.as_slice() != bytes {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
    /// Canonicalizes bounded authoring JSON using the native evidence codec.
    /// This creates data only; no root/context can be supplied through it.
    /// # Errors
    /// Refuses oversized, unknown, duplicate or malformed input fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_ENGAGEMENT_CONTROL_BYTES {
            return Err(Error::EvidenceLimit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        value.to_private_bytes()?;
        Ok(value)
    }
    /// Encodes original input bytes with the single native canonical contract.
    /// Decoding/encoding never verifies control signatures or grants authority.
    /// # Errors
    /// Refuses invalid schema, base64, counts, aggregate sizes or canonical size.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.schema != INPUT_SCHEMA {
            return Err(Error::Corrupt);
        }
        match &self.control {
            Control::Root { resources, .. } | Control::Enroll { resources, .. }
                if resources.len() > MAX_SCOPES
                    || resources
                        .iter()
                        .any(|r| !crate::participant_enrollment::identifier(&r.scope)) =>
            {
                return Err(Error::EvidenceLimit);
            }
            _ => {}
        }
        let inputs: Vec<_> = match &self.control {
            Control::Root {
                activation,
                resources,
            } => std::iter::once(activation)
                .chain(resources.iter().map(|r| &r.invocation))
                .collect(),
            Control::Enroll {
                authorization,
                acceptance,
                resources,
                ..
            } => [authorization, acceptance]
                .into_iter()
                .chain(resources.iter().map(|r| &r.invocation))
                .collect(),
            Control::Revoke { authorization } => vec![authorization],
        };
        let decoded = inputs
            .iter()
            .map(|v| v.decode())
            .collect::<Result<Vec<_>, _>>()?;
        bounded_invocations(decoded.iter().map(DecodedInvocation::borrowed))
            .map_err(|e| Error::Native(e.into()))?;
        let bytes = canonical(self)?;
        if bytes.len() > MAX_ENGAGEMENT_CONTROL_BYTES {
            return Err(Error::EvidenceLimit);
        }
        Ok(bytes)
    }
    pub(crate) fn is_root(&self) -> bool {
        matches!(self.control, Control::Root { .. })
    }
    pub(super) fn is_enrollment(&self) -> bool {
        matches!(self.control, Control::Enroll { .. })
    }
    pub(super) fn apply(
        &self,
        root: &ParentEnrollmentPins,
        context: &TrustedContext,
        current: Option<&EnrollmentTree>,
        now: u64,
    ) -> Result<EnrollmentTree, Error> {
        match &self.control {
            Control::Root {
                activation,
                resources,
            } => {
                if current.is_some() || resources.len() > MAX_SCOPES {
                    return Err(Error::Corrupt);
                }
                let activation = activation.decode()?;
                let decoded = resources
                    .iter()
                    .map(|r| r.invocation.decode())
                    .collect::<Result<Vec<_>, _>>()?;
                let resources: Vec<_> = resources
                    .iter()
                    .zip(&decoded)
                    .map(|(r, d)| EnrollmentResourceWitness {
                        scope_id: &r.scope,
                        invocation: d.borrowed(),
                    })
                    .collect();
                Ok(EnrollmentTree::bootstrap(
                    context,
                    root,
                    now,
                    &RootEnrollmentProofs {
                        activation: activation.borrowed(),
                        resources: &resources,
                    },
                )?)
            }
            Control::Enroll {
                parent,
                authorization,
                acceptance,
                resources,
            } => {
                if resources.len() > MAX_SCOPES {
                    return Err(Error::Corrupt);
                }
                let mut tree = current.ok_or(Error::Corrupt)?.clone();
                let authorization = authorization.decode()?;
                let acceptance = acceptance.decode()?;
                let decoded = resources
                    .iter()
                    .map(|r| r.invocation.decode())
                    .collect::<Result<Vec<_>, _>>()?;
                let resources: Vec<_> = resources
                    .iter()
                    .zip(&decoded)
                    .map(|(r, d)| EnrollmentResourceWitness {
                        scope_id: &r.scope,
                        invocation: d.borrowed(),
                    })
                    .collect();
                tree.enroll(
                    context,
                    *parent,
                    now,
                    &ParticipantEnrollmentProofs {
                        parent: authorization.borrowed(),
                        child: acceptance.borrowed(),
                        resources: &resources,
                    },
                )?;
                Ok(tree)
            }
            Control::Revoke { authorization } => {
                let mut tree = current.ok_or(Error::Corrupt)?.clone();
                tree.revoke_authorized(context, now, &authorization.decode()?.borrowed())?;
                Ok(tree)
            }
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    revision: u64,
    accepted_at: u64,
    before: Option<[u8; 32]>,
    after: [u8; 32],
    context: blob::Reference,
    inputs: blob::Reference,
}
pub(super) fn tree_commitment(tree: &EnrollmentTree) -> Result<[u8; 32], Error> {
    digest(
        "auths.engagement-audit-tree/1",
        &tree.encode().map_err(|_| Error::Corrupt)?,
    )
}
fn references(events: &[Event]) -> Result<BTreeSet<blob::Reference>, Error> {
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(Error::Corrupt);
    }
    let references: BTreeSet<_> = events
        .iter()
        .flat_map(|e| [&e.context, &e.inputs])
        .cloned()
        .collect();
    let mut bytes = 0usize;
    for reference in &references {
        if !reference.valid() {
            return Err(Error::Corrupt);
        }
        bytes = bytes
            .checked_add(reference.bytes())
            .ok_or(Error::EvidenceLimit)?;
    }
    if bytes > MAX_TOTAL_BYTES {
        return Err(Error::EvidenceLimit);
    }
    Ok(references)
}
pub(super) fn validate_history(snapshot: &EngagementConfigurationSnapshot) -> Result<(), Error> {
    references(&snapshot.events)?;
    let mut before = None;
    let mut time = 0;
    for (index, event) in snapshot.events.iter().enumerate() {
        if event.revision != (index as u64) + 1
            || event.before != before
            || event.accepted_at < time
            || event.accepted_at > super::MAX_INTEGER
            || event.inputs.bytes() > MAX_ENGAGEMENT_CONTROL_BYTES
        {
            return Err(Error::Corrupt);
        }
        before = Some(event.after);
        time = event.accepted_at;
    }
    if snapshot.revision != snapshot.events.len() as u64
        || snapshot.accepted_at != time
        || before != Some(tree_commitment(&snapshot.tree)?)
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}

pub(super) struct Staged {
    context: blob::Reference,
    inputs: blob::Reference,
}
impl Staged {
    pub(super) fn prepare(
        store: &dyn crate::GatewayAttemptStore,
        context: &TrustedContext,
        evidence: &EngagementControlEvidence,
        budget: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let context = Zeroizing::new(
            auths_codec::encode_verifier_context(context).map_err(|_| Error::Corrupt)?,
        );
        let inputs = canonical(evidence)?;
        if inputs.len() > MAX_ENGAGEMENT_CONTROL_BYTES {
            return Err(Error::EvidenceLimit);
        }
        let staged = Self {
            context: blob::Reference::new(&context)?,
            inputs: blob::Reference::new(&inputs)?,
        };
        budget(&staged)?;
        blob::stage(store, &context)?;
        blob::stage(store, &inputs)?;
        Ok(staged)
    }
    pub(super) fn entries(&self) -> Result<Vec<crate::GatewayRecordEntry>, Error> {
        Ok(vec![self.context.manifest()?, self.inputs.manifest()?])
    }
    pub(super) fn validate(&self, snapshots: &[Option<Vec<u8>>]) -> Result<(), Error> {
        let entries = self.entries()?;
        if snapshots.len() != entries.len()
            || snapshots
                .iter()
                .zip(entries)
                .any(|(s, e)| s.as_deref() != Some(e.record.as_slice()))
        {
            return Err(Error::MissingEvidence);
        }
        Ok(())
    }
    pub(super) fn event(
        &self,
        snapshot: &EngagementConfigurationSnapshot,
        before: Option<[u8; 32]>,
    ) -> Result<Event, Error> {
        Ok(Event {
            revision: snapshot.revision,
            accepted_at: snapshot.accepted_at,
            before,
            after: tree_commitment(&snapshot.tree)?,
            context: self.context.clone(),
            inputs: self.inputs.clone(),
        })
    }
}

/// A private checkpoint from an independently trusted acknowledged snapshot.
/// Obtain it through a trusted channel and retain an external monotonic floor.
/// An untrusted bundle cannot select this value for its own verification.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementAuditCheckpoint {
    schema: String,
    root: [u8; 32],
    revision: u64,
    record: [u8; 32],
}
impl std::fmt::Debug for EngagementAuditCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementAuditCheckpoint { private: [redacted] }")
    }
}
impl EngagementAuditCheckpoint {
    pub(super) fn for_record(bytes: &[u8], root: [u8; 32], revision: u64) -> Result<Self, Error> {
        Ok(Self {
            schema: "auths.engagement-audit-checkpoint/1".into(),
            root,
            revision,
            record: digest("auths.engagement-audit-checkpoint/1", bytes)?,
        })
    }
    /// Encodes private checkpoint data. It is neither a signature nor authority.
    /// # Errors
    /// Returns a closed encoding error; no proof material is in diagnostics.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        canonical(self)
    }
    /// Decodes exact private checkpoint data; authenticity must be established
    /// independently of this decoder and the audit bundle.
    /// # Errors
    /// Refuses oversized, obsolete, noncanonical or malformed checkpoints.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > 1024 {
            return Err(Error::Corrupt);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        if value.schema != "auths.engagement-audit-checkpoint/1"
            || !(1..=MAX_EVENTS as u64).contains(&value.revision)
            || canonical(&value)?.as_slice() != bytes
        {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExportBlob {
    reference: blob::Reference,
    data_b64: String,
}
impl Drop for ExportBlob {
    fn drop(&mut self) {
        self.data_b64.zeroize();
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    configuration: String,
    #[serde(deserialize_with = "deserialize_blobs")]
    blobs: Vec<ExportBlob>,
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.configuration.zeroize();
    }
}

/// Operator-private original control evidence for historical independent replay.
/// No accessor returns current eligibility, a permit, or provider credentials.
pub struct EngagementAudit {
    bytes: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for EngagementAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementAudit { private: [redacted] }")
    }
}
impl EngagementAudit {
    fn envelope(&self) -> Result<Envelope, Error> {
        let value: Envelope = serde_json::from_slice(&self.bytes).map_err(|_| Error::Corrupt)?;
        if value.schema != AUDIT_SCHEMA
            || value.configuration.len() > super::MAX_BYTES
            || value.blobs.len() > MAX_EVENTS * 2
            || canonical(&value)?.as_slice() != self.bytes.as_slice()
        {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
    /// Retains bounded, canonical private audit data without authenticating it.
    /// This offline format is at most 384 MiB, including all original evidence;
    /// keep it outside public status, logs and application result channels.
    /// # Errors
    /// Refuses oversize, unsupported, noncanonical or malformed export envelopes.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_EXPORT_BYTES {
            return Err(Error::EvidenceLimit);
        }
        let value = Self {
            bytes: Zeroizing::new(bytes.to_vec()),
        };
        value.envelope()?;
        Ok(value)
    }
    /// Returns sensitive original proof/context bytes for private export only.
    /// Decoding or exporting them establishes no authorization.
    #[must_use]
    pub fn private_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Replays every native control decision at its retained clock sample using
    /// independently trusted installation pins, contexts and checkpoint. Stored
    /// contexts cannot install trust. Clock truth, checkpoint authenticity and
    /// protection against whole-store rollback remain deployment assumptions.
    /// The result is historical data, never present authorization or a permit.
    /// # Errors
    /// Reports missing/corrupt evidence, unknown trusted contexts, a changed
    /// checkpoint/root, invalid native proofs or inconsistent transition history.
    #[allow(
        clippy::too_many_lines,
        reason = "one bounded historical native replay keeps trusted inputs and each immutable transition together"
    )]
    pub fn verify(
        &self,
        root: &ParentEnrollmentPins,
        trusted_contexts: &[TrustedContext],
        checkpoint: &EngagementAuditCheckpoint,
    ) -> Result<EngagementConfigurationSnapshot, Error> {
        if trusted_contexts.is_empty() || trusted_contexts.len() > MAX_EVENTS {
            return Err(Error::UntrustedEvidence);
        }
        let envelope = self.envelope()?;
        let snapshot =
            EngagementConfiguration::decode_for_root(root, envelope.configuration.as_bytes())?;
        if &snapshot.audit_checkpoint()? != checkpoint {
            return Err(Error::UntrustedEvidence);
        }
        let expected = references(&snapshot.events)?;
        if envelope.blobs.len() != expected.len() {
            return Err(Error::MissingEvidence);
        }
        let mut decoded = Vec::new();
        for (blob, expected) in envelope.blobs.iter().zip(expected) {
            if blob.reference != expected {
                return Err(Error::Corrupt);
            }
            let bytes = decode_b64(&blob.data_b64, blob::MAX_BYTES)?;
            expected.matches(&bytes)?;
            decoded.push((expected, bytes));
        }
        let contexts = trusted_contexts
            .iter()
            .map(|c| {
                let bytes = Zeroizing::new(
                    auths_codec::encode_verifier_context(c).map_err(|_| Error::Corrupt)?,
                );
                Ok((blob::Reference::new(&bytes)?, c, bytes))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut tree: Option<EnrollmentTree> = None;
        for event in &snapshot.events {
            let context = contexts
                .iter()
                .find(|(reference, _, _)| reference == &event.context)
                .ok_or(Error::UntrustedEvidence)?;
            let stored_context = decoded
                .iter()
                .find(|(r, _)| r == &event.context)
                .ok_or(Error::MissingEvidence)?;
            if context.2.as_slice() != stored_context.1.as_slice() {
                return Err(Error::Corrupt);
            }
            let inputs = decoded
                .iter()
                .find(|(r, _)| r == &event.inputs)
                .ok_or(Error::MissingEvidence)?;
            let next = EngagementControlEvidence::from_private_bytes(&inputs.1)?.apply(
                root,
                context.1,
                tree.as_ref(),
                event.accepted_at,
            )?;
            if tree.as_ref().map(tree_commitment).transpose()? != event.before
                || tree_commitment(&next)? != event.after
            {
                return Err(Error::Corrupt);
            }
            tree = Some(next);
        }
        if tree.as_ref() != Some(&snapshot.tree) {
            return Err(Error::Corrupt);
        }
        Ok(snapshot)
    }
}

impl EngagementConfiguration {
    /// Exports one acknowledged private history together with its matching head.
    /// The checkpoint comes from the same export, never a second concurrent read.
    /// Authenticate/retain it independently of an untrusted future bundle.
    /// # Errors
    /// Refuses unavailable/corrupt state or missing original evidence.
    pub fn export_audit_checkpointed(
        &self,
    ) -> Result<(EngagementAudit, EngagementAuditCheckpoint), Error> {
        let audit = self.export_audit()?;
        let envelope = audit.envelope()?;
        let snapshot = Self::decode_for_root(&self.root, envelope.configuration.as_bytes())?;
        let checkpoint = snapshot.audit_checkpoint()?;
        Ok((audit, checkpoint))
    }
    /// Finds an exact previously acknowledged control, returning its original
    /// revision rather than the current roster or eligibility. Original private
    /// bytes must still exist and match; no native permit is reconstructed.
    /// # Errors
    /// Returns `None` when no configuration/matching control exists; refuses
    /// corrupt configuration or missing/corrupt referenced original evidence.
    pub fn recorded_control(
        &self,
        evidence: &EngagementControlEvidence,
    ) -> Result<Option<u64>, Error> {
        let bytes = evidence.to_private_bytes()?;
        let expected = blob::Reference::new(&bytes)?;
        let Some(retained) = self
            .store
            .load(crate::GatewayRecordKind::EffectConfiguration, &self.key)?
        else {
            return Ok(None);
        };
        let snapshot = self.decode(&retained)?;
        for event in &snapshot.events {
            if event.inputs == expected {
                if event.inputs.load(&*self.store)?.as_slice() != bytes.as_slice() {
                    return Err(Error::Corrupt);
                }
                return Ok(Some(event.revision));
            }
        }
        Ok(None)
    }
    /// Exports all original control evidence referenced by one retained
    /// acknowledged snapshot. Reads immutable blobs; concurrent later control
    /// transitions do not change this checkpoint. Missing data fails explicitly.
    /// # Errors
    /// Refuses missing/corrupt state or evidence and oversized private exports.
    /// This synchronous operator-only API performs no authorization or I/O to a
    /// provider; async callers must run it off the async executor.
    pub fn export_audit(&self) -> Result<EngagementAudit, Error> {
        let bytes = Zeroizing::new(
            self.store
                .load(crate::GatewayRecordKind::EffectConfiguration, &self.key)?
                .ok_or(Error::MissingEvidence)?,
        );
        let snapshot = self.decode(&bytes)?;
        let blobs = references(&snapshot.events)?
            .into_iter()
            .map(|reference| {
                let bytes = reference.load(&*self.store)?;
                Ok(ExportBlob {
                    reference,
                    data_b64: Base64::encode_string(&bytes),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let envelope = Envelope {
            schema: AUDIT_SCHEMA.into(),
            configuration: String::from_utf8(bytes.to_vec()).map_err(|_| Error::Corrupt)?,
            blobs,
        };
        let bytes = canonical(&envelope)?;
        EngagementAudit::from_private_bytes(&bytes)
    }
}
