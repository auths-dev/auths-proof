//! Pure enrollment transitions for the engagement's authoritative transaction.
//!
//! This value is not a store, execution permit or capacity ledger. Its owner
//! must persist it with the operation journal under one lock before returning
//! enrollment success. Root installation and revocation are trusted inputs;
//! a public endpoint must authenticate them independently.

use super::{
    MAX_PARTICIPANTS, ParentEnrollmentPins, ParticipantEnrollment, ParticipantEnrollmentError,
    ParticipantEnrollmentProofs, VerifiedParticipantEnrollment, bounded_parent,
    verify_participant_enrollment,
};
use auths_model::{GrantId, PrincipalId, TrustedContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_TREE_BYTES: usize = 196_608;
const SCHEMA: &str = "auths.engagement-enrollment-tree/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildRecord {
    descriptor: ParticipantEnrollment,
    commitment: [u8; 32],
    revoked: bool,
}

/// Bounded enrollment tree belonging to one engagement partition.
///
/// Root pins must originate in authenticated activation and installed resource
/// bindings. They cannot come from a participant request. Root and child
/// authority are immutable; revocation only removes eligibility. Every record
/// remains present, including revoked participants, so IDs cannot be reused.
/// This does not implement persistence, ancestor usage or provider dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnrollmentTree {
    schema: String,
    root: ParentEnrollmentPins,
    children: BTreeMap<String, ChildRecord>,
}

/// Refusal of an enrollment transition; no variant permits an effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnrollmentTreeError {
    /// Root installation or parent/child relationship was invalid.
    #[error("invalid enrollment tree binding")]
    Binding,
    /// An ancestor was revoked or is outside its validity window.
    #[error("enrollment ancestry is inactive")]
    Inactive,
    /// All sixteen slots, including root and revoked records, are occupied.
    #[error("enrollment tree is full")]
    Full,
    /// An ID, commitment or principal is already in the tree.
    #[error("participant enrollment was already claimed")]
    Replay,
    /// The maintained native verifier refused enrollment evidence.
    #[error("participant enrollment verification refused")]
    Verification(#[from] ParticipantEnrollmentError),
    /// Stored representation is malformed, inconsistent or for another installation.
    #[error("enrollment tree state is corrupt or mismatched")]
    Corrupt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTree {
    schema: String,
    root: ParentEnrollmentPins,
    children: BTreeMap<String, ChildRecord>,
}

impl EnrollmentTree {
    /// Activate a root with native holder control and exact resource authority.
    ///
    /// Root pins must come from the signed engagement and installed bindings.
    /// This verifies their exact commitment, root possession and every pinned
    /// resource grant before constructing a tree. The owner must persist this
    /// together with the engagement journal in one initialization transaction.
    ///
    /// # Errors
    /// Refuses stale, substituted or unsupported evidence and invalid root pins.
    pub fn bootstrap(
        context: &TrustedContext,
        root: &ParentEnrollmentPins,
        now: u64,
        proofs: &super::RootEnrollmentProofs<'_>,
    ) -> Result<Self, EnrollmentTreeError> {
        super::root::verify_root(context, root, now, proofs)?;
        Self::new(root.clone())
    }

    /// Initialize from the authenticated root participant's immutable pins.
    ///
    /// # Errors
    /// Refuses malformed, unbounded or inactive root installation. This does
    /// not establish native root authority; activation must already do that.
    pub(crate) fn new(root: ParentEnrollmentPins) -> Result<Self, EnrollmentTreeError> {
        bounded_parent(&root).map_err(|_| EnrollmentTreeError::Binding)?;
        if !root.active {
            return Err(EnrollmentTreeError::Inactive);
        }
        Ok(Self {
            schema: SCHEMA.into(),
            root,
            children: BTreeMap::new(),
        })
    }

    /// Number of all retained participants, including the root and revoked ones.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        self.children.len() + 1
    }

    fn child(&self, commitment: &[u8; 32]) -> Option<&ChildRecord> {
        self.children
            .values()
            .find(|child| &child.commitment == commitment)
    }

    fn ancestry(&self, leaf: [u8; 32]) -> Result<Vec<[u8; 32]>, EnrollmentTreeError> {
        let mut path = Vec::with_capacity(MAX_PARTICIPANTS);
        let mut current = leaf;
        loop {
            if path.len() >= MAX_PARTICIPANTS || path.contains(&current) {
                return Err(EnrollmentTreeError::Binding);
            }
            path.push(current);
            if current == self.root.enrollment_commitment {
                path.reverse();
                return Ok(path);
            }
            current = self
                .child(&current)
                .ok_or(EnrollmentTreeError::Binding)?
                .descriptor
                .parent_enrollment;
        }
    }

    fn active_path(&self, leaf: [u8; 32], now: u64) -> Result<Vec<[u8; 32]>, EnrollmentTreeError> {
        let path = self.ancestry(leaf)?;
        if !self.root.active || now < self.root.not_before || now >= self.root.expires_at {
            return Err(EnrollmentTreeError::Inactive);
        }
        for commitment in path.iter().skip(1) {
            let child = self.child(commitment).ok_or(EnrollmentTreeError::Binding)?;
            if child.revoked
                || now < child.descriptor.not_before
                || now >= child.descriptor.expires_at
            {
                return Err(EnrollmentTreeError::Inactive);
            }
        }
        Ok(path)
    }

    /// Derive verifier pins from current immutable ancestry and root installation.
    ///
    /// # Errors
    /// Refuses unknown, revoked or expired ancestry. Returned snapshots never
    /// authorize a later mutation: [`Self::enroll`] derives its own current pins.
    pub fn parent_pins(
        &self,
        parent: [u8; 32],
        now: u64,
    ) -> Result<ParentEnrollmentPins, EnrollmentTreeError> {
        self.active_path(parent, now)?;
        self.pins_for(parent)
    }

    fn pins_for(&self, parent: [u8; 32]) -> Result<ParentEnrollmentPins, EnrollmentTreeError> {
        if parent == self.root.enrollment_commitment {
            return Ok(self.root.clone());
        }
        let child = self.child(&parent).ok_or(EnrollmentTreeError::Binding)?;
        let descriptor = &child.descriptor;
        let mut pins = self.root.clone();
        pins.enrollment_commitment = parent;
        pins.principal = PrincipalId::parse(&descriptor.child_principal)
            .map_err(|_| EnrollmentTreeError::Binding)?;
        pins.instance_generation = descriptor.child_instance_generation;
        pins.control_grant = GrantId::new(descriptor.control_grant);
        pins.not_before = descriptor.not_before;
        pins.expires_at = descriptor.expires_at;
        pins.remaining_depth = descriptor.remaining_depth;
        pins.ceilings = descriptor.ceilings;
        pins.scopes.retain(|scope| {
            descriptor
                .scopes
                .iter()
                .any(|grant| grant.scope_id == scope.scope_id)
        });
        for scope in &mut pins.scopes {
            scope.parent_grant = GrantId::new(
                descriptor
                    .scopes
                    .iter()
                    .find(|grant| grant.scope_id == scope.scope_id)
                    .ok_or(EnrollmentTreeError::Binding)?
                    .grant_id,
            );
        }
        Ok(pins)
    }

    /// Verify and apply enrollment against this transaction's current ancestry.
    ///
    /// The enclosing store must hold its exclusive partition transaction across
    /// this call and publication. `context` and `now` must be freshly obtained
    /// from the installed verification/time boundary. Native verification is
    /// offline; this function performs no custody, network or filesystem I/O.
    /// Enrollment creates a ceiling, never additional root capacity.
    ///
    /// # Errors
    /// Refuses inactive ancestry, native verification failure, ID/principal
    /// reuse and exhaustion. Every refusal leaves the entire tree unchanged.
    pub fn enroll(
        &mut self,
        context: &TrustedContext,
        parent: [u8; 32],
        now: u64,
        proofs: &ParticipantEnrollmentProofs<'_>,
    ) -> Result<[u8; 32], EnrollmentTreeError> {
        if self.participant_count() >= MAX_PARTICIPANTS {
            return Err(EnrollmentTreeError::Full);
        }
        let pins = self.parent_pins(parent, now)?;
        let verified = verify_participant_enrollment(context, &pins, now, proofs)?;
        self.insert_verified(verified)
    }

    fn insert_verified(
        &mut self,
        verified: VerifiedParticipantEnrollment,
    ) -> Result<[u8; 32], EnrollmentTreeError> {
        let descriptor = verified.enrollment;
        if self.children.contains_key(&descriptor.enrollment_id)
            || descriptor.child_principal == self.root.principal.as_str()
            || verified.commitment == self.root.enrollment_commitment
            || self.children.values().any(|child| {
                child.descriptor.child_principal == descriptor.child_principal
                    || child.commitment == verified.commitment
            })
        {
            return Err(EnrollmentTreeError::Replay);
        }
        self.children.insert(
            descriptor.enrollment_id.clone(),
            ChildRecord {
                descriptor,
                commitment: verified.commitment,
                revoked: false,
            },
        );
        Ok(verified.commitment)
    }

    /// Irreversibly revoke one node in the current partition transaction.
    ///
    /// The caller must authenticate revocation authority before this call.
    /// Descendants become ineligible without deleting any records or charges.
    /// This does not cancel an effect whose entry already won the transaction.
    ///
    /// # Errors
    /// Refuses unknown commitments. Repeated revocation is idempotent.
    pub fn revoke(&mut self, participant: [u8; 32]) -> Result<(), EnrollmentTreeError> {
        if participant == self.root.enrollment_commitment {
            self.root.active = false;
            return Ok(());
        }
        self.children
            .values_mut()
            .find(|child| child.commitment == participant)
            .ok_or(EnrollmentTreeError::Binding)?
            .revoked = true;
        Ok(())
    }

    /// Exact native scope grant IDs required as a suffix of an operation's
    /// single authorized branch, ordered root participant through acting leaf.
    ///
    /// # Errors
    /// Refuses inactive ancestry or any scope absent from an ancestor. This
    /// supplies comparison data only, not native proof verification or admission.
    pub fn resource_grant_path(
        &self,
        participant: [u8; 32],
        scope_id: &str,
        now: u64,
    ) -> Result<Vec<GrantId>, EnrollmentTreeError> {
        let path = self.active_path(participant, now)?;
        path.into_iter()
            .map(|node| {
                self.parent_pins(node, now)?
                    .scopes
                    .into_iter()
                    .find(|scope| scope.scope_id == scope_id)
                    .map(|scope| scope.parent_grant)
                    .ok_or(EnrollmentTreeError::Binding)
            })
            .collect()
    }
}

impl EnrollmentTree {
    /// Bounded canonical encoding for inclusion in the owner's atomic journal.
    /// No proof bytes, credentials or private provider content are retained.
    ///
    /// # Errors
    /// Refuses an encoding that exceeds the fixed 192 KiB tree bound.
    pub fn encode(&self) -> Result<Vec<u8>, EnrollmentTreeError> {
        let bytes =
            serde_json_canonicalizer::to_vec(self).map_err(|_| EnrollmentTreeError::Corrupt)?;
        if bytes.len() > MAX_TREE_BYTES {
            return Err(EnrollmentTreeError::Corrupt);
        }
        Ok(bytes)
    }

    /// Restore canonical state from the trusted ledger against independently
    /// authenticated root installation. This is not an untrusted import API.
    ///
    /// The owner must protect the store against tampering and rollback. Comparing
    /// the installed partition generation prevents loading another generation;
    /// it does not detect restoration of both the journal and its installation.
    /// Native proofs are not persisted or reauthenticated by this decoder.
    ///
    /// # Errors
    /// Refuses oversized/noncanonical/obsolete state, installation substitution,
    /// cycles, reused principals, altered commitments and authority widening.
    pub fn decode(
        bytes: &[u8],
        installed: &ParentEnrollmentPins,
    ) -> Result<Self, EnrollmentTreeError> {
        if bytes.is_empty() || bytes.len() > MAX_TREE_BYTES {
            return Err(EnrollmentTreeError::Corrupt);
        }
        bounded_parent(installed).map_err(|_| EnrollmentTreeError::Corrupt)?;
        let stored: StoredTree =
            serde_json::from_slice(bytes).map_err(|_| EnrollmentTreeError::Corrupt)?;
        let tree = Self {
            schema: stored.schema,
            root: stored.root,
            children: stored.children,
        };
        if tree.schema != SCHEMA
            || tree.participant_count() > MAX_PARTICIPANTS
            || tree.encode()? != bytes
        {
            return Err(EnrollmentTreeError::Corrupt);
        }
        let mut recorded = tree.root.clone();
        let mut expected = installed.clone();
        if !expected.active && recorded.active {
            return Err(EnrollmentTreeError::Corrupt);
        }
        // A persisted revocation is allowed to be stricter than activation.
        // Every other root field must match independent trusted installation.
        recorded.active = true;
        expected.active = true;
        if recorded != expected {
            return Err(EnrollmentTreeError::Corrupt);
        }
        tree.validate_records()?;
        Ok(tree)
    }

    fn validate_records(&self) -> Result<(), EnrollmentTreeError> {
        let mut principals = BTreeSet::from([self.root.principal.as_str()]);
        let mut commitments = BTreeSet::from([self.root.enrollment_commitment]);
        for (id, child) in &self.children {
            let descriptor = &child.descriptor;
            if id != &descriptor.enrollment_id
                || !principals.insert(&descriptor.child_principal)
                || !commitments.insert(child.commitment)
                || descriptor
                    .commitment()
                    .map_err(|_| EnrollmentTreeError::Corrupt)?
                    != child.commitment
            {
                return Err(EnrollmentTreeError::Corrupt);
            }
            self.ancestry(child.commitment)
                .map_err(|_| EnrollmentTreeError::Corrupt)?;
            let mut parent = self
                .pins_for(descriptor.parent_enrollment)
                .map_err(|_| EnrollmentTreeError::Corrupt)?;
            // Validate immutable narrowing at the original eligibility start;
            // expired and revoked records must remain decodable and retained.
            parent.active = true;
            descriptor
                .validate(&parent, descriptor.not_before)
                .map_err(|_| EnrollmentTreeError::Corrupt)?;
            if descriptor.scopes.iter().any(|scope| {
                !parent
                    .scopes
                    .iter()
                    .any(|pin| pin.scope_id == scope.scope_id)
            }) {
                return Err(EnrollmentTreeError::Corrupt);
            }
        }
        Ok(())
    }
}
