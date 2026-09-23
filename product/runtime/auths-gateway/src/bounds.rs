//! Bounded policy in the gateway path.
//!
//! A grant may carry a `bounded-policy-commitment-v1` critical extension. The
//! native verifier checks its shape and that a delegated bound links its
//! parent's exact extension bytes; it never interprets the policy. After
//! verification and before any durable claim, the gateway:
//!
//! 1. resolves every commitment in the authorized chain through a closed
//!    evaluator registry keyed by evaluator semantic identifier, refusing an
//!    unregistered evaluator or a commitment whose policy type, version, or
//!    canonicalization differs from the registered evaluator's;
//! 2. refuses a root bound that carries a parent link, and a delegated bound
//!    the registered tightening decider cannot prove tighter than its
//!    parent's;
//! 3. evaluates every bound against the verified action.
//!
//! After the claim and before any credential lease, it reserves one slot of
//! the actor's per-window count in the attempt store; an exhausted window
//! leaves the claim `not-entered`.
//!
//! One evaluator is registered: a ceiling on one named verified MCP argument
//! plus a maximum count of authorized actions per principal per fixed window.

use crate::engine::{GatewaySubmitResult, not_entered};
use crate::{GatewayAttemptError, LogicalOperationId, OperatorNamespace};
use auths_bounded_policy::kernel::{
    CeilingCountCode, ceiling_count_code, ceiling_count_tightens, window_index,
};
use auths_bounded_policy::{
    CanonicalizationId, EvaluatorRegistrationV1, EvaluatorSemanticId, ImplementationId,
    PolicyTypeId, ProfileId, validate_registry,
};
use auths_model::{
    BoundedPolicyCommitment, Digest, FactName, FactValue, PolicyCommitment, PolicyIdentifier,
    SignedGrant,
};
use auths_ports::ProfilePolicy as _;
use auths_profile_mcp::McpArgumentsPolicy;
use auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1;
use auths_verifier::VerifiedAction;
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};

/// Evaluator semantic identifier of the one registered evaluator.
pub const ARGUMENT_CEILING_EVALUATOR_V1: &str = "auths.gateway.argument-ceiling-window-count/1";
/// Policy type the registered evaluator reads.
pub const ARGUMENT_CEILING_POLICY_TYPE_V1: &str = "auths.gateway.argument-ceiling-policy/1";
/// Canonicalization of the registered evaluator's policy bytes.
pub const ARGUMENT_CEILING_CANONICALIZATION_V1: &str = "auths.canonical-cbor/1";
/// Policy schema version of the registered evaluator.
pub const ARGUMENT_CEILING_POLICY_VERSION: u16 = 1;
/// Longest counting window, in seconds.
pub const MAX_WINDOW_SECONDS: u64 = 31 * 86_400;
/// Largest per-window count a policy may allow.
pub const MAX_WINDOW_COUNT: u64 = 1 << 32;

const MAX_POLICY_BYTES: usize = auths_model::MAX_BOUNDED_POLICY_BYTES;

/// Refusal while building or reading a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundedPolicyError {
    /// Policy bytes are malformed, non-canonical, or outside their bounds.
    #[error("invalid argument-ceiling policy")]
    InvalidPolicy,
}

/// A ceiling on one named verified argument, and at most `max_count`
/// authorized actions per principal in each window of `window_seconds`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentCeilingPolicy {
    argument: FactName,
    ceiling: u64,
    window_seconds: u64,
    max_count: u64,
}

impl ArgumentCeilingPolicy {
    /// Constructs a policy.
    ///
    /// # Errors
    /// Refuses an invalid argument name, a window outside
    /// `1..=MAX_WINDOW_SECONDS`, or a count outside `1..=MAX_WINDOW_COUNT`.
    pub fn new(
        argument: &str,
        ceiling: u64,
        window_seconds: u64,
        max_count: u64,
    ) -> Result<Self, BoundedPolicyError> {
        if !(1..=MAX_WINDOW_SECONDS).contains(&window_seconds)
            || !(1..=MAX_WINDOW_COUNT).contains(&max_count)
        {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        Ok(Self {
            argument: FactName::parse(argument).map_err(|_| BoundedPolicyError::InvalidPolicy)?,
            ceiling,
            window_seconds,
            max_count,
        })
    }

    /// The named verified argument.
    #[must_use]
    pub fn argument(&self) -> &str {
        self.argument.as_str()
    }

    /// The largest admitted argument value.
    #[must_use]
    pub const fn ceiling(&self) -> u64 {
        self.ceiling
    }

    /// The counting window, in seconds.
    #[must_use]
    pub const fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    /// The largest number of authorized actions per principal per window.
    #[must_use]
    pub const fn max_count(&self) -> u64 {
        self.max_count
    }

    /// Canonical CBOR: `{0: argument, 1: ceiling, 2: window_seconds,
    /// 3: max_count}`.
    ///
    /// # Errors
    /// Returns [`BoundedPolicyError::InvalidPolicy`] only if encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, BoundedPolicyError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(4).map_err(invalid_policy)?;
        encoder.u8(0).map_err(invalid_policy)?;
        encoder
            .str(self.argument.as_str())
            .map_err(invalid_policy)?;
        encoder.u8(1).map_err(invalid_policy)?;
        encoder.u64(self.ceiling).map_err(invalid_policy)?;
        encoder.u8(2).map_err(invalid_policy)?;
        encoder.u64(self.window_seconds).map_err(invalid_policy)?;
        encoder.u8(3).map_err(invalid_policy)?;
        encoder.u64(self.max_count).map_err(invalid_policy)?;
        Ok(encoder.into_writer())
    }

    /// Decodes exactly the canonical encoding [`Self::encode`] produces.
    ///
    /// # Errors
    /// Refuses any other bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BoundedPolicyError> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.map().map_err(invalid_policy)? != Some(4) {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        next_key(&mut decoder, 0)?;
        let argument = decoder.str().map_err(invalid_policy)?.to_owned();
        next_key(&mut decoder, 1)?;
        let ceiling = decoder.u64().map_err(invalid_policy)?;
        next_key(&mut decoder, 2)?;
        let window_seconds = decoder.u64().map_err(invalid_policy)?;
        next_key(&mut decoder, 3)?;
        let max_count = decoder.u64().map_err(invalid_policy)?;
        if decoder.position() != bytes.len() {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        let policy = Self::new(&argument, ceiling, window_seconds, max_count)?;
        if policy.encode()? != bytes {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        Ok(policy)
    }

    /// The canonical extension body committing to this policy; `parent` is
    /// the digest of the parent grant's extension bytes when this bound
    /// narrows a parent's.
    ///
    /// # Errors
    /// Returns [`BoundedPolicyError::InvalidPolicy`] only if a compiled
    /// identifier is invalid.
    pub fn extension_body(&self, parent: Option<Digest>) -> Result<Vec<u8>, BoundedPolicyError> {
        let policy = self.encode()?;
        let commitment = PolicyCommitment::new(
            PolicyIdentifier::parse(ARGUMENT_CEILING_POLICY_TYPE_V1, 128)
                .map_err(invalid_policy)?,
            ARGUMENT_CEILING_POLICY_VERSION,
            PolicyIdentifier::parse(ARGUMENT_CEILING_CANONICALIZATION_V1, 64)
                .map_err(invalid_policy)?,
            auths_codec::bounded_policy_digest(&policy).map_err(invalid_policy)?,
            PolicyIdentifier::parse(ARGUMENT_CEILING_EVALUATOR_V1, 128).map_err(invalid_policy)?,
        )
        .map_err(invalid_policy)?;
        auths_codec::encode_bounded_policy_commitment(
            &BoundedPolicyCommitment::new(commitment, policy, parent).map_err(invalid_policy)?,
        )
        .map_err(invalid_policy)
    }

    /// The registered tightening decider: the same argument and window, and a
    /// ceiling and count no larger than `parent`'s.
    #[must_use]
    pub fn tightens(&self, parent: &Self) -> bool {
        self.argument == parent.argument
            && ceiling_count_tightens(
                self.ceiling,
                self.max_count,
                self.window_seconds,
                parent.ceiling,
                parent.max_count,
                parent.window_seconds,
            )
    }
}

fn invalid_policy<E>(_error: E) -> BoundedPolicyError {
    BoundedPolicyError::InvalidPolicy
}

fn next_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), BoundedPolicyError> {
    if decoder
        .u8()
        .map_err(|_| BoundedPolicyError::InvalidPolicy)?
        == expected
    {
        Ok(())
    } else {
        Err(BoundedPolicyError::InvalidPolicy)
    }
}

/// The closed set of evaluators the gateway executes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayEvaluator {
    ArgumentCeilingWindowCount,
}

/// The gateway's closed evaluator inventory, validated by the shared
/// registry rules.
///
/// # Errors
/// Returns a static code only if a compiled identifier is invalid.
pub fn gateway_evaluator_registrations() -> Result<Vec<EvaluatorRegistrationV1>, &'static str> {
    let invalid = |_| "gateway.policy.registry-invalid";
    let registrations = vec![EvaluatorRegistrationV1 {
        owning_package: "auths-gateway",
        layer: "product",
        profile_id: ProfileId::parse(auths_profile_mcp::PROFILE_ID).map_err(invalid)?,
        policy_type: PolicyTypeId::parse(ARGUMENT_CEILING_POLICY_TYPE_V1).map_err(invalid)?,
        evaluator_semantic_id: EvaluatorSemanticId::parse(ARGUMENT_CEILING_EVALUATOR_V1)
            .map_err(invalid)?,
        implementation_id: ImplementationId::parse(concat!(
            "auths-gateway/",
            env!("CARGO_PKG_VERSION")
        ))
        .map_err(invalid)?,
        canonicalization_id: CanonicalizationId::parse(ARGUMENT_CEILING_CANONICALIZATION_V1)
            .map_err(invalid)?,
        rust_symbol: "auths_gateway::ArgumentCeilingPolicy::tightens",
        lean_artifact: "Auths.Product.CeilingCount",
        fixture_manifest: "bindings/fixtures/gateway/bounds-hostile.json",
        migrated: true,
    }];
    validate_registry(&registrations).map_err(|_| "gateway.policy.registry-invalid")?;
    Ok(registrations)
}

/// Resolves a commitment's evaluator, refusing an unregistered identifier or
/// a policy type, version, or canonicalization the evaluator does not read.
fn registered(commitment: &PolicyCommitment) -> Result<GatewayEvaluator, &'static str> {
    let registrations = gateway_evaluator_registrations()?;
    let registration = registrations
        .iter()
        .find(|registration| {
            registration.evaluator_semantic_id.as_str()
                == commitment.evaluator_semantic_id().as_str()
        })
        .ok_or("gateway.policy.evaluator-unregistered")?;
    if registration.policy_type.as_str() != commitment.policy_type().as_str()
        || registration.canonicalization_id.as_str() != commitment.canonicalization_id().as_str()
        || commitment.policy_version() != ARGUMENT_CEILING_POLICY_VERSION
    {
        return Err("gateway.policy.evaluator-mismatch");
    }
    match registration.evaluator_semantic_id.as_str() {
        ARGUMENT_CEILING_EVALUATOR_V1 => Ok(GatewayEvaluator::ArgumentCeilingWindowCount),
        _ => Err("gateway.policy.evaluator-unregistered"),
    }
}

/// One slot of an actor's per-window count, reserved after the claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowReservation {
    counter: [u8; 32],
    max_count: u64,
}

/// The authorized chain of the one verified action, root to terminal.
fn authorized_chain(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
) -> Result<(auths_model::PrincipalId, Vec<SignedGrant>), &'static str> {
    let unavailable = "gateway.policy.proof-unavailable";
    let bundle = auths_codec::decode_bundle(proof_cbor, &auths_model::VerifierLimits::default())
        .map_err(|_| unavailable)?;
    let [action_id] = verified.action_ids() else {
        return Err("gateway.policy.multiple-branches");
    };
    let action = bundle
        .actions()
        .iter()
        .find(|action| auths_codec::action_id(action.envelope()).is_ok_and(|id| id == *action_id))
        .ok_or(unavailable)?;
    let mut chain = Vec::new();
    let mut cursor = action.envelope().terminal_grant();
    while let Some(id) = cursor {
        if chain.len() > bundle.grants().len() {
            return Err(unavailable);
        }
        let grant = bundle
            .grants()
            .iter()
            .find(|grant| auths_codec::grant_id(grant.statement()).is_ok_and(|found| found == id))
            .ok_or(unavailable)?;
        chain.push(grant.clone());
        cursor = grant.statement().parent();
    }
    chain.reverse();
    Ok((action.envelope().actor().clone(), chain))
}

/// Admits the verified action under every bound in its authorized chain, or
/// refuses it before any claim. `Ok(None)` is an unbounded chain.
pub(crate) fn admit_bounds(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
    namespace: &OperatorNamespace,
    now: u64,
) -> Result<Option<WindowReservation>, GatewaySubmitResult> {
    let refuse = not_entered;
    let (actor, chain) = authorized_chain(proof_cbor, verified).map_err(refuse)?;
    let mut bounds: Vec<(Vec<u8>, BoundedPolicyCommitment)> = Vec::new();
    for grant in &chain {
        for extension in grant.statement().extensions().as_slice() {
            if extension.id().as_str() != BOUNDED_POLICY_COMMITMENT_EXTENSION_V1 {
                continue;
            }
            let body = auths_codec::decode_bounded_policy_commitment(extension.bytes())
                .map_err(|_| refuse("gateway.policy.invalid-commitment"))?;
            bounds.push((extension.bytes().to_vec(), body));
        }
    }
    let Some((_, root)) = bounds.first() else {
        return Ok(None);
    };
    if root.parent().is_some() {
        return Err(refuse("gateway.policy.dangling-link"));
    }
    let mut policies = Vec::with_capacity(bounds.len());
    for (_, body) in &bounds {
        match registered(body.commitment()).map_err(refuse)? {
            GatewayEvaluator::ArgumentCeilingWindowCount => {
                policies.push(
                    ArgumentCeilingPolicy::decode(body.policy())
                        .map_err(|_| refuse("gateway.policy.invalid-policy"))?,
                );
            }
        }
    }
    for pair in policies.windows(2) {
        if !pair[1].tightens(&pair[0]) {
            return Err(refuse("gateway.policy.expanded"));
        }
    }
    let facts = McpArgumentsPolicy::new().map_err(|_| refuse("gateway.policy.registry-invalid"))?;
    for policy in &policies {
        let Ok(Some(FactValue::Uint(value))) =
            facts.action_fact(verified.canonical_action(), &policy.argument)
        else {
            return Err(refuse("gateway.policy.argument-unavailable"));
        };
        if ceiling_count_code(value, policy.ceiling, 0, policy.max_count)
            == CeilingCountCode::AboveCeiling
        {
            return Err(refuse("gateway.policy.above-ceiling"));
        }
    }
    let Some(terminal) = policies.last() else {
        return Ok(None);
    };
    let window = window_index(now, terminal.window_seconds)
        .ok_or_else(|| refuse("gateway.policy.invalid-policy"))?;
    let mut hash = Sha256::new();
    hash.update(b"auths.gateway-bounded-count/1\0");
    for component in [
        namespace.as_str().as_bytes(),
        actor.as_str().as_bytes(),
        ARGUMENT_CEILING_EVALUATOR_V1.as_bytes(),
    ] {
        hash.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(component);
    }
    hash.update(terminal.window_seconds.to_be_bytes());
    hash.update(window.to_be_bytes());
    Ok(Some(WindowReservation {
        counter: hash.finalize().into(),
        max_count: terminal.max_count,
    }))
}

/// Durable insert-once slots holding per-window counts. Every
/// implementation must give one winner per slot across processes and must
/// never report an unreadable slot as absent.
pub trait BoundedCountStore {
    /// Inserts slot `key` with `record`; `Ok(false)` when it already exists.
    ///
    /// # Errors
    /// Returns a store failure; the slot is then neither reserved nor free.
    fn insert_count_slot(&self, key: &[u8; 32], record: &[u8])
    -> Result<bool, GatewayAttemptError>;

    /// Reports whether slot `key` exists.
    ///
    /// # Errors
    /// Returns a store failure rather than guessing.
    fn count_slot_exists(&self, key: &[u8; 32]) -> Result<bool, GatewayAttemptError>;
}

/// Why a count slot was not reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReserveRefusal {
    Exhausted,
    Unavailable,
}

impl ReserveRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Exhausted => "gateway.policy.window-exhausted",
            Self::Unavailable => "gateway.policy.count-unavailable",
        }
    }
}

fn slot_key(counter: &[u8; 32], slot: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"auths.gateway-bounded-count-slot/1\0");
    hash.update(counter);
    hash.update(slot.to_be_bytes());
    hash.finalize().into()
}

/// Reserves the lowest free slot below the window maximum for `operation`.
///
/// Slots are only ever inserted at the frontier found by a binary search over
/// the occupied prefix, so occupied slots always form a prefix and the
/// search is exact. Work is logarithmic in the maximum plus one insert per
/// concurrent winner.
pub(crate) fn reserve_window(
    store: &impl BoundedCountStore,
    reservation: &WindowReservation,
    operation: &LogicalOperationId,
) -> Result<(), ReserveRefusal> {
    let exists = |slot| {
        store
            .count_slot_exists(&slot_key(&reservation.counter, slot))
            .map_err(|_| ReserveRefusal::Unavailable)
    };
    let (mut low, mut high) = (0_u64, reservation.max_count);
    while low < high {
        let middle = low + (high - low) / 2;
        if exists(middle)? {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    let record = serde_json::to_vec(&serde_json::json!({
        "schema": "auths.gateway-bounded-count/1",
        "operation_id": operation.as_str(),
    }))
    .map_err(|_| ReserveRefusal::Unavailable)?;
    let mut slot = low;
    while slot < reservation.max_count {
        if store
            .insert_count_slot(&slot_key(&reservation.counter, slot), &record)
            .map_err(|_| ReserveRefusal::Unavailable)?
        {
            return Ok(());
        }
        slot += 1;
    }
    Err(ReserveRefusal::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct MemoryCounts(Mutex<BTreeMap<[u8; 32], Vec<u8>>>);

    impl BoundedCountStore for MemoryCounts {
        fn insert_count_slot(
            &self,
            key: &[u8; 32],
            record: &[u8],
        ) -> Result<bool, GatewayAttemptError> {
            let mut slots = self
                .0
                .lock()
                .map_err(|_| GatewayAttemptError::Unavailable)?;
            if slots.contains_key(key) {
                return Ok(false);
            }
            slots.insert(*key, record.to_vec());
            Ok(true)
        }

        fn count_slot_exists(&self, key: &[u8; 32]) -> Result<bool, GatewayAttemptError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| GatewayAttemptError::Unavailable)?
                .contains_key(key))
        }
    }

    #[test]
    fn policy_encoding_is_canonical_and_bounded() {
        let policy = ArgumentCeilingPolicy::new("amount", 500, 3_600, 3).expect("policy");
        let bytes = policy.encode().expect("bytes");
        assert_eq!(ArgumentCeilingPolicy::decode(&bytes), Ok(policy.clone()));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ArgumentCeilingPolicy::decode(&trailing).is_err());
        assert!(ArgumentCeilingPolicy::new("amount", 1, 0, 1).is_err());
        assert!(ArgumentCeilingPolicy::new("amount", 1, 1, 0).is_err());
        assert!(ArgumentCeilingPolicy::new("amount", 1, MAX_WINDOW_SECONDS + 1, 1).is_err());
        assert!(ArgumentCeilingPolicy::new("amount", 1, 1, MAX_WINDOW_COUNT + 1).is_err());
    }

    #[test]
    fn decider_accepts_only_a_tighter_bound_on_the_same_argument_and_window() {
        let parent = ArgumentCeilingPolicy::new("amount", 500, 3_600, 3).expect("policy");
        let tighter = ArgumentCeilingPolicy::new("amount", 100, 3_600, 2).expect("policy");
        assert!(tighter.tightens(&parent));
        assert!(parent.tightens(&parent));
        assert!(!parent.tightens(&tighter));
        let other_argument = ArgumentCeilingPolicy::new("quantity", 1, 3_600, 1).expect("policy");
        assert!(!other_argument.tightens(&parent));
        let other_window = ArgumentCeilingPolicy::new("amount", 1, 60, 1).expect("policy");
        assert!(!other_window.tightens(&parent));
    }

    #[test]
    fn registry_refuses_unregistered_and_mismatched_evaluators() {
        let digest = Digest::new([1; 32]);
        let commitment = |evaluator: &str, policy_type: &str, version| {
            PolicyCommitment::new(
                PolicyIdentifier::parse(policy_type, 128).expect("type"),
                version,
                PolicyIdentifier::parse(ARGUMENT_CEILING_CANONICALIZATION_V1, 64).expect("canon"),
                digest,
                PolicyIdentifier::parse(evaluator, 128).expect("evaluator"),
            )
            .expect("commitment")
        };
        assert_eq!(
            registered(&commitment(
                ARGUMENT_CEILING_EVALUATOR_V1,
                ARGUMENT_CEILING_POLICY_TYPE_V1,
                1
            )),
            Ok(GatewayEvaluator::ArgumentCeilingWindowCount)
        );
        assert_eq!(
            registered(&commitment(
                "auths.gateway.other/1",
                ARGUMENT_CEILING_POLICY_TYPE_V1,
                1
            )),
            Err("gateway.policy.evaluator-unregistered")
        );
        assert_eq!(
            registered(&commitment(
                ARGUMENT_CEILING_EVALUATOR_V1,
                "auths.gateway.other-policy/1",
                1
            )),
            Err("gateway.policy.evaluator-mismatch")
        );
        assert_eq!(
            registered(&commitment(
                ARGUMENT_CEILING_EVALUATOR_V1,
                ARGUMENT_CEILING_POLICY_TYPE_V1,
                2
            )),
            Err("gateway.policy.evaluator-mismatch")
        );
    }

    #[test]
    fn window_reservation_takes_exactly_the_maximum() {
        let store = MemoryCounts(Mutex::new(BTreeMap::new()));
        let reservation = WindowReservation {
            counter: [9; 32],
            max_count: 3,
        };
        let operation = LogicalOperationId::parse("op-1").expect("operation");
        for _ in 0..3 {
            assert_eq!(reserve_window(&store, &reservation, &operation), Ok(()));
        }
        assert_eq!(
            reserve_window(&store, &reservation, &operation),
            Err(ReserveRefusal::Exhausted)
        );
        let other = WindowReservation {
            counter: [8; 32],
            max_count: 3,
        };
        assert_eq!(reserve_window(&store, &other, &operation), Ok(()));
    }
}
