//! Bounded policy in the gateway path: one spend limit.
//!
//! A grant may carry a `bounded-policy-commitment-v1` critical extension. The
//! native verifier checks its shape and that a delegated bound links its
//! parent's exact extension bytes; it never interprets the policy. After
//! verification and before any durable claim, the gateway:
//!
//! 1. takes the one authorized branch whose chain carries a bound; every
//!    grant from its first bounded grant to its terminal grant is a link,
//!    and a chain of more than [`MAX_BOUNDED_LINKS`] links is refused;
//! 2. resolves every link's commitment through a closed evaluator registry,
//!    refusing an unregistered evaluator or a commitment whose policy type,
//!    version, or canonicalization the registered evaluator does not read;
//! 3. refuses a root bound that carries a parent link, and a delegated bound
//!    the registered tightening decider cannot prove tighter than its
//!    parent's;
//! 4. evaluates every link against the verified action: the ceiling, every
//!    scope and partition list, and the smallest sum limit;
//! 5. derives the counters to reserve: one count counter per distinct link
//!    subject, and one sum counter per distinct link subject and partition
//!    value, each with the smallest capacity of the links that share it.
//!
//! The counters are keyed by the link's subject, not by the acting
//! principal, so an action charges the counter of its own subject and of
//! every ancestor link, and delegation cannot multiply a parent's count or
//! sum. Windows are fixed and epoch-aligned: the window index is
//! `floor(evaluated_at / window_seconds)` on the gateway clock, so up to
//! twice a count can be admitted across a window boundary. The slots are
//! reserved atomically with the claim (`GatewayAttempts::claim_bounded`),
//! and are never released.
//!
//! One evaluator is registered: a ceiling on one named verified MCP
//! argument, a maximum count per counter per fixed window, and optionally a
//! sum limit per listed partition value and a scope listing the values one
//! verified argument may take.

use crate::engine::{GatewaySubmitResult, not_entered};
use crate::{CompiledRecipe, OperatorNamespace};
use auths_bounded_policy::kernel::{
    CeilingCountCode, PolicyMembers, SumBound, ValueList, argument_policy_tightens,
    ceiling_count_code, window_index,
};
use auths_bounded_policy::{
    CanonicalizationId, EvaluatorRegistrationV1, EvaluatorSemanticId, ImplementationId,
    PolicyTypeId, ProfileId, validate_registry,
};
use auths_model::{
    BoundedPolicyCommitment, CanonicalAction, Digest, FactName, FactValue, PolicyCommitment,
    PolicyIdentifier, PrincipalId, SignedGrant,
};
use auths_ports::ProfilePolicy as _;
use auths_profile_mcp::McpArgumentsPolicy;
use auths_registries::{
    BOUNDED_POLICY_COMMITMENT_EXTENSION_V1, OBSERVATION_REQUIREMENT_EXTENSION_V1,
};
use auths_verifier::VerifiedAction;
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};

/// Evaluator semantic identifier of the one registered evaluator.
pub const ARGUMENT_CEILING_EVALUATOR: &str = "auths.gateway.argument-ceiling-window-count/2";
/// Policy type the registered evaluator reads.
pub const ARGUMENT_CEILING_POLICY_TYPE: &str = "auths.gateway.argument-ceiling-policy/2";
/// Canonicalization of the registered evaluator's policy bytes.
pub const ARGUMENT_CEILING_CANONICALIZATION: &str = "auths.canonical-cbor/1";
/// Policy schema version of the registered evaluator.
pub const ARGUMENT_CEILING_POLICY_VERSION: u16 = 1;
/// Longest counting window, in seconds.
pub const MAX_WINDOW_SECONDS: u64 = 31 * 86_400;
/// Largest per-window count a policy may allow.
pub const MAX_WINDOW_COUNT: u64 = 1 << 32;
/// Largest sum limit a policy may carry.
pub const MAX_SUM_LIMIT: u64 = (1 << 53) - 1;
/// Largest number of values one partition or scope list may carry.
pub const MAX_LISTED_VALUES: usize = 16;
/// Longest listed value, in bytes.
pub const MAX_LISTED_VALUE_BYTES: usize = 64;
/// Largest number of bounded links one authorized branch may carry.
pub const MAX_BOUNDED_LINKS: usize = 16;

const MAX_POLICY_BYTES: usize = auths_model::MAX_BOUNDED_POLICY_BYTES;

/// Refusal while building or reading a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundedPolicyError {
    /// Policy bytes are malformed, non-canonical, or outside their bounds.
    #[error("invalid argument-ceiling policy")]
    InvalidPolicy,
}

fn invalid_policy<E>(_error: E) -> BoundedPolicyError {
    BoundedPolicyError::InvalidPolicy
}

/// A listed value: 1–64 bytes, each in `0x21..=0x7e`.
fn valid_listed_value(value: &str) -> bool {
    (1..=MAX_LISTED_VALUE_BYTES).contains(&value.len())
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// The values a policy lists for one named verified text argument: 1–16
/// sorted, unique values of 1–64 bytes in `0x21..=0x7e`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedValues {
    argument: FactName,
    values: Vec<String>,
}

impl ListedValues {
    /// Lists `values` for `argument`, in byte order.
    ///
    /// # Errors
    /// Refuses an invalid argument name, an empty or oversized list, an
    /// invalid value, or a repeated value.
    pub fn new(argument: &str, values: &[&str]) -> Result<Self, BoundedPolicyError> {
        let mut sorted: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        sorted.sort_unstable();
        Self::from_sorted(argument, sorted)
    }

    fn from_sorted(argument: &str, values: Vec<String>) -> Result<Self, BoundedPolicyError> {
        if !(1..=MAX_LISTED_VALUES).contains(&values.len())
            || !values.iter().all(|value| valid_listed_value(value))
            || values.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        Ok(Self {
            argument: FactName::parse(argument).map_err(invalid_policy)?,
            values,
        })
    }

    /// The named verified argument.
    #[must_use]
    pub fn argument(&self) -> &str {
        self.argument.as_str()
    }

    /// The listed values, in byte order.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Whether `value` is listed.
    #[must_use]
    pub fn lists(&self, value: &str) -> bool {
        self.values.iter().any(|listed| listed == value)
    }

    fn encode(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), BoundedPolicyError> {
        encoder.map(2).map_err(invalid_policy)?;
        encoder.u8(0).map_err(invalid_policy)?;
        encoder
            .str(self.argument.as_str())
            .map_err(invalid_policy)?;
        encoder.u8(1).map_err(invalid_policy)?;
        encoder
            .array(u64::try_from(self.values.len()).map_err(invalid_policy)?)
            .map_err(invalid_policy)?;
        for value in &self.values {
            encoder.str(value).map_err(invalid_policy)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, BoundedPolicyError> {
        if decoder.map().map_err(invalid_policy)? != Some(2) {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        next_key(decoder, 0)?;
        let argument = decoder.str().map_err(invalid_policy)?.to_owned();
        next_key(decoder, 1)?;
        let length = decoder
            .array()
            .map_err(invalid_policy)?
            .ok_or(BoundedPolicyError::InvalidPolicy)?;
        if length == 0 || length > MAX_LISTED_VALUES as u64 {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        let mut values = Vec::new();
        for _ in 0..length {
            values.push(decoder.str().map_err(invalid_policy)?.to_owned());
        }
        Self::from_sorted(&argument, values)
    }

    fn members(&self) -> ValueList {
        ValueList {
            argument: self.argument.as_str().as_bytes().to_vec(),
            values: self
                .values
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
        }
    }
}

/// Policy `auths.gateway.argument-ceiling-policy/2`: a ceiling on one named
/// verified argument, at most `max_count` admitted actions per counter in
/// each fixed window of `window_seconds`, and optionally a sum limit on the
/// argument, per listed partition value, and a scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentCeilingPolicy {
    argument: FactName,
    ceiling: u64,
    window_seconds: u64,
    max_count: u64,
    sum_limit: Option<u64>,
    partition: Option<ListedValues>,
    scope: Option<ListedValues>,
}

impl ArgumentCeilingPolicy {
    /// Constructs a policy with no sum limit and no scope.
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
            argument: FactName::parse(argument).map_err(invalid_policy)?,
            ceiling,
            window_seconds,
            max_count,
            sum_limit: None,
            partition: None,
            scope: None,
        })
    }

    /// Adds a sum limit, optionally per value of a listed partition
    /// argument.
    ///
    /// # Errors
    /// Refuses a limit outside `1..=MAX_SUM_LIMIT`, or a partition on the
    /// bounded argument itself.
    pub fn with_sum(
        mut self,
        limit: u64,
        partition: Option<ListedValues>,
    ) -> Result<Self, BoundedPolicyError> {
        if !(1..=MAX_SUM_LIMIT).contains(&limit)
            || partition
                .as_ref()
                .is_some_and(|partition| partition.argument == self.argument)
        {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        self.sum_limit = Some(limit);
        self.partition = partition;
        Ok(self)
    }

    /// Adds a scope.
    ///
    /// # Errors
    /// Refuses a scope on the bounded argument itself.
    pub fn with_scope(mut self, scope: ListedValues) -> Result<Self, BoundedPolicyError> {
        if scope.argument == self.argument {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        self.scope = Some(scope);
        Ok(self)
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

    /// The fixed, epoch-aligned counting window, in seconds.
    #[must_use]
    pub const fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    /// The largest number of admitted actions per counter per window.
    #[must_use]
    pub const fn max_count(&self) -> u64 {
        self.max_count
    }

    /// The sum limit, when the policy carries one.
    #[must_use]
    pub const fn sum_limit(&self) -> Option<u64> {
        self.sum_limit
    }

    /// The partition of the sum limit, when the policy carries one.
    #[must_use]
    pub const fn partition(&self) -> Option<&ListedValues> {
        self.partition.as_ref()
    }

    /// The scope, when the policy carries one.
    #[must_use]
    pub const fn scope(&self) -> Option<&ListedValues> {
        self.scope.as_ref()
    }

    /// Canonical CBOR: `{0: argument, 1: ceiling, 2: window_seconds,
    /// 3: max_count}`, then the optional `4: sum limit`, `5: partition`, and
    /// `6: scope`, where each list is `{0: argument, 1: [values]}`.
    ///
    /// # Errors
    /// Returns [`BoundedPolicyError::InvalidPolicy`] only if encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, BoundedPolicyError> {
        let members = 4
            + u64::from(self.sum_limit.is_some())
            + u64::from(self.partition.is_some())
            + u64::from(self.scope.is_some());
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(members).map_err(invalid_policy)?;
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
        if let Some(limit) = self.sum_limit {
            encoder.u8(4).map_err(invalid_policy)?;
            encoder.u64(limit).map_err(invalid_policy)?;
        }
        if let Some(partition) = &self.partition {
            encoder.u8(5).map_err(invalid_policy)?;
            partition.encode(&mut encoder)?;
        }
        if let Some(scope) = &self.scope {
            encoder.u8(6).map_err(invalid_policy)?;
            scope.encode(&mut encoder)?;
        }
        Ok(encoder.into_writer())
    }

    /// Decodes exactly the canonical encoding [`Self::encode`] produces.
    ///
    /// # Errors
    /// Refuses any other bytes, including a partition without a sum limit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BoundedPolicyError> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(BoundedPolicyError::InvalidPolicy);
        }
        let mut decoder = Decoder::new(bytes);
        let members = decoder
            .map()
            .map_err(invalid_policy)?
            .ok_or(BoundedPolicyError::InvalidPolicy)?;
        if !(4..=7).contains(&members) {
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
        let mut policy = Self::new(&argument, ceiling, window_seconds, max_count)?;
        let mut previous = 3;
        let mut sum_limit = None;
        let mut partition = None;
        for _ in 4..members {
            let key = decoder.u8().map_err(invalid_policy)?;
            if key <= previous {
                return Err(BoundedPolicyError::InvalidPolicy);
            }
            previous = key;
            match key {
                4 => sum_limit = Some(decoder.u64().map_err(invalid_policy)?),
                5 => partition = Some(ListedValues::decode(&mut decoder)?),
                6 => policy = policy.with_scope(ListedValues::decode(&mut decoder)?)?,
                _ => return Err(BoundedPolicyError::InvalidPolicy),
            }
        }
        match (sum_limit, partition) {
            (Some(limit), partition) => policy = policy.with_sum(limit, partition)?,
            (None, Some(_)) => return Err(BoundedPolicyError::InvalidPolicy),
            (None, None) => {}
        }
        if decoder.position() != bytes.len() || policy.encode()? != bytes {
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
            PolicyIdentifier::parse(ARGUMENT_CEILING_POLICY_TYPE, 128).map_err(invalid_policy)?,
            ARGUMENT_CEILING_POLICY_VERSION,
            PolicyIdentifier::parse(ARGUMENT_CEILING_CANONICALIZATION, 64)
                .map_err(invalid_policy)?,
            auths_codec::bounded_policy_digest(&policy).map_err(invalid_policy)?,
            PolicyIdentifier::parse(ARGUMENT_CEILING_EVALUATOR, 128).map_err(invalid_policy)?,
        )
        .map_err(invalid_policy)?;
        auths_codec::encode_bounded_policy_commitment(
            &BoundedPolicyCommitment::new(commitment, policy, parent).map_err(invalid_policy)?,
        )
        .map_err(invalid_policy)
    }

    /// The members the translated tightening decider reads.
    fn members(&self) -> PolicyMembers {
        PolicyMembers {
            argument: self.argument.as_str().as_bytes().to_vec(),
            ceiling: self.ceiling,
            window: self.window_seconds,
            max_count: self.max_count,
            sum: self.sum_limit.map(|limit| SumBound {
                limit,
                partition: self.partition.as_ref().map(ListedValues::members),
            }),
            scope: self.scope.as_ref().map(ListedValues::members),
        }
    }

    /// The registered tightening decider, the translated
    /// `argument_policy_tightens`: the same argument and window, a ceiling
    /// and count no larger, a sum no larger with the parent's partition
    /// argument and a subset of its values whenever the parent has a sum,
    /// and a scope on the same argument with a subset of its values whenever
    /// the parent has one.
    #[must_use]
    pub fn tightens(&self, parent: &Self) -> bool {
        argument_policy_tightens(&self.members(), &parent.members())
    }
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
        policy_type: PolicyTypeId::parse(ARGUMENT_CEILING_POLICY_TYPE).map_err(invalid)?,
        evaluator_semantic_id: EvaluatorSemanticId::parse(ARGUMENT_CEILING_EVALUATOR)
            .map_err(invalid)?,
        implementation_id: ImplementationId::parse(concat!(
            "auths-gateway/",
            env!("CARGO_PKG_VERSION")
        ))
        .map_err(invalid)?,
        canonicalization_id: CanonicalizationId::parse(ARGUMENT_CEILING_CANONICALIZATION)
            .map_err(invalid)?,
        rust_symbol: "auths_gateway::ArgumentCeilingPolicy::tightens",
        lean_artifact: "Auths.Product.CeilingCount",
        fixture_manifest: "bindings/fixtures/gateway/bounds-aggregate.json",
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
        ARGUMENT_CEILING_EVALUATOR => Ok(GatewayEvaluator::ArgumentCeilingWindowCount),
        _ => Err("gateway.policy.evaluator-unregistered"),
    }
}

/// One link: a bounded grant's subject and its decoded policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundLink {
    pub(crate) subject: PrincipalId,
    pub(crate) policy: ArgumentCeilingPolicy,
}

/// One distinct count counter of a chain and its capacity: the smallest
/// maximum count of the links whose subject it counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CountCounter {
    pub(crate) key: [u8; 32],
    pub(crate) capacity: u64,
}

/// One distinct sum counter of a chain and its capacity: the smallest sum
/// limit of the links that share it. Every action that charges it also
/// charges its subject's count counter, so it holds at most `slots` slots
/// in a window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SumCounter {
    pub(crate) key: [u8; 32],
    pub(crate) capacity: u64,
    pub(crate) slots: u64,
}

/// What admission reserves with the claim, and what the account-scope
/// binding and an auditor read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundAdmission {
    /// The links of the bounded branch, from its first bounded grant to its
    /// terminal grant.
    pub(crate) links: Vec<BoundLink>,
    /// The verified value of the bounded argument.
    pub(crate) argument: u64,
    pub(crate) window_seconds: u64,
    pub(crate) window_index: u64,
    /// The first second after the window.
    pub(crate) window_end: u64,
    /// Distinct count counters, in key order.
    pub(crate) counts: Vec<CountCounter>,
    /// Distinct sum counters, in key order.
    pub(crate) sums: Vec<SumCounter>,
}

impl BoundAdmission {
    /// When the slots may be swept: one full window after the window ends.
    pub(crate) const fn expires_at(&self) -> u64 {
        self.window_end.saturating_add(self.window_seconds)
    }
}

/// The sum a recipe's `bounds.sum` requires of every link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SumRequirement {
    pub(crate) argument: String,
    pub(crate) partition: Option<String>,
}

/// SHA-256 of `domain`, each component with an eight-byte big-endian length
/// prefix, then the window length and index.
fn counter_key(domain: &[u8], components: &[&[u8]], window_seconds: u64, index: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for component in components {
        hash.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(component);
    }
    hash.update(window_seconds.to_be_bytes());
    hash.update(index.to_be_bytes());
    hash.finalize().into()
}

/// The count counter of `subject` in one fixed window.
pub(crate) fn count_counter_key(
    namespace: &OperatorNamespace,
    subject: &PrincipalId,
    window_seconds: u64,
    index: u64,
) -> [u8; 32] {
    counter_key(
        b"auths.gateway-bounded-count/2\0",
        &[
            namespace.as_str().as_bytes(),
            subject.as_str().as_bytes(),
            ARGUMENT_CEILING_EVALUATOR.as_bytes(),
        ],
        window_seconds,
        index,
    )
}

/// The sum counter of `subject` and `partition` (empty when unpartitioned)
/// in one fixed window.
pub(crate) fn sum_counter_key(
    namespace: &OperatorNamespace,
    subject: &PrincipalId,
    partition: &str,
    window_seconds: u64,
    index: u64,
) -> [u8; 32] {
    counter_key(
        b"auths.gateway-bounded-sum/1\0",
        &[
            namespace.as_str().as_bytes(),
            subject.as_str().as_bytes(),
            ARGUMENT_CEILING_EVALUATOR.as_bytes(),
            partition.as_bytes(),
        ],
        window_seconds,
        index,
    )
}

/// The key of slot `slot` of count counter `counter`.
pub(crate) fn count_slot_key(counter: &[u8; 32], slot: u64) -> [u8; 32] {
    slot_key(b"auths.gateway-bounded-count-slot/2\0", counter, slot)
}

/// The key of slot `slot` of sum counter `counter`.
pub(crate) fn sum_slot_key(counter: &[u8; 32], slot: u64) -> [u8; 32] {
    slot_key(b"auths.gateway-bounded-sum-slot/1\0", counter, slot)
}

fn slot_key(domain: &[u8], counter: &[u8; 32], slot: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(counter);
    hash.update(slot.to_be_bytes());
    hash.finalize().into()
}

/// The verified text value of `argument`, or `argument-unavailable`.
fn text_argument(
    facts: &McpArgumentsPolicy,
    action: &CanonicalAction,
    argument: &str,
) -> Result<String, &'static str> {
    let unavailable = "gateway.policy.argument-unavailable";
    let name = FactName::parse(argument).map_err(|_| unavailable)?;
    match facts.action_fact(action, &name) {
        Ok(Some(FactValue::Text(text))) => Ok(text.as_str().to_owned()),
        _ => Err(unavailable),
    }
}

/// The registered evaluator's policy a link's commitment names: an
/// unregistered evaluator, a mismatched policy type, version, or
/// canonicalization, and malformed policy bytes are refused.
pub(crate) fn link_policy(
    commitment: &PolicyCommitment,
    policy: &[u8],
) -> Result<ArgumentCeilingPolicy, &'static str> {
    match registered(commitment)? {
        GatewayEvaluator::ArgumentCeilingWindowCount => {
            ArgumentCeilingPolicy::decode(policy).map_err(|_| "gateway.policy.evaluator-mismatch")
        }
    }
}

/// Admits the verified action under every link of its bounded branch and
/// derives the counters to reserve, or refuses it before any claim. An
/// empty chain is unbounded, which a recipe that declares `bounds.sum`
/// refuses.
///
/// The checks run in this order: the link count, tightening of every linked
/// pair, the argument and every ceiling, every scope and partition list,
/// the smallest sum limit, and the recipe's sum requirement.
pub(crate) fn admit_links(
    links: Vec<BoundLink>,
    action: &CanonicalAction,
    recipe: &CompiledRecipe,
    now: u64,
) -> Result<Option<BoundAdmission>, &'static str> {
    let requirement = recipe.sum_requirement();
    if links.len() > MAX_BOUNDED_LINKS {
        return Err("gateway.policy.too-many-bounds");
    }
    let Some(first) = links.first() else {
        return match requirement {
            Some(_) => Err("gateway.policy.sum-required"),
            None => Ok(None),
        };
    };
    let window_seconds = first.policy.window_seconds;
    for pair in links.windows(2) {
        if !pair[1].policy.tightens(&pair[0].policy) {
            return Err("gateway.policy.expanded");
        }
    }
    let facts = McpArgumentsPolicy::new().map_err(|_| "gateway.policy.registry-invalid")?;
    let argument = bounded_argument(&links, &facts, action)?;
    let partitions = listed_arguments(&links, &facts, action)?;
    if links
        .iter()
        .filter_map(|link| link.policy.sum_limit)
        .min()
        .is_some_and(|smallest| argument > smallest)
    {
        return Err("gateway.policy.above-sum-limit");
    }
    if let Some(requirement) = &requirement {
        let satisfies = |link: &BoundLink| {
            link.policy.sum_limit.is_some()
                && link.policy.argument() == requirement.argument
                && link.policy.partition().map(ListedValues::argument)
                    == requirement.partition.as_deref()
        };
        if !links.iter().all(satisfies) {
            return Err("gateway.policy.sum-required");
        }
    }
    let index = window_index(now, window_seconds).ok_or("gateway.policy.evaluator-mismatch")?;
    let window_end = index
        .checked_add(1)
        .and_then(|next| next.checked_mul(window_seconds))
        .filter(|end| end.checked_add(window_seconds).is_some())
        .ok_or("gateway.verify.clock-unavailable")?;
    let (counts, sums) = chain_counters(
        &links,
        &partitions,
        recipe.namespace(),
        window_seconds,
        index,
    );
    Ok(Some(BoundAdmission {
        links,
        argument,
        window_seconds,
        window_index: index,
        window_end,
        counts,
        sums,
    }))
}

/// The verified value of the chain's bounded argument, within every
/// link's ceiling.
fn bounded_argument(
    links: &[BoundLink],
    facts: &McpArgumentsPolicy,
    action: &CanonicalAction,
) -> Result<u64, &'static str> {
    let mut argument = None;
    for link in links {
        let name = &link.policy.argument;
        let Ok(Some(FactValue::Uint(value))) = facts.action_fact(action, name) else {
            return Err("gateway.policy.argument-unavailable");
        };
        if argument.is_some_and(|previous| previous != value) {
            return Err("gateway.policy.argument-unavailable");
        }
        argument = Some(value);
        if ceiling_count_code(value, link.policy.ceiling, 0, link.policy.max_count)
            == CeilingCountCode::AboveCeiling
        {
            return Err("gateway.policy.above-ceiling");
        }
    }
    argument.ok_or("gateway.policy.argument-unavailable")
}

/// Checks every scope and partition list against the verified values and
/// returns each link's partition value, empty for a link without one.
fn listed_arguments(
    links: &[BoundLink],
    facts: &McpArgumentsPolicy,
    action: &CanonicalAction,
) -> Result<Vec<String>, &'static str> {
    let mut partitions = Vec::with_capacity(links.len());
    for link in links {
        if let Some(scope) = &link.policy.scope
            && !scope.lists(&text_argument(facts, action, scope.argument())?)
        {
            return Err("gateway.policy.scope-denied");
        }
        let partition = match &link.policy.partition {
            None => String::new(),
            Some(partition) => {
                let value = text_argument(facts, action, partition.argument())?;
                if !partition.lists(&value) {
                    return Err("gateway.policy.partition-denied");
                }
                value
            }
        };
        partitions.push(partition);
    }
    Ok(partitions)
}

/// The chain's distinct count and sum counters in one fixed window, each
/// with the smallest capacity of the links that share it, in key order.
fn chain_counters(
    links: &[BoundLink],
    partitions: &[String],
    namespace: &OperatorNamespace,
    window_seconds: u64,
    index: u64,
) -> (Vec<CountCounter>, Vec<SumCounter>) {
    let mut counts: Vec<CountCounter> = Vec::new();
    for link in links {
        let key = count_counter_key(namespace, &link.subject, window_seconds, index);
        match counts.iter_mut().find(|counter| counter.key == key) {
            Some(counter) => counter.capacity = counter.capacity.min(link.policy.max_count),
            None => counts.push(CountCounter {
                key,
                capacity: link.policy.max_count,
            }),
        }
    }
    let mut sums: Vec<SumCounter> = Vec::new();
    for (link, partition) in links.iter().zip(partitions) {
        let Some(limit) = link.policy.sum_limit else {
            continue;
        };
        let count = count_counter_key(namespace, &link.subject, window_seconds, index);
        let slots = counts
            .iter()
            .find(|counter| counter.key == count)
            .map_or(0, |counter| counter.capacity);
        let key = sum_counter_key(namespace, &link.subject, partition, window_seconds, index);
        match sums.iter_mut().find(|counter| counter.key == key) {
            Some(counter) => counter.capacity = counter.capacity.min(limit),
            None => sums.push(SumCounter {
                key,
                capacity: limit,
                slots,
            }),
        }
    }
    counts.sort_by_key(|counter| counter.key);
    sums.sort_by_key(|counter| counter.key);
    (counts, sums)
}

/// One authorized branch: its actor, its grant chain root to terminal, and
/// its action envelope's validity window in seconds.
struct AuthorizedBranch {
    actor: PrincipalId,
    chain: Vec<SignedGrant>,
    validity_seconds: u64,
}

/// The authorized branch of every verified action.
fn authorized_chains(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
) -> Result<Vec<AuthorizedBranch>, &'static str> {
    let unavailable = "gateway.policy.proof-unavailable";
    let bundle = auths_codec::decode_bundle(proof_cbor, &auths_model::VerifierLimits::default())
        .map_err(|_| unavailable)?;
    let mut chains = Vec::with_capacity(verified.action_ids().len());
    for action_id in verified.action_ids() {
        let action = bundle
            .actions()
            .iter()
            .find(|action| {
                auths_codec::action_id(action.envelope()).is_ok_and(|id| id == *action_id)
            })
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
                .find(|grant| {
                    auths_codec::grant_id(grant.statement()).is_ok_and(|found| found == id)
                })
                .ok_or(unavailable)?;
            chain.push(grant.clone());
            cursor = grant.statement().parent();
        }
        chain.reverse();
        let validity = action.envelope().validity();
        chains.push(AuthorizedBranch {
            actor: action.envelope().actor().clone(),
            chain,
            validity_seconds: validity
                .expires_at()
                .get()
                .saturating_sub(validity.not_before().get()),
        });
    }
    Ok(chains)
}

/// What admission needs of the authorized branches.
pub(crate) struct BranchFacts {
    /// The actor of every authorized branch, in verified order.
    pub(crate) actors: Vec<PrincipalId>,
    /// Every observation requirement of every grant of every branch.
    pub(crate) requirements: Vec<auths_model::ObservationRequirement>,
    /// The longest action validity window of any branch.
    pub(crate) validity_seconds: u64,
}

/// The actors, observation requirements, and longest validity window of
/// every authorized branch.
pub(crate) fn authorized_branches(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
) -> Result<BranchFacts, &'static str> {
    let branches = authorized_chains(proof_cbor, verified)?;
    let mut requirements = Vec::new();
    for branch in &branches {
        for grant in &branch.chain {
            for extension in grant.statement().extensions().as_slice() {
                if extension.id().as_str() != OBSERVATION_REQUIREMENT_EXTENSION_V1 {
                    continue;
                }
                let decoded = auths_codec::decode_observation_requirements(extension.bytes())
                    .map_err(|_| "gateway.policy.proof-unavailable")?;
                requirements.extend(decoded.as_slice().iter().cloned());
            }
        }
    }
    Ok(BranchFacts {
        actors: branches.iter().map(|branch| branch.actor.clone()).collect(),
        requirements,
        validity_seconds: branches
            .iter()
            .map(|branch| branch.validity_seconds)
            .max()
            .unwrap_or(0),
    })
}

fn carries_bound(grant: &SignedGrant) -> bool {
    grant
        .statement()
        .extensions()
        .as_slice()
        .iter()
        .any(|extension| extension.id().as_str() == BOUNDED_POLICY_COMMITMENT_EXTENSION_V1)
}

/// The one authorized chain that carries a bound. The other branches of a
/// composed proof must be unbounded, such as approvers anchored directly in
/// trust; a joint count over two bounded branches has no specified meaning,
/// so that composition is refused.
fn bounded_chain(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
) -> Result<Option<Vec<SignedGrant>>, &'static str> {
    let mut chains: Vec<_> = authorized_chains(proof_cbor, verified)?
        .into_iter()
        .filter(|branch| branch.chain.iter().any(carries_bound))
        .map(|branch| branch.chain)
        .collect();
    match chains.len() {
        0 | 1 => Ok(chains.pop()),
        _ => Err("gateway.policy.multiple-branches"),
    }
}

/// Admits the verified action under every link of its bounded branch, or
/// refuses it before any claim. `Ok(None)` is an unbounded chain, which a
/// recipe that declares `bounds.sum` refuses.
pub(crate) fn admit_bounds(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
    recipe: &CompiledRecipe,
    now: u64,
) -> Result<Option<BoundAdmission>, GatewaySubmitResult> {
    let refuse = not_entered;
    let chain = bounded_chain(proof_cbor, verified).map_err(refuse)?;
    let mut bounds: Vec<(PrincipalId, BoundedPolicyCommitment)> = Vec::new();
    for grant in chain
        .iter()
        .flatten()
        .skip_while(|grant| !carries_bound(grant))
    {
        let mut found = None;
        for extension in grant.statement().extensions().as_slice() {
            if extension.id().as_str() != BOUNDED_POLICY_COMMITMENT_EXTENSION_V1 {
                continue;
            }
            let body = auths_codec::decode_bounded_policy_commitment(extension.bytes())
                .map_err(|_| refuse("gateway.policy.invalid-commitment"))?;
            if found.replace(body).is_some() {
                return Err(refuse("gateway.policy.invalid-commitment"));
            }
        }
        let body = found.ok_or_else(|| refuse("gateway.policy.dangling-link"))?;
        bounds.push((grant.statement().subject().clone(), body));
        if bounds.len() > MAX_BOUNDED_LINKS {
            return Err(refuse("gateway.policy.too-many-bounds"));
        }
    }
    if bounds
        .first()
        .is_some_and(|(_, root)| root.parent().is_some())
    {
        return Err(refuse("gateway.policy.dangling-link"));
    }
    let links = bounds
        .into_iter()
        .map(|(subject, body)| {
            link_policy(body.commitment(), body.policy())
                .map(|policy| BoundLink { subject, policy })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(refuse)?;
    admit_links(links, verified.canonical_action(), recipe, now).map_err(refuse)
}

/// The account-scope binding: for a recipe with `account_scope`, the action
/// has a bounded branch in which every link's policy carries a scope on the
/// recipe's field that lists the verified value. A recipe without
/// `account_scope` binds nothing.
///
/// # Errors
/// `gateway.account-scope.unbound` when there is no bounded branch or a link
/// carries no scope on the field, and `gateway.policy.scope-denied` when a
/// link's scope does not list the verified value.
pub(crate) fn bind_account_scope(
    recipe: &CompiledRecipe,
    bound: Option<&BoundAdmission>,
    arguments: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), &'static str> {
    let Some(field) = recipe.account_scope_field() else {
        return Ok(());
    };
    let unbound = "gateway.account-scope.unbound";
    let bound = bound.ok_or(unbound)?;
    let value = arguments
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(unbound)?;
    if bound.links.is_empty() {
        return Err(unbound);
    }
    for link in &bound.links {
        let scope = link
            .policy
            .scope()
            .filter(|scope| scope.argument() == field)
            .ok_or(unbound)?;
        if !scope.lists(value) {
            return Err("gateway.policy.scope-denied");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd() -> ListedValues {
        ListedValues::new("currency", &["usd"]).expect("list")
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
    fn extended_policy_round_trips_and_refuses_every_malformed_member() {
        let full = ArgumentCeilingPolicy::new("amount", 500, 86_400, 3)
            .and_then(|policy| policy.with_sum(1_000, Some(usd())))
            .and_then(|policy| {
                policy.with_scope(
                    ListedValues::new("connect_account", &["acct_2", "acct_1"]).expect("list"),
                )
            })
            .expect("policy");
        let bytes = full.encode().expect("bytes");
        assert_eq!(ArgumentCeilingPolicy::decode(&bytes), Ok(full.clone()));
        assert_eq!(
            full.scope().map(ListedValues::values),
            Some(&["acct_1".to_owned(), "acct_2".to_owned()][..])
        );
        let base = || ArgumentCeilingPolicy::new("amount", 500, 86_400, 3).expect("policy");
        assert!(base().with_sum(0, None).is_err());
        assert!(base().with_sum(MAX_SUM_LIMIT + 1, None).is_err());
        assert!(
            base()
                .with_sum(1, Some(ListedValues::new("amount", &["x"]).expect("list")))
                .is_err()
        );
        assert!(
            base()
                .with_scope(ListedValues::new("amount", &["x"]).expect("list"))
                .is_err()
        );
        assert!(ListedValues::new("currency", &[]).is_err());
        assert!(ListedValues::new("currency", &["usd", "usd"]).is_err());
        assert!(ListedValues::new("currency", &["has space"]).is_err());
        assert!(ListedValues::new("currency", &[&"x".repeat(65)]).is_err());
        let seventeen: Vec<String> = (0..17).map(|index| format!("v{index:02}")).collect();
        let seventeen: Vec<&str> = seventeen.iter().map(String::as_str).collect();
        assert!(ListedValues::new("currency", &seventeen).is_err());

        // A partition without a sum, and members out of order, are refused.
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(5).expect("map");
        encoder.u8(0).expect("key").str("amount").expect("argument");
        encoder.u8(1).expect("key").u64(500).expect("ceiling");
        encoder.u8(2).expect("key").u64(86_400).expect("window");
        encoder.u8(3).expect("key").u64(3).expect("count");
        encoder.u8(5).expect("key");
        usd().encode(&mut encoder).expect("partition");
        assert!(ArgumentCeilingPolicy::decode(&encoder.into_writer()).is_err());
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(6).expect("map");
        encoder.u8(0).expect("key").str("amount").expect("argument");
        encoder.u8(1).expect("key").u64(500).expect("ceiling");
        encoder.u8(2).expect("key").u64(86_400).expect("window");
        encoder.u8(3).expect("key").u64(3).expect("count");
        encoder.u8(5).expect("key");
        usd().encode(&mut encoder).expect("partition");
        encoder.u8(4).expect("key").u64(1_000).expect("sum");
        assert!(ArgumentCeilingPolicy::decode(&encoder.into_writer()).is_err());
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
        let summed = parent.clone().with_sum(1_000, Some(usd())).expect("sum");
        assert!(summed.tightens(&parent), "adding a sum only narrows");
        assert!(!parent.tightens(&summed), "dropping a sum widens");
    }

    #[test]
    fn registry_refuses_unregistered_and_mismatched_evaluators() {
        let digest = Digest::new([1; 32]);
        let commitment = |evaluator: &str, policy_type: &str, version| {
            PolicyCommitment::new(
                PolicyIdentifier::parse(policy_type, 128).expect("type"),
                version,
                PolicyIdentifier::parse(ARGUMENT_CEILING_CANONICALIZATION, 64).expect("canon"),
                digest,
                PolicyIdentifier::parse(evaluator, 128).expect("evaluator"),
            )
            .expect("commitment")
        };
        assert_eq!(
            registered(&commitment(
                ARGUMENT_CEILING_EVALUATOR,
                ARGUMENT_CEILING_POLICY_TYPE,
                1
            )),
            Ok(GatewayEvaluator::ArgumentCeilingWindowCount)
        );
        assert_eq!(
            registered(&commitment(
                "auths.gateway.argument-ceiling-window-count/1",
                ARGUMENT_CEILING_POLICY_TYPE,
                1
            )),
            Err("gateway.policy.evaluator-unregistered")
        );
        assert_eq!(
            registered(&commitment(
                ARGUMENT_CEILING_EVALUATOR,
                "auths.gateway.argument-ceiling-policy/1",
                1
            )),
            Err("gateway.policy.evaluator-mismatch")
        );
        assert_eq!(
            registered(&commitment(
                ARGUMENT_CEILING_EVALUATOR,
                ARGUMENT_CEILING_POLICY_TYPE,
                2
            )),
            Err("gateway.policy.evaluator-mismatch")
        );
    }

    #[test]
    fn counter_domains_keep_count_and_sum_keys_apart() {
        let namespace = OperatorNamespace::parse("stripe-refunds").expect("namespace");
        let subject = PrincipalId::parse("did:key:z6MkTest").expect("principal");
        let count = count_counter_key(&namespace, &subject, 86_400, 7);
        let sum = sum_counter_key(&namespace, &subject, "", 86_400, 7);
        assert_ne!(count, sum);
        assert_ne!(count, count_counter_key(&namespace, &subject, 86_400, 8));
        assert_ne!(
            sum_counter_key(&namespace, &subject, "usd", 86_400, 7),
            sum_counter_key(&namespace, &subject, "eur", 86_400, 7)
        );
        assert_ne!(count_slot_key(&count, 0), sum_slot_key(&count, 0));
        assert_ne!(count_slot_key(&count, 0), count_slot_key(&count, 1));
    }
}
