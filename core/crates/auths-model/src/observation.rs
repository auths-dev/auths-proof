//! Evidence-conditioned authority vocabulary.
//!
//! A grant may carry observation requirements: fresh facts, signed by an
//! observer the verifier trusts for that subject, must satisfy a closed
//! conjunction of typed conditions before the action is authorized. The only
//! condition atoms are exact equality with a literal, exact equality with a
//! profile-derived action fact, an inclusive unsigned range, and membership
//! in a bounded literal list. There is no disjunction, negation, arithmetic,
//! pattern, or user-defined function, so adding a requirement or a condition
//! can only remove actions from the authorized set.
//!
//! The predicates at the end of this module are pure, bounded, and written in
//! the restricted style the mechanical Rust-to-Lean translation accepts.

use crate::{
    EvidenceObject, HARD_MAX_PERMISSIONS, HARD_MAX_REGISTRY_ENTRIES, ModelError, PrincipalId,
    PrincipalMethodId, ProtocolVersion, ResourceId, SignatureEnvelope, Timestamp, ValidityWindow,
    byte_slices_equal, parse_bounded,
};
use alloc::{string::String, vec::Vec};
use core::fmt;

/// Maximum facts in one observation statement.
pub const MAX_OBSERVATION_FACTS: usize = 16;
/// Maximum bytes in a byte-string fact value.
pub const MAX_FACT_VALUE_BYTES: usize = 64;
/// Maximum UTF-8 bytes in a text fact value.
pub const MAX_FACT_VALUE_TEXT_BYTES: usize = 256;
/// Maximum conditions in one observation requirement.
pub const MAX_OBSERVATION_CONDITIONS: usize = 16;
/// Maximum literal values in one membership condition.
pub const MAX_MEMBER_VALUES: usize = 16;
/// Maximum observation requirements carried by one grant.
pub const MAX_OBSERVATION_REQUIREMENTS_PER_GRANT: usize = 8;
/// Maximum distinct observation requirements evaluated for one grant chain.
pub const MAX_OBSERVATION_REQUIREMENTS_PER_CHAIN: usize = 32;
/// Maximum observation attachments bound by one action.
pub const MAX_OBSERVATION_ATTACHMENTS: usize = 32;
/// Maximum bytes of one signed observation attachment.
pub const MAX_OBSERVATION_BYTES: usize = 4_096;
/// Largest accepted requirement maximum age, in seconds.
pub const MAX_OBSERVATION_AGE_SECONDS: u32 = 86_400;
/// Maximum observer anchors in one trusted context.
pub const MAX_OBSERVER_ANCHORS: usize = 32;
/// Maximum control-evidence objects carried by one signed observation.
pub const MAX_OBSERVATION_EVIDENCE: usize = 4;
/// Media type that marks a detached attachment as a signed observation.
pub const OBSERVATION_MEDIA_TYPE: &str = "application/vnd.auths.observation.v1+cbor";

bounded_string!(ObservationSchemaId, 128, ModelError::InvalidObservation);
bounded_string!(ObserverAnchorId, 128, ModelError::InvalidObserverAnchor);
bounded_string!(FactName, 128, ModelError::InvalidObservation);

/// Exact fact-name equality used by production and extraction.
#[doc(hidden)]
#[must_use]
pub fn fact_name_equal(left: &FactName, right: &FactName) -> bool {
    byte_slices_equal(left.0.as_bytes(), right.0.as_bytes())
}

/// Bounded byte-string fact value.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FactBytes(Vec<u8>);

impl FactBytes {
    /// Constructs a byte-string fact value of at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservation`] above the bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.len() > MAX_FACT_VALUE_BYTES {
            return Err(ModelError::InvalidObservation);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Bounded UTF-8 text fact value.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FactText(String);

impl FactText {
    /// Constructs a text fact value of at most 256 UTF-8 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservation`] above the bound.
    pub fn new(value: &str) -> Result<Self, ModelError> {
        if value.len() > MAX_FACT_VALUE_TEXT_BYTES {
            return Err(ModelError::InvalidObservation);
        }
        Ok(Self(String::from(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One typed observed or action-derived fact value.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FactValue {
    Uint(u64),
    Bytes(FactBytes),
    Text(FactText),
}

/// One named fact inside an observation statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationFact {
    name: FactName,
    value: FactValue,
}

impl ObservationFact {
    #[must_use]
    pub const fn new(name: FactName, value: FactValue) -> Self {
        Self { name, value }
    }
    #[must_use]
    pub const fn name(&self) -> &FactName {
        &self.name
    }
    #[must_use]
    pub const fn value(&self) -> &FactValue {
        &self.value
    }
}

/// Canonical, non-empty fact map ordered by fact name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationFacts(Vec<ObservationFact>);

impl ObservationFacts {
    /// Sorts and validates one to sixteen uniquely named facts.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservation`] for no facts, more than
    /// [`MAX_OBSERVATION_FACTS`], or a repeated fact name.
    pub fn new(mut facts: Vec<ObservationFact>) -> Result<Self, ModelError> {
        if facts.is_empty() || facts.len() > MAX_OBSERVATION_FACTS {
            return Err(ModelError::InvalidObservation);
        }
        facts.sort_by(|left, right| left.name.cmp(&right.name));
        if facts
            .windows(2)
            .any(|window| window[0].name == window[1].name)
        {
            return Err(ModelError::InvalidObservation);
        }
        Ok(Self(facts))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ObservationFact] {
        &self.0
    }
}

/// Unsigned facts an observer asserts about one subject at one time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationStatement {
    version: ProtocolVersion,
    observer: PrincipalId,
    schema: ObservationSchemaId,
    subject: ResourceId,
    observed_at: Timestamp,
    facts: ObservationFacts,
}

impl ObservationStatement {
    #[must_use]
    pub const fn new(
        observer: PrincipalId,
        schema: ObservationSchemaId,
        subject: ResourceId,
        observed_at: Timestamp,
        facts: ObservationFacts,
    ) -> Self {
        Self {
            version: ProtocolVersion::V1,
            observer,
            schema,
            subject,
            observed_at,
            facts,
        }
    }
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    #[must_use]
    pub const fn observer(&self) -> &PrincipalId {
        &self.observer
    }
    #[must_use]
    pub const fn schema(&self) -> &ObservationSchemaId {
        &self.schema
    }
    #[must_use]
    pub const fn subject(&self) -> &ResourceId {
        &self.subject
    }
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
    #[must_use]
    pub const fn facts(&self) -> &ObservationFacts {
        &self.facts
    }
}

/// Observation statement, observer signature, and the observer's bounded
/// control evidence, carried as one detached attachment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedObservation {
    statement: ObservationStatement,
    signature: SignatureEnvelope,
    evidence: Vec<EvidenceObject>,
}

impl SignedObservation {
    /// Constructs a signed observation with canonical control evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservation`] for more than
    /// [`MAX_OBSERVATION_EVIDENCE`] evidence objects or a repeated evidence
    /// identifier.
    pub fn new(
        statement: ObservationStatement,
        signature: SignatureEnvelope,
        mut evidence: Vec<EvidenceObject>,
    ) -> Result<Self, ModelError> {
        if evidence.len() > MAX_OBSERVATION_EVIDENCE {
            return Err(ModelError::InvalidObservation);
        }
        evidence.sort_by_key(EvidenceObject::id);
        if evidence
            .windows(2)
            .any(|window| window[0].id() == window[1].id())
        {
            return Err(ModelError::InvalidObservation);
        }
        Ok(Self {
            statement,
            signature,
            evidence,
        })
    }
    #[must_use]
    pub const fn statement(&self) -> &ObservationStatement {
        &self.statement
    }
    #[must_use]
    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceObject] {
        &self.evidence
    }
}

/// The subject a requirement binds: a literal resource, or a resource named
/// by a profile action fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationSubject {
    Resource(ResourceId),
    ActionFact(FactName),
}

/// Inclusive unsigned range with `lo <= hi`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UintRange {
    lo: u64,
    hi: u64,
}

impl UintRange {
    /// Constructs an inclusive range.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservationRequirement`] when `lo > hi`.
    pub const fn new(lo: u64, hi: u64) -> Result<Self, ModelError> {
        if lo > hi {
            return Err(ModelError::InvalidObservationRequirement);
        }
        Ok(Self { lo, hi })
    }
    #[must_use]
    pub const fn lo(self) -> u64 {
        self.lo
    }
    #[must_use]
    pub const fn hi(self) -> u64 {
        self.hi
    }
}

/// One to sixteen distinct literal values, in signed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberValues(Vec<FactValue>);

impl MemberValues {
    /// Validates a bounded, duplicate-free membership list.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservationRequirement`] for an empty or
    /// oversized list, or a repeated value.
    pub fn new(values: Vec<FactValue>) -> Result<Self, ModelError> {
        if values.is_empty() || values.len() > MAX_MEMBER_VALUES {
            return Err(ModelError::InvalidObservationRequirement);
        }
        for (index, value) in values.iter().enumerate() {
            if values[..index].contains(value) {
                return Err(ModelError::InvalidObservationRequirement);
            }
        }
        Ok(Self(values))
    }
    #[must_use]
    pub fn as_slice(&self) -> &[FactValue] {
        &self.0
    }
}

/// The closed set of condition atoms applied to one named observed fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConditionTest {
    /// The observed fact equals the literal.
    EqLiteral(FactValue),
    /// The observed fact equals the named profile action fact.
    EqAction(FactName),
    /// The observed fact is an unsigned integer inside the inclusive range.
    UintRange(UintRange),
    /// The observed fact equals one of the literals.
    Member(MemberValues),
}

/// One condition: a fact name and the atom applied to its observed value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationCondition {
    name: FactName,
    test: ConditionTest,
}

impl ObservationCondition {
    #[must_use]
    pub const fn new(name: FactName, test: ConditionTest) -> Self {
        Self { name, test }
    }
    #[must_use]
    pub const fn name(&self) -> &FactName {
        &self.name
    }
    #[must_use]
    pub const fn test(&self) -> &ConditionTest {
        &self.test
    }
    /// Returns the action fact this condition compares against, if any.
    #[must_use]
    pub const fn action_fact(&self) -> Option<&FactName> {
        match &self.test {
            ConditionTest::EqAction(name) => Some(name),
            _ => None,
        }
    }
}

/// One requirement: a trusted observer, a schema, a subject, a maximum age,
/// and a conjunction of conditions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationRequirement {
    observer_anchor: ObserverAnchorId,
    schema: ObservationSchemaId,
    subject: ObservationSubject,
    max_age_seconds: u32,
    conditions: Vec<ObservationCondition>,
}

impl ObservationRequirement {
    /// Constructs a bounded requirement.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservationRequirement`] when the
    /// maximum age is outside `1..=86400` or the condition list is empty or
    /// longer than [`MAX_OBSERVATION_CONDITIONS`].
    pub fn new(
        observer_anchor: ObserverAnchorId,
        schema: ObservationSchemaId,
        subject: ObservationSubject,
        max_age_seconds: u32,
        conditions: Vec<ObservationCondition>,
    ) -> Result<Self, ModelError> {
        if max_age_seconds == 0
            || max_age_seconds > MAX_OBSERVATION_AGE_SECONDS
            || conditions.is_empty()
            || conditions.len() > MAX_OBSERVATION_CONDITIONS
        {
            return Err(ModelError::InvalidObservationRequirement);
        }
        Ok(Self {
            observer_anchor,
            schema,
            subject,
            max_age_seconds,
            conditions,
        })
    }
    #[must_use]
    pub const fn observer_anchor(&self) -> &ObserverAnchorId {
        &self.observer_anchor
    }
    #[must_use]
    pub const fn schema(&self) -> &ObservationSchemaId {
        &self.schema
    }
    #[must_use]
    pub const fn subject(&self) -> &ObservationSubject {
        &self.subject
    }
    #[must_use]
    pub const fn max_age_seconds(&self) -> u32 {
        self.max_age_seconds
    }
    #[must_use]
    pub fn conditions(&self) -> &[ObservationCondition] {
        &self.conditions
    }
}

/// The one to eight requirements carried by a grant's
/// `observation-requirement-v1` critical extension, in signed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationRequirements(Vec<ObservationRequirement>);

impl ObservationRequirements {
    /// Validates a bounded, duplicate-free requirement list.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObservationRequirement`] for an empty
    /// list or a repeated requirement, and
    /// [`ModelError::CollectionLimitExceeded`] above
    /// [`MAX_OBSERVATION_REQUIREMENTS_PER_GRANT`].
    pub fn new(requirements: Vec<ObservationRequirement>) -> Result<Self, ModelError> {
        if requirements.is_empty() {
            return Err(ModelError::InvalidObservationRequirement);
        }
        if requirements.len() > MAX_OBSERVATION_REQUIREMENTS_PER_GRANT {
            return Err(ModelError::CollectionLimitExceeded);
        }
        for (index, requirement) in requirements.iter().enumerate() {
            if requirements[..index].contains(requirement) {
                return Err(ModelError::InvalidObservationRequirement);
            }
        }
        Ok(Self(requirements))
    }
    #[must_use]
    pub fn as_slice(&self) -> &[ObservationRequirement] {
        &self.0
    }
}

/// A verifier-trusted observer. It can make facts count; it can never
/// authorize an action, issue a grant, or appear in an authority chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverAnchor {
    id: ObserverAnchorId,
    principal: PrincipalId,
    accepted_methods: Vec<PrincipalMethodId>,
    schemas: Vec<ObservationSchemaId>,
    subject_namespaces: Vec<ResourceId>,
    validity: ValidityWindow,
}

impl ObserverAnchor {
    /// Constructs a canonical observer anchor.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidObserverAnchor`] when any list is empty or
    /// exceeds its protocol bound.
    pub fn new(
        id: ObserverAnchorId,
        principal: PrincipalId,
        mut accepted_methods: Vec<PrincipalMethodId>,
        mut schemas: Vec<ObservationSchemaId>,
        mut subject_namespaces: Vec<ResourceId>,
        validity: ValidityWindow,
    ) -> Result<Self, ModelError> {
        accepted_methods.sort();
        accepted_methods.dedup();
        schemas.sort();
        schemas.dedup();
        subject_namespaces.sort();
        subject_namespaces.dedup();
        if accepted_methods.is_empty()
            || accepted_methods.len() > HARD_MAX_REGISTRY_ENTRIES
            || schemas.is_empty()
            || schemas.len() > HARD_MAX_REGISTRY_ENTRIES
            || subject_namespaces.is_empty()
            || subject_namespaces.len() > HARD_MAX_PERMISSIONS
        {
            return Err(ModelError::InvalidObserverAnchor);
        }
        Ok(Self {
            id,
            principal,
            accepted_methods,
            schemas,
            subject_namespaces,
            validity,
        })
    }
    #[must_use]
    pub const fn id(&self) -> &ObserverAnchorId {
        &self.id
    }
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    #[must_use]
    pub fn accepted_methods(&self) -> &[PrincipalMethodId] {
        &self.accepted_methods
    }
    #[must_use]
    pub fn schemas(&self) -> &[ObservationSchemaId] {
        &self.schemas
    }
    #[must_use]
    pub fn subject_namespaces(&self) -> &[ResourceId] {
        &self.subject_namespaces
    }
    #[must_use]
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
}

/// The observation that satisfied one requirement, reported in the result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObservationSatisfaction {
    requirement: crate::ObservationRequirementId,
    observation: crate::AttachmentDigest,
}

impl ObservationSatisfaction {
    #[must_use]
    pub const fn new(
        requirement: crate::ObservationRequirementId,
        observation: crate::AttachmentDigest,
    ) -> Self {
        Self {
            requirement,
            observation,
        }
    }
    /// Content identifier of the satisfied requirement.
    #[must_use]
    pub const fn requirement(self) -> crate::ObservationRequirementId {
        self.requirement
    }
    /// Signed attachment digest of the satisfying observation.
    #[must_use]
    pub const fn observation(self) -> crate::AttachmentDigest {
        self.observation
    }
}

/// Three-valued verdict for one requirement.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequirementVerdict {
    /// Some eligible observation satisfies every condition.
    Satisfied,
    /// Eligible observations exist and each falsifies some condition.
    ConditionFalse,
    /// No fresh, authentic, subject-matching observation exists.
    Missing,
}

/// Freshness at the verifier's evaluation time, inside the observer
/// anchor's inclusive validity. A future-dated observation is never fresh.
#[doc(hidden)]
#[must_use]
pub const fn observation_fresh(
    observed_at: u64,
    evaluation_time: u64,
    max_age_seconds: u64,
    anchor_not_before: u64,
    anchor_expires_at: u64,
) -> bool {
    if observed_at > evaluation_time {
        return false;
    }
    if evaluation_time - observed_at > max_age_seconds {
        return false;
    }
    observed_at >= anchor_not_before && observed_at <= anchor_expires_at
}

/// Exact subject binding: the resolved subject equals the observed subject.
#[doc(hidden)]
#[must_use]
pub fn observation_subject_equal(expected: &ResourceId, observed: &ResourceId) -> bool {
    byte_slices_equal(expected.0.as_bytes(), observed.0.as_bytes())
}

/// Exact typed fact equality. Values of different types are never equal.
#[doc(hidden)]
#[must_use]
pub fn fact_value_equal(left: &FactValue, right: &FactValue) -> bool {
    match left {
        FactValue::Uint(left) => match right {
            FactValue::Uint(right) => *left == *right,
            _ => false,
        },
        FactValue::Bytes(left) => match right {
            FactValue::Bytes(right) => byte_slices_equal(&left.0, &right.0),
            _ => false,
        },
        FactValue::Text(left) => match right {
            FactValue::Text(right) => byte_slices_equal(left.0.as_bytes(), right.0.as_bytes()),
            _ => false,
        },
    }
}

/// Inclusive unsigned range membership.
#[doc(hidden)]
#[must_use]
pub const fn uint_range_contains(lo: u64, hi: u64, value: u64) -> bool {
    value >= lo && value <= hi
}

/// Bounded membership in a literal list.
#[doc(hidden)]
#[must_use]
pub fn member_values_contain(values: &MemberValues, value: &FactValue) -> bool {
    let mut index = 0;
    while index < values.0.len() {
        if fact_value_equal(&values.0[index], value) {
            return true;
        }
        index += 1;
    }
    false
}

/// The observed value bound to `name`, if the observation carries it.
#[doc(hidden)]
#[must_use]
pub fn observation_fact<'a>(facts: &'a ObservationFacts, name: &FactName) -> Option<&'a FactValue> {
    let mut index = 0;
    while index < facts.0.len() {
        if fact_name_equal(&facts.0[index].name, name) {
            return Some(&facts.0[index].value);
        }
        index += 1;
    }
    None
}

/// One condition atom against the looked-up observed value. A missing fact,
/// a missing action value, or a type mismatch makes the condition false.
#[doc(hidden)]
#[must_use]
pub fn condition_value_holds(
    test: &ConditionTest,
    observed: Option<&FactValue>,
    action_value: Option<&FactValue>,
) -> bool {
    match observed {
        None => false,
        Some(observed) => match test {
            ConditionTest::EqLiteral(literal) => fact_value_equal(observed, literal),
            ConditionTest::EqAction(_) => match action_value {
                Some(action_value) => fact_value_equal(observed, action_value),
                None => false,
            },
            ConditionTest::UintRange(range) => match observed {
                FactValue::Uint(value) => uint_range_contains(range.lo, range.hi, *value),
                _ => false,
            },
            ConditionTest::Member(values) => member_values_contain(values, observed),
        },
    }
}

/// Every condition holds for one observation. `action_values[i]` is the
/// resolved action fact for `conditions[i]` and is ignored for atoms that
/// do not reference an action fact; a length mismatch is false.
#[doc(hidden)]
#[must_use]
pub fn observation_conditions_hold(
    conditions: &[ObservationCondition],
    action_values: &[Option<FactValue>],
    facts: &ObservationFacts,
) -> bool {
    if conditions.len() != action_values.len() {
        return false;
    }
    let mut index = 0;
    while index < conditions.len() {
        if !observation_condition_holds(&conditions[index], &action_values[index], facts) {
            return false;
        }
        index += 1;
    }
    true
}

/// One condition against the observation's facts and its resolved action
/// value. Kept separate from the loop so each iteration borrows nothing
/// across the loop join, which the mechanical translation requires.
#[doc(hidden)]
#[must_use]
pub fn observation_condition_holds(
    condition: &ObservationCondition,
    action_value: &Option<FactValue>,
    facts: &ObservationFacts,
) -> bool {
    let observed = observation_fact(facts, &condition.name);
    match action_value {
        Some(value) => condition_value_holds(&condition.test, observed, Some(value)),
        None => condition_value_holds(&condition.test, observed, None),
    }
}

/// Combines eligibility and satisfaction into the per-requirement verdict.
#[doc(hidden)]
#[must_use]
pub const fn requirement_verdict(any_eligible: bool, any_satisfying: bool) -> RequirementVerdict {
    if any_satisfying {
        return RequirementVerdict::Satisfied;
    }
    if any_eligible {
        return RequirementVerdict::ConditionFalse;
    }
    RequirementVerdict::Missing
}
