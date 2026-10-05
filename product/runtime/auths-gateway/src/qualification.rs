//! The runtime qualification gate: whether this deployment's exact recipe,
//! contract, build, and target are attested by signed release inputs that
//! are current, unrevoked, and checked against trusted time.
//!
//! The gate verifies signatures once per set of inputs and keeps the result
//! in memory. Before every lease it compares the deployment's tuple with
//! that result and evaluates the signed time bounds and revocations. It
//! performs no provider call and no network fetch, runs no qualification,
//! and is never told a provider's name: the tuple carries the provider
//! contract as a digest.

use crate::ClockTrustState;
use auths_recipe_qualification::{
    QualificationInputs, QualificationRefusal, QualificationTrustRoot, QualificationTuple,
    QualificationVerdict, RecipeQualificationState, VerifiedQualifications, VerifierState,
};
use sha2::{Digest as _, Sha256};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The install-time refusal of a qualification policy that is unknown or
/// that production does not permit.
pub const QUALIFICATION_POLICY_REFUSED: &str = "gateway.install.qualification-policy";

/// The schema identifier of the production lifecycle store.
pub const POSTGRES_STORE_SCHEMA: &str = "auths.lifecycle.postgresql/5";
/// The schema identifier of the development file store.
pub const FILE_STORE_SCHEMA: &str = "auths.gateway-attempt/3";

/// The stable code of one refusal.
#[must_use]
pub const fn qualification_code(refusal: QualificationRefusal) -> &'static str {
    match refusal {
        QualificationRefusal::Unavailable => "gateway.qualification.unavailable",
        QualificationRefusal::Revoked => "gateway.qualification.revoked",
        QualificationRefusal::ClockUntrusted => "gateway.qualification.clock-untrusted",
        QualificationRefusal::RevocationStale => "gateway.qualification.revocation-stale",
        QualificationRefusal::Missing => "gateway.qualification.missing",
        QualificationRefusal::Expired => "gateway.qualification.expired",
        QualificationRefusal::DigestMismatch => "gateway.qualification.digest-mismatch",
        QualificationRefusal::TargetMismatch => "gateway.qualification.target-mismatch",
    }
}

/// Whether a connection needs a qualification to lease its credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationPolicy {
    /// No lease without a current qualification.
    Required,
    /// Development only: the state is reported and never refuses.
    Optional,
}

impl QualificationPolicy {
    /// The canonical token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// Decides the policy of an installation.
///
/// Without a token, production requires qualification and development does
/// not. Production never accepts `optional`.
///
/// # Errors
///
/// Returns [`QUALIFICATION_POLICY_REFUSED`] for a token outside the closed
/// set and for `optional` under production policy.
pub fn qualification_policy(
    token: Option<&str>,
    production: bool,
) -> Result<QualificationPolicy, &'static str> {
    match (token, production) {
        (None | Some("required"), true) | (Some("required"), false) => {
            Ok(QualificationPolicy::Required)
        }
        (None | Some("optional"), false) => Ok(QualificationPolicy::Optional),
        _ => Err(QUALIFICATION_POLICY_REFUSED),
    }
}

mod sealed {
    pub trait Sealed {}
}

/// The time and clock trust a deployment supplies.
///
/// The trait is sealed: only this crate's maintained adapters implement it,
/// so no recipe, application, SDK, or configuration can supply clock trust.
pub trait DeploymentClock: sealed::Sealed + Send + Sync {
    /// Local time in unix seconds, when the clock can be read.
    fn now(&self) -> Option<u64>;
    /// Whether the platform reports the clock synchronized.
    fn trust(&self) -> ClockTrustState;
}

fn system_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// The production clock adapter: trusted exactly while the host's time
/// synchronization service has recorded a synchronization.
///
/// The service records one by creating a fixed marker file. The path is a
/// constant of this adapter and no configuration names another.
#[derive(Clone, Copy, Debug, Default)]
pub struct SynchronizedHostClock;

impl SynchronizedHostClock {
    /// The marker the host's time synchronization service creates once the
    /// clock is synchronized.
    pub const MARKER: &'static str = "/run/systemd/timesync/synchronized";
}

impl sealed::Sealed for SynchronizedHostClock {}

impl DeploymentClock for SynchronizedHostClock {
    fn now(&self) -> Option<u64> {
        system_seconds()
    }

    fn trust(&self) -> ClockTrustState {
        if std::fs::metadata(Self::MARKER).is_ok_and(|marker| marker.is_file()) {
            ClockTrustState::Trusted
        } else {
            ClockTrustState::Untrusted
        }
    }
}

/// The development clock adapter: the local clock, taken as trusted. A
/// production deployment never uses it.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevelopmentClock;

impl sealed::Sealed for DevelopmentClock {}

impl DeploymentClock for DevelopmentClock {
    fn now(&self) -> Option<u64> {
        system_seconds()
    }

    fn trust(&self) -> ClockTrustState {
        ClockTrustState::Trusted
    }
}

/// A clock a test sets.
#[cfg(any(test, feature = "testkit-harness"))]
#[derive(Debug)]
pub struct FixedClock {
    now: std::sync::atomic::AtomicU64,
    trusted: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "testkit-harness"))]
impl FixedClock {
    /// A trusted clock at `now`.
    #[must_use]
    pub const fn at(now: u64) -> Self {
        Self {
            now: std::sync::atomic::AtomicU64::new(now),
            trusted: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Moves the clock.
    pub fn set(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::SeqCst);
    }

    /// Sets what the platform reports.
    pub fn trust_is(&self, trusted: bool) {
        self.trusted
            .store(trusted, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "testkit-harness"))]
impl sealed::Sealed for Arc<FixedClock> {}

#[cfg(any(test, feature = "testkit-harness"))]
impl DeploymentClock for Arc<FixedClock> {
    fn now(&self) -> Option<u64> {
        Some(self.now.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn trust(&self) -> ClockTrustState {
        if self.trusted.load(std::sync::atomic::Ordering::SeqCst) {
            ClockTrustState::Trusted
        } else {
            ClockTrustState::Untrusted
        }
    }
}

/// The signed release inputs an operator placed on this host.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QualificationBundle {
    /// The signer certificate.
    pub signer_certificate: Vec<u8>,
    /// The revocation list.
    pub revocation_list: Vec<u8>,
    /// The release index.
    pub release_index: Vec<u8>,
    /// The records.
    pub records: Vec<Vec<u8>>,
    /// The attestations.
    pub attestations: Vec<Vec<u8>>,
}

impl QualificationBundle {
    /// One digest over every input, each framed by its length, so two
    /// bundles are equal exactly when their digests are.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut frame = |bytes: &[u8]| {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };
        frame(&self.signer_certificate);
        frame(&self.revocation_list);
        frame(&self.release_index);
        for group in [&self.records, &self.attestations] {
            frame(&(group.len() as u64).to_be_bytes());
            for member in group {
                frame(member);
            }
        }
        hasher.finalize().into()
    }

    fn verify(&self, root: &QualificationTrustRoot) -> VerifiedQualifications {
        let records: Vec<&[u8]> = self.records.iter().map(Vec::as_slice).collect();
        let attestations: Vec<&[u8]> = self.attestations.iter().map(Vec::as_slice).collect();
        VerifiedQualifications::verify(
            root,
            &QualificationInputs {
                signer_certificate: &self.signer_certificate,
                revocation_list: &self.revocation_list,
                release_index: &self.release_index,
                records: &records,
                attestations: &attestations,
            },
        )
    }
}

/// The verified result of one bundle.
struct Loaded {
    digest: [u8; 32],
    verified: VerifiedQualifications,
}

/// What the gate reports about itself. It names no provider and echoes no
/// input value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationStatus {
    /// The installation's policy.
    pub policy: QualificationPolicy,
    /// The derived state.
    pub state: RecipeQualificationState,
    /// The stable code of the first failed condition, when not qualified.
    pub code: Option<&'static str>,
}

impl QualificationStatus {
    /// Whether a credential may be leased under this status.
    #[must_use]
    pub const fn permits_lease(&self) -> bool {
        matches!(self.policy, QualificationPolicy::Optional) || self.code.is_none()
    }
}

/// The qualification gate of one installed recipe.
///
/// Invariant `fail-closed-qualification`: under the `required` policy the
/// gate permits a lease only when a bundle verified under the pinned trust
/// root qualifies exactly this deployment's tuple at the deployment clock's
/// trusted time and nothing it names is revoked. A missing root, tuple,
/// bundle, or clock refuses. There is no override and no grace period.
pub struct QualificationGate {
    policy: QualificationPolicy,
    root: Option<QualificationTrustRoot>,
    deployment: Option<QualificationTuple>,
    clock: Box<dyn DeploymentClock>,
    loaded: RwLock<Option<Arc<Loaded>>>,
    state: Mutex<VerifierState>,
}

impl std::fmt::Debug for QualificationGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QualificationGate")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl QualificationGate {
    /// A development gate: nothing is required and nothing is verified.
    #[must_use]
    pub fn development() -> Self {
        Self::new(
            QualificationPolicy::Optional,
            None,
            None,
            Box::new(DevelopmentClock),
            VerifierState::default(),
        )
    }

    /// The gate of an engine no operator plane has configured: qualification
    /// is required and nothing can satisfy it.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self::new(
            QualificationPolicy::Required,
            None,
            None,
            Box::new(DevelopmentClock),
            VerifierState::default(),
        )
    }

    /// A gate for `deployment` under `root`, resuming from what earlier
    /// inputs revoked.
    #[must_use]
    pub fn new(
        policy: QualificationPolicy,
        root: Option<QualificationTrustRoot>,
        deployment: Option<QualificationTuple>,
        clock: Box<dyn DeploymentClock>,
        state: VerifierState,
    ) -> Self {
        Self {
            policy,
            root,
            deployment,
            clock,
            loaded: RwLock::new(None),
            state: Mutex::new(state),
        }
    }

    /// The installation's policy.
    #[must_use]
    pub const fn policy(&self) -> QualificationPolicy {
        self.policy
    }

    /// Verifies `bundle` under the pinned root and replaces the verified
    /// result in one step. A bundle equal to the one already held is not
    /// verified again. Returns whether the held result was replaced.
    ///
    /// Everything a verified revocation list names is remembered, and stays
    /// revoked whatever a later bundle says. Without a pinned root nothing
    /// is held.
    pub fn load(&self, bundle: &QualificationBundle) -> bool {
        let Some(root) = &self.root else {
            return false;
        };
        let digest = bundle.digest();
        let held = self.held();
        if held.is_some_and(|held| held.digest == digest) {
            return false;
        }
        let verified = bundle.verify(root);
        verified.remember(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
        *self.loaded.write().unwrap_or_else(PoisonError::into_inner) =
            Some(Arc::new(Loaded { digest, verified }));
        true
    }

    fn held(&self) -> Option<Arc<Loaded>> {
        self.loaded
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the held inputs' certificate, index, and revocation list all
    /// verified under the pinned root and the list is no older than one
    /// already accepted. The operator plane refuses to import inputs for
    /// which this is false.
    #[must_use]
    pub fn inputs_usable(&self) -> bool {
        self.held()
            .is_some_and(|held| held.verified.inputs_usable(&self.verifier_state()))
    }

    /// What every verified revocation list so far has named, for the
    /// operator plane to keep across restarts.
    #[must_use]
    pub fn verifier_state(&self) -> VerifierState {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn verdict(&self) -> QualificationVerdict {
        let unavailable = QualificationVerdict {
            state: RecipeQualificationState::Unqualified,
            refusal: Some(QualificationRefusal::Unavailable),
        };
        let (Some(deployment), Some(held)) = (&self.deployment, self.held()) else {
            return unavailable;
        };
        let state = self.verifier_state();
        // An unreadable clock is evaluated as an untrusted one at the latest
        // representable time, so a revocation is still reported first.
        let (now, trusted) = match self.clock.now() {
            Some(now) => (now, self.clock.trust() == ClockTrustState::Trusted),
            None => (u64::MAX, false),
        };
        held.verified.evaluate(deployment, now, trusted, &state)
    }

    /// The gate's current state, derived now from the held result, trusted
    /// time, and remembered revocations.
    #[must_use]
    pub fn status(&self) -> QualificationStatus {
        let verdict = self.verdict();
        QualificationStatus {
            policy: self.policy,
            state: verdict.state,
            code: verdict.refusal.map(qualification_code),
        }
    }

    /// Whether a credential may be leased now.
    ///
    /// # Errors
    ///
    /// Under the `required` policy, returns the stable code of the first
    /// condition that fails.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.policy == QualificationPolicy::Optional {
            return Ok(());
        }
        match self.status().code {
            None => Ok(()),
            Some(code) => Err(code),
        }
    }
}

/// What a gateway process knows about itself and its installed recipe, from
/// which its qualification tuple is derived.
#[derive(Clone, Debug)]
pub struct DeploymentFacts<'facts> {
    /// The recipe family the operator declared at install.
    pub recipe_family: &'facts str,
    /// The provider contract the operator pinned at install, as a digest.
    pub provider_contract_id: &'facts str,
    /// The compiled recipe's digest, rederived from the installed source.
    pub compiled_recipe_sha256: [u8; 32],
    /// SHA-256 of the installed profile lock.
    pub profile_lock_sha256: [u8; 32],
    /// SHA-256 of the running gateway executable.
    pub gateway_build_sha256: [u8; 32],
    /// The lifecycle store in use.
    pub store_kind: auths_recipe_qualification::LifecycleStoreKind,
    /// The lifecycle store's schema identifier.
    pub store_schema: &'facts str,
    /// The credential store in use.
    pub credential_store_kind: auths_connections::CredentialStoreKind,
}

const fn target_os() -> Option<auths_recipe_qualification::TargetOs> {
    if cfg!(target_os = "linux") {
        Some(auths_recipe_qualification::TargetOs::Linux)
    } else if cfg!(target_os = "macos") {
        Some(auths_recipe_qualification::TargetOs::Macos)
    } else {
        None
    }
}

const fn target_arch() -> Option<auths_recipe_qualification::TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Some(auths_recipe_qualification::TargetArch::X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(auths_recipe_qualification::TargetArch::Aarch64)
    } else {
        None
    }
}

/// Derives the tuple this deployment must be qualified for. The semantic
/// closure, package, version, operating system, and architecture are those
/// of this build; nothing here is read from a recipe or a request.
///
/// Returns `None` when a declared identifier is malformed or the build's
/// platform is outside the closed target set, which a gate treats as
/// unqualified.
#[must_use]
pub fn deployment_tuple(facts: &DeploymentFacts<'_>) -> Option<QualificationTuple> {
    use auths_recipe_qualification::{
        BoundedText, QualificationTarget, RecipeFamilyId, Sha256Digest,
    };
    Some(QualificationTuple {
        recipe_family: RecipeFamilyId::parse(facts.recipe_family).ok()?,
        compiled_recipe_sha256: Sha256Digest::from_bytes(facts.compiled_recipe_sha256),
        profile_lock_sha256: Sha256Digest::from_bytes(facts.profile_lock_sha256),
        provider_contract_id: serde_json::from_value(serde_json::Value::String(
            facts.provider_contract_id.to_owned(),
        ))
        .ok()?,
        gateway_semantic_closure_sha256: Sha256Digest::try_from(
            crate::semantic_closure::GATEWAY_SEMANTIC_CLOSURE_SHA256.to_owned(),
        )
        .ok()?,
        target: QualificationTarget {
            os: target_os()?,
            arch: target_arch()?,
            gateway_package: BoundedText::parse(env!("CARGO_PKG_NAME")).ok()?,
            gateway_version: BoundedText::parse(env!("CARGO_PKG_VERSION")).ok()?,
            gateway_build_sha256: Sha256Digest::from_bytes(facts.gateway_build_sha256),
            store_kind: facts.store_kind,
            store_schema: BoundedText::parse(facts.store_schema).ok()?,
            credential_store_kind: facts.credential_store_kind,
        },
    })
}
