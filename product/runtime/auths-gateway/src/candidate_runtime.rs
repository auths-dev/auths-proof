//! Candidate checks use the shared acquisition owner and exact staged custody.
//! Publication is a separate operator action over complete retained evidence.

use super::*;
use crate::effect::{BoundEffect, CandidateCredentialTarget, compile_candidate_credential};
use crate::submit::AcquisitionIo;

impl GatewayEngine {
    /// Stages an operator-supplied rotation secret without leasing it or
    /// contacting the provider. The exact proposal can be persisted for native
    /// read authorization and approval. It never publishes the connection.
    /// Existing successor custody is never revoked or overwritten; a different
    /// secret at that generation fails. Cleanup notes precede the custody write.
    /// Only the trusted operator service may call this method.
    ///
    /// # Errors
    /// Refuses revoked/changed connections, missing current custody, invalid
    /// credential syntax/prefix, recipes without candidate reads, exhausted
    /// generations, conflicting staged custody or unavailable durable state.
    /// A custody failure can be ambiguous: retained cleanup notes remain and
    /// no automatic deletion or publication follows an error.
    pub async fn stage_candidate_rotation(
        &self,
        mut candidate: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<CandidateCredentialTarget, &'static str> {
        self.check_effect_configuration().await?;
        let current = self.load_for_admin().await?;
        let record = current.record();
        if record.state() == ConnectionState::Revoked {
            return Err("gateway.admin.connection-not-active");
        }
        if self
            .recipe
            .guard_checks()
            .as_ref()
            .is_some_and(|guard| !guard.admits_secret(&candidate))
        {
            return Err("gateway.admin.credential-guard");
        }
        let now = self
            .qualification
            .effect_time()
            .ok_or("gateway.admin.clock-unavailable")?;
        let proposed = record
            .rotated(
                record.descriptor().to_vec(),
                *record.account_commitment(),
                [0; 32],
                now,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        // Validate the complete relationship/check plan before touching custody.
        CandidateCredentialTarget::new(&self.recipe, &proposed, Some(record))
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        self.holds(record)
            .await
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let secret = SecretBytes::new(std::mem::take(&mut *candidate))
            .map_err(|_| "gateway.admin.invalid-credential")?;
        self.note_credential(record, proposed.credential_generation())
            .await?;
        let reference = self
            .credentials
            .replace(
                record.connection_id(),
                record.generation(),
                proposed.credential_generation(),
                secret,
            )
            .await
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let proposed = record
            .rotated(
                record.descriptor().to_vec(),
                *record.account_commitment(),
                *reference.as_bytes(),
                now,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        let target = CandidateCredentialTarget::new(&self.recipe, &proposed, Some(record))
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        self.check_candidate_predecessor(&target).await?;
        Ok(target)
    }

    /// Compiles independently authorized checks for a staged credential. The
    /// exact predecessor/absence must currently match; no custody or provider
    /// I/O occurs. The final entry transaction repeats this check under its fence.
    ///
    /// # Errors
    /// Refuses changed connection/configuration, unavailable clock or invalid
    /// native authority, candidate, recipe or effect limits.
    pub async fn compile_candidate_effect(
        &self,
        target: &CandidateCredentialTarget,
        proof: &[u8],
        action: &[u8],
    ) -> Result<BoundEffect, GatewaySubmitResult> {
        self.check_candidate_predecessor(target)
            .await
            .map_err(not_entered)?;
        self.compile_candidate_target(target, proof, action)
    }

    fn compile_candidate_target(
        &self,
        target: &CandidateCredentialTarget,
        proof: &[u8],
        action: &[u8],
    ) -> Result<BoundEffect, GatewaySubmitResult> {
        let now = self
            .qualification
            .effect_time()
            .ok_or_else(|| not_entered("gateway.verify.clock-unavailable"))?;
        compile_candidate_credential(
            &self.effect_policy.installation(
                &self.recipe,
                &self.trusted_context,
                target.record(),
                self.qualification.policy(),
                self.effect_configuration_candidate().map_err(not_entered)?,
            ),
            target,
            now,
            proof,
            action,
        )
    }

    async fn check_candidate_predecessor(
        &self,
        target: &CandidateCredentialTarget,
    ) -> Result<(), &'static str> {
        self.check_effect_configuration().await?;
        self.check_candidate_location(target)?;
        let current = self.connection.load().await.map_err(|error| match error {
            SharedConnectionError::Rollback => "gateway.connection.restore-rollback",
            _ => "gateway.connection.unavailable",
        })?;
        if !target.predecessor_matches(current.as_ref().map(LoadedConnection::private_bytes)) {
            return Err("gateway.connection.changed");
        }
        Ok(())
    }

    fn check_candidate_location(
        &self,
        target: &CandidateCredentialTarget,
    ) -> Result<(), &'static str> {
        let record = target.record();
        if record.provider_kind() != self.connection.provider()
            || record.alias() != self.connection.alias()
            || record.state() == ConnectionState::Revoked
            || !record.allowed_workloads().contains(&self.workload_id)
            || !record.allowed_profiles().contains(&self.profile)
        {
            return Err("gateway.connection.unavailable");
        }
        Ok(())
    }

    /// Publishes an exact staged credential using complete, fresh journaled
    /// checks. Only the trusted operator service may call this method; a read
    /// proof and approval do not grant connection administration authority.
    /// Native authority/configuration, retained check purposes and exact
    /// predecessor/absence are checked together under the store writer fence.
    /// No provider request or new allocation occurs. `AlreadyCurrent` reports
    /// exact state without attributing it to this invocation.
    ///
    /// # Errors
    /// Refuses missing custody, incomplete/failed/stale checks, invalid native
    /// authority or approval, and changed predecessor/configuration. A failed
    /// durability acknowledgement cannot report publication; retry observes
    /// current state and cannot recreate transport permits. Errors report
    /// unavailability, never that a connection write definitely did not occur.
    pub async fn publish_candidate_credential(
        &self,
        target: &CandidateCredentialTarget,
        proof: &[u8],
        action: &[u8],
        approval: ExactEffectApproval,
    ) -> Result<crate::CandidatePublication, &'static str> {
        let started = Instant::now();
        self.check_effect_configuration().await?;
        self.check_candidate_location(target)?;
        let current = self
            .connection
            .load()
            .await
            .map_err(|_| "gateway.connection.unavailable")?;
        if !target.predecessor_matches(current.as_ref().map(LoadedConnection::private_bytes))
            && !current
                .as_ref()
                .is_some_and(|loaded| loaded.record() == target.record())
        {
            return Err("gateway.connection.changed");
        }
        let effect = self
            .compile_candidate_target(target, proof, action)
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        let now = self
            .qualification
            .effect_time()
            .ok_or("gateway.verify.clock-unavailable")?;
        let approved = Arc::new(
            effect
                .approve(approval, self.effect_policy.approver(), now)
                .map_err(|_| "gateway.effect.approval")?,
        );
        self.holds(target.record())
            .await
            .map_err(|_| "gateway.credential.unavailable")?;
        let disposition = self
            .attempts
            .publish_candidate(approved, self.candidate_validation(target, started)?, now)
            .await
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        // Loading advances the independently retained generation floor. A
        // concurrent later update is not represented as this candidate.
        let current = self
            .connection
            .load()
            .await
            .map_err(|_| "gateway.connection.unavailable")?
            .ok_or("gateway.connection.unavailable")?;
        if current.record() != target.record() {
            return Err("gateway.connection.changed");
        }
        self.schedule_retirement(
            target.record(),
            target
                .previous()
                .map(ConnectionRecord::credential_generation),
        );
        self.delete_superseded_credentials(target.record()).await;
        Ok(disposition)
    }

    fn candidate_validation(
        &self,
        target: &CandidateCredentialTarget,
        started: Instant,
    ) -> Result<crate::entry::EntryValidation, &'static str> {
        Ok(crate::entry::EntryValidation::Installed(Box::new(
            crate::entry::InstalledEntry {
                recipe: self.recipe.clone(),
                trust: self.trusted_context.clone(),
                observer: None,
                policy: self.effect_policy.clone(),
                configuration: self.shared_configuration()?,
                connection: crate::entry::EntryConnection::Candidate(Box::new(target.clone())),
                connection_key: crate::connection_key(
                    self.connection.provider(),
                    self.connection.alias(),
                ),
                qualification: Arc::clone(&self.qualification),
                workload: self.workload_id.clone(),
                profile: self.profile.clone(),
                started,
                #[cfg(unix)]
                commissioning: None,
            },
        )))
    }

    /// Durably admits and executes native-approved candidate checks using the
    /// exact credential already staged in custody. Returns redacted journal
    /// facts only. It does not install, rotate or disclose a credential/content.
    /// A recorded final response still needs its purpose evaluated before any
    /// separately fenced publication; HTTP success alone is insufficient.
    ///
    /// # Errors
    /// Refuses changed predecessor/configuration, invalid authority/approval,
    /// unavailable staged custody, bad prerequisites or exhausted capacity.
    /// An uncertain grant retains its charges and cannot be retried implicitly.
    pub async fn acquire_candidate_credential(
        &self,
        target: &CandidateCredentialTarget,
        proof: &[u8],
        action: &[u8],
        approval: ExactEffectApproval,
    ) -> Result<crate::AcquisitionSnapshot, GatewaySubmitResult> {
        let started = Instant::now();
        let effect = self.compile_candidate_effect(target, proof, action).await?;
        let now = self
            .qualification
            .effect_time()
            .ok_or_else(|| not_entered("gateway.verify.clock-unavailable"))?;
        let approved = Arc::new(
            effect
                .approve(approval, self.effect_policy.approver(), now)
                .map_err(|_| not_entered("gateway.effect.approval"))?,
        );
        if let Some(snapshot) = self
            .attempts
            .read_acquisition(&approved)
            .await
            .map_err(|_| not_entered("gateway.attempt.state-unavailable"))?
            && snapshot.stage != crate::AcquisitionStage::Reserved
        {
            return Ok(snapshot);
        }
        let descriptor = GatewayConnectionDescriptor::from_record(target.record(), &self.recipe)
            .map_err(|_| not_entered("gateway.connection.recipe-mismatch"))?;
        let io = CandidateIo {
            engine: self,
            target,
            transport: self.prepare_transport(&descriptor).map_err(not_entered)?,
            started,
        };
        let reserved = match self
            .attempts
            .claim_candidate(
                &approved,
                now,
                io.acquisition_validation().map_err(not_entered)?,
            )
            .await
        {
            Ok(crate::AcquisitionClaim::Existing(snapshot)) => return Ok(snapshot),
            Ok(crate::AcquisitionClaim::Reserved(reserved)) => reserved,
            Err(crate::GatewayAttemptError::BindingConflict) => {
                return Err(not_entered("gateway.effect.operation-conflict"));
            }
            Err(_) => return self.recovery_projection(&approved).await,
        };
        let result = async {
            let _flight = submit::InFlight::enter(&io);
            self.check_candidate_predecessor(target).await?;
            self.qualification.check()?;
            self.execution_witness.lease();
            let lease = self
                .credentials
                .lease_secret(
                    &target.record().credential_binding(),
                    Instant::now() + Duration::from_secs(30),
                )
                .await
                .map_err(|_| "gateway.credential.unavailable")?;
            if self.recipe.guard_checks().as_ref().is_some_and(|guard| {
                !lease
                    .expose(Instant::now())
                    .is_ok_and(|secret| guard.admits_secret(secret))
            }) {
                return Err("gateway.credential.mode-guard");
            }
            submit::complete_acquisition(
                &self.attempts,
                &self.recipe,
                Arc::clone(&approved),
                *reserved,
                &io,
                &lease,
            )
            .await
        }
        .await;
        match result {
            Ok(snapshot) => Ok(snapshot),
            Err(_) => self.recovery_projection(&approved).await,
        }
    }
}

struct CandidateIo<'a> {
    engine: &'a GatewayEngine,
    target: &'a CandidateCredentialTarget,
    transport: GatewayHttpTransport,
    started: Instant,
}

impl AcquisitionIo for CandidateIo<'_> {
    type Lease = StoredSecretLease;
    fn acquisition_enter(&self) {
        self.engine.in_flight.fetch_add(1, Ordering::SeqCst);
    }
    fn acquisition_leave(&self) {
        self.engine.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
    fn acquisition_clock(&self) -> Option<u64> {
        self.engine.qualification.effect_time()
    }
    fn acquisition_validation(&self) -> Result<crate::entry::EntryValidation, &'static str> {
        self.engine.candidate_validation(self.target, self.started)
    }

    async fn acquisition_send(
        &self,
        lease: &Self::Lease,
        permit: crate::store::AcquisitionEntryPermit,
    ) -> Option<ProviderResponse> {
        self.transport.acquire(permit, lease).await
    }
}
