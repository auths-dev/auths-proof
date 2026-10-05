//! The store: the credential-store trait over the three service calls.

use crate::{DeploymentNamespace, SecretsApi, SecretsApiError, secret_name, secret_version};
use async_trait::async_trait;
use auths_connections::{
    ConnectionCredentialStore, ConnectionId, CredentialBinding, CredentialReferenceCommitment,
    CredentialStoreError, SecretBytes, StoredSecretLease,
};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

/// The longest stored secret, which is also the service's own limit.
const MAXIMUM_SECRET_BYTES: usize = 65_536;
/// How long an install, replace, or deletion may take.
const ADMINISTRATION_DEADLINE: Duration = Duration::from_secs(10);

/// The `aws-secrets-manager-v1` credential store of one deployment.
///
/// Every process of a deployment shares it, so it keeps nothing locally. A
/// lease reads the one exact version the binding names; a version other
/// than that one, a secret outside its bound, or bytes that do not match the
/// binding's commitment never reach the caller. A failed lease is never
/// answered from another generation, a file, the environment, or a cache.
pub struct AwsSecretsManagerStore<A> {
    api: A,
    namespace: DeploymentNamespace,
}

impl<A: SecretsApi> AwsSecretsManagerStore<A> {
    /// Creates the store of the deployment `namespace`.
    #[must_use]
    pub const fn new(api: A, namespace: DeploymentNamespace) -> Self {
        Self { api, namespace }
    }

    async fn create(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: &SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        let bytes = secret.expose_to_store();
        let commitment = CredentialReferenceCommitment::of(connection_id, generation, bytes);
        let name = secret_name(&self.namespace, connection_id, generation);
        let version = secret_version(connection_id, generation, commitment.as_bytes());
        match self
            .api
            .create(
                &name,
                &version,
                bytes,
                Instant::now() + ADMINISTRATION_DEADLINE,
            )
            .await
        {
            Ok(()) => Ok(commitment),
            Err(SecretsApiError::Exists) => Err(CredentialStoreError::Conflict),
            Err(SecretsApiError::NotFound | SecretsApiError::Unavailable) => {
                Err(CredentialStoreError::Unavailable)
            }
        }
    }
}

#[async_trait]
impl<A: SecretsApi> ConnectionCredentialStore for AwsSecretsManagerStore<A> {
    async fn install(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        self.create(connection_id, generation, &secret).await
    }

    async fn lease_secret(
        &self,
        binding: &CredentialBinding,
        deadline: Instant,
    ) -> Result<StoredSecretLease, CredentialStoreError> {
        let connection_id = binding.connection_id();
        let generation = binding.credential_generation();
        let name = secret_name(&self.namespace, connection_id, generation);
        let version = secret_version(connection_id, generation, binding.reference_commitment());
        let fetched = self
            .api
            .get(&name, &version, deadline)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        if Instant::now() > deadline {
            return Err(CredentialStoreError::Expired);
        }
        if fetched.version != version
            || fetched.bytes.is_empty()
            || fetched.bytes.len() > MAXIMUM_SECRET_BYTES
        {
            return Err(CredentialStoreError::Unavailable);
        }
        let commitment =
            CredentialReferenceCommitment::of(connection_id, generation, &fetched.bytes);
        if !commitment.matches(binding.reference_commitment()) {
            return Err(CredentialStoreError::Substitution);
        }
        Ok(StoredSecretLease::from_store(fetched.bytes, deadline))
    }

    async fn replace(
        &self,
        connection_id: &ConnectionId,
        old_generation: NonZeroU64,
        new_generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        if old_generation.get().checked_add(1) != Some(new_generation.get()) {
            return Err(CredentialStoreError::Conflict);
        }
        self.create(connection_id, new_generation, &secret).await
    }

    async fn revoke(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), CredentialStoreError> {
        let name = secret_name(&self.namespace, connection_id, generation);
        self.api
            .delete(&name, Instant::now() + ADMINISTRATION_DEADLINE)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)
    }

    async fn holds(&self, binding: &CredentialBinding) -> Result<(), CredentialStoreError> {
        self.lease_secret(binding, Instant::now() + ADMINISTRATION_DEADLINE)
            .await
            .map(drop)
    }

    async fn confirm(
        &self,
        binding: &CredentialBinding,
        secret: SecretBytes,
    ) -> Result<(), CredentialStoreError> {
        let commitment = CredentialReferenceCommitment::of(
            binding.connection_id(),
            binding.credential_generation(),
            secret.expose_to_store(),
        );
        if !commitment.matches(binding.reference_commitment()) {
            return Err(CredentialStoreError::Substitution);
        }
        self.holds(binding).await
    }

    async fn retire_superseded(
        &self,
        _binding: &CredentialBinding,
    ) -> Result<(), CredentialStoreError> {
        // The store never lists, so it cannot find superseded generations.
        // The caller revokes the exact generation it superseded.
        Ok(())
    }

    async fn delete_connection(
        &self,
        connection_id: &ConnectionId,
        known: &[NonZeroU64],
    ) -> Result<(), CredentialStoreError> {
        let mut outcome = Ok(());
        for generation in known {
            let name = secret_name(&self.namespace, connection_id, *generation);
            match self
                .api
                .delete(&name, Instant::now() + ADMINISTRATION_DEADLINE)
                .await
            {
                Ok(()) | Err(SecretsApiError::NotFound) => {}
                Err(_) => outcome = Err(CredentialStoreError::Unavailable),
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FetchedSecret;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// How the double answers the next read.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        None,
        Unreachable,
        AnotherVersion,
        OtherBytes,
        Empty,
        Oversized,
        AfterDeadline,
    }

    /// An in-memory service: one version per name, and reads that can be
    /// made to answer wrongly.
    struct Double {
        secrets: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
        fault: Mutex<Fault>,
        reads: Mutex<Vec<(String, String)>>,
    }

    impl Double {
        fn new() -> Self {
            Self {
                secrets: Mutex::new(BTreeMap::new()),
                fault: Mutex::new(Fault::None),
                reads: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SecretsApi for &Double {
        async fn create(
            &self,
            name: &str,
            version: &str,
            secret: &[u8],
            _deadline: Instant,
        ) -> Result<(), SecretsApiError> {
            let mut secrets = self.secrets.lock().expect("secrets");
            if secrets.contains_key(name) {
                return Err(SecretsApiError::Exists);
            }
            secrets.insert(name.to_owned(), (version.to_owned(), secret.to_vec()));
            Ok(())
        }

        async fn get(
            &self,
            name: &str,
            version: &str,
            _deadline: Instant,
        ) -> Result<FetchedSecret, SecretsApiError> {
            self.reads
                .lock()
                .expect("reads")
                .push((name.to_owned(), version.to_owned()));
            let fault = *self.fault.lock().expect("fault");
            if fault == Fault::Unreachable {
                return Err(SecretsApiError::Unavailable);
            }
            let secrets = self.secrets.lock().expect("secrets");
            let (stored_version, bytes) = secrets.get(name).ok_or(SecretsApiError::NotFound)?;
            if stored_version != version {
                return Err(SecretsApiError::NotFound);
            }
            let (version, bytes) = match fault {
                Fault::AnotherVersion => ("0".repeat(64), bytes.clone()),
                Fault::OtherBytes => (stored_version.clone(), b"other-bytes".to_vec()),
                Fault::Empty => (stored_version.clone(), Vec::new()),
                Fault::Oversized => (stored_version.clone(), vec![b'x'; MAXIMUM_SECRET_BYTES + 1]),
                _ => (stored_version.clone(), bytes.clone()),
            };
            Ok(FetchedSecret {
                version,
                bytes: Zeroizing::new(bytes),
            })
        }

        async fn delete(&self, name: &str, _deadline: Instant) -> Result<(), SecretsApiError> {
            self.secrets
                .lock()
                .expect("secrets")
                .remove(name)
                .map(drop)
                .ok_or(SecretsApiError::NotFound)
        }
    }

    fn ready<F: std::future::Future>(future: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("the double never waits"),
        }
    }

    fn connection() -> ConnectionId {
        ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("connection")
    }

    fn generation(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("generation")
    }

    fn secret(bytes: &[u8]) -> SecretBytes {
        SecretBytes::new(bytes.to_vec()).expect("secret")
    }

    fn store(double: &Double) -> AwsSecretsManagerStore<&Double> {
        AwsSecretsManagerStore::new(
            double,
            DeploymentNamespace::parse("production-eu-1").expect("namespace"),
        )
    }

    /// The store's view of a record at `generation` whose credential was
    /// stored at `credential` with `commitment`.
    fn binding(
        generation_value: u64,
        credential: u64,
        commitment: CredentialReferenceCommitment,
    ) -> CredentialBinding {
        use auths_connections::{
            ConnectionAlias, ConnectionProfile, ConnectionRecord, ConnectionState, ProviderKind,
            SemanticId,
        };
        let profile = ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2)
            .expect("profile");
        let installed = ConnectionRecord::new(
            ProviderKind::parse("example").expect("provider"),
            ConnectionAlias::parse("default").expect("alias"),
            connection(),
            SemanticId::parse("auths.gateway-operation/1").expect("contract"),
            SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
            b"descriptor".to_vec(),
            [2; 32],
            *commitment.as_bytes(),
            generation(credential),
            ConnectionState::Active,
            vec!["gateway".to_owned()],
            vec![profile],
            10,
            10,
            None,
        )
        .expect("record");
        let mut record = installed;
        while record.generation().get() < generation_value {
            let next = if record.state() == ConnectionState::Active {
                ConnectionState::Disabled
            } else {
                ConnectionState::Active
            };
            record = record.transition_state(next, 11).expect("state change");
        }
        record.credential_binding()
    }

    fn leased(
        store: &AwsSecretsManagerStore<&Double>,
        binding: &CredentialBinding,
    ) -> Result<Vec<u8>, CredentialStoreError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let lease = ready(store.lease_secret(binding, deadline))?;
        lease.expose(Instant::now()).map(<[u8]>::to_vec)
    }

    #[test]
    fn a_lease_reads_exactly_the_derived_name_and_version() {
        let double = Double::new();
        let store = store(&double);
        let first =
            ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        let serving = binding(3, 1, first);
        assert_eq!(leased(&store, &serving).expect("lease"), b"first");
        let namespace = DeploymentNamespace::parse("production-eu-1").expect("namespace");
        assert_eq!(
            *double.reads.lock().expect("reads"),
            vec![(
                secret_name(&namespace, &connection(), generation(1)),
                secret_version(&connection(), generation(1), first.as_bytes()),
            )]
        );
        assert!(crate::is_exact_version(
            &double.reads.lock().expect("reads")[0].1
        ));
    }

    #[test]
    fn hostile_answers_never_reach_the_caller() {
        let double = Double::new();
        let store = store(&double);
        let first =
            ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        let serving = binding(1, 1, first);
        for (fault, refusal) in [
            (Fault::Unreachable, CredentialStoreError::Unavailable),
            (Fault::AnotherVersion, CredentialStoreError::Unavailable),
            (Fault::Empty, CredentialStoreError::Unavailable),
            (Fault::Oversized, CredentialStoreError::Unavailable),
            (Fault::OtherBytes, CredentialStoreError::Substitution),
        ] {
            *double.fault.lock().expect("fault") = fault;
            assert_eq!(leased(&store, &serving), Err(refusal), "{fault:?}");
        }
        *double.fault.lock().expect("fault") = Fault::None;
        assert_eq!(leased(&store, &serving).expect("lease"), b"first");
    }

    #[test]
    fn a_lease_that_returns_after_its_deadline_is_refused() {
        let double = Double::new();
        let store = store(&double);
        let first =
            ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        *double.fault.lock().expect("fault") = Fault::AfterDeadline;
        let past = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("past");
        assert_eq!(
            ready(store.lease_secret(&binding(1, 1, first), past)).map(drop),
            Err(CredentialStoreError::Expired)
        );
    }

    #[test]
    fn a_commitment_for_another_secret_finds_no_version() {
        let double = Double::new();
        let store = store(&double);
        ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        let other = CredentialReferenceCommitment::of(&connection(), generation(1), b"other");
        assert_eq!(
            leased(&store, &binding(1, 1, other)),
            Err(CredentialStoreError::Unavailable),
            "the version is bound to the commitment, so another commitment names nothing"
        );
    }

    #[test]
    fn rotation_keeps_the_old_generation_until_it_is_revoked() {
        let double = Double::new();
        let store = store(&double);
        let first =
            ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        assert_eq!(
            ready(store.install(&connection(), generation(1), secret(b"again"))).map(drop),
            Err(CredentialStoreError::Conflict)
        );
        assert_eq!(
            ready(store.replace(&connection(), generation(1), generation(3), secret(b"skip")))
                .map(drop),
            Err(CredentialStoreError::Conflict)
        );
        let second = ready(store.replace(
            &connection(),
            generation(1),
            generation(2),
            secret(b"second"),
        ))
        .expect("replace");
        let old = binding(1, 1, first);
        let new = binding(2, 2, second);
        assert_eq!(
            leased(&store, &old).expect("old"),
            b"first",
            "an admitted attempt keeps its generation"
        );
        assert_eq!(leased(&store, &new).expect("new"), b"second");
        assert_eq!(ready(store.retire_superseded(&new)), Ok(()));
        assert_eq!(
            leased(&store, &old).expect("old"),
            b"first",
            "a store that cannot list retires nothing"
        );
        assert_eq!(ready(store.revoke(&connection(), generation(1))), Ok(()));
        assert_eq!(leased(&store, &old), Err(CredentialStoreError::Unavailable));
        assert_eq!(
            leased(&store, &new).expect("new"),
            b"second",
            "a revoked generation is never answered by another"
        );
    }

    #[test]
    fn confirming_checks_and_stores_nothing() {
        let double = Double::new();
        let store = store(&double);
        let first =
            ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        let serving = binding(2, 1, first);
        assert_eq!(ready(store.holds(&serving)), Ok(()));
        assert_eq!(ready(store.confirm(&serving, secret(b"first"))), Ok(()));
        assert_eq!(
            ready(store.confirm(&serving, secret(b"other"))),
            Err(CredentialStoreError::Substitution)
        );
        assert_eq!(double.secrets.lock().expect("secrets").len(), 1);
    }

    #[test]
    fn deleting_a_connection_deletes_the_named_generations() {
        let double = Double::new();
        let store = store(&double);
        let first =
            ready(store.install(&connection(), generation(1), secret(b"first"))).expect("install");
        ready(store.replace(
            &connection(),
            generation(1),
            generation(2),
            secret(b"second"),
        ))
        .expect("replace");
        let known = [generation(1), generation(2), generation(3)];
        assert_eq!(
            ready(store.delete_connection(&connection(), &known)),
            Ok(())
        );
        assert!(double.secrets.lock().expect("secrets").is_empty());
        assert_eq!(
            leased(&store, &binding(1, 1, first)),
            Err(CredentialStoreError::Unavailable)
        );
        assert_eq!(
            ready(store.delete_connection(&connection(), &known)),
            Ok(())
        );
    }

    #[test]
    fn the_store_never_prints_a_secret() {
        let double = Double::new();
        let store = store(&double);
        let first = ready(store.install(&connection(), generation(1), secret(b"canary-value")))
            .expect("install");
        let deadline = Instant::now() + Duration::from_secs(5);
        let lease = ready(store.lease_secret(&binding(1, 1, first), deadline)).expect("lease");
        assert!(!format!("{lease:?}").contains("canary"));
        assert!(!format!("{first:?}").contains("canary"));
    }
}
