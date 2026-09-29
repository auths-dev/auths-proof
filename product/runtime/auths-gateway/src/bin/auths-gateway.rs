//! Customer-operated gateway. The app socket accepts proof and action only;
//! installation and administration require the operator channel. A
//! development installation keeps attempts and the shared connection record
//! in a file store on one host; a production installation keeps them in the
//! multi-host `PostgreSQL` store, whose production qualification is still
//! open. Every process keeps its own credential store.

#[cfg(not(unix))]
fn main() {
    eprintln!("auths-gateway currently requires Unix process isolation");
    std::process::exit(2);
}

#[cfg(unix)]
mod unix {
    use auths_connections::{
        ConnectionAlias, ConnectionId, ConnectionProfile, ConnectionRecord, ConnectionState,
        PersistentCredentialStore, ProviderKind, SecretBytes, SemanticId,
    };
    use auths_gateway::app::{
        APP_OBSERVE_SCHEMA, APP_REQUEST_SCHEMA, AppObservation, AppSubmission, SessionClock,
        SessionLimits, app_session, read_frame, write_frame,
    };
    use auths_gateway::listener::{ADMIN_CAPACITY, serve_listener};
    use auths_gateway::{
        ArgumentCeilingPolicy, AuditPins, ListedValues, UnverifiedEntries, audit_bundle,
    };
    use auths_gateway::{
        CompiledRecipe, FileGatewayAttemptStore, GatewayAttempts, GatewayConnectionDescriptor,
        GatewayEngine, GatewayObserveRequest, GatewayObserveResult, GatewayObserver,
        GatewayObserverError, GatewaySubmitResult, ObserverCustody, OnboardingAccount,
        OnboardingFailure, OperatorNamespace, PostgresGatewayAttemptStore,
        PrincipalSeparationError, check_candidate_credential, check_principal_separation,
        gateway_verifier_configuration,
    };
    use auths_gateway::{
        GatewayAdminOutcome, GatewayAdminStatus, OperatorInstallation, OperatorStatement,
        SharedConnection, check_anchor_aliasing, install_connection, join_connection,
        verify_operator_attestation,
    };
    use auths_model::PrincipalId;
    use auths_stores::{PostgresLifecycleStore, PostgresStoreConfig};
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use clap::{Parser, Subcommand, ValueEnum};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{IsTerminal as _, Read as _, Write as _},
        num::NonZeroU64,
        os::unix::{
            fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
            process::CommandExt as _,
        },
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        net::{UnixListener, UnixStream},
        sync::Semaphore,
    };
    use zeroize::{Zeroize as _, Zeroizing};

    const MANIFEST_SCHEMA: &str = "auths.gateway-installation/3";
    const OBSERVER_SEED: &str = "observer.seed";
    const OPERATOR_ATTESTATION_FILE: &str = "operator-attestation.json";
    use auths_gateway::admin::{
        ADMIN_REQUEST_SCHEMA, ADMIN_RESPONSE_SCHEMA, AdminRequestCommand, parse_admin_request,
    };
    /// Descriptors `serve` keeps beyond its listeners' capacities and the
    /// store pool: standard streams, listeners, store and state files.
    const DESCRIPTOR_SLACK: u64 = 32;

    /// Admin sessions: each frame within 5 seconds; the change within 45
    /// seconds, which covers a rotation's 20-second onboarding reads, the
    /// commit within the store's statement timeout, and the 20-second drain;
    /// and the response within 5 seconds, all inside one 60-second session
    /// deadline. A change that has not answered by then still completes;
    /// only its connection closes.
    const ADMIN_SESSION_LIMITS: SessionLimits = SessionLimits {
        frame_read: Duration::from_secs(5),
        result_wait: Duration::from_secs(45),
        response_write: Duration::from_secs(5),
        session: Duration::from_mins(1),
    };

    #[derive(Parser)]
    #[command(
        name = "auths-gateway",
        about = "Customer-operated exact-action gateway"
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Operator-only install; credential bytes enter through stdin. The
        /// first host inserts the shared connection record; each further host
        /// joins it with `--join` and the same secret.
        Install {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            recipe: PathBuf,
            #[arg(long)]
            profile_lock: PathBuf,
            #[arg(long)]
            trusted_context: PathBuf,
            #[arg(long)]
            approve_digest: String,
            #[arg(long)]
            provider: String,
            #[arg(long)]
            alias: String,
            /// The provider account the first install binds; a join reads the
            /// record's commitment instead.
            #[arg(long, required_unless_present = "join", conflicts_with = "join")]
            account_label: Option<String>,
            /// Join the connection record another host installed on the same
            /// store, with the same recipe, trust, lock, provider, alias, and
            /// deployment.
            #[arg(long, default_value_t = false)]
            join: bool,
            /// Operator-selected header; must match the recipe's requirement.
            #[arg(long, default_value = "Authorization")]
            credential_header: String,
            #[arg(long, default_value_t = false)]
            credential_stdin: bool,
            /// `development` keeps attempts and the connection record in a
            /// single-host file store; `production` requires the
            /// `PostgreSQL` store, an authenticated operator, and no software
            /// observer key.
            #[arg(long, value_enum, default_value_t = Deployment::Development)]
            deployment: Deployment,
            /// The signed operator attestation from `operator-request`.
            /// Required for production.
            #[arg(long)]
            operator_attestation: Option<PathBuf>,
            /// Development only: the absolute directory of the file store
            /// the processes of one host share. Defaults to the state
            /// directory's own store.
            #[arg(long)]
            attempt_store: Option<PathBuf>,
            /// Development builds only: send the onboarding credential reads
            /// of a first install to a plain-HTTP provider double on
            /// 127.0.0.1:<port>.
            #[cfg(feature = "loopback-provider")]
            #[arg(long, conflicts_with = "join")]
            loopback_provider: Option<u16>,
        },
        /// Serve a restricted application socket and private admin socket.
        Serve {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            app_socket: PathBuf,
            /// Application connections served at once, 1-1024; the default
            /// is `APP_CAPACITY`.
            #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u16).range(1..=1024))]
            app_capacity: u16,
            /// Development builds only: send provider requests to a
            /// plain-HTTP provider double on 127.0.0.1:<port>.
            #[cfg(feature = "loopback-provider")]
            #[arg(long)]
            loopback_provider: Option<u16>,
        },
        /// Operator review before install: the recipe digest to approve,
        /// what the recipe sends, and the verifier configuration a gateway
        /// trusted context must pin. Prints no secret and contacts nothing.
        Review {
            #[arg(long)]
            recipe: PathBuf,
            #[arg(long)]
            profile_lock: PathBuf,
        },
        /// Print the grant extension committing to a ceiling on one verified
        /// integer argument and a count per fixed, epoch-aligned window, and
        /// optionally a sum limit per listed partition value and a scope, as
        /// this gateway's registered evaluator enforces it. The count and sum
        /// bound the grant's subject and every delegate together.
        BoundExtension(BoundOptions),
        /// Audit an exported bundle offline against pinned trust and observer.
        /// Opens no socket and reads no gateway state. Exits non-zero when an
        /// entry is inconsistent or has no gateway-signed outcome.
        Audit {
            #[arg(long)]
            bundle: PathBuf,
            /// SHA-256 of the installed trusted context, from the operator.
            #[arg(long)]
            trusted_context_sha256: String,
            /// Gateway observer principal, from the operator.
            #[arg(long)]
            observer: String,
            /// Accept entries without a gateway-signed outcome whose proof this
            /// audit refuses, such as a proof the gateway denied. An entry whose
            /// proof verifies still needs its outcome, even when the gateway
            /// refused it before recording it (for example while disabled).
            #[arg(long, default_value_t = false)]
            allow_unverified_refusals: bool,
        },
        /// Submit proof and action to the app socket, never a provider request.
        Submit {
            #[arg(long)]
            app_socket: PathBuf,
            #[arg(long)]
            proof: PathBuf,
            #[arg(long)]
            action: PathBuf,
        },
        /// Ask the private operator socket to disable new writes in every
        /// process sharing the store.
        Disable {
            #[arg(long)]
            state_dir: PathBuf,
        },
        /// Ask the private operator socket to enable a disabled connection.
        Enable {
            #[arg(long)]
            state_dir: PathBuf,
        },
        /// Ask the private operator socket for the connection state.
        Status {
            #[arg(long)]
            state_dir: PathBuf,
        },
        /// Ask the private operator socket for one read-only re-observation
        /// of a stored attempt.
        Reobserve {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            operation_id: String,
        },
        /// Print the operator statement and the preimage the operator's own
        /// signer signs for `install --operator-attestation`. Prints no
        /// secret and contacts nothing.
        OperatorRequest {
            #[arg(long)]
            recipe: PathBuf,
            #[arg(long)]
            profile_lock: PathBuf,
            #[arg(long)]
            trusted_context: PathBuf,
            #[arg(long)]
            provider: String,
            #[arg(long)]
            alias: String,
            #[arg(long, value_enum)]
            deployment: Deployment,
            #[arg(long)]
            operator_principal: String,
            #[arg(long)]
            principal_method: String,
            #[arg(long)]
            verification_method: String,
            #[arg(long)]
            signature_suite: String,
        },
        /// Offline, with every gateway process stopped: replace the operator
        /// attestation of an installation.
        OperatorAttest {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            operator_attestation: PathBuf,
            #[arg(long, required = true)]
            replace: bool,
        },
        /// Ask the private operator socket to revoke the connection.
        Revoke {
            #[arg(long)]
            state_dir: PathBuf,
        },
        /// Rotate the credential via the private operator socket and stdin.
        Rotate {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long, default_value_t = false)]
            credential_stdin: bool,
        },
        /// Operator-only: create the observer signing key in gateway state.
        ObserverInit {
            #[arg(long)]
            state_dir: PathBuf,
        },
        /// Operator-only: print the observer anchor facts and the verifier
        /// configuration a trusted context must pin. Prints no secret.
        ObserverShow {
            #[arg(long)]
            state_dir: PathBuf,
        },
        /// Ask the app socket for one signed observation, or for one
        /// operation's stored pre-entry observations; never a write.
        #[command(group(clap::ArgGroup::new("request").required(true).args(["read_back", "outcome", "pre_entry"])))]
        Observe {
            #[arg(long)]
            app_socket: PathBuf,
            /// JSON object naming exactly the recipe observation path fields.
            #[arg(long)]
            read_back: Option<String>,
            /// Logical operation ID whose stored outcome to sign.
            #[arg(long)]
            outcome: Option<String>,
            /// Logical operation ID whose stored pre-entry observations to
            /// return; nothing is signed.
            #[arg(long)]
            pre_entry: Option<String>,
        },
        /// Check offline whether a provider record holds one action's echo
        /// token. Reads no network and no gateway state; exits 0 only on a
        /// match, which shows consistency with the action, not authorship.
        #[command(group(clap::ArgGroup::new("source").required(true).args(["bundle", "action"])))]
        EchoVerify {
            /// The provider record, as JSON of at most 1 MiB.
            #[arg(long)]
            record: PathBuf,
            /// JSON pointer of the echo field in the record.
            #[arg(long)]
            pointer: String,
            /// The logical operation ID.
            #[arg(long)]
            operation_id: String,
            /// An audit bundle carrying the operation's action and recipe.
            #[arg(long, conflicts_with_all = ["namespace", "action"])]
            bundle: Option<PathBuf>,
            /// The operator namespace, with `--action`.
            #[arg(long, requires = "action")]
            namespace: Option<String>,
            /// The canonical action bytes, with `--namespace`.
            #[arg(long, requires = "namespace")]
            action: Option<PathBuf>,
        },
        /// Test isolation from the actual application UID and GID.
        Doctor {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            app_socket: PathBuf,
            #[arg(long)]
            app_uid: u32,
            #[arg(long)]
            app_gid: u32,
        },
        /// Internal privilege-dropped read/connect probe. No secret is printed.
        #[command(hide = true)]
        Probe {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            app_socket: PathBuf,
        },
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Deployment {
        Development,
        Production,
    }

    impl Deployment {
        const fn label(self) -> &'static str {
            match self {
                Self::Development => "development",
                Self::Production => "production",
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Installation {
        schema: String,
        recipe_digest: String,
        profile_lock_sha256: String,
        trusted_context_sha256: String,
        provider: String,
        alias: String,
        deployment: Deployment,
        /// SHA-256 of the operator attestation file; absent only for a
        /// development installation, which then has no operator.
        operator_attestation_sha256: Option<String>,
        /// The development file store's absolute directory; absent for
        /// production, which uses the `PostgreSQL` store.
        attempt_store: Option<String>,
    }

    impl Installation {
        fn operator_installation(&self) -> OperatorInstallation {
            OperatorInstallation {
                recipe_digest: self.recipe_digest.clone(),
                profile_lock_sha256: self.profile_lock_sha256.clone(),
                trusted_context_sha256: self.trusted_context_sha256.clone(),
                provider: self.provider.clone(),
                alias: self.alias.clone(),
                deployment: self.deployment.label().to_owned(),
            }
        }
    }

    #[derive(Serialize)]
    struct AdminResponse {
        schema: &'static str,
        ok: bool,
        code: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        drained: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        in_flight: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<GatewayAdminStatus>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<GatewaySubmitResult>,
    }

    impl AdminResponse {
        const fn refused(code: &'static str) -> Self {
            Self {
                schema: ADMIN_RESPONSE_SCHEMA,
                ok: false,
                code,
                drained: None,
                in_flight: None,
                status: None,
                result: None,
            }
        }

        fn of(result: Result<GatewayAdminOutcome, &'static str>) -> Self {
            match result {
                Ok(outcome) => Self {
                    drained: Some(outcome.drained),
                    in_flight: Some(outcome.in_flight),
                    ok: true,
                    ..Self::refused(outcome.code)
                },
                Err(code) => Self::refused(code),
            }
        }
    }

    fn private_root(path: &Path) -> Result<(), &'static str> {
        let _ = FileGatewayAttemptStore::open(path.to_path_buf())
            .map_err(|_| "gateway.state.unsafe-directory")?;
        Ok(())
    }

    fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, &'static str> {
        let file = File::open(path).map_err(|_| "gateway.input.unavailable")?;
        let mut bytes = Vec::new();
        file.take((maximum + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "gateway.input.unavailable")?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err("gateway.input.invalid-size");
        }
        Ok(bytes)
    }

    fn private_file(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "gateway.state.file-exists-or-unavailable")?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "gateway.state.write-failed")?;
        File::open(path.parent().ok_or("gateway.state.invalid-path")?)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "gateway.state.sync-failed")?;
        Ok(())
    }

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn now() -> Result<u64, &'static str> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| "gateway.clock.unavailable")
    }

    fn read_install_credential() -> Result<Zeroizing<Vec<u8>>, &'static str> {
        // Pre-sized to the read limit so reading never reallocates and strands
        // an unwiped partial copy; every exit path zeroizes the buffer.
        let mut bytes = Zeroizing::new(Vec::with_capacity(4_098));
        std::io::stdin()
            .take(4_098)
            .read_to_end(&mut bytes)
            .map_err(|_| "gateway.install.credential-unavailable")?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if bytes.is_empty()
            || bytes.len() > 4_096
            || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err("gateway.install.invalid-credential");
        }
        Ok(bytes)
    }

    /// Runs every credential check the recipe declares on the candidate
    /// secret before anything is stored: the prefix, the probe, the account
    /// read against the operator's label, and the denied reads.
    async fn checked_install_credential(
        recipe: &CompiledRecipe,
        mut candidate: Zeroizing<Vec<u8>>,
        account_label: &str,
        loopback_provider: Option<u16>,
    ) -> Result<SecretBytes, &'static str> {
        let account = OnboardingAccount::Label(account_label);
        let review = recipe.review();
        let requirement = review.credential();
        let checked = match loopback_provider {
            #[cfg(feature = "loopback-provider")]
            Some(port) => {
                auths_gateway::check_candidate_credential_loopback(
                    recipe,
                    requirement,
                    &candidate,
                    account,
                    port,
                )
                .await
            }
            _ => check_candidate_credential(recipe, requirement, &candidate, account).await,
        };
        checked.map_err(OnboardingFailure::install_code)?;
        SecretBytes::new(std::mem::take(&mut *candidate))
            .map_err(|_| "gateway.install.invalid-credential")
    }

    /// Verifies an operator attestation against the installation it must
    /// name, and requires the authenticated operator to pass separation by
    /// key from every root and observer of the trust.
    fn authenticated_operator(
        bytes: &[u8],
        expected: &OperatorInstallation,
        context: &auths_model::TrustedContext,
    ) -> Result<PrincipalId, &'static str> {
        let operator = verify_operator_attestation(bytes, expected, now()?)
            .map_err(auths_gateway::OperatorAttestationError::code)?;
        check_principal_separation(context, Some(&operator), None)
            .map_err(PrincipalSeparationError::code)?;
        Ok(operator)
    }

    /// Reads an attestation file of at most 16 KiB that only its owner can
    /// read.
    fn read_attestation(path: &Path) -> Result<Vec<u8>, &'static str> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "gateway.install.operator-attestation-invalid")?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("gateway.install.operator-attestation-invalid");
        }
        read_bounded(path, auths_gateway::MAX_OPERATOR_ATTESTATION_BYTES)
            .map_err(|_| "gateway.install.operator-attestation-invalid")
    }

    /// The development file store's directory: the one named, which must be
    /// absolute, or the state directory's own.
    fn development_store(
        state_dir: &Path,
        attempt_store: Option<PathBuf>,
    ) -> Result<PathBuf, &'static str> {
        match attempt_store {
            Some(path) if path.is_absolute() => Ok(path),
            Some(_) => Err("gateway.install.invalid-attempt-store"),
            None => Ok(state_dir.join("attempts")),
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn install(
        state_dir: PathBuf,
        recipe_path: PathBuf,
        lock_path: PathBuf,
        context_path: PathBuf,
        approved: String,
        provider_text: String,
        alias_text: String,
        account_label: Option<String>,
        join: bool,
        credential_header: String,
        credential_stdin: bool,
        deployment: Deployment,
        operator_attestation: Option<PathBuf>,
        attempt_store: Option<PathBuf>,
        loopback_provider: Option<u16>,
    ) -> Result<(), &'static str> {
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.install.credential-must-be-piped-to-stdin");
        }
        let source = read_bounded(&recipe_path, 65_536)?;
        let lock = read_bounded(&lock_path, 65_536)?;
        let trust = read_bounded(&context_path, 4 * 1024 * 1024)?;
        let context = auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.install.invalid-trusted-context")?;
        check_anchor_aliasing(&context).map_err(PrincipalSeparationError::code)?;
        let recipe = installable_recipe(&source, &lock)?;
        if approved != recipe.digest_hex() {
            return Err("gateway.install.approval-digest-mismatch");
        }
        let descriptor = GatewayConnectionDescriptor::approve(&recipe, &credential_header)
            .map_err(|_| "gateway.install.credential-header-mismatch")?
            .to_bytes()
            .map_err(|_| "gateway.install.invalid-descriptor")?;
        let provider = ProviderKind::parse(provider_text.clone())
            .map_err(|_| "gateway.install.invalid-provider")?;
        let alias = ConnectionAlias::parse(alias_text.clone())
            .map_err(|_| "gateway.install.invalid-alias")?;
        let store_path = match deployment {
            Deployment::Development => Some(development_store(&state_dir, attempt_store)?),
            Deployment::Production if attempt_store.is_some() => {
                return Err("gateway.install.invalid-attempt-store");
            }
            Deployment::Production => None,
        };
        let mut manifest = Installation {
            schema: MANIFEST_SCHEMA.to_owned(),
            recipe_digest: approved,
            profile_lock_sha256: digest(&lock),
            trusted_context_sha256: digest(&trust),
            provider: provider_text,
            alias: alias_text,
            deployment,
            operator_attestation_sha256: None,
            attempt_store: store_path.as_ref().map(|path| path.display().to_string()),
        };
        let attestation = match (operator_attestation, deployment) {
            (Some(path), _) => {
                let bytes = read_attestation(&path)?;
                authenticated_operator(&bytes, &manifest.operator_installation(), &context)?;
                manifest.operator_attestation_sha256 = Some(digest(&bytes));
                Some(bytes)
            }
            (None, Deployment::Production) => {
                return Err("gateway.install.operator-attestation-required");
            }
            (None, Deployment::Development) => None,
        };
        let candidate = read_install_credential()?;
        private_root(&state_dir)?;
        if state_dir.join("installation.json").exists() {
            return Err("gateway.install.already-installed");
        }
        let attempts = {
            let store_path = store_path.clone();
            tokio::task::spawn_blocking(move || open_attempts(deployment, store_path))
                .await
                .map_err(|_| "gateway.install.attempt-store-unavailable")?
                .map_err(|_| "gateway.install.attempt-store-unavailable")?
        };
        let credentials = PersistentCredentialStore::open(state_dir.join("credentials.cbor"))
            .map_err(|_| "gateway.install.credential-store-unavailable")?;
        let shared = SharedConnection::new(attempts.store(), provider.clone(), alias.clone());
        if join {
            join_connection(&shared, &credentials, &recipe, &candidate).await?;
        } else {
            let account_label = account_label.ok_or("gateway.install.invalid-account-label")?;
            if account_label.is_empty() || account_label.len() > 256 {
                return Err("gateway.install.invalid-account-label");
            }
            let secret =
                checked_install_credential(&recipe, candidate, &account_label, loopback_provider)
                    .await?;
            let connection_id =
                ConnectionId::generate().map_err(|_| "gateway.install.randomness-unavailable")?;
            let profile = ConnectionProfile::new(
                SemanticId::parse("auths.mcp").map_err(|_| "gateway.install.profile")?,
                2,
            )
            .map_err(|_| "gateway.install.profile")?;
            let mut account_hash = Sha256::new();
            account_hash.update(b"auths.gateway-account/1\0");
            account_hash.update(account_label.as_bytes());
            let account_commitment: [u8; 32] = account_hash.finalize().into();
            let timestamp = now()?;
            let record_id = connection_id.clone();
            install_connection(
                &shared,
                &credentials,
                move |reference| {
                    ConnectionRecord::new(
                        provider,
                        alias,
                        record_id,
                        SemanticId::parse("auths.gateway-operation/1")
                            .map_err(|_| "gateway.install.contract")?,
                        SemanticId::parse("auths.gateway-connection-descriptor/1")
                            .map_err(|_| "gateway.install.descriptor-schema")?,
                        descriptor,
                        account_commitment,
                        reference,
                        NonZeroU64::MIN,
                        ConnectionState::Active,
                        vec!["gateway".to_owned()],
                        vec![profile],
                        timestamp,
                        timestamp,
                        None,
                    )
                    .map_err(|_| "gateway.install.connection-invalid")
                },
                &connection_id,
                secret,
            )
            .await?;
        }
        private_file(&state_dir.join("recipe.json"), &source)?;
        private_file(&state_dir.join("profile.lock.json"), &lock)?;
        private_file(&state_dir.join("trusted.context.cbor"), &trust)?;
        if let Some(bytes) = &attestation {
            private_file(&state_dir.join(OPERATOR_ATTESTATION_FILE), bytes)?;
        }
        let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest)
            .map_err(|_| "gateway.install.manifest-invalid")?;
        private_file(&state_dir.join("installation.json"), &manifest_bytes)?;
        println!(
            "{} recipe {} with separate gateway credential custody",
            if join { "joined" } else { "installed" },
            manifest.recipe_digest
        );
        Ok(())
    }

    fn installation(state_dir: &Path) -> Result<Installation, &'static str> {
        let manifest_bytes = read_bounded(&state_dir.join("installation.json"), 4_096)?;
        let manifest: Installation = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| "gateway.serve.invalid-installation")?;
        if manifest.schema != MANIFEST_SCHEMA
            || serde_json_canonicalizer::to_vec(&manifest)
                .map_err(|_| "gateway.serve.invalid-installation")?
                != manifest_bytes
            || (manifest.deployment == Deployment::Production) != manifest.attempt_store.is_none()
        {
            return Err("gateway.serve.invalid-installation");
        }
        Ok(manifest)
    }

    /// Opens the store the installation names: the development file store
    /// at its directory, or the production `PostgreSQL` store from the
    /// reference deployment's secret slots. It blocks, so the caller must
    /// not be on an async executor.
    fn open_attempts(
        deployment: Deployment,
        store_path: Option<PathBuf>,
    ) -> Result<GatewayAttempts, &'static str> {
        Ok(GatewayAttempts::new(match (deployment, store_path) {
            (Deployment::Development, Some(path)) => Arc::new(
                FileGatewayAttemptStore::open(path)
                    .map_err(|_| "gateway.serve.attempt-store-unavailable")?,
            ),
            (Deployment::Production, None) => {
                let configuration = PostgresStoreConfig::from_env(Vec::new(), 1_000_000)
                    .map_err(|_| "gateway.serve.postgres-configuration")?;
                Arc::new(PostgresGatewayAttemptStore::new(Arc::new(
                    PostgresLifecycleStore::connect(configuration)
                        .map_err(|_| "gateway.serve.attempt-store-unavailable")?,
                )))
            }
            _ => return Err("gateway.serve.invalid-installation"),
        }))
    }

    /// The store connections `serve` may hold: the `PostgreSQL` pool's
    /// maximum, or none for the file store.
    fn store_pool(deployment: Deployment) -> Result<u64, &'static str> {
        match deployment {
            Deployment::Development => Ok(0),
            Deployment::Production => PostgresStoreConfig::from_env(Vec::new(), 1_000_000)
                .map(|configuration| u64::from(configuration.summary().maximum_connections()))
                .map_err(|_| "gateway.serve.postgres-configuration"),
        }
    }

    /// Refuses to serve when the descriptor limit cannot hold both
    /// listeners' capacities, the store pool, and the fixed slack.
    fn check_descriptor_limit(app_capacity: usize, pool: u64) -> Result<(), &'static str> {
        let needed = u64::try_from(app_capacity)
            .ok()
            .and_then(|app| app.checked_add(u64::try_from(ADMIN_CAPACITY).ok()?))
            .and_then(|listeners| listeners.checked_add(pool))
            .and_then(|total| total.checked_add(DESCRIPTOR_SLACK))
            .ok_or("gateway.serve.descriptor-limit")?;
        match rustix::process::getrlimit(rustix::process::Resource::Nofile).current {
            Some(limit) if limit < needed => Err("gateway.serve.descriptor-limit"),
            _ => Ok(()),
        }
    }

    fn load_engine(state_dir: &Path) -> Result<GatewayEngine, &'static str> {
        private_root(state_dir)?;
        let manifest = installation(state_dir)?;
        let source = read_bounded(&state_dir.join("recipe.json"), 65_536)?;
        let lock = read_bounded(&state_dir.join("profile.lock.json"), 65_536)?;
        let trust = read_bounded(&state_dir.join("trusted.context.cbor"), 4 * 1024 * 1024)?;
        if digest(&lock) != manifest.profile_lock_sha256
            || digest(&trust) != manifest.trusted_context_sha256
        {
            return Err("gateway.serve.installation-changed");
        }
        let context = auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.serve.invalid-installation")?;
        check_anchor_aliasing(&context).map_err(PrincipalSeparationError::code)?;
        let operator = match (&manifest.operator_attestation_sha256, manifest.deployment) {
            (Some(pinned), _) => {
                let bytes = read_attestation(&state_dir.join(OPERATOR_ATTESTATION_FILE))?;
                if digest(&bytes) != *pinned {
                    return Err("gateway.install.operator-attestation-invalid");
                }
                Some(authenticated_operator(
                    &bytes,
                    &manifest.operator_installation(),
                    &context,
                )?)
            }
            (None, Deployment::Production) => {
                return Err("gateway.install.operator-attestation-required");
            }
            (None, Deployment::Development) => None,
        };
        let recipe =
            CompiledRecipe::compile(&source, &lock).map_err(|_| "gateway.serve.invalid-recipe")?;
        if recipe.digest_hex() != manifest.recipe_digest {
            return Err("gateway.serve.recipe-changed");
        }
        let approved = *recipe.digest();
        let profile = ConnectionProfile::new(
            SemanticId::parse("auths.mcp").map_err(|_| "gateway.serve.profile")?,
            2,
        )
        .map_err(|_| "gateway.serve.profile")?;
        let observer = load_observer(state_dir)?;
        if manifest.deployment == Deployment::Production
            && observer
                .as_ref()
                .is_some_and(|observer| observer.custody() == ObserverCustody::Software)
        {
            return Err("gateway.production.observer-software-custody");
        }
        let engine = GatewayEngine::new(
            recipe,
            approved,
            &trust,
            ProviderKind::parse(manifest.provider.clone())
                .map_err(|_| "gateway.serve.invalid-provider")?,
            ConnectionAlias::parse(manifest.alias.clone())
                .map_err(|_| "gateway.serve.invalid-alias")?,
            "gateway".to_owned(),
            profile,
            PersistentCredentialStore::open(state_dir.join("credentials.cbor"))
                .map_err(|_| "gateway.serve.credential-store-unavailable")?,
            open_attempts(
                manifest.deployment,
                manifest.attempt_store.as_ref().map(PathBuf::from),
            )?,
        )
        .map_err(|_| "gateway.serve.invalid-installation")?;
        let engine = match observer {
            Some(observer) => engine.with_observer(observer),
            None => engine,
        };
        // Separation is checked against an authenticated operator. A
        // development installation without one keeps its observer key
        // outside the trust it installed, as `observer-init` creates it after
        // install; aliased anchors were refused above either way.
        if let Some(operator) = &operator {
            engine
                .check_principal_separation(Some(operator))
                .map_err(PrincipalSeparationError::code)?;
        }
        Ok(engine)
    }

    /// Loads the observer key when the operator provisioned one. A present
    /// but unsafe or malformed key stops the gateway rather than serving
    /// without it.
    fn load_observer(state_dir: &Path) -> Result<Option<GatewayObserver>, &'static str> {
        let path = state_dir.join(OBSERVER_SEED);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("gateway.observer.key-unavailable"),
            Ok(_) => GatewayObserver::load(&path)
                .map(Some)
                .map_err(GatewayObserverError::code),
        }
    }

    fn installed_recipe(state_dir: &Path) -> Result<CompiledRecipe, &'static str> {
        let source = read_bounded(&state_dir.join("recipe.json"), 65_536)?;
        let lock = read_bounded(&state_dir.join("profile.lock.json"), 65_536)?;
        let recipe =
            CompiledRecipe::compile(&source, &lock).map_err(|_| "gateway.serve.invalid-recipe")?;
        if recipe.digest_hex() != engine_recipe_marker(state_dir)? {
            return Err("gateway.serve.recipe-changed");
        }
        Ok(recipe)
    }

    fn print_observer(
        observer: &GatewayObserver,
        recipe: &CompiledRecipe,
    ) -> Result<(), &'static str> {
        let namespace: &OperatorNamespace = recipe.namespace();
        let configuration = gateway_verifier_configuration()?;
        let output = serde_json::json!({
            "observer_anchor": observer.anchor_template(recipe.review().origin(), namespace),
            "observer_custody": observer.custody().label(),
            "verifier_configuration": hex::encode(configuration.as_bytes()),
            "profile_policy": auths_profile_mcp::MCP_ARGUMENTS_V1,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| "gateway.observer.output")?
        );
        Ok(())
    }

    fn observer_init(state_dir: &Path) -> Result<(), &'static str> {
        if installation(state_dir)?.deployment == Deployment::Production {
            return Err("gateway.production.observer-software-custody");
        }
        private_root(state_dir)?;
        let recipe = installed_recipe(state_dir)?;
        let observer = GatewayObserver::generate(&state_dir.join(OBSERVER_SEED))
            .map_err(GatewayObserverError::code)?;
        File::open(state_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "gateway.state.sync-failed")?;
        print_observer(&observer, &recipe)
    }

    fn observer_show(state_dir: &Path) -> Result<(), &'static str> {
        private_root(state_dir)?;
        let recipe = installed_recipe(state_dir)?;
        let observer = load_observer(state_dir)?.ok_or("gateway.observer.not-provisioned")?;
        print_observer(&observer, &recipe)
    }

    /// One admin command, with the secret a rotation carries.
    enum AdminCommand {
        Disable,
        Enable,
        Revoke,
        Rotate(Zeroizing<Vec<u8>>),
        Status,
        Reobserve(String),
    }

    /// Reads the command frame and, for a rotation, the secret frame, each
    /// within the admin frame deadline.
    async fn read_admin_command(
        clock: &SessionClock,
        stream: &mut UnixStream,
    ) -> Result<AdminCommand, &'static str> {
        let bytes = clock
            .read_frame(stream)
            .await
            .map_err(|_| "gateway.admin.invalid-frame")?;
        match parse_admin_request(&bytes)? {
            AdminRequestCommand::Disable {} => Ok(AdminCommand::Disable),
            AdminRequestCommand::Enable {} => Ok(AdminCommand::Enable),
            AdminRequestCommand::Revoke {} => Ok(AdminCommand::Revoke),
            AdminRequestCommand::Status {} => Ok(AdminCommand::Status),
            AdminRequestCommand::Reobserve { operation_id } => {
                Ok(AdminCommand::Reobserve(operation_id))
            }
            AdminRequestCommand::Rotate {} => {
                let mut secret = clock
                    .read_frame(stream)
                    .await
                    .map_err(|_| "gateway.admin.invalid-credential")?;
                if secret.is_empty()
                    || secret.len() > 4_096
                    || !secret.iter().all(|byte| (0x21..=0x7e).contains(byte))
                {
                    secret.zeroize();
                    return Err("gateway.admin.invalid-credential");
                }
                Ok(AdminCommand::Rotate(Zeroizing::new(secret)))
            }
        }
    }

    /// Serves one admin connection within [`ADMIN_SESSION_LIMITS`]. The peer
    /// check at accept alone authorizes every command, so custody
    /// unavailability can never block the kill switch. A change the engine
    /// has started is never cancelled by a deadline.
    async fn admin_session(mut stream: UnixStream, engine: Arc<GatewayEngine>) {
        let clock = SessionClock::start(ADMIN_SESSION_LIMITS);
        let command = read_admin_command(&clock, &mut stream).await;
        let change = async {
            match command {
                Ok(AdminCommand::Disable) => AdminResponse::of(engine.disable_connection().await),
                Ok(AdminCommand::Enable) => AdminResponse::of(engine.enable_connection().await),
                Ok(AdminCommand::Revoke) => AdminResponse::of(engine.revoke_connection().await),
                Ok(AdminCommand::Rotate(secret)) => {
                    AdminResponse::of(engine.rotate_connection(secret).await)
                }
                Ok(AdminCommand::Status) => match engine.status().await {
                    Ok(status) => AdminResponse {
                        ok: true,
                        status: Some(status),
                        ..AdminResponse::refused("gateway.admin.status")
                    },
                    Err(code) => AdminResponse::refused(code),
                },
                Ok(AdminCommand::Reobserve(operation_id)) => {
                    match engine.reobserve(&operation_id).await {
                        Ok(result) => AdminResponse {
                            ok: true,
                            result: Some(result),
                            ..AdminResponse::refused("gateway.admin.reobserved")
                        },
                        Err(code) => AdminResponse::refused(code),
                    }
                }
                Err(code) => AdminResponse::refused(code),
            }
        };
        if let Some((mut stream, response)) = clock.complete(stream, change).await
            && let Ok(bytes) = serde_json::to_vec(&response)
        {
            let _ = clock.write_frame(&mut stream, &bytes).await;
        }
    }

    /// Admits an admin connection only from the gateway's own effective UID
    /// or root, before it takes an admin permit.
    fn admin_peer_admitted(stream: &UnixStream, owner: u32) -> bool {
        let admitted = stream
            .peer_cred()
            .is_ok_and(|peer| peer.uid() == owner || peer.uid() == 0);
        if !admitted {
            eprintln!("gateway.admin.peer-refused");
        }
        admitted
    }

    fn secure_socket_parent(path: &Path, owner_uid: u32) -> bool {
        let Some(parent) = path.parent() else {
            return false;
        };
        let Ok(metadata) = fs::symlink_metadata(parent) else {
            return false;
        };
        metadata.file_type().is_dir()
            && metadata.uid() == owner_uid
            && metadata.permissions().mode() & 0o022 == 0
            && fs::canonicalize(parent).is_ok_and(|canonical| canonical == parent)
    }

    fn bind_recovering_socket(
        path: &Path,
        code: &'static str,
    ) -> Result<UnixListener, &'static str> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                // Only replace a dead socket owned by this gateway inside its own
                // non-writable directory. A live listener or foreign inode fails closed.
                if !secure_socket_parent(path, rustix::process::geteuid().as_raw())
                    || !metadata.file_type().is_socket()
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                    || !matches!(
                        std::os::unix::net::UnixStream::connect(path),
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused
                    )
                {
                    return Err(code);
                }
                fs::remove_file(path).map_err(|_| code)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(code),
        }
        UnixListener::bind(path).map_err(|_| code)
    }

    async fn serve(
        state_dir: PathBuf,
        app_socket: PathBuf,
        app_capacity: usize,
        loopback_provider: Option<u16>,
    ) -> Result<(), &'static str> {
        let loading = state_dir.clone();
        let engine = tokio::task::spawn_blocking(move || {
            let deployment = installation(&loading)?.deployment;
            check_descriptor_limit(app_capacity, store_pool(deployment)?)?;
            load_engine(&loading)
        })
        .await
        .map_err(|_| "gateway.serve.load-failed")??;
        #[cfg(feature = "loopback-provider")]
        let engine = match loopback_provider {
            Some(port) => {
                eprintln!(
                    "development build: provider requests go to http://127.0.0.1:{port}, not the approved origin"
                );
                engine.with_loopback_provider(port)
            }
            None => engine,
        };
        #[cfg(not(feature = "loopback-provider"))]
        let _ = loopback_provider;
        let engine = Arc::new(engine);
        if !app_socket.is_absolute() {
            return Err("gateway.serve.invalid-app-socket");
        }
        let admin_socket = state_dir.join("admin.sock");
        let app = bind_recovering_socket(&app_socket, "gateway.serve.app-bind-failed")?;
        fs::set_permissions(&app_socket, fs::Permissions::from_mode(0o660))
            .map_err(|_| "gateway.serve.app-permissions-failed")?;
        let admin = bind_recovering_socket(&admin_socket, "gateway.serve.admin-bind-failed")?;
        fs::set_permissions(&admin_socket, fs::Permissions::from_mode(0o600))
            .map_err(|_| "gateway.serve.admin-permissions-failed")?;
        println!(
            "app socket ready; exact recipe {}, no provider-effect qualification",
            engine_recipe_marker(&state_dir)?
        );
        // Separate capacities: the application can fill its own listener but
        // never take an admin permit.
        let app_engine = Arc::clone(&engine);
        let sweep_engine = Arc::clone(&engine);
        let app_listener = serve_listener(
            app,
            Arc::new(Semaphore::new(app_capacity)),
            "app",
            |_: &UnixStream| true,
            move |stream, permit| {
                let engine = Arc::clone(&app_engine);
                async move {
                    let _permit = permit;
                    app_session(stream, engine.as_ref()).await;
                }
            },
        );
        let owner = rustix::process::geteuid().as_raw();
        let admin_listener = serve_listener(
            admin,
            Arc::new(Semaphore::new(ADMIN_CAPACITY)),
            "admin",
            move |stream: &UnixStream| admin_peer_admitted(stream, owner),
            move |stream, permit| {
                let engine = Arc::clone(&engine);
                async move {
                    let _permit = permit;
                    admin_session(stream, engine).await;
                }
            },
        );
        let sweeper = async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                auths_gateway::SLOT_SWEEP_INTERVAL_SECONDS,
            ));
            loop {
                tick.tick().await;
                if let Err(code) = sweep_engine.sweep_expired_slots().await {
                    eprintln!("{code}");
                }
            }
        };
        tokio::select! {
            never = app_listener => match never {},
            never = admin_listener => match never {},
            never = sweeper => match never {},
        }
    }

    /// Compiles a recipe this gateway can run.
    fn installable_recipe(source: &[u8], lock: &[u8]) -> Result<CompiledRecipe, &'static str> {
        CompiledRecipe::compile(source, lock).map_err(|_| "gateway.install.invalid-recipe")
    }

    fn review(recipe_path: &Path, lock_path: &Path) -> Result<(), &'static str> {
        let recipe = CompiledRecipe::compile(
            &read_bounded(recipe_path, 65_536)?,
            &read_bounded(lock_path, 65_536)?,
        )
        .map_err(|_| "gateway.review.invalid-recipe")?;
        let mut output = recipe.review_document();
        output["recipe_digest"] = serde_json::json!(recipe.digest_hex());
        output["verifier_configuration"] =
            serde_json::json!(hex::encode(gateway_verifier_configuration()?.as_bytes()));
        output["profile_policy"] = serde_json::json!(auths_profile_mcp::MCP_ARGUMENTS_V1);
        output["bounded_policy_extension"] =
            serde_json::json!(auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1);
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| "gateway.output")?
        );
        Ok(())
    }

    /// Parses `<argument>=<value>,<value>...`.
    fn listed_values(text: &str) -> Result<ListedValues, &'static str> {
        let invalid = "gateway.policy.invalid-policy";
        let (argument, values) = text.split_once('=').ok_or(invalid)?;
        let values: Vec<&str> = values.split(',').collect();
        ListedValues::new(argument, &values).map_err(|_| invalid)
    }

    #[derive(clap::Args)]
    struct BoundOptions {
        #[arg(long)]
        argument: String,
        #[arg(long)]
        ceiling: u64,
        #[arg(long)]
        window_seconds: u64,
        #[arg(long)]
        max_count: u64,
        /// The largest window sum of the argument.
        #[arg(long)]
        sum_limit: Option<u64>,
        /// `<argument>=<value>,<value>...`: the sum counts each listed value
        /// of this verified text argument separately.
        #[arg(long, requires = "sum_limit")]
        partition: Option<String>,
        /// `<argument>=<value>,<value>...`: the values this verified text
        /// argument may take.
        #[arg(long)]
        scope: Option<String>,
    }

    fn bound_extension(options: &BoundOptions) -> Result<(), &'static str> {
        let invalid = "gateway.policy.invalid-policy";
        let mut policy = ArgumentCeilingPolicy::new(
            &options.argument,
            options.ceiling,
            options.window_seconds,
            options.max_count,
        )
        .map_err(|_| invalid)?;
        let partition = options
            .partition
            .as_deref()
            .map(listed_values)
            .transpose()?;
        match options.sum_limit {
            Some(limit) => policy = policy.with_sum(limit, partition).map_err(|_| invalid)?,
            None if partition.is_some() => return Err(invalid),
            None => {}
        }
        if let Some(scope) = options.scope.as_deref() {
            policy = policy
                .with_scope(listed_values(scope)?)
                .map_err(|_| invalid)?;
        }
        let body = policy.extension_body(None).map_err(|_| invalid)?;
        let list = |values: Option<&ListedValues>| {
            values.map(|values| {
                serde_json::json!({"argument": values.argument(), "values": values.values()})
            })
        };
        let output = serde_json::json!({
            "extension_id": auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1,
            "extension_body_hex": hex::encode(body),
            "evaluator": auths_gateway::ARGUMENT_CEILING_EVALUATOR,
            "policy_type": auths_gateway::ARGUMENT_CEILING_POLICY_TYPE,
            "argument": policy.argument(),
            "ceiling": policy.ceiling(),
            "window_seconds": policy.window_seconds(),
            "window": "fixed, epoch-aligned",
            "max_count": policy.max_count(),
            "sum_limit": policy.sum_limit(),
            "partition": list(policy.partition()),
            "scope": list(policy.scope()),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| "gateway.output")?
        );
        Ok(())
    }

    fn audit(
        bundle: &Path,
        trust_sha256: &str,
        observer: &str,
        unverified: UnverifiedEntries,
    ) -> Result<(), &'static str> {
        let pinned: [u8; 32] = hex::decode(trust_sha256)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or("audit.invalid-trust-pin")?;
        let observer =
            auths_model::PrincipalId::parse(observer).map_err(|_| "audit.invalid-observer-pin")?;
        let bytes = read_bounded(bundle, auths_gateway::MAX_AUDIT_BUNDLE_BYTES)?;
        let report = audit_bundle(
            &bytes,
            &AuditPins {
                trusted_context_sha256: pinned,
                observer,
            },
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| "audit.output")?
        );
        report.verdict(unverified)
    }

    fn engine_recipe_marker(state_dir: &Path) -> Result<String, &'static str> {
        let bytes = read_bounded(&state_dir.join("installation.json"), 4_096)?;
        let manifest: Installation =
            serde_json::from_slice(&bytes).map_err(|_| "gateway.serve.invalid-installation")?;
        Ok(manifest.recipe_digest)
    }

    async fn submit(socket: PathBuf, proof: PathBuf, action: PathBuf) -> Result<(), &'static str> {
        let proof = read_bounded(&proof, 4 * 1024 * 1024)?;
        let action = read_bounded(&action, 64 * 1024)?;
        let request = AppSubmission {
            schema: APP_REQUEST_SCHEMA.to_owned(),
            proof_b64: Base64UrlUnpadded::encode_string(&proof),
            action_b64: Base64UrlUnpadded::encode_string(&action),
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| "gateway.submit.encoding-failed")?;
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| "gateway.submit.socket-unavailable")?;
        write_frame(&mut stream, &bytes).await?;
        let response = read_frame(&mut stream).await?;
        let result: GatewaySubmitResult =
            serde_json::from_slice(&response).map_err(|_| "gateway.submit.invalid-response")?;
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|_| "gateway.submit.invalid-response")?
        );
        Ok(())
    }

    async fn observe(
        socket: PathBuf,
        read_back: Option<String>,
        outcome: Option<String>,
        pre_entry: Option<String>,
    ) -> Result<(), &'static str> {
        let request = match (read_back, outcome, pre_entry) {
            (Some(arguments), None, None) => GatewayObserveRequest::ReadBack {
                arguments: serde_json::from_str(&arguments)
                    .map_err(|_| "gateway.observe.invalid-arguments")?,
            },
            (None, Some(operation_id), None) => GatewayObserveRequest::Outcome { operation_id },
            (None, None, Some(operation_id)) => GatewayObserveRequest::PreEntry { operation_id },
            _ => return Err("gateway.observe.invalid-request"),
        };
        let bytes = serde_json::to_vec(&AppObservation {
            schema: APP_OBSERVE_SCHEMA.to_owned(),
            request,
        })
        .map_err(|_| "gateway.observe.encoding-failed")?;
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| "gateway.observe.socket-unavailable")?;
        write_frame(&mut stream, &bytes).await?;
        let response = read_frame(&mut stream).await?;
        let result: GatewayObserveResult =
            serde_json::from_slice(&response).map_err(|_| "gateway.observe.invalid-response")?;
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|_| "gateway.observe.invalid-response")?
        );
        match result {
            GatewayObserveResult::Signed { .. } | GatewayObserveResult::PreEntry { .. } => Ok(()),
            GatewayObserveResult::Refused { .. } => Err("gateway.observe.refused"),
        }
    }

    fn echo_verify(
        record: &Path,
        pointer: &str,
        operation_id: &str,
        source: EchoSource,
    ) -> Result<(), &'static str> {
        let record = read_bounded(record, auths_gateway::MAX_ECHO_RECORD_BYTES)
            .map_err(|_| "gateway.echo-verify.record-invalid")?;
        let verified = match source {
            EchoSource::Bundle(bundle) => {
                let bundle = read_bounded(&bundle, auths_gateway::MAX_AUDIT_BUNDLE_BYTES)
                    .map_err(|_| "gateway.echo-verify.action-invalid")?;
                auths_gateway::echo_verify_bundle(&record, pointer, &bundle, operation_id)
            }
            EchoSource::Action { namespace, action } => {
                let action = read_bounded(&action, 64 * 1024)
                    .map_err(|_| "gateway.echo-verify.action-invalid")?;
                auths_gateway::echo_verify(&record, pointer, &namespace, operation_id, &action)
            }
        }
        .map_err(auths_gateway::EchoVerifyError::code)?;
        // The result holds only strings and closed enums, so it always
        // serializes; the exit status carries the result either way.
        if let Ok(text) = serde_json::to_string_pretty(&verified) {
            println!("{text}");
        }
        if verified.result == auths_gateway::EchoResult::Match {
            Ok(())
        } else {
            Err(verified.code)
        }
    }

    /// Where `echo-verify` finds the action and namespace.
    enum EchoSource {
        Bundle(PathBuf),
        Action { namespace: String, action: PathBuf },
    }

    async fn admin_command(
        state_dir: &Path,
        command: serde_json::Value,
        secret: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        private_root(state_dir)?;
        let mut request = serde_json::json!({"schema": ADMIN_REQUEST_SCHEMA});
        if let (Some(request), serde_json::Value::Object(fields)) =
            (request.as_object_mut(), command)
        {
            request.extend(fields);
        }
        let frame = serde_json::to_vec(&request).map_err(|_| "gateway.admin.invalid-frame")?;
        let mut stream = UnixStream::connect(state_dir.join("admin.sock"))
            .await
            .map_err(|_| "gateway.admin.socket-unavailable")?;
        write_frame(&mut stream, &frame).await?;
        if let Some(secret) = secret {
            write_frame(&mut stream, secret).await?;
        }
        let bytes = read_frame(&mut stream).await?;
        let response: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "gateway.admin.invalid-response")?;
        println!("{response}");
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err("gateway.admin.refused")
        }
    }

    async fn rotate(state_dir: &Path, credential_stdin: bool) -> Result<(), &'static str> {
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.admin.credential-must-be-piped-to-stdin");
        }
        // Pre-sized to the read limit so reading never reallocates and strands
        // an unwiped partial copy; every exit path zeroizes the buffer.
        let mut bytes = Zeroizing::new(Vec::with_capacity(4_098));
        std::io::stdin()
            .take(4_098)
            .read_to_end(&mut bytes)
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if bytes.is_empty()
            || bytes.len() > 4_096
            || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err("gateway.admin.invalid-credential");
        }
        admin_command(
            state_dir,
            serde_json::json!({"command": "rotate"}),
            Some(bytes.as_slice()),
        )
        .await
    }

    /// Prints the operator statement for an installation and the exact
    /// preimage the operator's own signer signs. The signed result, with the
    /// signer's control evidence, is the `--operator-attestation` file.
    #[allow(clippy::too_many_arguments)]
    fn operator_request(
        recipe_path: &Path,
        lock_path: &Path,
        context_path: &Path,
        provider: String,
        alias: String,
        deployment: Deployment,
        operator_principal: String,
        principal_method: String,
        verification_method: String,
        signature_suite: String,
    ) -> Result<(), &'static str> {
        let source = read_bounded(recipe_path, 65_536)?;
        let lock = read_bounded(lock_path, 65_536)?;
        let trust = read_bounded(context_path, 4 * 1024 * 1024)?;
        let recipe = CompiledRecipe::compile(&source, &lock)
            .map_err(|_| "gateway.operator.invalid-recipe")?;
        let statement = OperatorStatement {
            schema: auths_gateway::OPERATOR_ATTESTATION_SCHEMA.to_owned(),
            operator_principal,
            principal_method,
            verification_method,
            signature_suite,
            installation: OperatorInstallation {
                recipe_digest: recipe.digest_hex(),
                profile_lock_sha256: digest(&lock),
                trusted_context_sha256: digest(&trust),
                provider,
                alias,
                deployment: deployment.label().to_owned(),
            },
            issued_at: now()?,
        };
        let preimage = statement
            .preimage()
            .map_err(auths_gateway::OperatorAttestationError::code)?;
        let output = serde_json::json!({
            "statement": statement,
            "preimage_b64": Base64UrlUnpadded::encode_string(&preimage),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| "gateway.output")?
        );
        Ok(())
    }

    /// Atomically replaces an owner-only state file.
    fn replace_private_file(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
        let parent = path.parent().ok_or("gateway.state.invalid-path")?;
        let mut pending =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| "gateway.state.write-failed")?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "gateway.state.write-failed")?;
        pending
            .write_all(bytes)
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| "gateway.state.write-failed")?;
        pending
            .persist(path)
            .map_err(|_| "gateway.state.write-failed")?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "gateway.state.sync-failed")
    }

    /// Replaces the operator attestation of a stopped installation. The new
    /// operator must authenticate and pass separation by key.
    fn operator_attest(state_dir: &Path, attestation: &Path) -> Result<(), &'static str> {
        private_root(state_dir)?;
        if std::os::unix::net::UnixStream::connect(state_dir.join("admin.sock")).is_ok() {
            return Err("gateway.operator.gateway-running");
        }
        let mut manifest = installation(state_dir)?;
        let trust = read_bounded(&state_dir.join("trusted.context.cbor"), 4 * 1024 * 1024)?;
        if digest(&trust) != manifest.trusted_context_sha256 {
            return Err("gateway.serve.installation-changed");
        }
        let context = auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.serve.invalid-installation")?;
        let bytes = read_attestation(attestation)?;
        authenticated_operator(&bytes, &manifest.operator_installation(), &context)?;
        manifest.operator_attestation_sha256 = Some(digest(&bytes));
        let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest)
            .map_err(|_| "gateway.install.manifest-invalid")?;
        replace_private_file(&state_dir.join(OPERATOR_ATTESTATION_FILE), &bytes)?;
        replace_private_file(&state_dir.join("installation.json"), &manifest_bytes)?;
        println!("operator attestation replaced");
        Ok(())
    }

    fn doctor(
        state_dir: &Path,
        app_socket: &Path,
        application_uid: u32,
        probe_group: u32,
    ) -> Result<(), &'static str> {
        let state =
            fs::symlink_metadata(state_dir).map_err(|_| "gateway.doctor.state-unavailable")?;
        let credential = fs::symlink_metadata(state_dir.join("credentials.cbor"))
            .map_err(|_| "gateway.doctor.credential-unavailable")?;
        let admin = fs::symlink_metadata(state_dir.join("admin.sock"))
            .map_err(|_| "gateway.doctor.admin-unavailable")?;
        let app = fs::symlink_metadata(app_socket).map_err(|_| "gateway.doctor.app-unavailable")?;
        let observer_private = match fs::symlink_metadata(state_dir.join(OBSERVER_SEED)) {
            Ok(seed) => {
                let exposed = seed.permissions().mode() & 0o077 != 0;
                seed.file_type().is_file() && !exposed && seed.uid() == state.uid()
            }
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
        if !state.file_type().is_dir()
            || state.permissions().mode() & 0o077 != 0
            || !credential.file_type().is_file()
            || credential.permissions().mode() & 0o077 != 0
            || !admin.file_type().is_socket()
            || !app.file_type().is_socket()
            || !secure_socket_parent(app_socket, state.uid())
            || app.uid() != state.uid()
            || state.uid() != credential.uid()
            || state.uid() == application_uid
            || !observer_private
        {
            return Err("gateway.doctor.isolation-not-established");
        }
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("gateway.doctor.privilege-drop-not-checked");
        }
        // The probe runs as the application UID, which may read its
        // /proc/<pid>/environ, and the operator's environment can hold store
        // secrets. It execs this binary by absolute path and needs none.
        let status = std::process::Command::new(
            std::env::current_exe().map_err(|_| "gateway.doctor.binary-unavailable")?,
        )
        .env_clear()
        .arg("probe")
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--app-socket")
        .arg(app_socket)
        .gid(probe_group)
        .uid(application_uid)
        .status()
        .map_err(|_| "gateway.doctor.probe-unavailable")?;
        if !status.success() {
            return Err("gateway.doctor.isolation-not-established");
        }
        println!(
            "gateway state and admin socket denied to app UID; app socket reachable. Independent token copies and egress policy not checked."
        );
        Ok(())
    }

    fn probe(state_dir: &Path, app_socket: &Path) -> Result<(), &'static str> {
        // Doctor starts the probe with an empty environment. On Linux nothing
        // adds to it, so any variable was inherited and could carry operator
        // secrets to the application UID. macOS system libraries set their own.
        if cfg!(target_os = "linux") && std::env::vars_os().next().is_some() {
            return Err("gateway.doctor.probe-environment-not-empty");
        }
        if File::open(state_dir.join("credentials.cbor")).is_ok()
            || File::open(state_dir.join(OBSERVER_SEED)).is_ok()
            || std::os::unix::net::UnixStream::connect(state_dir.join("admin.sock")).is_ok()
            || std::os::unix::net::UnixStream::connect(app_socket).is_err()
        {
            return Err("gateway.doctor.probe-failed");
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per command keeps the command-to-handler mapping in one place"
    )]
    pub async fn run() -> Result<(), &'static str> {
        match Cli::parse().command {
            Command::Install {
                state_dir,
                recipe,
                profile_lock,
                trusted_context,
                approve_digest,
                provider,
                alias,
                account_label,
                join,
                credential_header,
                credential_stdin,
                deployment,
                operator_attestation,
                attempt_store,
                #[cfg(feature = "loopback-provider")]
                loopback_provider,
            } => {
                #[cfg(not(feature = "loopback-provider"))]
                let loopback_provider = None;
                install(
                    state_dir,
                    recipe,
                    profile_lock,
                    trusted_context,
                    approve_digest,
                    provider,
                    alias,
                    account_label,
                    join,
                    credential_header,
                    credential_stdin,
                    deployment,
                    operator_attestation,
                    attempt_store,
                    loopback_provider,
                )
                .await
            }
            #[cfg(feature = "loopback-provider")]
            Command::Serve {
                state_dir,
                app_socket,
                app_capacity,
                loopback_provider,
            } => {
                serve(
                    state_dir,
                    app_socket,
                    usize::from(app_capacity),
                    loopback_provider,
                )
                .await
            }
            #[cfg(not(feature = "loopback-provider"))]
            Command::Serve {
                state_dir,
                app_socket,
                app_capacity,
            } => serve(state_dir, app_socket, usize::from(app_capacity), None).await,
            Command::Review {
                recipe,
                profile_lock,
            } => review(&recipe, &profile_lock),
            Command::BoundExtension(options) => bound_extension(&options),
            Command::Audit {
                bundle,
                trusted_context_sha256,
                observer,
                allow_unverified_refusals,
            } => audit(
                &bundle,
                &trusted_context_sha256,
                &observer,
                if allow_unverified_refusals {
                    UnverifiedEntries::AllowRefusals
                } else {
                    UnverifiedEntries::Fail
                },
            ),
            Command::Submit {
                app_socket,
                proof,
                action,
            } => submit(app_socket, proof, action).await,
            Command::Disable { state_dir } => {
                admin_command(&state_dir, serde_json::json!({"command": "disable"}), None).await
            }
            Command::Enable { state_dir } => {
                admin_command(&state_dir, serde_json::json!({"command": "enable"}), None).await
            }
            Command::Revoke { state_dir } => {
                admin_command(&state_dir, serde_json::json!({"command": "revoke"}), None).await
            }
            Command::Status { state_dir } => {
                admin_command(&state_dir, serde_json::json!({"command": "status"}), None).await
            }
            Command::Reobserve {
                state_dir,
                operation_id,
            } => {
                admin_command(
                    &state_dir,
                    serde_json::json!({"command": "reobserve", "operation_id": operation_id}),
                    None,
                )
                .await
            }
            Command::OperatorRequest {
                recipe,
                profile_lock,
                trusted_context,
                provider,
                alias,
                deployment,
                operator_principal,
                principal_method,
                verification_method,
                signature_suite,
            } => operator_request(
                &recipe,
                &profile_lock,
                &trusted_context,
                provider,
                alias,
                deployment,
                operator_principal,
                principal_method,
                verification_method,
                signature_suite,
            ),
            Command::OperatorAttest {
                state_dir,
                operator_attestation,
                replace: _,
            } => operator_attest(&state_dir, &operator_attestation),
            Command::Rotate {
                state_dir,
                credential_stdin,
            } => rotate(&state_dir, credential_stdin).await,
            Command::ObserverInit { state_dir } => observer_init(&state_dir),
            Command::ObserverShow { state_dir } => observer_show(&state_dir),
            Command::Observe {
                app_socket,
                read_back,
                outcome,
                pre_entry,
            } => observe(app_socket, read_back, outcome, pre_entry).await,
            Command::EchoVerify {
                record,
                pointer,
                operation_id,
                bundle,
                namespace,
                action,
            } => {
                let source = match (bundle, namespace, action) {
                    (Some(bundle), None, None) => EchoSource::Bundle(bundle),
                    (None, Some(namespace), Some(action)) => {
                        EchoSource::Action { namespace, action }
                    }
                    _ => return Err("gateway.echo-verify.action-invalid"),
                };
                echo_verify(&record, &pointer, &operation_id, source)
            }
            Command::Doctor {
                state_dir,
                app_socket,
                app_uid,
                app_gid,
            } => doctor(&state_dir, &app_socket, app_uid, app_gid),
            Command::Probe {
                state_dir,
                app_socket,
            } => probe(&state_dir, &app_socket),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use auths_gateway::listener::APP_CAPACITY;

        fn serve_capacity(arguments: &[&str]) -> Result<usize, clap::Error> {
            let mut command = vec![
                "auths-gateway",
                "serve",
                "--state-dir",
                "/state",
                "--app-socket",
                "/app.sock",
            ];
            command.extend_from_slice(arguments);
            match Cli::try_parse_from(command)?.command {
                Command::Serve { app_capacity, .. } => Ok(usize::from(app_capacity)),
                _ => panic!("serve parses as serve"),
            }
        }

        #[test]
        fn app_capacity_defaults_to_the_listener_capacity_and_is_bounded() {
            assert_eq!(serve_capacity(&[]).expect("default"), APP_CAPACITY);
            assert_eq!(serve_capacity(&["--app-capacity", "1"]).expect("one"), 1);
            assert_eq!(
                serve_capacity(&["--app-capacity", "1024"]).expect("largest"),
                1_024
            );
            for refused in ["0", "1025", "-1"] {
                assert!(
                    serve_capacity(&["--app-capacity", refused]).is_err(),
                    "{refused}"
                );
            }
        }

        #[test]
        fn the_descriptor_check_counts_both_capacities_the_pool_and_the_slack() {
            let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile).current;
            if let Some(limit) = limit {
                let pool = limit.saturating_sub(4 + 32);
                assert_eq!(
                    check_descriptor_limit(1, pool),
                    Err("gateway.serve.descriptor-limit")
                );
                assert_eq!(check_descriptor_limit(1, pool.saturating_sub(1)), Ok(()));
            }
            assert_eq!(
                check_descriptor_limit(1, u64::MAX),
                Err("gateway.serve.descriptor-limit")
            );
        }

        #[test]
        fn admin_frames_are_closed_and_versioned() {
            let parse = |value: serde_json::Value| {
                parse_admin_request(&serde_json::to_vec(&value).expect("json"))
            };
            let disable =
                parse(serde_json::json!({"schema": ADMIN_REQUEST_SCHEMA, "command": "disable"}))
                    .expect("disable");
            assert!(matches!(disable, AdminRequestCommand::Disable {}));
            let reobserve = parse(serde_json::json!({
                "schema": ADMIN_REQUEST_SCHEMA,
                "command": "reobserve",
                "operation_id": "op-1"
            }))
            .expect("reobserve");
            assert!(matches!(
                reobserve,
                AdminRequestCommand::Reobserve { ref operation_id } if operation_id == "op-1"
            ));
            for refused in [
                serde_json::json!({"command": "disable"}),
                serde_json::json!({"schema": ADMIN_REQUEST_SCHEMA, "command": "delete"}),
                serde_json::json!({"schema": ADMIN_REQUEST_SCHEMA, "command": "disable", "secret": "x"}),
                serde_json::json!({"schema": "auths.gateway-admin-request/2", "command": "disable"}),
                serde_json::json!({"schema": ADMIN_REQUEST_SCHEMA, "command": "reobserve"}),
            ] {
                assert!(parse(refused.clone()).is_err(), "{refused}");
            }
            let response = serde_json::to_value(AdminResponse::of(Ok(GatewayAdminOutcome {
                code: "gateway.admin.disabled",
                drained: false,
                in_flight: 2,
            })))
            .expect("response");
            assert_eq!(
                response,
                serde_json::json!({
                    "schema": ADMIN_RESPONSE_SCHEMA,
                    "ok": true,
                    "code": "gateway.admin.disabled",
                    "drained": false,
                    "in_flight": 2
                })
            );
        }

        #[test]
        fn application_frame_cannot_supply_provider_request_fields() {
            let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../../../bindings/fixtures/gateway/service-hostile.json"
            ))
            .expect("service hostile cases");
            assert_eq!(cases["schema"], "auths.gateway-service-hostile/1");
            assert_eq!(cases["cases"].as_array().expect("cases").len(), 15);
            let canonical = serde_json::json!({
                "schema": APP_REQUEST_SCHEMA,
                "proof_b64": "AA",
                "action_b64": "AA"
            });
            assert!(serde_json::from_value::<AppSubmission>(canonical.clone()).is_ok());
            for (key, value) in [
                ("url", "https://attacker.example"),
                ("method", "POST"),
                ("headers", "Authorization: stolen"),
                ("body", "arbitrary"),
            ] {
                let mut mutated = canonical.clone();
                mutated[key] = serde_json::Value::String(value.to_owned());
                assert!(serde_json::from_value::<AppSubmission>(mutated).is_err());
            }
        }
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(code) = unix::run().await {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
