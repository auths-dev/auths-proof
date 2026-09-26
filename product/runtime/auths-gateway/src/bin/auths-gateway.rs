//! Customer-operated gateway. The app socket accepts proof and action only;
//! installation and administration require the operator channel. A
//! development installation keeps attempts on one host; a production
//! installation keeps them in the multi-host `PostgreSQL` store, whose
//! production qualification is still open.

#[cfg(not(unix))]
fn main() {
    eprintln!("auths-gateway currently requires Unix process isolation");
    std::process::exit(2);
}

#[cfg(unix)]
mod unix {
    use auths_connections::{
        ConnectionAlias, ConnectionCredentialStore, ConnectionId, ConnectionProfile,
        ConnectionRecord, ConnectionState, PersistentCredentialStore, ProviderKind, RegistryLimits,
        SecretBytes, SemanticId,
    };
    use auths_gateway::app::{
        APP_OBSERVE_SCHEMA, APP_REQUEST_SCHEMA, AppObservation, AppSubmission, SessionClock,
        SessionLimits, app_session, read_frame, write_frame,
    };
    use auths_gateway::listener::{ADMIN_CAPACITY, APP_CAPACITY, serve_listener};
    use auths_gateway::{ArgumentCeilingPolicy, AuditPins, audit_bundle};
    use auths_gateway::{
        CompiledRecipe, FileGatewayAttemptStore, GatewayAttempts, GatewayConnectionDescriptor,
        GatewayEngine, GatewayObserveRequest, GatewayObserveResult, GatewayObserver,
        GatewayObserverError, GatewaySubmitResult, ObserverCustody, OperatorNamespace,
        PostgresGatewayAttemptStore, PrincipalSeparationError, check_principal_separation,
        gateway_verifier_configuration,
    };
    use auths_model::PrincipalId;
    use auths_stores::{PersistentConnectionStore, PostgresLifecycleStore, PostgresStoreConfig};
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

    const MANIFEST_SCHEMA: &str = "auths.gateway-installation/2";
    const OBSERVER_SEED: &str = "observer.seed";

    /// Admin sessions: each frame within 5 seconds, the change within 45
    /// seconds, and the response within 5 seconds, all inside one 60-second
    /// session deadline. A change that has not answered by then still
    /// completes; only its connection closes.
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
        /// Operator-only initial install; credential bytes enter through stdin.
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
            #[arg(long)]
            account_label: String,
            /// Operator-selected header; must match the recipe's requirement.
            #[arg(long, default_value = "Authorization")]
            credential_header: String,
            #[arg(long, default_value_t = false)]
            credential_stdin: bool,
            /// `development` keeps attempts in a single-host file store;
            /// `production` requires the `PostgreSQL` store, a
            /// separate operator principal, and no software observer key.
            #[arg(long, value_enum, default_value_t = Deployment::Development)]
            deployment: Deployment,
            /// The operator's principal, which must be neither a root nor an
            /// observer of the installed trust. Required for production.
            #[arg(long)]
            operator_principal: Option<String>,
        },
        /// Serve a restricted application socket and private admin socket.
        Serve {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            app_socket: PathBuf,
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
        /// integer argument and a count per principal per window, as this
        /// gateway's registered evaluator enforces it.
        BoundExtension {
            #[arg(long)]
            argument: String,
            #[arg(long)]
            ceiling: u64,
            #[arg(long)]
            window_seconds: u64,
            #[arg(long)]
            max_count: u64,
        },
        /// Audit an exported bundle offline against pinned trust and observer.
        /// Opens no socket and reads no gateway state.
        Audit {
            #[arg(long)]
            bundle: PathBuf,
            /// SHA-256 of the installed trusted context, from the operator.
            #[arg(long)]
            trusted_context_sha256: String,
            /// Gateway observer principal, from the operator.
            #[arg(long)]
            observer: String,
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
        /// Ask the private operator socket to disable new writes.
        Disable {
            #[arg(long)]
            state_dir: PathBuf,
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
        /// Ask the app socket for one signed observation; never a write.
        Observe {
            #[arg(long)]
            app_socket: PathBuf,
            /// JSON object naming exactly the recipe observation path fields.
            #[arg(long, conflicts_with = "outcome", required_unless_present = "outcome")]
            read_back: Option<String>,
            /// Logical operation ID whose stored outcome to sign.
            #[arg(long)]
            outcome: Option<String>,
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
        operator_principal: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
    enum AdminRequest {
        Disable,
        Revoke,
        Rotate,
    }

    #[derive(Serialize)]
    struct AdminResponse {
        ok: bool,
        code: &'static str,
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

    fn read_install_credential() -> Result<SecretBytes, &'static str> {
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
        SecretBytes::new(std::mem::take(&mut *bytes))
            .map_err(|_| "gateway.install.invalid-credential")
    }

    /// A production installation names an operator principal that is neither
    /// a root nor an observer of the trust it installs.
    fn separated_operator(
        context: &auths_model::TrustedContext,
        deployment: Deployment,
        operator: Option<&str>,
    ) -> Result<(), &'static str> {
        match (operator, deployment) {
            (Some(operator), _) => {
                let operator = PrincipalId::parse(operator)
                    .map_err(|_| "gateway.install.invalid-operator-principal")?;
                check_principal_separation(context, &operator, None)
                    .map_err(PrincipalSeparationError::code)
            }
            (None, Deployment::Production) => Err("gateway.install.operator-principal-required"),
            (None, Deployment::Development) => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn install(
        state_dir: PathBuf,
        recipe_path: PathBuf,
        lock_path: PathBuf,
        context_path: PathBuf,
        approved: String,
        provider_text: String,
        alias_text: String,
        account_label: String,
        credential_header: String,
        credential_stdin: bool,
        deployment: Deployment,
        operator_principal: Option<String>,
    ) -> Result<(), &'static str> {
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.install.credential-must-be-piped-to-stdin");
        }
        let source = read_bounded(&recipe_path, 65_536)?;
        let lock = read_bounded(&lock_path, 65_536)?;
        let trust = read_bounded(&context_path, 4 * 1024 * 1024)?;
        let context = auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.install.invalid-trusted-context")?;
        separated_operator(&context, deployment, operator_principal.as_deref())?;
        let recipe = CompiledRecipe::compile(&source, &lock)
            .map_err(|_| "gateway.install.invalid-recipe")?;
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
        if account_label.is_empty() || account_label.len() > 256 {
            return Err("gateway.install.invalid-account-label");
        }
        let secret = read_install_credential()?;
        private_root(&state_dir)?;
        if state_dir.join("installation.json").exists() {
            return Err("gateway.install.already-installed");
        }
        let credentials = PersistentCredentialStore::open(state_dir.join("credentials.cbor"))
            .map_err(|_| "gateway.install.credential-store-unavailable")?;
        let connection_id =
            ConnectionId::generate().map_err(|_| "gateway.install.randomness-unavailable")?;
        let generation = NonZeroU64::new(1).ok_or("gateway.install.generation")?;
        let reference = credentials
            .install(&connection_id, generation, secret)
            .await
            .map_err(|_| "gateway.install.credential-store-unavailable")?;
        let profile = ConnectionProfile::new(
            SemanticId::parse("auths.mcp").map_err(|_| "gateway.install.profile")?,
            2,
        )
        .map_err(|_| "gateway.install.profile")?;
        let mut account_hash = Sha256::new();
        account_hash.update(b"auths.gateway-account/1\0");
        account_hash.update(account_label.as_bytes());
        let timestamp = now()?;
        let record = ConnectionRecord::new(
            provider,
            alias,
            connection_id,
            SemanticId::parse("auths.gateway-operation/1")
                .map_err(|_| "gateway.install.contract")?,
            SemanticId::parse("auths.gateway-connection-descriptor/1")
                .map_err(|_| "gateway.install.descriptor-schema")?,
            descriptor,
            account_hash.finalize().into(),
            *reference.as_bytes(),
            generation,
            ConnectionState::Active,
            vec!["gateway".to_owned()],
            vec![profile],
            timestamp,
            timestamp,
            None,
        )
        .map_err(|_| "gateway.install.connection-invalid")?;
        PersistentConnectionStore::open(
            state_dir.join("connections.cbor"),
            RegistryLimits::default(),
        )
        .map_err(|_| "gateway.install.connection-store-unavailable")?
        .insert(record)
        .map_err(|_| "gateway.install.connection-store-unavailable")?;
        private_file(&state_dir.join("recipe.json"), &source)?;
        private_file(&state_dir.join("profile.lock.json"), &lock)?;
        private_file(&state_dir.join("trusted.context.cbor"), &trust)?;
        let manifest = Installation {
            schema: MANIFEST_SCHEMA.to_owned(),
            recipe_digest: approved,
            profile_lock_sha256: digest(&lock),
            trusted_context_sha256: digest(&trust),
            provider: provider_text,
            alias: alias_text,
            deployment,
            operator_principal,
        };
        let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest)
            .map_err(|_| "gateway.install.manifest-invalid")?;
        private_file(&state_dir.join("installation.json"), &manifest_bytes)?;
        println!(
            "installed recipe {} with separate gateway credential custody",
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
        {
            return Err("gateway.serve.invalid-installation");
        }
        Ok(manifest)
    }

    /// Opens the attempt store the installation names. Production uses the
    /// `PostgreSQL` store from the reference deployment's secret
    /// slots; it blocks, so the caller must not be on an async executor.
    fn attempt_store(
        state_dir: &Path,
        deployment: Deployment,
    ) -> Result<GatewayAttempts, &'static str> {
        Ok(GatewayAttempts::new(match deployment {
            Deployment::Development => Arc::new(
                FileGatewayAttemptStore::open(state_dir.join("attempts"))
                    .map_err(|_| "gateway.serve.attempt-store-unavailable")?,
            ),
            Deployment::Production => {
                let configuration = PostgresStoreConfig::from_env(Vec::new(), 1_000_000)
                    .map_err(|_| "gateway.serve.postgres-configuration")?;
                Arc::new(PostgresGatewayAttemptStore::new(Arc::new(
                    PostgresLifecycleStore::connect(configuration)
                        .map_err(|_| "gateway.serve.attempt-store-unavailable")?,
                )))
            }
        }))
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
            ProviderKind::parse(manifest.provider).map_err(|_| "gateway.serve.invalid-provider")?,
            ConnectionAlias::parse(manifest.alias).map_err(|_| "gateway.serve.invalid-alias")?,
            "gateway".to_owned(),
            profile,
            PersistentConnectionStore::open(
                state_dir.join("connections.cbor"),
                RegistryLimits::default(),
            )
            .map_err(|_| "gateway.serve.connection-store-unavailable")?,
            PersistentCredentialStore::open(state_dir.join("credentials.cbor"))
                .map_err(|_| "gateway.serve.credential-store-unavailable")?,
            attempt_store(state_dir, manifest.deployment)?,
        )
        .map_err(|_| "gateway.serve.invalid-installation")?;
        let engine = match observer {
            Some(observer) => engine.with_observer(observer),
            None => engine,
        };
        if let Some(operator) = &manifest.operator_principal {
            let operator =
                PrincipalId::parse(operator).map_err(|_| "gateway.serve.invalid-installation")?;
            engine
                .check_principal_separation(&operator)
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
        Revoke,
        Rotate(SecretBytes),
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
        match serde_json::from_slice::<AdminRequest>(&bytes)
            .map_err(|_| "gateway.admin.invalid-frame")?
        {
            AdminRequest::Disable => Ok(AdminCommand::Disable),
            AdminRequest::Revoke => Ok(AdminCommand::Revoke),
            AdminRequest::Rotate => {
                let mut secret = clock
                    .read_frame(stream)
                    .await
                    .map_err(|_| "gateway.admin.invalid-credential")?;
                if secret.len() > 4_096 || !secret.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
                    secret.zeroize();
                    return Err("gateway.admin.invalid-credential");
                }
                SecretBytes::new(secret)
                    .map(AdminCommand::Rotate)
                    .map_err(|_| "gateway.admin.invalid-credential")
            }
        }
    }

    fn admin_response(result: Result<(), &'static str>, done: &'static str) -> AdminResponse {
        match result {
            Ok(()) => AdminResponse {
                ok: true,
                code: done,
            },
            Err(code) => AdminResponse { ok: false, code },
        }
    }

    /// Serves one admin connection within [`ADMIN_SESSION_LIMITS`]. A change
    /// the engine has started is never cancelled by a deadline.
    async fn admin_session(mut stream: UnixStream, engine: Arc<GatewayEngine>) {
        let clock = SessionClock::start(ADMIN_SESSION_LIMITS);
        let command = read_admin_command(&clock, &mut stream).await;
        let change = async {
            match command {
                Ok(AdminCommand::Disable) => {
                    admin_response(engine.disable_connection().await, "gateway.admin.disabled")
                }
                Ok(AdminCommand::Revoke) => {
                    admin_response(engine.revoke_connection().await, "gateway.admin.revoked")
                }
                Ok(AdminCommand::Rotate(secret)) => admin_response(
                    engine.rotate_connection(secret).await,
                    "gateway.admin.rotated",
                ),
                Err(code) => AdminResponse { ok: false, code },
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
        loopback_provider: Option<u16>,
    ) -> Result<(), &'static str> {
        let loading = state_dir.clone();
        let engine = tokio::task::spawn_blocking(move || load_engine(&loading))
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
        let app_listener = serve_listener(
            app,
            Arc::new(Semaphore::new(APP_CAPACITY)),
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
        tokio::select! {
            never = app_listener => match never {},
            never = admin_listener => match never {},
        }
    }

    fn review(recipe_path: &Path, lock_path: &Path) -> Result<(), &'static str> {
        let recipe = CompiledRecipe::compile(
            &read_bounded(recipe_path, 65_536)?,
            &read_bounded(lock_path, 65_536)?,
        )
        .map_err(|_| "gateway.review.invalid-recipe")?;
        let review = recipe.review();
        let output = serde_json::json!({
            "recipe_digest": recipe.digest_hex(),
            "operator_namespace": recipe.namespace().as_str(),
            "service": review.service(),
            "tool": review.tool(),
            "origin": review.origin(),
            "method": review.method().as_str(),
            "path": review.path(),
            "sends_idempotency_key": review.sends_idempotency_key(),
            "verifier_configuration": hex::encode(gateway_verifier_configuration()?.as_bytes()),
            "profile_policy": auths_profile_mcp::MCP_ARGUMENTS_V1,
            "bounded_policy_extension": auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| "gateway.output")?
        );
        Ok(())
    }

    fn bound_extension(
        argument: &str,
        ceiling: u64,
        window_seconds: u64,
        max_count: u64,
    ) -> Result<(), &'static str> {
        let policy = ArgumentCeilingPolicy::new(argument, ceiling, window_seconds, max_count)
            .map_err(|_| "gateway.policy.invalid-policy")?;
        let body = policy
            .extension_body(None)
            .map_err(|_| "gateway.policy.invalid-policy")?;
        let output = serde_json::json!({
            "extension_id": auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1,
            "extension_body_hex": hex::encode(body),
            "evaluator": auths_gateway::ARGUMENT_CEILING_EVALUATOR_V1,
            "argument": policy.argument(),
            "ceiling": policy.ceiling(),
            "window_seconds": policy.window_seconds(),
            "max_count": policy.max_count(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| "gateway.output")?
        );
        Ok(())
    }

    fn audit(bundle: &Path, trust_sha256: &str, observer: &str) -> Result<(), &'static str> {
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
        if report.inconsistent == 0 {
            Ok(())
        } else {
            Err("audit.inconsistent")
        }
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
    ) -> Result<(), &'static str> {
        let request = match (read_back, outcome) {
            (Some(arguments), None) => GatewayObserveRequest::ReadBack {
                arguments: serde_json::from_str(&arguments)
                    .map_err(|_| "gateway.observe.invalid-arguments")?,
            },
            (None, Some(operation_id)) => GatewayObserveRequest::Outcome { operation_id },
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
            GatewayObserveResult::Signed { .. } => Ok(()),
            GatewayObserveResult::Refused { .. } => Err("gateway.observe.refused"),
        }
    }

    async fn admin_command(
        state_dir: &Path,
        command: &'static [u8],
        secret: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        private_root(state_dir)?;
        let mut stream = UnixStream::connect(state_dir.join("admin.sock"))
            .await
            .map_err(|_| "gateway.admin.socket-unavailable")?;
        write_frame(&mut stream, command).await?;
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
            br#"{"command":"rotate"}"#,
            Some(bytes.as_slice()),
        )
        .await
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
                credential_header,
                credential_stdin,
                deployment,
                operator_principal,
            } => {
                install(
                    state_dir,
                    recipe,
                    profile_lock,
                    trusted_context,
                    approve_digest,
                    provider,
                    alias,
                    account_label,
                    credential_header,
                    credential_stdin,
                    deployment,
                    operator_principal,
                )
                .await
            }
            #[cfg(feature = "loopback-provider")]
            Command::Serve {
                state_dir,
                app_socket,
                loopback_provider,
            } => serve(state_dir, app_socket, loopback_provider).await,
            #[cfg(not(feature = "loopback-provider"))]
            Command::Serve {
                state_dir,
                app_socket,
            } => serve(state_dir, app_socket, None).await,
            Command::Review {
                recipe,
                profile_lock,
            } => review(&recipe, &profile_lock),
            Command::BoundExtension {
                argument,
                ceiling,
                window_seconds,
                max_count,
            } => bound_extension(&argument, ceiling, window_seconds, max_count),
            Command::Audit {
                bundle,
                trusted_context_sha256,
                observer,
            } => audit(&bundle, &trusted_context_sha256, &observer),
            Command::Submit {
                app_socket,
                proof,
                action,
            } => submit(app_socket, proof, action).await,
            Command::Disable { state_dir } => {
                admin_command(&state_dir, br#"{"command":"disable"}"#, None).await
            }
            Command::Revoke { state_dir } => {
                admin_command(&state_dir, br#"{"command":"revoke"}"#, None).await
            }
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
            } => observe(app_socket, read_back, outcome).await,
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
