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
        ConnectionAlias, ConnectionCredentialStore, ConnectionId, ConnectionProfile,
        ConnectionRecord, ConnectionState, CredentialStoreKind, PersistentCredentialStore,
        ProviderKind, SecretBytes, SemanticId,
    };
    use auths_gateway::app::{
        APP_OBSERVE_SCHEMA, APP_REQUEST_SCHEMA, AppObservation, AppSubmission, SessionClock,
        SessionLimits, app_session, read_frame, write_frame,
    };
    use auths_gateway::listener::{ADMIN_CAPACITY, check_socket_path_length, serve_listener};
    use auths_gateway::{
        ArgumentCeilingPolicy, AuditPins, ListedValues, UnverifiedEntries, audit_bundle,
    };
    use auths_gateway::{
        CompiledRecipe, FileGatewayAttemptStore, GatewayAttempts, GatewayConnectionDescriptor,
        GatewayEngine, GatewayObserveRequest, GatewayObserveResult, GatewayObserver,
        GatewayObserverError, GatewaySubmitResult, ObserverCustody, OnboardingAccount,
        OnboardingFailure, OperatorNamespace, PostgresGatewayAttemptStore,
        PrincipalSeparationError, check_candidate_credential, check_principal_separation,
        check_private_directory, check_private_directory_owned_by, gateway_verifier_configuration,
    };
    use auths_gateway::{
        DeploymentFacts, DevelopmentClock, FILE_STORE_SCHEMA, POSTGRES_STORE_SCHEMA,
        QUALIFICATION_POLICY_REFUSED, QualificationBundle, QualificationGate, QualificationPolicy,
        SynchronizedHostClock, deployment_tuple, qualification_policy,
    };
    use auths_gateway::{
        GatewayAdminOutcome, GatewayAdminStatus, OperatorInstallation, OperatorStatement,
        SharedConnection, check_anchor_aliasing, install_connection, join_connection,
        verify_operator_attestation,
    };
    use auths_model::PrincipalId;
    use auths_recipe_qualification::{
        LifecycleStoreKind, MAX_ATTESTATION_BYTES, MAX_INDEX_ENTRIES, MAX_RECORD_BYTES,
        MAX_RELEASE_INDEX_BYTES, MAX_REVOCATION_LIST_BYTES, MAX_SIGNER_CERTIFICATE_BYTES,
        MAX_TRUST_ROOT_BYTES, QualificationId, QualificationSignerId, QualificationTrustRoot,
        QualificationTuple, RELEASE_ATTESTATIONS_DIRECTORY, RELEASE_INDEX_FILE,
        RELEASE_RECORDS_DIRECTORY, RELEASE_REVOCATION_LIST_FILE, RELEASE_SIGNER_CERTIFICATE_FILE,
        RecipeFamilyId, VerifierState,
    };
    use auths_stores::{PostgresLifecycleStore, PostgresStoreConfig};
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use clap::{Parser, Subcommand, ValueEnum};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};
    use std::{
        fmt,
        fs::{self, File, OpenOptions},
        io::{IsTerminal as _, Read as _, Write as _},
        num::NonZeroU64,
        os::unix::{
            fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
            process::CommandExt as _,
        },
        path::{Component, Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        net::{UnixListener, UnixStream},
        sync::Semaphore,
    };
    use zeroize::{Zeroize as _, Zeroizing};

    const MANIFEST_SCHEMA: &str = "auths.gateway-installation/5";
    /// The directory of the state directory that holds the signed
    /// qualification inputs the operator imported.
    const QUALIFICATION_DIRECTORY: &str = "qualification";
    /// What every verified revocation list has named so far.
    const QUALIFICATION_STATE_FILE: &str = "qualification-state.json";
    /// A development installation's own trust root.
    const QUALIFICATION_ROOT_FILE: &str = "qualification-trust-root.json";
    /// The qualification trust root this build pins. It is `None` until a
    /// reviewed release pins the root the offline ceremony created; until
    /// then a production gateway finds every recipe unqualified.
    const PINNED_QUALIFICATION_ROOT: Option<&[u8]> = None;
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

    /// A command's failure: its stable code, always the first token printed,
    /// and an optional detail. A detail holds only paths, lengths, modes,
    /// UIDs, and operating-system errors, never a credential.
    #[derive(Debug)]
    pub struct Failure {
        code: &'static str,
        detail: Option<String>,
    }

    impl Failure {
        /// A failure concerning `path`, printed as `code path=<path>: cause`.
        fn at(code: &'static str, path: &Path, cause: impl fmt::Display) -> Self {
            Self {
                code,
                detail: Some(format!("path={}: {cause}", path.display())),
            }
        }
    }

    impl From<&'static str> for Failure {
        fn from(code: &'static str) -> Self {
            Self { code, detail: None }
        }
    }

    impl fmt::Display for Failure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self.detail {
                Some(detail) => write!(formatter, "{} {detail}", self.code),
                None => formatter.write_str(self.code),
            }
        }
    }

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
    #[allow(
        clippy::large_enum_variant,
        reason = "one command is parsed per process"
    )]
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
            /// Where the provider secret is kept: `local-file-v1`
            /// (development only) or `aws-secrets-manager-v1`. Production
            /// refuses the local file.
            #[arg(long, default_value = "local-file-v1")]
            credential_store: String,
            /// The deployment namespace of the production credential store.
            #[arg(long)]
            credential_namespace: Option<String>,
            /// The region of the production credential store.
            #[arg(long)]
            aws_region: Option<String>,
            /// The key new secrets are encrypted under.
            #[arg(long)]
            aws_kms_key: Option<String>,
            /// The workload identity the gateway uses: `web-identity`,
            /// `container`, or `instance-metadata`.
            #[arg(long)]
            aws_identity: Option<String>,
            /// Development only: the absolute directory of the file store
            /// the processes of one host share. Defaults to the state
            /// directory's own store.
            #[arg(long)]
            attempt_store: Option<PathBuf>,
            #[command(flatten)]
            qualification: QualificationOptions,
            /// Development builds only: send the onboarding credential reads
            /// of a first install to a plain-HTTP provider double on
            /// 127.0.0.1:<port>.
            #[cfg(feature = "loopback-provider")]
            #[arg(long, conflicts_with = "join")]
            loopback_provider: Option<u16>,
        },
        /// Serve a restricted application socket and private admin socket.
        /// A Unix socket path holds at most 103 bytes on macOS and 107 on
        /// Linux; `serve` refuses a longer socket path before binding either
        /// socket.
        Serve {
            /// The installed state directory: absolute, owned by this UID,
            /// mode 0700, and reached through no symbolic link (on macOS,
            /// `/tmp` is `/private/tmp`). The default admin socket,
            /// `<state-dir>/admin.sock`, must fit the socket path limit; for a
            /// longer state directory pass `--admin-socket`.
            #[arg(long)]
            state_dir: PathBuf,
            /// The application socket's absolute path, at most 103 bytes on
            /// macOS and 107 on Linux.
            #[arg(long)]
            app_socket: PathBuf,
            /// The admin socket's absolute path, at most 103 bytes on macOS
            /// and 107 on Linux; defaults to `<state-dir>/admin.sock`. Its
            /// parent must already exist, be owned by this UID with mode 0700
            /// or narrower, and be reached through no symbolic link. Admin
            /// commands and `doctor` must be given the same path.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
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
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
        },
        /// Ask the private operator socket to enable a disabled connection.
        Enable {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
        },
        /// Operator-only: verify a signed release directory under the
        /// installation's qualification trust root and make it this host's
        /// qualification inputs. An unsigned proposal, a forged input, and a
        /// revocation list older than one already accepted are refused and
        /// change nothing. A running gateway is asked to read the new inputs.
        QualificationImport {
            #[arg(long)]
            state_dir: PathBuf,
            /// The release directory: the signer certificate, revocation
            /// list, release index, records, and attestations.
            #[arg(long)]
            from: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
        },
        /// Print this installation's qualification policy, state, and code,
        /// derived now from the imported inputs. Contacts nothing.
        QualificationStatus {
            #[arg(long)]
            state_dir: PathBuf,
            /// Print the tuple this deployment must be qualified for instead.
            #[arg(long, default_value_t = false)]
            tuple: bool,
        },
        /// Ask the private operator socket for the connection state.
        Status {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
        },
        /// Ask the private operator socket for one read-only re-observation
        /// of a stored attempt.
        Reobserve {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
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
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
            #[arg(long)]
            operator_attestation: PathBuf,
            #[arg(long, required = true)]
            replace: bool,
        },
        /// Ask the private operator socket to revoke the connection.
        Revoke {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
        },
        /// Rotate the credential via the private operator socket and stdin.
        Rotate {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
            #[arg(long, default_value_t = false)]
            credential_stdin: bool,
        },
        /// First phase of a two-phase rotation: store the new credential
        /// from stdin without publishing it, and print its commitment.
        RotatePrepare {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
            #[arg(long, default_value_t = false)]
            credential_stdin: bool,
        },
        /// Second phase: publish the prepared credential the commitment
        /// names to every process sharing the store.
        RotateCommit {
            #[arg(long)]
            state_dir: PathBuf,
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
            /// The commitment `rotate-prepare` printed.
            #[arg(long)]
            commitment: String,
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
            /// The admin socket `serve` was given with `--admin-socket`;
            /// defaults to `<state-dir>/admin.sock`.
            #[arg(long)]
            admin_socket: Option<PathBuf>,
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
            admin_socket: Option<PathBuf>,
            #[arg(long)]
            app_socket: PathBuf,
        },
    }

    /// What the operator declares about qualification at install.
    #[derive(clap::Args)]
    struct QualificationOptions {
        /// `required` or `optional`. Production requires qualification and
        /// refuses `optional`; development defaults to `optional`.
        #[arg(long)]
        qualification_policy: Option<String>,
        /// The recipe family the installed recipe belongs to, as its
        /// decision record names it.
        #[arg(long)]
        recipe_family: Option<String>,
        /// The provider contract the recipe is deployed against, as 64
        /// lowercase hexadecimal characters.
        #[arg(long)]
        provider_contract_id: Option<String>,
        /// Development only: a qualification trust root for this
        /// installation. Production uses the root its build pins.
        #[arg(long)]
        qualification_trust_root: Option<PathBuf>,
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
        /// Where provider secrets are kept. It names no secret and no
        /// external location.
        credential_store: CredentialStoreSettings,
        /// Whether the recipe must be qualified, and what it is deployed as.
        qualification: QualificationSettings,
    }

    /// The installation's qualification policy and the two tuple members a
    /// gateway cannot derive from its own build and installed files. Neither
    /// is a claim of qualification: a wrong family or contract matches no
    /// attestation and refuses.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct QualificationSettings {
        policy: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recipe_family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_contract_id: Option<String>,
        /// SHA-256 of a development installation's own trust root file.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trust_root_sha256: Option<String>,
    }

    /// Whether production qualification policy applies. It always does for
    /// a production deployment in a shipped build; only a build made for
    /// tests can relax it.
    const fn production_qualification(deployment: Deployment) -> bool {
        matches!(deployment, Deployment::Production)
            && !cfg!(feature = "testkit-production-unqualified")
    }

    /// Checks the operator's qualification declaration before anything is
    /// read or written, and returns the settings and a development trust
    /// root's bytes.
    fn qualification_settings(
        options: QualificationOptions,
        deployment: Deployment,
    ) -> Result<(QualificationSettings, Option<Vec<u8>>), Failure> {
        let policy = qualification_policy(
            options.qualification_policy.as_deref(),
            production_qualification(deployment),
        )?;
        let lowercase_digest = |text: &String| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let declared = options
            .recipe_family
            .as_ref()
            .is_none_or(|family| RecipeFamilyId::parse(family.as_str()).is_ok())
            && options
                .provider_contract_id
                .as_ref()
                .is_none_or(lowercase_digest);
        let complete = options.recipe_family.is_some() && options.provider_contract_id.is_some();
        if !declared || (policy == QualificationPolicy::Required && !complete) {
            return Err(QUALIFICATION_POLICY_REFUSED.into());
        }
        let root = match (options.qualification_trust_root, deployment) {
            (None, _) => None,
            (Some(path), Deployment::Development) => {
                let bytes = read_bounded(&path, MAX_TRUST_ROOT_BYTES)
                    .map_err(|_| Failure::at(QUALIFICATION_POLICY_REFUSED, &path, "unreadable"))?;
                QualificationTrustRoot::from_canonical_json(&bytes)
                    .map_err(|error| Failure::at(QUALIFICATION_POLICY_REFUSED, &path, error))?;
                Some(bytes)
            }
            (Some(_), Deployment::Production) => return Err(QUALIFICATION_POLICY_REFUSED.into()),
        };
        Ok((
            QualificationSettings {
                policy: policy.as_str().to_owned(),
                recipe_family: options.recipe_family,
                provider_contract_id: options.provider_contract_id,
                trust_root_sha256: root.as_deref().map(digest),
            },
            root,
        ))
    }

    /// The operator's choice of credential store and, for the production
    /// store, its deployment namespace, region, key, and workload identity.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct CredentialStoreSettings {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kms_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<String>,
    }

    /// Whether production custody policy applies. It always does for a
    /// production deployment in a shipped build; only a build made for
    /// tests can relax it.
    const fn production_custody(deployment: Deployment) -> bool {
        matches!(deployment, Deployment::Production)
            && !cfg!(feature = "testkit-production-plaintext")
    }

    /// Opens the credential store the settings select, under the
    /// deployment's policy. `unavailable` is the caller's code for a store
    /// that is selected and permitted but cannot be opened.
    fn open_credentials(
        state_dir: &Path,
        settings: &CredentialStoreSettings,
        deployment: Deployment,
        unavailable: &'static str,
    ) -> Result<Arc<dyn ConnectionCredentialStore>, &'static str> {
        use auths_credentials_aws_secrets_manager::{
            AwsSecretsManagerStore, ContainerEndpoint, DeploymentNamespace, HttpSecretsApi,
            InstanceMetadata, Region, WebIdentity, WorkloadIdentity,
        };
        let kind =
            auths_gateway::credential_store_policy(&settings.kind, production_custody(deployment))?;
        let aws_only = [
            &settings.namespace,
            &settings.region,
            &settings.kms_key,
            &settings.identity,
        ];
        match kind {
            CredentialStoreKind::LocalFileV1 => {
                if aws_only.iter().any(|setting| setting.is_some()) {
                    return Err(unavailable);
                }
                Ok(Arc::new(
                    PersistentCredentialStore::open(state_dir.join("credentials.cbor"))
                        .map_err(|_| unavailable)?,
                ))
            }
            CredentialStoreKind::AwsSecretsManagerV1 => {
                let namespace = settings
                    .namespace
                    .as_deref()
                    .and_then(|value| DeploymentNamespace::parse(value).ok())
                    .ok_or(unavailable)?;
                let region = settings
                    .region
                    .as_deref()
                    .and_then(|value| Region::parse(value).ok())
                    .ok_or(unavailable)?;
                let variable = |name: &str| std::env::var(name).map_err(|_| unavailable);
                // Each identity is selected by name. None falls back to another.
                let identity: Box<dyn WorkloadIdentity> = match settings.identity.as_deref() {
                    Some("web-identity") => Box::new(
                        WebIdentity::new(
                            &region,
                            variable("AWS_ROLE_ARN")?,
                            variable("AWS_WEB_IDENTITY_TOKEN_FILE")?,
                        )
                        .map_err(|_| unavailable)?,
                    ),
                    Some("container") => Box::new(
                        ContainerEndpoint::new(
                            variable("AWS_CONTAINER_CREDENTIALS_FULL_URI")?,
                            variable("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")?,
                        )
                        .map_err(|_| unavailable)?,
                    ),
                    Some("instance-metadata") => {
                        Box::new(InstanceMetadata::new().map_err(|_| unavailable)?)
                    }
                    _ => return Err(unavailable),
                };
                let api = HttpSecretsApi::new(region, settings.kms_key.clone(), identity)
                    .map_err(|_| unavailable)?;
                Ok(Arc::new(AwsSecretsManagerStore::new(api, namespace)))
            }
        }
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
        /// The reference commitment of a prepared successor. It names the
        /// stored secret without revealing it or where it is kept.
        #[serde(skip_serializing_if = "Option::is_none")]
        commitment: Option<String>,
        /// The qualification state a reload derived.
        #[serde(skip_serializing_if = "Option::is_none")]
        qualification: Option<QualificationReport>,
    }

    /// The gate's policy, state, and code. It names no provider and echoes
    /// no input.
    #[derive(Serialize)]
    struct QualificationReport {
        policy: &'static str,
        state: &'static str,
        code: Option<&'static str>,
    }

    impl QualificationReport {
        fn of(gate: &QualificationGate) -> Self {
            let status = gate.status();
            Self {
                policy: status.policy.as_str(),
                state: status.state.as_str(),
                code: status.code,
            }
        }
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
                commitment: None,
                qualification: None,
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

    fn private_root(path: &Path) -> Result<(), Failure> {
        match FileGatewayAttemptStore::open(path.to_path_buf()) {
            Ok(_) => Ok(()),
            Err(error) => Err(Failure::at(
                "gateway.state.unsafe-directory",
                path,
                check_private_directory(path)
                    .err()
                    .map_or_else(|| error.to_string(), |cause| cause.to_string()),
            )),
        }
    }

    /// The admin socket: the explicit `--admin-socket`, or
    /// `<state-dir>/admin.sock`.
    fn admin_socket_path(state_dir: &Path, explicit: Option<PathBuf>) -> AdminSocket {
        match explicit {
            Some(path) => AdminSocket {
                path,
                relocated: true,
            },
            None => AdminSocket {
                path: state_dir.join("admin.sock"),
                relocated: false,
            },
        }
    }

    /// A resolved admin socket path, and whether `--admin-socket` moved it.
    struct AdminSocket {
        path: PathBuf,
        relocated: bool,
    }

    /// The codes an admin socket check reports under.
    struct AdminSocketCodes {
        invalid: &'static str,
        unsafe_directory: &'static str,
        too_long: &'static str,
    }

    const SERVE_ADMIN_SOCKET: AdminSocketCodes = AdminSocketCodes {
        invalid: "gateway.serve.invalid-admin-socket",
        unsafe_directory: "gateway.serve.unsafe-admin-socket-directory",
        too_long: "gateway.serve.admin-socket-too-long",
    };

    const CLIENT_ADMIN_SOCKET: AdminSocketCodes = AdminSocketCodes {
        invalid: "gateway.admin.socket-unavailable",
        unsafe_directory: "gateway.admin.socket-unavailable",
        too_long: "gateway.admin.socket-unavailable",
    };

    /// The admin socket must be absolute and normalized, sit in an existing
    /// directory private to this UID, and fit the platform's socket path
    /// limit. The directory's privacy is what keeps another user from
    /// listening at the path the credential is rotated through, and from
    /// connecting while the socket still has its bind-time mode.
    fn check_admin_socket(admin: &AdminSocket, codes: &AdminSocketCodes) -> Result<(), Failure> {
        let path = admin.path.as_path();
        let parent = path.parent().filter(|_| {
            path.is_absolute()
                && path.file_name().is_some()
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        });
        let Some(parent) = parent else {
            return Err(Failure::at(
                codes.invalid,
                path,
                "not an absolute socket path free of `.` and `..` components",
            ));
        };
        check_private_directory(parent)
            .map_err(|cause| Failure::at(codes.unsafe_directory, parent, cause))?;
        check_socket_path_length(path).map_err(|cause| {
            let remedy = if admin.relocated {
                "pass a shorter --admin-socket"
            } else {
                "use a shorter --state-dir or pass --admin-socket"
            };
            Failure::at(codes.too_long, path, format_args!("{cause}; {remedy}"))
        })
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
        credential_store: CredentialStoreSettings,
        qualification: QualificationOptions,
        loopback_provider: Option<u16>,
    ) -> Result<(), Failure> {
        // The store choice is checked before anything is read or written.
        auths_gateway::credential_store_policy(
            &credential_store.kind,
            production_custody(deployment),
        )?;
        let (qualification, qualification_root) =
            qualification_settings(qualification, deployment)?;
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.install.credential-must-be-piped-to-stdin".into());
        }
        let source = read_bounded(&recipe_path, 65_536)?;
        let lock = read_bounded(&lock_path, 65_536)?;
        let trust = read_bounded(&context_path, 4 * 1024 * 1024)?;
        let context = auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.install.invalid-trusted-context")?;
        check_anchor_aliasing(&context).map_err(PrincipalSeparationError::code)?;
        let recipe = installable_recipe(&source, &lock)?;
        if approved != recipe.digest_hex() {
            return Err("gateway.install.approval-digest-mismatch".into());
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
                return Err("gateway.install.invalid-attempt-store".into());
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
            credential_store,
            qualification,
        };
        let attestation = match (operator_attestation, deployment) {
            (Some(path), _) => {
                let bytes = read_attestation(&path)?;
                authenticated_operator(&bytes, &manifest.operator_installation(), &context)?;
                manifest.operator_attestation_sha256 = Some(digest(&bytes));
                Some(bytes)
            }
            (None, Deployment::Production) => {
                return Err("gateway.install.operator-attestation-required".into());
            }
            (None, Deployment::Development) => None,
        };
        let candidate = read_install_credential()?;
        private_root(&state_dir)?;
        if state_dir.join("installation.json").exists() {
            return Err("gateway.install.already-installed".into());
        }
        let attempts = {
            let store_path = store_path.clone();
            tokio::task::spawn_blocking(move || open_attempts(deployment, store_path))
                .await
                .map_err(|_| "gateway.install.attempt-store-unavailable")?
                .map_err(|_| "gateway.install.attempt-store-unavailable")?
        };
        let credentials = open_credentials(
            &state_dir,
            &manifest.credential_store,
            deployment,
            "gateway.install.credential-store-unavailable",
        )?;
        let shared = SharedConnection::new(attempts.store(), provider.clone(), alias.clone());
        if join {
            join_connection(&shared, &*credentials, &recipe, &candidate).await?;
        } else {
            let account_label = account_label.ok_or("gateway.install.invalid-account-label")?;
            if account_label.is_empty() || account_label.len() > 256 {
                return Err("gateway.install.invalid-account-label".into());
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
                &*credentials,
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
        if let Some(bytes) = &qualification_root {
            private_file(&state_dir.join(QUALIFICATION_ROOT_FILE), bytes)?;
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

    /// The files of `directory` in name order, each at most `maximum` bytes
    /// and at most [`MAX_INDEX_ENTRIES`] of them. A missing directory holds
    /// none.
    fn qualification_files(directory: &Path, maximum: usize) -> Result<Vec<Vec<u8>>, &'static str> {
        const CODE: &str = "gateway.qualification.unavailable";
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(CODE),
        };
        let mut paths = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CODE)?;
        if paths.len() > MAX_INDEX_ENTRIES {
            return Err(CODE);
        }
        paths.sort();
        paths
            .iter()
            .map(|path| read_bounded(path, maximum).map_err(|_| CODE))
            .collect()
    }

    /// Reads a release directory. An absent file is read as empty, which
    /// verifies as an unusable input, never as a permissive one.
    fn qualification_bundle(directory: &Path) -> Result<QualificationBundle, &'static str> {
        let optional =
            |name: &str, maximum: usize| match read_bounded(&directory.join(name), maximum) {
                Ok(bytes) => Ok(bytes),
                Err(_) if !directory.join(name).exists() => Ok(Vec::new()),
                Err(_) => Err("gateway.qualification.unavailable"),
            };
        Ok(QualificationBundle {
            signer_certificate: optional(
                RELEASE_SIGNER_CERTIFICATE_FILE,
                MAX_SIGNER_CERTIFICATE_BYTES,
            )?,
            revocation_list: optional(RELEASE_REVOCATION_LIST_FILE, MAX_REVOCATION_LIST_BYTES)?,
            release_index: optional(RELEASE_INDEX_FILE, MAX_RELEASE_INDEX_BYTES)?,
            records: qualification_files(
                &directory.join(RELEASE_RECORDS_DIRECTORY),
                MAX_RECORD_BYTES,
            )?,
            attestations: qualification_files(
                &directory.join(RELEASE_ATTESTATIONS_DIRECTORY),
                MAX_ATTESTATION_BYTES,
            )?,
        })
    }

    /// What every verified revocation list has named, as this host keeps it
    /// across restarts.
    #[derive(Default, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct StoredVerifierState {
        accepted_revocation_sequence: u64,
        revoked_signers: Vec<QualificationSignerId>,
        revoked_qualifications: Vec<QualificationId>,
    }

    /// Reads the remembered revocations. A missing file is a host that has
    /// accepted nothing; an unreadable or malformed one is an error, so
    /// damage cannot forget a revocation.
    fn read_verifier_state(state_dir: &Path) -> Result<VerifierState, &'static str> {
        let path = state_dir.join(QUALIFICATION_STATE_FILE);
        if !path.exists() {
            return Ok(VerifierState::default());
        }
        let stored: StoredVerifierState = read_bounded(&path, 256 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or("gateway.qualification.unavailable")?;
        Ok(VerifierState {
            accepted_revocation_sequence: stored.accepted_revocation_sequence,
            revoked_signers: stored.revoked_signers.into_iter().collect(),
            revoked_qualifications: stored.revoked_qualifications.into_iter().collect(),
        })
    }

    fn write_verifier_state(state_dir: &Path, state: &VerifierState) -> Result<(), &'static str> {
        let stored = StoredVerifierState {
            accepted_revocation_sequence: state.accepted_revocation_sequence,
            revoked_signers: state.revoked_signers.iter().cloned().collect(),
            revoked_qualifications: state.revoked_qualifications.iter().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| "gateway.qualification.unavailable")?;
        replace_private_file(&state_dir.join(QUALIFICATION_STATE_FILE), &bytes)
            .map_err(|_| "gateway.qualification.unavailable")
    }

    /// The trust root of an installation: the root this build pins, or a
    /// development installation's own file, which must be the one install
    /// recorded.
    fn qualification_root(
        state_dir: &Path,
        manifest: &Installation,
    ) -> Result<Option<QualificationTrustRoot>, &'static str> {
        const CODE: &str = "gateway.serve.installation-changed";
        let bytes = match (
            &manifest.qualification.trust_root_sha256,
            manifest.deployment,
        ) {
            (Some(pinned), Deployment::Development) => {
                let bytes = read_bounded(
                    &state_dir.join(QUALIFICATION_ROOT_FILE),
                    MAX_TRUST_ROOT_BYTES,
                )
                .map_err(|_| CODE)?;
                if digest(&bytes) != *pinned {
                    return Err(CODE);
                }
                Some(bytes)
            }
            (Some(_), Deployment::Production) => return Err("gateway.serve.invalid-installation"),
            (None, _) => PINNED_QUALIFICATION_ROOT.map(<[u8]>::to_vec),
        };
        bytes
            .map(|bytes| {
                QualificationTrustRoot::from_canonical_json(&bytes)
                    .map_err(|_| "gateway.serve.invalid-installation")
            })
            .transpose()
    }

    /// The tuple this installation must be qualified for, when the operator
    /// declared a family and a contract and the running executable can be
    /// read.
    fn qualification_deployment(
        state_dir: &Path,
        manifest: &Installation,
    ) -> Option<QualificationTuple> {
        let fixed = |text: &str| {
            let mut bytes = [0_u8; 32];
            hex::decode_to_slice(text, &mut bytes).ok().map(|()| bytes)
        };
        let source = read_bounded(&state_dir.join("recipe.json"), 65_536).ok()?;
        let lock = read_bounded(&state_dir.join("profile.lock.json"), 65_536).ok()?;
        let recipe = CompiledRecipe::compile(&source, &lock).ok()?;
        let executable = fs::read(std::env::current_exe().ok()?).ok()?;
        let (store_kind, store_schema) = match manifest.deployment {
            Deployment::Production => (LifecycleStoreKind::PostgresqlV1, POSTGRES_STORE_SCHEMA),
            Deployment::Development => (LifecycleStoreKind::SharedFileV1, FILE_STORE_SCHEMA),
        };
        deployment_tuple(&DeploymentFacts {
            recipe_family: manifest.qualification.recipe_family.as_deref()?,
            provider_contract_id: manifest.qualification.provider_contract_id.as_deref()?,
            compiled_recipe_sha256: *recipe.digest(),
            profile_lock_sha256: fixed(&digest(&lock))?,
            gateway_build_sha256: Sha256::digest(&executable).into(),
            store_kind,
            store_schema,
            credential_store_kind: CredentialStoreKind::parse(&manifest.credential_store.kind)
                .ok()?,
        })
    }

    /// Builds the installation's gate and loads the inputs the operator
    /// imported. The policy is decided again from the deployment, so an
    /// edited manifest cannot relax production.
    fn qualification_gate(
        state_dir: &Path,
        manifest: &Installation,
    ) -> Result<QualificationGate, Failure> {
        let policy = qualification_policy(
            Some(&manifest.qualification.policy),
            production_qualification(manifest.deployment),
        )
        .map_err(|_| "gateway.serve.invalid-installation")?;
        let clock: Box<dyn auths_gateway::DeploymentClock> = match manifest.deployment {
            Deployment::Production => Box::new(SynchronizedHostClock),
            Deployment::Development => Box::new(DevelopmentClock),
        };
        let gate = QualificationGate::new(
            policy,
            qualification_root(state_dir, manifest)?,
            qualification_deployment(state_dir, manifest),
            clock,
            read_verifier_state(state_dir)?,
        );
        qualification_reload(state_dir, &gate)?;
        Ok(gate)
    }

    /// Loads the installed engine for `serve` after checking that the
    /// process may hold the descriptors it will need.
    fn load_for_serve(state_dir: &Path, app_capacity: usize) -> Result<GatewayEngine, Failure> {
        let deployment = installation(state_dir)?.deployment;
        check_descriptor_limit(app_capacity, store_pool(deployment)?)?;
        load_engine(state_dir)
    }

    /// Prints the readiness line. A recipe that is not qualified is
    /// disabled, not the process: proof verification and the operator plane
    /// keep working, and the line says which state was derived.
    fn announce_ready(engine: &GatewayEngine, recipe_marker: &str) {
        let qualification = engine.qualification().status();
        println!(
            "app socket ready; exact recipe {recipe_marker}, qualification policy={} state={} code={}",
            qualification.policy.as_str(),
            qualification.state.as_str(),
            qualification.code.unwrap_or("none")
        );
    }

    /// Reads this host's imported inputs into `gate` and keeps what they
    /// revoke.
    fn qualification_reload(
        state_dir: &Path,
        gate: &QualificationGate,
    ) -> Result<(), &'static str> {
        let bundle = qualification_bundle(&state_dir.join(QUALIFICATION_DIRECTORY))?;
        if gate.load(&bundle) {
            write_verifier_state(state_dir, &gate.verifier_state())?;
        }
        Ok(())
    }

    /// Verifies a release directory under the installation's trust root and
    /// makes it this host's qualification inputs. Inputs whose certificate,
    /// index, or revocation list cannot be used are refused and nothing
    /// changes; anything else is authentic and is kept, whatever state it
    /// derives.
    fn qualification_import(state_dir: &Path, from: &Path) -> Result<(), Failure> {
        const CODE: &str = "gateway.qualification.unavailable";
        private_root(state_dir)?;
        let manifest = installation(state_dir)?;
        let bundle =
            qualification_bundle(from).map_err(|code| Failure::at(code, from, "unreadable"))?;
        let candidate = QualificationGate::new(
            QualificationPolicy::Required,
            qualification_root(state_dir, &manifest)?,
            qualification_deployment(state_dir, &manifest),
            Box::new(DevelopmentClock),
            read_verifier_state(state_dir)?,
        );
        candidate.load(&bundle);
        let status = candidate.status();
        if !candidate.inputs_usable() {
            return Err(Failure::at(
                CODE,
                from,
                "not a release this installation's root signed",
            ));
        }
        let staged = state_dir.join(format!("{QUALIFICATION_DIRECTORY}.next"));
        let retired = state_dir.join(format!("{QUALIFICATION_DIRECTORY}.previous"));
        let current = state_dir.join(QUALIFICATION_DIRECTORY);
        let failed = |error: std::io::Error| Failure::at(CODE, &current, error);
        for stale in [&staged, &retired] {
            if stale.exists() {
                fs::remove_dir_all(stale).map_err(failed)?;
            }
        }
        for directory in [
            staged.clone(),
            staged.join(RELEASE_RECORDS_DIRECTORY),
            staged.join(RELEASE_ATTESTATIONS_DIRECTORY),
        ] {
            fs::create_dir(&directory).map_err(failed)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(failed)?;
        }
        private_file(
            &staged.join(RELEASE_SIGNER_CERTIFICATE_FILE),
            &bundle.signer_certificate,
        )?;
        private_file(
            &staged.join(RELEASE_REVOCATION_LIST_FILE),
            &bundle.revocation_list,
        )?;
        private_file(&staged.join(RELEASE_INDEX_FILE), &bundle.release_index)?;
        for (directory, members) in [
            (RELEASE_RECORDS_DIRECTORY, &bundle.records),
            (RELEASE_ATTESTATIONS_DIRECTORY, &bundle.attestations),
        ] {
            for (position, member) in members.iter().enumerate() {
                private_file(
                    &staged.join(directory).join(format!("{position:04}.json")),
                    member,
                )?;
            }
        }
        if current.exists() {
            fs::rename(&current, &retired).map_err(failed)?;
        }
        fs::rename(&staged, &current).map_err(failed)?;
        if retired.exists() {
            fs::remove_dir_all(&retired).map_err(failed)?;
        }
        write_verifier_state(state_dir, &candidate.verifier_state())?;
        println!(
            "imported qualification inputs: state={} code={}",
            status.state.as_str(),
            status.code.unwrap_or("none")
        );
        Ok(())
    }

    /// Prints the installation's qualification state, or the tuple it must
    /// be qualified for.
    fn qualification_status(state_dir: &Path, tuple: bool) -> Result<(), Failure> {
        private_root(state_dir)?;
        let manifest = installation(state_dir)?;
        if tuple {
            let deployment = qualification_deployment(state_dir, &manifest)
                .ok_or("gateway.qualification.unavailable")?;
            let bytes = serde_json_canonicalizer::to_vec(&deployment)
                .map_err(|_| "gateway.qualification.unavailable")?;
            println!("{}", String::from_utf8_lossy(&bytes));
            return Ok(());
        }
        let status = qualification_gate(state_dir, &manifest)?.status();
        println!(
            "policy={} state={} code={}",
            status.policy.as_str(),
            status.state.as_str(),
            status.code.unwrap_or("none")
        );
        if status.permits_lease() {
            Ok(())
        } else {
            Err(status
                .code
                .unwrap_or("gateway.qualification.unavailable")
                .into())
        }
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

    fn load_engine(state_dir: &Path) -> Result<GatewayEngine, Failure> {
        private_root(state_dir)?;
        let manifest = installation(state_dir)?;
        let source = read_bounded(&state_dir.join("recipe.json"), 65_536)?;
        let lock = read_bounded(&state_dir.join("profile.lock.json"), 65_536)?;
        let trust = read_bounded(&state_dir.join("trusted.context.cbor"), 4 * 1024 * 1024)?;
        if digest(&lock) != manifest.profile_lock_sha256
            || digest(&trust) != manifest.trusted_context_sha256
        {
            return Err("gateway.serve.installation-changed".into());
        }
        let context = auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.serve.invalid-installation")?;
        check_anchor_aliasing(&context).map_err(PrincipalSeparationError::code)?;
        let operator = match (&manifest.operator_attestation_sha256, manifest.deployment) {
            (Some(pinned), _) => {
                let bytes = read_attestation(&state_dir.join(OPERATOR_ATTESTATION_FILE))?;
                if digest(&bytes) != *pinned {
                    return Err("gateway.install.operator-attestation-invalid".into());
                }
                Some(authenticated_operator(
                    &bytes,
                    &manifest.operator_installation(),
                    &context,
                )?)
            }
            (None, Deployment::Production) => {
                return Err("gateway.install.operator-attestation-required".into());
            }
            (None, Deployment::Development) => None,
        };
        let recipe =
            CompiledRecipe::compile(&source, &lock).map_err(|_| "gateway.serve.invalid-recipe")?;
        if recipe.digest_hex() != manifest.recipe_digest {
            return Err("gateway.serve.recipe-changed".into());
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
            return Err("gateway.production.observer-software-custody".into());
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
            open_credentials(
                state_dir,
                &manifest.credential_store,
                manifest.deployment,
                "gateway.serve.credential-store-unavailable",
            )?,
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
        let engine = engine.with_qualification(Arc::new(qualification_gate(state_dir, &manifest)?));
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

    fn observer_init(state_dir: &Path) -> Result<(), Failure> {
        if installation(state_dir)?.deployment == Deployment::Production {
            return Err("gateway.production.observer-software-custody".into());
        }
        private_root(state_dir)?;
        let recipe = installed_recipe(state_dir)?;
        let observer = GatewayObserver::generate(&state_dir.join(OBSERVER_SEED))
            .map_err(GatewayObserverError::code)?;
        File::open(state_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "gateway.state.sync-failed")?;
        Ok(print_observer(&observer, &recipe)?)
    }

    fn observer_show(state_dir: &Path) -> Result<(), Failure> {
        private_root(state_dir)?;
        let recipe = installed_recipe(state_dir)?;
        let observer = load_observer(state_dir)?.ok_or("gateway.observer.not-provisioned")?;
        Ok(print_observer(&observer, &recipe)?)
    }

    /// One admin command, with the secret a rotation carries.
    enum AdminCommand {
        Disable,
        Enable,
        Revoke,
        Rotate(Zeroizing<Vec<u8>>),
        RotatePrepare(Zeroizing<Vec<u8>>),
        RotateCommit([u8; 32]),
        Status,
        Reobserve(String),
        QualificationReload,
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
            AdminRequestCommand::QualificationReload {} => Ok(AdminCommand::QualificationReload),
            AdminRequestCommand::Reobserve { operation_id } => {
                Ok(AdminCommand::Reobserve(operation_id))
            }
            AdminRequestCommand::Rotate {} => read_admin_secret(clock, stream)
                .await
                .map(AdminCommand::Rotate),
            AdminRequestCommand::RotatePrepare {} => read_admin_secret(clock, stream)
                .await
                .map(AdminCommand::RotatePrepare),
            AdminRequestCommand::RotateCommit { commitment } => {
                let mut bytes = [0_u8; 32];
                let lowercase = commitment
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                if commitment.len() != 64
                    || !lowercase
                    || hex::decode_to_slice(&commitment, &mut bytes).is_err()
                {
                    return Err("gateway.admin.invalid-frame");
                }
                Ok(AdminCommand::RotateCommit(bytes))
            }
        }
    }

    /// Reads the secret frame a rotation carries.
    async fn read_admin_secret(
        clock: &SessionClock,
        stream: &mut UnixStream,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
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
        Ok(Zeroizing::new(secret))
    }

    /// Serves one admin connection within [`ADMIN_SESSION_LIMITS`]. The peer
    /// check at accept alone authorizes every command, so custody
    /// unavailability can never block the kill switch. A change the engine
    /// has started is never cancelled by a deadline.
    async fn admin_session(
        mut stream: UnixStream,
        engine: Arc<GatewayEngine>,
        state_dir: Arc<PathBuf>,
    ) {
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
                Ok(AdminCommand::RotatePrepare(secret)) => {
                    match engine.prepare_rotation(secret).await {
                        Ok(commitment) => AdminResponse {
                            ok: true,
                            commitment: Some(hex::encode(commitment)),
                            ..AdminResponse::refused("gateway.admin.rotation-prepared")
                        },
                        Err(code) => AdminResponse::refused(code),
                    }
                }
                Ok(AdminCommand::RotateCommit(commitment)) => {
                    AdminResponse::of(engine.commit_rotation(commitment).await)
                }
                Ok(AdminCommand::Status) => match engine.status().await {
                    Ok(status) => AdminResponse {
                        ok: true,
                        status: Some(status),
                        ..AdminResponse::refused("gateway.admin.status")
                    },
                    Err(code) => AdminResponse::refused(code),
                },
                Ok(AdminCommand::QualificationReload) => {
                    let reloading = Arc::clone(&engine);
                    let directory = Arc::clone(&state_dir);
                    let reloaded = tokio::task::spawn_blocking(move || {
                        qualification_reload(&directory, reloading.qualification())
                    })
                    .await;
                    match reloaded {
                        Ok(Ok(())) => AdminResponse {
                            ok: true,
                            qualification: Some(QualificationReport::of(engine.qualification())),
                            ..AdminResponse::refused("gateway.admin.qualification-reloaded")
                        },
                        Ok(Err(code)) => AdminResponse::refused(code),
                        Err(_) => AdminResponse::refused("gateway.qualification.unavailable"),
                    }
                }
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

    fn bind_recovering_socket(path: &Path, code: &'static str) -> Result<UnixListener, Failure> {
        let owner = rustix::process::geteuid().as_raw();
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                // Only replace a dead socket owned by this gateway inside its own
                // non-writable directory. A live listener or foreign inode fails closed.
                if !secure_socket_parent(path, owner) {
                    return Err(Failure::at(
                        code,
                        path,
                        "the parent directory is not this gateway's own directory closed to group and other writes",
                    ));
                }
                if !metadata.file_type().is_socket() {
                    return Err(Failure::at(code, path, "an existing file is not a socket"));
                }
                if metadata.uid() != owner {
                    return Err(Failure::at(
                        code,
                        path,
                        format_args!("the existing socket is owned by UID {}", metadata.uid()),
                    ));
                }
                match std::os::unix::net::UnixStream::connect(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    Ok(_) => {
                        return Err(Failure::at(
                            code,
                            path,
                            "a live listener answers at this path",
                        ));
                    }
                    Err(error) => {
                        return Err(Failure::at(
                            code,
                            path,
                            format_args!("cannot tell whether a listener answers: {error}"),
                        ));
                    }
                }
                fs::remove_file(path).map_err(|error| Failure::at(code, path, error))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Failure::at(code, path, error)),
        }
        UnixListener::bind(path).map_err(|error| Failure::at(code, path, error))
    }

    /// Removes a socket file this process bound when startup fails after
    /// the bind; [`BoundSocket::keep`] leaves it for the running gateway.
    struct BoundSocket<'a> {
        path: &'a Path,
        kept: bool,
    }

    impl<'a> BoundSocket<'a> {
        const fn new(path: &'a Path) -> Self {
            Self { path, kept: false }
        }

        fn keep(mut self) {
            self.kept = true;
        }
    }

    impl Drop for BoundSocket<'_> {
        fn drop(&mut self) {
            if !self.kept {
                let _ = fs::remove_file(self.path);
            }
        }
    }

    async fn serve(
        state_dir: PathBuf,
        app_socket: PathBuf,
        admin_socket: AdminSocket,
        app_capacity: usize,
        loopback_provider: Option<u16>,
    ) -> Result<(), Failure> {
        let loading = state_dir.clone();
        let engine = tokio::task::spawn_blocking(move || load_for_serve(&loading, app_capacity))
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
        // Both paths are checked before either socket is bound.
        if !app_socket.is_absolute() {
            return Err("gateway.serve.invalid-app-socket".into());
        }
        check_socket_path_length(&app_socket).map_err(|cause| {
            Failure::at("gateway.serve.app-socket-too-long", &app_socket, cause)
        })?;
        if admin_socket.path == app_socket {
            return Err(Failure::at(
                SERVE_ADMIN_SOCKET.invalid,
                &admin_socket.path,
                "the same path as --app-socket",
            ));
        }
        check_admin_socket(&admin_socket, &SERVE_ADMIN_SOCKET)?;
        let admin_path = admin_socket.path.as_path();
        // The admin socket is bound first, so the socket an application
        // waits for appears last.
        let admin = bind_recovering_socket(admin_path, "gateway.serve.admin-bind-failed")?;
        let admin_bound = BoundSocket::new(admin_path);
        fs::set_permissions(admin_path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            Failure::at("gateway.serve.admin-permissions-failed", admin_path, error)
        })?;
        let app = bind_recovering_socket(&app_socket, "gateway.serve.app-bind-failed")?;
        let app_bound = BoundSocket::new(&app_socket);
        fs::set_permissions(&app_socket, fs::Permissions::from_mode(0o660)).map_err(|error| {
            Failure::at("gateway.serve.app-permissions-failed", &app_socket, error)
        })?;
        let recipe_marker = engine_recipe_marker(&state_dir)?;
        let admin_state_dir = Arc::new(state_dir.clone());
        admin_bound.keep();
        app_bound.keep();
        announce_ready(&engine, &recipe_marker);
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
                let state_dir = Arc::clone(&admin_state_dir);
                async move {
                    let _permit = permit;
                    admin_session(stream, engine, state_dir).await;
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

    /// Connects to an application socket, reporting a path over the
    /// platform limit before connecting and any connect error with its path.
    async fn connect_app_socket(socket: &Path, code: &'static str) -> Result<UnixStream, Failure> {
        check_socket_path_length(socket).map_err(|cause| Failure::at(code, socket, cause))?;
        UnixStream::connect(socket)
            .await
            .map_err(|error| Failure::at(code, socket, error))
    }

    async fn submit(socket: PathBuf, proof: PathBuf, action: PathBuf) -> Result<(), Failure> {
        let proof = read_bounded(&proof, 4 * 1024 * 1024)?;
        let action = read_bounded(&action, 64 * 1024)?;
        let request = AppSubmission {
            schema: APP_REQUEST_SCHEMA.to_owned(),
            proof_b64: Base64UrlUnpadded::encode_string(&proof),
            action_b64: Base64UrlUnpadded::encode_string(&action),
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| "gateway.submit.encoding-failed")?;
        let mut stream = connect_app_socket(&socket, "gateway.submit.socket-unavailable").await?;
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
    ) -> Result<(), Failure> {
        let request = match (read_back, outcome, pre_entry) {
            (Some(arguments), None, None) => GatewayObserveRequest::ReadBack {
                arguments: serde_json::from_str(&arguments)
                    .map_err(|_| "gateway.observe.invalid-arguments")?,
            },
            (None, Some(operation_id), None) => GatewayObserveRequest::Outcome { operation_id },
            (None, None, Some(operation_id)) => GatewayObserveRequest::PreEntry { operation_id },
            _ => return Err("gateway.observe.invalid-request".into()),
        };
        let bytes = serde_json::to_vec(&AppObservation {
            schema: APP_OBSERVE_SCHEMA.to_owned(),
            request,
        })
        .map_err(|_| "gateway.observe.encoding-failed")?;
        let mut stream = connect_app_socket(&socket, "gateway.observe.socket-unavailable").await?;
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
            GatewayObserveResult::Refused { .. } => Err("gateway.observe.refused".into()),
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

    /// Sends one admin command. Before anything is written, the admin
    /// socket must pass the checks `serve` applies, and the listener must
    /// run as this user or root, so a rotated credential never reaches a
    /// socket another user controls.
    async fn admin_command(
        state_dir: &Path,
        admin_socket: &AdminSocket,
        command: serde_json::Value,
        secret: Option<&[u8]>,
    ) -> Result<(), Failure> {
        const CODE: &str = "gateway.admin.socket-unavailable";
        private_root(state_dir)?;
        check_admin_socket(admin_socket, &CLIENT_ADMIN_SOCKET)?;
        let path = admin_socket.path.as_path();
        let mut request = serde_json::json!({"schema": ADMIN_REQUEST_SCHEMA});
        if let (Some(request), serde_json::Value::Object(fields)) =
            (request.as_object_mut(), command)
        {
            request.extend(fields);
        }
        let frame = serde_json::to_vec(&request).map_err(|_| "gateway.admin.invalid-frame")?;
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(|error| Failure::at(CODE, path, error))?;
        let listener = stream
            .peer_cred()
            .map_err(|error| Failure::at(CODE, path, error))?
            .uid();
        if listener != rustix::process::geteuid().as_raw() && listener != 0 {
            return Err(Failure::at(
                CODE,
                path,
                format_args!("the listener runs as UID {listener}, neither this user nor root"),
            ));
        }
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
            Err("gateway.admin.refused".into())
        }
    }

    async fn rotate(
        state_dir: &Path,
        admin_socket: &AdminSocket,
        credential_stdin: bool,
        command: &str,
    ) -> Result<(), Failure> {
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.admin.credential-must-be-piped-to-stdin".into());
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
            return Err("gateway.admin.invalid-credential".into());
        }
        admin_command(
            state_dir,
            admin_socket,
            serde_json::json!({"command": command}),
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
    fn operator_attest(
        state_dir: &Path,
        admin_socket: &Path,
        attestation: &Path,
    ) -> Result<(), Failure> {
        private_root(state_dir)?;
        if std::os::unix::net::UnixStream::connect(admin_socket).is_ok() {
            return Err("gateway.operator.gateway-running".into());
        }
        let mut manifest = installation(state_dir)?;
        let trust = read_bounded(&state_dir.join("trusted.context.cbor"), 4 * 1024 * 1024)?;
        if digest(&trust) != manifest.trusted_context_sha256 {
            return Err("gateway.serve.installation-changed".into());
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
        admin_socket: &Path,
        app_socket: &Path,
        application_uid: u32,
        probe_group: u32,
    ) -> Result<(), &'static str> {
        let state =
            fs::symlink_metadata(state_dir).map_err(|_| "gateway.doctor.state-unavailable")?;
        // Only the development store keeps a credential file in the state
        // directory. The production store keeps nothing there to protect.
        let custody = installation(state_dir)
            .map_err(|_| "gateway.doctor.state-unavailable")?
            .credential_store
            .kind;
        let credential_file = if custody == CredentialStoreKind::LocalFileV1.as_str() {
            Some(
                fs::symlink_metadata(state_dir.join("credentials.cbor"))
                    .map_err(|_| "gateway.doctor.credential-unavailable")?,
            )
        } else {
            None
        };
        let credential_private = credential_file.as_ref().is_none_or(|credential| {
            let exposed = credential.permissions().mode() & 0o077 != 0;
            credential.file_type().is_file() && !exposed
        });
        let admin =
            fs::symlink_metadata(admin_socket).map_err(|_| "gateway.doctor.admin-unavailable")?;
        let admin_parent_private = admin_socket
            .parent()
            .is_some_and(|parent| check_private_directory_owned_by(parent, state.uid()).is_ok());
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
            || !credential_private
            || !admin.file_type().is_socket()
            || !admin_parent_private
            || !app.file_type().is_socket()
            || !secure_socket_parent(app_socket, state.uid())
            || app.uid() != state.uid()
            || credential_file
                .as_ref()
                .is_some_and(|credential| state.uid() != credential.uid())
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
        .arg("--admin-socket")
        .arg(admin_socket)
        .arg("--app-socket")
        .arg(app_socket)
        .gid(probe_group)
        .uid(application_uid)
        .status()
        .map_err(|_| "gateway.doctor.probe-unavailable")?;
        if !status.success() {
            return Err("gateway.doctor.isolation-not-established");
        }
        let observer = if state_dir.join(OBSERVER_SEED).exists() {
            "configured"
        } else {
            "not configured (signed outcomes unavailable)"
        };
        println!(
            "gateway state and admin socket denied to app UID; app socket reachable. Independent token copies and egress policy not checked."
        );
        println!("provider credential store: {custody}");
        println!("observer: {observer}");
        let manifest = installation(state_dir).map_err(|_| "gateway.doctor.state-unavailable")?;
        let qualification = qualification_gate(state_dir, &manifest)
            .map_err(|failure| failure.code)?
            .status();
        println!(
            "qualification: policy={} state={} code={}",
            qualification.policy.as_str(),
            qualification.state.as_str(),
            qualification.code.unwrap_or("none")
        );
        Ok(())
    }

    fn probe(state_dir: &Path, admin_socket: &Path, app_socket: &Path) -> Result<(), &'static str> {
        // Doctor starts the probe with an empty environment. On Linux nothing
        // adds to it, so any variable was inherited and could carry operator
        // secrets to the application UID. macOS system libraries set their own.
        if cfg!(target_os = "linux") && std::env::vars_os().next().is_some() {
            return Err("gateway.doctor.probe-environment-not-empty");
        }
        if File::open(state_dir.join("credentials.cbor")).is_ok()
            || File::open(state_dir.join(OBSERVER_SEED)).is_ok()
            || std::os::unix::net::UnixStream::connect(admin_socket).is_ok()
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
    pub async fn run() -> Result<(), Failure> {
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
                qualification,
                credential_store,
                credential_namespace,
                aws_region,
                aws_kms_key,
                aws_identity,
                #[cfg(feature = "loopback-provider")]
                loopback_provider,
            } => {
                #[cfg(not(feature = "loopback-provider"))]
                let loopback_provider = None;
                let credential_store = CredentialStoreSettings {
                    kind: credential_store,
                    namespace: credential_namespace,
                    region: aws_region,
                    kms_key: aws_kms_key,
                    identity: aws_identity,
                };
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
                    credential_store,
                    qualification,
                    loopback_provider,
                )
                .await
            }
            Command::QualificationImport {
                state_dir,
                from,
                admin_socket,
            } => {
                let importing = state_dir.clone();
                tokio::task::spawn_blocking(move || qualification_import(&importing, &from))
                    .await
                    .map_err(|_| "gateway.qualification.unavailable")??;
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                // A gateway that is not serving reads the inputs when it
                // starts; only a listening one is asked to read them now.
                if UnixStream::connect(&admin_socket.path).await.is_err() {
                    return Ok(());
                }
                let command = serde_json::json!({"command": "qualification-reload"});
                admin_command(&state_dir, &admin_socket, command, None).await
            }
            Command::QualificationStatus { state_dir, tuple } => {
                tokio::task::spawn_blocking(move || qualification_status(&state_dir, tuple))
                    .await
                    .map_err(|_| "gateway.qualification.unavailable")?
            }
            #[cfg(feature = "loopback-provider")]
            Command::Serve {
                state_dir,
                app_socket,
                admin_socket,
                app_capacity,
                loopback_provider,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                serve(
                    state_dir,
                    app_socket,
                    admin_socket,
                    usize::from(app_capacity),
                    loopback_provider,
                )
                .await
            }
            #[cfg(not(feature = "loopback-provider"))]
            Command::Serve {
                state_dir,
                app_socket,
                admin_socket,
                app_capacity,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                serve(
                    state_dir,
                    app_socket,
                    admin_socket,
                    usize::from(app_capacity),
                    None,
                )
                .await
            }
            Command::Review {
                recipe,
                profile_lock,
            } => Ok(review(&recipe, &profile_lock)?),
            Command::BoundExtension(options) => Ok(bound_extension(&options)?),
            Command::Audit {
                bundle,
                trusted_context_sha256,
                observer,
                allow_unverified_refusals,
            } => Ok(audit(
                &bundle,
                &trusted_context_sha256,
                &observer,
                if allow_unverified_refusals {
                    UnverifiedEntries::AllowRefusals
                } else {
                    UnverifiedEntries::Fail
                },
            )?),
            Command::Submit {
                app_socket,
                proof,
                action,
            } => submit(app_socket, proof, action).await,
            Command::Disable {
                state_dir,
                admin_socket,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                let command = serde_json::json!({"command": "disable"});
                admin_command(&state_dir, &admin_socket, command, None).await
            }
            Command::Enable {
                state_dir,
                admin_socket,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                let command = serde_json::json!({"command": "enable"});
                admin_command(&state_dir, &admin_socket, command, None).await
            }
            Command::Revoke {
                state_dir,
                admin_socket,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                let command = serde_json::json!({"command": "revoke"});
                admin_command(&state_dir, &admin_socket, command, None).await
            }
            Command::Status {
                state_dir,
                admin_socket,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                let command = serde_json::json!({"command": "status"});
                admin_command(&state_dir, &admin_socket, command, None).await
            }
            Command::Reobserve {
                state_dir,
                admin_socket,
                operation_id,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                let command =
                    serde_json::json!({"command": "reobserve", "operation_id": operation_id});
                admin_command(&state_dir, &admin_socket, command, None).await
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
            } => Ok(operator_request(
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
            )?),
            Command::OperatorAttest {
                state_dir,
                admin_socket,
                operator_attestation,
                replace: _,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                operator_attest(&state_dir, &admin_socket.path, &operator_attestation)
            }
            Command::Rotate {
                state_dir,
                admin_socket,
                credential_stdin,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                rotate(&state_dir, &admin_socket, credential_stdin, "rotate").await
            }
            Command::RotatePrepare {
                state_dir,
                admin_socket,
                credential_stdin,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                rotate(
                    &state_dir,
                    &admin_socket,
                    credential_stdin,
                    "rotate-prepare",
                )
                .await
            }
            Command::RotateCommit {
                state_dir,
                admin_socket,
                commitment,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                admin_command(
                    &state_dir,
                    &admin_socket,
                    serde_json::json!({"command": "rotate-commit", "commitment": commitment}),
                    None,
                )
                .await
            }
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
                    _ => return Err("gateway.echo-verify.action-invalid".into()),
                };
                Ok(echo_verify(&record, &pointer, &operation_id, source)?)
            }
            Command::Doctor {
                state_dir,
                admin_socket,
                app_socket,
                app_uid,
                app_gid,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                Ok(doctor(
                    &state_dir,
                    &admin_socket.path,
                    &app_socket,
                    app_uid,
                    app_gid,
                )?)
            }
            Command::Probe {
                state_dir,
                admin_socket,
                app_socket,
            } => {
                let admin_socket = admin_socket_path(&state_dir, admin_socket);
                Ok(probe(&state_dir, &admin_socket.path, &app_socket)?)
            }
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
    if let Err(failure) = unix::run().await {
        eprintln!("{failure}");
        std::process::exit(1);
    }
}
