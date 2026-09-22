//! Single-host customer-operated gateway. The app socket accepts proof and
//! action only; installation and administration require the operator channel.

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
    use auths_gateway::{
        CompiledRecipe, FileGatewayAttemptStore, GatewayConnectionDescriptor, GatewayEngine,
        GatewaySubmitResult,
    };
    use auths_stores::PersistentConnectionStore;
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use clap::{Parser, Subcommand};
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
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{UnixListener, UnixStream},
        sync::Semaphore,
    };

    const MANIFEST_SCHEMA: &str = "auths.gateway-installation/1";
    const APP_REQUEST_SCHEMA: &str = "auths.gateway-submit/1";
    const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

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
        },
        /// Serve a restricted application socket and private admin socket.
        Serve {
            #[arg(long)]
            state_dir: PathBuf,
            #[arg(long)]
            app_socket: PathBuf,
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

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Installation {
        schema: String,
        recipe_digest: String,
        profile_lock_sha256: String,
        trusted_context_sha256: String,
        provider: String,
        alias: String,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct AppSubmission {
        schema: String,
        proof_b64: String,
        action_b64: String,
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
    ) -> Result<(), &'static str> {
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.install.credential-must-be-piped-to-stdin");
        }
        let source = read_bounded(&recipe_path, 65_536)?;
        let lock = read_bounded(&lock_path, 65_536)?;
        let trust = read_bounded(&context_path, 4 * 1024 * 1024)?;
        auths_codec::decode_verifier_context(&trust)
            .map_err(|_| "gateway.install.invalid-trusted-context")?;
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
        let mut secret = Vec::new();
        std::io::stdin()
            .take(4_098)
            .read_to_end(&mut secret)
            .map_err(|_| "gateway.install.credential-unavailable")?;
        if secret.last() == Some(&b'\n') {
            secret.pop();
        }
        if secret.is_empty()
            || secret.len() > 4_096
            || !secret.iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err("gateway.install.invalid-credential");
        }
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
            .install(
                &connection_id,
                generation,
                SecretBytes::new(secret).map_err(|_| "gateway.install.invalid-credential")?,
            )
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

    fn load_engine(state_dir: &Path) -> Result<GatewayEngine, &'static str> {
        private_root(state_dir)?;
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
        GatewayEngine::new(
            recipe,
            approved,
            trust,
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
            FileGatewayAttemptStore::open(state_dir.join("attempts"))
                .map_err(|_| "gateway.serve.attempt-store-unavailable")?,
        )
        .map_err(|_| "gateway.serve.invalid-installation")
    }

    async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
        let length = stream
            .read_u32()
            .await
            .map_err(|_| "gateway.ipc.read-failed")? as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err("gateway.ipc.invalid-size");
        }
        let mut bytes = vec![0_u8; length];
        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|_| "gateway.ipc.read-failed")?;
        Ok(bytes)
    }

    async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err("gateway.ipc.invalid-size");
        }
        stream
            .write_u32(bytes.len() as u32)
            .await
            .map_err(|_| "gateway.ipc.write-failed")?;
        stream
            .write_all(bytes)
            .await
            .map_err(|_| "gateway.ipc.write-failed")
    }

    async fn app_session(mut stream: UnixStream, engine: Arc<GatewayEngine>) {
        let result =
            match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream)).await {
                Ok(Ok(bytes)) => match serde_json::from_slice::<AppSubmission>(&bytes) {
                    Ok(submission) if submission.schema == APP_REQUEST_SCHEMA => {
                        match (
                            Base64UrlUnpadded::decode_vec(&submission.proof_b64),
                            Base64UrlUnpadded::decode_vec(&submission.action_b64),
                        ) {
                            (Ok(proof), Ok(action)) => engine.submit(&proof, &action).await,
                            _ => GatewaySubmitResult::Indeterminate {
                                code: "gateway.submit.invalid-encoding".to_owned(),
                            },
                        }
                    }
                    _ => GatewaySubmitResult::Indeterminate {
                        code: "gateway.submit.invalid-frame".to_owned(),
                    },
                },
                _ => GatewaySubmitResult::Indeterminate {
                    code: "gateway.submit.invalid-frame".to_owned(),
                },
            };
        if let Ok(bytes) = serde_json::to_vec(&result) {
            let _ = write_frame(&mut stream, &bytes).await;
        }
    }

    async fn admin_session(mut stream: UnixStream, engine: Arc<GatewayEngine>) {
        let response = match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
            .await
        {
            Ok(Ok(bytes)) => match serde_json::from_slice::<AdminRequest>(&bytes) {
                Ok(AdminRequest::Disable) => match engine.disable_connection().await {
                    Ok(()) => AdminResponse {
                        ok: true,
                        code: "gateway.admin.disabled",
                    },
                    Err(code) => AdminResponse { ok: false, code },
                },
                Ok(AdminRequest::Revoke) => match engine.revoke_connection().await {
                    Ok(()) => AdminResponse {
                        ok: true,
                        code: "gateway.admin.revoked",
                    },
                    Err(code) => AdminResponse { ok: false, code },
                },
                Ok(AdminRequest::Rotate) => {
                    let secret =
                        tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream)).await;
                    match secret {
                        Ok(Ok(bytes))
                            if bytes.len() <= 4_096
                                && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) =>
                        {
                            match SecretBytes::new(bytes) {
                                Ok(secret) => match engine.rotate_connection(secret).await {
                                    Ok(()) => AdminResponse {
                                        ok: true,
                                        code: "gateway.admin.rotated",
                                    },
                                    Err(code) => AdminResponse { ok: false, code },
                                },
                                Err(_) => AdminResponse {
                                    ok: false,
                                    code: "gateway.admin.invalid-credential",
                                },
                            }
                        }
                        Ok(Ok(mut bytes)) => {
                            bytes.fill(0);
                            AdminResponse {
                                ok: false,
                                code: "gateway.admin.invalid-credential",
                            }
                        }
                        _ => AdminResponse {
                            ok: false,
                            code: "gateway.admin.invalid-credential",
                        },
                    }
                }
                Err(_) => AdminResponse {
                    ok: false,
                    code: "gateway.admin.invalid-frame",
                },
            },
            _ => AdminResponse {
                ok: false,
                code: "gateway.admin.invalid-frame",
            },
        };
        if let Ok(bytes) = serde_json::to_vec(&response) {
            let _ = write_frame(&mut stream, &bytes).await;
        }
    }

    async fn serve(state_dir: PathBuf, app_socket: PathBuf) -> Result<(), &'static str> {
        let engine = Arc::new(load_engine(&state_dir)?);
        if !app_socket.is_absolute() || app_socket.exists() {
            return Err("gateway.serve.invalid-app-socket");
        }
        let admin_socket = state_dir.join("admin.sock");
        if admin_socket.exists() {
            return Err("gateway.serve.admin-socket-exists");
        }
        let app = UnixListener::bind(&app_socket).map_err(|_| "gateway.serve.app-bind-failed")?;
        fs::set_permissions(&app_socket, fs::Permissions::from_mode(0o660))
            .map_err(|_| "gateway.serve.app-permissions-failed")?;
        let admin =
            UnixListener::bind(&admin_socket).map_err(|_| "gateway.serve.admin-bind-failed")?;
        fs::set_permissions(&admin_socket, fs::Permissions::from_mode(0o600))
            .map_err(|_| "gateway.serve.admin-permissions-failed")?;
        println!(
            "app socket ready; exact recipe {}, no provider-effect qualification",
            engine_recipe_marker(&state_dir)?
        );
        let capacity = Arc::new(Semaphore::new(64));
        loop {
            tokio::select! {
                accepted = app.accept() => {
                    let (stream, _) = accepted.map_err(|_| "gateway.serve.app-accept-failed")?;
                    if let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() {
                        let engine = Arc::clone(&engine);
                        tokio::spawn(async move { let _permit = permit; app_session(stream, engine).await; });
                    }
                }
                accepted = admin.accept() => {
                    let (stream, _) = accepted.map_err(|_| "gateway.serve.admin-accept-failed")?;
                    if let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() {
                        let engine = Arc::clone(&engine);
                        tokio::spawn(async move { let _permit = permit; admin_session(stream, engine).await; });
                    }
                }
            }
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

    async fn admin_command(
        state_dir: PathBuf,
        command: &'static [u8],
        secret: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        private_root(&state_dir)?;
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
        println!("{}", response);
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err("gateway.admin.refused")
        }
    }

    async fn rotate(state_dir: PathBuf, credential_stdin: bool) -> Result<(), &'static str> {
        if !credential_stdin || std::io::stdin().is_terminal() {
            return Err("gateway.admin.credential-must-be-piped-to-stdin");
        }
        let mut bytes = Vec::new();
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
        let result = admin_command(state_dir, br#"{"command":"rotate"}"#, Some(&bytes)).await;
        bytes.fill(0);
        result
    }

    fn doctor(
        state_dir: PathBuf,
        app_socket: PathBuf,
        app_uid: u32,
        app_gid: u32,
    ) -> Result<(), &'static str> {
        let state =
            fs::symlink_metadata(&state_dir).map_err(|_| "gateway.doctor.state-unavailable")?;
        let credential = fs::symlink_metadata(state_dir.join("credentials.cbor"))
            .map_err(|_| "gateway.doctor.credential-unavailable")?;
        let admin = fs::symlink_metadata(state_dir.join("admin.sock"))
            .map_err(|_| "gateway.doctor.admin-unavailable")?;
        let app =
            fs::symlink_metadata(&app_socket).map_err(|_| "gateway.doctor.app-unavailable")?;
        if !state.file_type().is_dir()
            || state.permissions().mode() & 0o077 != 0
            || !credential.file_type().is_file()
            || credential.permissions().mode() & 0o077 != 0
            || !admin.file_type().is_socket()
            || !app.file_type().is_socket()
            || state.uid() != credential.uid()
            || state.uid() == app_uid
        {
            return Err("gateway.doctor.isolation-not-established");
        }
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("gateway.doctor.privilege-drop-not-checked");
        }
        let status = std::process::Command::new(
            std::env::current_exe().map_err(|_| "gateway.doctor.binary-unavailable")?,
        )
        .arg("probe")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--app-socket")
        .arg(&app_socket)
        .gid(app_gid)
        .uid(app_uid)
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
        if File::open(state_dir.join("credentials.cbor")).is_ok()
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
                )
                .await
            }
            Command::Serve {
                state_dir,
                app_socket,
            } => serve(state_dir, app_socket).await,
            Command::Submit {
                app_socket,
                proof,
                action,
            } => submit(app_socket, proof, action).await,
            Command::Disable { state_dir } => {
                admin_command(state_dir, br#"{"command":"disable"}"#, None).await
            }
            Command::Revoke { state_dir } => {
                admin_command(state_dir, br#"{"command":"revoke"}"#, None).await
            }
            Command::Rotate {
                state_dir,
                credential_stdin,
            } => rotate(state_dir, credential_stdin).await,
            Command::Doctor {
                state_dir,
                app_socket,
                app_uid,
                app_gid,
            } => doctor(state_dir, app_socket, app_uid, app_gid),
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
            assert_eq!(cases["cases"].as_array().expect("cases").len(), 13);
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
