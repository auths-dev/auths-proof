//! Test-only access to both attempt stores behind one handle, so the same
//! suites run against the single-host file store and the qualified
//! multi-host `PostgreSQL` store.
//!
//! `PostgreSQL` runs need the TLS fixture's three environment slots. Each
//! handle gets its own schema, so parallel tests never share a logical
//! operation, and a reopened handle is a second store instance on its own
//! connection pool, as a second gateway host would be.

use crate::{
    FileGatewayAttemptStore, GatewayAttemptStore, GatewayAttempts, PostgresGatewayAttemptStore,
};
use auths_stores::{
    PostgresLifecycleStore, PostgresPoolConfig, PostgresServerName, PostgresStoreConfig,
    PostgresTlsConfig, SecretConnectionString,
};
use postgres::{Client, Config, config::SslMode};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use std::{path::PathBuf, str::FromStr as _, sync::Arc};
use tokio_postgres_rustls::MakeRustlsConnect;

const URL: &str = "AUTHS_POSTGRES_URL";
const CA: &str = "AUTHS_POSTGRES_CA_PEM";
const SERVER: &str = "AUTHS_POSTGRES_SERVER_NAME";

/// Which store implementation a suite runs against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Backend {
    File,
    Postgres,
}

impl Backend {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Postgres => "postgres",
        }
    }

    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "file" => Self::File,
            "postgres" => Self::Postgres,
            _ => panic!("unknown test backend {value}"),
        }
    }
}

enum Location {
    File {
        root: PathBuf,
        _temp: Option<tempfile::TempDir>,
    },
    Postgres {
        schema: String,
        owned: bool,
    },
}

/// One isolated attempt store and the means to open it again.
pub(crate) struct TestAttempts {
    location: Location,
    attempts: GatewayAttempts,
}

impl TestAttempts {
    /// Opens a fresh, empty store of `backend`.
    pub(crate) fn open(backend: Backend) -> Self {
        let location = match backend {
            Backend::File => {
                let temp = tempfile::tempdir().expect("temp directory");
                let root = std::fs::canonicalize(temp.path())
                    .expect("canonical temp")
                    .join("attempts");
                Location::File {
                    root,
                    _temp: Some(temp),
                }
            }
            Backend::Postgres => {
                let mut suffix = [0_u8; 8];
                getrandom::fill(&mut suffix).expect("randomness");
                let schema = format!("gateway_{}", hex::encode(suffix));
                let statement = format!("CREATE SCHEMA {schema}");
                off_runtime(move || admin_client().batch_execute(&statement))
                    .expect("create test schema");
                Location::Postgres {
                    schema,
                    owned: true,
                }
            }
        };
        let attempts = attempts_at(&location);
        Self { location, attempts }
    }

    /// Attaches to a store another process created at `location`.
    pub(crate) fn attach(backend: Backend, location: &str) -> Self {
        let location = match backend {
            Backend::File => Location::File {
                root: PathBuf::from(location),
                _temp: None,
            },
            Backend::Postgres => Location::Postgres {
                schema: location.to_owned(),
                owned: false,
            },
        };
        let attempts = attempts_at(&location);
        Self { location, attempts }
    }

    pub(crate) const fn attempts(&self) -> &GatewayAttempts {
        &self.attempts
    }

    /// A second, independently opened store over the same durable state.
    pub(crate) fn reopen(&self) -> GatewayAttempts {
        attempts_at(&self.location)
    }

    /// Replaces this handle's store with a newly opened one, as a restart.
    pub(crate) fn restart(&mut self) {
        self.attempts = self.reopen();
    }

    /// Passed to a child process so it attaches to the same state.
    pub(crate) fn location(&self) -> String {
        match &self.location {
            Location::File { root, .. } => root.display().to_string(),
            Location::Postgres { schema, .. } => schema.clone(),
        }
    }

    /// The raw mechanism, for tests that bypass the attempt semantics.
    pub(crate) fn raw(&self) -> Arc<dyn GatewayAttemptStore> {
        raw_at(&self.location)
    }
}

impl Drop for TestAttempts {
    fn drop(&mut self) {
        if let Location::Postgres {
            schema,
            owned: true,
        } = &self.location
        {
            let statement = format!("DROP SCHEMA IF EXISTS {schema} CASCADE");
            let _ = off_runtime(move || admin_client().batch_execute(&statement));
        }
    }
}

fn attempts_at(location: &Location) -> GatewayAttempts {
    GatewayAttempts::new(raw_at(location))
}

fn raw_at(location: &Location) -> Arc<dyn GatewayAttemptStore> {
    match location {
        Location::File { root, .. } => {
            Arc::new(FileGatewayAttemptStore::open(root.clone()).expect("file store"))
        }
        Location::Postgres { schema, .. } => {
            let schema = schema.clone();
            let store = off_runtime(move || {
                PostgresLifecycleStore::connect(postgres_configuration(&schema))
            })
            .expect("TLS PostgreSQL store");
            Arc::new(PostgresGatewayAttemptStore::new(Arc::new(store)))
        }
    }
}

/// Whether the TLS `PostgreSQL` fixture's environment slots are present.
pub(crate) fn postgres_configured() -> bool {
    [URL, CA, SERVER]
        .iter()
        .all(|name| std::env::var_os(name).is_some())
}

fn postgres_configuration(schema: &str) -> PostgresStoreConfig {
    let url = std::env::var(URL).expect("AUTHS_POSTGRES_URL");
    PostgresStoreConfig::new(
        SecretConnectionString::new(format!("{url} options='-c search_path={schema}'"))
            .expect("connection"),
        PostgresTlsConfig::new(
            PathBuf::from(std::env::var(CA).expect("AUTHS_POSTGRES_CA_PEM")),
            PostgresServerName::parse(std::env::var(SERVER).expect("server name"))
                .expect("server name"),
        ),
        PostgresPoolConfig::default(),
        1_024,
        Vec::new(),
    )
    .expect("store configuration")
}

fn admin_client() -> Client {
    let config =
        Config::from_str(&std::env::var(URL).expect("AUTHS_POSTGRES_URL")).expect("connection");
    assert_eq!(config.get_ssl_mode(), SslMode::Require);
    let mut roots = RootCertStore::empty();
    for certificate in
        CertificateDer::pem_file_iter(std::env::var(CA).expect("CA")).expect("CA bundle")
    {
        roots.add(certificate.expect("certificate")).expect("root");
    }
    config
        .connect(MakeRustlsConnect::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
        .expect("admin connection")
}

/// Runs blocking `PostgreSQL` client work on a plain thread; the sync client
/// may not run on an async executor thread.
fn off_runtime<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(work).join().expect("off-runtime work")
}
