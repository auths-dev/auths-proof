#![forbid(unsafe_code)]

use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, ExitCode},
    sync::Arc,
};

use auths_radicle::{NodeId, RadicleDid};
use auths_radicle_demo::{
    AppConfig, HttpPropagationObserver, LiveAppConfig, NodeConfiguration, NodeRole,
    ObserverRuntime, RunningNode, ensure_demo_repository, live_app, observer_app,
};
use axum::Router;

#[tokio::main]
async fn main() -> ExitCode {
    let role = match required("AUTHS_RADICLE_ROLE") {
        Ok(role) => role,
        Err(error) => return startup_failure(&error),
    };
    let router = match role.as_str() {
        "executor" => executor_router(),
        "observer" => observer_router(),
        _ => Err("AUTHS_RADICLE_ROLE must be executor or observer".into()),
    };
    let router = match router {
        Ok(router) => router,
        Err(error) => return startup_failure(&error),
    };
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);
    let address = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => return startup_failure(&format!("could not bind {address}: {error}")),
    };
    if let Err(error) = axum::serve(listener, router).await {
        return startup_failure(&format!("server failed: {error}"));
    }
    ExitCode::SUCCESS
}

fn executor_router() -> Result<Router, String> {
    let common = CommonConfiguration::load(NodeRole::Executor)?;
    let app = AppConfig::from_environment().map_err(|error| error.to_string())?;
    let node = Arc::new(
        RunningNode::start(common.node_configuration()).map_err(|error| error.to_string())?,
    );
    let metadata = ensure_demo_repository(&node).map_err(|error| error.to_string())?;
    let observer_node_id = NodeId::parse(required("AUTHS_RADICLE_OBSERVER_NODE_ID")?)
        .map_err(|error| error.to_string())?;
    let observer_signer_did = RadicleDid::parse(format!("did:key:{observer_node_id}"))
        .map_err(|error| error.to_string())?;
    if observer_signer_did == node.signer_did {
        return Err("observer and executor identities must differ".into());
    }
    let observer_address = required("AUTHS_RADICLE_OBSERVER_P2P_ADDRESS")?;
    node.connect(&observer_node_id, &observer_address)
        .map_err(|error| error.to_string())?;
    let observer = HttpPropagationObserver::new(
        required("AUTHS_RADICLE_OBSERVER_URL")?,
        required("AUTHS_RADICLE_OBSERVER_TOKEN")?,
        required("AUTHS_RADICLE_EXECUTOR_P2P_ADDRESS")?,
        observer_node_id.clone(),
    )
    .map_err(|error| error.to_string())?;
    observer
        .prepare(&metadata, &node.node_id)
        .map_err(|error| error.to_string())?;
    live_app(
        app,
        LiveAppConfig {
            node,
            metadata,
            observer,
            observer_node_id,
            git_executable: common.git_executable,
            rad_executable: common.rad_executable,
            helper_path: common.helper_path,
            expected_rad_version: common.expected_rad_version,
        },
    )
    .map_err(|error| error.to_string())
}

fn observer_router() -> Result<Router, String> {
    let common = CommonConfiguration::load(NodeRole::Observer)?;
    let node = Arc::new(
        RunningNode::start(common.node_configuration()).map_err(|error| error.to_string())?,
    );
    let runtime = ObserverRuntime::new(
        node,
        required("AUTHS_RADICLE_OBSERVER_TOKEN")?,
        env::var("AUTHS_RADICLE_RELEASE").unwrap_or_else(|_| "development".into()),
    )
    .map_err(|error| error.to_string())?;
    Ok(observer_app(runtime))
}

struct CommonConfiguration {
    role: NodeRole,
    rad_executable: PathBuf,
    git_executable: PathBuf,
    helper_path: PathBuf,
    rad_home: PathBuf,
    listen: String,
    expected_rad_version: String,
}

impl CommonConfiguration {
    fn load(role: NodeRole) -> Result<Self, String> {
        let rad_executable = absolute_path("AUTHS_RADICLE_RAD_BIN", "/usr/local/bin/rad")?;
        let git_executable = absolute_path("AUTHS_RADICLE_GIT_BIN", "/usr/bin/git")?;
        let helper_path =
            absolute_path("AUTHS_RADICLE_HELPER_PATH", "/usr/local/bin:/usr/bin:/bin")?;
        let rad_home = absolute_path("AUTHS_RADICLE_HOME", "/data/radicle")?;
        let listen = env::var("AUTHS_RADICLE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8776".into());
        let expected_rad_version = required("AUTHS_RADICLE_EXPECTED_VERSION")?;
        let output = Command::new(&rad_executable)
            .arg("--version")
            .output()
            .map_err(|_| "could not execute pinned rad binary".to_owned())?;
        let actual = String::from_utf8(output.stdout)
            .map_err(|_| "rad --version was not UTF-8".to_owned())?
            .trim()
            .to_owned();
        if !output.status.success() || actual != expected_rad_version {
            return Err(format!(
                "pinned Radicle version mismatch: expected {expected_rad_version:?}, got {actual:?}"
            ));
        }
        Ok(Self {
            role,
            rad_executable,
            git_executable,
            helper_path,
            rad_home,
            listen,
            expected_rad_version,
        })
    }

    fn node_configuration(&self) -> NodeConfiguration {
        NodeConfiguration {
            role: self.role,
            rad_executable: self.rad_executable.clone(),
            git_executable: self.git_executable.clone(),
            helper_path: self.helper_path.clone(),
            rad_home: self.rad_home.clone(),
            listen: self.listen.clone(),
        }
    }
}

fn required(name: &'static str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("required environment variable {name} missing"))
}

fn absolute_path(name: &'static str, fallback: &'static str) -> Result<PathBuf, String> {
    let path = PathBuf::from(env::var(name).unwrap_or_else(|_| fallback.into()));
    path.is_absolute()
        .then_some(path)
        .ok_or_else(|| format!("{name} must be absolute"))
}

fn startup_failure(error: &str) -> ExitCode {
    eprintln!("auths-radicle-demo: {error}");
    ExitCode::from(1)
}
