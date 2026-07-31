//! Native interactive demonstration for the Radicle issue workflow.

#![forbid(unsafe_code)]

mod app;
mod deployment;
mod fixture;
mod lifecycle;
mod live;
mod observer;
mod scenario;

pub use app::{AppConfig, StartupError, app};
pub use deployment::{
    DeploymentError, DeploymentMetadata, NodeConfiguration, NodeRole, RunningNode,
    ensure_demo_repository, storage_repository,
};
pub use fixture::{AuthorizationFixture, authorization_fixture};
pub use live::{LiveAppConfig, LiveStartupError, live_app};
pub use observer::{HttpPropagationObserver, ObserverError, ObserverRuntime, observer_app};
pub use scenario::{DemoScenario, DemoVariant, ScenarioError};
