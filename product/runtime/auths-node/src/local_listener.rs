//! Accept loops for the local agent's Unix sockets.
//!
//! Each listener admits a connection only while it is below its own
//! connection limit and below the limit for the connecting peer's UID; a
//! connection past either limit is closed at accept, before any byte is read.
//! The admin socket's limit is separate, so application connections never
//! count against it, and the application limit is sized so that its
//! connections can hold at most half of the descriptors the process limit
//! leaves after the admin socket's share.
//!
//! Admitted connections are served by hyper's HTTP/1 server with a Tokio
//! timer, which hyper needs to enforce its header-read timeout. That timeout
//! bounds the headers of each request and the idle gap before each later
//! request on a kept-alive connection. A request body that stops arriving is
//! abandoned after the body idle timeout. The admin socket also answers a
//! client that closes its sending side once its request is written, as the
//! operator CLI does. An accept error is logged and followed by a back-off;
//! it never ends the loop.

#![forbid(unsafe_code)]

use crate::local_agent::PeerCredentials;
use axum::{Extension, Router, extract::ConnectInfo};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    collections::{HashMap, hash_map::Entry},
    convert::Infallible,
    future::Future,
    io,
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tower::Layer as _;
use tower_http::timeout::RequestBodyTimeout;

/// Application connections admitted agent-wide.
pub(crate) const APPLICATION_CONNECTIONS: usize = 8_192;
/// Application connections one peer UID may hold: 64 sessions per principal,
/// 32 connections per session.
pub(crate) const APPLICATION_CONNECTIONS_PER_PEER: usize = 2_048;
/// Admin connections admitted. Application connections never count here.
pub(crate) const ADMIN_CONNECTIONS: usize = 16;
/// Header-read timeout, which also bounds the idle gap between requests.
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for the next part of a request body.
pub(crate) const REQUEST_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Wait after a failed accept before the listener accepts again.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// The agent does not start with room for fewer application connections than
/// one session may use.
const MINIMUM_APPLICATION_CONNECTIONS: usize = 32;

/// The process descriptor limit cannot hold the admin socket's share and the
/// smallest application limit the agent serves with.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the process descriptor limit is too low to reserve the admin socket's connections")]
pub(crate) struct DescriptorLimitError;

/// Connection limits, timeouts, and HTTP behavior for one listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ListenerPolicy {
    connections: NonZeroUsize,
    connections_per_peer: NonZeroUsize,
    header_read: Duration,
    body_idle: Duration,
    /// Whether a client may close its sending side after a complete request
    /// and still receive the response, as the operator CLI does.
    half_close: bool,
}

impl ListenerPolicy {
    /// Builds a policy, refusing zero values and a per-peer limit above the
    /// listener's. A client that closes its sending side is treated as gone.
    pub(crate) fn new(
        connections: usize,
        connections_per_peer: usize,
        header_read: Duration,
        body_idle: Duration,
    ) -> Option<Self> {
        let connections = NonZeroUsize::new(connections)?;
        let connections_per_peer = NonZeroUsize::new(connections_per_peer)?;
        (connections_per_peer <= connections && !header_read.is_zero() && !body_idle.is_zero())
            .then_some(Self {
                connections,
                connections_per_peer,
                header_read,
                body_idle,
                half_close: false,
            })
    }

    /// The application socket's limits for a process whose soft descriptor
    /// limit is `soft_limit` (`None` when unlimited).
    ///
    /// # Errors
    /// Returns [`DescriptorLimitError`] when half of the descriptors left
    /// after the admin socket's share cannot hold the minimum.
    pub(crate) fn application(soft_limit: Option<u64>) -> Result<Self, DescriptorLimitError> {
        let connections = match soft_limit {
            None => APPLICATION_CONNECTIONS,
            Some(soft_limit) => {
                let admin = u64::try_from(ADMIN_CONNECTIONS).unwrap_or(u64::MAX);
                usize::try_from(soft_limit.saturating_sub(admin) / 2)
                    .map_or(APPLICATION_CONNECTIONS, |half| {
                        half.min(APPLICATION_CONNECTIONS)
                    })
            }
        };
        if connections < MINIMUM_APPLICATION_CONNECTIONS {
            return Err(DescriptorLimitError);
        }
        Self::new(
            connections,
            APPLICATION_CONNECTIONS_PER_PEER.min(connections),
            HEADER_READ_TIMEOUT,
            REQUEST_BODY_IDLE_TIMEOUT,
        )
        .ok_or(DescriptorLimitError)
    }

    /// The admin socket's policy. The operator CLI closes its sending side
    /// once its request is written, so the admin socket still answers it.
    pub(crate) const fn admin() -> Self {
        Self {
            connections: NonZeroUsize::MIN.saturating_add(ADMIN_CONNECTIONS - 1),
            connections_per_peer: NonZeroUsize::MIN.saturating_add(ADMIN_CONNECTIONS - 1),
            header_read: HEADER_READ_TIMEOUT,
            body_idle: REQUEST_BODY_IDLE_TIMEOUT,
            half_close: true,
        }
    }
}

/// This process's soft descriptor limit, or `None` when it is unlimited.
pub(crate) fn descriptor_soft_limit() -> Option<u64> {
    rustix::process::getrlimit(rustix::process::Resource::Nofile).current
}

/// Where a listener's connections come from: a bound [`UnixListener`], or a
/// test double that injects accept errors.
pub(crate) trait AcceptSource {
    /// Accepts the next connection.
    fn accept(&self) -> impl Future<Output = io::Result<UnixStream>> + Send;
}

impl AcceptSource for UnixListener {
    async fn accept(&self) -> io::Result<UnixStream> {
        UnixListener::accept(self).await.map(|(stream, _)| stream)
    }
}

#[derive(Default)]
struct Counts {
    total: usize,
    per_peer: HashMap<u32, usize>,
}

/// Open-connection counts for one listener. The per-peer map holds only
/// peers with an open connection, so it never exceeds the listener's limit.
struct Admission {
    policy: ListenerPolicy,
    counts: Mutex<Counts>,
}

impl Admission {
    fn new(policy: ListenerPolicy) -> Arc<Self> {
        Arc::new(Self {
            policy,
            counts: Mutex::new(Counts::default()),
        })
    }

    /// Counts one more connection from `uid`, or refuses it at either limit.
    fn admit(self: &Arc<Self>, uid: u32) -> Option<Admitted> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let peer = counts.per_peer.get(&uid).copied().unwrap_or(0);
        if counts.total >= self.policy.connections.get()
            || peer >= self.policy.connections_per_peer.get()
        {
            return None;
        }
        counts.total += 1;
        counts.per_peer.insert(uid, peer + 1);
        Some(Admitted {
            admission: Arc::clone(self),
            uid,
        })
    }
}

/// One admitted connection; dropping it releases its place.
struct Admitted {
    admission: Arc<Admission>,
    uid: u32,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut counts = self
            .admission
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Entry::Occupied(mut peer) = counts.per_peer.entry(self.uid) {
            if *peer.get() <= 1 {
                peer.remove();
            } else {
                *peer.get_mut() -= 1;
            }
        }
    }
}

fn peer_credentials(stream: &UnixStream) -> Option<PeerCredentials> {
    let credentials = stream.peer_cred().ok()?;
    Some(PeerCredentials {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid: credentials
            .pid()
            .and_then(|value| u32::try_from(value).ok()),
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        qualification_fault: None,
    })
}

/// Serves `router` on `source` for the life of the process.
///
/// A connection whose peer credentials cannot be read, whose peer `admit`
/// refuses, or that finds the listener or its peer at the limit is closed at
/// accept. Each admitted connection runs on its own task and keeps its place
/// until it closes. An accept error is written to standard error with the
/// listener's `label`, then the loop waits [`ACCEPT_BACKOFF`] and accepts
/// again.
pub(crate) async fn serve<S, A>(
    source: S,
    router: Router,
    policy: ListenerPolicy,
    label: &'static str,
    admit: A,
) -> Infallible
where
    S: AcceptSource,
    A: Fn(PeerCredentials) -> bool,
{
    let admission = Admission::new(policy);
    loop {
        match source.accept().await {
            Ok(stream) => {
                let Some(peer) = peer_credentials(&stream) else {
                    continue;
                };
                if !admit(peer) {
                    continue;
                }
                let Some(admitted) = admission.admit(peer.uid) else {
                    continue;
                };
                tokio::spawn(serve_connection(
                    stream,
                    router.clone(),
                    peer,
                    policy,
                    admitted,
                ));
            }
            Err(error) => {
                eprintln!("auths agent: {label} socket accept failed: {error}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

async fn serve_connection(
    stream: UnixStream,
    router: Router,
    peer: PeerCredentials,
    policy: ListenerPolicy,
    admitted: Admitted,
) {
    let service =
        RequestBodyTimeout::new(Extension(ConnectInfo(peer)).layer(router), policy.body_idle);
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(policy.header_read)
        .half_close(policy.half_close);
    // A connection error (a peer that went away, or a timeout) only ends
    // this connection.
    let _ = http
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
        .await;
    drop(admitted);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        time::{Instant, timeout},
    };

    #[test]
    fn application_limits_leave_half_the_descriptors_to_the_admin_socket_and_the_agent() {
        let unlimited = ListenerPolicy::application(None).unwrap();
        assert_eq!(unlimited.connections.get(), APPLICATION_CONNECTIONS);
        assert_eq!(
            unlimited.connections_per_peer.get(),
            APPLICATION_CONNECTIONS_PER_PEER
        );
        let generous = ListenerPolicy::application(Some(1_048_576)).unwrap();
        assert_eq!(generous.connections.get(), APPLICATION_CONNECTIONS);
        let common = ListenerPolicy::application(Some(1_024)).unwrap();
        assert_eq!(common.connections.get(), (1_024 - ADMIN_CONNECTIONS) / 2);
        assert_eq!(common.connections_per_peer.get(), common.connections.get());
        let smallest = ListenerPolicy::application(Some(
            u64::try_from(2 * MINIMUM_APPLICATION_CONNECTIONS + ADMIN_CONNECTIONS).unwrap(),
        ))
        .unwrap();
        assert_eq!(smallest.connections.get(), MINIMUM_APPLICATION_CONNECTIONS);
        assert_eq!(
            ListenerPolicy::application(Some(
                u64::try_from(2 * MINIMUM_APPLICATION_CONNECTIONS + ADMIN_CONNECTIONS - 1).unwrap()
            )),
            Err(DescriptorLimitError)
        );
        assert_eq!(
            ListenerPolicy::application(Some(0)),
            Err(DescriptorLimitError)
        );
        let admin = ListenerPolicy::admin();
        assert_eq!(admin.connections.get(), ADMIN_CONNECTIONS);
        assert_eq!(admin.connections_per_peer.get(), ADMIN_CONNECTIONS);
    }

    #[test]
    fn admission_caps_connections_listener_wide_and_per_peer() {
        let admission = Admission::new(
            ListenerPolicy::new(4, 2, HEADER_READ_TIMEOUT, REQUEST_BODY_IDLE_TIMEOUT).unwrap(),
        );
        let first = admission.admit(1000).unwrap();
        let _second = admission.admit(1000).unwrap();
        assert!(admission.admit(1000).is_none(), "per-peer limit");
        let _third = admission.admit(1001).unwrap();
        let _fourth = admission.admit(1001).unwrap();
        assert!(admission.admit(1002).is_none(), "listener-wide limit");
        drop(first);
        assert!(
            admission.admit(1001).is_none(),
            "a freed place does not lift another peer's limit"
        );
        let _fifth = admission.admit(1002).unwrap();
        assert!(admission.admit(1000).is_none());
        let counts = admission.counts.lock().unwrap();
        assert_eq!(counts.total, 4);
        assert_eq!(counts.per_peer.len(), 3);
    }

    /// Fails its first `remaining` accepts with `EMFILE`, then accepts from
    /// a real listener.
    struct FailingSource {
        remaining: AtomicUsize,
        listener: UnixListener,
    }

    impl AcceptSource for FailingSource {
        async fn accept(&self) -> io::Result<UnixStream> {
            if self
                .remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
            {
                return Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::MFILE.raw_os_error(),
                ));
            }
            UnixListener::accept(&self.listener)
                .await
                .map(|(stream, _)| stream)
        }
    }

    #[tokio::test]
    async fn accept_errors_back_off_and_the_listener_keeps_serving() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let source = FailingSource {
            remaining: AtomicUsize::new(3),
            listener: UnixListener::bind(&path).unwrap(),
        };
        let router = Router::new().route("/v1/probe", get(|| async { "served" }));
        let policy =
            ListenerPolicy::new(4, 4, HEADER_READ_TIMEOUT, REQUEST_BODY_IDLE_TIMEOUT).unwrap();
        let started = Instant::now();
        let serving = tokio::spawn(serve(source, router, policy, "test", |_| true));
        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(b"GET /v1/probe HTTP/1.1\r\nHost: auths.local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .expect("served after the injected accept errors")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"served"));
        assert!(started.elapsed() >= ACCEPT_BACKOFF * 3);
        assert!(!serving.is_finished(), "an accept error ended the listener");
        serving.abort();
    }
}
