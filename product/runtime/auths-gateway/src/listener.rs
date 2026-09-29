//! Accept loops for the gateway's Unix sockets.
//!
//! Each listener draws on its own capacity, so application connections can
//! never hold the permits the operator's admin socket needs. A connection
//! that finds its listener full, or whose peer the listener does not admit,
//! is closed at accept without a response. An accept error is logged and
//! followed by a back-off; it never ends the loop, so a transient shortage of
//! descriptors cannot stop the gateway.
//!
//! A socket path must fit in the platform's `sun_path` with its terminating
//! NUL: at most 103 bytes on macOS and 107 on Linux.
//! [`check_socket_path_length`] refuses a longer path before anything binds
//! or connects.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    io,
    os::unix::ffi::OsStrExt as _,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// Application connections the gateway serves at once.
pub const APP_CAPACITY: usize = 64;

/// Admin connections the gateway serves at once. They come from a separate
/// capacity that no application connection can take.
pub const ADMIN_CAPACITY: usize = 4;

/// Wait after a failed accept before the listener accepts again.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Longest length probed when measuring the platform's socket path limit.
const SOCKET_PATH_PROBE_LIMIT: usize = 4_096;

/// The longest Unix socket path, in bytes, this platform accepts: the
/// largest length `std::os::unix::net::SocketAddr::from_pathname` accepts,
/// which is the rule tokio's bind and connect apply. It is the size of
/// `sun_path` less its terminating NUL: 103 on macOS and 107 on Linux.
///
/// It is measured once, without creating a socket or touching a file.
#[must_use]
pub fn max_socket_path_bytes() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        (1..=SOCKET_PATH_PROBE_LIMIT)
            .take_while(|&length| {
                std::os::unix::net::SocketAddr::from_pathname("a".repeat(length)).is_ok()
            })
            .last()
            .unwrap_or(0)
    })
}

/// A socket path longer than [`max_socket_path_bytes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketPathTooLong {
    /// The path's length in bytes.
    pub bytes: usize,
    /// The longest path this platform accepts, in bytes.
    pub max: usize,
}

impl fmt::Display for SocketPathTooLong {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} bytes; this platform allows at most {} (sun_path is {} bytes, including the terminating NUL)",
            self.bytes,
            self.max,
            self.max + 1
        )
    }
}

impl std::error::Error for SocketPathTooLong {}

/// Refuses a socket path whose byte length exceeds
/// [`max_socket_path_bytes`], before anything binds or connects to it.
///
/// # Errors
/// Returns the path's length and the platform maximum when it is too long.
pub fn check_socket_path_length(path: &Path) -> Result<(), SocketPathTooLong> {
    let bytes = path.as_os_str().as_bytes().len();
    let max = max_socket_path_bytes();
    if bytes > max {
        return Err(SocketPathTooLong { bytes, max });
    }
    Ok(())
}

/// Where a listener's connections come from: a bound [`UnixListener`], or a
/// test double that injects accept errors.
pub trait ConnectionSource {
    /// Accepts the next connection.
    fn accept(&self) -> impl Future<Output = io::Result<UnixStream>> + Send;
}

impl ConnectionSource for UnixListener {
    async fn accept(&self) -> io::Result<UnixStream> {
        UnixListener::accept(self).await.map(|(stream, _)| stream)
    }
}

/// Serves `source` for the life of the process.
///
/// `admit` sees each accepted connection before it takes a permit, so a peer
/// it refuses never counts against `capacity`. An admitted connection that
/// finds no free permit is closed at once. `session` runs on its own task and
/// holds the permit until it returns. An accept error is written to standard
/// error as `gateway.serve.accept-failed` with the listener's `label`, then
/// the loop waits [`ACCEPT_BACKOFF`] and accepts again.
pub async fn serve_listener<S, A, F, Fut>(
    source: S,
    capacity: Arc<Semaphore>,
    label: &'static str,
    admit: A,
    session: F,
) -> Infallible
where
    S: ConnectionSource,
    A: Fn(&UnixStream) -> bool,
    F: Fn(UnixStream, OwnedSemaphorePermit) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        match source.accept().await {
            Ok(stream) => {
                if !admit(&stream) {
                    continue;
                }
                if let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() {
                    tokio::spawn(session(stream, permit));
                }
            }
            Err(error) => {
                eprintln!("gateway.serve.accept-failed listener={label}: {error}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::Notify,
        time::{Instant, timeout},
    };

    /// Fails its first `remaining` accepts with `EMFILE`, then accepts from
    /// a real listener.
    struct FailingSource {
        remaining: AtomicUsize,
        listener: UnixListener,
    }

    impl ConnectionSource for FailingSource {
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

    #[test]
    fn socket_path_limit_is_sun_path_less_its_nul() {
        let max = max_socket_path_bytes();
        #[cfg(target_os = "linux")]
        assert_eq!(max, 107);
        #[cfg(target_os = "macos")]
        assert_eq!(max, 103);
        assert!(std::os::unix::net::SocketAddr::from_pathname("a".repeat(max)).is_ok());
        assert!(std::os::unix::net::SocketAddr::from_pathname("a".repeat(max + 1)).is_err());
    }

    #[test]
    fn the_kernel_binds_the_longest_path() {
        let max = max_socket_path_bytes();
        let directory = tempfile::tempdir_in("/tmp").expect("short directory");
        let base = std::fs::canonicalize(directory.path()).expect("canonical directory");
        let prefix = base.as_os_str().as_bytes().len() + 1;
        assert!(prefix < max, "the temporary directory is too long");
        let longest = base.join("s".repeat(max - prefix));
        assert_eq!(longest.as_os_str().as_bytes().len(), max);
        let listener = std::os::unix::net::UnixListener::bind(&longest).expect("bind at max");
        drop(listener);
        let over = base.join("t".repeat(max + 1 - prefix));
        let refused = std::os::unix::net::UnixListener::bind(&over)
            .expect_err("a path one byte over the maximum binds");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn check_socket_path_length_reports_the_figures() {
        let max = max_socket_path_bytes();
        let path = "/".repeat(max + 5);
        let refused = check_socket_path_length(Path::new(&path)).expect_err("too long");
        assert_eq!(
            refused,
            SocketPathTooLong {
                bytes: max + 5,
                max
            }
        );
        let text = refused.to_string();
        for figure in [max + 5, max, max + 1] {
            assert!(text.contains(&figure.to_string()), "{text}");
        }
        assert!(check_socket_path_length(Path::new(&"/".repeat(max))).is_ok());
    }

    async fn closed_without_response(stream: &mut UnixStream) -> bool {
        let mut byte = [0_u8; 1];
        matches!(
            timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    #[tokio::test]
    async fn accept_errors_back_off_and_the_listener_keeps_serving() {
        let directory = tempfile::tempdir().expect("socket directory");
        let path = directory.path().join("app.sock");
        let source = FailingSource {
            remaining: AtomicUsize::new(3),
            listener: UnixListener::bind(&path).expect("bind"),
        };
        let started = Instant::now();
        let serving = tokio::spawn(serve_listener(
            source,
            Arc::new(Semaphore::new(1)),
            "test",
            |_: &UnixStream| true,
            |mut stream: UnixStream, permit| async move {
                let _permit = permit;
                let _ = stream.write_all(b"served").await;
            },
        ));
        let mut client = UnixStream::connect(&path).await.expect("connect");
        let mut reply = [0_u8; 6];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("served after the injected accept errors")
            .expect("reply");
        assert_eq!(&reply, b"served");
        assert!(started.elapsed() >= ACCEPT_BACKOFF * 3);
        assert!(!serving.is_finished(), "an accept error ended the listener");
        serving.abort();
    }

    #[tokio::test]
    async fn a_full_listener_closes_new_connections_while_a_separate_capacity_still_serves() {
        let directory = tempfile::tempdir().expect("socket directory");
        let app_path = directory.path().join("app.sock");
        let admin_path = directory.path().join("admin.sock");
        let release = Arc::new(Notify::new());
        let held = Arc::new(AtomicUsize::new(0));
        let app = {
            let release = Arc::clone(&release);
            let held = Arc::clone(&held);
            tokio::spawn(serve_listener(
                UnixListener::bind(&app_path).expect("bind app"),
                Arc::new(Semaphore::new(2)),
                "app",
                |_: &UnixStream| true,
                move |stream: UnixStream, permit| {
                    let release = Arc::clone(&release);
                    let held = Arc::clone(&held);
                    async move {
                        let _permit = permit;
                        held.fetch_add(1, Ordering::SeqCst);
                        release.notified().await;
                        drop(stream);
                    }
                },
            ))
        };
        let admin = tokio::spawn(serve_listener(
            UnixListener::bind(&admin_path).expect("bind admin"),
            Arc::new(Semaphore::new(1)),
            "admin",
            |_: &UnixStream| true,
            |mut stream: UnixStream, permit| async move {
                let _permit = permit;
                let _ = stream.write_all(b"admin").await;
            },
        ));

        let _first = UnixStream::connect(&app_path).await.expect("first");
        let _second = UnixStream::connect(&app_path).await.expect("second");
        let deadline = Instant::now() + Duration::from_secs(5);
        while held.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "sessions were not admitted");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut past_capacity = UnixStream::connect(&app_path).await.expect("third");
        assert!(closed_without_response(&mut past_capacity).await);

        let mut operator = UnixStream::connect(&admin_path).await.expect("admin");
        let mut reply = [0_u8; 5];
        timeout(Duration::from_secs(5), operator.read_exact(&mut reply))
            .await
            .expect("admin answered while the app listener was full")
            .expect("reply");
        assert_eq!(&reply, b"admin");

        release.notify_waiters();
        app.abort();
        admin.abort();
    }

    #[tokio::test]
    async fn a_refused_peer_never_takes_a_permit() {
        let directory = tempfile::tempdir().expect("socket directory");
        let path = directory.path().join("admin.sock");
        let admitted = Arc::new(AtomicUsize::new(0));
        let serving = {
            let admitted = Arc::clone(&admitted);
            tokio::spawn(serve_listener(
                UnixListener::bind(&path).expect("bind"),
                Arc::new(Semaphore::new(1)),
                "admin",
                move |_: &UnixStream| admitted.fetch_add(1, Ordering::SeqCst) >= 3,
                |mut stream: UnixStream, permit| async move {
                    let _permit = permit;
                    let _ = stream.write_all(b"ok").await;
                },
            ))
        };
        for _ in 0..3 {
            let mut refused = UnixStream::connect(&path).await.expect("connect");
            assert!(closed_without_response(&mut refused).await);
        }
        let mut accepted = UnixStream::connect(&path).await.expect("connect");
        let mut reply = [0_u8; 2];
        timeout(Duration::from_secs(5), accepted.read_exact(&mut reply))
            .await
            .expect("the single permit was still free")
            .expect("reply");
        assert_eq!(&reply, b"ok");
        serving.abort();
    }
}
