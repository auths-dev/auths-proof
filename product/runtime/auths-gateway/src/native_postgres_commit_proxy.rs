//! Opaque test transport: TLS remains between the native client and `PostgreSQL`.
//! No credential, SQL statement or encrypted record is decoded or synthesized.
use std::{
    io::{Read as _, Write as _},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

struct Shared {
    stop: AtomicBool,
    hold: AtomicBool,
    withheld: AtomicU64,
    sockets: Mutex<Vec<TcpStream>>,
}
impl Shared {
    fn disconnect(&self) {
        // New connections cannot register until old sockets are closed. A
        // partially withheld TLS record cannot become an acknowledged COMMIT.
        let mut sockets = self.sockets.lock().expect("proxy sockets");
        for socket in sockets.drain(..) {
            let _ = socket.shutdown(Shutdown::Both);
        }
        self.hold.store(false, Ordering::SeqCst);
    }
}

fn forward(mut source: TcpStream, mut target: TcpStream, server_to_client: bool, shared: &Shared) {
    let mut bytes = [0; 8_192];
    while !shared.stop.load(Ordering::SeqCst) {
        let size = match source.read(&mut bytes) {
            Ok(0) => break,
            Ok(size) => size,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if server_to_client && shared.hold.load(Ordering::SeqCst) {
            shared.withheld.fetch_add(
                u64::try_from(size).expect("bounded packet"),
                Ordering::SeqCst,
            );
            continue;
        }
        if target.write_all(&bytes[..size]).is_err() {
            break;
        }
    }
    let _ = source.shutdown(Shutdown::Both);
    let _ = target.shutdown(Shutdown::Both);
}

fn attach(
    client: TcpStream,
    upstream: SocketAddr,
    shared: &Arc<Shared>,
    threads: &mut Vec<JoinHandle<()>>,
) {
    let server =
        TcpStream::connect_timeout(&upstream, Duration::from_secs(1)).expect("fixture upstream");
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("proxy poll");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("proxy deadline");
        stream.set_nodelay(true).expect("proxy latency");
    }
    {
        let mut sockets = shared.sockets.lock().expect("proxy registry");
        sockets.push(client.try_clone().expect("client control"));
        sockets.push(server.try_clone().expect("server control"));
    }
    let client_read = client.try_clone().expect("client reader");
    let server_read = server.try_clone().expect("server reader");
    let outbound = shared.clone();
    threads.push(thread::spawn(move || {
        forward(client_read, server, false, &outbound);
    }));
    let inbound = shared.clone();
    threads.push(thread::spawn(move || {
        forward(server_read, client, true, &inbound);
    }));
}

pub(super) struct Proxy {
    port: u16,
    shared: Arc<Shared>,
    service: Option<JoinHandle<()>>,
}
impl Proxy {
    pub(super) fn start(upstream_port: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("proxy listener");
        listener.set_nonblocking(true).expect("proxy polling");
        let port = listener.local_addr().expect("proxy address").port();
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            hold: AtomicBool::new(false),
            withheld: AtomicU64::new(0),
            sockets: Mutex::new(Vec::new()),
        });
        let run = shared.clone();
        let service = thread::spawn(move || {
            let mut threads = Vec::new();
            while !run.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => attach(
                        client,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, upstream_port)),
                        &run,
                        &mut threads,
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("proxy accept: {error}"),
                }
            }
            run.disconnect();
            for thread in threads {
                thread.join().expect("proxy forwarding");
            }
        });
        Self {
            port,
            shared,
            service: Some(service),
        }
    }
    pub(super) fn url(&self, original: &str) -> String {
        let mut replaced = 0;
        let parts: Vec<_> = original
            .split_ascii_whitespace()
            .map(|part| {
                if part.starts_with("port=") {
                    replaced += 1;
                    format!("port={}", self.port)
                } else {
                    part.to_owned()
                }
            })
            .collect();
        assert_eq!(
            replaced, 1,
            "the canonical fixture URL has one explicit port"
        );
        parts.join(" ")
    }
    pub(super) fn hold_replies(&self) {
        assert!(!self.shared.hold.swap(true, Ordering::SeqCst));
        assert_eq!(self.shared.withheld.load(Ordering::SeqCst), 0);
    }
    pub(super) fn wait_for_withheld_reply(&self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.shared.withheld.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "server commit reply was not observed"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
    pub(super) fn disconnect_and_resume(&self) {
        self.shared.disconnect();
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.disconnect();
        if let Some(service) = self.service.take() {
            service.join().expect("proxy service");
        }
    }
}
