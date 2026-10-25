//! Independent HTTP/1 wire oracle for the actual pinned client policy.
//!
//! A local TLS peer parses raw request bytes without reqwest, URL, HTTP or
//! Auths rendering helpers. Only DNS admission and certificate trust are
//! replaced: an explicit local socket and a fresh test-only root. Production
//! HTTPS-only, pinning, timeout, redirect and retry settings are shared.
//! These tests do not establish verifier soundness, provider interpretation,
//! OS isolation, or the protocol behavior of a different enabled HTTP stack.

use super::*;
use auths_connections::{
    ConnectionAlias, ConnectionId, ConnectionProfile, ConnectionRecord, ConnectionState,
    CredentialReferenceCommitment, ProviderKind, SemanticId,
};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    thread::{self, JoinHandle},
};

const HOST: &str = "wire.auths.invalid";
const SECRET: &[u8] = b"synthetic-wire-oracle-secret";
const LOCK: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");

#[derive(Debug)]
struct WireRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl WireRequest {
    fn values(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(key, _)| key == name).map(|(_, value)| value.as_str()).collect()
    }
}

#[derive(Clone, Copy)]
enum Reply { Json, Redirect, Close }
#[derive(Default, Debug)]
struct Transcript { requests: Vec<WireRequest>, tls_refusals: usize }

struct WireServer {
    port: u16,
    certificate: reqwest::Certificate,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<Transcript>>,
}
impl Drop for WireServer {
    fn drop(&mut self) { self.stopped.store(true, Ordering::SeqCst); }
}
impl WireServer {
    fn start(replies: Vec<Reply>) -> Self {
        let generated = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
        let certificate = reqwest::Certificate::from_der(generated.cert.der()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![generated.cert.der().clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()).into()).unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let thread = thread::spawn(move || {
            let mut transcript = Transcript::default();
            let started = Instant::now();
            let mut last = started;
            while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(8) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                        let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                        let mut tls = rustls::StreamOwned::new(connection, socket);
                        let mut handshake_ok = true;
                        while tls.conn.is_handshaking() {
                            if tls.conn.complete_io(&mut tls.sock).is_err() { handshake_ok = false; break; }
                        }
                        if !handshake_ok {
                            transcript.tls_refusals += 1;
                            last = Instant::now();
                            continue;
                        }
                        let request = read_request(&mut tls);
                        let reply = replies.get(transcript.requests.len()).copied().unwrap_or(Reply::Json);
                        transcript.requests.push(request);
                        match reply {
                            Reply::Close => {}
                            Reply::Json => {
                                tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").unwrap();
                                tls.flush().unwrap();
                            }
                            Reply::Redirect => {
                                let response = format!("HTTP/1.1 307 Temporary Redirect\r\nlocation: https://{HOST}:{port}/redirected\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                                tls.write_all(response.as_bytes()).unwrap();
                                tls.flush().unwrap();
                            }
                        }
                        last = Instant::now();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        let entered = transcript.requests.len() + transcript.tls_refusals;
                        if entered >= replies.len() && last.elapsed() > Duration::from_millis(250) { break; }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("wire oracle accept: {error}"),
                }
            }
            transcript
        });
        Self { port, certificate, stopped, thread: Some(thread) }
    }

    fn transport(&self, recipe: &CompiledRecipe, hostname: &str, trust_root: bool) -> GatewayHttpTransport {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
        let builder = pinned_client_builder(hostname, socket);
        let builder = if trust_root { builder.add_root_certificate(self.certificate.clone()) } else { builder };
        GatewayHttpTransport {
            client: builder.build().unwrap(),
            approved_namespace: recipe.namespace().as_str().to_owned(),
            approved_recipe_digest: *recipe.digest(),
            origin: recipe.review().origin().to_owned(),
            target_origin: format!("https://{hostname}:{}", self.port),
            requirement: recipe.review().credential().clone(),
            required_versions: recipe.required_response_versions(),
            witness: None,
        }
    }
    fn finish(mut self) -> Transcript { self.thread.take().unwrap().join().expect("wire oracle") }
}

fn read_request(tls: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>) -> WireRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let end = loop {
        let read = tls.read(&mut buffer).expect("wire head");
        assert!(read > 0, "incomplete wire head");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 131_072, "wire head bound");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break end; }
    };
    let head = std::str::from_utf8(&bytes[..end]).expect("ASCII request head");
    let mut lines = head.split("\r\n");
    let request_line: Vec<_> = lines.next().unwrap().split(' ').collect();
    assert_eq!(request_line.len(), 3);
    assert_eq!(request_line[2], "HTTP/1.1");
    let method = request_line[0].to_owned();
    let target = request_line[1].to_owned();
    let headers: Vec<_> = lines.map(|line| {
        let (key, value) = line.split_once(':').expect("wire header separator");
        (key.to_ascii_lowercase(), value.trim_matches([' ', '\t']).to_owned())
    }).collect();
    let lengths: Vec<_> = headers.iter().filter(|(key, _)| key == "content-length").collect();
    assert!(lengths.len() <= 1, "ambiguous wire content length");
    assert!(!headers.iter().any(|(key, _)| key == "transfer-encoding"), "unexpected chunked body");
    let length = lengths.first().map_or(0, |(_, value)| value.parse::<usize>().expect("wire content length"));
    assert!(length <= 1_048_576, "wire body bound");
    while bytes.len() < end + 4 + length {
        let read = tls.read(&mut buffer).expect("wire body");
        assert!(read > 0, "incomplete wire body");
        bytes.extend_from_slice(&buffer[..read]);
    }
    assert_eq!(bytes.len(), end + 4 + length, "unexpected pipelined bytes");
    WireRequest { method, target, headers, body: bytes[end + 4..].to_vec() }
}

fn source() -> Value {
    serde_json::from_slice(include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json")).unwrap()
}
fn recipe() -> CompiledRecipe {
    let mut source = source();
    source["write"]["body"]["value"]["fields"]["wire_text"] =
        json!({"kind":"string", "value":"quote\" slash\\ newline\n control\u{0001} é 😀"});
    source["write"]["idempotency"] = json!({"kind":"derived-header", "retention_seconds":86_400});
    CompiledRecipe::compile(&serde_json::to_vec(&source).unwrap(), LOCK).unwrap()
}
fn request(recipe: &CompiledRecipe) -> ClosedProviderRequest {
    let arguments = json!({"operation_id":"wire-operation", "record_id":"recTEST0000000001",
        "replacement":"Approved", "operator_namespace":recipe.namespace().as_str(), "recipe_digest":recipe.digest_hex()});
    recipe.closed_request_from_arguments(arguments.as_object().unwrap(), [0x51; 32]).unwrap()
}
fn lease() -> StoredSecretLease {
    let id = ConnectionId::generate().unwrap();
    let generation = std::num::NonZeroU64::MIN;
    let commitment = CredentialReferenceCommitment::of(&id, generation, SECRET);
    let profile = ConnectionProfile::new(SemanticId::parse("auths.mcp").unwrap(), 2).unwrap();
    let record = ConnectionRecord::new(
        ProviderKind::parse("airtable").unwrap(),
        ConnectionAlias::parse("wire").unwrap(),
        id,
        SemanticId::parse("auths.gateway-operation/1").unwrap(),
        SemanticId::parse("auths.gateway-connection-descriptor/1").unwrap(),
        b"{}".to_vec(),
        [0; 32],
        *commitment.as_bytes(),
        generation,
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![profile],
        1,
        1,
        None,
    ).unwrap();
    StoredSecretLease::from_store(
        &record.credential_binding(),
        Zeroizing::new(SECRET.to_vec()),
        Instant::now() + Duration::from_secs(30),
    ).unwrap()
}

#[tokio::test]
async fn a_failed_final_entry_gate_dispatches_no_tls_or_http_and_records_no_entry() {
    let recipe = recipe();
    let request = request(&recipe);
    let server = WireServer::start(Vec::new());
    let witness = Arc::new(crate::execution_witness::ExecutionWitness::new().unwrap());
    let transport = server.transport(&recipe, HOST, true).with_witness(Arc::clone(&witness));
    let before = witness.snapshot();
    let gate_calls = std::sync::atomic::AtomicUsize::new(0);
    let result = transport.write(&request, &lease(), || {
        gate_calls.fetch_add(1, Ordering::SeqCst);
        false
    }).await;
    assert_eq!(result, Err(GatewayTransportError::EntryDeadline));
    assert_eq!(gate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(witness.snapshot(), before);
    let transcript = server.finish();
    assert!(transcript.requests.is_empty());
    assert_eq!(transcript.tls_refusals, 0);
}

#[tokio::test]
async fn tls_wire_preserves_the_closed_tuple_and_unique_transport_headers() {
    let recipe = recipe();
    let request = request(&recipe);
    let server = WireServer::start(vec![Reply::Json]);
    let port = server.port;
    let transport = server.transport(&recipe, HOST, true);
    assert!(matches!(transport.write(&request, &lease(), || true).await,
        Ok(WriteTransportOutcome::ResponseRecorded { status: 200, .. })));
    let transcript = server.finish();
    assert_eq!(transcript.tls_refusals, 0);
    assert_eq!(transcript.requests.len(), 1);
    let wire = &transcript.requests[0];
    assert_eq!(wire.method, "PATCH");
    assert_eq!(wire.target, "/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001");
    assert_eq!(wire.body, request.body());
    let document: Value = serde_json::from_slice(&wire.body).unwrap();
    assert_eq!(document["fields"]["DemoStatus"], "Approved");
    assert_eq!(document["wire_text"], "quote\" slash\\ newline\n control\u{0001} é 😀");
    assert_eq!(wire.values("authorization"), vec!["Bearer synthetic-wire-oracle-secret"]);
    assert_eq!(wire.values("content-type"), vec!["application/json"]);
    assert_eq!(wire.values("accept"), vec!["application/json"]);
    let expected_host = format!("{HOST}:{port}");
    let expected_length = wire.body.len().to_string();
    assert_eq!(wire.values("host"), vec![expected_host.as_str()]);
    assert_eq!(wire.values("content-length"), vec![expected_length.as_str()]);
    let mut expected_names: std::collections::BTreeSet<_> =
        ["accept", "authorization", "content-type", "content-length", "host"]
            .into_iter().map(str::to_owned).collect();
    for header in request.headers() {
        let name = header.name().to_ascii_lowercase();
        assert_eq!(wire.values(&name), vec![header.value()]);
        expected_names.insert(name);
    }
    let actual_names: std::collections::BTreeSet<_> = wire.headers.iter().map(|(name, _)| name.clone()).collect();
    assert_eq!(wire.headers.len(), actual_names.len(), "no repeated transport or declared header");
    assert_eq!(actual_names, expected_names, "review every default header on the pinned wire stack");
}

#[tokio::test]
async fn a_different_recipe_with_identical_wire_bytes_is_refused_before_tls_entry() {
    let installed = recipe();
    // Build the other mapping from original source, preserving every rendered
    // byte while changing an approval-bound retention rule.
    let mut changed = source();
    changed["write"]["body"]["value"]["fields"]["wire_text"] =
        json!({"kind":"string", "value":"quote\" slash\\ newline\n control\u{0001} é 😀"});
    changed["write"]["idempotency"] = json!({"kind":"derived-header", "retention_seconds":86_401});
    let other = CompiledRecipe::compile(&serde_json::to_vec(&changed).unwrap(), LOCK).unwrap();
    let original_request = request(&installed);
    let supplied = request(&other);
    assert_ne!(original_request.recipe_digest(), supplied.recipe_digest());
    assert_eq!(original_request.namespace(), supplied.namespace());
    assert_eq!(original_request.method(), supplied.method());
    assert_eq!(original_request.url(), supplied.url());
    assert_eq!(original_request.content_type(), supplied.content_type());
    assert_eq!(original_request.body(), supplied.body());
    assert_eq!(original_request.headers(), supplied.headers());
    let server = WireServer::start(Vec::new());
    let transport = server.transport(&installed, HOST, true);
    assert!(matches!(transport.write(&supplied, &lease(), || true).await, Err(GatewayTransportError::NotEntered)));
    let transcript = server.finish();
    assert!(transcript.requests.is_empty());
    assert_eq!(transcript.tls_refusals, 0);
}

#[tokio::test]
async fn percent_escapes_are_verbatim_and_normalized_targets_never_enter() {
    let recipe = recipe();
    let accepted = ["/v1/a%2Fb", "/v1/a%2fb", "/v1/a%252Fb", "/v1/%E2%82%AC", "/v1/a%3Fb%23c"];
    let server = WireServer::start(vec![Reply::Json; accepted.len()]);
    let transport = server.transport(&recipe, HOST, true);
    for path in ["/v1/../other", "/v1/./other", "/v1/%2e%2e/other", "/v1/%2E/other", "/v1/a\\b", "/v1/space here", "/v1/é", "/v1/\ttrimmed"] {
        let url = format!("{}{path}", recipe.review().origin());
        assert!(!transport.owns_url(&url), "non-verbatim target {path:?}");
        assert!(transport.read(reqwest::Method::GET, &url, &[], 1024, SECRET).await.is_none());
    }
    for path in accepted {
        let url = format!("{}{path}", recipe.review().origin());
        assert!(transport.read(reqwest::Method::GET, &url, &[], 1024, SECRET).await.is_some());
    }
    let transcript = server.finish();
    assert_eq!(transcript.tls_refusals, 0);
    assert_eq!(transcript.requests.len(), accepted.len());
    for (wire, expected) in transcript.requests.iter().zip(accepted) {
        assert_eq!(wire.method, "GET");
        assert_eq!(wire.target, expected);
        assert!(wire.body.is_empty());
    }
}

#[tokio::test]
async fn redirects_and_ambiguous_disconnects_never_issue_a_second_write() {
    for reply in [Reply::Redirect, Reply::Close] {
        let recipe = recipe();
        let server = WireServer::start(vec![reply]);
        let transport = server.transport(&recipe, HOST, true);
        let result = transport.write(&request(&recipe), &lease(), || true).await;
        match reply {
            Reply::Redirect => assert!(matches!(result, Ok(WriteTransportOutcome::ResponseRecorded { status: 307, .. }))),
            Reply::Close => assert!(matches!(result, Ok(WriteTransportOutcome::Unknown))),
            Reply::Json => unreachable!(),
        }
        let transcript = server.finish();
        assert_eq!(transcript.tls_refusals, 0);
        assert_eq!(transcript.requests.len(), 1, "one provider entry despite redirect or unknown result");
    }
}

#[tokio::test]
async fn certificate_trust_hostname_and_https_only_policy_precede_http_bytes() {
    for (hostname, trusted) in [(HOST, false), ("wrong.auths.invalid", true)] {
        let recipe = recipe();
        let server = WireServer::start(vec![Reply::Json]);
        let transport = server.transport(&recipe, hostname, trusted);
        assert!(matches!(transport.write(&request(&recipe), &lease(), || true).await, Ok(WriteTransportOutcome::Unknown)));
        let transcript = server.finish();
        assert!(transcript.requests.is_empty(), "TLS refusal must expose no HTTP credential or body");
        assert!(transcript.tls_refusals >= 1);
    }
    let recipe = recipe();
    let server = WireServer::start(Vec::new());
    let transport = server.transport(&recipe, HOST, true);
    assert!(transport.client.get(format!("http://{HOST}:{}/plaintext", server.port)).send().await.is_err());
    let transcript = server.finish();
    assert!(transcript.requests.is_empty());
    assert_eq!(transcript.tls_refusals, 0, "HTTPS-only refusal precedes opening the socket");
}

#[test]
fn recipe_headers_cannot_shadow_transport_owned_fields() {
    for name in ["Authorization", "Content-Type", "Content-Length", "Host", "Accept", "Idempotency-Key"] {
        let mut source = source();
        source["provider_headers"] = Value::Object(serde_json::Map::from_iter([
            (name.to_owned(), Value::String("shadow".to_owned())),
        ]));
        assert!(CompiledRecipe::compile(&serde_json::to_vec(&source).unwrap(), LOCK).is_err(), "reserved header {name}");
    }
}
