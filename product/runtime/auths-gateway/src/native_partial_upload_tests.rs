//! Real TCP relay drops a request after forwarding one approved body byte.
//! The destination observes a partial request; no provider atomicity or kernel
//! backpressure claim is inferred from that application-level observation.
use super::*;
use std::net::TcpStream;

fn socket(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read deadline");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write deadline");
}

fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16_384);
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("header");
        bytes.push(byte[0]);
    }
    bytes
}

fn one(backend: Backend, flavor: Flavor) -> Value {
    let mut case = Case::new(backend, flavor, Point::DuringResponse, ResumeGate::Current);
    let destination = TcpListener::bind("127.0.0.1:0").expect("destination");
    let destination_port = destination.local_addr().expect("port").port();
    let listener = TcpListener::bind("127.0.0.1:0").expect("relay");
    case.setup.installation.provider_port = listener.local_addr().expect("port").port();
    let expected = case.authorization.request.body.clone();
    assert!(expected.len() > 1);
    let destination_task = thread::spawn(move || {
        let (mut stream, _) = destination.accept().expect("provider accept");
        socket(&stream);
        let head = header(&mut stream);
        let text = std::str::from_utf8(&head).expect("HTTP");
        assert_eq!(text.lines().next(), Some(flavor.request_line()));
        let length = text
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>().expect("length"))
            })
            .expect("content length");
        assert_eq!(length, expected.len());
        let mut received = Vec::new();
        stream.take(16_385).read_to_end(&mut received).expect("EOF");
        assert_eq!(received, expected[..1]);
        (length, received.len())
    });
    let pause_port = case.setup.installation.barrier_port;
    let relay_task = thread::spawn(move || {
        let (mut incoming, _) = listener.accept().expect("relay accept");
        socket(&incoming);
        let mut outgoing =
            TcpStream::connect(("127.0.0.1", destination_port)).expect("destination connect");
        socket(&outgoing);
        let head = header(&mut incoming);
        outgoing.write_all(&head).expect("forward header");
        let mut first = [0];
        incoming
            .read_exact(&mut first)
            .expect("approved body prefix");
        outgoing.write_all(&first).expect("forward one body byte");
        pause_at(pause_port);
        // Drop both sockets without forwarding any buffered remainder.
    });
    let input = case
        .setup
        .installation
        .root
        .join("partial-upload-input.json");
    private(&input, &serde_json::to_vec(&case.setup).expect("setup"));
    let mut peer = Peer::start(
        &input,
        "native_mutation_crash_tests::native_mutation_crash_peer",
        ENVIRONMENT,
    );
    let mut paused = peer.await_pause(&case.listener);
    assert!(
        !case
            .setup
            .installation
            .root
            .join("caller-result.json")
            .exists()
    );
    peer.kill();
    paused
        .write_all(b"G")
        .expect("drop connection after SIGKILL");
    relay_task.join().expect("relay");
    let (declared, received) = destination_task.join().expect("destination");
    let before = case.raw().expect("durable grant");
    assert_eq!(
        PausedStore::phase_for(CrashProtocol::Mutation, OPERATION, &before),
        "entry-granted"
    );
    let slots = case.slots(true);
    let engine = case.reopened_engine();
    let witness = engine.execution_witness();
    for _ in 0..2 {
        assert_eq!(
            case.runtime
                .block_on(submit(&engine, &case.setup.installation.root)),
            GatewaySubmitResult::Unknown
        );
    }
    assert_eq!(
        engine.execution_witness(),
        witness,
        "partial upload never authorizes another entry"
    );
    assert_eq!(case.raw().expect("retained"), before);
    assert_eq!(case.slots(true), slots);
    assert_eq!(
        case.provider.calls(),
        0,
        "the unused complete-request double received no request"
    );
    json!({"recipe":flavor.label(),"sigkill_during_request":true,"destination_connections":1,
        "declared_native_body_bytes":declared,"destination_consumed_body_bytes":received,
        "exact_approved_prefix":true,"complete_destination_requests":0,
        "reopened_result":"unknown","retained_charges_and_journal_unchanged":true,"replay_has_no_custody_or_transport":true})
}

fn matrix(backend: Backend) {
    let cases = [Flavor::Airtable, Flavor::StripePlain].map(|flavor| one(backend, flavor));
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.native-partial-upload/1","adapter":backend.label(),
        "scope":"real gateway worker, approved request, TCP relay/destination, SIGKILL, maintained durable store",
        "excluded":["kernel backpressure","provider atomicity or known non-effect","power loss","live provider qualification"],"cases":cases})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-partial-upload-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}

#[test]
fn native_file_partial_upload_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires maintained TLS PostgreSQL fixture"]
fn postgres_native_partial_upload_fixture_is_current() {
    assert!(postgres_configured(), "TLS PostgreSQL fixture is required");
    matrix(Backend::Postgres);
}
