// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Responsible for: external HTTP fixture, authored-byte, refusal, and CLI controls.
//! NOT responsible for: endpoint parsing, TLS setup, or production socket exchange logic.
//! Upstream: the external endpoint transport. Downstream: loopback peers and isolated case fixtures.

use super::*;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use crate::cli::{self, exit};
use crate::sut::{Profile, Sut, Transport};

fn responding_server(response: &'static [u8]) -> (String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener.set_nonblocking(true).expect("bound accept wait");
    let address = listener.local_addr().expect("listener address");
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept client before deadline: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking request reads");
        let request = read_complete_request(&mut stream);
        stream.write_all(response).expect("write response");
        request
    });
    (format!("http://{address}"), handle)
}

fn read_complete_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set request deadline");
    let mut request = Vec::new();
    loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).expect("read request");
        assert_ne!(read, 0, "request ended before its framing completed");
        request.extend_from_slice(&chunk[..read]);
        let Some(head_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        else {
            continue;
        };
        let head = std::str::from_utf8(&request[..head_end]).expect("request head is UTF-8");
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("numeric content length"))
            })
            .unwrap_or(0);
        if request.len() >= head_end + length {
            return request;
        }
    }
}

fn empty_wire() -> crate::inprocess::Wire {
    crate::inprocess::Wire {
        method: "GET".to_owned(),
        target: "/".to_owned(),
        headers: Vec::new(),
        raw_head: None,
        h2_frames: false,
        http_version: None,
        body: Vec::new(),
        frames: Vec::new(),
        steps: Vec::new(),
        sign: None,
    }
}

fn execute_response_result(response: &'static [u8]) -> Result<super::super::exchange::SocketExchangeResult, SutError> {
    let (url, server) = responding_server(response);
    let endpoint = ExternalEndpoint::parse(&url).expect("local endpoint");
    let mut connection = endpoint
        .open(Instant::now() + Duration::from_secs(2))
        .expect("connect client");
    let wire = empty_wire();
    let head = Head {
        bytes: format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", endpoint.authority()).into_bytes(),
        declared_length: 0,
    };
    let started = Instant::now();
    let result = execute_socket_exchange(&mut connection, &wire, &head, started, started + Duration::from_secs(2), true);
    let _ = server.join().expect("server exits");
    result
}

fn execute_response(response: &'static [u8]) -> Result<Observation, SutError> {
    execute_response_result(response).map(|result| result.observation)
}

fn write_case(root: &Path, id: &str, polarity: &str, status: u16) {
    let case = format!(
        r#"[case]
id = "{id}"
schema_version = 1
title = "External endpoint command control"
rationale = "This isolated corpus proves the command reaches the supplied socket and judges the response instead of silently selecting a local target."
polarity = "{polarity}"
operation = "PutObject"
tags = ["external-endpoint"]
timeout_ms = 2000
quirks = []

[[case.evidence]]
url = "https://www.rfc-editor.org/rfc/rfc9112"
summary = "HTTP/1.1 messages travel as a request and response over a transport connection."
kind = "rfc"

[request]
method = "PUT"
target = "/external/command"

[[request.chunks]]
utf8 = "cli-body"

[expect]
kind = "response"
status = {status}
"#
    );
    fs::write(root.join("cases/external").join(format!("{id}.toml")), case).expect("write case");
}

struct TestCorpus(std::path::PathBuf);

impl TestCorpus {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestCorpus {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn isolated_corpus() -> TestCorpus {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "rustfs-gateway-external-corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("cases/external")).expect("create cases directory");
    let repository = crate::corpus::Corpus::discover_root().expect("repository corpus");
    fs::copy(repository.join("case.schema.json"), root.join("case.schema.json")).expect("copy frozen schema");
    write_case(&root, "c-external-0001", "positive", 204);
    write_case(&root, "c-external-n001", "negative", 400);
    write_case(&root, "c-external-n002", "negative", 403);
    TestCorpus(root)
}

fn cli_args(root: &Path, endpoint: &str) -> Vec<String> {
    [
        "run".to_owned(),
        "--root".to_owned(),
        root.display().to_string(),
        "--filter".to_owned(),
        "c-external-0001".to_owned(),
        "--endpoint".to_owned(),
        endpoint.to_owned(),
    ]
    .into_iter()
    .collect()
}

#[test]
fn observes_a_real_external_http_response_without_inventing_request_progress() {
    let observation = execute_response(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").expect("valid response");

    assert_eq!(observation.status, Some(204));
    assert_eq!(observation.request_body_bytes_sent_at_response, None);
    assert_eq!(observation.ttfb_ms, None);
}

#[test]
fn response_connection_close_marks_the_external_socket_for_discard() {
    let result = execute_response_result(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").expect("valid close response");

    assert!(result.torn_down);
}

#[test]
fn unsigned_raw_head_preserves_bytes_and_reports_a_truncated_body_as_not_fully_sent() {
    let raw = b"PUT /raw HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n".to_vec();
    let expected_request = [raw.as_slice(), b"part"].concat();
    let request_len = expected_request.len();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set request deadline");
        // Consume the four authored body bytes, not the declared five, before closing.
        let mut captured = vec![0; request_len];
        stream.read_exact(&mut captured).expect("read the authored request bytes");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .expect("write response");
        captured
    });
    let mut connection = Connection::open(address).expect("connect client");
    let mut wire = empty_wire();
    wire.raw_head = Some(raw.clone());
    wire.steps.push(ChunkStep::Data(b"part".to_vec(), 0));
    let target = Conn::new(std::path::PathBuf::from("."));
    let stamp = crate::time::parse_rfc3339(crate::time::DEFAULT_FIXED).expect("fixed clock");
    let head = target.head(&wire, &stamp).expect("raw head");

    assert_eq!(head.bytes, raw, "unsigned raw-head bytes stay authored byte for byte");
    assert_eq!(head.declared_length, 5, "the authored Content-Length frames progress");

    let started = Instant::now();
    let result = execute_socket_exchange(&mut connection, &wire, &head, started, started + Duration::from_secs(2), true)
        .expect("external exchange");
    let captured = server.join().expect("server exits");

    assert_eq!(captured, expected_request, "the fixture consumes the authored bytes before closing");
    assert_eq!(result.observation.request_body_fully_sent, Some(false));
}

#[test]
fn conn_sends_the_authored_target_host_and_nonempty_body() {
    let (url, server) = responding_server(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
    let mut target = Conn::external(std::path::PathBuf::from("."), &url).expect("external target");
    target.prepare("c-external-direct-0001", None).expect("empty setup");
    let request = crate::toml::parse(
        "method = \"PUT\"\ntarget = \"/bucket/key?part=1\"\nheaders = { content-type = \"text/plain\" }\n\
             [[chunks]]\nutf8 = \"first-\"\n[[chunks]]\nutf8 = \"second\"\n",
    )
    .expect("request block");
    let plan = ExchangePlan {
        case_id: "c-external-direct-0001",
        index: 0,
        request,
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        transport: Transport::Conn,
        profile: Profile::Aws,
    };

    let observation = target.exchange(&plan).expect("external exchange");
    let captured = server.join().expect("server exits");
    let text = std::str::from_utf8(&captured).expect("captured request is UTF-8");

    assert!(text.starts_with("PUT /bucket/key?part=1 HTTP/1.1\r\n"));
    assert!(
        text.lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("host: {}", url.trim_start_matches("http://"))))
    );
    assert!(captured.ends_with(b"first-second"));
    assert_eq!(observation.status, Some(204));
    assert_eq!(observation.request_body_bytes_sent_at_response, None);
}

#[test]
fn cli_main_reaches_the_supplied_endpoint_and_judges_its_response() {
    let corpus = isolated_corpus();
    let (url, server) = responding_server(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");

    let code = cli::main(&cli_args(corpus.path(), &url));
    assert_eq!(code, ExitCode::from(exit::SUCCESS));

    let captured = server.join().expect("server exits");
    assert!(captured.ends_with(b"cli-body"));
}

#[test]
fn cli_main_maps_refused_connection_to_environment() {
    let corpus = isolated_corpus();
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve address");
    let address = listener.local_addr().expect("reserved address");
    drop(listener);

    let code = cli::main(&cli_args(corpus.path(), &format!("http://{address}")));

    assert_eq!(code, ExitCode::from(exit::ENVIRONMENT));
}

#[test]
fn cli_main_maps_malformed_response_to_environment() {
    let corpus = isolated_corpus();
    let (url, server) = responding_server(b"not-http\r\n\r\n");

    let code = cli::main(&cli_args(corpus.path(), &url));
    let _ = server.join().expect("server exits");

    assert_eq!(code, ExitCode::from(exit::ENVIRONMENT));
}

#[test]
fn malformed_external_response_fails_closed_as_environment() {
    let error = execute_response(b"not-http\r\n\r\n").expect_err("malformed response is not a reset");

    assert!(error.to_string().contains("complete HTTP/1.1 response"));
}

#[test]
fn non_http_status_line_fails_closed_as_environment() {
    let error = execute_response(b"NOTHTTP 204 OK\r\n\r\n").expect_err("protocol token is not HTTP/1.1");

    assert!(error.to_string().contains("complete HTTP/1.1 response"));
}

#[test]
fn invalid_content_length_fails_closed_as_environment() {
    let error = execute_response(b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n")
        .expect_err("invalid framing is not an empty body");

    assert!(error.to_string().contains("Content-Length is invalid"));
}

#[test]
fn truncated_fixed_length_body_fails_closed_as_environment() {
    let error = execute_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npart").expect_err("partial body is not complete");

    assert!(error.to_string().contains("before the response completed"));
}

#[test]
fn unsupported_transfer_framing_fails_closed_as_environment() {
    let error = execute_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody")
        .expect_err("unsupported transfer coding is not a framed response");

    assert!(error.to_string().contains("not terminated by chunked framing"));
}

#[test]
fn stacked_transfer_coding_fails_closed_until_it_can_be_decoded() {
    let error = execute_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n")
        .expect_err("undecoded gzip bytes are not a response body");

    assert!(error.to_string().contains("single chunked coding"));
}

#[test]
fn surplus_fixed_length_bytes_fail_closed_before_reuse() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let _ = read_complete_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
            .expect("write framed response");
        thread::sleep(Duration::from_millis(25));
        stream.write_all(b"x").expect("write later surplus");
    });
    let mut connection = Connection::open(address).expect("connect client");
    let wire = empty_wire();
    let head = Head {
        bytes: b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        declared_length: 0,
    };
    let started = Instant::now();
    let error = execute_socket_exchange(&mut connection, &wire, &head, started, started + Duration::from_secs(2), true)
        .err()
        .expect("segmented surplus byte must not be discarded");
    server.join().expect("server exits");

    assert!(error.to_string().contains("bytes after the framed response body"));
}

#[test]
fn surplus_chunked_bytes_fail_closed_before_reuse() {
    let error = execute_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\nx")
        .expect_err("surplus byte must not be discarded");

    assert!(error.to_string().contains("bytes after the framed response body"));
}

#[test]
fn informational_response_fails_closed_before_connection_reuse() {
    let error = execute_response(b"HTTP/1.1 100 Continue\r\n\r\n").expect_err("100 is not a final response");

    assert!(error.to_string().contains("informational status 100"));
}

#[test]
fn close_delimited_response_fails_closed_instead_of_reporting_an_empty_body() {
    let error = execute_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
        .expect_err("close-delimited response is unsupported");

    assert!(error.to_string().contains("close-delimited response body"));
}

#[test]
fn cleartext_delays_are_accepted_but_tls_delays_and_controls_fail_closed() {
    let mut delayed = empty_wire();
    delayed.steps.push(ChunkStep::Data(b"late".to_vec(), 1));
    validate_authored_steps(&delayed, true, Duration::from_secs(1)).expect("cleartext can observe response bytes");
    let tls_error = validate_authored_steps(&delayed, false, Duration::from_secs(1))
        .expect_err("TLS record readiness is not an HTTP response observation");

    let mut controlled = empty_wire();
    controlled.steps.push(ChunkStep::Control {
        action: "stall".to_owned(),
        delay_ms: 0,
        duration_ms: 1,
    });
    let control_error = validate_authored_steps(&controlled, true, Duration::from_secs(1))
        .expect_err("control needs concurrent response observation");

    assert!(tls_error.to_string().contains("encrypted socket readiness"));
    assert!(control_error.to_string().contains("concurrent response observation"));
}

#[test]
fn early_response_during_declared_delay_stops_the_request_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener.set_nonblocking(true).expect("bounded accept wait");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(500);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Vec::new(),
                Err(error) => panic!("accept client before deadline: {error}"),
            }
        };
        // An accepted socket inherits the listener's non-blocking flag on macOS; put it back
        // into blocking mode so the read timeout below is the deadline (rustfs/gateway#684).
        stream.set_nonblocking(false).expect("blocking head read");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set head deadline");
        let mut request = Vec::new();
        let head_end = loop {
            let mut block = [0_u8; 1024];
            let read = stream.read(&mut block).expect("read request head");
            assert_ne!(read, 0, "request ended before its head completed");
            request.extend_from_slice(&block[..read]);
            if let Some(end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
            {
                break end;
            }
        };
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .expect("write early response");
        stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set body observation window");
        let mut body = request.split_off(head_end);
        loop {
            let mut block = [0_u8; 64];
            match stream.read(&mut block) {
                Ok(0) => break,
                Ok(read) => body.extend_from_slice(&block[..read]),
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    break;
                }
                Err(error) => panic!("observe body bytes: {error}"),
            }
        }
        body
    });
    let mut target = Conn::external(std::path::PathBuf::from("."), &format!("http://{address}")).expect("external target");
    target.prepare("c-external-paced-0001", None).expect("empty setup");
    let request = crate::toml::parse(
        "method = \"PUT\"\ntarget = \"/bucket/key\"\nheaders = { content-length = \"4\" }\n\
             [[chunks]]\nraw_utf8 = \"late\"\ndelay_ms = 200\n",
    )
    .expect("delayed request block");
    let plan = ExchangePlan {
        case_id: "c-external-paced-0001",
        index: 0,
        request,
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        transport: Transport::Conn,
        profile: Profile::Aws,
    };

    let result = target.exchange(&plan);
    let body = server.join().expect("server exits");
    let observation = result.expect("early response is observable during the delay");

    assert_eq!(observation.status, Some(403));
    assert_eq!(observation.request_body_bytes_sent_at_response, Some(0));
    assert_eq!(observation.request_body_fully_sent, Some(false));
    assert!(body.is_empty(), "body transmission stopped after the response");
    assert!(target.connection.is_none(), "an unfinished request connection is not reusable");
}

#[test]
fn delayed_https_body_is_rejected_before_connecting_to_the_external_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener.set_nonblocking(true).expect("nonblocking listener");
    let address = listener.local_addr().expect("listener address");
    let mut target = Conn::external(std::path::PathBuf::from("."), &format!("https://{address}")).expect("external target");
    target.prepare("c-external-direct-n001", None).expect("empty setup");
    let request =
        crate::toml::parse("method = \"PUT\"\ntarget = \"/bucket/key\"\n[[chunks]]\nraw_utf8 = \"late\"\ndelay_ms = 1\n")
            .expect("delayed request block");
    let plan = ExchangePlan {
        case_id: "c-external-direct-n001",
        index: 0,
        request,
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        transport: Transport::Conn,
        profile: Profile::Aws,
    };

    let error = target.exchange(&plan).expect_err("paced HTTPS body is unsupported");

    assert!(error.to_string().contains("encrypted socket readiness"));
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected accept error: {error}"),
        Ok(_) => panic!("external target connected before rejecting the paced body"),
    }
}

#[test]
fn body_delay_beyond_the_exchange_budget_fails_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener.set_nonblocking(true).expect("nonblocking listener");
    let address = listener.local_addr().expect("listener address");
    let mut target = Conn::external(std::path::PathBuf::from("."), &format!("http://{address}")).expect("external target");
    target.prepare("c-external-direct-n002", None).expect("empty setup");
    let request =
        crate::toml::parse("method = \"PUT\"\ntarget = \"/bucket/key\"\n[[chunks]]\nraw_utf8 = \"late\"\ndelay_ms = 2\n")
            .expect("delayed request block");
    let plan = ExchangePlan {
        case_id: "c-external-direct-n002",
        index: 0,
        request,
        clock: None,
        connection: None,
        timeout_ms: Some(1),
        transport: Transport::Conn,
        profile: Profile::Aws,
    };

    let error = target.exchange(&plan).expect_err("delay exceeds the exchange budget");

    assert!(error.to_string().contains("exceeds the exchange timeout"));
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected accept error: {error}"),
        Ok(_) => panic!("external target connected before rejecting the over-budget delay"),
    }
}

#[test]
fn reports_connection_refusal_as_an_environment_error() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve address");
    let address = listener.local_addr().expect("reserved address");
    drop(listener);
    let endpoint = ExternalEndpoint::parse(&format!("http://{address}")).expect("local endpoint");

    let error = match endpoint.open(Instant::now() + Duration::from_secs(1)) {
        Ok(_) => panic!("nothing is listening"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("connect"));
}
