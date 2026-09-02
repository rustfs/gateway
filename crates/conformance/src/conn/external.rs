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

//! External endpoint exchange over caller-selected HTTP or HTTPS.
//!
//! Responsible for: driving unpaced request steps without the loopback server's private demand
//! observer. NOT responsible for: endpoint parsing, TLS setup, HTTP/2, paced or controlled bodies,
//! remote fixture setup, request interpretation, or response judgement. Upstream: `super`;
//! downstream: `crate::cli` through [`super::Conn`].

use std::path::Path;
use std::time::{Duration, Instant};

use super::external_endpoint::ExternalEndpoint;
use super::{BodyProgress, Conn, DispatchedExchange, Head, budget_of, observe_socket_exchange, read_connection};
use crate::inprocess::{ChunkStep, InProcess};
use crate::observation::{ConnectionState, Observation};
use crate::socket::{Connection, ReadFailure};
use crate::sut::SutError;
use crate::sut::{ExchangePlan, Sut};
use crate::value::Value;

impl Conn {
    /// Builds a target that writes corpus requests to a caller-supplied HTTP(S) endpoint.
    pub fn external(root: std::path::PathBuf, endpoint: &str) -> Result<Conn, SutError> {
        Self::external_with_ca(root, endpoint, None)
    }

    /// Builds an HTTP(S) target, optionally trusting additional PEM-encoded CA certificates.
    pub fn external_with_ca(root: std::path::PathBuf, endpoint: &str, ca_path: Option<&Path>) -> Result<Conn, SutError> {
        Ok(Conn {
            inner: InProcess::new(root),
            external: Some(ExternalEndpoint::parse_with_ca(endpoint, ca_path)?),
            listener: None,
            connection: None,
            #[cfg(feature = "production-transports")]
            production: None,
            #[cfg(feature = "production-transports")]
            driver: None,
            pacer: std::sync::Arc::new(crate::socket::Pacer::new()),
        })
    }

    pub(super) fn prepare_external(
        &mut self,
        case_id: &str,
        setup: Option<&Value>,
    ) -> Result<crate::interpolate::Captures, SutError> {
        self.connection = None;
        if setup.is_some() {
            return Err(SutError::Environment(
                "external endpoint fixture setup is not implemented; refusing to run a case against undeclared remote state"
                    .to_owned(),
            ));
        }
        self.inner.prepare(case_id, None)
    }

    pub(super) fn exchange_external(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        let endpoint = self
            .external
            .clone()
            .ok_or_else(|| SutError::Environment("external exchange has no configured endpoint".to_owned()))?;
        let (fixed, request_time, _) = crate::inprocess::clock_of(plan.clock)?;
        let reuse = read_connection(plan.connection)?;
        self.inner.set_fixture_now(fixed.unix_seconds);
        let wire = self.inner.read_wire(&plan.request)?;
        if wire.h2_frames || wire.http_version.as_deref() == Some("h2") {
            return Err(SutError::Environment(
                "external endpoint HTTP/2 framing is not implemented; this target writes HTTP/1.1 bytes".to_owned(),
            ));
        }
        validate_authored_steps(&wire)?;
        let head = self.head(&wire, &request_time)?;
        let existing = self.connection.as_ref().map(Connection::observe_pending);
        if reuse && existing.is_some_and(|(_, pending)| pending) {
            self.connection = None;
            return Err(SutError::Environment(
                "external endpoint sent unframed bytes before connection reuse".to_owned(),
            ));
        }
        let fresh = !reuse || existing.is_none_or(|(state, _)| state != ConnectionState::Open);
        if fresh {
            self.connection = Some(endpoint.open()?);
        }
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| SutError::Environment("external endpoint connection was not opened".to_owned()))?;
        let result = execute_socket_exchange(connection, &wire, &head, budget_of(plan.timeout_ms))?;
        if result.torn_down || endpoint.is_tls() {
            self.connection = None;
        }
        Ok(result.observation)
    }
}

fn execute_socket_exchange(
    connection: &mut Connection,
    wire: &crate::inprocess::Wire,
    head: &Head,
    budget: Duration,
) -> Result<super::exchange::SocketExchangeResult, SutError> {
    validate_authored_steps(wire)?;
    connection.start_exchange();
    let started = Instant::now();
    let deadline = started + budget;
    connection.write(&head.bytes)?;
    let progress = write_authored_body(connection, wire, head.declared_length)?;
    let mut result = observe_socket_exchange(
        connection,
        wire,
        head,
        DispatchedExchange {
            progress,
            started,
            deadline,
        },
    );
    validate_external_response(&result, wire)?;
    result.observation.ttfb_ms = None;
    result
        .observation
        .notes
        .push("external endpoint TTFB is unavailable because this target does not instrument the first response byte".to_owned());
    if wire.raw_head.is_some() && wire.sign.is_none() {
        result.observation.request_body_fully_sent = None;
        result.observation.notes.push(
            "external unsigned raw-head framing was preserved but not interpreted, so body completion is unavailable".to_owned(),
        );
    }
    if connection_closes(&result.observation.headers)
        || crate::socket::parse_head(&head.bytes).is_some_and(|parsed| connection_closes(&parsed.headers))
    {
        result.torn_down = true;
    }
    Ok(result)
}

fn validate_authored_steps(wire: &crate::inprocess::Wire) -> Result<(), SutError> {
    for (index, step) in wire.steps.iter().enumerate() {
        match step {
            ChunkStep::Data(_, 0) => {}
            ChunkStep::Data(_, delay_ms) => {
                return Err(SutError::Environment(format!(
                    "external endpoint data step {index} declares a {delay_ms}ms delay, but this target cannot observe an early response concurrently; refusing to turn the delay into TTFB"
                )));
            }
            ChunkStep::Control { action, .. } => {
                return Err(SutError::Environment(format!(
                    "external endpoint `{action}` control is not implemented with concurrent response observation"
                )));
            }
        }
    }
    Ok(())
}

fn validate_external_response(
    result: &super::exchange::SocketExchangeResult,
    wire: &crate::inprocess::Wire,
) -> Result<(), SutError> {
    match result.read_failure.as_ref() {
        Some(ReadFailure::TimedOut | ReadFailure::Reset) => return Ok(()),
        Some(failure) => {
            return Err(SutError::Environment(format!(
                "external endpoint did not send a complete HTTP/1.1 response: {failure}"
            )));
        }
        None => {}
    }
    if result.pending_input {
        return Err(SutError::Environment(
            "external endpoint sent bytes after the framed response body".to_owned(),
        ));
    }
    let observation = &result.observation;
    let Some(status) = observation.status else {
        return Err(SutError::Environment(
            "external endpoint response completed without an observed status".to_owned(),
        ));
    };
    if (100..200).contains(&status) {
        return Err(SutError::Environment(format!(
            "external endpoint returned informational status {status}; consuming the following final response is not implemented"
        )));
    }
    let framed = observation
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding"));
    if crate::socket::carries_a_body(&wire.method, status) && !framed {
        return Err(SutError::Environment(
            "external endpoint returned a close-delimited response body; this target cannot observe it without consuming connection state"
                .to_owned(),
        ));
    }
    Ok(())
}

fn connection_closes(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}

fn write_authored_body(
    connection: &mut Connection,
    wire: &crate::inprocess::Wire,
    declared_length: u64,
) -> Result<BodyProgress, SutError> {
    let notes = vec![
        "external endpoints expose no server-side demand observer; request body bytes sent when the response existed are unavailable"
            .to_owned(),
    ];
    for step in &wire.steps {
        match step {
            ChunkStep::Data(bytes, 0) => connection.write_body(bytes)?,
            ChunkStep::Data(_, _) | ChunkStep::Control { .. } => {
                return Err(SutError::Environment(
                    "an unsupported external request step passed preflight validation".to_owned(),
                ));
            }
        }
        if connection.torn_down() {
            break;
        }
    }
    let sent = connection.body_written();
    Ok(BodyProgress {
        sent_at_response: sent,
        measured_at_response: false,
        fully_sent: sent >= declared_length,
        torn_down: connection.torn_down(),
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use crate::cli::{self, exit};
    use crate::sut::{Profile, Transport};

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
        let mut connection = Connection::open(endpoint.address()).expect("connect client");
        let wire = empty_wire();
        let head = Head {
            bytes: format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", endpoint.authority()).into_bytes(),
            declared_length: 0,
        };
        let result = execute_socket_exchange(&mut connection, &wire, &head, Duration::from_secs(2));
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
        let result =
            execute_response_result(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").expect("valid close response");

        assert!(result.torn_down);
    }

    #[test]
    fn unsigned_raw_head_does_not_claim_that_its_declared_body_was_fully_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .expect("write response");
        });
        let mut connection = Connection::open(address).expect("connect client");
        let raw = b"PUT /raw HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n".to_vec();
        let mut wire = empty_wire();
        wire.raw_head = Some(raw.clone());
        wire.steps.push(ChunkStep::Data(b"part".to_vec(), 0));
        let result = execute_socket_exchange(
            &mut connection,
            &wire,
            &Head {
                bytes: raw,
                declared_length: 0,
            },
            Duration::from_secs(2),
        )
        .expect("external exchange");
        server.join().expect("server exits");

        assert_eq!(result.observation.request_body_fully_sent, None);
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
        let error =
            execute_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npart").expect_err("partial body is not complete");

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
        let error = execute_socket_exchange(&mut connection, &wire, &head, Duration::from_secs(2))
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
    fn delayed_and_controlled_bodies_fail_before_opening_an_exchange() {
        let mut delayed = empty_wire();
        delayed.steps.push(ChunkStep::Data(b"late".to_vec(), 1));
        let delayed_error = validate_authored_steps(&delayed).expect_err("delay needs concurrent response observation");

        let mut controlled = empty_wire();
        controlled.steps.push(ChunkStep::Control {
            action: "stall".to_owned(),
            delay_ms: 0,
            duration_ms: 1,
        });
        let control_error = validate_authored_steps(&controlled).expect_err("control needs concurrent response observation");

        assert!(
            delayed_error
                .to_string()
                .contains("cannot observe an early response concurrently")
        );
        assert!(control_error.to_string().contains("concurrent response observation"));
    }

    #[test]
    fn delayed_body_is_rejected_before_connecting_to_the_external_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let mut target = Conn::external(std::path::PathBuf::from("."), &format!("http://{address}")).expect("external target");
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

        let error = target.exchange(&plan).expect_err("paced body is unsupported");

        assert!(error.to_string().contains("cannot observe an early response concurrently"));
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("unexpected accept error: {error}"),
            Ok(_) => panic!("external target connected before rejecting the paced body"),
        }
    }

    #[test]
    fn reports_connection_refusal_as_an_environment_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve address");
        let address = listener.local_addr().expect("reserved address");
        drop(listener);
        let endpoint = ExternalEndpoint::parse(&format!("http://{address}")).expect("local endpoint");

        let error = match Connection::open(endpoint.address()) {
            Ok(_) => panic!("nothing is listening"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("connect"));
    }
}
