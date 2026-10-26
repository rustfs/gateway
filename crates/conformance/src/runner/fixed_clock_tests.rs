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

//! Configured external clocks across CLI selection, runner preflight and actual fixture traffic.
//!
//! Responsible for: observing signing dates on setup, authored requests and cleanup, and refusing
//! a mismatched or unsupported case clock before fixture contact. NOT responsible for: proving a
//! remote server's clock; the loopback peer supplies responses and records only request dates.
//! Upstream: CLI options and the runner. Downstream: bounded test-only socket peers.

use super::*;
use crate::cli::{Options, external_target};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const FIXED: &str = "2026-01-02T03:04:05Z";
const STAMP: &str = "20260102T030405Z";

fn arguments(extra: &[&str]) -> Vec<String> {
    std::iter::once("run")
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn parsed(extra: &[&str]) -> Options {
    Options::parse(&arguments(extra))
        .expect("valid explicit clock configuration")
        .expect("not help")
}

#[test]
fn fixed_clock_option_accepts_an_explicit_endpoint_for_run_and_baseline() {
    for command in ["run", "baseline"] {
        let args = [command, "--endpoint", "http://127.0.0.1:9100", "--endpoint-fixed-time", FIXED].map(str::to_owned);
        let options = Options::parse(&args).expect("clock configuration parses").expect("not help");
        assert_eq!(options.transport, Transport::Conn);
    }
}

#[test]
fn fixed_clock_option_requires_an_endpoint() {
    let error = Options::parse(&arguments(&["--endpoint-fixed-time", FIXED])).expect_err("no endpoint");
    assert!(error.contains("requires") && error.contains("--endpoint"), "{error}");
}

#[test]
fn fixed_clock_option_rejects_commands_that_do_not_execute_one_external_target() {
    for command in ["validate", "audit-keys", "diff-transports"] {
        let args = [command, "--endpoint", "http://127.0.0.1:9100", "--endpoint-fixed-time", FIXED].map(str::to_owned);
        let error = Options::parse(&args).expect_err("not an external execution command");
        assert!(error.contains("run") && error.contains("baseline"), "{command}: {error}");
    }
}

#[test]
fn fixed_clock_option_rejects_invalid_or_lossy_instants() {
    for value in [
        "",
        "today",
        "2026-02-30T03:04:05Z",
        "2026-01-02T03:04:05.1Z",
        "2026-01-02T03:04:05+00:00",
        "2026-01-02T03:04:60Z",
        "2026-01-02",
    ] {
        let error = Options::parse(&arguments(&["--endpoint", "http://127.0.0.1:9100", "--endpoint-fixed-time", value]))
            .expect_err("not an exact whole-second UTC instant");
        assert!(error.contains("UTC"), "{value:?}: {error}");
    }
}

#[test]
fn fixed_clock_option_rejects_a_missing_value_and_repeated_declaration() {
    let error = Options::parse(&arguments(&["--endpoint", "http://127.0.0.1:9100", "--endpoint-fixed-time"]))
        .expect_err("missing instant");
    assert!(error.contains("value"), "{error}");
    for second in [FIXED, "2026-01-02T03:04:06Z"] {
        let error = Options::parse(&arguments(&[
            "--endpoint",
            "http://127.0.0.1:9100",
            "--endpoint-fixed-time",
            FIXED,
            "--endpoint-fixed-time",
            second,
        ]))
        .expect_err("ambiguous repeated configuration");
        assert!(error.contains("once"), "{error}");
    }
}

#[derive(Debug)]
struct RequestDate {
    line: String,
    date: Option<String>,
}

struct Peer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<Vec<RequestDate>>>,
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> Option<RequestDate> {
    let mut bytes = Vec::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let mut block = [0; 2048];
        let count = match stream.read(&mut block) {
            Ok(0) => return None,
            Ok(count) => count,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(error) => panic!("read bounded clock request: {error}"),
        };
        bytes.extend_from_slice(&block[..count]);
        let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else { continue };
        let head = std::str::from_utf8(&bytes[..end]).expect("UTF-8 request head");
        let fields: Vec<_> = head.lines().skip(1).filter_map(|line| line.split_once(':')).collect();
        let length = fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, value)| value.trim().parse::<usize>().expect("numeric body length"));
        if bytes.len() < end + 4 + length {
            continue;
        }
        return Some(RequestDate {
            line: head.lines().next().expect("request line").to_owned(),
            date: fields
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-amz-date"))
                .map(|(_, value)| value.trim().to_owned()),
        });
    }
}

impl Peer {
    fn new(statuses: &[u16]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind clock peer");
        listener.set_nonblocking(true).expect("bounded accept");
        let endpoint = format!("http://{}", listener.local_addr().expect("peer address"));
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let state = Arc::new(Mutex::new((VecDeque::from(statuses.to_vec()), Vec::new())));
        let thread = thread::spawn(move || {
            let mut children = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking bounded peer read");
                        stream.set_read_timeout(Some(Duration::from_millis(100))).expect("read bound");
                        stream.set_write_timeout(Some(Duration::from_secs(1))).expect("write bound");
                        let state = Arc::clone(&state);
                        let stopping = Arc::clone(&stopping);
                        children.push(thread::spawn(move || {
                            while let Some(request) = read_request(&mut stream, &stopping) {
                                let mut state = state.lock().expect("peer state");
                                let status = state.0.pop_front().unwrap_or(500);
                                let read = request.line.starts_with("GET ");
                                state.1.push(request);
                                drop(state);
                                let body = if read && status == 200 { "hello" } else { "" };
                                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nLast-Modified: Fri, 02 Jan 2026 03:04:05 GMT\r\n\r\n{body}", body.len());
                                stream.write_all(response.as_bytes()).expect("write clock response");
                            }
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
                    Err(error) => panic!("accept clock request: {error}"),
                }
            }
            for child in children {
                child.join().expect("peer request worker");
            }
            let mut state = state.lock().expect("completed peer state");
            std::mem::take(&mut state.1)
        });
        Self {
            endpoint,
            stop,
            thread: Some(thread),
        }
    }

    fn finish(&mut self) -> Vec<RequestDate> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().expect("peer thread exists").join().expect("peer exits")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn original_case() -> (PathBuf, Case) {
    let root = Corpus::discover_root().expect("repository corpus");
    let relative = "cases/cond/c-cond-0008.toml";
    let path = root.join(relative);
    let text = std::fs::read_to_string(&path).expect("original fixed-time positive");
    let case = Case {
        id: "c-cond-0008".to_owned(),
        domain: "cond".to_owned(),
        path,
        relative: relative.to_owned(),
        document: Some(crate::toml::parse(&text).expect("case TOML")),
        diagnostics: Vec::new(),
    };
    (root, case)
}

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        Err(format!("unexpected golden: {relative}"))
    }
}

fn drive(case: &Case, root: PathBuf, endpoint: &str, fixed: Option<&str>) -> CaseOutcome {
    let mut args = vec!["--endpoint", endpoint, "--allow-external-fixtures"];
    if let Some(fixed) = fixed {
        args.extend(["--endpoint-fixed-time", fixed]);
    }
    let options = parsed(&args);
    let mut target = external_target(&options, root).expect("configured CLI target");
    run_case(
        case,
        &mut target,
        &RunOptions {
            transport: Transport::Conn,
            ..RunOptions::default()
        },
        &NoGoldens,
        &mut Vec::new(),
    )
}

const SUCCESS: &[u16] = &[404, 200, 404, 200, 200, 204, 204];

#[test]
fn equal_fixed_clocks_sign_setup_authored_read_and_cleanup_at_the_declared_instant() {
    let (root, case) = original_case();
    let mut peer = Peer::new(SUCCESS);
    let outcome = drive(&case, root, &peer.endpoint, Some(FIXED));
    let requests = peer.finish();
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(
        requests.iter().map(|request| request.line.as_str()).collect::<Vec<_>>(),
        [
            "HEAD /conf-cond HTTP/1.1",
            "PUT /conf-cond HTTP/1.1",
            "HEAD /conf-cond/dates/modified HTTP/1.1",
            "PUT /conf-cond/dates/modified HTTP/1.1",
            "GET /conf-cond/dates/modified HTTP/1.1",
            "DELETE /conf-cond/dates/modified HTTP/1.1",
            "DELETE /conf-cond HTTP/1.1",
        ]
    );
    for request in requests {
        assert_eq!(request.date.as_deref(), Some(STAMP), "{}", request.line);
    }
}

#[test]
fn unequal_fixed_clocks_are_refused_before_any_fixture_contact() {
    for fixed in ["2026-01-02T03:04:04Z", "2026-01-02T03:04:06Z"] {
        let (root, case) = original_case();
        let mut peer = Peer::new(&[]);
        let outcome = drive(&case, root, &peer.endpoint, Some(fixed));
        let requests = peer.finish();
        assert!(requests.is_empty(), "mismatched clocks sent requests: {requests:?}");
        assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
        assert!(
            outcome
                .skip_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("clock.fixed") && reason.contains("--endpoint-fixed-time")),
            "{outcome:?}"
        );
    }
}

#[test]
fn unsupported_clock_changes_are_refused_before_any_fixture_contact() {
    for (key, value) in [("skew_ms", 1), ("advance_ms_between_exchanges", 1), ("presign_expires_s", 60)] {
        let (root, mut case) = original_case();
        case.document
            .as_mut()
            .expect("document")
            .get_mut("clock")
            .expect("clock")
            .insert(key, Value::Integer(value));
        let mut peer = Peer::new(&[]);
        let outcome = drive(&case, root, &peer.endpoint, Some(FIXED));
        let requests = peer.finish();
        assert!(requests.is_empty(), "unsupported {key} sent requests: {requests:?}");
        assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
        assert!(outcome.skip_reason.as_deref().is_some_and(|reason| reason.contains(key)), "{outcome:?}");
    }
}

#[test]
fn a_failed_authored_read_still_cleans_at_the_fixed_instant() {
    let (root, case) = original_case();
    let mut peer = Peer::new(&[404, 200, 404, 200, 403, 204, 204]);
    let outcome = drive(&case, root, &peer.endpoint, Some(FIXED));
    let requests = peer.finish();
    assert_eq!(outcome.verdict, Verdict::Failed, "{outcome:?}");
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[5].line, "DELETE /conf-cond/dates/modified HTTP/1.1");
    assert_eq!(requests[6].line, "DELETE /conf-cond HTTP/1.1");
    assert_eq!(requests[5].date.as_deref(), Some(STAMP));
    assert_eq!(requests[6].date.as_deref(), Some(STAMP));
}

#[test]
fn fixed_clock_cases_remain_unsupported_without_the_endpoint_opt_in() {
    let (root, case) = original_case();
    let mut peer = Peer::new(&[404, 200, 404, 200, 204, 204]);
    let outcome = drive(&case, root, &peer.endpoint, None);
    let requests = peer.finish();
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert!(
        outcome
            .skip_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("clock.fixed")),
        "{outcome:?}"
    );
    assert!(requests.iter().all(|request| !request.line.starts_with("GET ")));
}

#[test]
fn no_clock_and_no_opt_in_keep_wall_time_signing() {
    let before = wall_stamp();
    let (root, mut case) = original_case();
    case.document
        .as_mut()
        .expect("document")
        .insert("clock", Value::empty_table());
    let mut peer = Peer::new(SUCCESS);
    let outcome = drive(&case, root, &peer.endpoint, None);
    let requests = peer.finish();
    let after = wall_stamp();
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(requests.len(), 7);
    for request in requests {
        let date = request.date.expect("signed request date");
        assert!(before <= date && date <= after, "request date is outside the observed wall-time interval");
    }
}

fn wall_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
    rustfs_gateway::Timestamp::from_secs(i64::try_from(seconds).expect("representable time"))
        .render(rustfs_gateway::TimestampFormat::Iso8601Basic)
        .expect("wall-time stamp")
}

#[test]
fn authored_past_and_future_request_times_do_not_move_fixture_control_time() {
    for (request_time, stamp) in [
        ("2026-01-02T02:48:05Z", "20260102T024805Z"),
        ("2026-01-02T03:20:05Z", "20260102T032005Z"),
    ] {
        let (root, mut case) = original_case();
        case.document
            .as_mut()
            .expect("document")
            .get_mut("clock")
            .expect("clock")
            .insert("request_time", Value::String(request_time.to_owned()));
        let mut peer = Peer::new(SUCCESS);
        let outcome = drive(&case, root, &peer.endpoint, Some(FIXED));
        let requests = peer.finish();
        assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
        assert_eq!(requests.len(), 7);
        for request in requests {
            let expected = if request.line.starts_with("GET ") { stamp } else { STAMP };
            assert_eq!(request.date.as_deref(), Some(expected), "{}", request.line);
        }
    }
}

#[test]
fn the_configured_endpoint_clock_also_signs_cases_without_an_authored_fixed_instant() {
    let (root, mut case) = original_case();
    case.document
        .as_mut()
        .expect("document")
        .insert("clock", Value::empty_table());
    let mut peer = Peer::new(SUCCESS);
    let outcome = drive(&case, root, &peer.endpoint, Some(FIXED));
    let requests = peer.finish();
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(requests.len(), 7);
    for request in requests {
        assert_eq!(request.date.as_deref(), Some(STAMP), "{}", request.line);
    }
}
