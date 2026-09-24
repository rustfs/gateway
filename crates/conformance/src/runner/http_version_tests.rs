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

//! HTTP-version applicability controls for the runner.
//!
//! Responsible for: checking every declared exchange before fixture setup, and proving that an
//! applicable HTTP/2 script still reaches the selected transport's actual response or refusal.
//! NOT responsible for: implementing HTTP/2 frames or extending supported transports.
//! Upstream: `super::run_case`; downstream: counting targets and the production socket driver.

use super::*;
use crate::observation::Observation;

struct NoGoldens;

impl GoldenSource for NoGoldens {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        Err(format!("no golden declared: {relative}"))
    }
}

fn case(versions: &str, exchanges: &str) -> Case {
    let source = format!("[case]\n timeout_ms = 5000\n[case.applies_to]\nhttp_versions = [{versions}]\n{exchanges}");
    Case {
        id: "s-http-version-0001".to_owned(),
        domain: "synthetic".to_owned(),
        path: std::path::PathBuf::from("cases/synthetic/s-http-version-0001.toml"),
        relative: "cases/synthetic/s-http-version-0001.toml".to_owned(),
        document: Some(crate::toml::parse(&source).expect("valid test TOML")),
        diagnostics: Vec::new(),
    }
}

fn exchange(version: Option<&str>) -> String {
    let declaration = version.map_or_else(String::new, |version| format!("http_version = \"{version}\"\n"));
    format!(
        "[[exchanges]]\n[exchanges.request]\nmethod = \"GET\"\ntarget = \"/\"\n{declaration}\
         [exchanges.expect]\nkind = \"response\"\nstatus = 204\n"
    )
}

fn drive(case: &Case, sut: &mut dyn Sut) -> CaseOutcome {
    run_case(case, sut, &RunOptions::default(), &NoGoldens, &mut Vec::new())
}

#[derive(Default)]
struct CountOnly;

impl Sut for CountOnly {
    fn describe(&self) -> String {
        "applicability counting target; no wire observations".to_owned()
    }

    fn prepare(&mut self, _case_id: &str, _setup: Option<&Value>) -> Result<Captures, SutError> {
        Ok(Captures::new())
    }

    fn exchange(&mut self, _plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        Ok(Observation::response(204, Vec::new(), Vec::new()))
    }
}

struct Recorded<S> {
    inner: S,
    calls: Vec<&'static str>,
    versions: Vec<Option<String>>,
}

impl<S> Recorded<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            calls: Vec::new(),
            versions: Vec::new(),
        }
    }
}

impl<S: Sut> Sut for Recorded<S> {
    fn describe(&self) -> String {
        self.inner.describe()
    }

    fn prepare(&mut self, case_id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
        self.calls.push("prepare");
        self.inner.prepare(case_id, setup)
    }

    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        self.calls.push("exchange");
        let observed = self.inner.exchange(plan)?;
        self.versions.push(observed.http_version.clone());
        Ok(observed)
    }

    fn finish(&mut self, case_id: &str) -> Result<(), SutError> {
        self.calls.push("finish");
        self.inner.finish(case_id)
    }
}

fn assert_gated(versions: &str, exchanges: &str) {
    let mut sut = Recorded::new(CountOnly);
    let outcome = drive(&case(versions, exchanges), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Convention);
    assert!(
        outcome
            .skip_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("http_versions")),
        "{outcome:?}"
    );
    assert!(sut.calls.is_empty(), "an excluded exchange touched the SUT: {:?}", sut.calls);
}

/// Negative: an HTTP/1.1-only case cannot execute its declared HTTP/2 request.
#[test]
fn an_h2_request_excluded_by_the_gate_never_prepares_the_sut() {
    assert_gated("\"http/1.1\"", &exchange(Some("h2")));
}

/// Negative: an absent declaration retains the HTTP/1.1 default, rather than borrowing the gate.
#[test]
fn an_implicit_http11_request_is_excluded_by_an_h2_only_gate() {
    assert_gated("\"h2\"", &exchange(None));
}

/// Negative: an explicit HTTP/1.1 declaration is not promoted to HTTP/2 by its applicability list.
#[test]
fn an_explicit_http11_request_is_excluded_by_an_h2_only_gate() {
    assert_gated("\"h2\"", &exchange(Some("http/1.1")));
}

/// Negative: checking only the first exchange would permit an excluded later exchange.
#[test]
fn an_excluded_later_exchange_prevents_all_fixture_and_exchange_calls() {
    assert_gated("\"http/1.1\"", &(exchange(None) + &exchange(Some("h2"))));
}

/// Negative: checking only the last exchange would permit an excluded earlier exchange.
#[test]
fn an_excluded_first_exchange_is_not_hidden_by_a_later_allowed_exchange() {
    assert_gated("\"http/1.1\"", &(exchange(Some("h2")) + &exchange(None)));
}

/// Positive counting control: two permitted declarations mean two authored exchanges, not a matrix.
#[test]
fn allowing_both_versions_does_not_duplicate_or_drop_authored_exchanges() {
    for exchanges in [
        exchange(None),
        exchange(Some("http/1.1")),
        exchange(Some("h2")) + &exchange(None),
    ] {
        let expected = if exchanges.matches("[[exchanges]]").count() == 2 {
            vec!["prepare", "exchange", "exchange", "finish"]
        } else {
            vec!["prepare", "exchange", "finish"]
        };
        let mut sut = Recorded::new(CountOnly);
        let outcome = drive(&case("\"http/1.1\", \"h2\"", &exchanges), &mut sut);
        assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
        assert_eq!(sut.calls, expected);
    }
}

// Literal HPACK for GET / over http with authority s3.example.com; no high-level client encodes it.
const AUTHORED_H2: &str = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/"
http_version = "h2"
[[exchanges.request.h2_frames]]
type = "settings"
[[exchanges.request.h2_frames]]
type = "headers"
stream_id = 1
flags = ["end_stream", "end_headers"]
payload_hex = "828684410e73332e6578616d706c652e636f6d"
[exchanges.expect]
kind = "response"
status = 403
http_version = "h2"
[exchanges.expect.error]
code = "AccessDenied"
"#;

/// Positive wire control: passing applicability reaches the real Hyper peer and its HTTP/2 head.
#[cfg(feature = "production-transports")]
#[test]
fn an_applicable_h2_script_observes_the_production_hyper_response() {
    let mut sut = Recorded::new(crate::conn::Conn::production(
        std::path::PathBuf::from("."),
        crate::production::ProductionDriver::Hyper,
    ));
    let outcome = drive(&case("\"h2\"", AUTHORED_H2), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(sut.calls, ["prepare", "exchange", "finish"]);
    assert_eq!(sut.versions, [Some("h2".to_owned())]);
}

fn assert_transport_refusal<S: Sut>(sut: S, source: &str, expected: &str) {
    let mut sut = Recorded::new(sut);
    let outcome = drive(&case("\"h2\"", source), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Execute);
    assert!(
        outcome.skip_reason.as_deref().is_some_and(|reason| reason.contains(expected)),
        "{outcome:?}"
    );
    assert_eq!(sut.calls, ["prepare", "exchange", "finish"]);
    assert!(sut.versions.is_empty(), "a refused transport returned a response");
}

/// Negative: applicability is not a capability claim for the ordinary test socket harness.
#[test]
fn an_applicable_h2_script_preserves_the_test_harness_refusal() {
    assert_transport_refusal(
        crate::conn::Conn::new(std::path::PathBuf::from(".")),
        AUTHORED_H2,
        "test socket harness frames HTTP/1.1 only",
    );
}

/// Negative: no remote connection is needed to refuse an external HTTP/2 script.
#[test]
fn an_applicable_h2_script_preserves_the_external_endpoint_refusal() {
    let sut = crate::conn::Conn::external(std::path::PathBuf::from("."), "http://127.0.0.1:9").expect("valid endpoint");
    assert_transport_refusal(sut, AUTHORED_H2, "external endpoint HTTP/2 framing is not implemented");
}

/// Negative: the self-held driver's HTTP/1.1 support must not be mistaken for Hyper HTTP/2.
#[cfg(feature = "production-transports")]
#[test]
fn an_applicable_h2_script_preserves_the_self_held_refusal() {
    assert_transport_refusal(
        crate::conn::Conn::production(std::path::PathBuf::from("."), crate::production::ProductionDriver::SelfHeld),
        AUTHORED_H2,
        "self-held driver speaks HTTP/1.1 only",
    );
}

/// Negative: a structured request cannot acquire a frame writer by passing the version gate.
#[cfg(feature = "production-transports")]
#[test]
fn an_applicable_structured_h2_request_still_requires_authored_frames() {
    assert_transport_refusal(
        crate::conn::Conn::production(std::path::PathBuf::from("."), crate::production::ProductionDriver::Hyper),
        &exchange(Some("h2")),
        "HTTP/2",
    );
}

/// Positive counting control: the top-level request form retains the HTTP/1.1 default.
#[test]
fn a_single_top_level_request_uses_http11_without_repetition() {
    let source = exchange(None).replace("[[exchanges]]\n", "").replace("exchanges.", "");
    let mut sut = Recorded::new(CountOnly);
    let outcome = drive(&case("\"http/1.1\"", &source), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(sut.calls, ["prepare", "exchange", "finish"]);
}

/// Negative: the non-array request form must also check its declared HTTP version.
#[test]
fn an_excluded_top_level_request_never_touches_the_sut() {
    let source = exchange(Some("h2")).replace("[[exchanges]]\n", "").replace("exchanges.", "");
    assert_gated("\"http/1.1\"", &source);
}

/// Negative: allowing HTTP/2 does not authorize TLS for the cleartext frame writer.
#[cfg(feature = "production-transports")]
#[test]
fn an_applicable_h2_script_preserves_the_tls_refusal() {
    let source = format!("[connection.tls]\nenabled = true\n{AUTHORED_H2}");
    assert_transport_refusal(
        crate::conn::Conn::production(std::path::PathBuf::from("."), crate::production::ProductionDriver::Hyper),
        &source,
        "`[connection.tls]`",
    );
}

/// Negative: accepting the first scripted exchange cannot silently replace requested reuse.
#[cfg(feature = "production-transports")]
#[test]
fn an_applicable_h2_script_preserves_the_connection_reuse_refusal() {
    let mut sut = Recorded::new(crate::conn::Conn::production(
        std::path::PathBuf::from("."),
        crate::production::ProductionDriver::Hyper,
    ));
    let source = format!("[connection]\nreuse = true\n{AUTHORED_H2}{AUTHORED_H2}");
    let outcome = drive(&case("\"h2\"", &source), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Execute);
    assert!(
        outcome
            .skip_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("reuse the connection")),
        "{outcome:?}"
    );
    assert_eq!(sut.calls, ["prepare", "exchange", "exchange", "finish"]);
    assert_eq!(sut.versions, [Some("h2".to_owned())]);
}

/// Negative: an explicitly empty frame list cannot stand in for an executed HTTP/2 script.
#[cfg(feature = "production-transports")]
#[test]
fn an_applicable_h2_request_with_empty_frames_is_still_refused() {
    let source = exchange(Some("h2")).replace("http_version = \"h2\"\n", "http_version = \"h2\"\nh2_frames = []\n");
    assert_transport_refusal(
        crate::conn::Conn::production(std::path::PathBuf::from("."), crate::production::ProductionDriver::Hyper),
        &source,
        "HTTP/2",
    );
}
