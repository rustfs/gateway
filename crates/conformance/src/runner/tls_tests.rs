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

//! Configured TLS applicability at the runner/target boundary.
//! Responsible for: rejecting incompatible cases before setup and retaining real production TLS
//! execution and transport refusals. NOT responsible for: TLS handshake or frame implementation.
//! Upstream: `super::run_case`, `crate::sut::Sut`; downstream: configured connection targets.

use super::*;
use crate::conn::Conn;
use crate::observation::Observation;
#[cfg(feature = "production-transports")]
use crate::production::ProductionDriver;

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        Err(format!("no golden declared: {relative}"))
    }
}

struct Recorded<S> {
    inner: S,
    calls: Vec<&'static str>,
    socket_reads: Vec<bool>,
}
impl<S> Recorded<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            calls: Vec::new(),
            socket_reads: Vec::new(),
        }
    }
}
impl<S: Sut> Sut for Recorded<S> {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn configured_tls(&self, request: &Value, connection: Option<&Value>) -> bool {
        self.inner.configured_tls(request, connection)
    }
    fn prepare(&mut self, id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
        self.calls.push("prepare");
        self.inner.prepare(id, setup)
    }
    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        self.calls.push("exchange");
        let observed = self.inner.exchange(plan)?;
        self.socket_reads.push(observed.socket_read_after.is_some());
        Ok(observed)
    }
    fn exchange_concurrent(&mut self, plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        self.calls.push("concurrent");
        self.inner.exchange_concurrent(plans)
    }
    fn finish(&mut self, id: &str) -> Result<(), SutError> {
        self.calls.push("finish");
        self.inner.finish(id)
    }
}

fn case(gate: &str, connection: &str, request: &str) -> Case {
    let source = format!("[case]\ntimeout_ms = 5000\n[case.applies_to]\ntls = \"{gate}\"\n{connection}\n{request}");
    Case {
        id: "s-tls-0001".to_owned(),
        domain: "synthetic".to_owned(),
        path: std::path::PathBuf::from("cases/synthetic/s-tls-0001.toml"),
        relative: "cases/synthetic/s-tls-0001.toml".to_owned(),
        document: Some(crate::toml::parse(&source).expect("valid test TOML")),
        diagnostics: Vec::new(),
    }
}
fn drive(case: &Case, sut: &mut dyn Sut) -> CaseOutcome {
    let options = RunOptions {
        transport: Transport::Conn,
        ..RunOptions::default()
    };
    run_case(case, sut, &options, &NoGoldens, &mut Vec::new())
}
const HTTP1: &str = r#"
[request]
method = "GET"
target = "/"
[expect]
kind = "response"
status = 403
"#;
const H2: &str = r#"
[request]
method = "GET"
target = "/"
http_version = "h2"
[[request.h2_frames]]
type = "settings"
[[request.h2_frames]]
type = "headers"
stream_id = 1
flags = ["end_stream", "end_headers"]
payload_hex = "828684410e73332e6578616d706c652e636f6d"
[expect]
kind = "response"
status = 403
http_version = "h2"
[expect.error]
code = "AccessDenied"
"#;
const ENABLED: &str = "[connection.tls]\nenabled = true\nalpn = [\"h2\"]";
const DISABLED: &str = "[connection.tls]\nenabled = false";
#[cfg(feature = "production-transports")]
const DEFAULTED: &str = "[connection.tls]\nalpn = [\"h2\"]";

fn assert_gated<S: Sut>(sut: &mut Recorded<S>, case: &Case, gate: &str, mode: &str) -> CaseOutcome {
    let outcome = drive(case, sut);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Convention, "{outcome:?}");
    let reason = outcome.skip_reason.as_deref().expect("a gate reports its reason");
    assert!(reason.contains(&format!("`{gate}`")) && reason.contains(mode), "{reason}");
    assert!(reason.contains("configured"), "applicability must describe configuration: {reason}");
    assert!(sut.calls.is_empty(), "an excluded case touched the SUT: {:?}", sut.calls);
    outcome
}
fn assert_refused<S: Sut>(sut: &mut Recorded<S>, case: &Case, reason: &str) {
    let outcome = drive(case, sut);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Execute, "{outcome:?}");
    assert!(
        outcome.skip_reason.as_deref().is_some_and(|actual| actual.contains(reason)),
        "{outcome:?}"
    );
    assert_eq!(sut.calls, ["prepare", "exchange", "finish"]);
}
#[cfg(feature = "production-transports")]
fn production() -> Recorded<Conn> {
    Recorded::new(Conn::production(std::path::PathBuf::from("."), ProductionDriver::Hyper))
}
#[cfg(feature = "production-transports")]
fn assert_passed(sut: &mut Recorded<Conn>, case: &Case, cleartext: bool) {
    let outcome = drive(case, sut);
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Execute);
    assert_eq!(sut.calls, ["prepare", "exchange", "finish"]);
    assert_eq!(sut.socket_reads, [cleartext], "socket state availability retains the transport's mode");
}

// Port zero cannot be a listening destination: these controls need deterministic connection refusal.
/// Negative: both authored HTTP versions must reject HTTPS under a cleartext-only gate.
#[test]
fn n_external_https_forbidden_stops_before_setup() {
    for request in [HTTP1, H2] {
        let mut sut =
            Recorded::new(Conn::external(std::path::PathBuf::from("."), "https://127.0.0.1:0").expect("valid endpoint"));
        assert_gated(&mut sut, &case("forbidden", "", request), "forbidden", "over TLS");
    }
}
/// Negative: configured TLS applicability must not pretend that an unreachable peer was contacted.
#[test]
fn n_external_https_required_reaches_the_endpoint_refusal() {
    for request in [HTTP1, H2] {
        let mut sut =
            Recorded::new(Conn::external(std::path::PathBuf::from("."), "https://127.0.0.1:0").expect("valid endpoint"));
        assert_refused(&mut sut, &case("required", "", request), "could not connect");
    }
}
/// Negative: requiring TLS must still exclude a cleartext endpoint before fixtures.
#[test]
fn n_external_http_required_stops_before_setup() {
    for request in [HTTP1, H2] {
        let mut sut = Recorded::new(Conn::external(std::path::PathBuf::from("."), "http://127.0.0.1:0").expect("valid endpoint"));
        assert_gated(&mut sut, &case("required", "", request), "required", "in cleartext");
    }
}
/// Negative: a declared TLS block cannot turn an HTTP endpoint into HTTPS; normal refusal remains.
#[test]
fn n_external_endpoint_security_overrides_script_tls() {
    let mut sut = Recorded::new(Conn::external(std::path::PathBuf::from("."), "http://127.0.0.1:0").expect("valid endpoint"));
    assert_gated(&mut sut, &case("required", ENABLED, H2), "required", "in cleartext");
    let mut sut = Recorded::new(Conn::external(std::path::PathBuf::from("."), "https://127.0.0.1:0").expect("valid endpoint"));
    assert_gated(&mut sut, &case("forbidden", DISABLED, H2), "forbidden", "over TLS");
}
/// Negative: cleartext applicability must still reach the selected endpoint's environment failure.
#[test]
fn n_external_http_forbidden_reaches_the_endpoint_refusal() {
    let mut sut = Recorded::new(Conn::external(std::path::PathBuf::from("."), "http://127.0.0.1:0").expect("valid endpoint"));
    assert_refused(&mut sut, &case("forbidden", "", H2), "could not connect");
}
/// Negative: a configured TLS frame script cannot be judged as a cleartext-only case.
#[cfg(feature = "production-transports")]
#[test]
fn n_production_tls_forbidden_stops_before_setup() {
    for connection in [ENABLED, DEFAULTED] {
        assert_gated(&mut production(), &case("forbidden", connection, H2), "forbidden", "over TLS");
    }
}
/// Negative: TLS requirements must not enable an unsupported HTTP/1.1 TLS implementation.
#[cfg(feature = "production-transports")]
#[test]
fn n_required_tls_http1_retains_its_transport_refusal() {
    assert_refused(&mut production(), &case("required", ENABLED, HTTP1), "`[connection.tls]`");
}
/// Negative: configured TLS does not promise HTTP/2 support from the self-held driver.
#[cfg(feature = "production-transports")]
#[test]
fn n_required_tls_self_held_retains_its_transport_refusal() {
    let mut sut = Recorded::new(Conn::production(std::path::PathBuf::from("."), ProductionDriver::SelfHeld));
    assert_refused(&mut sut, &case("required", ENABLED, H2), "self-held driver speaks HTTP/1.1 only");
}
/// Negative: the test harness still refuses authored HTTP/2 instead of acquiring TLS support.
#[test]
fn n_required_tls_harness_retains_its_transport_refusal() {
    let mut sut = Recorded::new(Conn::new(std::path::PathBuf::from(".")));
    assert_refused(&mut sut, &case("required", ENABLED, H2), "test socket harness frames HTTP/1.1 only");
}
/// Negative: unsupported handshake instructions keep their execution reason.
#[cfg(feature = "production-transports")]
#[test]
fn n_required_tls_unapplied_fields_retain_their_refusals() {
    for field in ["sni = \"example.com\"", "min_version = \"1.3\"", "close_notify = false"] {
        let connection = format!("{ENABLED}\n{field}");
        let name = field.split_once(' ').expect("field assignment").0;
        assert_refused(&mut production(), &case("required", &connection, H2), &format!("connection.tls.{name}"));
    }
}
/// Negative: applicability cannot manufacture an ALPN agreement the real peer did not make.
#[cfg(feature = "production-transports")]
#[test]
fn n_required_tls_retains_the_real_alpn_refusal() {
    assert_refused(
        &mut production(),
        &case("required", "[connection.tls]\nalpn = []", H2),
        "selected no ALPN protocol",
    );
}
/// Positive wire control: explicit and defaulted TLS execute against the real Hyper TLS listener.
#[cfg(feature = "production-transports")]
#[test]
fn required_tls_executes_a_real_production_tls_script() {
    for connection in [ENABLED, DEFAULTED] {
        assert_passed(&mut production(), &case("required", connection, H2), false);
    }
}
/// Positive reciprocal wire control: absent and explicitly disabled TLS remain cleartext.
#[cfg(feature = "production-transports")]
#[test]
fn forbidden_tls_executes_a_real_cleartext_script() {
    for connection in ["", DISABLED] {
        assert_passed(&mut production(), &case("forbidden", connection, H2), true);
    }
}
/// Positive wire control: `any` does not choose or rewrite the configured connection mode.
#[cfg(feature = "production-transports")]
#[test]
fn any_tls_executes_both_configured_modes() {
    for (connection, cleartext) in [(ENABLED, false), (DEFAULTED, false), (DISABLED, true), ("", true)] {
        assert_passed(&mut production(), &case("any", connection, H2), cleartext);
    }
}
/// Positive wire control: earlier listener state cannot change a later case's applicability.
#[cfg(feature = "production-transports")]
#[test]
fn mixed_tls_and_cleartext_cases_use_their_own_configuration_in_both_orders() {
    for order in [
        [("required", ENABLED, false), ("forbidden", "", true)],
        [("forbidden", "", true), ("required", ENABLED, false)],
    ] {
        let mut sut = production();
        for (gate, connection, cleartext) in order {
            assert_passed(&mut sut, &case(gate, connection, H2), cleartext);
            sut.calls.clear();
            sut.socket_reads.clear();
        }
    }
}

// A target whose exchange configuration can differ within one case. Its canned observations test
// runner dispatch only; they make no assertion about a TLS handshake or wire behavior.
struct ByRequest;
impl Sut for ByRequest {
    fn describe(&self) -> String {
        "request-configured counting target".to_owned()
    }
    fn configured_tls(&self, request: &Value, _connection: Option<&Value>) -> bool {
        request.read("requestSpec.target").and_then(Value::as_str) == Some("/tls")
    }
    fn prepare(&mut self, _id: &str, _setup: Option<&Value>) -> Result<Captures, SutError> {
        Ok(Captures::new())
    }
    fn exchange(&mut self, _plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        Ok(Observation::response(403, Vec::new(), Vec::new()))
    }
    fn exchange_concurrent(&mut self, plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        Ok(plans
            .iter()
            .map(|_| Observation::response(403, Vec::new(), Vec::new()))
            .collect())
    }
}
fn exchanges(targets: &[&str]) -> String {
    targets
        .iter()
        .map(|target| {
            format!(
                "[[exchanges]]\n{}",
                HTTP1
                    .replace("[request]", "[exchanges.request]")
                    .replace("[expect]", "[exchanges.expect]")
                    .replace("target = \"/\"", &format!("target = \"{target}\""))
            )
        })
        .collect()
}
fn assert_mixed_gated(gate: &str, targets: &[&str], concurrent: bool, mode: &str) {
    let connection = if concurrent { "[connection]\nconcurrent = true" } else { "" };
    let case = case(gate, connection, &exchanges(targets));
    let mut sut = Recorded::new(ByRequest);
    let outcome = assert_gated(&mut sut, &case, gate, mode);
    let excluded = targets
        .iter()
        .position(|target| {
            if gate == "required" {
                *target == "/plain"
            } else {
                *target == "/tls"
            }
        })
        .expect("an excluded member");
    assert!(
        outcome
            .skip_reason
            .as_deref()
            .is_some_and(|reason| reason.contains(&format!("exchange #{}", excluded + 1))),
        "{outcome:?}"
    );
}
/// Negative: a later cleartext exchange invalidates a TLS-only serial case before any setup.
#[test]
fn n_required_tls_checks_the_later_serial_exchange() {
    assert_mixed_gated("required", &["/tls", "/plain"], false, "in cleartext");
}
/// Negative: a later TLS exchange cannot conceal an earlier excluded cleartext exchange.
#[test]
fn n_required_tls_checks_the_first_serial_exchange() {
    assert_mixed_gated("required", &["/plain", "/tls"], false, "in cleartext");
}
/// Negative: TLS in a later serial exchange invalidates the complete cleartext-only case.
#[test]
fn n_forbidden_tls_checks_the_later_serial_exchange() {
    assert_mixed_gated("forbidden", &["/plain", "/tls"], false, "over TLS");
}
/// Negative: a later cleartext exchange cannot conceal the first TLS exchange.
#[test]
fn n_forbidden_tls_checks_the_first_serial_exchange() {
    assert_mixed_gated("forbidden", &["/tls", "/plain"], false, "over TLS");
}
/// Negative: a concurrent batch must reject any excluded cleartext member, in either position.
#[test]
fn n_required_tls_checks_every_concurrent_exchange() {
    for targets in [["/tls", "/plain"], ["/plain", "/tls"]] {
        assert_mixed_gated("required", &targets, true, "in cleartext");
    }
}
/// Negative: a concurrent batch must reject any excluded TLS member, in either position.
#[test]
fn n_forbidden_tls_checks_every_concurrent_exchange() {
    for targets in [["/tls", "/plain"], ["/plain", "/tls"]] {
        assert_mixed_gated("forbidden", &targets, true, "over TLS");
    }
}
/// Negative: choosing a TLS configuration cannot implement concurrent TLS dispatch for Conn.
#[cfg(feature = "production-transports")]
#[test]
fn n_required_tls_concurrent_dispatch_retains_its_refusal() {
    let connection = "[connection]\nconcurrent = true\n[connection.tls]\nenabled = true";
    let request = H2
        .replace("[request]", "[exchanges.request]")
        .replace("[[request.", "[[exchanges.request.")
        .replace("[expect", "[exchanges.expect");
    let source = format!("[[exchanges]]\n{request}\n[[exchanges]]\n{request}");
    let mut sut = production();
    let outcome = drive(&case("required", connection, &source), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{outcome:?}");
    assert_eq!(outcome.phase, Phase::Execute, "{outcome:?}");
    assert!(
        outcome
            .skip_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("concurrent batches currently require cleartext sockets")),
        "{outcome:?}"
    );
    assert_eq!(sut.calls, ["prepare", "concurrent", "finish"]);
}
/// Positive counting control: `any` preserves every member in serial and concurrent dispatch.
#[test]
fn any_tls_preserves_mixed_exchange_dispatch() {
    for (connection, expected) in [
        ("", vec!["prepare", "exchange", "exchange", "finish"]),
        ("[connection]\nconcurrent = true", vec!["prepare", "concurrent", "finish"]),
    ] {
        let mut sut = Recorded::new(ByRequest);
        let outcome = drive(&case("any", connection, &exchanges(&["/plain", "/tls"])), &mut sut);
        assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
        assert_eq!(sut.calls, expected);
    }
}

struct DefaultCleartext;
impl Sut for DefaultCleartext {
    fn describe(&self) -> String {
        "default cleartext counting target".to_owned()
    }
    fn prepare(&mut self, _id: &str, _setup: Option<&Value>) -> Result<Captures, SutError> {
        Ok(Captures::new())
    }
    fn exchange(&mut self, _plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        Ok(Observation::response(403, Vec::new(), Vec::new()))
    }
}
/// Negative: targets without an override must not claim TLS from the case's requested block.
#[test]
fn n_default_sut_security_stays_cleartext() {
    assert_gated(
        &mut Recorded::new(DefaultCleartext),
        &case("required", ENABLED, HTTP1),
        "required",
        "in cleartext",
    );
}
/// Positive counting control: the additive trait method preserves ordinary cleartext targets.
#[test]
fn default_sut_security_permits_cleartext() {
    let mut sut = Recorded::new(DefaultCleartext);
    let outcome = drive(&case("forbidden", "", HTTP1), &mut sut);
    assert_eq!(outcome.verdict, Verdict::Passed, "{outcome:?}");
    assert_eq!(sut.calls, ["prepare", "exchange", "finish"]);
}
