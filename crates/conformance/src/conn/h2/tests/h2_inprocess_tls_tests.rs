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
//! Responsible for: `[connection.tls]` on authored HTTP/2 scripts against the production Hyper
//! listener — ALPN `h2` negotiated with the real server, and every TLS field or combination this
//! transport does not carry out refused by name.
//! NOT responsible for: external https endpoints (`h2_tls_tests`) or the server's ALPN policy
//! (`rustfs-gateway-server` `tests/tls_alpn.rs`).
//! Upstream: `Conn::exchange`; downstream: the production Hyper listener over TLS.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-3.2 — over TLS, HTTP/2 is used
//! only after both sides agree on the `h2` token through ALPN.

use super::*;

fn tls(block_source: &str) -> Value {
    block(&format!("[tls]\n{block_source}"))
}

fn run(driver: ProductionDriver, request: Value, connection: &Value) -> Result<Observation, SutError> {
    let mut conn = production(driver, "s-h2-tls");
    conn.exchange(&h2_plan("s-h2-tls", request, Some(connection)))
}

/// Positive — the script runs inside a TLS session with the production listener after it
/// selected `h2`, and the real service's answer is observed as HTTP/2.
#[test]
fn an_h2_script_runs_over_tls_against_production_hyper() {
    let observed = run(
        ProductionDriver::Hyper,
        h2_request(ANONYMOUS_GET_ROOT_HPACK),
        &tls("enabled = true\nalpn = [\"h2\"]\n"),
    )
    .expect("the script runs over TLS");
    assert_eq!(observed.status, Some(403), "{observed:?}");
    assert_eq!(observed.http_version.as_deref(), Some("h2"));
    assert_eq!(observed.socket_read_after, None, "TLS records hide the socket state");
}

/// Positive — omitting `alpn` offers `h2`, the protocol the script speaks.
#[test]
fn alpn_defaults_to_h2_for_a_frame_script() {
    let observed = run(ProductionDriver::Hyper, h2_request(ANONYMOUS_GET_ROOT_HPACK), &tls("enabled = true\n"))
        .expect("the script runs over TLS");
    assert_eq!(observed.status, Some(403), "{observed:?}");
}

/// Negative — offering only `http/1.1` gets `http/1.1` from the listener, so no frame is written.
#[test]
fn a_session_that_negotiated_http1_writes_no_frame() {
    let error = run(
        ProductionDriver::Hyper,
        h2_request(ANONYMOUS_GET_ROOT_HPACK),
        &tls("alpn = [\"http/1.1\"]\n"),
    )
    .expect_err("h2 was not negotiated");
    assert!(error.to_string().contains("selected ALPN `http/1.1`, not `h2`"), "{error}");
}

/// Negative — the TLS fields this transport does not apply are refused by name, not ignored.
#[test]
fn unapplied_tls_fields_are_refused_by_name() {
    for (field, source) in [
        ("sni", "sni = \"example.com\"\n"),
        ("min_version", "min_version = \"1.3\"\n"),
        ("close_notify", "close_notify = false\n"),
    ] {
        let error = run(ProductionDriver::Hyper, h2_request(ANONYMOUS_GET_ROOT_HPACK), &tls(source))
            .expect_err("the field is not applied");
        assert!(error.to_string().contains(&format!("`connection.tls.{field}`")), "{field}: {error}");
    }
}

/// Negative — the self-held driver speaks cleartext HTTP/1.1 only, over TLS too.
#[test]
fn the_self_held_driver_still_refuses_an_h2_script_over_tls() {
    let error = run(ProductionDriver::SelfHeld, h2_request(ANONYMOUS_GET_ROOT_HPACK), &tls("enabled = true\n"))
        .expect_err("self-held is HTTP/1.1 only");
    assert!(error.to_string().contains("self-held driver speaks HTTP/1.1 only"), "{error}");
}

/// Negative — an HTTP/1.1 request with `[connection.tls]` is still refused: only frame scripts run
/// over TLS here.
#[test]
fn an_http1_request_over_tls_is_still_refused() {
    let request = block("method = \"GET\"\ntarget = \"/\"\n");
    let error = run(ProductionDriver::Hyper, request, &tls("enabled = true\n")).expect_err("HTTP/1.1 over TLS is not run");
    assert!(error.to_string().contains("`[connection.tls]`"), "{error}");
}

/// Positive — `enabled = false` is an explicit cleartext connection.
#[test]
fn a_disabled_tls_block_runs_in_cleartext() {
    let observed = run(ProductionDriver::Hyper, h2_request(ANONYMOUS_GET_ROOT_HPACK), &tls("enabled = false\n"))
        .expect("the script runs in cleartext");
    assert_eq!(observed.status, Some(403), "{observed:?}");
    assert!(observed.socket_read_after.is_some(), "cleartext keeps the socket measurable");
}

/// Negative — an empty `alpn` offers nothing, which is not `h2`, so no frame is written.
#[test]
fn an_empty_alpn_list_offers_nothing() {
    let error = run(ProductionDriver::Hyper, h2_request(ANONYMOUS_GET_ROOT_HPACK), &tls("alpn = []\n"))
        .expect_err("nothing was negotiated");
    assert!(error.to_string().contains("selected no ALPN protocol, not `h2`"), "{error}");
}
