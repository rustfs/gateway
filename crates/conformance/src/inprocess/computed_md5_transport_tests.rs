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

//! Responsible for: computed digests after response capture through real socket transports.
//! NOT responsible for: schema validation, digest primitives, or transport performance.
//! Upstream: the runner's interpolation and signing path. Downstream: fixture object storage.

use crate::conn::Conn;
use crate::corpus::Corpus;
use crate::report::Verdict;
use crate::runner::{self, RunOptions};
use crate::sut::Transport;
use std::sync::OnceLock;

// A captured ETag includes quotes. Reading the second object back proves interpolation preserved
// those bytes, while the signed Content-MD5 proves its digest was computed before signing.
const BODY: &str = "\"900150983cd24fb0d6963f7d28e17f72\"";

fn document(digest: &str, credential: &str, status: u16, error: Option<&str>) -> String {
    let polarity = if error.is_some() { "negative" } else { "positive" };
    let refusal = error.map_or_else(String::new, |code| format!("\n[exchanges.expect.error]\ncode = {code:?}\n"));
    let readback = if error.is_none() {
        format!(
            r#"
[[exchanges]]
name = "read-back-captured-bytes"
[exchanges.request]
method = "GET"
target = "/md5-capture/copied"
sign = {{ mode = "sigv4_header", credential = "valid" }}
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.body]
exact_utf8 = '{BODY}'
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"
[case]
id = "c-md5-transport-0001"
schema_version = 3
title = "Computed digest follows response capture"
polarity = "{polarity}"
operation = "PutObject"
timeout_ms = 10000
[[setup.buckets]]
name = "md5-capture"
[[exchanges]]
name = "produce-capture"
[exchanges.request]
method = "PUT"
target = "/md5-capture/source"
body = {{ utf8 = "abc" }}
sign = {{ mode = "sigv4_header", credential = "valid" }}
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.capture]
etag = {{ header = "etag" }}
[[exchanges]]
name = "write-captured-bytes"
[exchanges.request]
method = "PUT"
target = "/md5-capture/copied"
{digest}
body = {{ utf8 = "${{capture.etag}}" }}
sign = {{ mode = "sigv4_header", credential = "{credential}", signed_headers = ["host", "content-md5", "x-amz-date", "x-amz-content-sha256"] }}
[exchanges.expect]
kind = "response"
status = {status}
{refusal}
{readback}
"#
    )
}

fn prepared_case(source: &str) -> Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    let mut corpus = CORPUS
        .get_or_init(|| {
            let root = Corpus::discover_root().expect("the corpus exists");
            Corpus::load(&root).expect("the corpus loads")
        })
        .clone();
    // Reuse a selected slot without touching on-disk cases. This is a runner/transport unit test;
    // the frozen schema and convention lints have their own tests.
    let case = &mut corpus.cases_mut()[0];
    case.id = "c-md5-transport-0001".to_owned();
    case.document = Some(crate::toml::parse(source).expect("the synthetic exchanges parse"));
    case.diagnostics.clear();
    corpus
}

fn exercise(mut target: Conn, corpus: &Corpus) {
    let options = RunOptions {
        filter: Some(corpus.cases()[0].relative.clone()),
        transport: Transport::Conn,
        ..RunOptions::default()
    };
    let report = runner::run(corpus, &mut target, &options);
    assert_eq!(report.outcomes.len(), 1, "the synthetic case must run once");
    assert_eq!(report.outcomes[0].verdict, Verdict::Passed, "{:#?}", report.outcomes[0]);
}

fn transports(source: &str) {
    let root = Corpus::discover_root().expect("the corpus exists");
    let corpus = prepared_case(source);
    exercise(Conn::new(root.clone()), &corpus);
    #[cfg(feature = "production-transports")]
    for driver in [
        crate::production::ProductionDriver::Hyper,
        crate::production::ProductionDriver::SelfHeld,
    ] {
        exercise(Conn::production(root.clone(), driver), &corpus);
    }
}

#[test]
fn computed_md5_response_capture_is_signed_and_stored_over_sockets() {
    transports(&document("content_md5 = \"computed\"", "valid", 200, None));
}

#[test]
fn computed_md5_transport_controls_reject_a_stale_literal_digest() {
    transports(&document(
        "headers = { 'content-md5' = 'kAFQmDzST7DWlj99KOF/cg==' }",
        "valid",
        400,
        Some("BadDigest"),
    ));
}

#[test]
fn computed_md5_transport_controls_reject_an_invalid_literal_digest() {
    transports(&document(
        "headers = { 'content-md5' = 'not-a-digest' }",
        "valid",
        400,
        Some("InvalidDigest"),
    ));
}

#[test]
fn computed_md5_transport_controls_still_require_a_valid_signature() {
    transports(&document(
        "content_md5 = \"computed\"",
        "wrong_secret",
        403,
        Some("SignatureDoesNotMatch"),
    ));
}
