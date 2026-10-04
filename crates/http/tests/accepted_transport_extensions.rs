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

//! Responsible for: retained transport values and omission of raw request/form data from Debug.
//! NOT responsible for: handler context assembly or protocol decoding.
//! Upstream: transport-installed extensions. Downstream: the read-only wire context.

use http::Request;
use rustfs_gateway_http::{FileStep, FormGrammar, FormLimits, FormReader, FormStep, Limits, WireRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct TransportNote {
    clones: Arc<AtomicUsize>,
    value: &'static str,
}

impl Clone for TransportNote {
    fn clone(&self) -> Self {
        self.clones.fetch_add(1, Ordering::SeqCst);
        Self {
            clones: Arc::clone(&self.clones),
            value: self.value,
        }
    }
}

fn request() -> Request<()> {
    Request::builder()
        .uri("/bucket/key")
        .header("host", "s3.example.com")
        .body(())
        .expect("fixture request")
}

fn marked_wire() -> (WireRequest<()>, Arc<AtomicUsize>) {
    let clones = Arc::new(AtomicUsize::new(0));
    let mut request = request();
    request.extensions_mut().insert(TransportNote {
        clones: Arc::clone(&clones),
        value: "private-transport-note",
    });
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted fixture");
    (wire, clones)
}

#[test]
fn retained_transport_view_outlives_the_request_body() {
    let (wire, _) = marked_wire();
    let view = wire.transport_extensions().clone();
    drop(wire);
    assert_eq!(view.get::<TransportNote>().expect("retained value").value, "private-transport-note");
}

#[test]
fn acceptance_body_mapping_and_view_cloning_do_not_clone_transport_values() {
    let (wire, clones) = marked_wire();
    let view = wire.transport_extensions().clone();
    let mapped = wire.map_body(|()| 17_u8);
    assert_eq!(clones.load(Ordering::SeqCst), 0);
    assert!(core::ptr::eq(
        view.get::<TransportNote>().expect("original value"),
        mapped.transport_extensions().get::<TransportNote>().expect("mapped value"),
    ));
}

#[test]
fn absent_transport_types_are_not_substituted_or_recovered_from_headers() {
    let (wire, _) = marked_wire();
    assert!(wire.transport_extensions().get::<String>().is_none());
    let mut request = request();
    request
        .headers_mut()
        .insert("x-transport-note", http::HeaderValue::from_static("private-transport-note"));
    let empty = WireRequest::accept(request, &Limits::default()).expect("header is unrelated");
    assert!(empty.transport_extensions().get::<TransportNote>().is_none());
    assert!(empty.transport_extensions().get::<usize>().is_none());
}

#[test]
fn wire_and_view_debug_never_format_transport_values() {
    let (wire, _) = marked_wire();
    for rendered in [format!("{wire:?}"), format!("{:?}", wire.transport_extensions())] {
        assert!(!rendered.contains("private-transport-note"));
    }
}

const DEBUG_HOST: &str = "private-host-sentinel.example.com";
const DEBUG_BODY: &str = "BODY_SECRET_SENTINEL";
const DEBUG_QUERY: &str = concat!(
    "X-Amz-Credential=QUERY_CREDENTIAL_SENTINEL&",
    "X-Amz-Signature=QUERY_SIGNATURE_SENTINEL&",
    "X-Amz-Security-Token=QUERY_TOKEN_SENTINEL&",
    "CUSTOM_QUERY_NAME_SENTINEL=CUSTOM_QUERY_VALUE_SENTINEL"
);
const HEADER_SECRETS: &[&str] = &[
    DEBUG_HOST,
    "HEADER_CREDENTIAL_SENTINEL",
    "HEADER_SIGNATURE_SENTINEL",
    "HEADER_TOKEN_SENTINEL",
    "SSE_CUSTOMER_KEY_SENTINEL",
    "x-custom-header-name-sentinel",
    "CUSTOM_HEADER_VALUE_SENTINEL",
];
const QUERY_SECRETS: &[&str] = &[
    "QUERY_CREDENTIAL_SENTINEL",
    "QUERY_SIGNATURE_SENTINEL",
    "QUERY_TOKEN_SENTINEL",
    "CUSTOM_QUERY_NAME_SENTINEL",
    "CUSTOM_QUERY_VALUE_SENTINEL",
];

fn secret_wire() -> WireRequest<String> {
    let request = Request::builder()
        .method("PUT")
        .uri(format!("https://{DEBUG_HOST}/URI_PATH_SENTINEL?{DEBUG_QUERY}"))
        .header("host", DEBUG_HOST)
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=HEADER_CREDENTIAL_SENTINEL, SignedHeaders=host, Signature=HEADER_SIGNATURE_SENTINEL",
        )
        .header("x-amz-security-token", "HEADER_TOKEN_SENTINEL")
        .header("x-amz-server-side-encryption-customer-key", "SSE_CUSTOMER_KEY_SENTINEL")
        .header("x-custom-header-name-sentinel", "CUSTOM_HEADER_VALUE_SENTINEL")
        .header("content-length", DEBUG_BODY.len())
        .body(DEBUG_BODY.to_owned())
        .expect("secret-bearing fixture request");
    WireRequest::accept(request, &Limits::default()).expect("the request head is accepted")
}

fn assert_debug_omits(rendered: &str, secrets: &[&str]) {
    let compact: String = rendered.chars().filter(|character| !character.is_whitespace()).collect();
    for secret in secrets {
        assert!(!rendered.contains(secret), "Debug must omit every raw request name and value");
        let numeric = format!("{:?}", secret.as_bytes()).replace(' ', "");
        let numeric = numeric.trim_start_matches('[').trim_end_matches(']');
        assert!(!compact.contains(numeric), "Debug must omit byte representations of request values");
    }
}

#[test]
fn wire_request_debug_omits_uri_header_and_body_values() {
    let wire = secret_wire();
    for rendered in [format!("{wire:?}"), format!("{wire:#?}")] {
        assert_debug_omits(&rendered, HEADER_SECRETS);
        assert_debug_omits(&rendered, QUERY_SECRETS);
        assert_debug_omits(&rendered, &["URI_PATH_SENTINEL", DEBUG_BODY]);
        assert!(rendered.contains("method: PUT"));
        assert!(rendered.contains("version: HTTP/1.1"));
        assert!(rendered.contains("headers: 6"));
    }
}

#[test]
fn wire_request_debug_omits_byte_body_values() {
    let wire = secret_wire().map_body(String::into_bytes);
    for rendered in [format!("{wire:?}"), format!("{wire:#?}")] {
        assert_debug_omits(&rendered, &[DEBUG_BODY]);
    }
}

#[test]
fn header_view_debug_omits_unmarked_header_names_and_values() {
    let wire = secret_wire();
    let view = wire.headers();
    for rendered in [format!("{view:?}"), format!("{view:#?}")] {
        assert_debug_omits(&rendered, HEADER_SECRETS);
        assert!(rendered.contains("HeaderView"));
        assert!(rendered.contains("headers: 6"));
    }
}

#[test]
fn query_view_debug_omits_raw_parameter_names_and_values() {
    let wire = secret_wire();
    let view = wire.query();
    for rendered in [format!("{view:?}"), format!("{view:#?}")] {
        assert_debug_omits(&rendered, QUERY_SECRETS);
        assert!(rendered.contains("QueryView"));
        assert!(rendered.contains("params: 4"));
        assert!(rendered.contains(&format!("query_bytes: {}", DEBUG_QUERY.len())));
    }
}

#[test]
fn debug_views_keep_counts_for_a_request_without_a_query() {
    let wire = WireRequest::accept(request(), &Limits::default()).expect("the bodyless fixture is accepted");
    assert!(format!("{wire:?}").contains("headers: 1"));
    assert!(format!("{:?}", wire.headers()).contains("headers: 1"));
    let query = format!("{:?}", wire.query());
    assert!(query.contains("params: 0"));
    assert!(query.contains("query_bytes: 0"));
}

const FORM_BOUNDARY: &str = "boundary_form_sentinel_0123456789";
const FORM_FILENAME: &str = "filename_form_sentinel";
const FORM_CARRY: &str = "carry_body_sentinel";
const FORM_FIELDS: &[(&str, &str)] = &[
    ("x-amz-credential", "credential_form_sentinel"),
    ("x-amz-signature", "signature_form_sentinel"),
    ("x-amz-security-token", "token_form_sentinel"),
    ("field_name_sentinel", "field_value_sentinel"),
];
const FORM_GRAMMARS: [FormGrammar; 2] = [FormGrammar::Gateway, FormGrammar::LegacyRustfs { declared_length: false }];

fn form_reader_at_file(grammar: FormGrammar) -> FormReader {
    let mut body = String::new();
    for (name, value) in FORM_FIELDS {
        body.push_str(&format!(
            "--{FORM_BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{FORM_BOUNDARY}\r\nContent-Disposition: form-data; name=\"FiLe\"; filename=\"{FORM_FILENAME}\"\r\n\r\n{FORM_CARRY}"
    ));
    let mut reader =
        FormReader::with_grammar(&format!("multipart/form-data; boundary={FORM_BOUNDARY}"), FormLimits::default(), grammar)
            .expect("bounded form fixture");
    assert!(matches!(reader.push(body.as_bytes()), Ok(FormStep::FileReached { .. })));
    assert_eq!(reader.fields().len(), FORM_FIELDS.len(), "the public reader actually produced the fields");
    reader
}

// ── negative — forbidden raw form data in Debug ────────────────────────────────

#[test]
fn form_field_debug_omits_authentication_names_and_values() {
    for grammar in FORM_GRAMMARS {
        let reader = form_reader_at_file(grammar);
        for (field, (name, value)) in reader.fields().iter().zip(FORM_FIELDS) {
            for rendered in [format!("{field:?}"), format!("{field:#?}")] {
                assert_debug_omits(&rendered, &[name, value]);
                assert!(rendered.contains("FormField"));
                assert!(rendered.contains(&format!("name_bytes: {}", name.len())));
                assert!(rendered.contains(&format!("value_bytes: {}", value.len())));
            }
        }
    }
}

#[test]
fn form_reader_debug_omits_partial_field_and_part_headers() {
    let name = "partial_name_sentinel";
    let value = "partial_value_sentinel";
    for grammar in FORM_GRAMMARS {
        for suffix in [
            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{FORM_FILENAME}"),
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}"),
        ] {
            let mut reader = FormReader::with_grammar(
                &format!("multipart/form-data; boundary={FORM_BOUNDARY}"),
                FormLimits::default(),
                grammar,
            )
            .expect("partial form fixture");
            assert_eq!(reader.push(format!("--{FORM_BOUNDARY}\r\n{suffix}").as_bytes()), Ok(FormStep::NeedMore));
            for rendered in [format!("{reader:?}"), format!("{reader:#?}")] {
                assert_debug_omits(&rendered, &[FORM_BOUNDARY, FORM_FILENAME, name, value]);
                assert!(rendered.contains("FormReader"));
                assert!(rendered.contains("fields: 0"));
                assert!(rendered.contains(&format!("bytes_seen: {}", reader.bytes_seen())));
            }
        }
    }
}

#[test]
fn form_reader_debug_omits_completed_fields_and_file_lookahead() {
    for grammar in FORM_GRAMMARS {
        let reader = form_reader_at_file(grammar);
        for rendered in [format!("{reader:?}"), format!("{reader:#?}")] {
            for (name, value) in FORM_FIELDS {
                assert_debug_omits(&rendered, &[name, value]);
            }
            assert_debug_omits(&rendered, &[FORM_BOUNDARY, FORM_FILENAME, FORM_CARRY, "FiLe"]);
            assert!(rendered.contains("state: FileReached"));
            assert!(rendered.contains("fields: 4"));
            assert!(rendered.contains(&format!("buffer_bytes: {}", FORM_CARRY.len())));
            assert!(rendered.contains(&format!("bytes_seen: {}", reader.bytes_seen())));
        }
    }
}

#[test]
fn form_file_reader_debug_omits_body_carry_and_scratch() {
    let next = format!("scratch_body_sentinel{}carry_tail_sentinel", "p".repeat(100));
    for grammar in FORM_GRAMMARS {
        let mut file = form_reader_at_file(grammar)
            .into_file(512)
            .expect("file reached under a ceiling");
        for rendered in [format!("{file:?}"), format!("{file:#?}")] {
            assert_debug_omits(&rendered, &[FORM_BOUNDARY, FORM_CARRY]);
            assert!(rendered.contains("FileReader"));
            assert!(rendered.contains("ceiling: 512"));
            assert!(rendered.contains("file_bytes: 0"));
            assert!(rendered.contains(&format!("carry_bytes: {}", FORM_CARRY.len())));
        }
        let mut delivered = Vec::new();
        let mut sink = |bytes: &[u8]| delivered.extend_from_slice(bytes);
        assert_eq!(file.push(next.as_bytes(), &mut sink), Ok(FileStep::NeedMore));
        for rendered in [format!("{file:?}"), format!("{file:#?}")] {
            assert_debug_omits(&rendered, &[FORM_BOUNDARY, FORM_CARRY, "scratch_body_sentinel", "carry_tail_sentinel"]);
            assert!(rendered.contains("tail: Content"));
            assert!(rendered.contains(&format!("file_bytes: {}", file.file_bytes())));
            assert!(rendered.contains(&format!("bytes_seen: {}", file.bytes_seen())));
        }
        file.push(format!("\r\n--{FORM_BOUNDARY}--\r\n").as_bytes(), &mut sink)
            .expect("the file closes");
        assert_eq!(file.finish(), Ok((FORM_CARRY.len() + next.len()) as u64));
        assert_eq!(delivered, format!("{FORM_CARRY}{next}").into_bytes());
    }
}

// ── positive — useful empty-reader diagnostics ────────────────────────────────

#[test]
fn form_debug_preserves_empty_reader_shape() {
    for grammar in FORM_GRAMMARS {
        let reader = FormReader::with_grammar("multipart/form-data; boundary=empty", FormLimits::default(), grammar)
            .expect("empty reader fixture");
        for rendered in [format!("{reader:?}"), format!("{reader:#?}")] {
            assert!(rendered.contains("FormReader"));
            assert!(rendered.contains("fields: 0"));
            assert!(rendered.contains("buffer_bytes: 0"));
            assert!(rendered.contains("bytes_seen: 0"));
        }
    }
}
