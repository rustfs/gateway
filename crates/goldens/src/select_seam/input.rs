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

//! Select request conversion checked against independently decoded public inputs.
//!
//! Responsible for: nested presence, header readings, explicit name policy and field coverage.
//! NOT responsible for: query execution, authorization timing or native RustFS assembly.
//! Upstream: public codec/service measurements. Downstream: the three-revision migration gate.

macro_rules! define_tests {
    ($name:ident, $revision:ident) => {
        mod $name {
            use bytes::Bytes;
            use rustfs_gateway_core::{
                codec::{MetaView, OperationCodec, RequestBody},
                route::TargetKind,
            };
            use rustfs_gateway_http::{Limits, WireRequest};
            use rustfs_gateway_types::compat::$revision as seam;
            use rustfs_gateway_types::{NamePolicy, NameValidator, SlashPolicy, Stricter, dto};
            use seam::s3s::{self, S3, S3Request, S3Response, S3Result, dto as legacy};
            use std::{
                future::Future,
                pin::Pin,
                sync::{Arc, Mutex},
                task::{Context, Poll, Wake, Waker},
            };

            const MINIMAL: &str = "<SelectObjectContentRequest><Expression>x</Expression><ExpressionType>SQL</ExpressionType><InputSerialization/><OutputSerialization/></SelectObjectContentRequest>";
            const EMPTY: &str = "<SelectObjectContentRequest><Expression>x</Expression><ExpressionType>SQL</ExpressionType><InputSerialization><CSV/><JSON/><Parquet/></InputSerialization><OutputSerialization><CSV/><JSON/></OutputSerialization><RequestProgress/><ScanRange/></SelectObjectContentRequest>";
            const FULL: &str = "<SelectObjectContentRequest><Expression>x &amp; y</Expression><ExpressionType>SQL</ExpressionType><InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo><Comments></Comments><QuoteEscapeCharacter>!</QuoteEscapeCharacter><RecordDelimiter>&#10;</RecordDelimiter><FieldDelimiter>|</FieldDelimiter><QuoteCharacter>&quot;</QuoteCharacter><AllowQuotedRecordDelimiter>false</AllowQuotedRecordDelimiter></CSV><CompressionType>GZIP</CompressionType><JSON><Type>LINES</Type></JSON><Parquet/></InputSerialization><OutputSerialization><CSV><QuoteFields>ALWAYS</QuoteFields><QuoteEscapeCharacter>!</QuoteEscapeCharacter><RecordDelimiter>&#13;</RecordDelimiter><FieldDelimiter>;</FieldDelimiter><QuoteCharacter>'</QuoteCharacter></CSV><JSON><RecordDelimiter></RecordDelimiter></JSON></OutputSerialization><RequestProgress><Enabled>false</Enabled></RequestProgress><ScanRange><Start>-7</Start><End>9223372036854775807</End></ScanRange></SelectObjectContentRequest>";

            fn block_on<F: Future>(future: F) -> F::Output {
                struct Thread(std::thread::Thread);
                impl Wake for Thread {
                    fn wake(self: Arc<Self>) {
                        self.0.unpark();
                    }
                }
                let waker = Waker::from(Arc::new(Thread(std::thread::current())));
                let mut context = Context::from_waker(&waker);
                let mut future = std::pin::pin!(future);
                loop {
                    match future.as_mut().poll(&mut context) {
                        Poll::Ready(value) => return value,
                        Poll::Pending => std::thread::park(),
                    }
                }
            }
            fn head(body: &str, header: Option<&str>) -> http::request::Builder {
                let mut head = http::Request::builder()
                    .method("POST")
                    .uri("/bkt/key?select&select-type=2")
                    .header("host", "host.invalid")
                    .header("content-type", "application/xml")
                    .header("content-length", body.len());
                if let Some(value) = header {
                    for name in [
                        "x-amz-server-side-encryption-customer-algorithm",
                        "x-amz-server-side-encryption-customer-key",
                        "x-amz-server-side-encryption-customer-key-md5",
                        "x-amz-expected-bucket-owner",
                    ] {
                        head = head.header(name, value);
                    }
                }
                head
            }
            fn owned(body: &str, header: Option<&str>) -> dto::SelectObjectContentInput {
                let wire = WireRequest::accept(head(body, header).body(()).unwrap(), &Limits::default()).unwrap();
                let view = MetaView::of(&wire, TargetKind::Object).unwrap();
                dto::SelectObjectContent::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(body.as_bytes())))
                    .expect("owned fixture decodes")
            }
            struct Capture(Arc<Mutex<Option<legacy::SelectObjectContentInput>>>);
            impl S3 for Capture {
                fn select_object_content<'life0, 'future>(
                    &'life0 self,
                    request: S3Request<legacy::SelectObjectContentInput>,
                ) -> Pin<Box<dyn Future<Output = S3Result<S3Response<legacy::SelectObjectContentOutput>>> + Send + 'future>>
                where
                    'life0: 'future,
                    Self: 'future,
                {
                    *self.0.lock().unwrap() = Some(request.input);
                    Box::pin(async { Ok(S3Response::new(Default::default())) })
                }
            }
            fn legacy(body: &str, header: Option<&str>) -> legacy::SelectObjectContentInput {
                let slot = Arc::new(Mutex::new(None));
                let service = s3s::service::S3ServiceBuilder::new(Capture(Arc::clone(&slot))).build();
                let request = head(body, header)
                    .body(s3s::Body::from(Bytes::copy_from_slice(body.as_bytes())))
                    .unwrap();
                let _response = block_on(service.call(request)).expect("legacy service accepts fixture");
                slot.lock().unwrap().take().expect("legacy handler receives fixture")
            }
            fn legacy_view(input: &legacy::SelectObjectContentInput, key: Option<&str>) -> serde_json::Value {
                serde_json::json!({"request": format!("{:?}", input.request), "bucket": input.bucket, "key": input.key,
                                    "algorithm": input.sse_customer_algorithm, "md5": input.sse_customer_key_md5, "owner": input.expected_bucket_owner,
                                    "secret_matches": input.sse_customer_key.as_deref() == key})
            }
            fn owned_view(input: &dto::SelectObjectContentInput, key: Option<&str>) -> serde_json::Value {
                serde_json::json!({"request": format!("{:?}", (&input.expression, &input.expression_type, &input.input_serialization, &input.output_serialization, &input.request_progress, &input.scan_range)),
                                    "bucket": input.bucket.as_str(), "key": input.key.as_str(), "algorithm": input.sse_customer_algorithm,
                                    "md5": input.sse_customer_key_md5, "owner": input.expected_bucket_owner,
                                    "secret_matches": input.sse_customer_key.as_ref().map(|value| value.expose_secret()) == key})
            }

            fn cases() -> Vec<(dto::SelectObjectContentInput, legacy::SelectObjectContentInput)> {
                let truthy = FULL
                    .replace("false", "true")
                    .replace("<Start>-7</Start>", "<Start>-9223372036854775808</Start>");
                let mut cases = [MINIMAL, EMPTY, FULL, truthy.as_str()]
                    .into_iter()
                    .map(|body| (owned(body, Some("fixture")), legacy(body, Some("fixture"))))
                    .collect::<Vec<_>>();
                for spelling in ["FUTURE", ""] {
                    let mut left = owned(FULL, Some("fixture"));
                    let mut right = legacy(FULL, Some("fixture"));
                    left.expression_type = dto::ExpressionType::custom(spelling);
                    right.request.expression_type = legacy::ExpressionType::from(spelling.to_owned());
                    left.input_serialization.compression_type = Some(dto::CompressionType::custom(spelling));
                    right.request.input_serialization.compression_type = Some(legacy::CompressionType::from(spelling.to_owned()));
                    left.input_serialization.csv.as_mut().unwrap().file_header_info = Some(dto::FileHeaderInfo::custom(spelling));
                    right.request.input_serialization.csv.as_mut().unwrap().file_header_info =
                        Some(legacy::FileHeaderInfo::from(spelling.to_owned()));
                    left.input_serialization.json.as_mut().unwrap().r#type = Some(dto::Type::custom(spelling));
                    right.request.input_serialization.json.as_mut().unwrap().type_ = Some(legacy::JSONType::from(spelling.to_owned()));
                    left.output_serialization.csv.as_mut().unwrap().quote_fields = Some(dto::QuoteFields::custom(spelling));
                    right.request.output_serialization.csv.as_mut().unwrap().quote_fields =
                        Some(legacy::QuoteFields::from(spelling.to_owned()));
                    cases.push((left, right));
                }
                cases
            }

            /// Positive — independently decoded inputs agree after conversion, including empty structures.
            #[test]
            fn input_to_legacy_preserves_nested_values() {
                for (input, expected) in cases() {
                    let actual = seam::select::input_to_s3s(input);
                    assert_eq!(legacy_view(&actual, Some("fixture")), legacy_view(&expected, Some("fixture")));
                }
            }
            /// Positive — reverse conversion preserves the values without relying on a round trip.
            #[test]
            fn input_from_legacy_preserves_nested_values() {
                for (expected, input) in cases() {
                    let actual =
                        seam::select::input_from_s3s(input, &NamePolicy::default()).map(|input| owned_view(&input, Some("fixture")));
                    assert_eq!(actual, Ok(owned_view(&expected, Some("fixture"))));
                }
            }
            /// Negative — empty HTTP headers are absent, but whitespace is not trimmed.
            #[test]
            fn input_to_legacy_keeps_the_measured_header_reading() {
                for header in [None, Some(""), Some(" "), Some("fixture")] {
                    let expected = legacy(MINIMAL, header);
                    let key = header.filter(|value| !value.is_empty());
                    let actual = seam::select::input_to_s3s(owned(MINIMAL, header));
                    assert_eq!(legacy_view(&actual, key), legacy_view(&expected, key));
                }
            }
            /// Negative — explicit emptiness in an already constructed DTO is not erased on reverse conversion.
            #[test]
            fn input_from_legacy_preserves_explicit_empty_header_members() {
                let mut input = legacy(MINIMAL, None);
                input.sse_customer_algorithm = Some(String::new());
                input.sse_customer_key = Some(String::new());
                input.sse_customer_key_md5 = Some(String::new());
                input.expected_bucket_owner = Some(String::new());
                let actual = seam::select::input_from_s3s(input, &NamePolicy::default()).map(|input| owned_view(&input, Some("")));
                assert_eq!(actual, Ok(owned_view(&owned(MINIMAL, Some("")), Some(""))));
            }
            struct DeploymentNames;
            impl NameValidator for DeploymentNames {
                fn check_bucket(&self, _: &str) -> Stricter {
                    Stricter::NoOpinion
                }
                fn check_key(&self, _: &str) -> Stricter {
                    Stricter::NoOpinion
                }
            }
            /// Negative — decoded names must not be decoded or normalized again, or forced through AWS policy.
            #[test]
            fn input_from_legacy_uses_explicit_policy_without_decoding() {
                let policy = NamePolicy::new(SlashPolicy::Collapse, Arc::new(DeploymentNames)).with_legacy_rustfs_key_floor();
                for key in ["a%2Fb", "a//b", "a/../b", "a\\b", "a\u{1}b"] {
                    let mut input = legacy(MINIMAL, None);
                    input.bucket = "Legacy_Bucket".to_owned();
                    input.key = key.to_owned();
                    let actual = seam::select::input_from_s3s(input, &policy)
                        .map(|input| (input.bucket.as_str().to_owned(), input.key.as_str().to_owned()));
                    assert_eq!(actual, Ok(("Legacy_Bucket".to_owned(), key.to_owned())));
                }
            }
            /// Negative — policy refusals name the member; already-decoded escape text remains literal.
            #[test]
            fn input_from_legacy_matches_the_requested_name_policy() {
                let long = "x".repeat(1025);
                let cases = [
                    ("", "key", "bucket"),
                    ("ab", "key", "bucket"),
                    ("Bad_Bucket", "key", "bucket"),
                    ("/bkt", "key", "bucket"),
                    ("bkt%32", "key", "bucket"),
                    ("-bkt", "key", "bucket"),
                    ("bkt-", "key", "bucket"),
                    (".bkt", "key", "bucket"),
                    ("bkt.", "key", "bucket"),
                    ("a..b", "key", "bucket"),
                    ("bkt\0", "key", "bucket"),
                    ("a_b", "key", "bucket"),
                    ("bkt", "", "key"),
                    ("bkt", long.as_str(), "key"),
                    ("bkt", "a\0b", "key"),
                    ("bkt", "../a", "key"),
                    ("bkt", "a/../b", "key"),
                    ("bkt", "a%2Fb", ""),
                    ("bkt", "a%5Cb", ""),
                    ("bkt", "a\\b", ""),
                    ("bkt", "C:/drive", "key"),
                    ("bkt", "a\u{1}b", "key"),
                    ("/bkt", "a\0b", "bucket"),
                    (" bkt", "key", "bucket"),
                    ("\\bkt", "key", "bucket"),
                    ("bkt", "//server/share", "key"),
                    ("bkt", "\\server", "key"),
                    ("bkt", "a\u{7f}b", "key"),
                    ("bkt", "a/../../b", "key"),
                ];
                for (bucket, key, field) in cases {
                    let mut input = legacy(MINIMAL, None);
                    input.bucket = bucket.to_owned();
                    input.key = key.to_owned();
                    let result = seam::select::input_from_s3s(input, &NamePolicy::default());
                    let actual = match result {
                        Ok(input) => ("", Some(input.key.as_str().to_owned())),
                        Err(error) => (error.field, None),
                    };
                    let expected = (field, field.is_empty().then(|| key.to_owned()));
                    assert_eq!(actual, expected, "{bucket:?}/{key:?}");
                }
            }
            /// Negative — a new owned input member cannot escape the explicit conversion census.
            #[test]
            fn the_input_seam_declares_every_owned_member() {
                let counts =
                    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/dto/field_counts.txt")).unwrap();
                let count: usize = counts
                    .lines()
                    .find_map(|line| {
                        let (name, count) = line.split_once(' ')?;
                        (name == "SelectObjectContentInput").then(|| count.trim().parse().unwrap())
                    })
                    .unwrap();
                let members = seam::select::GATEWAY_INPUT_MEMBERS;
                assert_eq!(
                    (members, count),
                    (
                        &[
                            "bucket",
                            "key",
                            "sse_customer_algorithm",
                            "sse_customer_key",
                            "sse_customer_key_md5",
                            "expression",
                            "expression_type",
                            "request_progress",
                            "input_serialization",
                            "output_serialization",
                            "scan_range",
                            "expected_bucket_owner"
                        ][..],
                        members.len()
                    )
                );
            }
        }
    };
}

define_tests!(release, s3s_0_17_0);
define_tests!(rustfs, s3s_5761ddfe);
define_tests!(baseline, s3s_9c4690d8);
