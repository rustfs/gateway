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

//! Whether an arbitrary select-restore document survives the trip out and back, on the one wire
//! shape this family can reach.
//!
//! Responsible for: the last family `rustfs/gateway#231` names — `SelectObjectContentRequest`
//! and `RestoreRequest` — with a shape every sibling round-trip property in this workspace does
//! not have to answer for: **neither document is ever emitted by this gateway**. Every other
//! family pairs a `Get*` that writes a document with a `Put*` that reads one, so the identity runs
//! entirely through two generated production codecs. Both `SelectObjectContent` and
//! `RestoreObject` are request-only — nothing in the documented API answers with either shape — so
//! there is no production encoder to pair with the generated decoder here. The property below
//! hand-authors the encoder, in this file, and runs only the generated **decoder** in production
//! code, which is the opposite balance of risk from every sibling file: a sibling property can
//! blame either side of a mismatch on the encoder or the decoder, while this one can only ever be
//! reporting on the decoder, because the encoder is test fixture rather than shipped code.
//! What that still catches: whether the decoder accepts the full grammar it is specified to —
//! the `SelectParameters` nesting shared between the two operations, the one wrapped list this
//! family carries (`OutputLocation.S3Location.UserMetadata`), and the leniency and exclusivity
//! seams between the generated decoder and `ops::shared::{select, restore}`'s validators.
//! NOT responsible for: `S3Location`'s `AccessControlList` (a `Grant`/`Grantee` list whose
//! discriminator is an XML attribute, `acl_roundtrip.rs`'s entire reason for existing) or its
//! `Tagging`/`Encryption` members — including them here would mean re-deriving that attribute
//! grammar a second time from a hand-written encoder with no production counterpart to check it
//! against, which is a correctness risk this file declines to take on for members `shared::restore`
//! itself never inspects. Nor the four status/header behaviours `shared::restore`'s own tests
//! already cover byte for byte. Nor the event-stream response framing, which is
//! `shared::event_stream`'s and carries no request document at all.
//! Upstream: the generated decoders for `SelectObjectContent` and `RestoreObject`, and
//! `ops::shared::{select, restore}`. Downstream: nothing.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::restore::{RestoreRejection, validate_restore};
use rustfs_gateway_core::ops::shared::select::{SelectRejection, validate_select};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{BucketName, dto};

fn accepted(target: &str) -> WireRequest<()> {
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// Escapes text content the hand-written encoders below place between tags. The generated
/// decoder is the thing under test, not this escaper, so it only has to cover the characters the
/// generators below actually sample.
fn esc(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", esc(text))
}

fn decode_select(document: &str) -> Result<dto::SelectObjectContentInput, CodecError> {
    let request = accepted("/photos/key?select&select-type=2");
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::SelectObjectContent::decode(&view, body)
}

fn decode_restore(document: &str) -> Result<dto::RestoreRequest, CodecError> {
    let request = accepted("/photos/key?restore");
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::RestoreObject::decode(&view, body).map(|input| input.restore_request)
}

// ── the fixtures this file compares, and the encoders that write them ──────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum InputFormat {
    Csv,
    Json,
    Parquet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OutputFormat {
    Csv,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectFixture {
    expression: String,
    input: InputFormat,
    compression: Option<&'static str>,
    output: OutputFormat,
    request_progress: Option<bool>,
    scan_range: Option<(Option<i64>, Option<i64>)>,
}

fn encode_select_body(fixture: &SelectFixture) -> String {
    let input = match fixture.input {
        InputFormat::Csv => "<CSV></CSV>".to_owned(),
        InputFormat::Json => "<JSON></JSON>".to_owned(),
        InputFormat::Parquet => "<Parquet></Parquet>".to_owned(),
    };
    let compression = fixture
        .compression
        .map(|value| element("CompressionType", value))
        .unwrap_or_default();
    let output = match fixture.output {
        OutputFormat::Csv => "<CSV></CSV>".to_owned(),
        OutputFormat::Json => "<JSON></JSON>".to_owned(),
    };
    let request_progress = fixture
        .request_progress
        .map(|enabled| {
            format!(
                "<RequestProgress>{}</RequestProgress>",
                element("Enabled", if enabled { "true" } else { "false" })
            )
        })
        .unwrap_or_default();
    let scan_range = fixture
        .scan_range
        .map(|(start, end)| {
            let start = start.map(|value| element("Start", &value.to_string())).unwrap_or_default();
            let end = end.map(|value| element("End", &value.to_string())).unwrap_or_default();
            format!("<ScanRange>{start}{end}</ScanRange>")
        })
        .unwrap_or_default();
    format!(
        "<SelectObjectContentRequest>{}<ExpressionType>SQL</ExpressionType><InputSerialization>{input}{compression}</InputSerialization>\
         <OutputSerialization>{output}</OutputSerialization>{request_progress}{scan_range}</SelectObjectContentRequest>",
        element("Expression", &fixture.expression),
    )
}

/// Which of the three formats an `InputSerialization` names, and its compression — the mapping
/// both `select_projection` and `restore_projection` need, since `SelectParameters` carries the
/// identical structure nested inside a `RestoreRequest`.
fn input_format_projection(input: &dto::InputSerialization) -> (InputFormat, Option<&'static str>) {
    let format = if input.csv.is_some() {
        InputFormat::Csv
    } else if input.json.is_some() {
        InputFormat::Json
    } else {
        InputFormat::Parquet
    };
    let compression = input.compression_type.as_ref().map(|value| {
        if *value == dto::CompressionType::GZIP {
            "GZIP"
        } else if *value == dto::CompressionType::BZIP2 {
            "BZIP2"
        } else {
            "NONE"
        }
    });
    (format, compression)
}

/// Which of the two formats an `OutputSerialization` names. The sibling of the function above.
fn output_format_projection(output: &dto::OutputSerialization) -> OutputFormat {
    if output.csv.is_some() {
        OutputFormat::Csv
    } else {
        OutputFormat::Json
    }
}

fn select_projection(input: &dto::SelectObjectContentInput) -> SelectFixture {
    let (format, compression) = input_format_projection(&input.input_serialization);
    SelectFixture {
        expression: input.expression.clone(),
        input: format,
        compression,
        output: output_format_projection(&input.output_serialization),
        request_progress: input.request_progress.as_ref().and_then(|progress| progress.enabled),
        scan_range: input.scan_range.as_ref().map(|range| (range.start, range.end)),
    }
}

fn awkward_expression() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"' _*=]{1,40}"
}

fn select_fixture() -> impl Strategy<Value = SelectFixture> {
    (
        awkward_expression(),
        prop_oneof![Just(InputFormat::Csv), Just(InputFormat::Json), Just(InputFormat::Parquet)],
        prop::option::of(prop_oneof![Just("NONE"), Just("GZIP"), Just("BZIP2")]),
        prop_oneof![Just(OutputFormat::Csv), Just(OutputFormat::Json)],
        prop::option::of(any::<bool>()),
        prop::option::of(prop_oneof![
            (0i64..1000).prop_map(|start| (Some(start), Some(start + 10))),
            (0i64..1000).prop_map(|start| (Some(start), None)),
            (1i64..1000).prop_map(|end| (None, Some(end))),
        ]),
    )
        .prop_map(|(expression, input, compression, output, request_progress, scan_range)| SelectFixture {
            expression,
            input,
            compression,
            output,
            request_progress,
            scan_range,
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MetadataPair {
    name: String,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RestoreFixture {
    Days {
        days: i32,
        tier: Option<&'static str>,
        description: Option<String>,
    },
    Select {
        select: SelectFixture,
        bucket_name: String,
        prefix: String,
        user_metadata: Vec<MetadataPair>,
    },
}

fn encode_restore_body(fixture: &RestoreFixture) -> String {
    match fixture {
        RestoreFixture::Days { days, tier, description } => {
            let tier = tier.map(|value| element("Tier", value)).unwrap_or_default();
            let description = description
                .as_ref()
                .map(|value| element("Description", value))
                .unwrap_or_default();
            format!(
                "<RestoreRequest>{}{tier}{description}</RestoreRequest>",
                element("Days", &days.to_string())
            )
        }
        RestoreFixture::Select {
            select,
            bucket_name,
            prefix,
            user_metadata,
        } => {
            // `Prefix` is a required member of `S3Location`, unlike every other member here.
            let prefix = element("Prefix", prefix);
            let metadata = if user_metadata.is_empty() {
                String::new()
            } else {
                let entries: String = user_metadata
                    .iter()
                    .map(|pair| {
                        format!(
                            "<MetadataEntry>{}{}</MetadataEntry>",
                            element("Name", &pair.name),
                            element("Value", &pair.value)
                        )
                    })
                    .collect();
                format!("<UserMetadata>{entries}</UserMetadata>")
            };
            let select_body = encode_select_body(select);
            // `SelectParameters` carries the same four members as a plain select request, minus
            // the envelope: strip the root tag the plain-select encoder writes and keep the rest.
            let select_inner = select_body
                .strip_prefix("<SelectObjectContentRequest>")
                .and_then(|rest| rest.strip_suffix("</SelectObjectContentRequest>"))
                .expect("the select encoder always writes its own envelope");
            format!(
                "<RestoreRequest><Type>SELECT</Type><SelectParameters>{select_inner}</SelectParameters>\
                 <OutputLocation><S3>{}{prefix}{metadata}</S3></OutputLocation></RestoreRequest>",
                element("BucketName", bucket_name),
            )
        }
    }
}

fn restore_projection(request: &dto::RestoreRequest) -> Option<RestoreFixture> {
    if let Some(days) = request.days {
        return Some(RestoreFixture::Days {
            days,
            tier: request.tier.as_ref().map(|tier| {
                if *tier == dto::Tier::EXPEDITED {
                    "Expedited"
                } else if *tier == dto::Tier::BULK {
                    "Bulk"
                } else {
                    "Standard"
                }
            }),
            description: request.description.clone(),
        });
    }
    let parameters = request.select_parameters.as_ref()?;
    let location = request.output_location.as_ref()?.s3.as_ref()?;
    let (input, compression) = input_format_projection(&parameters.input_serialization);
    Some(RestoreFixture::Select {
        select: SelectFixture {
            expression: parameters.expression.clone(),
            input,
            compression,
            output: output_format_projection(&parameters.output_serialization),
            request_progress: None,
            scan_range: None,
        },
        bucket_name: location.bucket_name.as_str().to_owned(),
        prefix: location.prefix.clone(),
        user_metadata: location
            .user_metadata
            .iter()
            .map(|entry| MetadataPair {
                name: entry.name.clone().unwrap_or_default(),
                value: entry.value.clone().unwrap_or_default(),
            })
            .collect(),
    })
}

fn tier_name() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("Expedited"), Just("Standard"), Just("Bulk")]
}

fn bucket_name_text() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{1,19}[a-z0-9]".prop_filter("the fixture only emits legal AWS bucket names", |name| {
        BucketName::new(name.clone()).is_ok()
    })
}

fn metadata_pair() -> impl Strategy<Value = MetadataPair> {
    ("[a-zA-Z0-9-]{1,16}", "[a-zA-Z0-9&<>\"' _-]{0,24}").prop_map(|(name, value)| MetadataPair { name, value })
}

fn restore_days_fixture() -> impl Strategy<Value = RestoreFixture> {
    (1i32..3650, prop::option::of(tier_name()), prop::option::of("[a-zA-Z0-9&<>\"' _-]{0,32}"))
        .prop_map(|(days, tier, description)| RestoreFixture::Days { days, tier, description })
}

fn restore_select_fixture() -> impl Strategy<Value = RestoreFixture> {
    (
        select_fixture(),
        bucket_name_text(),
        "[a-zA-Z0-9/_-]{0,16}",
        prop::collection::vec(metadata_pair(), 0..3),
    )
        .prop_map(|(mut select, bucket_name, prefix, user_metadata)| {
            // `SelectParameters` carries no `RequestProgress` or `ScanRange` on the wire — see
            // the module note — so a fixture destined for the select-restore form never asks the
            // encoder to write either, keeping the projection's comparison total.
            select.request_progress = None;
            select.scan_range = None;
            RestoreFixture::Select {
                select,
                bucket_name,
                prefix,
                user_metadata,
            }
        })
}

// ── the properties ──────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever a `SelectObjectContentRequest` says, the generated decoder reads it back as the
    /// same request — one of three input formats, one of two output formats, the compression
    /// switch, the progress flag and the scan-range window, all preserved.
    #[test]
    fn a_select_request_survives_decode(fixture in select_fixture()) {
        let document = encode_select_body(&fixture);
        let input = decode_select(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this fixture wrote is one the decoder must read: {error:?}: {document}"))
        })?;
        prop_assert_eq!(select_projection(&input), fixture, "document: {}", document);
    }

    /// Whatever a `RestoreRequest` says — either documented form — the generated decoder reads it
    /// back the same way, including the `SelectParameters` nesting the two operations share and
    /// the `UserMetadata` wrapper the request's one wrapped list requires.
    #[test]
    fn a_restore_request_survives_decode(fixture in prop_oneof![restore_days_fixture(), restore_select_fixture()]) {
        let document = encode_restore_body(&fixture);
        let request = decode_restore(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this fixture wrote is one the decoder must read: {error:?}: {document}"))
        })?;
        prop_assert_eq!(restore_projection(&request), Some(fixture), "document: {}", document);
    }
}

// ── boundaries the property reaches only by luck ────────────────────────────────────────────

/// The Restore fixture must not emit the reserved `xn--` bucket prefix that the decoder correctly
/// refuses under the current AWS general-purpose bucket naming rules.
///
/// The fixed seed is the counterexample from rustfs/gateway#632. Replaying the actual fixture
/// strategy, rather than only asserting the validator, keeps the generator half of the contract
/// independently falsifiable when its regular expression changes.
#[test]
fn n_restore_bucket_generator_excludes_reserved_xn_prefix() {
    assert!(BucketName::new("xn--0").is_err(), "xn-- is an AWS-reserved bucket prefix");

    let seed = [
        0x0e, 0x02, 0x42, 0x59, 0xc7, 0x36, 0x17, 0x0b, 0xee, 0x0f, 0x27, 0xd6, 0x91, 0x93, 0xbe, 0x63, 0x31, 0x44, 0x9c, 0xf9,
        0xdb, 0x21, 0x9e, 0x05, 0x53, 0x39, 0x59, 0x8f, 0x96, 0x22, 0x8c, 0x6c,
    ];
    let mut runner = TestRunner::new_with_rng(
        Config {
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );
    let strategy = prop_oneof![restore_days_fixture(), restore_select_fixture()];
    let case = strategy
        .new_tree(&mut runner)
        .expect("the fixed fixture seed generates a case");
    runner
        .run_one(case, |fixture| {
            let document = encode_restore_body(&fixture);
            let request = decode_restore(&document).map_err(|error| {
                TestCaseError::fail(format!(
                    "a document this fixture wrote is one the decoder must read: {error:?}: {document}"
                ))
            })?;
            prop_assert_eq!(restore_projection(&request), Some(fixture), "document: {}", document);
            Ok(())
        })
        .expect("the Restore fixture only generates bucket names its decoder accepts");
}

/// A realistic select-on-restore document decodes and passes both layers of validation — the
/// generated decoder's syntax and `validate_restore`'s (which calls `validate_select` on the
/// nested members with the identical rules a plain select uses).
#[test]
fn a_realistic_select_on_restore_document_is_accepted_by_both_layers() {
    let fixture = RestoreFixture::Select {
        select: SelectFixture {
            expression: "SELECT * FROM S3Object".to_owned(),
            input: InputFormat::Csv,
            compression: Some("NONE"),
            output: OutputFormat::Csv,
            request_progress: None,
            scan_range: None,
        },
        bucket_name: "results".to_owned(),
        prefix: "out/".to_owned(),
        user_metadata: vec![MetadataPair {
            name: "origin".to_owned(),
            value: "nightly".to_owned(),
        }],
    };
    let request = decode_restore(&encode_restore_body(&fixture)).expect("decodes");
    assert_eq!(validate_restore(&request), Ok(()));
}

// ── negative: shapes and values that must not survive ───────────────────────────────────────

/// A document rooted at anything else is refused rather than skimmed for familiar element names.
/// `SelectRequest`, MinIO's root, is the one alias the decoder admits (q-select-0008), so the
/// wrong root here is the operation's own name — and the alias is pinned as accepted beside it.
#[test]
fn n_a_select_document_under_another_root_is_refused() {
    let document = "<SelectObjectContent><Expression>SELECT 1</Expression></SelectObjectContent>";
    let error = decode_select(document).expect_err("the wire roots are SelectObjectContentRequest and SelectRequest");
    assert_eq!(error.code(), &rustfs_gateway_types::ErrorCode::MALFORMED_XML, "{error:?}");
    assert!(error.message().contains("root"), "{error:?}");

    let alias = "<SelectRequest><Expression>SELECT 1</Expression></SelectRequest>";
    let refused = decode_select(alias).expect_err("the alias root is read; the members are then judged");
    assert!(!refused.message().contains("root"), "the alias root is not the refusal: {refused:?}");
}

/// Same for a restore document: the read side of `q-restore-root-namespace-0137`'s local-name
/// matching is that a genuinely different name is still refused.
#[test]
fn n_a_restore_document_under_another_root_is_refused() {
    let document = "<RetrievalRequest><Days>1</Days></RetrievalRequest>";
    let error = decode_restore(document).expect_err("the wire root is RestoreRequest");
    assert_eq!(error.member(), Some("RestoreRequest"), "{error:?}");
}

/// An empty body is refused rather than read as a request with every member defaulted
/// (`q-restore-0006`): the payload member is promoted to required.
#[test]
fn n_an_empty_restore_body_is_not_an_empty_request() {
    assert!(decode_restore("").is_err(), "an empty body is not a restore request");
}

/// Unknown elements are skipped rather than refused (`q-select-0007`), and the half that
/// matters: an unknown element does not survive into the decoded request, so re-inspecting a
/// document with one added never conjures a member that was never sent.
#[test]
fn n_an_unknown_select_element_is_skipped_and_carries_no_member() {
    let document = "<SelectObjectContentRequest><Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
                    <InputSerialization><CSV></CSV></InputSerialization><OutputSerialization><CSV></CSV></OutputSerialization>\
                    <Vendor>acme</Vendor></SelectObjectContentRequest>";
    let input = decode_select(document).expect("an unknown element is skipped, not refused");
    assert_eq!(input.expression, "SELECT 1");
}

/// The same leniency on the restore side (`q-restore-0007`).
#[test]
fn n_an_unknown_restore_element_is_skipped() {
    let document = "<RestoreRequest><Days>3</Days><Vendor>acme</Vendor></RestoreRequest>";
    let request = decode_restore(document).expect("an unknown element is skipped, not refused");
    assert_eq!(request.days, Some(3));
}

/// The one wrapped list this family carries: a `MetadataEntry` repeated directly under `S3`,
/// without the `<UserMetadata>` wrapper, is not read as metadata at all — the same silent-drop
/// shape `website_roundtrip.rs` names for `RoutingRules`, reached here through a document that
/// still decodes (leniency skips the unwrapped elements) rather than one that is refused.
#[test]
fn n_metadata_outside_the_wrapper_is_not_read_as_metadata() {
    let document = "<RestoreRequest><Type>SELECT</Type>\
                    <SelectParameters><Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
                    <InputSerialization><CSV></CSV></InputSerialization><OutputSerialization><CSV></CSV></OutputSerialization>\
                    </SelectParameters><OutputLocation><S3><BucketName>results</BucketName><Prefix></Prefix>\
                    <MetadataEntry><Name>origin</Name><Value>nightly</Value></MetadataEntry>\
                    </S3></OutputLocation></RestoreRequest>";
    let request = decode_restore(document).expect("the decoder does not require the wrapper to parse");
    let location = request
        .output_location
        .as_ref()
        .and_then(|location| location.s3.as_ref())
        .expect("S3 decodes");
    assert!(
        location.user_metadata.is_empty(),
        "an unwrapped MetadataEntry must not be read as metadata: {:?}",
        location.user_metadata
    );
}

/// `Days` beside a `SELECT` form decodes — the generated decoder does not enforce the exclusion
/// — and is refused by `validate_restore` rather than silently preferring one form
/// (`q-restore-days-select-0130`). Decode succeeding and validation refusing are two different
/// facts, and this is the seam between them.
#[test]
fn n_days_beside_select_survives_the_decoder_and_is_refused_after() {
    let document = "<RestoreRequest><Days>3</Days><Type>SELECT</Type>\
                    <SelectParameters><Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
                    <InputSerialization><CSV></CSV></InputSerialization><OutputSerialization><CSV></CSV></OutputSerialization>\
                    </SelectParameters><OutputLocation><S3><BucketName>results</BucketName><Prefix></Prefix></S3>\
                    </OutputLocation></RestoreRequest>";
    let request = decode_restore(document).expect("the decoder does not enforce the exclusion");
    assert_eq!(request.days, Some(3));
    assert!(request.select_parameters.is_some());
    assert_eq!(validate_restore(&request), Err(RestoreRejection::DaysWithSelect));
}

/// Two `InputSerialization` formats at once survives the decoder for the identical reason
/// (`q-select-0003`), refused by `validate_select` rather than the codec picking one.
#[test]
fn n_two_input_formats_survive_the_decoder_and_are_refused_after() {
    let document = "<SelectObjectContentRequest><Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
                    <InputSerialization><CSV></CSV><JSON></JSON></InputSerialization>\
                    <OutputSerialization><CSV></CSV></OutputSerialization></SelectObjectContentRequest>";
    let input = decode_select(document).expect("the decoder does not enforce the exclusion");
    assert!(input.input_serialization.csv.is_some() && input.input_serialization.json.is_some());
    assert_eq!(
        validate_select(
            &input.expression,
            &input.expression_type,
            &input.input_serialization,
            &input.output_serialization,
            None,
        ),
        Err(SelectRejection::InputSerializationAmbiguous)
    );
}

/// An empty `ScanRange` — neither `Start` nor `End` — survives the decoder and is refused by
/// `validate_select` (`q-select-0005`), the same layering as the two cases above.
#[test]
fn n_an_empty_scan_range_survives_the_decoder_and_is_refused_after() {
    let document = "<SelectObjectContentRequest><Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
                    <InputSerialization><CSV></CSV></InputSerialization><OutputSerialization><CSV></CSV></OutputSerialization>\
                    <ScanRange></ScanRange></SelectObjectContentRequest>";
    let input = decode_select(document).expect("the decoder does not enforce the exclusion");
    let range = input.scan_range.expect("ScanRange decodes as present");
    assert_eq!(
        validate_select(
            &input.expression,
            &input.expression_type,
            &input.input_serialization,
            &input.output_serialization,
            Some(&range),
        ),
        Err(SelectRejection::ScanRangeEmpty)
    );
}

/// A document with neither documented form — no `Days`, no `Type SELECT` — decodes to a request
/// naming neither, and `validate_restore` is the layer that refuses it
/// (`q-restore-form-required-0129`).
#[test]
fn n_a_document_with_neither_form_survives_the_decoder_and_is_refused_after() {
    let document = "<RestoreRequest><Description>rehydrate</Description></RestoreRequest>";
    let request = decode_restore(document).expect("a description alone still decodes");
    assert_eq!(validate_restore(&request), Err(RestoreRejection::FormMissing));
}
