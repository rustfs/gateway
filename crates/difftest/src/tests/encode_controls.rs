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

//! Encode negative controls: the gateway's answer broken on purpose, and each break reported as
//! the finding it is and refused by the register; the normaliser's formats held both ways.
//!
//! Responsible for: a-df-0011 (element order), a-df-0012 (`xmlns`), a-df-0013 (empty-element
//! spelling), a-df-0014 (an upload id re-encoded: the placeholder hides the value, the format
//! check does not), a-df-0015 (an unregistered header), a-df-0004 (the request id's format),
//! a-df-0005 (the deterministic placeholder body), and every format's positive and negative cases.
//! NOT responsible for: the sample matrix (`encoding.rs`).
//! Upstream: the samples and the encode faults. Downstream: none.

use crate::decode::Fault;
use crate::encode::{WireAnswer, compare, respell_first_empty_element, swap_first_two_children};
use crate::normalize::{Format, Side};
use crate::{Differ, EncodeDiff, Item, KnownDiffs};

fn sample(name: &str) -> crate::OutputSample {
    super::encoding::all_rows()
        .into_iter()
        .find(|row| row.sample.name == name)
        .unwrap_or_else(|| panic!("no sample {name}"))
        .sample
}

fn encoded(fault: Fault, name: &str) -> EncodeDiff {
    Differ::with_fault(fault)
        .expect("both stacks build")
        .encode(&sample(name))
        .expect("the harness runs")
}

/// The findings the register does not accept.
fn unregistered(diff: &EncodeDiff) -> Vec<Item> {
    KnownDiffs::checked_in()
        .expect("parses")
        .verdict(diff.findings())
        .failures
        .into_iter()
        .map(|finding| finding.item)
        .collect()
}

/// Negative (a-df-0011) — a gateway that writes the root's first two children the other way round
/// is an element-order finding no entry accepts.
#[test]
fn reordered_elements_are_an_unregistered_order_finding() {
    let diff = encoded(Fault::GatewayXmlElementsReordered, "list-objects-v2-full");
    assert_eq!(unregistered(&diff), [Item::BodyOrder("ListBucketResult".to_owned())]);
    assert!(unregistered(&encoded(Fault::None, "list-objects-v2-full")).is_empty());
}

/// Negative (a-df-0012) — a gateway that drops the root's `xmlns` is an element finding.
#[test]
fn a_dropped_xmlns_is_an_unregistered_element_finding() {
    let diff = encoded(Fault::GatewayXmlnsDropped, "list-objects-v2-full");
    assert_eq!(unregistered(&diff), [Item::BodyElement("ListBucketResult".to_owned())]);
    let finding = diff
        .findings()
        .into_iter()
        .find(|finding| finding.item == Item::BodyElement("ListBucketResult".to_owned()));
    assert_eq!(finding.map(|finding| finding.gateway), Some("<ListBucketResult>".to_owned()));
}

/// Negative (a-df-0013) — `<Prefix></Prefix>` written as `<Prefix/>` is an element finding, though
/// an XML reader would read the two the same.
#[test]
fn a_respelled_empty_element_is_an_unregistered_element_finding() {
    let diff = encoded(Fault::GatewayEmptyElementRespelled, "list-objects-v2-empty");
    assert_eq!(unregistered(&diff), [Item::BodyElement("ListBucketResult/Prefix".to_owned())]);
}

/// Negative (a-df-0014) — an upload id re-encoded as hex fails twice: its value differs from the
/// one s3s wrote from the same output, and it no longer has the format RustFS mints. Neither is
/// normalised away — an upload id comes from the output both stacks were handed.
#[test]
fn a_re_encoded_upload_id_fails_its_value_and_its_format() {
    let diff = encoded(Fault::GatewayUploadIdAsHex, "create-multipart-upload");
    assert_eq!(
        unregistered(&diff),
        [
            Item::BodyElement("InitiateMultipartUploadResult/UploadId".to_owned()),
            Item::Format("xml UploadId".to_owned())
        ]
    );
    let failed: Vec<_> = diff.assertions.iter().filter(|assertion| !assertion.holds).collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].side, Side::Gateway);
    assert_eq!(failed[0].format, Format::UploadId);
    let unbroken = encoded(Fault::None, "create-multipart-upload");
    assert!(
        unbroken
            .assertions
            .iter()
            .any(|assertion| assertion.field == "xml UploadId" && assertion.holds)
    );
    assert!(unregistered(&unbroken).is_empty());
}

/// Negative (a-df-0015) — a header no entry names fails; the difference is not tolerated because it
/// is only a header.
#[test]
fn an_extra_header_is_an_unregistered_header_finding() {
    let diff = encoded(Fault::GatewayExtraHeader, "put-object");
    assert_eq!(unregistered(&diff), [Item::Header("x-amz-difftest-extra".to_owned())]);
}

/// Negative (a-df-0004) — the request id is replaced by a placeholder and its format asserted: a
/// lowercase id fails the format while the placeholder still matches.
#[test]
fn a_malformed_request_id_fails_its_format_behind_the_placeholder() {
    let diff = encoded(Fault::GatewayRequestIdMalformed, "put-object");
    assert_eq!(unregistered(&diff), [Item::Format("header x-amz-request-id".to_owned())]);
    let unbroken = encoded(Fault::None, "put-object");
    let held = unbroken
        .assertions
        .iter()
        .find(|assertion| assertion.field == "header x-amz-request-id")
        .expect("the gateway stamps a request id");
    assert!(held.holds && held.side == Side::Gateway && held.value.len() == 16);
}

/// Positive (a-df-0005) — a streaming output carries the deterministic placeholder and both stacks
/// write exactly its bytes.
#[test]
fn a_streaming_body_is_the_placeholder_on_both_stacks() {
    let diff = encoded(Fault::None, "get-object-full");
    assert_eq!(diff.body.gateway, b"difftest placeholder streaming body");
    assert!(diff.body.same());
}

/// Negative — an output missing a member the gateway output requires is refused by name, and the
/// register does not accept it.
#[test]
fn an_output_missing_a_required_member_is_an_unregistered_unconvertible() {
    let mut row = sample("list-objects-v2-empty");
    row.output = std::sync::Arc::new(|| {
        crate::OracleOutput::ListObjectsV2(crate::s3s::dto::ListObjectsV2Output {
            prefix: Some(String::new()),
            max_keys: Some(1),
            key_count: Some(0),
            is_truncated: Some(false),
            ..Default::default()
        })
    });
    let diff = Differ::new()
        .expect("both stacks build")
        .encode(&row)
        .expect("the harness runs");
    assert_eq!(diff.unconvertible.as_ref().map(|refused| refused.member), Some("name"));
    assert_eq!(unregistered(&diff), [Item::Unconvertible("name".to_owned())]);
}

fn answer(headers: &[(&str, &str)], body: &[u8]) -> WireAnswer {
    WireAnswer {
        status: 200,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.as_bytes().to_vec()))
            .collect(),
        body: body.to_vec(),
    }
}

/// Negative — a Content-Length that does not match the body its side wrote fails, whichever side.
#[test]
fn a_content_length_that_is_not_the_body_length_fails() {
    for (gateway_length, s3s_length, side) in [("4", "3", Side::Gateway), ("3", "4", Side::S3s)] {
        let diff = compare(
            "PutObject".to_owned(),
            false,
            &mut answer(&[("content-length", gateway_length)], b"abc"),
            &mut answer(&[("content-length", s3s_length)], b"abc"),
        );
        let failed: Vec<_> = diff.assertions.iter().filter(|assertion| !assertion.holds).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].side, side);
    }
}

/// Positive — a Content-Length one side left to its transport is framing, not a difference.
#[test]
fn a_content_length_only_one_side_wrote_is_framing() {
    let diff = compare(
        "PutObject".to_owned(),
        false,
        &mut answer(&[("content-length", "3")], b"abc"),
        &mut answer(&[], b"abc"),
    );
    assert!(diff.findings().is_empty(), "{:?}", diff.findings());
}

/// Negative — hop-by-hop headers are dropped from both sides, and nothing else is.
#[test]
fn only_hop_by_hop_headers_are_dropped() {
    let diff = compare(
        "PutObject".to_owned(),
        false,
        &mut answer(&[("connection", "close"), ("etag", "\"a\"")], b""),
        &mut answer(&[("transfer-encoding", "chunked"), ("etag", "\"b\"")], b""),
    );
    assert_eq!(
        diff.findings().iter().map(|finding| finding.item.clone()).collect::<Vec<_>>(),
        [Item::Header("etag".to_owned())]
    );
}

/// Negative — each format holds for its producer's shape and nothing next to it.
#[test]
fn every_format_refuses_the_shapes_next_to_its_own() {
    let cases: &[(Format, &str, &[&str])] = &[
        (
            Format::RequestId,
            "0123456789ABCDEF",
            &[
                "0123456789abcdef",
                "0123456789ABCDE",
                "0123456789ABCDEFA",
                "0123456789ABCDEG",
                "",
            ],
        ),
        (
            Format::HostId,
            "0123456789ABCDEF0123456789ABCDEF",
            &[
                "0123456789ABCDEF",
                "0123456789abcdef0123456789abcdef",
                "0123456789ABCDEF0123456789ABCDEG",
            ],
        ),
        (
            Format::HttpDate,
            "Thu, 01 Jan 2026 00:00:00 GMT",
            &[
                "Thu, 1 Jan 2026 00:00:00 GMT",
                "2026-01-01T00:00:00Z",
                "Thu, 01 Jan 2026 00:00:00 UTC",
                "Xyz, 01 Jan 2026 00:00:00 GMT",
                "Thu, 01 Foo 2026 00:00:00 GMT",
                "Thu 01 Jan 2026 00:00:00 GMT",
            ],
        ),
        (Format::ServerName, "RustFS", &["", "Rust FS", "Rust\tFS"]),
        (
            Format::VersionId,
            "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0",
            &[
                "0F1E2D3C-4B5A-4978-8796-A5B4C3D2E1F0",
                "0f1e2d3c4b5a49788796a5b4c3d2e1f0",
                "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f",
                "Null",
                "",
            ],
        ),
        (
            Format::UploadId,
            crate::samples::UPLOAD_ID,
            &[
                "",
                "not base64!",
                "ZjNhMWMy",
                "3858f62230ac3c915f300c664312c11f",
                "LjdjMmU5ZjEwLTNiNGEtNGQ1ZS05ZjYwLTcxODI5M2E0YjVjNg",
            ],
        ),
        (
            Format::XmlInstant,
            "2026-01-01T00:00:00.000Z",
            &[
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00.00Z",
                "2026-01-01 00:00:00.000Z",
                "2026-01-01T00:00:00.000+00:00",
                "Thu, 01 Jan 2026 00:00:00 GMT",
            ],
        ),
        (Format::BodyLength(3), "3", &["4", "03x", "", "-3"]),
    ];
    for (format, good, bad) in cases {
        assert!(format.holds(good), "{format:?} should hold for {good:?}");
        for value in *bad {
            assert!(!format.holds(value), "{format:?} held for {value:?}");
        }
    }
    assert!(Format::VersionId.holds("null"));
}

/// Negative — the two XML defects the controls inject are what they claim, in both directions.
#[test]
fn the_injected_xml_defects_do_what_they_say() {
    assert_eq!(swap_first_two_children("<R><A>1</A><B/><C>3</C></R>"), "<R><B/><A>1</A><C>3</C></R>");
    assert_eq!(respell_first_empty_element("<R><A></A><B/></R>"), "<R><A/><B/></R>");
    assert_eq!(respell_first_empty_element("<R><A>x</A><B/></R>"), "<R><A>x</A><B></B></R>");
    assert_eq!(respell_first_empty_element("<R><A>x</A></R>"), "<R><A>x</A></R>");
}

/// Negative — whitespace between elements is a difference at the parent; bytes that differ where
/// the structure cannot (`<B />` and `<B/>`), and any difference in a body that is not XML, are a
/// byte finding.
#[test]
fn whitespace_and_bytes_the_structure_hides_are_still_findings() {
    let cases: [(&[u8], &[u8], Item); 3] = [
        (b"<R><A>1</A></R>", b"<R>\n<A>1</A></R>", Item::BodyElement("R".to_owned())),
        (b"<R><B /></R>", b"<R><B/></R>", Item::Body),
        (b"plain one", b"plain two", Item::Body),
    ];
    for (gateway, s3s, item) in cases {
        let diff = compare("GetBucketLocation".to_owned(), false, &mut answer(&[], gateway), &mut answer(&[], s3s));
        let items: Vec<Item> = diff.findings().into_iter().map(|finding| finding.item).collect();
        assert_eq!(items, [item], "{:?}", String::from_utf8_lossy(gateway));
    }
}

/// Negative — on a HEAD answer Content-Length is content: a side that omits it, or writes another
/// size, is a header finding, never framing.
#[test]
fn a_head_answers_content_length_is_compared_as_content() {
    for (gateway, s3s) in [
        (&[("content-length", "1024")][..], &[][..]),
        (&[("content-length", "1024")][..], &[("content-length", "5")][..]),
    ] {
        let diff = compare("HeadObject".to_owned(), true, &mut answer(gateway, b""), &mut answer(s3s, b""));
        let items: Vec<Item> = diff.findings().into_iter().map(|finding| finding.item).collect();
        assert_eq!(items, [Item::Header("content-length".to_owned())]);
    }
    let same = compare(
        "HeadObject".to_owned(),
        true,
        &mut answer(&[("content-length", "1024")], b""),
        &mut answer(&[("content-length", "1024")], b""),
    );
    assert!(same.findings().is_empty());
}

/// Negative — a nested reorder is found at its element, and a reorder is found even when one side
/// also has a child the other lacks.
#[test]
fn a_nested_reorder_and_a_reorder_beside_a_missing_child_are_order_findings() {
    let cases: [(&[u8], &[u8], &[Item]); 2] = [
        (
            b"<R><C><A>1</A><B>2</B></C></R>",
            b"<R><C><B>2</B><A>1</A></C></R>",
            &[Item::BodyOrder("R/C".to_owned())],
        ),
        (
            b"<R><A>1</A><B>2</B><X>3</X></R>",
            b"<R><B>2</B><A>1</A></R>",
            &[Item::BodyOrder("R".to_owned()), Item::BodyElement("R/X".to_owned())],
        ),
    ];
    for (gateway, s3s, expected) in cases {
        let diff = compare("ListObjects".to_owned(), false, &mut answer(&[], gateway), &mut answer(&[], s3s));
        let items: Vec<Item> = diff.findings().into_iter().map(|finding| finding.item).collect();
        assert_eq!(items, expected, "{:?}", String::from_utf8_lossy(gateway));
    }
}
