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

//! Every argument of the select, restore, upload-id, part-table, pagination and bucket-region
//! contracts, built out of a decoded request and what a backend holds beside it.
//!
//! Responsible for: proving that a backend outside this workspace can *call* [`validate_select`]
//! and [`select_scan_bytes`], [`validate_restore`], [`resolve_upload`], [`resolve_part`],
//! [`key_count`] and the three redirect constructors — and naming, for every argument that is
//! not the decoded input, what a backend supplies it from: the stored object's bytes, its own
//! upload records, its own part lengths, its listing's counts, its own region label.
//! NOT responsible for: what the rules decide (`rustfs-gateway-core`'s and
//! `rustfs-gateway-types`'s inline tests) or the wire shapes (`conformance/cases/`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15's acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** This is the last band, and its contracts are the ones
//! whose arguments are *meant* to come from the backend's own state — an upload-id claim is
//! exchanged against the backend's records, a part number against the backend's part table, a
//! scan range against the object the backend holds. The bar for these is not "from `Req<O>`
//! alone" but "from `Req<O>` plus state the backend has by definition", and this file writes each
//! pairing down so the signature is never read as asking for something the request does not
//! carry (the way `evaluate_range` once asked for a raw header the decoder had consumed).

use rustfs_gateway::{
    ErrorCode, MetaView, OperationCodec, PartWindow, RecordedUpload, RegionLabel, RequestBody, RestoreRejection, SelectRejection,
    TargetKind, UploadRejection, dto, key_count, permanent_redirect, resolve_part, resolve_upload, select_scan_bytes,
    validate_restore, validate_select,
};

use super::tagging_reachability::accepted;

/// An object-level request decoded as `O`, with or without a document body.
fn decoded<O: OperationCodec>(method: &'static str, target: &str, document: Option<&'static str>) -> O::Input {
    let uri: &'static str = Box::leak(format!("http://host.invalid/conf-select{target}").into_boxed_str());
    // A streaming write (`UploadPart`) declares its length on the head; a document write is
    // buffered and a read has neither.
    let headers: &[(&'static str, &'static str)] = match (document, method) {
        (Some(_), _) => &[("content-type", "application/xml")],
        (None, "PUT") => &[("content-length", "0")],
        (None, _) => &[],
    };
    let request = accepted(method, uri, headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    let body = document.map_or(RequestBody::None, |text| RequestBody::Buffered(text.as_bytes().into()));
    O::decode(&view, body).expect("a well-formed request is not the decoder's refusal")
}

/// The bridge for select, once: five members of the decoded request to the contract's five
/// arguments. `expression` and `expression_type` are required members, the serializations are
/// required shapes, and the scan range is optional — exactly the contract's shape.
fn judge_select(input: &dto::SelectObjectContentInput) -> Result<(), SelectRejection> {
    validate_select(
        &input.expression,
        &input.expression_type,
        &input.input_serialization,
        &input.output_serialization,
        input.scan_range.as_ref(),
    )
}

// ---------------------------------------------------------------------------------------------
// Select and restore: documents with more than one member the contract reads
// ---------------------------------------------------------------------------------------------

/// Negative with its control — a complete select request passes; an inverted scan range decodes
/// (two integers, no refusal) and is the contract's `InvalidArgument`. The scan then selects the
/// bytes of the object the backend holds.
#[test]
fn n_an_inverted_scan_range_is_the_contracts_refusal_and_the_scan_is_over_the_backends_bytes() {
    let whole = decoded::<dto::SelectObjectContent>(
        "POST",
        "/data.csv?select&select-type=2",
        Some(
            "<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization><ScanRange><Start>2</Start><End>5</End></ScanRange></SelectObjectContentRequest>",
        ),
    );
    judge_select(&whole).expect("a complete request with a forward range");
    assert_eq!(
        select_scan_bytes(whole.scan_range.as_ref(), b"0123456789"),
        b"2345",
        "the range selects from what the backend holds, inclusive at both ends"
    );
    assert_eq!(select_scan_bytes(None, b"0123456789"), b"0123456789");

    let inverted = decoded::<dto::SelectObjectContent>(
        "POST",
        "/data.csv?select&select-type=2",
        Some(
            "<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization><ScanRange><Start>5</Start><End>2</End></ScanRange></SelectObjectContentRequest>",
        ),
    );
    let rejection = judge_select(&inverted).expect_err("End before Start");
    assert_eq!(rejection, SelectRejection::ScanRangeInverted);
    assert_eq!(rejection.code(), ErrorCode::INVALID_ARGUMENT);
}

/// Negative with its control — a restore of one day passes; zero days decodes as `Some(0)` and is
/// the contract's refusal, not the decoder's.
#[test]
fn n_a_restore_below_the_day_minimum_is_the_contracts_refusal() {
    let one_day =
        decoded::<dto::RestoreObject>("POST", "/archived?restore", Some("<RestoreRequest><Days>1</Days></RestoreRequest>"));
    validate_restore(&one_day.restore_request).expect("one day is the minimum");
    let zero =
        decoded::<dto::RestoreObject>("POST", "/archived?restore", Some("<RestoreRequest><Days>0</Days></RestoreRequest>"));
    assert_eq!(zero.restore_request.days, Some(0), "the decoder keeps the zero");
    assert_eq!(validate_restore(&zero.restore_request), Err(RestoreRejection::DaysTooSmall));
}

// ---------------------------------------------------------------------------------------------
// Upload id and part table: the request's claim against the backend's own records
// ---------------------------------------------------------------------------------------------

/// What a backend records for one multipart upload — the two members the contract compares.
#[derive(Debug)]
struct Record {
    bucket: &'static str,
    key: &'static str,
}

impl RecordedUpload for Record {
    fn bucket(&self) -> &str {
        self.bucket
    }
    fn key(&self) -> &str {
        self.key
    }
}

/// Positive and negative — the decoded `upload_id` is a claim, exchanged through the backend's
/// own lookup: a record for this bucket and key resolves, a record for another key is
/// `NoSuchUpload`, and a claim nothing recorded is `NoSuchUpload` without the lookup being asked
/// anything it would refuse.
#[test]
fn n_an_upload_id_claim_is_exchanged_against_the_backends_records() {
    let part = decoded::<dto::UploadPart>("PUT", "/big?partNumber=1&uploadId=upload-0001", None);
    let mine = Record {
        bucket: "conf-select",
        key: "big",
    };
    let (resolved, record) =
        resolve_upload(&part.upload_id, &part.bucket, &part.key, |id| (id == "upload-0001").then_some(&mine))
            .expect("the claim names a recorded upload of this object");
    assert_eq!(resolved.id(), "upload-0001");
    assert_eq!(record.key(), "big");

    let elsewhere = Record {
        bucket: "conf-select",
        key: "other",
    };
    let Err(rejection): Result<_, UploadRejection> =
        resolve_upload(&part.upload_id, &part.bucket, &part.key, |_| Some(&elsewhere))
    else {
        panic!("another key's upload does not resolve");
    };
    assert_eq!(rejection.code(), &ErrorCode::NO_SUCH_UPLOAD);
    assert!(resolve_upload(&part.upload_id, &part.bucket, &part.key, |_| None::<&Record>).is_err());
}

/// Positive and negative — `partNumber` on a read is the request's; the part lengths are the
/// backend's; the window is the contract's. A number past the table is a `416`, from the
/// precondition contract's rejection.
#[test]
fn n_a_part_number_past_the_backends_table_is_the_contracts_refusal() {
    let read = decoded::<dto::GetObject>("GET", "/big?partNumber=2", None);
    let number = u32::try_from(read.part_number.expect("the query named a part")).expect("a positive part number");
    let lengths = [10_u64, 20, 5];
    let window: PartWindow = resolve_part(number, &lengths).expect("part 2 is in the table");
    assert_eq!((window.start, window.end_inclusive, window.total), (10, 29, 35));
    let past = decoded::<dto::GetObject>("GET", "/big?partNumber=4", None);
    let number = u32::try_from(past.part_number.expect("named")).expect("positive");
    let code = resolve_part(number, &lengths).expect_err("part 4 of three").code().clone();
    assert_eq!(code.as_str(), ErrorCode::INVALID_PART_NUMBER.as_str());
    assert_eq!(
        code.default_status().as_u16(),
        416,
        "the part table's refusal renders Range Not Satisfiable, not the code's usual 400"
    );
}

// ---------------------------------------------------------------------------------------------
// Pagination and region: arguments the backend has by definition
// ---------------------------------------------------------------------------------------------

/// Positive — `KeyCount` is the sum of what the listing returned, both kinds; the region redirect
/// is built from the backend's own label and nothing from the request. Neither has an argument a
/// request could fail to carry.
#[test]
fn a_key_count_and_a_region_redirect_need_nothing_from_the_request() {
    assert_eq!(key_count(3, 2), 5);
    assert_eq!(key_count(0, 0), 0);
    let region = RegionLabel::new("eu-west-1").expect("a region label");
    let redirect = permanent_redirect(region);
    assert_eq!(redirect.code(), &ErrorCode::PERMANENT_REDIRECT);
}
