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

//! The page-size ceiling a view applies for the RustFS profile, seen through the generated
//! listing decoders.
//!
//! Responsible for: an oversized `max-keys` decoding as the ceiling on every listing that reads
//! it, and everything else — absent, in range, negative, unparseable, another parameter, a view
//! without a ceiling — decoding exactly as it did before.
//! NOT responsible for: which operations an assembly clamps (`rustfs-gateway`'s builder) or the
//! default refusal, which `super`'s max-keys tests pin.
//! Upstream: `crate::codec::view::PageSizeCeiling`. Downstream: nothing.

use super::*;
use crate::codec::PageSizeCeiling;

const MAX_KEYS: PageSizeCeiling = PageSizeCeiling::new("max-keys", 1000);

fn list_v2(query: &str, ceiling: Option<PageSizeCeiling>) -> Result<Option<i32>, crate::codec::CodecError> {
    let request = accepted("GET", &format!("/photos?list-type=2&{query}"), &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let view = match ceiling {
        Some(ceiling) => view.with_page_size_ceiling(ceiling),
        None => view,
    };
    dto::ListObjectsV2::decode(&view, RequestBody::None).map(|input| input.max_keys)
}

#[test]
fn an_oversized_max_keys_decodes_as_the_ceiling() {
    for raw in ["1001", "5000", "100000", "2147483647", "%205000"] {
        assert_eq!(
            list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).ok(),
            Some(Some(1000)),
            "max-keys={raw}"
        );
    }
}

#[test]
fn n_an_in_range_or_absent_max_keys_is_not_touched() {
    for (raw, expected) in [("0", 0), ("1", 1), ("999", 999), ("1000", 1000)] {
        assert_eq!(
            list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).ok(),
            Some(Some(expected)),
            "max-keys={raw}"
        );
    }
    assert_eq!(list_v2("prefix=a", Some(MAX_KEYS)).ok(), Some(Some(1000)), "the model default");
}

#[test]
fn n_a_negative_max_keys_is_still_refused_under_the_ceiling() {
    for raw in ["-1", "-2147483648"] {
        let error = list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).expect_err("a ceiling is not a floor");
        assert_eq!(error.code().as_str(), "InvalidArgument", "max-keys={raw}");
        assert_eq!(error.member(), Some("MaxKeys"), "max-keys={raw}");
    }
}

#[test]
fn n_an_unparseable_max_keys_is_still_refused_under_the_ceiling() {
    for raw in ["abc", "1e4", "", "2147483648", "99999999999", "5000abc"] {
        let error = list_v2(&format!("max-keys={raw}"), Some(MAX_KEYS)).expect_err("only an integer is clamped");
        assert_eq!(error.code().as_str(), "InvalidArgument", "max-keys={raw}");
        assert_eq!(error.member(), Some("MaxKeys"), "max-keys={raw}");
    }
}

#[test]
fn n_without_the_ceiling_an_oversized_max_keys_is_still_refused() {
    let error = list_v2("max-keys=1001", None).expect_err("the default view keeps the modelled range");
    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.member(), Some("MaxKeys"));
}

#[test]
fn the_unbounded_listings_read_the_ceiling_too() {
    let request = accepted("GET", "/photos?max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListObjects::decode(&view, RequestBody::None).expect("ListObjects has no modelled ceiling");
    assert_eq!(input.max_keys, Some(1000));

    let request = accepted("GET", "/photos?versions&max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListObjectVersions::decode(&view, RequestBody::None).expect("ListObjectVersions has no modelled ceiling");
    assert_eq!(input.max_keys, Some(1000));
}

#[test]
fn n_without_the_ceiling_v1_and_versions_refuse_oversized_max_keys() {
    let request = accepted("GET", "/photos?max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let err = dto::ListObjects::decode(&view, RequestBody::None).expect_err("ListObjects enforces 0..=1000");
    assert_eq!(err.code().as_str(), "InvalidArgument");
    assert_eq!(err.member(), Some("MaxKeys"));

    let request = accepted("GET", "/photos?versions&max-keys=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let err = dto::ListObjectVersions::decode(&view, RequestBody::None).expect_err("ListObjectVersions enforces 0..=1000");
    assert_eq!(err.code().as_str(), "InvalidArgument");
    assert_eq!(err.member(), Some("MaxKeys"));
}

#[test]
fn n_the_ceiling_governs_only_its_own_parameter() {
    let small_ceiling = PageSizeCeiling::new("max-keys", 100);
    let request = accepted("GET", "/photos?uploads&max-uploads=500&prefix=500", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_page_size_ceiling(small_ceiling);
    let input = dto::ListMultipartUploads::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.max_uploads, Some(500), "max-uploads is not max-keys");
    assert_eq!(input.prefix.as_deref(), Some("500"), "another parameter reads as sent");

    let request = accepted("GET", "/photos/key?uploadId=u1&max-parts=5000", &[]);
    let view = MetaView::of(&request, TargetKind::Object)
        .expect("view")
        .with_page_size_ceiling(MAX_KEYS);
    let input = dto::ListParts::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.max_parts, Some(5000), "max-parts is not max-keys");
}

#[test]
fn n_bounded_s3_params_reject_out_of_range_values_at_decode() {
    // UploadPartCopy.PartNumber: 1..=10000
    for bad in ["0", "-1", "10001"] {
        let req = accepted("PUT", &format!("/dst/k?partNumber={bad}&uploadId=u"), &[("x-amz-copy-source", "src/k")]);
        let view = MetaView::of(&req, TargetKind::Object).expect("view");
        let err = dto::UploadPartCopy::decode(&view, RequestBody::None).expect_err("out of range partNumber");
        assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("PartNumber")), "{bad}");
    }

    // CompleteMultipartUpload CompletedPart.PartNumber: 1..=10000 under Tree, deferred under RustFs
    for bad in ["0", "-1", "10001"] {
        let xml = format!(
            "<CompleteMultipartUpload><Part><PartNumber>{bad}</PartNumber><ETag>\"abc\"</ETag></Part></CompleteMultipartUpload>"
        );
        let req = accepted("POST", "/dst/k?uploadId=u", &[]);
        let view = MetaView::of(&req, TargetKind::Object).expect("view");
        let err = dto::CompleteMultipartUpload::decode(&view, RequestBody::Buffered(Bytes::from(xml.clone())))
            .expect_err("out of range CompletedPart.PartNumber");
        assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("PartNumber")), "{bad}");

        let rustfs_view = view.with_document_reading(crate::codec::DocumentReading::RustFs);
        let decoded = dto::CompleteMultipartUpload::decode(&rustfs_view, RequestBody::Buffered(Bytes::from(xml)))
            .expect("RustFs profile defers part number bounds to handler");
        assert_eq!(
            decoded.multipart_upload.parts.first().map(|part| part.part_number),
            Some(bad.parse::<i32>().expect("int"))
        );
    }

    // GetObject & HeadObject PartNumber: 1..=10000 -> 400 InvalidPartNumber
    for bad in ["0", "-1", "10001"] {
        let get_req = accepted("GET", &format!("/dst/k?partNumber={bad}"), &[]);
        let get_view = MetaView::of(&get_req, TargetKind::Object).expect("view");
        let err = dto::GetObject::decode(&get_view, RequestBody::None).expect_err("GetObject bad partNumber");
        assert_eq!(
            (err.code().as_str(), err.status(), err.member()),
            ("InvalidPartNumber", StatusCode::BAD_REQUEST, Some("PartNumber")),
            "{bad}"
        );

        let head_req = accepted("HEAD", &format!("/dst/k?partNumber={bad}"), &[]);
        let head_view = MetaView::of(&head_req, TargetKind::Object).expect("view");
        let err = dto::HeadObject::decode(&head_view, RequestBody::None).expect_err("HeadObject bad partNumber");
        assert_eq!(
            (err.code().as_str(), err.status(), err.member()),
            ("InvalidPartNumber", StatusCode::BAD_REQUEST, Some("PartNumber")),
            "{bad}"
        );
    }

    // ListMultipartUploads.MaxUploads: 1..=1000
    for bad in ["0", "-1", "1001"] {
        let req = accepted("GET", &format!("/dst?uploads&max-uploads={bad}"), &[]);
        let view = MetaView::of(&req, TargetKind::Bucket).expect("view");
        let err = dto::ListMultipartUploads::decode(&view, RequestBody::None).expect_err("bad max-uploads");
        assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("MaxUploads")), "{bad}");
    }

    // ListParts.MaxParts: negative rejected, >= 0 accepted (c-mpu-0048 caps > 1000 in handler)
    let neg_parts = accepted("GET", "/dst/k?uploadId=u&max-parts=-1", &[]);
    let err = dto::ListParts::decode(&MetaView::of(&neg_parts, TargetKind::Object).expect("view"), RequestBody::None)
        .expect_err("negative max-parts");
    assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("MaxParts")));

    // ListBuckets.MaxBuckets: 1..=10000
    for bad in ["0", "-1", "10001"] {
        let req = accepted("GET", &format!("/?max-buckets={bad}"), &[]);
        let view = MetaView::of(&req, TargetKind::Service).expect("view");
        let err = dto::ListBuckets::decode(&view, RequestBody::None).expect_err("bad max-buckets");
        assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("MaxBuckets")), "{bad}");
    }

    // ListDirectoryBuckets.MaxDirectoryBuckets: 1..=1000
    for bad in ["0", "-1", "1001"] {
        let req = accepted("GET", &format!("/?max-directory-buckets={bad}"), &[]);
        let view = MetaView::of(&req, TargetKind::Service).expect("view");
        let err = dto::ListDirectoryBuckets::decode(&view, RequestBody::None).expect_err("bad max-directory-buckets");
        assert_eq!(
            (err.code().as_str(), err.member()),
            ("InvalidArgument", Some("MaxDirectoryBuckets")),
            "{bad}"
        );
    }

    // PutObject.WriteOffsetBytes, CompleteMultipartUpload.MpuObjectSize, DeleteObject.IfMatchSize: >= 0
    let put_req = accepted("PUT", "/dst/k", &[("content-length", "0"), ("x-amz-write-offset-bytes", "-1")]);
    let err = dto::PutObject::decode(&MetaView::of(&put_req, TargetKind::Object).expect("view"), RequestBody::None)
        .expect_err("negative WriteOffsetBytes");
    assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("WriteOffsetBytes")));

    let cmpu_req = accepted("POST", "/dst/k?uploadId=u", &[("x-amz-mp-object-size", "-1")]);
    let err = dto::CompleteMultipartUpload::decode(
        &MetaView::of(&cmpu_req, TargetKind::Object).expect("view"),
        RequestBody::Buffered(Bytes::from_static(b"<CompleteMultipartUpload/>")),
    )
    .expect_err("negative MpuObjectSize");
    assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("MpuObjectSize")));

    let del_req = accepted("DELETE", "/dst/k", &[("x-amz-if-match-size", "-1")]);
    let err = dto::DeleteObject::decode(&MetaView::of(&del_req, TargetKind::Object).expect("view"), RequestBody::None)
        .expect_err("negative IfMatchSize");
    assert_eq!((err.code().as_str(), err.member()), ("InvalidArgument", Some("IfMatchSize")));
}

#[test]
fn n_list_objects_v2_omits_owner_when_fetch_owner_is_false_while_v1_keeps_it() {
    let owner = dto::Owner {
        id: Some("owner-id".to_owned()),
        display_name: Some("owner-name".to_owned()),
    };
    let make_v2_out = || {
        let mut out = one_entry_listing("a.txt", "b28354b543375bfa94dabaeda722927f");
        if let Some(first) = out.contents.first_mut() {
            first.owner = Some(owner.clone());
        }
        out
    };

    // Absent fetch-owner defaults to false -> Owner omitted even if handler populated it.
    let absent = accepted("GET", "/conf-list?list-type=2", &[]);
    let body = body_text(
        &dto::ListObjectsV2::encode(make_v2_out(), &MetaView::of(&absent, TargetKind::Bucket).expect("view"), 200)
            .expect("encodes")
            .body,
    );
    assert!(!body.contains("<Owner>"), "absent fetch-owner must omit Owner: {body}");

    // Explicit fetch-owner=false -> Owner omitted.
    let explicit_false = accepted("GET", "/conf-list?list-type=2&fetch-owner=false", &[]);
    let body = body_text(
        &dto::ListObjectsV2::encode(make_v2_out(), &MetaView::of(&explicit_false, TargetKind::Bucket).expect("view"), 200)
            .expect("encodes")
            .body,
    );
    assert!(!body.contains("<Owner>"), "fetch-owner=false must omit Owner: {body}");

    // Explicit fetch-owner=true -> Owner emitted.
    let explicit_true = accepted("GET", "/conf-list?list-type=2&fetch-owner=true", &[]);
    let body = body_text(
        &dto::ListObjectsV2::encode(make_v2_out(), &MetaView::of(&explicit_true, TargetKind::Bucket).expect("view"), 200)
            .expect("encodes")
            .body,
    );
    assert!(body.contains("<Owner><ID>owner-id</ID>"), "fetch-owner=true must emit Owner: {body}");

    // ListObjects (V1) has no FetchOwner parameter -> Owner always emitted.
    let v1_req = accepted("GET", "/conf-list", &[]);
    let v1_out = dto::ListObjectsOutput {
        name: BucketName::new("conf-list").expect("bucket"),
        contents: make_v2_out().contents,
        ..Default::default()
    };
    let body = body_text(
        &dto::ListObjects::encode(v1_out, &MetaView::of(&v1_req, TargetKind::Bucket).expect("view"), 200)
            .expect("encodes")
            .body,
    );
    assert!(body.contains("<Owner><ID>owner-id</ID>"), "ListObjects V1 must emit Owner: {body}");
}
