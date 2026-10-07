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

//! The request documents the RustFS profile still answers differently from legacy RustFS, each a
//! named test carrying its ruling id (`rd-doc-0001`..`0004`, `rd-doc-0006`..`0008`; `rd-doc-0005`
//! is retired, an empty list wrapper being carried now).
//!
//! Responsible for: one concrete document per divergence, both stacks' answers pinned. Each
//! divergence is a refusal where legacy RustFS accepts: a value the gateway cannot carry exactly
//! is refused rather than handed over differently, and two security refusals stand.
//! NOT responsible for: finding the divergences — `parity` sends every perturbation and requires
//! each difference it meets to fall in exactly one of these ids.
//! Upstream: the parent harness. Downstream: the request-divergence register.

use rustfs_gateway_core::DocumentReading;

use super::{Op, gateway, legacy};

fn rustfs(op: Op, body: &str) -> Result<String, String> {
    gateway(op, DocumentReading::RustFs, body.as_bytes())
}

/// Both stacks' answers: the gateway refuses with `code`, the legacy stack hands a document over.
fn refused_where_legacy_accepts(op: Op, body: &str, code: &str) {
    assert_eq!(rustfs(op, body), Err(code.to_owned()), "{op:?}: {body}");
    let handed = legacy(op, body.as_bytes());
    assert!(handed.is_ok(), "{op:?}: the legacy stack refused {body}: {handed:?}");
}

// ── named divergences ─────────────────────────────────────────────────────────────────────────

/// A `DOCTYPE` in front of a request document: the legacy stack skips the declaration and reads the
/// document; the RustFS profile keeps the reader's refusal of the entity-expansion entry point.
///
/// Ruling: `rd-doc-0001`
#[test]
fn a_doctype_is_refused_by_the_gateway_and_skipped_by_the_legacy_stack() {
    for op in [Op::PutBucketTagging, Op::PutBucketLifecycleConfiguration] {
        let body = match op {
            Op::PutBucketTagging => {
                "<!DOCTYPE Tagging><Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>"
            }
            _ => {
                "<!DOCTYPE x [<!ENTITY e \"v\">]><LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>\
                  <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
            }
        };
        refused_where_legacy_accepts(op, body, "MalformedXML");
    }
}

/// A character XML 1.0 cannot represent inside a value: the legacy stack stores it, after which
/// every read of the configuration is a document no XML parser reads; the RustFS profile keeps the
/// reader's refusal.
///
/// Ruling: `rd-doc-0002`
#[test]
fn a_character_xml_cannot_represent_is_refused_by_the_gateway_and_stored_by_the_legacy_stack() {
    refused_where_legacy_accepts(
        Op::PutBucketTagging,
        "<Tagging><TagSet><Tag><Key>a\u{1}</Key><Value>b</Value></Tag></TagSet></Tagging>",
        "MalformedXML",
    );
    refused_where_legacy_accepts(
        Op::PutBucketCors,
        "<CORSConfiguration><CORSRule><ID>r\u{b}</ID><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>",
        "MalformedXML",
    );
}

/// A member the model requires and the legacy stack reads as optional, absent: a tag without its
/// `Key` or `Value`, a completed part without its `PartNumber`. The gateway's member has no absent
/// spelling, so the document is refused rather than handed over with an invented value.
///
/// Ruling: `rd-doc-0003`
#[test]
fn an_absent_member_the_model_requires_is_refused_by_the_gateway_and_read_by_the_legacy_stack() {
    refused_where_legacy_accepts(
        Op::PutBucketTagging,
        "<Tagging><TagSet><Tag><Key>key-only</Key></Tag></TagSet></Tagging>",
        "MalformedXML",
    );
    refused_where_legacy_accepts(
        Op::PutObjectTagging,
        "<Tagging><TagSet><Tag><Value>value-only</Value></Tag></TagSet></Tagging>",
        "MalformedXML",
    );
    refused_where_legacy_accepts(
        Op::CompleteMultipartUpload,
        "<CompleteMultipartUpload><Part><ETag>\"abc\"</ETag></Part></CompleteMultipartUpload>",
        "MalformedXML",
    );
}

/// A value the legacy stack reads and the gateway cannot hold exactly: a date with a non-zero UTC
/// offset (the gateway's timestamp is a UTC instant; the legacy stack keeps the offset), and an
/// entity tag no gateway tag spells (empty, or carrying a quote). Refused rather than stored
/// differently.
///
/// Ruling: `rd-doc-0004`
#[test]
fn a_value_the_gateway_cannot_carry_is_refused_by_the_gateway_and_read_by_the_legacy_stack() {
    refused_where_legacy_accepts(
        Op::PutObjectRetention,
        "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-02T03:04:05+08:00</RetainUntilDate></Retention>",
        "InvalidArgument",
    );
    refused_where_legacy_accepts(
        Op::PutBucketLifecycleConfiguration,
        "<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Expiration><Date>2027-01-01T00:00:00-05:00</Date>\
         </Expiration></Rule></LifecycleConfiguration>",
        "InvalidArgument",
    );
    refused_where_legacy_accepts(
        Op::CompleteMultipartUpload,
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag></ETag></Part></CompleteMultipartUpload>",
        "InvalidArgument",
    );
    refused_where_legacy_accepts(
        Op::DeleteObjects,
        "<Delete><Object><Key>k</Key><ETag>a\"b</ETag></Object></Delete>",
        "InvalidArgument",
    );
}

/// An empty body where the legacy stack reads the document as optional and the model requires it:
/// the legacy stack hands no document over, and RustFS's handler refuses the request —
/// `InvalidArgument` for the object-lock configuration (`rustfs/src/storage/ecfs.rs:1678`),
/// `MalformedXML` for the restore (`execute_restore_object_rejects_missing_restore_request`,
/// `rustfs/src/app/object/restore.rs`), both at rustfs/rustfs@e870a6d25. The gateway answers the
/// same code before any handler.
///
/// Ruling: `rd-doc-0006`
#[test]
fn an_empty_body_the_model_requires_is_refused_by_the_gateway_and_handed_over_absent_by_the_legacy_stack() {
    for (op, code) in [
        (Op::PutObjectLockConfiguration, "InvalidArgument"),
        (Op::RestoreObject, "MalformedXML"),
    ] {
        assert_eq!(rustfs(op, ""), Err(code.to_owned()), "{op:?}");
        assert_eq!(legacy(op, b""), Ok("None".to_owned()), "{op:?}");
    }
}

/// A key carried in the body that the gateway's name policy refuses — empty, or holding a control
/// character — in a `DeleteObjects` object or a website error document. The legacy stack reads any
/// text; the RustFS profile's key policy is rustfs/gateway#1107's, and the body keys follow it.
///
/// Ruling: `rd-doc-0007`
#[test]
fn a_body_key_the_name_policy_refuses_is_refused_by_the_gateway_and_read_by_the_legacy_stack() {
    refused_where_legacy_accepts(Op::DeleteObjects, "<Delete><Object><Key></Key></Object></Delete>", "InvalidArgument");
    refused_where_legacy_accepts(
        Op::DeleteObjects,
        "<Delete><Object><Key>a\r\nb</Key></Object></Delete>",
        "InvalidArgument",
    );
    refused_where_legacy_accepts(
        Op::PutBucketWebsite,
        "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key></Key></ErrorDocument>\
         </WebsiteConfiguration>",
        "InvalidArgument",
    );
}

/// A restore output location naming a bucket that is not a valid bucket name: the legacy stack reads
/// any text, and RustFS then refuses the output location itself; the gateway refuses the name first.
///
/// Ruling: `rd-doc-0008`
#[test]
fn an_invalid_output_bucket_name_is_refused_by_the_gateway_and_read_by_the_legacy_stack() {
    refused_where_legacy_accepts(
        Op::RestoreObject,
        "<RestoreRequest><Type>SELECT</Type><OutputLocation><S3><BucketName>Not A Bucket</BucketName><Prefix>p/</Prefix></S3>\
         </OutputLocation></RestoreRequest>",
        "InvalidArgument",
    );
}

/// The #1078 ruling deliberately refuses this value earlier than the legacy decoder.
///
/// Ruling: `rd-doc-0009`
#[test]
fn empty_required_status_is_refused_before_the_backend() {
    refused_where_legacy_accepts(
        Op::PutBucketLifecycleConfiguration,
        "<LifecycleConfiguration><Rule><Status/></Rule></LifecycleConfiguration>",
        "MalformedXML",
    );
}
