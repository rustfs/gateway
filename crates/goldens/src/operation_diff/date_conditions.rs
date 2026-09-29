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

//! Conditional dates under the RustFS profile, against the legacy stack RustFS main links
//! (rustfs/backlog#1677, ruling R14).
//!
//! Responsible for: proving that `strict_http_date` reads exactly the spellings the legacy stack
//! reads, as the same instant, over fixed rows and fixed-seed generated ones; and that an assembled
//! gateway with `ServiceBuilder::refuse_unreadable_date_conditions` answers each of the four
//! operations' date headers as the legacy service does — the same status, code and message when
//! it refuses, and the same instant handed to the handler when it does not.
//! NOT responsible for: the core default, which ignores an unreadable date
//! (`crates/core/tests/tolerant_conditions.rs`), or what a backend does with a condition.
//! Upstream: `rustfs-gateway`, and the legacy service the enclosing compilation binds.
//! Downstream: none.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerResult, InputAuthzRequest, InputDecisions,
    RegionSet, Req, RequestContext, Resp, S3Service, SecurityFloor, ServiceBuilder, SigV4Authenticator, StaticCredentials, dto,
};
use rustfs_gateway_core::codec::strict_http_date;

use super::{block_on, oracle, s3s};

/// The instant the legacy reader reads `value` as, in whole seconds, or `None` when it refuses it.
fn legacy_reads(value: &str) -> Option<i64> {
    let stamp = oracle::Timestamp::parse(oracle::TimestampFormat::HttpDate, value).ok()?;
    let mut text = Vec::new();
    stamp
        .format(oracle::TimestampFormat::EpochSeconds, &mut text)
        .expect("an instant the reader produced renders as epoch seconds");
    let text = String::from_utf8(text).expect("epoch seconds are ASCII");
    Some(text.parse().expect("an HTTP-date has no fractional second"))
}

fn gateway_reads(value: &str) -> Option<i64> {
    strict_http_date(value).map(|stamp| stamp.secs())
}

fn agree(value: &str) {
    assert_eq!(gateway_reads(value), legacy_reads(value), "{value:?}");
}

/// Rows chosen at every boundary of the grammar, each read by both.
const ROWS: &[&str] = &[
    "Sun, 06 Nov 1994 08:49:37 GMT",
    "Mon, 06 Nov 1994 08:49:37 GMT",
    "Sun, 06 Nov +1994 08:49:37 GMT",
    "Sun, 06 Nov -1994 08:49:37 GMT",
    "Sun, 06 Nov +0000 08:49:37 GMT",
    "Sun, 06 Nov -0000 08:49:37 GMT",
    "Sun, 06 Nov -9999 08:49:37 GMT",
    "Sun, 06 Nov +9999 08:49:37 GMT",
    "Sat, 01 Jan -0001 00:00:00 GMT",
    "Thu, 01 Jan 0000 00:00:00 GMT",
    "Thu, 31 Dec 9999 23:59:59 GMT",
    "Tue, 29 Feb 2000 00:00:00 GMT",
    "Tue, 29 Feb 1900 00:00:00 GMT",
    "Tue, 29 Feb -0004 00:00:00 GMT",
    "Tue, 29 Feb -0100 00:00:00 GMT",
    "Tue, 29 Feb -0400 00:00:00 GMT",
    "Thu, 29 Feb 2023 00:00:00 GMT",
    "Sun, 31 Nov 1994 08:49:37 GMT",
    "Sun, 00 Nov 1994 08:49:37 GMT",
    "Sun, 06 Nov 1994 08:49:60 GMT",
    "Sun, 06 Nov 1994 24:00:00 GMT",
    "Sun, 06 Nov 1994 08:60:37 GMT",
    "Sun, 6 Nov 1994 08:49:37 GMT",
    "Sun, 06 Nov 94 08:49:37 GMT",
    "Sun, 06 Nov 01994 08:49:37 GMT",
    "Sun, 06 Nov +10000 08:49:37 GMT",
    "Sun, 06 Nov ++1994 08:49:37 GMT",
    "Sun, 06 Nov -001 08:49:37 GMT",
    "Sun, 06 Nov 1994 8:49:37 GMT",
    "Sun, 06 Nov 1994 08:49:37.5 GMT",
    "Sun, +6 Nov 1994 08:49:37 GMT",
    "sun, 06 Nov 1994 08:49:37 GMT",
    "SUN, 06 NOV 1994 08:49:37 GMT",
    "Sun, 06 nov 1994 08:49:37 GMT",
    "Xyz, 06 Nov 1994 08:49:37 GMT",
    "Sun, 06 Nov 1994 08:49:37 gmt",
    "Sun, 06 Nov 1994 08:49:37 UTC",
    "Sun, 06 Nov 1994 08:49:37 GMTX",
    "Sun, 06 Nov 1994 08:49:37 +0000",
    " Sun, 06 Nov 1994 08:49:37 GMT",
    "Sun, 06 Nov 1994 08:49:37 GMT ",
    "Sun, 06 Nov 1994 08:49:37 GMT\t",
    "Sun,  06 Nov 1994 08:49:37 GMT",
    "Sun,06 Nov 1994 08:49:37 GMT",
    "Sun, 06 Nov 1994 08:49:37",
    "Sunday, 06-Nov-94 08:49:37 GMT",
    "Sun Nov  6 08:49:37 1994",
    "Invalid Date",
    "",
    "784111777",
    "1994-11-06T08:49:37Z",
    "Sun, 06 Nov 1994 08:49:37 GMT, Mon, 07 Nov 1994 08:49:37 GMT",
    "Sun, \u{0660}\u{0666} Nov 1994 08:49:37 GMT",
];

#[test]
fn every_boundary_row_reads_alike() {
    for row in ROWS {
        agree(row);
    }
    // The rows are not vacuous: both readers accept some and refuse others.
    assert!(ROWS.iter().any(|row| legacy_reads(row).is_some()));
    assert!(ROWS.iter().any(|row| legacy_reads(row).is_none()));
}

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A date in the fixed shape, with every field drawn a little past its valid range.
fn shaped() -> impl Strategy<Value = String> {
    (
        0..7_usize,
        0..34_u32,
        0..12_usize,
        prop::sample::select(vec!["", "+", "-"]),
        0..10_000_u32,
        0..26_u32,
        0..62_u32,
        0..62_u32,
    )
        .prop_map(|(weekday, day, month, sign, year, hour, minute, second)| {
            format!(
                "{}, {day:02} {} {sign}{year:04} {hour:02}:{minute:02}:{second:02} GMT",
                WEEKDAYS[weekday], MONTHS[month]
            )
        })
}

/// A shaped date with one byte replaced, inserted or removed, from the bytes the grammar turns on.
fn edited() -> impl Strategy<Value = String> {
    let alphabet = prop::sample::select(vec![
        '0', '1', '9', ' ', '\t', ',', ':', '+', '-', '.', 'G', 'M', 'T', 'g', 'n', 'x', '\u{e9}',
    ]);
    (shaped(), 0..40_usize, alphabet, 0..3_u8).prop_map(|(date, at, byte, edit)| {
        let mut chars: Vec<char> = date.chars().collect();
        let at = at.min(chars.len());
        match edit {
            0 if at < chars.len() => chars[at] = byte,
            1 => chars.insert(at, byte),
            _ if at < chars.len() => {
                chars.remove(at);
            }
            _ => chars.push(byte),
        }
        chars.into_iter().collect()
    })
}

fn runner() -> TestRunner {
    TestRunner::new_with_rng(
        Config {
            cases: 20_000,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &[0x14; 32]),
    )
}

#[test]
fn every_shaped_date_reads_alike() {
    let accepted = std::cell::Cell::new(0_u32);
    let refused = std::cell::Cell::new(0_u32);
    runner()
        .run(&shaped(), |date| {
            prop_assert_eq!(gateway_reads(&date), legacy_reads(&date), "{:?}", date);
            let counter = if legacy_reads(&date).is_some() { &accepted } else { &refused };
            counter.set(counter.get() + 1);
            Ok(())
        })
        .expect("the two readers agree on every shaped date");
    // Coverage floors: the generator reaches both sides of the grammar in bulk.
    let (accepted, refused) = (accepted.get(), refused.get());
    assert!(accepted > 5_000 && refused > 2_000, "accepted {accepted}, refused {refused}");
}

#[test]
fn every_edited_date_reads_alike() {
    let accepted = std::cell::Cell::new(0_u32);
    let refused = std::cell::Cell::new(0_u32);
    runner()
        .run(&edited(), |date| {
            prop_assert_eq!(gateway_reads(&date), legacy_reads(&date), "{:?}", date);
            let counter = if legacy_reads(&date).is_some() { &accepted } else { &refused };
            counter.set(counter.get() + 1);
            Ok(())
        })
        .expect("the two readers agree on every edited date");
    let (accepted, refused) = (accepted.get(), refused.get());
    assert!(accepted > 300 && refused > 5_000, "accepted {accepted}, refused {refused}");
}

// ── the four operations, through both services ───────────────────────────────────────────────

/// What one side's handler was handed: the two date members, in seconds.
type Handed = Arc<Mutex<Option<(Option<i64>, Option<i64>)>>>;

fn secs(stamp: Option<&rustfs_gateway_types::Timestamp>) -> Option<i64> {
    stamp.map(rustfs_gateway_types::Timestamp::secs)
}

fn legacy_secs(stamp: Option<&oracle::Timestamp>) -> Option<i64> {
    let mut text = Vec::new();
    stamp?.format(oracle::TimestampFormat::EpochSeconds, &mut text).ok()?;
    String::from_utf8(text).ok()?.parse().ok()
}

struct Recording(Handed);

impl Handler<dto::CopyObject> for Recording {
    async fn call(&self, request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        let input = request.into_input();
        let handed = (
            secs(input.copy_source_if_modified_since.as_ref()),
            secs(input.copy_source_if_unmodified_since.as_ref()),
        );
        *self.0.lock().expect("unpoisoned") = Some(handed);
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }
}

impl Handler<dto::UploadPartCopy> for Recording {
    async fn call(&self, request: Req<dto::UploadPartCopy>) -> HandlerResult<dto::UploadPartCopy> {
        let input = request.into_input();
        let handed = (
            secs(input.copy_source_if_modified_since.as_ref()),
            secs(input.copy_source_if_unmodified_since.as_ref()),
        );
        *self.0.lock().expect("unpoisoned") = Some(handed);
        Ok(Resp::new(dto::UploadPartCopyOutput::default()))
    }
}

impl Handler<dto::GetObject> for Recording {
    async fn call(&self, request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        let input = request.into_input();
        let handed = (secs(input.if_modified_since.as_ref()), secs(input.if_unmodified_since.as_ref()));
        *self.0.lock().expect("unpoisoned") = Some(handed);
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

impl Handler<dto::HeadObject> for Recording {
    async fn call(&self, request: Req<dto::HeadObject>) -> HandlerResult<dto::HeadObject> {
        let input = request.into_input();
        let handed = (secs(input.if_modified_since.as_ref()), secs(input.if_unmodified_since.as_ref()));
        *self.0.lock().expect("unpoisoned") = Some(handed);
        Ok(Resp::new(dto::HeadObjectOutput::default()))
    }
}

/// Allows both stages: the diff is about the date, not policy.
struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_route<'a>(&'a self, _: &'a RequestContext<'a>, _: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

fn gateway(handed: &Handed) -> S3Service {
    let credentials = Credentials::new("AKIDDATECONDITIONS", b"date-conditions-secret").expect("a credential");
    let backend = Arc::new(Recording(Arc::clone(handed)));
    ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(credentials)),
            RegionSet::new(["us-east-1"]).expect("a region"),
        ))
        .authorizer(AllowAll)
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .refuse_unreadable_date_conditions()
        .register::<dto::CopyObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPartCopy, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::HeadObject, _>(backend)
        .build()
        .expect("a complete assembly")
}

/// The legacy service's handler for the same four operations, recording the same two members.
struct LegacyRecording(Handed);

type Answer<T> = Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<T>>> + Send + 'static>>;

impl LegacyRecording {
    fn record(&self, handed: (Option<i64>, Option<i64>)) {
        *self.0.lock().expect("unpoisoned") = Some(handed);
    }
}

impl s3s::S3 for LegacyRecording {
    // The trait is declared with `#[async_trait]`; these are the signatures that attribute expands
    // a `&self` method to, spelled out so the harness needs no proc-macro dependency.
    fn copy_object<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::CopyObjectInput>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<oracle::CopyObjectOutput>>> + Send + 'future>>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record((
            legacy_secs(request.input.copy_source_if_modified_since.as_ref()),
            legacy_secs(request.input.copy_source_if_unmodified_since.as_ref()),
        ));
        let answer: Answer<oracle::CopyObjectOutput> =
            Box::pin(async { Ok(s3s::S3Response::new(oracle::CopyObjectOutput::default())) });
        answer
    }

    fn upload_part_copy<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::UploadPartCopyInput>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<oracle::UploadPartCopyOutput>>> + Send + 'future>>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record((
            legacy_secs(request.input.copy_source_if_modified_since.as_ref()),
            legacy_secs(request.input.copy_source_if_unmodified_since.as_ref()),
        ));
        let answer: Answer<oracle::UploadPartCopyOutput> =
            Box::pin(async { Ok(s3s::S3Response::new(oracle::UploadPartCopyOutput::default())) });
        answer
    }

    fn get_object<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::GetObjectInput>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<oracle::GetObjectOutput>>> + Send + 'future>>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record((
            legacy_secs(request.input.if_modified_since.as_ref()),
            legacy_secs(request.input.if_unmodified_since.as_ref()),
        ));
        let answer: Answer<oracle::GetObjectOutput> =
            Box::pin(async { Ok(s3s::S3Response::new(oracle::GetObjectOutput::default())) });
        answer
    }

    fn head_object<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::HeadObjectInput>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<oracle::HeadObjectOutput>>> + Send + 'future>>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record((
            legacy_secs(request.input.if_modified_since.as_ref()),
            legacy_secs(request.input.if_unmodified_since.as_ref()),
        ));
        let answer: Answer<oracle::HeadObjectOutput> =
            Box::pin(async { Ok(s3s::S3Response::new(oracle::HeadObjectOutput::default())) });
        answer
    }
}

/// One side's answer: status, error code and message (XML text escapes undone), and what the
/// handler was handed, if it ran.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    status: u16,
    code: Option<String>,
    message: Option<String>,
    handed: Option<(Option<i64>, Option<i64>)>,
}

fn element(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))? + start;
    Some(
        body[start..end]
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

/// One anonymous request, path-style, with `lines` as its header lines in order.
fn request(method: &http::Method, target: &str, lines: &[(&str, &[u8])]) -> http::request::Builder {
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(target)
        .header("host", "host.invalid");
    if matches!(*method, http::Method::PUT) {
        builder = builder.header("x-amz-copy-source", "src/key").header("content-length", "0");
    }
    for (name, value) in lines {
        builder = builder.header(*name, http::HeaderValue::from_bytes(value).expect("a representable header value"));
    }
    builder
}

fn both(method: &http::Method, target: &str, lines: &[(&str, &[u8])]) -> (Seen, Seen) {
    let handed: Handed = Arc::new(Mutex::new(None));
    let response = block_on(gateway(&handed).call_bytes(request(method, target, lines).body(Bytes::new()).expect("a request")));
    let collected = block_on(rustfs_gateway::collect(response)).expect("a finite answer");
    let body = String::from_utf8_lossy(collected.body()).into_owned();
    let gateway_seen = Seen {
        status: collected.status().as_u16(),
        code: element(&body, "Code"),
        message: element(&body, "Message"),
        handed: handed.lock().expect("unpoisoned").take(),
    };

    let handed: Handed = Arc::new(Mutex::new(None));
    let service = s3s::service::S3ServiceBuilder::new(LegacyRecording(Arc::clone(&handed))).build();
    let response = block_on(service.call(request(method, target, lines).body(s3s::Body::empty()).expect("a request")))
        .expect("the legacy service answers");
    let (parts, mut body) = response.into_parts();
    let body = block_on(body.store_all_limited(1 << 20)).expect("a finite legacy body");
    let body = String::from_utf8_lossy(&body).into_owned();
    let legacy_seen = Seen {
        status: parts.status.as_u16(),
        code: element(&body, "Code"),
        message: element(&body, "Message"),
        handed: handed.lock().expect("unpoisoned").take(),
    };
    (gateway_seen, legacy_seen)
}

/// The four operations and their two date headers, as `(method, target, modified, unmodified)`.
const OPERATIONS: [(&str, &str, &str, &str); 4] = [
    (
        "PUT",
        "/bkt/dst",
        "x-amz-copy-source-if-modified-since",
        "x-amz-copy-source-if-unmodified-since",
    ),
    (
        "PUT",
        "/bkt/dst?partNumber=1&uploadId=up",
        "x-amz-copy-source-if-modified-since",
        "x-amz-copy-source-if-unmodified-since",
    ),
    ("GET", "/bkt/key", "if-modified-since", "if-unmodified-since"),
    ("HEAD", "/bkt/key", "if-modified-since", "if-unmodified-since"),
];

fn method(name: &str) -> http::Method {
    http::Method::from_bytes(name.as_bytes()).expect("a method")
}

/// Both sides answer `verb target` with `lines` alike, and the legacy handler ran exactly when the
/// row is not one legacy refuses.
fn alike(verb: &str, target: &str, lines: &[(&str, &[u8])], refused: bool) {
    let (gateway, legacy) = both(&method(verb), target, lines);
    assert_eq!(gateway, legacy, "{verb} {target} {lines:?}");
    assert_eq!(legacy.handed.is_none(), refused, "{verb} {target} {lines:?}: {legacy:?}");
}

#[test]
fn a_readable_date_is_handed_on_as_the_same_instant() {
    for (verb, target, modified, unmodified) in OPERATIONS {
        for value in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Mon, 06 Nov +1994 08:49:37 GMT",
            "Sat, 01 Jan -0001 00:00:00 GMT",
        ] {
            alike(verb, target, &[(modified, value.as_bytes())], false);
            alike(verb, target, &[(unmodified, value.as_bytes())], false);
        }
    }
}

#[test]
fn n_an_unreadable_date_is_refused_with_the_same_code_and_message() {
    for (verb, target, modified, unmodified) in OPERATIONS {
        for value in [
            b"Invalid Date".as_slice(),
            b"Sunday, 06-Nov-94 08:49:37 GMT",
            b"Sun Nov  6 08:49:37 1994",
            b"say \"hi\"",
            b"Sun, 06 Nov 1994 08:49:37 GMT\t",
            "Sun, 06 Nov 1994 08:49:37 GMT\u{e9}".as_bytes(),
        ] {
            alike(verb, target, &[(modified, value)], true);
            alike(verb, target, &[(unmodified, value)], true);
        }
    }
}

#[test]
fn n_a_repeated_date_is_refused_with_the_same_code_and_message() {
    let date = b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice();
    for (verb, target, modified, unmodified) in OPERATIONS {
        alike(verb, target, &[(modified, date), (modified, date)], true);
        alike(verb, target, &[(unmodified, b""), (unmodified, b"")], true);
    }
}

#[test]
fn n_with_both_unreadable_the_modified_since_form_is_answered() {
    for (verb, target, modified, unmodified) in OPERATIONS {
        alike(verb, target, &[(unmodified, b"first garbage"), (modified, b"second garbage")], true);
    }
}

#[test]
fn n_another_operations_date_header_is_no_condition_on_either() {
    for (verb, target, _, _) in OPERATIONS {
        let foreign = if verb == "PUT" {
            "if-modified-since"
        } else {
            "x-amz-copy-source-if-modified-since"
        };
        alike(verb, target, &[(foreign, b"Invalid Date")], false);
    }
}

#[test]
fn an_empty_date_is_no_condition_on_either() {
    for (verb, target, modified, _) in OPERATIONS {
        alike(verb, target, &[(modified, b"")], false);
    }
}
