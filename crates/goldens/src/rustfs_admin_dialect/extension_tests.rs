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

//! RustFS's S3-shaped extension operations and the object-zip-download pair through the assembled
//! service (rustfs/backlog#2753), and bound to the recorded inventory.
//!
//! Responsible for: every extension record agreeing with its inventory row; for every extension
//! row, SigV4 and then exactly the inventory's action asked on the bucket or object the path names
//! (or on nothing, for the service listener) and the handler reached with that bucket; refusal
//! before the handler when the action is denied or only other actions are allowed, and refusal
//! before the authorizer when the request is unsigned or presigned — `403`, never a `501`; and
//! the zip pair's own labels about the caller, its opaque `{+id}` capture, and the download URL's
//! `403` without a header signature.
//! NOT responsible for: the harness (`super`), routing without a service (the dialect crate's
//! `extensions` tests), or the generator.
//! Upstream: `super`, the recorded inventory. Downstream: nothing.

use bytes::Bytes;
use http::{HeaderValue, Method, Request};
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, ExtensionRouteRecord, ROUTES};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RequestNow, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};

use super::{Asked, BUCKET, Exchange, REGION, assemble, assemble_on, in_lanes, in_lanes_on, rustfs_profile_floor, wire};
use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST, SECRET_KEY, amz_date};
use crate::rustfs_admin_route_inventory;

const KEY: &str = "key-1";

/// The path an extension record's target addresses.
fn path(record: &ExtensionRouteRecord) -> String {
    match record.target {
        "service" => "/".to_owned(),
        "bucket" => format!("/{BUCKET}"),
        "object" => format!("/{BUCKET}/{KEY}"),
        other => panic!("{}: an unknown target {other:?}", record.operation),
    }
}

/// The query that selects an extension record: the key with the value its rule reads.
fn query(record: &ExtensionRouteRecord) -> String {
    let (key, rule) = record.query;
    match rule.strip_prefix("equals:") {
        Some(value) => format!("{key}={value}"),
        None => format!("{key}=s3:ObjectCreated:*"),
    }
}

/// A signed request for the record's row.
fn signed(record: &ExtensionRouteRecord) -> Request<Bytes> {
    let request = match record.method {
        "GET" => ContextRequest::get(PATH_HOST, &path(record), &query(record)),
        "PUT" => ContextRequest::put_with_query(PATH_HOST, &path(record), &query(record), b""),
        other => panic!("{}: no signed fixture for {other}", record.operation),
    };
    wire(&request.signed(REGION))
}

/// The same request with no credentials at all.
fn unsigned(record: &ExtensionRouteRecord) -> Request<Bytes> {
    unsigned_at(record.method, &format!("{}?{}", path(record), query(record)))
}

fn unsigned_at(method: &str, uri: &str) -> Request<Bytes> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", PATH_HOST)
        .body(Bytes::new())
        .expect("a fixture request")
}

/// The record's row presigned in the query with the shared credential, now.
fn presigned(record: &ExtensionRouteRecord) -> Request<Bytes> {
    let method = Method::from_bytes(record.method.as_bytes()).expect("a method");
    let stamp = AmzDate::parse(&amz_date(RequestNow::capture().unix_seconds())).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("credentials");
    let mut signer = SigV4Signer::new(credentials, scope);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_str(PATH_HOST).expect("a host"));
    let host = RawHost::from_host_header(PATH_HOST.as_bytes()).expect("an acceptable host");
    let path = path(record);
    let query = query(record);
    let signing = SigningRequest::new(&method, &path, &query, &headers, &host, PayloadMode::Unsigned, stamp);
    let signed = signer.presign(&signing, 900).expect("a presignable request");
    let mut builder = Request::builder().method(method).uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a request")
}

/// The question the route stage asked about the record's operation and action.
fn route_question<'a>(exchange: &'a Exchange, record: &ExtensionRouteRecord) -> &'a Asked {
    exchange
        .asked
        .iter()
        .find(|asked| asked.stage == "route" && asked.operation == record.operation)
        .unwrap_or_else(|| panic!("{}: no route question in {:?}", record.operation, exchange.asked))
}

fn refused_before_the_handler(exchange: &Exchange, at: &str) {
    assert_eq!(exchange.status, 403, "{at}: {}", exchange.body);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran: {:?}", exchange.reached);
}

fn refused_without_asking(exchange: &Exchange, at: &str) {
    refused_before_the_handler(exchange, at);
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
}

/// Positive — every extension record is an inventory extension route, with the same method,
/// target, discriminator and action, and every inventory extension route is a record.
#[test]
fn every_extension_record_is_bound_to_its_inventory_route() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    assert_eq!(inventory.extension_routes().len(), EXTENSION_ROUTES.len());
    assert_eq!(EXTENSION_ROUTES.len(), 8);
    for (record, route) in EXTENSION_ROUTES.iter().zip(inventory.extension_routes()) {
        let at = record.operation;
        assert_eq!(record.name, route.name, "{at}: the inventory's order is the records'");
        let bound = inventory.extension_route(record.name).expect("an inventory extension route");
        assert_eq!(record.method, bound.method.as_str(), "{at}");
        assert_eq!(record.target, bound.target, "{at}");
        assert_eq!(
            record.query,
            (bound.query_discriminator.key.as_str(), bound.query_discriminator.rule.as_str()),
            "{at}"
        );
        assert_eq!(record.action, bound.iam_action_wire, "{at}");
        assert_eq!(bound.auth_detail, "SignatureRequiredThenHandlerCheck", "{at}");
        assert!(record.action.starts_with("s3:"), "{at}: {}", record.action);
        assert!(record.operation.starts_with("rustfs:"), "{at}");
        assert!(
            !ROUTES.iter().any(|route| route.operation == record.operation),
            "{at}: also a claimed route"
        );
    }
}

/// Positive — a signed extension request is authorised by exactly the inventory's action, on the
/// bucket or object the path names and on nothing for the service listener, and reaches its
/// operation's handler with that bucket; the standard operation the query would otherwise name is
/// never asked about.
#[test]
fn every_extension_row_is_authorised_by_its_inventory_action_on_its_target() {
    let assembled = assemble(|operation, action| {
        EXTENSION_ROUTES
            .iter()
            .any(|record| record.operation == operation && record.action == action)
    });
    for record in EXTENSION_ROUTES {
        let at = record.operation;
        let exchange = assembled.exchange(signed(record));
        assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
        assert_eq!(exchange.reached, [record.operation], "{at}");
        let asked = route_question(&exchange, record);
        assert_eq!(asked.action, record.action, "{at}");
        assert_eq!(asked.caller.as_deref(), Some(ACCESS_KEY), "{at}");
        assert_eq!(asked.subject, None, "{at}");
        let (bucket, key) = match record.target {
            "service" => (None, None),
            "bucket" => (Some(BUCKET), None),
            _ => (Some(BUCKET), Some(KEY)),
        };
        assert_eq!((asked.bucket.as_deref(), asked.key.as_deref()), (bucket, key), "{at}");
        assert!(
            exchange.asked.iter().all(|asked| asked.operation == record.operation),
            "{at}: another operation was asked about: {:?}",
            exchange.asked
        );
        assert_eq!(exchange.handed[0].bucket.as_deref(), bucket, "{at}");
        assert!(!exchange.handed[0].holds_secret, "{at}");
    }
}

/// Negative — an unsigned extension request is `403` before the authorizer is asked, never the
/// `501` of an operation the gateway lacks: the floor is privileged.
#[test]
fn n_an_unsigned_extension_request_is_refused_without_asking() {
    in_lanes(
        |_, _| true,
        EXTENSION_ROUTES,
        |assembled, record| {
            refused_without_asking(&assembled.exchange(unsigned(record)), record.operation);
        },
    );
}

/// Negative — a denied action refuses the request before its handler, after asking exactly it.
#[test]
fn n_an_extension_request_whose_action_is_denied_is_refused_before_its_handler() {
    in_lanes(
        |_, _| false,
        EXTENSION_ROUTES,
        |assembled, record| {
            let exchange = assembled.exchange(signed(record));
            refused_before_the_handler(&exchange, record.operation);
            assert_eq!(route_question(&exchange, record).action, record.action, "{}", record.operation);
        },
    );
}

/// Negative — allowing every action but the inventory's does not authorise the row: the wrong
/// IAM action is a `403` from the authorizer path the dialect uses.
#[test]
fn n_every_other_action_does_not_authorise_an_extension_row() {
    in_lanes(
        |operation, action| {
            !EXTENSION_ROUTES
                .iter()
                .any(|record| record.operation == operation && record.action == action)
        },
        EXTENSION_ROUTES,
        |assembled, record| {
            let exchange = assembled.exchange(signed(record));
            refused_before_the_handler(&exchange, record.operation);
            assert_eq!(route_question(&exchange, record).action, record.action, "{}", record.operation);
        },
    );
}

/// Negative — a presigned extension request is refused without asking, on the default floor and
/// on the RustFS profile's, which admits presigned URLs on standard operations only.
#[test]
fn n_a_presigned_extension_request_is_refused_without_asking() {
    in_lanes(
        |_, _| true,
        EXTENSION_ROUTES,
        |assembled, record| {
            refused_without_asking(&assembled.exchange(presigned(record)), record.operation);
        },
    );
    in_lanes_on(
        &rustfs_profile_floor(),
        |_, _| true,
        EXTENSION_ROUTES,
        |assembled, record| {
            refused_without_asking(&assembled.exchange(presigned(record)), record.operation);
        },
    );
}

/// Positive and negative — the zip pair: the minting `POST` is authorised by its own label about
/// the caller and hands its body over; the download is authorised by its own label about the
/// caller, hands the whole `{id}.zip` segment over as `id`, and is `403` without a header
/// signature, the minted `?token=` URL included (rustfs/backlog#2753, ADR-0026 (g)).
#[test]
fn the_zip_pair_is_authorised_by_its_own_labels_about_the_caller_and_never_anonymously() {
    let assembled = assemble(|_, action| action.starts_with("rustfs:"));
    let mint = ContextRequest::post(PATH_HOST, "/rustfs/admin/v3/object-zip-downloads", "").signed(REGION);
    let exchange = assembled.exchange(wire(&mint));
    assert_eq!(exchange.status, 200, "{}", exchange.body);
    assert_eq!(exchange.reached, ["rustfs:PostV3ObjectZipDownloads"]);
    let asked = exchange
        .asked
        .iter()
        .find(|asked| asked.stage == "route")
        .expect("a route question");
    assert_eq!(
        (asked.action.as_str(), asked.subject.clone()),
        ("rustfs:CreateObjectZipDownload", Some(None))
    );
    let download = ContextRequest::get(PATH_HOST, "/rustfs/admin/v3/object-zip-downloads/abc.zip", "token=t").signed(REGION);
    let exchange = assembled.exchange(wire(&download));
    assert_eq!(exchange.status, 200, "{}", exchange.body);
    assert_eq!(exchange.reached, ["rustfs:GetV3ObjectZipDownloadsByIdZip"]);
    assert_eq!(exchange.handed[0].params, [("id".to_owned(), "abc.zip".to_owned())]);
    let asked = exchange
        .asked
        .iter()
        .find(|asked| asked.stage == "route")
        .expect("a route question");
    assert_eq!((asked.action.as_str(), asked.subject.clone()), ("rustfs:DownloadObjectZip", Some(None)));
    for uri in [
        "/rustfs/admin/v3/object-zip-downloads/abc.zip?token=t",
        "/minio/admin/v3/object-zip-downloads/abc.zip?token=t",
    ] {
        refused_without_asking(&assembled.exchange(unsigned_at("GET", uri)), uri);
    }
    refused_without_asking(
        &assembled.exchange(unsigned_at("POST", "/rustfs/admin/v3/object-zip-downloads")),
        "an unsigned mint",
    );
    let refused = assemble_on(rustfs_profile_floor(), |_, _| true);
    refused_without_asking(
        &refused.exchange(unsigned_at("GET", "/rustfs/admin/v3/object-zip-downloads/abc.zip?token=t")),
        "an unsigned download under the RustFS profile floor",
    );
}
