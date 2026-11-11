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

//! RustFS's object lambda route (`GET /{bucket}/{key}?lambdaArn=…`) through the assembled service
//! under `ServiceBuilder::rustfs_profile()` and its authenticator half, and its versioned read
//! (rustfs/gateway#1576).
//!
//! Responsible for: the presigned and header-signed request reaching the handler under the whole
//! RustFS profile; refusals there of an unsigned request, a presigned URL whose signature was
//! stripped, an unsigned `x-amz-*` header beside a presigned URL, and SigV2 header and presigned
//! requests; a request naming `versionId` asked `s3:GetObjectVersion` instead of `s3:GetObject`,
//! header-signed and presigned, while an unversioned one is asked `s3:GetObject`; and the
//! start-up posture listing the operation as presigned-reachable and nothing else of the dialect.
//! NOT responsible for: the default and profile-floor lanes the sibling routes share
//! (`super::extension_tests`), or the harness (`super`).
//! Upstream: `super`, `super::extension_tests`. Downstream: nothing.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request};
use rustfs_gateway::{Credentials, SecurityFloor, SigV4Authenticator, StaticCredentials};
use rustfs_gateway_sig::{RawQuery, RegionSet, RequestNow, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

use super::extension_tests::{
    KEY, LAMBDA, LAMBDA_ACTION, LAMBDA_ARN, LAMBDA_EXPIRES, lambda_floors, presign_at, presigned_lambda,
    refused_before_the_handler, refused_without_asking, sigv2_presigned_lambda, unsigned_at,
};
use super::{Assembled, BUCKET, Exchange, REGION, assemble_installing, assemble_on, wire};
use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST, REGIONS, SECRET_KEY};

const VERSION_ACTION: &str = "s3:GetObjectVersion";

/// The dialect behind the whole RustFS profile: `ServiceBuilder::rustfs_profile()` and
/// `SigV4Authenticator::rustfs_profile()`, as a RustFS deployment assembles them.
fn assemble_rustfs_profile(policy: impl Fn(&str, &str) -> bool + Send + Sync + 'static) -> Assembled {
    assemble_installing(SecurityFloor::new(), policy, false, None, |builder| {
        let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
        let regions = RegionSet::new(REGIONS).expect("fixture regions");
        let authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions)
            .hand_caller_secret_to_handlers()
            .rustfs_profile();
        builder.rustfs_profile().authenticator(authenticator)
    })
}

/// Only the object lambda's own action is allowed, on every lane.
fn lambda_only(operation: &str, action: &str) -> bool {
    operation == LAMBDA && action == LAMBDA_ACTION
}

/// The header-signed object lambda request, with `extra` after `lambdaArn` in its query.
fn header_signed_lambda(extra: &str) -> Request<Bytes> {
    let query = format!("lambdaArn={LAMBDA_ARN}{extra}");
    wire(&ContextRequest::get(PATH_HOST, &format!("/{BUCKET}/{KEY}"), &query).signed(REGION))
}

/// The presigned object lambda request, with `extra` after `lambdaArn` inside the signed query.
fn presigned_lambda_with(extra: &str) -> Request<Bytes> {
    let query = format!("lambdaArn={LAMBDA_ARN}{extra}");
    presign_at(
        &Method::GET,
        &format!("/{BUCKET}/{KEY}"),
        &query,
        RequestNow::capture().unix_seconds(),
        LAMBDA_EXPIRES,
    )
}

/// The route stage's question.
fn route_action(exchange: &Exchange, at: &str) -> String {
    exchange
        .asked
        .iter()
        .find(|asked| asked.stage == "route")
        .unwrap_or_else(|| panic!("{at}: no route question in {:?}", exchange.asked))
        .action
        .clone()
}

/// `seconds` as an RFC 1123 date, the spelling SigV2's `Date` header carries.
fn rfc1123(seconds: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (days, of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let weekday = WEEKDAYS[usize::try_from(days.rem_euclid(7)).expect("a weekday")];
    let month_name = MONTHS[usize::try_from(month - 1).expect("a month")];
    format!(
        "{weekday}, {day:02} {month_name} {year} {:02}:{:02}:{:02} GMT",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// The object lambda request header-signed with SigV2, now.
fn sigv2_header_signed_lambda() -> Request<Bytes> {
    let mut request = unsigned_at("GET", &format!("/{BUCKET}/{KEY}?lambdaArn={LAMBDA_ARN}"));
    let date = rfc1123(RequestNow::capture().unix_seconds());
    request
        .headers_mut()
        .insert(http::header::DATE, HeaderValue::from_str(&date).expect("a date"));
    let query = RawQuery::new(request.uri().query().unwrap_or_default());
    let spec = SigV2StringToSignSpec::new(
        SigV2Mode::HeaderAuth,
        request.method(),
        request.uri().path(),
        &query,
        request.headers(),
        None,
    );
    let authorization = SigV2Signer::new(ACCESS_KEY, SECRET_KEY.as_bytes())
        .expect("a signer")
        .authorization(&spec)
        .expect("a signable request");
    request
        .headers_mut()
        .insert(http::header::AUTHORIZATION, HeaderValue::from_str(&authorization).expect("a credential"));
    request
}

/// Positive — RustFS's own presigned object lambda request, and the header-signed one, reach the
/// handler under the whole RustFS profile, asked `s3:GetObject` for the caller.
#[test]
fn a_presigned_and_a_header_signed_lambda_request_reach_the_handler_under_the_rustfs_profile() {
    let assembled = assemble_rustfs_profile(lambda_only);
    for (at, request) in [("presigned", presigned_lambda()), ("header-signed", header_signed_lambda(""))] {
        let exchange = assembled.exchange(request);
        assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
        assert_eq!(exchange.reached, [LAMBDA], "{at}");
        assert_eq!(route_action(&exchange, at), LAMBDA_ACTION, "{at}");
    }
}

/// Negative — under the whole RustFS profile, which reads an unsigned presigned query as
/// anonymous and delegates anonymous requests to the authorizer, an unsigned request and a
/// presigned URL with its `X-Amz-Signature` stripped are both `403` before the authorizer.
#[test]
fn n_an_unsigned_or_signature_stripped_lambda_request_is_refused_under_the_rustfs_profile() {
    let assembled = assemble_rustfs_profile(|_, _| true);
    let unsigned = unsigned_at("GET", &format!("/{BUCKET}/{KEY}?lambdaArn={LAMBDA_ARN}"));
    refused_without_asking(&assembled.exchange(unsigned), "unsigned");
    let presigned = presigned_lambda();
    let uri = presigned.uri().to_string();
    let stripped = uri
        .split('&')
        .filter(|pair| !pair.starts_with("X-Amz-Signature="))
        .collect::<Vec<_>>()
        .join("&");
    assert_ne!(stripped, uri, "the fixture carried a signature to strip");
    refused_without_asking(&assembled.exchange(unsigned_at("GET", &stripped)), "signature stripped");
}

/// Negative — an `x-amz-*` header the presigned URL did not sign is refused under the whole
/// RustFS profile before the handler, as RustFS refuses it on every custom route (GHSA-g8w9).
#[test]
fn n_an_unsigned_amz_header_beside_a_presigned_lambda_url_is_refused_under_the_rustfs_profile() {
    let assembled = assemble_rustfs_profile(|_, _| true);
    let mut request = presigned_lambda();
    request
        .headers_mut()
        .insert("x-amz-tagging", HeaderValue::from_static("owner=attacker"));
    refused_without_asking(&assembled.exchange(request), "unsigned x-amz-tagging");
}

/// Negative — a SigV2 header signature and a SigV2 presigned URL are both `403` before the
/// authorizer under the whole RustFS profile, and the header signature on the default floor too:
/// RustFS requires header or query SigV4 on every extension route.
#[test]
fn n_a_sigv2_lambda_request_is_refused_under_the_rustfs_profile_and_the_default_floor() {
    let profile = assemble_rustfs_profile(|_, _| true);
    refused_without_asking(&profile.exchange(sigv2_header_signed_lambda()), "profile: SigV2 header");
    refused_without_asking(&profile.exchange(sigv2_presigned_lambda()), "profile: SigV2 presigned");
    let default = assemble_on(SecurityFloor::new(), |_, _| true);
    refused_without_asking(&default.exchange(sigv2_header_signed_lambda()), "default: SigV2 header");
}

/// Negative — a request naming `versionId` from a caller allowed `s3:GetObject` but not
/// `s3:GetObjectVersion` is refused before the handler, header-signed and presigned, on the
/// default floor, the profile floor and the whole profile: it is asked `s3:GetObjectVersion`
/// (GHSA-3ppv), as RustFS's handler asks it through its GetObject check.
#[test]
fn n_a_versioned_lambda_request_without_the_version_action_is_refused_before_its_handler() {
    let mut lanes: Vec<(&str, Assembled)> = lambda_floors()
        .into_iter()
        .map(|(at, floor)| (at, assemble_on(floor, lambda_only)))
        .collect();
    lanes.push(("whole RustFS profile", assemble_rustfs_profile(lambda_only)));
    for (at, assembled) in &lanes {
        for (form, request) in [
            ("header-signed", header_signed_lambda("&versionId=v1")),
            ("presigned", presigned_lambda_with("&versionId=v1")),
        ] {
            let exchange = assembled.exchange(request);
            refused_before_the_handler(&exchange, &format!("{at}, {form}"));
            assert_eq!(route_action(&exchange, at), VERSION_ACTION, "{at}, {form}");
        }
    }
}

/// Positive — with `s3:GetObjectVersion` allowed, the versioned request reaches the handler,
/// header-signed and presigned, asked that action alone.
#[test]
fn a_versioned_lambda_request_with_the_version_action_reaches_its_handler() {
    let version_only = |operation: &str, action: &str| operation == LAMBDA && action == VERSION_ACTION;
    for (at, floor) in lambda_floors() {
        let assembled = assemble_on(floor, version_only);
        for (form, request) in [
            ("header-signed", header_signed_lambda("&versionId=v1")),
            ("presigned", presigned_lambda_with("&versionId=v1")),
        ] {
            let exchange = assembled.exchange(request);
            assert_eq!(exchange.status, 200, "{at}, {form}: {}", exchange.body);
            assert_eq!(exchange.reached, [LAMBDA], "{at}, {form}");
            assert_eq!(route_action(&exchange, at), VERSION_ACTION, "{at}, {form}");
        }
    }
}

/// Negative — an unversioned request is still asked `s3:GetObject`: allowed only the version
/// action, it is refused before the handler.
#[test]
fn n_an_unversioned_lambda_request_is_not_authorised_by_the_version_action() {
    let version_only = |operation: &str, action: &str| operation == LAMBDA && action == VERSION_ACTION;
    for (at, floor) in lambda_floors() {
        let assembled = assemble_on(floor, version_only);
        let exchange = assembled.exchange(presigned_lambda());
        refused_before_the_handler(&exchange, at);
        assert_eq!(route_action(&exchange, at), LAMBDA_ACTION, "{at}");
    }
}

/// Positive and negative — with the dialect installed, the start-up posture lists the object
/// lambda as presigned-reachable and no other admin-router operation, under the default floor and
/// the whole RustFS profile. The metadata route's two listings are on the standard listing floor
/// (ADR-0050), so the whole profile, which admits a presigned URL on every standard operation,
/// lists them exactly as it lists `ListObjectsV2`, and the default floor lists neither.
#[test]
fn the_posture_lists_only_the_object_lambda_of_the_dialect_as_presigned_reachable() {
    for (at, assembled, listings) in [
        ("default floor", assemble_on(SecurityFloor::new(), |_, _| true), &[][..]),
        (
            "whole RustFS profile",
            assemble_rustfs_profile(|_, _| true),
            &super::metadata_listing_tests::LISTINGS[..],
        ),
    ] {
        let posture = assembled.service.startup_posture().to_string();
        let line = posture
            .lines()
            .find(|line| line.starts_with("SECURITY_POSTURE "))
            .unwrap_or_else(|| panic!("{at}: no SECURITY_POSTURE line in {posture}"));
        let presigned = line
            .split(" presigned_allowed_ops=[")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .unwrap_or_else(|| panic!("{at}: no presigned list in {line}"));
        let mut dialect: Vec<&str> = presigned.split(',').filter(|name| name.starts_with("rustfs:")).collect();
        let mut expected = vec![LAMBDA];
        expected.extend_from_slice(listings);
        dialect.sort_unstable();
        expected.sort_unstable();
        assert_eq!(dialect, expected, "{at}: {line}");
    }
}
