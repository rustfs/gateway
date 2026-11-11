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

//! The SigV2 census of the RustFS dialect (rustfs/gateway#1582): a SigV2 header signature on
//! every claimed admin row, every extension route and both admin fallbacks is `403 AccessDenied`
//! before the authorizer, on the default floor and on the RustFS profile's.
//!
//! Responsible for: that census; the rows it leaves out with their reason — the OIDC bootstrap
//! rows, which RustFS answers before it reads any credential, and the zip download, whose minted
//! `?token=` URL RustFS also admits without one (rustfs/gateway#1592); and the positive control,
//! a SigV2 header signature on an exempt row that is verified and reaches its handler, so a
//! fixture that is refused for its own reasons fails the control rather than passing the census.
//! NOT responsible for: SigV2 presigned URLs (refused by every privileged floor already) or the
//! object lambda's own lanes (`super::lambda_tests`).
//! Upstream: `super`, `super::tests`, `super::extension_tests`, `super::lambda_tests`.
//! Downstream: nothing.

use std::sync::Mutex;

use rustfs_gateway::SecurityFloor;
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, RouteRecord};

use super::extension_tests::{path, query, unsigned_at};
use super::lambda_tests::sigv2_header_signed;
use super::tests::rows;
use super::{ACCESS_KEY, Exchange, assemble_on, in_lanes_on, rustfs_profile_floor, unsigned};

/// The zip download, whose `?token=` URL RustFS admits without a credential.
const ZIP_DOWNLOAD: &str = "rustfs:GetV3ObjectZipDownloadsByIdZip";

/// The two floors the census runs on.
fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default floor", SecurityFloor::new()),
        ("RustFS profile floor", rustfs_profile_floor()),
    ]
}

/// Every claimed row the census covers: all but the OIDC bootstrap rows and the zip download.
fn census() -> Vec<(&'static RouteRecord, String)> {
    rows()
        .filter(|(record, _)| !record.anonymous && record.operation != ZIP_DOWNLOAD)
        .collect()
}

/// Why `exchange` is not the floor's refusal: `403 AccessDenied` (a `HEAD` answer carries no
/// body to read the code from), with no authorizer question and no handler reached.
fn not_refused(exchange: &Exchange, method: &str) -> Option<String> {
    let coded = method == "HEAD" || exchange.body.contains("<Code>AccessDenied</Code>");
    if exchange.status == 403 && coded && exchange.asked.is_empty() && exchange.reached.is_empty() {
        return None;
    }
    Some(format!(
        "status {}, asked {:?}, reached {:?}, body {}",
        exchange.status, exchange.asked, exchange.reached, exchange.body
    ))
}

/// Runs `send` over `items` on both floors and fails once, naming every item that was not
/// refused on each floor, so a broken half never hides behind the other.
fn refused_on_both_floors<T: Sync>(items: &[T], send: impl Fn(&super::Assembled, &T) -> Option<String> + Sync) {
    let failures = Mutex::new(Vec::new());
    for (at, floor) in floors() {
        in_lanes_on(
            &floor,
            |_, _| true,
            items,
            |assembled, item| {
                if let Some(failure) = send(assembled, item) {
                    failures.lock().expect("an unpoisoned list").push(format!("{at}: {failure}"));
                }
            },
        );
    }
    let failures = failures.into_inner().expect("an unpoisoned list");
    assert!(failures.is_empty(), "{} not refused:\n{}", failures.len(), failures.join("\n"));
}

/// Negative — a SigV2 header signature on every claimed admin row is `403 AccessDenied` before
/// the authorizer, on the default floor and on the RustFS profile's: RustFS refuses SigV2 on every
/// authenticated custom route because SigV2 binds neither its query arguments nor its payload.
#[test]
fn n_a_sigv2_header_signature_on_every_claimed_admin_row_is_refused_without_asking() {
    let rows = census();
    assert_eq!(rows.len(), 670 - 8 - 2, "every row but the eight OIDC rows and the zip download's two");
    refused_on_both_floors(&rows, |assembled, (record, path)| {
        let exchange = assembled.exchange(sigv2_header_signed(unsigned(record, path)));
        not_refused(&exchange, record.method).map(|why| format!("{} {path}: {why}", record.method))
    });
}

/// Negative — a SigV2 header signature on every extension route is `403 AccessDenied` before the
/// authorizer, on the default floor and on the RustFS profile's.
#[test]
fn n_a_sigv2_header_signature_on_every_extension_route_is_refused_without_asking() {
    assert_eq!(EXTENSION_ROUTES.len(), 8);
    refused_on_both_floors(EXTENSION_ROUTES, |assembled, record| {
        let request = unsigned_at(record.method, &format!("{}?{}", path(record), query(record)));
        let exchange = assembled.exchange(sigv2_header_signed(request));
        not_refused(&exchange, record.method).map(|why| format!("{}: {why}", record.operation))
    });
}

/// Negative — a SigV2 header signature on a path no claimed row names, which the two admin
/// fallbacks answer (`v3` with `501`, `v4` with its downgrade `426`), is `403 AccessDenied`
/// before the authorizer under both admin prefixes, on both floors: the fallbacks share
/// `admin::floor`, and they are not rows of `ROUTES`, so the claimed-row census never reaches them.
#[test]
fn n_a_sigv2_header_signature_on_either_admin_fallback_is_refused_without_asking() {
    let paths: Vec<String> = ["/rustfs/admin", "/minio/admin"]
        .iter()
        .flat_map(|prefix| [format!("{prefix}/v3/no-such-route"), format!("{prefix}/v4/x")])
        .collect();
    refused_on_both_floors(&paths, |assembled, path| {
        let exchange = assembled.exchange(sigv2_header_signed(unsigned_at("GET", path)));
        not_refused(&exchange, "GET").map(|why| format!("GET {path}: {why}"))
    });
}

/// Positive — the control: the same SigV2 header fixture on an exempt OIDC bootstrap row is
/// verified as the shared caller and reaches its handler, on both floors. A fixture refused for
/// its own reasons would fail here instead of passing the census as a refusal.
#[test]
fn a_sigv2_header_signature_on_an_exempt_row_is_verified_and_reaches_its_handler() {
    let (record, path) = rows()
        .find(|(record, _)| record.anonymous && record.method == "GET")
        .expect("the inventory has a GET OIDC bootstrap row");
    for (at, floor) in floors() {
        let assembled = assemble_on(floor, |_, _| true);
        let exchange = assembled.exchange(sigv2_header_signed(unsigned(record, &path)));
        assert_eq!(exchange.status, 200, "{at}: GET {path}: {}", exchange.body);
        assert_eq!(exchange.reached, [record.operation], "{at}");
        assert!(
            exchange.asked.iter().all(|asked| asked.caller.as_deref() == Some(ACCESS_KEY)),
            "{at}: the SigV2 signature was not verified as the caller: {:?}",
            exchange.asked
        );
        assert!(!exchange.asked.is_empty(), "{at}: the authorizer was not asked");
    }
}
