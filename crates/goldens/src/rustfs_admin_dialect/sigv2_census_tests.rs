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
//! every claimed admin row and every extension route is `403` before the authorizer, on the
//! default floor and on the RustFS profile's.
//!
//! Responsible for: that census, and the rows it leaves out with their reason — the OIDC bootstrap
//! rows, which RustFS answers before it reads any credential, and the zip download, whose minted
//! `?token=` URL RustFS also admits without one.
//! NOT responsible for: SigV2 presigned URLs (refused by every privileged floor already) or the
//! object lambda's own lanes (`super::lambda_tests`).
//! Upstream: `super`, `super::tests`, `super::extension_tests`, `super::lambda_tests`.
//! Downstream: nothing.

use rustfs_gateway::SecurityFloor;
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, RouteRecord};

use super::extension_tests::{path, query, refused_without_asking, unsigned_at};
use super::lambda_tests::sigv2_header_signed;
use super::tests::rows;
use super::{in_lanes_on, rustfs_profile_floor, unsigned};

/// The zip download, whose `?token=` URL RustFS admits without a credential.
const ZIP_DOWNLOAD: &str = "rustfs:GetV3ObjectZipDownloadsByIdZip";

/// Every claimed row the census covers: all but the OIDC bootstrap rows and the zip download.
fn census() -> Vec<(&'static RouteRecord, String)> {
    rows()
        .filter(|(record, _)| !record.anonymous && record.operation != ZIP_DOWNLOAD)
        .collect()
}

/// Negative — a SigV2 header signature on every claimed admin row is `403` before the authorizer,
/// on the default floor and on the RustFS profile's: RustFS refuses SigV2 on every authenticated
/// custom route because SigV2 binds neither its query arguments nor its payload.
#[test]
fn n_a_sigv2_header_signature_on_every_claimed_admin_row_is_refused_without_asking() {
    let rows = census();
    assert_eq!(rows.len(), 670 - 8 - 2, "every row but the eight OIDC rows and the zip download's two");
    for floor in [SecurityFloor::new(), rustfs_profile_floor()] {
        in_lanes_on(
            &floor,
            |_, _| true,
            &rows,
            |assembled, (record, path)| {
                let exchange = assembled.exchange(sigv2_header_signed(unsigned(record, path)));
                refused_without_asking(&exchange, &format!("{} {path}", record.method));
            },
        );
    }
}

/// Negative — a SigV2 header signature on every extension route is `403` before the authorizer,
/// on the default floor and on the RustFS profile's.
#[test]
fn n_a_sigv2_header_signature_on_every_extension_route_is_refused_without_asking() {
    assert_eq!(EXTENSION_ROUTES.len(), 8);
    for floor in [SecurityFloor::new(), rustfs_profile_floor()] {
        in_lanes_on(
            &floor,
            |_, _| true,
            EXTENSION_ROUTES,
            |assembled, record| {
                let request = unsigned_at(record.method, &format!("{}?{}", path(record), query(record)));
                let exchange = assembled.exchange(sigv2_header_signed(request));
                refused_without_asking(&exchange, record.operation);
            },
        );
    }
}
