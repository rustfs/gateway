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

//! The zip download's SigV2 refusal through the assembled service (ADR-0052,
//! rustfs/gateway#1592): `admin::zip_token_floor` refuses SigV2 under every policy beside its
//! bearer claim.
//!
//! Responsible for: a SigV2 header signature on the download, with no token and with a good one,
//! with and without a bearer verifier, refused `403 AccessDenied` at the floor on the default and
//! the RustFS profile's floor — no authorizer question, no handler, no verifier call; and the
//! control in the other direction, the same SigV2 fixture verified and served on a row whose floor
//! does not refuse SigV2.
//! NOT responsible for: the token path or the SigV4-signed download, which keep their own proofs
//! (`super::zip_token_tests`).
//! Upstream: `super`'s harness, `super::zip_token_tests`' fixtures, `super::lambda_tests`' SigV2
//! signer. Downstream: nothing.

use super::lambda_tests::sigv2_header_signed;
use super::tests::rows;
use super::zip_token_tests::{FixtureVerifier, GOOD, ZIP_GET, asked_of, floors, unsigned, with_verifier};
use super::{ACCESS_KEY, Exchange, assemble_on};

const DOWNLOAD: &str = "/rustfs/admin/v3/object-zip-downloads/abc.zip";

/// The floor's refusal: `403 AccessDenied`, no authorizer question, no handler.
fn refused_at_the_floor(exchange: &Exchange, at: &str) {
    assert_eq!(exchange.status, 403, "{at}: {}", exchange.body);
    assert!(exchange.body.contains("<Code>AccessDenied</Code>"), "{at}: {}", exchange.body);
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran: {:?}", exchange.reached);
}

/// Negative — a SigV2 header signature on the download is refused at the floor, with no token and
/// with a good one, on both floors and without a verifier: the difference recorded on
/// rustfs/gateway#1592, where the request was verified and reached the handler, is closed.
#[test]
fn n_a_sigv2_header_download_is_refused_at_the_floor_without_a_verifier() {
    for (at, floor) in floors() {
        let assembled = assemble_on(floor, |_, _| true);
        for query in [String::new(), format!("?token={GOOD}")] {
            let exchange = assembled.exchange(sigv2_header_signed(unsigned("GET", &format!("{DOWNLOAD}{query}"))));
            refused_at_the_floor(&exchange, &format!("{at} {query}"));
        }
    }
}

/// Negative — with a bearer verifier installed the same requests are refused at the floor too,
/// and the verifier is never asked: a SigV2 signature is not laundered through a good token.
#[test]
fn n_a_sigv2_header_download_is_refused_at_the_floor_with_a_verifier() {
    for (at, floor) in floors() {
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor, |_, _| true, verifier.clone());
        for query in [String::new(), format!("?token={GOOD}")] {
            let exchange = assembled.exchange(sigv2_header_signed(unsigned("GET", &format!("{DOWNLOAD}{query}"))));
            refused_at_the_floor(&exchange, &format!("{at} {query}"));
            assert!(asked_of(&verifier).is_empty(), "{at} {query}: the verifier was asked");
        }
    }
}

/// Positive — the control in the other direction: the same SigV2 header fixture on an OIDC
/// bootstrap row, whose floor does not refuse SigV2, is verified as the shared caller and reaches
/// its handler on both floors, so the refusals above are the download floor's.
#[test]
fn the_same_sigv2_fixture_is_served_on_a_row_whose_floor_does_not_refuse_it() {
    let (record, path) = rows()
        .find(|(record, _)| record.anonymous && record.method == "GET")
        .expect("the inventory has a GET OIDC bootstrap row");
    assert_ne!(record.operation, ZIP_GET);
    for (at, floor) in floors() {
        let exchange = assemble_on(floor, |_, _| true).exchange(sigv2_header_signed(unsigned("GET", &path)));
        assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
        assert_eq!(exchange.reached, [record.operation], "{at}");
        assert!(
            !exchange.asked.is_empty() && exchange.asked.iter().all(|asked| asked.caller.as_deref() == Some(ACCESS_KEY)),
            "{at}: the SigV2 signature was not verified as the caller: {:?}",
            exchange.asked
        );
    }
}
