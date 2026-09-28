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

//! Responsible for: proving the signed-body harness and the seam verify an upload with the time it
//! was signed at, and still refuse one signed outside the skew window of that time (#896).
//! NOT responsible for: the s3s oracle, which keeps its own wall clock, or the body comparison.
//! Upstream: the signed-body harness. Downstream: the gateway's SigV4 and chunk verification.

use rustfs_gateway_sig::RequestNow;

use super::{Mode, Upload, gateway_side, through_seam_at};

/// A signing time far outside any skew window of the host clock.
const HISTORICAL: i64 = 1_440_938_160;
/// Past the fifteen-minute window SigV4 allows between the signature and the verifier.
const BEYOND_WINDOW: i64 = 16 * 60;

fn at(seconds: i64) -> RequestNow {
    RequestNow::from_unix_seconds(seconds)
}

fn gateway_at(mode: Mode, signed: i64, verified: i64) -> super::Side {
    let upload = Upload::new(mode, b"fixture-clock body");
    let wire = upload.wire(at(signed)).expect("the upload signs");
    gateway_side(&wire.headers, upload.split(&wire.body), at(verified)).expect("the gateway answers")
}

const MODES: [Mode; 2] = [Mode::Signed, Mode::SignedTrailer];

#[test]
fn an_upload_signed_at_the_fixture_time_reaches_the_gateway_handler() {
    for mode in MODES {
        let side = gateway_at(mode, HISTORICAL, HISTORICAL);
        assert_eq!((side.status, side.handler.is_some()), (200, true), "{mode:?}: {:?}", side.code);
    }
}

#[test]
fn an_upload_signed_outside_the_window_of_the_fixture_time_is_refused_before_the_handler() {
    for mode in MODES {
        for (signed, verified) in [
            (HISTORICAL, HISTORICAL + BEYOND_WINDOW),
            (HISTORICAL + BEYOND_WINDOW, HISTORICAL),
        ] {
            let side = gateway_at(mode, signed, verified);
            assert_eq!(
                (side.status, side.code.as_deref(), side.handler.is_some()),
                (403, Some("RequestTimeTooSkewed"), false),
                "{mode:?} signed {signed} verified {verified}"
            );
        }
    }
}

#[test]
fn the_seam_accepts_an_upload_at_the_fixture_time_and_refuses_one_outside_its_window() {
    let upload = Upload::new(Mode::Signed, b"fixture-clock body");
    let (status, _) = through_seam_at(&upload, at(HISTORICAL), at(HISTORICAL)).expect("the seam handler runs");
    assert_eq!(status, 200);
    let Err(refused) = through_seam_at(&upload, at(HISTORICAL), at(HISTORICAL + BEYOND_WINDOW)) else {
        panic!("a stale upload reached the seam handler");
    };
    assert!(refused.contains("status 403"), "{refused}");
}
