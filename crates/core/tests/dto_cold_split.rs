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

//! P1-06's cold request representation without changing the public DTO surface.
//!
//! Responsible for: the `Req<PutObject>` size ceiling and proving the boxed request still returns
//! the exact public DTO built with functional update syntax. NOT responsible for: wire codecs or
//! generated DTO layout. Upstream: `rustfs-gateway-types`. Downstream: handlers.

use core::mem::size_of;

use rustfs_gateway_core::Req;
use rustfs_gateway_types::dto::{PutObject, PutObjectInput};
use rustfs_gateway_types::{BucketName, ObjectKey};

const _: () = assert!(size_of::<Req<PutObject>>() <= 136);

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Req<PutObject>>() == 32);

#[test]
fn c_dto_n011_req_put_object_has_the_boxed_snapshot_and_stays_within_the_ceiling() {
    assert!(
        size_of::<Req<PutObject>>() <= 136,
        "Req<PutObject> is {} bytes",
        size_of::<Req<PutObject>>()
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(size_of::<Req<PutObject>>(), 32, "the boxed request snapshot drifted");
}

#[test]
fn public_fields_default_and_fru_survive_the_cold_request_representation() {
    let input = PutObjectInput {
        bucket: BucketName::new("example-bucket").expect("valid bucket"),
        key: ObjectKey::new("key").expect("valid key"),
        content_length: 7,
        content_type: Some("text/plain".to_owned()),
        ..Default::default()
    };
    let request: Req<PutObject> = Req::new(input);

    assert_eq!(request.input().content_type.as_deref(), Some("text/plain"));
    let input = request.into_input();
    assert_eq!(
        (input.bucket.as_str(), input.key.as_str(), input.content_length),
        ("example-bucket", "key", 7)
    );
}
