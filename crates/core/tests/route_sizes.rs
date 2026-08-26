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

//! The compiled route bucket's independently compiled size ceiling.
//!
//! Responsible for: making `c-fast-1010` a compile-time consumer outside the production module.
//! NOT responsible for: route lookup semantics or wall-clock performance.
//! Upstream: `rustfs_gateway_core::route::RouteBucket`. Downstream: the core integration target.

use std::mem::size_of;

use rustfs_gateway_core::route::RouteBucket;

const ROUTE_BUCKET_SIZE_CEILING: usize = 64;
const _: () = assert!(size_of::<RouteBucket>() <= ROUTE_BUCKET_SIZE_CEILING);

/// c-fast-1010 — reports the observed size beside the compile-time ceiling.
#[test]
fn n_route_bucket_cannot_outgrow_the_hot_path_ceiling() {
    println!("route/RouteBucket: {} bytes", size_of::<RouteBucket>());
    assert!(
        size_of::<RouteBucket>() <= ROUTE_BUCKET_SIZE_CEILING,
        "RouteBucket is {} bytes, above the {}-byte ceiling",
        size_of::<RouteBucket>(),
        ROUTE_BUCKET_SIZE_CEILING,
    );
}
