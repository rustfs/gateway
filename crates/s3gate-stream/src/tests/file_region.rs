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

//! Ranges a file region may and may not describe.
//!
//! Responsible for: proving that an end offset which cannot exist is refused at construction,
//! not at transfer time, and that a refusal is a value rather than a panic.
//! NOT responsible for: whether the descriptor is readable or the range is inside the file —
//! that is the transport's problem, and it needs an i/o driver to answer.
//! Upstream: `std::fs`. Downstream: nothing.

use std::os::fd::OwnedFd;

use crate::file_region::{FileRegion, FileRegionError};

fn null_fd() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null is readable"))
}

#[test]
fn a_region_reports_its_range() {
    let region = FileRegion::new(null_fd(), 4096, 8192).expect("the range fits in a u64");

    assert_eq!(region.offset(), 4096);
    assert_eq!(region.len(), 8192);
    assert_eq!(region.end_offset(), 12288);
    assert!(!region.is_empty());
}

#[test]
fn an_empty_region_is_allowed() {
    let region = FileRegion::new(null_fd(), 0, 0).expect("an empty range is representable");

    assert!(region.is_empty());
    assert_eq!(region.end_offset(), 0);
}

/// c-stream-n013: an end offset that does not fit in a `u64` is refused as a value. Letting it
/// through would either wrap into a different, plausible-looking range or panic inside a
/// transport, far from the request that caused it.
#[test]
fn a_range_whose_end_overflows_is_refused() {
    let err = FileRegion::new(null_fd(), u64::MAX, 1).expect_err("the range cannot exist");

    assert_eq!(
        err,
        FileRegionError::RangeOverflow {
            offset: u64::MAX,
            len: 1,
        }
    );
}

#[test]
fn the_largest_representable_range_is_accepted() {
    let region = FileRegion::new(null_fd(), u64::MAX, 0).expect("the range fits exactly");
    assert_eq!(region.end_offset(), u64::MAX);

    let region = FileRegion::new(null_fd(), 0, u64::MAX).expect("the range fits exactly");
    assert_eq!(region.end_offset(), u64::MAX);
}

#[test]
fn a_region_hands_its_descriptor_back() {
    let region = FileRegion::new(null_fd(), 0, 1).expect("the range fits in a u64");
    let borrowed = region.fd();
    let _ = borrowed;
    let _owned: OwnedFd = region.into_fd();
}
