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

//! A half-open byte range of an owned file descriptor.
//!
//! Responsible for: naming the one payload shape a kernel-side transfer can consume, and
//! rejecting a range that cannot exist before anyone tries to transfer it.
//! NOT responsible for: performing the transfer. No `sendfile`, `splice` or ring submission
//! happens here — that needs an i/o driver, and an i/o driver would drag a runtime into a crate
//! that every downstream tree depends on. The transfer belongs to the transport layer.
//! Upstream: `std::os::fd`. Downstream: `payload`, and the transport that asks a payload for a
//! file region before it picks a write strategy.

use core::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// A file descriptor plus the half-open range `[offset, offset + len)` inside it.
///
/// The descriptor is owned: a borrowed one would need a lifetime parameter, and a payload with
/// a lifetime parameter cannot be moved through the stages of an asynchronous pipeline without
/// becoming self-referential.
#[derive(Debug)]
pub struct FileRegion {
    fd: OwnedFd,
    offset: u64,
    len: u64,
}

/// A file region that cannot exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRegionError {
    /// `offset + len` does not fit in a `u64`.
    ///
    /// Rejected at construction rather than at transfer time: an overflowing end offset would
    /// either wrap — turning a range into a different, valid-looking range — or panic deep
    /// inside a transport, where the request that caused it is no longer in scope.
    RangeOverflow {
        /// The requested start offset.
        offset: u64,
        /// The requested length.
        len: u64,
    },
}

impl FileRegion {
    /// Builds a region, rejecting a range whose end offset does not fit in a `u64`.
    pub fn new(fd: OwnedFd, offset: u64, len: u64) -> Result<Self, FileRegionError> {
        if offset.checked_add(len).is_none() {
            return Err(FileRegionError::RangeOverflow { offset, len });
        }
        Ok(Self { fd, offset, len })
    }

    /// Borrows the descriptor.
    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// The start offset of the region inside the file.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The length of the region in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the region is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The end offset of the region; never overflows, because construction rejects that case.
    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.offset + self.len
    }

    /// Consumes the region and returns the owned descriptor.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

impl fmt::Display for FileRegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RangeOverflow { offset, len } => write!(f, "file region offset {offset} plus length {len} overflows a u64"),
        }
    }
}

impl std::error::Error for FileRegionError {}
