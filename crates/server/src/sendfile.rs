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

//! Safe platform normalization for one file-to-socket transfer attempt.
//!
//! Responsible for: adapting Linux and Apple `sendfile` signatures into one progress result.
//! NOT responsible for: socket readiness, write deadlines, HTTP framing or retry policy.
//! Upstream: the bounded file-transfer handoff. Downstream: `nix`'s safe syscall wrappers.

use std::io;
use std::os::fd::BorrowedFd;

use crate::sendfile_task::BlockingFileTransferPermit;

pub(crate) const MAX_CHUNK: u64 = 0x7fff_f000;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn send_file(
    _permit: &BlockingFileTransferPermit,
    socket: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    offset: u64,
    count: usize,
) -> io::Result<usize> {
    let mut offset = nix::libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file region offset exceeds sendfile range"))?;
    nix::sys::sendfile::sendfile(socket, file, Some(&mut offset), count).map_err(Into::into)
}

#[cfg(target_vendor = "apple")]
pub(crate) fn send_file(
    _permit: &BlockingFileTransferPermit,
    socket: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    offset: u64,
    count: usize,
) -> io::Result<usize> {
    let offset = nix::libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file region offset exceeds sendfile range"))?;
    let count = nix::libc::off_t::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file region length exceeds sendfile range"))?;
    let (result, written) = nix::sys::sendfile::sendfile(file, socket, offset, Some(count), None, None);
    if written > 0 {
        usize::try_from(written).map_err(io::Error::other)
    } else {
        result.map(|()| 0).map_err(Into::into)
    }
}
