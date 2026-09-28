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

//! Responsible for: deciding what a failed `accept(2)` means for the listener: a failure local to
//! one queued connection, a process-wide resource shortage that clears, or a broken listener.
//! NOT responsible for: admission limits, counting, or backoff timing; the accept loop in
//! `conn.rs` owns those. Upstream: `tokio::net::TcpListener::accept`. Downstream: `run_server`.

use std::io;
use std::time::Duration;

/// How long the accept loop waits before retrying after the process ran out of a resource. Long
/// enough not to spin on a full descriptor table, short enough that a freed descriptor is used
/// promptly; shutdown is honoured during the wait.
pub(crate) const EXHAUSTED_BACKOFF: Duration = Duration::from_millis(50);

/// What one failed accept means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptFailure {
    /// The queued connection failed, or the accepted socket could not be described; the listener
    /// is healthy and the next connection may be accepted at once.
    Connection,
    /// The process or system is out of descriptors, buffers or memory; retrying immediately
    /// would spin, and the listener stays up to accept once the shortage clears.
    Exhausted,
    /// The listening socket itself is unusable; serving cannot continue.
    Fatal,
}

/// Classifies one `accept` error.
///
/// Linux's accept(2) passes a queued connection's pending network error back as the accept error
/// and asks callers to retry on `ENETDOWN`, `EPROTO`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`,
/// `EHOSTUNREACH`, `EOPNOTSUPP` and `ENETUNREACH`. macOS can complete an accept whose peer
/// address has length zero because the connection was reset while queued; Mio reports that as
/// an `InvalidInput` error with no OS error code. Anything unrecognised is fatal, which is what
/// every accept error was before this classification existed.
pub(crate) fn classify(error: &io::Error) -> AcceptFailure {
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => return AcceptFailure::Connection,
        // The kernel's own EINVAL (a listener that is not listening) carries its OS code.
        io::ErrorKind::InvalidInput if error.raw_os_error().is_none() => return AcceptFailure::Connection,
        io::ErrorKind::OutOfMemory => return AcceptFailure::Exhausted,
        _ => {}
    }
    classify_os(error.raw_os_error())
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn classify_os(code: Option<i32>) -> AcceptFailure {
    use nix::errno::Errno;
    let Some(errno) = code.map(Errno::from_raw) else {
        return AcceptFailure::Fatal;
    };
    match errno {
        Errno::EMFILE | Errno::ENFILE | Errno::ENOBUFS | Errno::ENOMEM => AcceptFailure::Exhausted,
        // EPERM is a firewall refusing this one connection, not a property of the listener.
        Errno::ENETDOWN
        | Errno::EPROTO
        | Errno::ENOPROTOOPT
        | Errno::EHOSTDOWN
        | Errno::EHOSTUNREACH
        | Errno::EOPNOTSUPP
        | Errno::ENETUNREACH
        | Errno::EPERM => AcceptFailure::Connection,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Errno::ENONET => AcceptFailure::Connection,
        _ => AcceptFailure::Fatal,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn classify_os(_code: Option<i32>) -> AcceptFailure {
    AcceptFailure::Fatal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn a_connection_that_failed_while_queued_does_not_end_the_listener() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
        ] {
            assert_eq!(classify(&io::Error::from(kind)), AcceptFailure::Connection, "{kind:?}");
        }
    }

    #[test]
    fn an_accepted_socket_without_a_peer_address_does_not_end_the_listener() {
        let unaddressable = io::Error::new(io::ErrorKind::InvalidInput, "invalid socket address");
        assert_eq!(classify(&unaddressable), AcceptFailure::Connection);
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn the_os_errors_accept_asks_callers_to_retry_are_connection_local() {
        use nix::errno::Errno;
        for errno in [
            Errno::ECONNABORTED,
            Errno::ENETDOWN,
            Errno::EPROTO,
            Errno::ENOPROTOOPT,
            Errno::EHOSTDOWN,
            Errno::EHOSTUNREACH,
            Errno::EOPNOTSUPP,
            Errno::ENETUNREACH,
            Errno::EPERM,
        ] {
            assert_eq!(classify(&os(errno as i32)), AcceptFailure::Connection, "{errno:?}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn a_resource_shortage_is_waited_out_rather_than_fatal() {
        use nix::errno::Errno;
        for errno in [Errno::EMFILE, Errno::ENFILE, Errno::ENOBUFS, Errno::ENOMEM] {
            assert_eq!(classify(&os(errno as i32)), AcceptFailure::Exhausted, "{errno:?}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn a_broken_listening_socket_still_ends_the_listener() {
        use nix::errno::Errno;
        for errno in [Errno::EBADF, Errno::ENOTSOCK, Errno::EINVAL, Errno::EFAULT] {
            assert_eq!(classify(&os(errno as i32)), AcceptFailure::Fatal, "{errno:?}");
        }
    }

    #[test]
    fn an_unrecognised_error_still_ends_the_listener() {
        assert_eq!(classify(&io::Error::other("unknown")), AcceptFailure::Fatal);
        assert_eq!(classify(&io::Error::from(io::ErrorKind::PermissionDenied)), AcceptFailure::Fatal);
    }
}
