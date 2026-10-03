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

//! The per-client connection ceiling (rustfs/gateway#1210).
//!
//! Responsible for: counting open connections per client and refusing one past
//! `ServerConfig::max_connections_per_ip`.
//! NOT responsible for: the global connection ceiling or request permits (`conn`,
//! `request_capacity`), or rate limits, which a service applies above this crate.
//! Upstream: the accept loop in `conn`. Downstream: none.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};

/// The client a peer address belongs to, which is what the ceiling counts: an IPv4 address, or an
/// IPv6 `/64`.
///
/// One IPv6 host is assigned at least a `/64`, so counting whole addresses would let one host hold
/// as many seats as it has addresses to spend. The address is canonicalised first: a dual-stack
/// listener reports an IPv4 client as `::ffff:a.b.c.d`, every one of which shares the `/64` `::`,
/// and keyed as written every IPv4 client of such a listener would share one set of seats. The
/// gateway's per-client governor keys the same way (`crates/gateway/src/ext/governor.rs`).
fn client_key(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(u128::from(address) & (u128::MAX << 64))),
    }
}

pub(crate) struct IpCounts {
    limit: Option<usize>,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl IpCounts {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            limit,
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn try_acquire(&self, peer: IpAddr) -> Option<IpLease> {
        let ip = client_key(peer);
        let Some(limit) = self.limit else {
            return Some(IpLease { ip, counts: None });
        };
        let mut counts = lock_recover(&self.counts);
        let count = counts.entry(ip).or_default();
        if *count >= limit {
            return None;
        }
        *count = count.saturating_add(1);
        Some(IpLease {
            ip,
            counts: Some(Arc::clone(&self.counts)),
        })
    }
}

pub(crate) struct IpLease {
    ip: IpAddr,
    counts: Option<Arc<Mutex<HashMap<IpAddr, usize>>>>,
}

impl Drop for IpLease {
    fn drop(&mut self) {
        let Some(counts) = &self.counts else { return };
        let mut counts = lock_recover(counts);
        let remove = if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove {
            counts.remove(&self.ip);
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only address literals are fixed and valid.
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::IpCounts;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a fixture address")
    }

    /// Negative — one IPv6 host holds at least a `/64`, so two addresses in one prefix are one
    /// client: the second is refused at a ceiling of one. Before #1210 each address had its own
    /// seat, so the prefix held as many connections as it had addresses to spend.
    #[test]
    fn two_addresses_in_one_ipv6_prefix_share_one_ceiling() {
        let counts = IpCounts::new(Some(1));
        let _first = counts
            .try_acquire(ip("2001:db8:1:2::1"))
            .expect("the first connection is admitted");
        assert!(
            counts.try_acquire(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")).is_none(),
            "a second address in the same /64 was admitted as another client"
        );
    }

    /// Negative — an IPv4 client reported through a dual-stack listener as `::ffff:a.b.c.d` is the
    /// same client as that IPv4 address.
    #[test]
    fn an_ipv4_mapped_peer_is_the_same_client_as_its_ipv4_address() {
        let counts = IpCounts::new(Some(1));
        let _first = counts
            .try_acquire(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
            .expect("the first connection is admitted");
        assert!(
            counts.try_acquire(ip("::ffff:192.0.2.1")).is_none(),
            "the mapped form of an admitted IPv4 client was admitted as another client"
        );
    }

    /// Negative — a seat released by a closed connection is the one the next connection from that
    /// prefix takes; the count does not drift.
    #[test]
    fn a_released_seat_is_reused_by_the_same_prefix_and_no_more() {
        let counts = IpCounts::new(Some(1));
        let first = counts
            .try_acquire(ip("2001:db8::1"))
            .expect("the first connection is admitted");
        drop(first);
        let _second = counts.try_acquire(ip("2001:db8::2")).expect("the released seat is reused");
        assert!(counts.try_acquire(ip("2001:db8::3")).is_none(), "the prefix holds more than its ceiling");
    }

    /// Positive — different `/64`s, and different IPv4 clients behind one dual-stack listener, are
    /// different clients: none of them is charged for another.
    #[test]
    fn different_prefixes_and_different_ipv4_clients_are_counted_apart() {
        let counts = IpCounts::new(Some(1));
        let _prefix = counts.try_acquire(ip("2001:db8:1:2::1")).expect("a first /64");
        let _other_prefix = counts.try_acquire(ip("2001:db8:1:3::1")).expect("a second /64");
        let _mapped = counts.try_acquire(ip("::ffff:192.0.2.1")).expect("a first IPv4 client");
        let _other_mapped = counts.try_acquire(ip("::ffff:192.0.2.2")).expect("a second IPv4 client");
    }
}
