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

//! What the transport knew about the client, as one value both authorization stages and the
//! handler context read (rustfs/backlog#2752).
//!
//! Responsible for: [`ClientFacts`] — the socket peer, whether the transport was secure, and the
//! client address a host attested after its trusted-proxy rules — and [`ClientFacts::observed`],
//! the one derivation from the values already installed in a request's extensions: the server
//! runtime's `ConnectionInfo`, a host's `TransportSecurity` (the customer-key gate's input) and a
//! host's `ClientAddr` (the governor's input).
//! NOT responsible for: parsing `X-Forwarded-For`, `Forwarded` or any other client header —
//! nothing here reads a header, and a value that is not in the extension bag does not exist; nor
//! for deciding anything with the facts, which is the authorizer's and the handler's.
//! Upstream: `rustfs-gateway-server` (`ConnectionInfo`), `rustfs-gateway-core`
//! (`TransportSecurity`), `super::governor` (`ClientAddr`), and a host's `StageFilter::on_wire`
//! through `WireHead::set_client_facts`.
//! Downstream: `crate::service` installs the observed value before the wire seam;
//! `RequestContext::client` and `RequestContextView::transport_extensions` read it.
//!
//! # Why the default is not a fact
//!
//! [`ClientFacts::default`] is the base every derivation and every override starts from, and it
//! says the least that can be said: no peer, no client address, and a transport that is **not**
//! secure. A default of `transport_secure: true` would turn every request nobody annotated into
//! one a policy's `aws:SecureTransport` condition admits — the shape of a development deployment
//! serving customer keys over HTTP. The same reasoning makes [`ClientFacts::observed`] answer
//! `None` rather than the default when nothing at all was installed: "unknown" and "cleartext
//! from nowhere" are different answers, and a policy engine must be able to tell them apart.

use std::net::{IpAddr, SocketAddr};

use rustfs_gateway_core::TransportSecurity;

use super::ClientAddr;

/// What the transport knew about the client of one request.
///
/// Installed by the facade from the values the transport and the host put in the request
/// extensions, or by a host through `WireHead::set_client_facts`, which replaces the whole value.
/// Read through `RequestContext::client` by both authorization stages and through
/// `RequestContextView::transport_extensions` by a handler.
///
/// # Security
///
/// The derived `Default` is the least that can be said — no peer, no client address, and a
/// transport that is **not** secure — and it is the base every derivation and every host override
/// starts from. Nothing a client sends reaches any field: the peer is the listener's socket, the
/// transport bit is the listener's handshake or the host's own declaration, and the client address
/// is the host's attestation; `X-Forwarded-For`, `Forwarded` and `X-Forwarded-Proto` are never
/// read. A `Default` that leaned the other way would admit every unannotated request to a policy's
/// `aws:SecureTransport` condition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClientFacts {
    /// The socket peer the listener accepted, when a listener reported one. Behind a proxy this
    /// is the proxy.
    pub peer: Option<SocketAddr>,
    /// Whether the connection was secure: the listener completed TLS, or a host declared
    /// `TransportSecurity::Encrypted` for a connection it terminated TLS on. `false` unless one of
    /// them said so.
    pub transport_secure: bool,
    /// The client address a host attested after applying its own trusted-proxy rules; never a
    /// raw `X-Forwarded-For` value. `None` when no host attested one.
    pub client_ip: Option<IpAddr>,
}

impl ClientFacts {
    /// The address a policy's `aws:SourceIp` is judged against: the attested client address when
    /// a host supplied one, otherwise the socket peer's; `None` when neither is known.
    #[must_use]
    pub fn source_ip(&self) -> Option<IpAddr> {
        self.client_ip.or_else(|| self.peer.map(|peer| peer.ip()))
    }

    /// The facts the values already installed in `extensions` add up to, or `None` when none of
    /// them is present.
    ///
    /// A `ClientFacts` a host installed itself wins outright. Otherwise the server runtime's
    /// `ConnectionInfo` supplies the peer and whether TLS completed, a `TransportSecurity` adds a
    /// host's own word on the transport, and a `ClientAddr` supplies the attested client address.
    /// Every field starts from [`Self::default`].
    #[must_use]
    pub(crate) fn observed(extensions: &http::Extensions) -> Option<Self> {
        if let Some(installed) = extensions.get::<Self>() {
            return Some(*installed);
        }
        let mut facts = Self::default();
        let mut present = false;
        #[cfg(feature = "server")]
        if let Some(connection) = extensions.get::<rustfs_gateway_server::ConnectionInfo>() {
            present = true;
            facts.peer = Some(connection.peer_addr());
            facts.transport_secure = connection.transport() == rustfs_gateway_server::TransportKind::Tls;
        }
        if let Some(security) = extensions.get::<TransportSecurity>() {
            present = true;
            facts.transport_secure |= *security == TransportSecurity::Encrypted;
        }
        if let Some(address) = extensions.get::<ClientAddr>() {
            present = true;
            facts.client_ip = Some(address.ip());
        }
        present.then_some(facts)
    }

    /// Installs [`Self::observed`] into `extensions`, where the wire seam can read and correct it
    /// and acceptance then freezes it. A request nobody annotated gets nothing installed, and one
    /// a host layer already annotated keeps the host's value without a second write.
    pub(crate) fn install(extensions: &mut http::Extensions) {
        if extensions.get::<Self>().is_some() {
            return;
        }
        if let Some(facts) = Self::observed(extensions) {
            extensions.insert(facts);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use rustfs_gateway_core::TransportSecurity;

    use super::ClientFacts;
    use crate::ext::ClientAddr;

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
    }

    /// Negative — the default says the least it can: nothing known, and not secure.
    #[test]
    fn n_the_default_knows_nothing_and_is_not_secure() {
        let facts = ClientFacts::default();
        assert_eq!(facts.peer, None);
        assert_eq!(facts.client_ip, None);
        assert!(!facts.transport_secure);
        assert_eq!(facts.source_ip(), None);
    }

    /// Negative — a request nobody annotated has no facts at all, which is distinct from the
    /// default.
    #[test]
    fn n_an_empty_bag_yields_no_facts() {
        assert_eq!(ClientFacts::observed(&http::Extensions::new()), None);
    }

    /// Negative — a host that declares cleartext is believed, and the declaration alone makes
    /// the facts present with nothing else known.
    #[test]
    fn n_a_declared_cleartext_transport_is_present_and_not_secure() {
        let mut extensions = http::Extensions::new();
        extensions.insert(TransportSecurity::Plaintext);
        assert_eq!(ClientFacts::observed(&extensions), Some(ClientFacts::default()));
    }

    /// Negative — a host's own `ClientFacts` wins over the other values, even where it contradicts
    /// them: it is the later and more specific word.
    #[test]
    fn n_installed_facts_win_over_a_contradicting_declaration() {
        let installed = ClientFacts {
            peer: Some(SocketAddr::new(address(), 4433)),
            transport_secure: false,
            client_ip: None,
        };
        let mut extensions = http::Extensions::new();
        extensions.insert(TransportSecurity::Encrypted);
        extensions.insert(ClientAddr::from_peer(address()));
        extensions.insert(installed);
        assert_eq!(ClientFacts::observed(&extensions), Some(installed));
    }

    /// Negative — installing into an empty bag leaves it empty: no placeholder is written for a
    /// request nobody annotated.
    #[test]
    fn n_install_writes_nothing_into_an_empty_bag() {
        let mut extensions = http::Extensions::new();
        ClientFacts::install(&mut extensions);
        assert!(extensions.is_empty());
        assert!(extensions.get::<ClientFacts>().is_none());
    }

    /// Positive — installing records what was declared, readable by type afterwards.
    #[test]
    fn install_records_what_was_declared() {
        let mut extensions = http::Extensions::new();
        extensions.insert(ClientAddr::from_peer(address()));
        ClientFacts::install(&mut extensions);
        assert_eq!(
            extensions.get::<ClientFacts>(),
            Some(&ClientFacts {
                peer: None,
                transport_secure: false,
                client_ip: Some(address()),
            })
        );
    }

    /// Positive — the values a host installs for the customer-key gate and the governor add up.
    #[test]
    fn a_declared_secure_transport_and_a_client_address_add_up() {
        let mut extensions = http::Extensions::new();
        extensions.insert(TransportSecurity::Encrypted);
        extensions.insert(ClientAddr::from_peer(address()));
        let facts = ClientFacts::observed(&extensions).expect("two values were installed");
        assert_eq!(
            facts,
            ClientFacts {
                peer: None,
                transport_secure: true,
                client_ip: Some(address()),
            }
        );
        assert_eq!(facts.source_ip(), Some(address()));
    }

    /// Positive — without an attested client address the source address is the peer's.
    #[test]
    fn the_source_address_falls_back_to_the_peer() {
        let facts = ClientFacts {
            peer: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000)),
            ..ClientFacts::default()
        };
        assert_eq!(facts.source_ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
