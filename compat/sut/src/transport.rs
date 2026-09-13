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

//! Telling the gateway whether the socket a request arrived on was encrypted.
//!
//! Responsible for: translating the listener's [`ConnectionInfo`] into the
//! [`TransportSecurity`] extension `S3Service` reads, on every request, for both listeners.
//! NOT responsible for: the handshake (`rustfs-gateway-server`), or deciding what an encrypted
//! transport permits (`rustfs_gateway_core::sse::enforce`).
//! Upstream: the listeners `main` starts. Downstream: `crate::probe::ProbeService`, then `S3Service`.
//!
//! Without this the gateway sees no extension and fails closed to
//! [`TransportSecurity::Plaintext`], so a TLS listener would still refuse every customer-provided
//! key. The value is always overwritten, never trusted if already present: only the accepted
//! socket may say what it was.

use std::task::{Context, Poll};

use http::Request;
use rustfs_gateway::TransportSecurity;
use rustfs_gateway_server::{ConnectionInfo, TransportKind};

/// Inserts the connection's [`TransportSecurity`] before calling `inner`.
#[derive(Clone)]
pub(crate) struct DeclareTransport<S> {
    inner: S,
}

impl<S> DeclareTransport<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self { inner }
    }
}

/// What the accepted socket was. A request with no connection record — one that did not come
/// through a listener at all — is plaintext.
pub(crate) fn transport_security(extensions: &http::Extensions) -> TransportSecurity {
    match extensions.get::<ConnectionInfo>().map(|connection| connection.transport()) {
        Some(TransportKind::Tls) => TransportSecurity::Encrypted,
        Some(TransportKind::Plaintext) | None => TransportSecurity::Plaintext,
    }
}

impl<S, B> tower::Service<Request<B>> for DeclareTransport<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let security = transport_security(request.extensions());
        request.extensions_mut().insert(security);
        self.inner.call(request)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::transport_security;

    use rustfs_gateway::TransportSecurity;

    /// Negative — a request that no listener accepted is plaintext, and so is one that already
    /// carries a claim of encryption but no connection record: the claim is not the socket.
    #[test]
    fn n_without_a_connection_record_the_transport_is_plaintext() {
        assert_eq!(transport_security(&http::Extensions::new()), TransportSecurity::Plaintext);
        let mut claimed = http::Extensions::new();
        claimed.insert(TransportSecurity::Encrypted);
        assert_eq!(transport_security(&claimed), TransportSecurity::Plaintext);
    }
}
