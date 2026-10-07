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

//! The RustFS-profile switch that answers a customer-provided key on a cleartext connection where
//! and as legacy RustFS answers it: before routing and authentication, on every request, with its
//! sentence (rustfs/gateway#1349).
//!
//! Responsible for: [`ServiceBuilder::refuse_plaintext_customer_keys_before_routing`], the
//! sentence, and [`PlaintextCustomerKeys::refusal`], which the pipeline asks once the head is
//! accepted.
//! NOT responsible for: which key positions a deployment refuses over cleartext (its
//! [`rustfs_gateway_core::SseConfig`]), whether the connection is encrypted (the transport's
//! [`rustfs_gateway_core::TransportSecurity`]), or the gate the pipeline keeps after
//! authorization (`rustfs_gateway_core::sse::enforce`), which this one answers ahead of.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! With `RUSTFS_SSE_C_REQUIRE_TLS` set, legacy RustFS refuses a request carrying any of the six
//! customer-key headers — the target object's algorithm, key and key MD5, and the copy source's
//! (rustfs/rustfs `5c9941707`, rustfs#8296, added the copy source's) — on a connection that is not
//! TLS, in a layer that runs before CORS, its SigV4 header guard, routing and signature
//! verification (rustfs/rustfs `95268a3b9`, `rustfs/src/server/ssec_transport.rs:69-149`, installed
//! at `rustfs/src/server/http.rs:2107`). A header counts when present, an empty value included.
//! Measured on a native build of that revision: a signed PUT, an unsigned one and one with a forged
//! signature, a copy naming only a copy-source key, a GET with an empty key-MD5 header, an admin
//! request and a CORS preflight each carrying such a header all answer `400 InvalidRequest` with
//! [`RUSTFS_PLAINTEXT_CUSTOMER_KEY`].
//!
//! The gateway's own gate refuses the same requests after authorization, so an unsigned or
//! badly signed request is answered `403` there; under this switch it is answered as legacy RustFS
//! answers it. Nothing is served under the switch that is refused without it.

use http::HeaderMap;
use rustfs_gateway_core::sse::headers::{
    COPY_SSEC_ALGORITHM, COPY_SSEC_KEY, COPY_SSEC_KEY_MD5, SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5,
};
use rustfs_gateway_core::{HandlerError, ResponseKind, SseConfig, TransportSecurity};
use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::close::ConnectionIntent;
use crate::render::{S3Error, from_handler};

/// Legacy RustFS's sentence for a customer-provided key on a cleartext connection.
pub(crate) const RUSTFS_PLAINTEXT_CUSTOMER_KEY: &str =
    "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.";

/// Whether the cleartext customer-key gate answers before routing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PlaintextCustomerKeys {
    /// After authorization, with the gateway's sentence: the default.
    #[default]
    AfterAuthorization,
    /// Before routing and authentication, with legacy RustFS's sentence.
    BeforeRouting,
}

impl PlaintextCustomerKeys {
    /// The refusal a request is owed before it is routed: under [`Self::BeforeRouting`], on a
    /// cleartext connection, when it carries a customer-key header of a position `sse` refuses
    /// over cleartext.
    pub(crate) fn refusal(
        self,
        sse: &SseConfig,
        connection: TransportSecurity,
        headers: &HeaderMap,
        response: ResponseKind,
    ) -> Option<S3Error> {
        if self != Self::BeforeRouting || connection != TransportSecurity::Plaintext {
            return None;
        }
        let present = |names: [&str; 3]| names.iter().any(|name| headers.contains_key(*name));
        let target = !sse.allows_customer_keys_over_plaintext() && present([SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5]);
        let copy_source =
            !sse.allows_copy_source_keys_over_plaintext() && present([COPY_SSEC_ALGORITHM, COPY_SSEC_KEY, COPY_SSEC_KEY_MD5]);
        (target || copy_source).then(|| {
            from_handler(
                HandlerError::new(ErrorCode::INVALID_REQUEST, RUSTFS_PLAINTEXT_CUSTOMER_KEY),
                response,
                ConnectionIntent::MayKeepAlive,
            )
        })
    }
}

impl ServiceBuilder {
    /// Answers a customer-provided key on a cleartext connection before the request is routed or
    /// authenticated, on every request, with legacy RustFS's sentence, as RustFS does with
    /// `RUSTFS_SSE_C_REQUIRE_TLS` set (rustfs/gateway#1349).
    ///
    /// The positions refused are the assembly's [`rustfs_gateway_core::SseConfig`]'s: under
    /// [`SseConfig::strict`] all six headers, under
    /// [`SseConfig::refusing_only_target_keys_over_plaintext`] the target's three, under
    /// [`SseConfig::allowing_customer_keys_over_plaintext`] none. A header counts when present,
    /// whatever it holds. Off by default: the gateway refuses the same requests after authorization,
    /// with its own sentence.
    #[must_use]
    pub fn refuse_plaintext_customer_keys_before_routing(mut self) -> Self {
        self.view_policy.plaintext_customer_keys = PlaintextCustomerKeys::BeforeRouting;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use rustfs_gateway_core::PlaintextCustomerKeyAck;

    fn head(name: &str, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
        map
    }

    fn answer(gate: PlaintextCustomerKeys, sse: &SseConfig, connection: TransportSecurity, map: &HeaderMap) -> Option<String> {
        gate.refusal(sse, connection, map, ResponseKind::Other)
            .map(|refusal| refusal.message().unwrap_or_default().to_owned())
    }

    const SIX: [&str; 6] = [
        SSEC_ALGORITHM,
        SSEC_KEY,
        SSEC_KEY_MD5,
        COPY_SSEC_ALGORITHM,
        COPY_SSEC_KEY,
        COPY_SSEC_KEY_MD5,
    ];

    /// Negative — under the strict configuration every one of the six headers, an empty value
    /// included, is refused over cleartext with legacy's sentence and code.
    #[test]
    fn n_every_customer_key_header_over_cleartext_is_refused() {
        let strict = SseConfig::strict();
        for name in SIX {
            for value in ["AES256", ""] {
                let map = head(name, value);
                let refusal = PlaintextCustomerKeys::BeforeRouting
                    .refusal(&strict, TransportSecurity::Plaintext, &map, ResponseKind::Other)
                    .expect("a refusal");
                assert_eq!(refusal.message(), Some(RUSTFS_PLAINTEXT_CUSTOMER_KEY), "{name}");
                assert_eq!(refusal.code(), Some(&ErrorCode::INVALID_REQUEST), "{name}");
                assert_eq!(refusal.status(), http::StatusCode::BAD_REQUEST, "{name}");
            }
        }
    }

    /// Negative — the configuration decides the positions: target-only gates the target's three,
    /// the open configuration none.
    #[test]
    fn n_the_configuration_decides_which_positions_are_refused() {
        let ack = PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear;
        let target_only = SseConfig::refusing_only_target_keys_over_plaintext(ack());
        let open = SseConfig::allowing_customer_keys_over_plaintext(ack());
        for (index, name) in SIX.into_iter().enumerate() {
            let map = head(name, "AES256");
            let gated = answer(PlaintextCustomerKeys::BeforeRouting, &target_only, TransportSecurity::Plaintext, &map);
            assert_eq!(gated.is_some(), index < 3, "{name}");
            assert_eq!(
                answer(PlaintextCustomerKeys::BeforeRouting, &open, TransportSecurity::Plaintext, &map),
                None,
                "{name}"
            );
        }
    }

    /// Positive — an encrypted connection, a request with no customer-key header, and the default
    /// placement are never refused here.
    #[test]
    fn what_the_gate_does_not_reach_passes() {
        let strict = SseConfig::strict();
        let key = head(SSEC_ALGORITHM, "AES256");
        assert_eq!(
            answer(PlaintextCustomerKeys::BeforeRouting, &strict, TransportSecurity::Encrypted, &key),
            None
        );
        let other = head("x-amz-server-side-encryption", "AES256");
        assert_eq!(
            answer(PlaintextCustomerKeys::BeforeRouting, &strict, TransportSecurity::Plaintext, &other),
            None
        );
        assert_eq!(
            answer(PlaintextCustomerKeys::AfterAuthorization, &strict, TransportSecurity::Plaintext, &key),
            None
        );
    }
}
