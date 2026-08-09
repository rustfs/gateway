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

//! What a deployment writes to put its own identity store behind the gateway.
//!
//! Responsible for: the two shapes of [`rustfs_gateway::CredentialProvider`] — a hand-written
//! `impl` and the closure adapter — a long-term principal and an STS session beside each other,
//! and the three answers a lookup may give, including the one most implementations get wrong.
//! NOT responsible for: verifying a signature (the framework does that, and nothing here can stop
//! it), deciding permissions (that is `Authorizer`), or being a real identity store — there is no
//! I/O here at all.
//! Upstream: `rustfs-gateway`. Downstream: nothing; this is a leaf.
//!
//! # The three answers, and the fourth that does not exist
//!
//! * `Ok(CredentialLookup::Found(credentials))` — the access key is known. Finding it is **not** authentication: the
//!   framework still derives a signing key from the secret and compares in constant time, and only
//!   that comparison produces the receipt an authenticated verdict requires.
//! * `Ok(CredentialLookup::NotFound)` — no principal under that access key. The framework answers
//!   `403` after doing the same derivation work a known key costs, so the two are not separable by
//!   latency.
//! * `Err(ProviderError::Unavailable)` — the store could not answer. Fail closed: the framework
//!   answers the same `403`, never anonymous.
//!
//! There is no fourth answer that skips verification. In particular, returning a blanket secret —
//! or an empty one — for a key the store does not recognise does not wave the request through; the
//! derivation runs against those bytes and the comparison fails. It is the shape this example
//! exists to *not* show.

use std::collections::HashMap;
use std::sync::Arc;

use rustfs_gateway::{
    BoxFuture, CredentialLookup, CredentialProvider, Credentials, ProviderError, RegionSet, SessionBinding, SigV4Authenticator,
    fn_credential_provider,
};

/// An identity store that happens to be a map. A real one awaits a database here.
struct DirectoryProvider {
    /// Access key id to the secret and, for an STS issuance, its whole session.
    principals: HashMap<String, Credentials>,
    /// Whether the store is reachable. A real implementation would learn this from a connection
    /// pool or a circuit breaker rather than from a field.
    reachable: bool,
}

impl CredentialProvider for DirectoryProvider {
    /// Held as `Arc<dyn CredentialProvider>`, so this is a hand-written `BoxFuture` (ADR-0002).
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        Box::pin(async move {
            if !self.reachable {
                // Fail closed. Never `Unknown`: telling every client its credentials are wrong
                // during an outage is how a database blip becomes a support incident, and never
                // anonymous, which is how it becomes a breach.
                return Err(ProviderError::Unavailable);
            }
            // Byte for byte, and case-sensitively: the access key id is part of what was signed,
            // so a lenient match accepts a signature computed over different bytes.
            self.principals
                .get(access_key_id)
                .map(Credentials::clone_credentials)
                .map_or(Ok(CredentialLookup::NotFound), |credentials| Ok(CredentialLookup::Found(credentials)))
        })
    }
}

/// The same store, written as a closure for a deployment whose lookup is one function.
///
/// It can answer nothing a hand-written implementation cannot — in particular it cannot produce a
/// verdict, because the trait does not return one.
fn closure_form() -> impl CredentialProvider {
    fn_credential_provider(|access_key_id: &str| {
        let found = if access_key_id == "AKIDLONGTERMEXAMPLE" {
            CredentialLookup::Found(
                Credentials::new("AKIDLONGTERMEXAMPLE", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
                    .expect("the fixture access key is valid"),
            )
        } else {
            CredentialLookup::NotFound
        };
        Box::pin(async move { Ok(found) })
    })
}

fn main() {
    let mut principals = HashMap::new();

    // A long-term principal: an access key and a secret, and nothing else. It carries no session
    // token, so a request that presents one is refused rather than run as this principal.
    let long_term = Credentials::new("AKIDLONGTERMEXAMPLE", b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .expect("a well-formed access key id"); // Fixture literals; a real store validates what it read.
    principals.insert("AKIDLONGTERMEXAMPLE".to_owned(), long_term);

    // A temporary principal, from this deployment's own STS. The token and the lifetime go in
    // together: there is no method that takes one without the other, so "a session that never
    // expires" is not a state the framework can hold. The issuer and the policy handle are
    // opaque — the framework stores them for the audit record and parses neither.
    let binding = SessionBinding::new("sts.example.com", 4_102_444_800)
        .expect("a well-formed issuer")
        .with_inline_policy("policy-blob-7")
        .expect("a well-formed handle");
    let session = Credentials::new("ASIDSESSIONEXAMPLE", b"5ZXcQfQm9nY0hK7wLpRs2VtBnMxJ4uEaCvDgHiKl")
        .expect("a well-formed access key id")
        .with_session("FQoGZXIvYXdzEExampleSessionTokenValue", binding)
        .expect("a non-empty token");
    principals.insert("ASIDSESSIONEXAMPLE".to_owned(), session);

    // A principal that exists and has been switched off. It is answered exactly as an access key
    // that does not exist is — same status, same code, same bytes — because "this key exists but
    // is disabled" confirms the key exists to whoever is guessing.
    let retired = Credentials::new("AKIDRETIREDEXAMPLE", b"CzQeXvBn4mKp8sLw1RtYu6IoAd3FgHjKl9MnBvCx")
        .expect("a well-formed access key id")
        .disable();
    principals.insert("AKIDRETIREDEXAMPLE".to_owned(), retired);

    let provider = Arc::new(DirectoryProvider {
        principals,
        reachable: true,
    });

    // Either form drops straight into the assembly.
    let regions = RegionSet::new(["us-east-1"]).expect("a non-empty region set");
    let _authenticator = SigV4Authenticator::new(Arc::clone(&provider) as Arc<dyn CredentialProvider>, regions.clone());
    let _closure_authenticator = SigV4Authenticator::new(Arc::new(closure_form()), regions);

    println!("credential provider wired: 3 principals, one of them a session and one of them disabled");
}
