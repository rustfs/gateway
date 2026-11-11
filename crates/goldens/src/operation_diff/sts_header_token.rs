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

//! The STS endpoint against a host-verified header token (ADR-0053, rustfs/gateway#1586).
//!
//! Responsible for: that the STS form, whose floor admits an anonymous Web Identity request,
//! refuses the same request once it carries the claimed header, before the authorizer and
//! without the host's verifier being asked.
//! NOT responsible for: the STS request matrix through both stacks, or the fixtures (`super`).
//! Upstream: `super` (`sts_parity`). Downstream: nothing.

use super::*;

/// Negative — the STS endpoint issues credentials and refuses a host-verified header token
/// (ADR-0053), although its floor is not privileged and admits the anonymous Web Identity form.
/// With the claim installed, the form reaches its handler without the header and is refused with
/// it, before the authorizer, and the host's verifier is never asked.
#[test]
fn n_the_sts_endpoint_refuses_a_header_token_it_would_serve_without() {
    use rustfs_gateway::{HeaderTokenClaim, HeaderTokenRefused, HeaderTokenVerifier, Identity};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What the host's outer layer left in the request; the spy would name it if it were asked.
    #[derive(Clone)]
    struct Outer;
    struct Spy(Arc<AtomicUsize>);

    impl HeaderTokenVerifier for Spy {
        type Established = Outer;

        fn identity(&self, _established: &Outer, _now: RequestNow) -> Result<Identity, HeaderTokenRefused> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Identity::new("KEYSTONEUSER").map_err(|_| HeaderTokenRefused)
        }
    }

    let now = RequestNow::capture();
    let form = b"Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=x.y.z";
    let sent = Sent::new(Signing::Anonymous).body(Bytes::from_static(form));
    let verifier_asked = Arc::new(AtomicUsize::new(0));
    for with_token in [false, true] {
        let reached = Arc::new(Mutex::new(None));
        let asked: Asked = Arc::new(Mutex::new(Vec::new()));
        let claim = HeaderTokenClaim::new("x-auth-token").expect("a legal claim");
        let service = gateway_builder(now, &asked)
            .host_verified_header_token(claim, Spy(Arc::clone(&verifier_asked)))
            .register::<StsFormPost, _>(Arc::new(Sts {
                handed: Arc::clone(&reached),
            }))
            .build()
            .expect("a complete assembly");
        let mut request = sent.request(now);
        if with_token {
            let token = http::HeaderValue::from_static("gAAAAABheader-token-sentinel");
            request.headers_mut().insert("x-auth-token", token);
            request.extensions_mut().insert(Outer);
        }
        let response = block_on(service.call_bytes(request));
        let collected = block_on(rustfs_gateway::collect(response)).expect("an in-memory answer");
        let reached = reached.lock().expect("uncontended").take();
        let questions = std::mem::take(&mut *asked.lock().expect("uncontended"));
        let body = String::from_utf8_lossy(collected.body()).into_owned();
        if with_token {
            assert_eq!(collected.status().as_u16(), 403, "{body}");
            assert_eq!(element(&body, "Code").as_deref(), Some("AccessDenied"), "{body}");
            assert!(reached.is_none() && questions.is_empty(), "{reached:?} {questions:?}");
            assert!(!body.to_ascii_lowercase().contains("sentinel"), "{body}");
        } else {
            assert_eq!(collected.status().as_u16(), 200, "{body}");
            assert!(reached == handed(None, &sent), "the control: the anonymous form reaches its handler");
        }
    }
    assert_eq!(verifier_asked.load(Ordering::SeqCst), 0, "the host's verifier was asked");
}
