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

//! Responsible for: accepted headers shared by both authorization stages without Debug disclosure.
//! NOT responsible for: interpreting policy conditions or authenticating the request.
//! Upstream: the real service pipeline; downstream: authorizer observation assertions.

use super::*;

struct Observation {
    input: bool,
    value: Option<String>,
    debug: String,
    raw: Vec<Vec<u8>>,
}

#[derive(Default)]
struct HeaderObserver {
    seen: Mutex<Vec<Observation>>,
}

impl HeaderObserver {
    fn observe(&self, context: &RequestContext<'_>, input: bool) {
        let value = context
            .headers()
            .and_then(|headers| headers.get_str(&http::HeaderName::from_static("x-policy-probe")));
        self.seen.lock().expect("not poisoned").push(Observation {
            input,
            value: value.map(str::to_owned),
            debug: format!("{context:?}"),
            raw: context
                .headers()
                .map(|headers| {
                    headers
                        .iter_raw()
                        .filter(|(name, _)| name.as_str() == "x-policy-probe")
                        .map(|(_, value)| value.as_bytes().to_vec())
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
}

impl Authorizer for HeaderObserver {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.observe(context, false);
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.observe(context, true);
        Box::pin(async move { request.decide_all(Decision::Allow, |_| Decision::Allow) })
    }
}

#[tokio::test]
async fn n_authz_headers_reach_both_stages_without_debug_disclosure_or_cross_request_reuse() {
    let observer = Arc::new(HeaderObserver::default());
    let service = base()
        .authorizer(Arc::clone(&observer) as Arc<dyn Authorizer>)
        .build()
        .expect("a complete assembly");
    let mut request = ping();
    request
        .headers_mut()
        .insert("x-policy-probe", http::HeaderValue::from_static("private-header-marker"));
    request
        .headers_mut()
        .append("x-policy-probe", http::HeaderValue::from_static("second-header-marker"));
    assert_eq!(exchange(&service, request).await.0, http::StatusCode::OK);
    assert_eq!(exchange(&service, ping()).await.0, http::StatusCode::OK);
    let seen = observer.seen.lock().expect("not poisoned");
    let values: Vec<_> = seen.iter().map(|seen| (seen.input, seen.value.as_deref())).collect();
    assert_eq!(
        values,
        [
            (false, Some("private-header-marker")),
            (true, Some("private-header-marker")),
            (false, None),
            (true, None)
        ]
    );
    let raw: Vec<_> = seen.iter().map(|seen| seen.raw.clone()).collect();
    let repeated = vec![b"private-header-marker".to_vec(), b"second-header-marker".to_vec()];
    assert_eq!(raw, [repeated.clone(), repeated, vec![], vec![]]);
    for Observation { debug, .. } in seen.iter() {
        assert!(
            !debug.contains("private-header-marker"),
            "authorization context Debug disclosed a header value"
        );
    }
}

#[test]
fn n_authz_headers_manual_context_has_no_request_values() {
    let policy = PolicySnapshot::of(Arc::new(()));
    let context = RequestContext::new(rustfs_gateway::RequestNow::from_unix_seconds(0), &policy);
    assert!(context.headers().is_none());
}

#[tokio::test]
async fn n_authz_headers_preserve_unreadable_unrelated_header_bytes() {
    let observer = Arc::new(HeaderObserver::default());
    let service = base()
        .authorizer(Arc::clone(&observer) as Arc<dyn Authorizer>)
        .build()
        .expect("a complete assembly");
    let mut request = ping();
    request
        .headers_mut()
        .insert("x-policy-probe", http::HeaderValue::from_bytes(&[0xff]).expect("opaque field bytes"));
    assert_eq!(exchange(&service, request).await.0, http::StatusCode::OK);
    let seen = observer.seen.lock().expect("not poisoned");
    assert_eq!(seen.len(), 2);
    for observed in seen.iter() {
        assert_eq!(observed.raw, [vec![0xff]]);
        assert!(observed.value.is_none(), "an unreadable value must not become text");
    }
}
