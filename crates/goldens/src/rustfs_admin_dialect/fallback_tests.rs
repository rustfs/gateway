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

//! Assembled-service controls for unmatched admin requests (ADR-0039).
//!
//! Responsible for: downgrade and ordinary fallback answers, signature refusals, both policy
//! stages and preservation of a registered operation's denial.
//! NOT responsible for: native observations, socket/body progress, or generator completeness.
//! Upstream: `super`'s real SigV4 assembly and the admin dialect. Downstream: nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::Request;
use rustfs_gateway_dialect_rustfs_admin::ROUTES;

use super::{ACCESS_KEY, ContextRequest, PATH_HOST, REGION, assemble_on, paths, rustfs_profile_floor, signed, wire};

fn request(path: &str) -> ContextRequest {
    ContextRequest::get(PATH_HOST, path, "").signed(REGION)
}

/// Positive — the exact prefix, its slash and a descendant share the empty downgrade answer.
#[test]
fn unmatched_v4_has_an_empty_downgrade_answer() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for suffix in ["/v4", "/v4/", "/v4/gateway-absent"] {
            let path = format!("{prefix}{suffix}");
            let exchange = assembled.exchange(wire(&request(&path)));
            assert_eq!(exchange.status, 426, "{path}: {}", exchange.body);
            assert!(exchange.body.is_empty(), "{path}: {}", exchange.body);
        }
    }
}

/// Negative — even a globally permissive anonymous floor cannot expose either fallback answer.
#[test]
fn n_an_unsigned_fallback_is_refused_before_policy() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for suffix in ["/v4/gateway-absent", "/v3/gateway-absent"] {
            let path = format!("{prefix}{suffix}");
            let request = Request::builder()
                .uri(&path)
                .header("host", PATH_HOST)
                .body(Bytes::new())
                .expect("a fixture request");
            let exchange = assembled.exchange(request);
            assert_eq!(exchange.status, 403, "{path}: {}", exchange.body);
            assert!(exchange.body.contains("<Code>AccessDenied</Code>"), "{path}");
            assert!(exchange.asked.is_empty(), "{path}: {:?}", exchange.asked);
            assert!(exchange.reached.is_empty(), "{path}: {:?}", exchange.reached);
        }
    }
}

/// Negative — neither a forged known key nor an unknown key reaches policy or a handler.
#[test]
fn n_a_forged_or_unknown_fallback_is_refused_before_policy() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for suffix in ["/v4/gateway-absent", "/v3/gateway-absent"] {
            let path = format!("{prefix}{suffix}");
            for request in [request(&path).forged(), request(&path).unknown_key()] {
                let exchange = assembled.exchange(wire(&request));
                assert_eq!(exchange.status, 403, "{path}: {}", exchange.body);
                assert!(exchange.asked.is_empty(), "{path}: {:?}", exchange.asked);
                assert!(exchange.reached.is_empty(), "{path}: {:?}", exchange.reached);
            }
        }
    }
}

/// Negative — either policy stage can withhold the downgrade signal from an authenticated caller.
#[test]
fn n_either_policy_stage_can_deny_the_downgrade() {
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        let path = format!("{prefix}/v4/gateway-absent");
        for deny_at in [0, 1] {
            let calls = AtomicUsize::new(0);
            let assembled = assemble_on(rustfs_profile_floor(), move |_, _| calls.fetch_add(1, Ordering::SeqCst) != deny_at);
            let exchange = assembled.exchange(wire(&request(&path)));
            assert_eq!(exchange.status, 403, "{path}, deny {deny_at}: {}", exchange.body);
            assert!(exchange.body.contains("<Code>AccessDenied</Code>"), "{path}");
            let stages: Vec<_> = exchange.asked.iter().map(|asked| asked.stage).collect();
            let expected = if deny_at == 0 { vec!["route"] } else { vec!["route", "input"] };
            assert_eq!(stages, expected, "{path}");
            assert!(exchange.reached.is_empty(), "{path}: {:?}", exchange.reached);
        }
    }
}

/// Negative — the non-v4 501 is not permission to skip either caller-only policy question.
#[test]
fn n_non_v4_prefixes_cannot_skip_authorization() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for suffix in [
            "",
            "/",
            "/v3/gateway-absent",
            "/v40/gateway-absent",
            "/v4-extra/gateway-absent",
        ] {
            let path = format!("{prefix}{suffix}");
            let exchange = assembled.exchange(wire(&request(&path)));
            assert_eq!(exchange.status, 501, "{path}: {}", exchange.body);
            assert!(exchange.body.contains("<Code>NotImplemented</Code>"), "{path}");
            assert!(
                exchange
                    .body
                    .contains("<Message>A header you provided implies functionality that is not implemented.</Message>"),
                "{path}: {}",
                exchange.body
            );
            let stages: Vec<_> = exchange.asked.iter().map(|asked| asked.stage).collect();
            assert_eq!(stages, ["route", "input"], "{path}");
            for asked in &exchange.asked {
                assert_eq!(asked.action, "rustfs:AdminFallback", "{path}");
                assert_eq!(asked.caller.as_deref(), Some(ACCESS_KEY), "{path}");
                assert_eq!(asked.subject, Some(None), "{path}");
                assert_eq!((asked.bucket.as_deref(), asked.key.as_deref()), (None, None), "{path}");
            }
        }
    }
}

/// Negative — a registered v4 operation's denial must never retry the downgrade operation.
#[test]
fn n_a_registered_v4_denial_does_not_fall_back() {
    let record = ROUTES
        .iter()
        .find(|record| record.path.starts_with("/rustfs/admin/v4/") && !record.anonymous)
        .expect("the inventory has registered privileged v4 routes");
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| false);
    for path in paths(record) {
        let exchange = assembled.exchange(wire(&signed(record, &path)));
        assert_eq!(exchange.status, 403, "{path}: {}", exchange.body);
        assert_eq!(exchange.asked.len(), 1, "{path}");
        assert_eq!(exchange.asked[0].operation, record.operation, "{path}");
        assert!(exchange.reached.is_empty(), "{path}: {:?}", exchange.reached);
    }
}

/// Negative — a nonempty raw parameter is still a registered native route, even when its value
/// contains a dot segment or an encoded separator. It must not turn into an SDK downgrade.
#[test]
fn n_a_registered_raw_parameter_does_not_become_a_downgrade() {
    let record = ROUTES
        .iter()
        .find(|record| record.method == "GET" && record.path == "/rustfs/admin/v4/plugins/instances/{id}")
        .expect("the recorded native instance route");
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for (raw, decoded) in [("gateway-absent", "gateway-absent"), ("%2e%2e", ".."), ("a%2Fb", "a/b")] {
            let path = format!("{prefix}/v4/plugins/instances/{raw}");
            let exchange = assembled.exchange(wire(&signed(record, &path)));
            assert_eq!(exchange.status, 200, "{path}: the recording handler's response, not a fallback");
            assert_eq!(exchange.reached, [record.operation], "{path}");
            assert!(exchange.handed[0].params.contains(&("id".to_owned(), decoded.to_owned())), "{path}");
        }
    }
}

/// The unmatched response still requires both caller-only policy decisions and no bucket scope.
pub(super) fn assert_general_fallback_policy(exchange: &super::Exchange, at: &str) {
    let stages: Vec<_> = exchange.asked.iter().map(|asked| asked.stage).collect();
    assert_eq!(stages, ["route", "input"], "{at}");
    for asked in &exchange.asked {
        assert_eq!(asked.operation, "rustfs:AdminFallback", "{at}");
        assert_eq!(asked.action, "rustfs:AdminFallback", "{at}");
        assert_eq!(asked.caller.as_deref(), Some(ACCESS_KEY), "{at}");
        assert_eq!(asked.subject, Some(None), "{at}");
        assert_eq!((asked.bucket.as_deref(), asked.key.as_deref()), (None, None), "{at}");
    }
}

/// Negative — fallback handlers cannot acquire a secret, bucket, or query-chosen subject.
#[test]
fn n_fallback_context_cannot_be_widened_by_query_data() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for (suffix, operation, status) in [
            ("/v4/gateway-absent", "rustfs:AdminV4Fallback", 426),
            ("/v3/gateway-absent", "rustfs:AdminFallback", 501),
        ] {
            let path = format!("{prefix}{suffix}");
            let request =
                ContextRequest::get(PATH_HOST, &path, "accessKey=someone-else&bucket=private&user=someone-else").signed(REGION);
            let exchange = assembled.exchange(wire(&request));
            assert_eq!(exchange.status, status, "{path}");
            assert_eq!(exchange.reached, [operation], "{path}: the fixed handler must actually run");
            assert_eq!(exchange.handed.len(), 1, "{path}");
            let handed = &exchange.handed[0];
            assert!(!handed.holds_secret && !handed.secret_is_the_callers, "{path}");
            assert_eq!(handed.subjects, "caller", "{path}");
            assert!(handed.has_one_subject, "{path}");
            assert_eq!(handed.bucket, None, "{path}");
            assert_eq!(
                handed.params,
                [(
                    "remainder".to_owned(),
                    if status == 426 {
                        "gateway-absent"
                    } else {
                        "v3/gateway-absent"
                    }
                    .to_owned()
                )],
                "{path}"
            );
            assert_eq!(exchange.asked.len(), 2, "{path}");
            for asked in &exchange.asked {
                assert_eq!(asked.subject, Some(None), "{path}");
                assert_eq!((asked.bucket.as_deref(), asked.key.as_deref()), (None, None), "{path}");
            }
        }
    }
}

/// Negative — a matched real operation with no handler keeps the framework's unregistered
/// answer; registration failure must never retry a fallback and tell an SDK to downgrade.
#[test]
fn n_a_missing_registered_handler_does_not_turn_into_a_downgrade() {
    let record = ROUTES
        .iter()
        .find(|record| record.operation == "rustfs:GetV4PluginsInstancesById")
        .expect("registered v4 route");
    let assembled = super::assemble_with_profile(rustfs_profile_floor(), |_, _| true, false, Some(record.operation));
    for path in paths(record) {
        let exchange = assembled.exchange(wire(&signed(record, &path)));
        assert_eq!(exchange.status, 501, "{path}: {}", exchange.body);
        assert!(exchange.body.contains("<Code>NotImplemented</Code>"), "{path}");
        assert!(exchange.asked.is_empty(), "{path}");
        assert!(exchange.reached.is_empty(), "{path}");
    }
}
