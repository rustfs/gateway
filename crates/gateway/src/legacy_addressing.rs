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

//! The two pipeline positions of legacy RustFS's path addressing (rustfs/gateway#1115): `GET //`
//! read as `GET /` before anything else sees the request, and the path judged before routing.
//!
//! Responsible for: [`rewrite_double_slash_root`] and [`classify`], each a no-op unless the
//! assembly's naming policy selects [`PathSplit::RustfsLegacy`].
//! NOT responsible for: the split and the name rules themselves
//! ([`rustfs_gateway_core::codec::legacy_rustfs_target`]), or the switch that selects them
//! (`crate::builder::names`).
//! Upstream: `crate::service`. Downstream: acceptance and routing, which read what these leave.

use http::Method;
use http::request::Parts;
use rustfs_gateway_core::codec::legacy_rustfs_target;
use rustfs_gateway_core::route::ClaimLookup;
use rustfs_gateway_core::{CodecError, RouteRequestParts, Router};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_types::{NamePolicy, PathSplit};

use crate::ext::ResolvedHost;

/// Reads a `GET` of exactly `//` as a `GET` of `/`, query kept, before acceptance, so that routing
/// and the signature both read `/`.
///
/// Legacy-compat (rustfs/backlog#2684): RustFS's `DoubleSlashListBucketsCompat` layer rewrites the
/// request target this way ahead of its S3 service (`rustfs/src/server/layer.rs:2311-2366` on
/// rustfs/rustfs `e870a6d25b`), because the AWS S3 browser sends `GET //` for `ListBuckets` with a
/// signature computed over `/`. A signature over a path the client did not send is questionable,
/// and it makes `GET //` signed over `//` fail; kept so that browser keeps listing its buckets. The
/// intended future behaviour is routing `GET //` to `ListBuckets` with the signature verified over
/// the path sent.
pub(crate) fn rewrite_double_slash_root(names: &NamePolicy, parts: &mut Parts) {
    if names.path_split() != PathSplit::RustfsLegacy || parts.method != Method::GET || parts.uri.path() != "//" {
        return;
    }
    let target = match parts.uri.query() {
        Some(query) => format!("/?{query}"),
        None => "/".to_owned(),
    };
    let mut uri = std::mem::take(&mut parts.uri).into_parts();
    // The rewritten target is the original query behind `/`, which parses whenever the original
    // did; if it ever did not, the request goes on unrewritten rather than altered some other way.
    let Ok(path_and_query) = target.parse() else {
        parts.uri = http::Uri::from_parts(uri).unwrap_or_default();
        return;
    };
    uri.path_and_query = Some(path_and_query);
    parts.uri = http::Uri::from_parts(uri).unwrap_or_default();
}

/// The target routing reads under legacy RustFS's split, judged before routing, or the refusal
/// legacy RustFS answers with there. A request inside a dialect's path-prefix claim is left as the
/// resolver classified it: legacy RustFS's own routes also claim their paths before its path
/// parser runs.
pub(crate) fn classify<B>(
    names: &NamePolicy,
    router: &Router,
    wire: &WireRequest<B>,
    mut resolved: ResolvedHost,
) -> Result<ResolvedHost, CodecError> {
    if names.path_split() != PathSplit::RustfsLegacy {
        return Ok(resolved);
    }
    let parts = RouteRequestParts {
        method: wire.method(),
        path: wire.raw_path().as_str(),
        target: resolved.target,
        host_class: resolved.host_class,
        arn_form: resolved.arn_form,
        query: wire.query(),
        headers: wire.headers(),
        host_named_bucket: resolved.bucket().is_some(),
    };
    if matches!(router.claims().lookup(&parts), ClaimLookup::Inside { .. }) {
        return Ok(resolved);
    }
    resolved.target = legacy_rustfs_target(wire.raw_path().as_str(), resolved.bucket().is_some(), names)?;
    Ok(resolved)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn legacy() -> NamePolicy {
        NamePolicy::default().with_legacy_rustfs_path_split()
    }

    fn rewritten(names: &NamePolicy, method: Method, target: &str) -> String {
        let (mut parts, ()) = http::Request::builder()
            .method(method)
            .uri(target)
            .body(())
            .expect("a valid request")
            .into_parts();
        rewrite_double_slash_root(names, &mut parts);
        parts.uri.to_string()
    }

    /// Positive — exactly `GET //` is read as `GET /`, with its query.
    #[test]
    fn a_get_of_double_slash_is_the_service_root() {
        assert_eq!(rewritten(&legacy(), Method::GET, "//"), "/");
        assert_eq!(rewritten(&legacy(), Method::GET, "//?x-id=ListBuckets"), "/?x-id=ListBuckets");
    }

    fn accepted(method: Method, target: &str) -> WireRequest<()> {
        let request = http::Request::builder()
            .method(method)
            .uri(target)
            .header("host", "s3.example.com")
            .body(())
            .expect("a valid request");
        WireRequest::accept(request, &rustfs_gateway_http::Limits::default()).expect("an acceptable request")
    }

    /// A router over the generated table and one claim, `/_iceberg/v1`, whose first segment no
    /// bucket rule admits: the shape of RustFS's own table-catalog prefix.
    fn claiming_router() -> Router {
        use rustfs_gateway_core::route::{ClaimedTable, InstalledClaim, PathClaim, RouteTable, SHADOWING, ShadowingDecls};
        let claims = ClaimedTable::build(
            vec![InstalledClaim {
                dialect: "fixture",
                claim: PathClaim {
                    prefix: "/_iceberg/v1",
                    reason: "a fixture claim whose first segment is no bucket name",
                    evidence: &["https://github.com/rustfs/gateway/issues/1115"],
                },
            }],
            Vec::new(),
            &ShadowingDecls::NONE,
        )
        .expect("a valid claim");
        let table = RouteTable::build(rustfs_gateway_core::route::generated_entries().expect("the generated rows"), &SHADOWING)
            .expect("the generated table");
        Router::with_claims(table, claims, rustfs_gateway_core::Registry::default()).expect("a router")
    }

    /// The target `classify` leaves for `target`, which the default resolver classified `literal`.
    fn classified(
        names: &NamePolicy,
        target: &str,
        literal: rustfs_gateway_core::TargetKind,
    ) -> Result<rustfs_gateway_core::TargetKind, rustfs_gateway_types::ErrorCode> {
        let wire = accepted(Method::GET, target);
        let resolved = ResolvedHost::standard(literal);
        classify(names, &claiming_router(), &wire, resolved)
            .map(|resolved| resolved.target)
            .map_err(|error| error.code().clone())
    }

    /// Positive — outside a claim the legacy split decides the target, before routing.
    #[test]
    fn the_legacy_split_decides_the_target() {
        use rustfs_gateway_core::TargetKind;
        assert_eq!(classified(&legacy(), "/bkt%2Fkey", TargetKind::Bucket), Ok(TargetKind::Object));
        assert_eq!(
            classified(&NamePolicy::default(), "/bkt%2Fkey", TargetKind::Bucket),
            Ok(TargetKind::Bucket),
            "the literal split"
        );
    }

    /// Negative — a claimed path is left as the resolver classified it, even when its first
    /// segment is no bucket name, as legacy RustFS's own routes take their paths first.
    #[test]
    fn n_a_claimed_path_is_not_judged_as_s3_addressing() {
        use rustfs_gateway_core::TargetKind;
        assert_eq!(classified(&legacy(), "/_iceberg/v1/config", TargetKind::Object), Ok(TargetKind::Object));
        assert_eq!(
            classified(&legacy(), "/_iceberg/x", TargetKind::Object),
            Err(rustfs_gateway_types::ErrorCode::INVALID_BUCKET_NAME),
            "outside the claim the same segment is refused"
        );
    }

    /// Negative — nothing else is rewritten: another method, a longer path, or the default split.
    #[test]
    fn n_nothing_else_is_rewritten() {
        for (method, target) in [
            (Method::HEAD, "//"),
            (Method::PUT, "//"),
            (Method::GET, "///"),
            (Method::GET, "//bkt"),
            (Method::GET, "/%2F"),
            (Method::GET, "/bkt//key"),
        ] {
            assert_eq!(rewritten(&legacy(), method.clone(), target), target, "{method} {target}");
        }
        assert_eq!(rewritten(&NamePolicy::default(), Method::GET, "//"), "//", "only under the legacy split");
    }
}
