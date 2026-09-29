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
use rustfs_gateway_core::codec::{legacy_rustfs_decodable, legacy_rustfs_target};
use rustfs_gateway_core::route::ClaimLookup;
use rustfs_gateway_core::{CodecError, RouteRequestParts, Router};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_types::{ErrorCode, NamePolicy, PathSplit};

use crate::ext::target_of_path;
use crate::ext::{HostQuery, HostRefusal, HostResolver, ResolvedHost};

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
/// legacy RustFS answers with there — the host resolver's among them, in legacy RustFS's order: an
/// undecodable path, then a host it cannot read, then (outside a claim) a bucket the host names
/// that its rules refuse, then the path's own bucket and key. A request inside a dialect's
/// path-prefix claim is left as the resolver classified it: legacy RustFS's own routes also claim
/// their paths before its path parser runs.
pub(crate) fn classify<B>(
    names: &NamePolicy,
    resolver: &dyn HostResolver,
    router: &Router,
    wire: &WireRequest<B>,
    mut resolved: ResolvedHost,
) -> Result<ResolvedHost, CodecError> {
    let refusal = resolver.refusal(&HostQuery {
        host: wire.host(),
        path: wire.raw_path().as_str(),
        method: wire.method(),
    });
    let legacy_split = names.path_split() == PathSplit::RustfsLegacy;
    if !legacy_split && refusal.is_none() {
        return Ok(resolved);
    }
    if legacy_split {
        legacy_rustfs_decodable(wire.raw_path().as_str())?;
    }
    if refusal == Some(HostRefusal::UnusableHost) {
        return Err(CodecError::new(ErrorCode::INVALID_REQUEST, "Invalid host header"));
    }
    // Legacy-compat (rustfs/backlog#2684): legacy RustFS matches its own routes by the path alone,
    // whatever bucket the host names, so on a virtual host a claimed path is the dialect's and an
    // object key spelling the same path is unreachable there; ADR-0024's rule is the opposite (a
    // bucket's key space holds no claim). Kept under the legacy split so an admin client addressing
    // a RustFS host that also names a bucket keeps reaching the admin API; the intended future
    // behaviour is ADR-0024's.
    if legacy_split && resolved.bucket().is_some() {
        let path_style = ResolvedHost::standard(target_of_path(wire.raw_path().as_str()));
        if claimed(router, wire, &path_style) {
            return Ok(path_style);
        }
    }
    if claimed(router, wire, &resolved) {
        return Ok(resolved);
    }
    if refusal == Some(HostRefusal::RefusedBucket) {
        return Err(CodecError::new(ErrorCode::INVALID_BUCKET_NAME, "The specified bucket is not valid").about("Bucket"));
    }
    if legacy_split {
        resolved.target = legacy_rustfs_target(wire.raw_path().as_str(), resolved.bucket().is_some(), names)?;
    }
    Ok(resolved)
}

/// Whether a dialect's claim covers the request under this reading of its host.
fn claimed<B>(router: &Router, wire: &WireRequest<B>, resolved: &ResolvedHost) -> bool {
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
    matches!(router.claims().lookup(&parts), ClaimLookup::Inside { .. })
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
        classify(names, &crate::ext::PathStyleOnly, &claiming_router(), &wire, resolved)
            .map(|resolved| resolved.target)
            .map_err(|error| error.code().clone())
    }

    /// Negative — legacy RustFS decodes the whole path before its own routes take theirs, so an
    /// undecodable claimed path is `InvalidURI` under the legacy split, and the dialect's otherwise.
    #[test]
    fn n_an_undecodable_claimed_path_is_an_invalid_uri() {
        use rustfs_gateway_core::TargetKind;
        assert_eq!(
            classified(&legacy(), "/_iceberg/v1/a%FF", TargetKind::Object),
            Err(rustfs_gateway_types::ErrorCode::INVALID_URI)
        );
        assert_eq!(
            classified(&NamePolicy::default(), "/_iceberg/v1/a%FF", TargetKind::Object),
            Ok(TargetKind::Object)
        );
    }

    /// Positive — a claimed path on a host that names a bucket is the dialect's under the legacy
    /// split, read path-style, and the bucket's object under the default.
    #[test]
    fn a_claimed_path_on_a_virtual_host_is_the_dialects() {
        use rustfs_gateway_core::TargetKind;
        let wire = accepted(Method::GET, "/_iceberg/v1/config");
        let hosted = || {
            ResolvedHost::virtual_hosted(
                TargetKind::Object,
                rustfs_gateway_types::BucketName::new("vhb").expect("a bucket"),
                None,
            )
        };
        let legacy_reading =
            classify(&legacy(), &crate::ext::PathStyleOnly, &claiming_router(), &wire, hosted()).expect("the dialect's");
        assert_eq!(legacy_reading.bucket(), None, "read path-style");
        let default_reading = classify(&NamePolicy::default(), &crate::ext::PathStyleOnly, &claiming_router(), &wire, hosted())
            .expect("no refusal");
        assert_eq!(default_reading.bucket().map(rustfs_gateway_types::BucketName::as_str), Some("vhb"));
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
