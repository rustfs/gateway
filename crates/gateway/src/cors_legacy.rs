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

//! The CORS answers legacy RustFS gives, for the RustFS profile (rustfs/gateway#1120).
//!
//! Responsible for: [`LegacyRustfsCors`], the setting; which paths legacy RustFS treats as S3 paths
//! and which bucket it reads a request's CORS document from; the deployment-wide fallback headers
//! (`RUSTFS_CORS_ALLOWED_ORIGINS`); the headers a bucket's stored rules give a preflight or an
//! ordinary request; and the status a preflight is answered with.
//! NOT responsible for: reading a document (the deployment's `CorsSource`, through the mandatory
//! cache in `crate::ext::cors`), or where in the pipeline these run (`crate::service`'s CORS stage).
//! The gateway's own CORS runtime, `rustfs_gateway_core::cors`, stays the default.
//! Upstream: `crate::builder`. Downstream: `crate::service::cors`.
//!
//! # What legacy RustFS does
//!
//! RustFS answers CORS in a tower layer around its legacy stack (`ConditionalCorsLayer`,
//! `rustfs/src/server/layer.rs:2012-2309`, rustfs/rustfs#1496, #2026, #2053, #2774) and in its
//! object handlers, both through one rule evaluation (`apply_cors_headers`,
//! `rustfs/src/storage/ecfs_extend.rs:852-1060`):
//!
//! - **Every `OPTIONS`** is answered by the layer, before routing and authentication. On `/` and on
//!   an S3 path it is `400` with no body unless both `Origin` and `Access-Control-Request-Method`
//!   are present. On `/`, and on an S3 path whose bucket has no CORS document (or does not exist),
//!   it is `200` with the fallback headers. On an S3 path whose bucket has a document it is `200`
//!   with the matched rule's headers, or `403` with no body when no rule matches. On any other path
//!   (admin, table catalog, console, RPC, health, profiling) it is `200` with the fallback headers.
//! - **Every other request carrying `Origin`** gets its answer decorated, refusals before
//!   authentication included, unless the answer already names an allowed origin (the object
//!   handlers write their own): on an S3 path with a bucket, the bucket's document decides and
//!   replaces any CORS header already there — a document with no matching rule leaves none — and
//!   without a document the fallback headers apply; `/` and other paths get the fallback headers.
//!   Here the bucket's document decides whatever the handler wrote: RustFS's object handlers write
//!   the answer this module computes, so only the credentials differ (see below).
//! - The bucket is the first path segment, however the request was addressed.
//! - A rule matches when an allowed origin is `*`, equal to `Origin`, or a one-`*` pattern whose two
//!   halves prefix and suffix it; when an allowed method equals `Access-Control-Request-Method` if
//!   the request has one and its own method otherwise; and, on a preflight that lists requested
//!   headers, when the rule allows every one of them (`*` or equal, ignoring case) — a rule with no
//!   allowed headers matches no such preflight. Methods outside `GET`, `PUT`, `POST`, `DELETE`,
//!   `HEAD`, `OPTIONS` match nothing.
//! - A matched rule answers the origin — `*` for a wildcard rule unless the request is
//!   credentialed (it carries `Authorization`, `Cookie`, `x-amz-security-token` or
//!   `x-amz-content-sha256`), the request's own origin otherwise — with `Vary: Origin` when the
//!   origin is echoed, the rule's methods; and, on a preflight, the requested headers lower-cased
//!   and joined with `,`, a `Vary` naming the two request headers (and `Origin` when echoed), and
//!   the rule's `MaxAgeSeconds`; on an ordinary request, the rule's `ExposeHeaders`.
//! - The fallback headers come from `RUSTFS_CORS_ALLOWED_ORIGINS`: none when it is unset or empty;
//!   `Access-Control-Allow-Origin: *` when it is `*`; the request's origin when the origin is one of
//!   its comma-separated entries; each time with a fixed list of methods, `*` for headers, and five
//!   exposed headers.
//!
//! A header value that cannot be written is left out, as RustFS leaves it out.
//!
//! # What this module does not reproduce: credentials
//!
//! Legacy RustFS also answers `Access-Control-Allow-Credentials: true` to every credentialed
//! request a bucket rule matches — under a rule whose origin is `*` too, where it echoes the
//! request's origin, so any site that makes a browser send a cookie may read the answer — and to
//! an origin listed in `RUSTFS_CORS_ALLOWED_ORIGINS`. That is `GHSA-x5xv-223c-8vm7`'s shape, and
//! this crate writes that header from one place only, `rustfs_gateway_core::cors`'s answer
//! builder, under an operator's `CorsPolicy` (`scripts/check_cors_credentials_exclusive.sh`, which
//! admits no exemption). So these answers never allow credentials: a browser request made with
//! `credentials: "include"` that legacy RustFS let read its answer is refused by the browser here.
//! Whether RustFS keeps that allowance, and through which policy, is the maintainer's decision
//! (rustfs/gateway#1120).

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rustfs_gateway_core::cors::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use rustfs_gateway_types::dto::{CorsConfiguration, CorsRule};

/// The console prefix RustFS serves by default (`RUSTFS_CONSOLE_PREFIX`).
pub const DEFAULT_RUSTFS_CONSOLE_PREFIX: &str = "/rustfs/console";

/// The path prefixes legacy RustFS never treats as S3 paths: its admin API under both spellings,
/// the table catalog under both, and its internode RPC.
const NON_S3_PREFIXES: [&str; 5] = ["/rustfs/admin", "/minio/admin", "/iceberg/v1", "/_iceberg/v1", "/rustfs/rpc"];

/// The exact paths legacy RustFS never treats as S3 paths: health probes and profiling triggers.
const NON_S3_PATHS: [&str; 9] = [
    "/health",
    "/health/live",
    "/health/ready",
    "/minio/health/live",
    "/minio/health/ready",
    "/minio/health/cluster",
    "/minio/health/cluster/read",
    "/profile/cpu",
    "/profile/memory",
];

/// The console's fixed icon paths, which are console paths whatever its prefix.
const CONSOLE_PATHS: [&str; 3] = ["/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"];

/// The only methods a stored rule can admit.
const RULE_METHODS: [&str; 6] = ["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS"];

/// The fallback answer's fixed values.
const FALLBACK_METHODS: HeaderValue = HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS, HEAD");
const FALLBACK_HEADERS: HeaderValue = HeaderValue::from_static("*");
const FALLBACK_EXPOSED: HeaderValue =
    HeaderValue::from_static("x-request-id, x-amz-request-id, content-type, content-length, etag");

/// The two `Vary` values a matched preflight is answered with.
const PREFLIGHT_VARY_ECHOED: HeaderValue =
    HeaderValue::from_static("Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
const PREFLIGHT_VARY: HeaderValue = HeaderValue::from_static("Access-Control-Request-Method, Access-Control-Request-Headers");

/// Legacy RustFS's CORS answers, installed with [`crate::ServiceBuilder::answer_cors_as_legacy_rustfs`].
///
/// Every answer but one: credentials are never allowed (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyRustfsCors {
    fallback: Fallback,
    console_prefix: String,
}

/// `RUSTFS_CORS_ALLOWED_ORIGINS`, read once.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Fallback {
    None,
    Any,
    Listed(Vec<String>),
}

impl LegacyRustfsCors {
    /// Legacy RustFS's answers, with `fallback_origins` as `RUSTFS_CORS_ALLOWED_ORIGINS` reads —
    /// `None` or an empty value for none, `*` for any origin, or a comma-separated list — and the
    /// default console prefix.
    #[must_use]
    pub fn with_fallback_origins(fallback_origins: Option<&str>) -> Self {
        let fallback = match fallback_origins.map(str::trim) {
            None | Some("") => Fallback::None,
            Some("*") => Fallback::Any,
            Some(list) => Fallback::Listed(list.split(',').map(|entry| entry.trim().to_owned()).collect()),
        };
        Self {
            fallback,
            console_prefix: DEFAULT_RUSTFS_CONSOLE_PREFIX.to_owned(),
        }
    }

    /// The same answers for a deployment whose console is served under `prefix`
    /// (`RUSTFS_CONSOLE_PREFIX`), with no trailing `/`.
    #[must_use]
    pub fn with_console_prefix(mut self, prefix: &str) -> Self {
        prefix
            .strip_suffix('/')
            .unwrap_or(prefix)
            .clone_into(&mut self.console_prefix);
        self
    }

    /// Whether legacy RustFS treats `path` as an S3 path.
    pub(crate) fn is_s3_path(&self, path: &str) -> bool {
        !(NON_S3_PREFIXES.iter().any(|prefix| has_path_prefix(path, prefix))
            || CONSOLE_PATHS.contains(&path)
            || has_path_prefix(path, &self.console_prefix)
            || NON_S3_PATHS.contains(&path))
    }

    /// Which answer legacy RustFS gives an `OPTIONS` of `path`.
    pub(crate) fn preflight_plan<'a>(&self, path: &'a str, headers: &HeaderMap) -> PreflightPlan<'a> {
        let is_root = path == "/";
        if !is_root && !self.is_s3_path(path) {
            return PreflightPlan::Fallback;
        }
        if !headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD) || !headers.contains_key(ORIGIN) {
            return PreflightPlan::BadRequest;
        }
        if is_root {
            return PreflightPlan::Fallback;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers a preflight of a bucket without
        // a document — or of one that does not exist — `200` with its fallback headers, where the
        // bucket allows nothing and the gateway answers `403`; with no fallback origins the browser
        // still refuses, but the preflight reads as a success in logs and to a script. Kept for the
        // clients RustFS serves today; the intended future behaviour is the gateway's `403`.
        PreflightPlan::Bucket(first_segment(path))
    }

    /// Where legacy RustFS reads an ordinary request's CORS answer from, or `None` when the request
    /// carries no `Origin`.
    pub(crate) fn actual_plan<'a>(&self, path: &'a str, headers: &HeaderMap) -> Option<ActualPlan<'a>> {
        if !headers.contains_key(ORIGIN) {
            return None;
        }
        let bucket = first_segment(path);
        Some(if !self.is_s3_path(path) || path == "/" || bucket.is_empty() {
            ActualPlan::Fallback
        } else {
            ActualPlan::Bucket(bucket)
        })
    }

    /// The deployment-wide fallback headers for a request carrying `headers`.
    pub(crate) fn fallback_headers(&self, headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
        let Some(origin) = headers.get(ORIGIN).filter(|origin| origin.to_str().is_ok()) else {
            return Vec::new();
        };
        let allow_origin = match &self.fallback {
            Fallback::None => return Vec::new(),
            Fallback::Any => HeaderValue::from_static("*"),
            Fallback::Listed(list) if list.iter().any(|entry| entry.as_bytes() == origin.as_bytes()) => origin.clone(),
            Fallback::Listed(_) => return Vec::new(),
        };
        // Legacy RustFS also allows credentials to a listed origin; see the module documentation
        // for why these answers never do.
        vec![
            (ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin),
            (ACCESS_CONTROL_ALLOW_METHODS, FALLBACK_METHODS),
            (ACCESS_CONTROL_ALLOW_HEADERS, FALLBACK_HEADERS),
            (ACCESS_CONTROL_EXPOSE_HEADERS, FALLBACK_EXPOSED),
        ]
    }
}

/// How legacy RustFS answers one `OPTIONS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreflightPlan<'a> {
    /// `400` with no body: `Origin` or `Access-Control-Request-Method` is missing on `/` or an S3 path.
    BadRequest,
    /// `200` with the fallback headers.
    Fallback,
    /// The named bucket's document decides; with none, [`PreflightPlan::Fallback`].
    Bucket(&'a str),
}

/// Where legacy RustFS reads one ordinary request's CORS answer from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActualPlan<'a> {
    /// The fallback headers.
    Fallback,
    /// The named bucket's document; with none, [`ActualPlan::Fallback`].
    Bucket(&'a str),
}

/// The CORS headers a bucket's stored `configuration` gives a request of `method` carrying
/// `headers`: empty when the document has no rules, for a method no rule can admit, and when no
/// rule matches; `None` when the request carries no readable `Origin`, which legacy RustFS answers
/// as it answers a bucket without a document.
pub(crate) fn bucket_headers(
    configuration: &CorsConfiguration,
    method: &Method,
    headers: &HeaderMap,
) -> Option<Vec<(HeaderName, HeaderValue)>> {
    let origin = headers.get(ORIGIN)?.to_str().ok()?;
    if configuration.cors_rules.is_empty() || !RULE_METHODS.contains(&method.as_str()) {
        return Some(Vec::new());
    }
    let preflight = *method == Method::OPTIONS;
    let requested_method = headers
        .get(ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(method.as_str());
    let requested_headers: Option<Vec<String>> = if preflight {
        headers
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|value| value.to_str().ok())
            .map(|list| list.split(',').map(|name| name.trim().to_lowercase()).collect())
    } else {
        None
    };
    let Some(rule) = configuration
        .cors_rules
        .iter()
        .find(|rule| rule_matches(rule, origin, requested_method, requested_headers.as_deref()))
    else {
        return Some(Vec::new());
    };
    let credentialed = ["authorization", "cookie", "x-amz-security-token", "x-amz-content-sha256"]
        .iter()
        .any(|name| headers.contains_key(*name));
    let mut pairs: Vec<(HeaderName, HeaderValue)> = Vec::new();
    let wildcard = rule.allowed_origins.iter().any(|allowed| allowed == "*");
    let echoed = !wildcard || credentialed;
    if echoed {
        if let Ok(value) = HeaderValue::from_str(origin) {
            pairs.push((ACCESS_CONTROL_ALLOW_ORIGIN, value));
            pairs.push((VARY, HeaderValue::from_static("Origin")));
        }
    } else {
        pairs.push((ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*")));
    }
    let echoed = pairs.iter().any(|(name, _)| *name == VARY);
    // Legacy RustFS also allows credentials here, to every credentialed request; see the module
    // documentation for why these answers never do. Echoing the origin without them lets no page
    // read what a `*` would not have let it read.
    if (preflight || !rule.allowed_methods.is_empty())
        && let Ok(value) = HeaderValue::from_str(&rule.allowed_methods.join(", "))
    {
        pairs.push((ACCESS_CONTROL_ALLOW_METHODS, value));
    }
    if preflight
        && let Some(requested) = &requested_headers
        && let Ok(value) = HeaderValue::from_str(&requested.join(","))
    {
        pairs.push((ACCESS_CONTROL_ALLOW_HEADERS, value));
    }
    if preflight {
        let vary = if echoed { PREFLIGHT_VARY_ECHOED } else { PREFLIGHT_VARY };
        match pairs.iter_mut().find(|(name, _)| *name == VARY) {
            Some((_, value)) => *value = vary,
            None => pairs.push((VARY, vary)),
        }
    }
    if !preflight
        && !rule.expose_headers.is_empty()
        && let Ok(value) = HeaderValue::from_str(&rule.expose_headers.join(", "))
    {
        pairs.push((ACCESS_CONTROL_EXPOSE_HEADERS, value));
    }
    if preflight
        && let Some(seconds) = rule.max_age_seconds
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        pairs.push((ACCESS_CONTROL_MAX_AGE, value));
    }
    Some(pairs)
}

/// Whether one stored rule admits the request.
fn rule_matches(rule: &CorsRule, origin: &str, method: &str, requested_headers: Option<&[String]>) -> bool {
    let origin_matches = rule
        .allowed_origins
        .iter()
        .any(|allowed| allowed == "*" || allowed == origin || matches_origin_pattern(allowed, origin));
    if !origin_matches || !rule.allowed_methods.iter().any(|allowed| allowed == method) {
        return false;
    }
    match requested_headers {
        None => true,
        Some(requested) if rule.allowed_headers.is_empty() => requested.is_empty(),
        Some(requested) => requested.iter().all(|name| {
            rule.allowed_headers.iter().any(|allowed| {
                let allowed = allowed.to_lowercase();
                allowed == "*" || allowed == *name
            })
        }),
    }
}

/// A pattern with exactly one `*` matches an origin that begins with what precedes it and ends with
/// what follows it; a pattern with none matches itself; any other pattern matches nothing.
fn matches_origin_pattern(pattern: &str, origin: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == origin;
    }
    let mut parts = pattern.split('*');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(head), Some(tail), None) => origin.starts_with(head) && origin.ends_with(tail),
        _ => false,
    }
}

/// The prefix itself, or the prefix followed by `/` and anything.
fn has_path_prefix(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The first segment of `path`, after its leading slashes: legacy RustFS's bucket, however the
/// request was addressed.
fn first_segment(path: &str) -> &str {
    // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a request's CORS document from the
    // bucket its path's first segment names, however the request was addressed, so a
    // virtual-hosted request to `bucket.host/key/object` is answered from the document of a
    // bucket named `key`, and its own bucket's rules never apply. Kept so browsers see the answers
    // they see today; the intended future behaviour is the addressed bucket's document, as the
    // gateway's own runtime reads it.
    let trimmed = path.trim_start_matches('/');
    trimmed.split('/').next().unwrap_or(trimmed)
}

#[cfg(test)]
#[path = "cors_legacy_tests.rs"]
mod tests;
