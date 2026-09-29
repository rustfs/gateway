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

//! The request-context half of the migration seam: what a RustFS app body reads from an
//! `s3s::S3Request` besides its input, rebuilt from what the gateway knows about one request.
//!
//! Responsible for: turning a [`GatewayRequestContext`] — the facts the gateway holds once a
//! request is accepted, resolved, authenticated and routed — into the context members of the
//! `s3s::S3Request<T>` of the revision this file is compiled against (`method`, `uri`, `headers`,
//! `extensions`, `credentials`, `region`, `service`, `trailing_headers`), around an input
//! converted elsewhere. A fact the s3s request cannot hold is a [`ConversionError`] naming the
//! member, never a default.
//! NOT responsible for: gathering those facts. A handler reads every one of them from its request
//! context (`Req::context`, ADR-0022) and copies them in — [`GatewayRequestContext::raw_headers`]
//! for the header lines, [`Principal::from_handler`] for the principal and its handed-over secret —
//! so an adapter needs no second source. Nor for the input members ([`super::put_object`],
//! [`super::get_bucket_location`]) or any RustFS extension type.
//! Upstream: the s3s request type of the enclosing revision. Downstream: the goldens context diff
//! under every seam revision (rustfs/backlog#1762), and the RustFS ring-2 adapter through the
//! revision RustFS links (rustfs/backlog#1752), which must add the RustFS extensions itself.
//!
//! # Extensions
//!
//! The produced request carries **no** extensions. Everything a RustFS app body reads from
//! `S3Request::extensions` is a RustFS type (`ReqInfo`, `RequestContext`, the server context slot,
//! `Option<RemoteAddr>`, the POST Object marker) installed by RustFS's own HTTP layer or access
//! hook, and this ring-0 crate may not name one. The ring-2 adapter owns installing them; an app
//! body that finds one missing already fails closed (`ReqInfo not found in request extensions`).

use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, Uri};

use super::s3s;
use s3s::S3Request;
use s3s::auth::{Credentials, SecretKey};
use s3s::region::Region;

use crate::compat::ConversionError;

/// Every context member of this revision's `s3s::S3Request`, in declaration order.
///
/// The goldens diff destructures the request with no `..` and pins its census to this list, so an
/// s3s re-pin that adds a member fails to compile there instead of going uncompared.
pub const S3S_CONTEXT_MEMBERS: &[&str] = &[
    "method",
    "uri",
    "headers",
    "extensions",
    "credentials",
    "region",
    "service",
    "trailing_headers",
];

/// The credential scope a SigV4 signature was verified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedScope {
    /// The region the signing key was scoped to, as the client spelled it.
    pub region: String,
    /// The service the signing key was scoped to, as the client spelled it.
    pub service: String,
}

/// Who an authenticated request runs as.
///
/// The secret is held as the s3s type so it is zeroized on drop and never printed; the s3s request
/// carries it because its credentials member does, not because any RustFS app body is known to read
/// it.
pub struct Principal {
    /// The access key id the signature named.
    pub access_key: String,
    /// The secret the credential store holds for that access key.
    pub secret_key: SecretKey,
    /// The verified scope, for SigV4. `None` for a scheme without one (SigV2).
    pub scope: Option<VerifiedScope>,
}

impl core::fmt::Debug for Principal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Principal")
            .field("access_key", &self.access_key)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl Principal {
    /// The principal a handler's request context names (ADR-0022): its access key id, the secret
    /// the gateway authenticator handed over (`RequestPrincipal::secret_key_from_authenticator_lookup`)
    /// and the verified scope.
    ///
    /// # Errors
    ///
    /// [`ConversionError`] naming `credentials` when no secret was handed over — s3s credentials
    /// always carry one, and this conversion does not invent it — or when the secret is not UTF-8,
    /// which the s3s secret type cannot spell.
    pub fn from_handler(
        access_key: &str,
        secret_key: Option<&[u8]>,
        scope: Option<VerifiedScope>,
    ) -> Result<Self, ConversionError> {
        let Some(secret_key) = secret_key else {
            return Err(refusal(
                "credentials",
                "the gateway authenticator did not hand the caller's secret to the handler",
            ));
        };
        let secret_key = core::str::from_utf8(secret_key).map_err(|_| refusal("credentials", "an s3s secret key is UTF-8"))?;
        Ok(Self {
            access_key: access_key.to_owned(),
            secret_key: SecretKey::from(secret_key),
            scope,
        })
    }
}

/// What the gateway knows about one request, beyond its decoded input.
#[derive(Debug)]
pub struct GatewayRequestContext {
    /// The request method.
    pub method: Method,
    /// The request path exactly as it arrived, still percent-encoded.
    pub raw_path: String,
    /// The query string exactly as it arrived, without its `?`. Empty when there is none.
    pub raw_query: String,
    /// Every accepted header line, in arrival order per name; see [`Self::raw_headers`].
    pub headers: HeaderMap,
    /// The authenticated principal. `None` for an anonymous request.
    pub principal: Option<Principal>,
    /// The region label a virtual-hosted host carried, when it carried one.
    pub host_region: Option<String>,
    /// Whether the request declared trailing headers (`x-amz-trailer`).
    pub declares_trailers: bool,
}

impl GatewayRequestContext {
    /// The `headers` member, built from the raw field lines a handler's request context yields
    /// (`RequestContextView::headers().iter_raw()`, ADR-0022): every accepted line in map order, an
    /// unrelated value that is not UTF-8 included, so the s3s handler sees the lines it sees today.
    #[must_use]
    pub fn raw_headers<'a>(lines: impl IntoIterator<Item = (&'a HeaderName, &'a HeaderValue)>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in lines {
            headers.append(name.clone(), value.clone());
        }
        headers
    }
}

/// Wraps `input` in the s3s request context `context` describes.
///
/// The region follows the s3s precedence: the verified signing region when there is one,
/// otherwise the region a virtual host named. An empty region, signed or hosted, is no region, as
/// legacy RustFS reads it: its replication client signs with an empty region, and the request then
/// carries the host's region or none.
///
/// # Errors
///
/// [`ConversionError`] naming the member when:
/// - `uri`: the raw path and query do not form an origin-form URI;
/// - `credentials`: the principal has an empty access key;
/// - `region`: the chosen region is empty or outside the s3s region grammar (`[a-z0-9-]+`);
/// - `service`: the verified service is empty;
/// - `trailing_headers`: the request declared trailers. The s3s trailer handle has no
///   public constructor, so the trailers a gateway body ends with cannot be delivered where an app
///   body looks for them.
pub fn request_to_s3s<T>(context: GatewayRequestContext, input: T) -> Result<S3Request<T>, ConversionError> {
    let GatewayRequestContext {
        method,
        raw_path,
        raw_query,
        headers,
        principal,
        host_region,
        declares_trailers,
    } = context;
    if declares_trailers {
        return Err(refusal(
            "trailing_headers",
            "the pinned s3s trailer handle has no public constructor, so declared trailers cannot be delivered",
        ));
    }
    let uri = origin_form(&raw_path, &raw_query)?;
    let (credentials, scope) = match principal {
        Some(principal) => {
            if principal.access_key.is_empty() {
                return Err(refusal("credentials", "an authenticated principal needs an access key"));
            }
            let credentials = Credentials {
                access_key: principal.access_key,
                secret_key: principal.secret_key,
            };
            (Some(credentials), principal.scope)
        }
        None => (None, None),
    };
    let service = match &scope {
        Some(scope) if scope.service.is_empty() => return Err(refusal("service", "a verified scope names a service")),
        Some(scope) => Some(scope.service.clone()),
        None => None,
    };
    let region = scope
        .map(|scope| scope.region)
        .filter(|signed| !signed.is_empty())
        .or_else(|| host_region.filter(|hosted| !hosted.is_empty()))
        .map(region)
        .transpose()?;
    Ok(S3Request {
        input,
        method,
        uri,
        headers,
        extensions: Extensions::new(),
        credentials,
        region,
        service,
        trailing_headers: None,
    })
}

fn origin_form(raw_path: &str, raw_query: &str) -> Result<Uri, ConversionError> {
    if !raw_path.starts_with('/') {
        return Err(refusal("uri", "an origin-form path starts with '/'"));
    }
    let target = if raw_query.is_empty() {
        raw_path.to_owned()
    } else {
        format!("{raw_path}?{raw_query}")
    };
    Uri::try_from(target).map_err(|_| refusal("uri", "the raw path and query do not form a URI"))
}

fn region(value: String) -> Result<Region, ConversionError> {
    Region::new(value.into_boxed_str()).map_err(|_| refusal("region", "an s3s region is non-empty [a-z0-9-]"))
}

const fn refusal(field: &'static str, reason: &'static str) -> ConversionError {
    ConversionError { field, reason }
}
