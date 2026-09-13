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
//! pinned `s3s::S3Request<T>` (`method`, `uri`, `headers`, `extensions`, `credentials`, `region`,
//! `service`, `trailing_headers`), around an input converted elsewhere. A fact the s3s request
//! cannot hold is a [`ConversionError`] naming the member, never a default.
//! NOT responsible for: gathering those facts (the gateway's wire layer publishes no way back to a
//! header map or URI, so the caller assembles them from the typed views), the input members
//! ([`super::put_object`]), any RustFS extension type, or any production call site. Nothing
//! outside the goldens context diff calls it (rustfs/backlog#1762, rustfs/backlog#1752).
//! Upstream: the pinned s3s request type. Downstream: the goldens context diff; later the RustFS
//! ring-2 adapter, which must add the RustFS extensions itself.
//!
//! # Extensions
//!
//! The produced request carries **no** extensions. Everything a RustFS app body reads from
//! `S3Request::extensions` is a RustFS type (`ReqInfo`, `RequestContext`, the server context slot,
//! `Option<RemoteAddr>`, the POST Object marker) installed by RustFS's own HTTP layer or access
//! hook, and this ring-0 crate may not name one. The ring-2 adapter owns installing them; an app
//! body that finds one missing already fails closed (`ReqInfo not found in request extensions`).

use http::{Extensions, HeaderMap, Method, Uri};

use super::s3s;
use s3s::S3Request;
use s3s::auth::{Credentials, SecretKey};
use s3s::region::Region;

use super::put_object::ConversionError;

/// Every context member of the pinned `s3s::S3Request`, in declaration order.
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

/// What the gateway knows about one request, beyond its decoded input.
#[derive(Debug)]
pub struct GatewayRequestContext {
    /// The request method.
    pub method: Method,
    /// The request path exactly as it arrived, still percent-encoded.
    pub raw_path: String,
    /// The query string exactly as it arrived, without its `?`. Empty when there is none.
    pub raw_query: String,
    /// The request headers the gateway can read back, in arrival order per name.
    pub headers: HeaderMap,
    /// The authenticated principal. `None` for an anonymous request.
    pub principal: Option<Principal>,
    /// The region label a virtual-hosted host carried, when it carried one.
    pub host_region: Option<String>,
    /// Whether the request declared trailing headers (`x-amz-trailer`).
    pub declares_trailers: bool,
}

/// Wraps `input` in the s3s request context `context` describes.
///
/// The region follows the pinned s3s precedence: the verified signing region when there is one,
/// otherwise the region a virtual host named.
///
/// # Errors
///
/// [`ConversionError`] naming the member when:
/// - `uri`: the raw path and query do not form an origin-form URI;
/// - `credentials`: the principal has an empty access key;
/// - `region`: the chosen region is empty or outside the s3s region grammar (`[a-z0-9-]+`);
/// - `service`: the verified service is empty;
/// - `trailing_headers`: the request declared trailers. The pinned s3s trailer handle has no
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
    let region = scope.map(|scope| scope.region).or(host_region).map(region).transpose()?;
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
