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

//! Service-scope isolation helpers keeping S3-only middleware off non-S3 services.
//!
//! Responsible for: deciding whether an assembled router serves a non-S3 signing service,
//! bypassing S3 virtual-host bucket extraction on non-S3 services, and bypassing S3 checksum
//! arbitration on non-S3 services.
//! NOT responsible for: S3 virtual-host matching (`crate::ext::vhost`), checksum parsing
//! (`crate::integrity`), or routing table lookup (`rustfs-gateway-core`).
//! Upstream: `rustfs_gateway_sig::SigService`, `crate::ext`, `crate::integrity`.
//! Downstream: `crate::service`, `crate::classify`, `crate::legacy_addressing`.

use http::Method;
use rustfs_gateway_core::{HandlerError, MetaView};
use rustfs_gateway_http::{BodyIntegrity, HeaderView, WireRequest};
use rustfs_gateway_sig::SigService;

use super::extension_guards::resolve_host_safely;
use crate::ext::{HostResolver, ResolvedHost, target_of_path};
use crate::integrity::{Integrity, resolve_in};
use crate::render::S3Error;
use crate::trace::RequestTrace;

/// Whether `service` is an independently assembled non-S3 signing service (such as
/// [`SigService::S3Vectors`] or [`SigService::Sts`]).
///
/// Ordinary S3 assemblies (`None`) and explicit [`SigService::S3`] assemblies return `false`.
pub(crate) const fn is_non_s3_service(service: Option<SigService>) -> bool {
    matches!(service, Some(service) if !matches!(service, SigService::S3))
}

/// Resolves host addressing for `wire`, skipping S3 virtual-host bucket extraction and S3
/// `VhostHint` diagnostics on non-S3 services, and containing panics on S3 services.
pub(crate) fn resolve_host_for_service<B>(
    resolver: &dyn HostResolver,
    wire: &WireRequest<B>,
    signing_service: Option<SigService>,
    trace: Option<&RequestTrace>,
) -> Result<(ResolvedHost, Option<String>), HandlerError> {
    if is_non_s3_service(signing_service) {
        return Ok((ResolvedHost::standard(target_of_path(wire.raw_path().as_str())), None));
    }
    resolve_host_safely(resolver, wire, trace)
}

/// Resolves request-body checksum obligations, bypassing S3 checksum/Content-MD5 arbitration on
/// non-S3 services.
pub(crate) fn resolve_integrity_for_service(
    signing_service: Option<SigService>,
    meta: &MetaView<'_>,
    headers: &HeaderView<'_>,
    method: &Method,
    operation: &str,
) -> Result<Integrity, S3Error> {
    if is_non_s3_service(signing_service) {
        return Ok(Integrity::from(BodyIntegrity::NONE));
    }
    resolve_in(meta, headers, method, operation)
}
