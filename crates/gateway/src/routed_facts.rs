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

//! What routing decided about a request beyond its operation (ADR-0024, ADR-0025): whether it is
//! service-level, the target every later stage addresses, a claimed row's bound bucket, whether its
//! handler may hold the caller's secret, a claimed row's typed path values, and the accounts the
//! request names.
//!
//! Responsible for: [`RoutedFacts::of`], one pure function over the dispatch, the raw target and
//! the deployment's name policy.
//! Also `CallerKeyOptIn::admits`, the per-request decision whether the secret the authenticator
//! handed over reaches this operation's handler.
//! NOT responsible for: routing (`rustfs-gateway-core`'s router), dropping the secret
//! (`crate::service`, on the line that reads the verdict), deciding whether a signature covers the
//! body (`crate::ext::Authentication::signs_its_body`), asking the authorizer, or rendering a
//! refusal.
//! Upstream: `rustfs_gateway_core::Dispatch`, `crate::dispatch::target_of`. Downstream:
//! `crate::service`.
//!
//! # Why a claimed or service-level request has no bucket
//!
//! Inside a claim the path is not S3 addressing, a form claim (ADR-0041) addresses no bucket
//! whatever the host names, and a `ResourceShape::Service` operation names no resource a path
//! could supply. Addressing each as `TargetKind::Service` is what keeps a path-style
//! `/rustfs/admin/…` from reaching the governor, both authorizer stages, the audit event and the
//! handler context as bucket `rustfs`. The raw path is untouched, so the signature
//! and the context still read it exactly as it arrived.
//!
//! # Why a bound bucket is read from the raw segment
//!
//! A claimed row may bind one template parameter as its bucket (`/quota/{bucket}`). The segment
//! then goes through `bucket_label`, the very function a path-style `/{bucket}` meets, *before*
//! it is decoded: the S3 rules admit no character that needs escaping, so an escaped spelling is
//! refused here exactly as it is there, and the governor, both authorizer stages and the handler
//! see one `BucketName`. A bucket named in the query (ADR-0026) is read the same way: the one
//! occurrence of its parameter, found by the strict reader subjects use, and its raw value through
//! `bucket_label`.

use rustfs_gateway_core::codec::bucket_label;
use rustfs_gateway_core::{BucketParam, CodecError, Dispatch, PathParams, ResourceShape, Subjects, TargetKind, single_raw_value};
use rustfs_gateway_types::{BucketName, NamePolicy};

use crate::dispatch::target_of;

/// What the pipeline reads from the routed row and the operation's own spec, once.
pub(crate) struct RoutedFacts {
    /// No bucket and no key reach any later stage.
    pub(crate) service_level: bool,
    /// A claimed row or a form claim answered: its path is not S3 addressing, so no bucket CORS
    /// applies, and the profile's claimed-route body ceiling does.
    pub(crate) claimed: bool,
    /// The target every later stage addresses: `Service` for a service-level request, `Bucket`
    /// for a claimed row that binds its bucket.
    pub(crate) target: TargetKind,
    /// The bucket a claimed row's template or query parameter names, validated as S3 validates one.
    pub(crate) bound_bucket: Option<BucketName>,
    /// The routed operation's opt-in to the caller's secret.
    pub(crate) secret: CallerKeyOptIn,
    /// The claimed row's decoded values; none outside a claim.
    pub(crate) path_params: PathParams,
    /// The accounts the request acts on, for an operation that declares a subject rule.
    pub(crate) subjects: Option<Subjects>,
}

impl RoutedFacts {
    /// The facts of one dispatched request.
    ///
    /// # Errors
    ///
    /// A `400 InvalidArgument` naming the path parameter, the bucket query parameter or the subject
    /// parameter whose value no handler may be handed, or a `400 InvalidBucketName` for a bound
    /// bucket that breaks the S3 naming rules. Every message is a constant and never carries the
    /// value.
    pub(crate) fn of(dispatched: &Dispatch<'_>, raw_path: &str, raw_query: &str, names: &NamePolicy) -> Result<Self, CodecError> {
        let path_params = match dispatched.claimed {
            Some(claimed) => claimed.template().extract(raw_path).map_err(|error| {
                let refusal = CodecError::invalid_argument(error.message());
                match error.name() {
                    Some(name) => refusal.about(name),
                    None => refusal,
                }
            })?,
            None => PathParams::none(),
        };
        let bound_bucket = match dispatched
            .claimed
            .and_then(|claimed| Some((claimed, claimed.bucket_param()?)))
        {
            Some((claimed, BucketParam::Path(param))) => {
                // The row matched, so the template has the parameter; a `None` here is refused
                // rather than read as "no bucket", which would make the request service-level.
                let raw = claimed
                    .template()
                    .raw_value(raw_path, param)
                    .ok_or_else(|| CodecError::invalid_argument("the bound bucket parameter matched nothing").about(param))?;
                Some(bucket_label(raw, names)?)
            }
            Some((_, BucketParam::Query(param))) => {
                // Exactly one occurrence, in any key spelling; absent or empty is refused rather
                // than read as "no bucket", which would make the request service-level.
                let raw = single_raw_value(raw_query, param)
                    .map_err(|error| CodecError::invalid_argument(error.message()).about(param))?
                    .filter(|raw| !raw.is_empty())
                    .ok_or_else(|| CodecError::invalid_argument("the request names no bucket").about(param))?;
                Some(bucket_label(raw, names)?)
            }
            None => None,
        };
        let subjects = match dispatched.spec.auth.and_then(|auth| auth.subject()) {
            Some(rule) => Some(rule.extract(raw_query).map_err(|error| {
                let refusal = CodecError::invalid_argument(error.message());
                match rule.refused_param(error) {
                    Some(param) => refusal.about(param),
                    None => refusal,
                }
            })?),
            None => None,
        };
        let claimed = dispatched.claimed.is_some() || dispatched.form.is_some();
        let service_level = bound_bucket.is_none()
            && (claimed
                || dispatched
                    .spec
                    .auth
                    .is_some_and(|auth| auth.resource == ResourceShape::Service));
        let target = if service_level {
            TargetKind::Service
        } else if bound_bucket.is_some() {
            TargetKind::Bucket
        } else {
            target_of(dispatched.entry)
        };
        Ok(Self {
            service_level,
            claimed,
            target,
            bound_bucket,
            secret: CallerKeyOptIn {
                opted_in: dispatched.spec.receives_caller_secret(),
                over_a_signed_body: dispatched.spec.caller_secret_needs_a_signed_body(),
            },
            path_params,
            subjects,
        })
    }
}

/// An operation's opt-in to the caller's secret (ADR-0024), as its spec declared it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CallerKeyOptIn {
    /// The spec opted in.
    pub(crate) opted_in: bool,
    /// Only for a request whose signature covers its body (rustfs/gateway#1587).
    pub(crate) over_a_signed_body: bool,
}

impl CallerKeyOptIn {
    /// Whether a secret the authenticator handed over reaches this request's handler: the operation
    /// opted in, or the assembly hands it to every operation; and, for an operation that asked for
    /// a signed body, `signed_body` holds. Anything else drops it, zeroized, at the line that reads
    /// the verdict, so no later stage holds the key.
    pub(crate) const fn admits(self, signed_body: bool, every_operation: bool) -> bool {
        (self.opted_in || every_operation) && (signed_body || !self.over_a_signed_body)
    }
}

#[cfg(test)]
mod caller_key_opt_in_tests {
    use super::CallerKeyOptIn;

    const PLAIN: CallerKeyOptIn = CallerKeyOptIn {
        opted_in: true,
        over_a_signed_body: false,
    };
    const SIGNED_BODY: CallerKeyOptIn = CallerKeyOptIn {
        opted_in: true,
        over_a_signed_body: true,
    };
    const NONE: CallerKeyOptIn = CallerKeyOptIn {
        opted_in: false,
        over_a_signed_body: false,
    };

    /// Positive — an opt-in over a signed body admits a signed body; a plain opt-in admits either.
    #[test]
    fn an_opt_in_admits_the_bodies_it_asked_for() {
        assert!(SIGNED_BODY.admits(true, false));
        assert!(PLAIN.admits(true, false));
        assert!(PLAIN.admits(false, false));
    }

    /// Negative — an opt-in over a signed body refuses an unsigned one, even when the assembly
    /// hands the secret to every operation; an operation that did not opt in gets nothing unless
    /// the assembly says every operation.
    #[test]
    fn n_an_unsigned_body_or_no_opt_in_gets_no_secret() {
        assert!(!SIGNED_BODY.admits(false, false));
        assert!(!SIGNED_BODY.admits(false, true));
        assert!(!NONE.admits(true, false));
        assert!(!NONE.admits(false, false));
        assert!(NONE.admits(false, true), "the every-operation scope is the deployment's listed choice");
    }
}
