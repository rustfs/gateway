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

//! The body-dependent refusal of an unrouted RustFS object-path form (rustfs/gateway#1184).
//!
//! Responsible for: bounded metadata, form authentication (a SigV4 or a SigV2 policy signature),
//! and the final method refusal.
//! Not responsible for: upload-policy enforcement, authorization, file reads, or dispatch.
//! Upstream: the service's route error. Downstream: the error renderer; no operation can run here.

use http::{HeaderMap, Method, Response, header::CONTENT_TYPE};
use rustfs_gateway_core::{
    ErrorContext, HandlerError, LegacyRustfsFacts, LegacyRustfsRefusal, MetaView, Operation, ResponseKind, Router,
    error::PreAuthError, resolve,
};
use rustfs_gateway_core::{
    dispatch::NO_ROUTE_MESSAGE,
    route::{Selection, TargetKind},
};
use rustfs_gateway_http::{FormReject, WireRequest};
use rustfs_gateway_sig::{
    Admission, PayloadMode, RawQuery, RequestNow, SecurityFloor, UnroutedPostPolicy, UnroutedPostPolicyError, WireView,
    detect_credentials,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::ErrorCode;

use super::{Outcome, S3Service};
use crate::close::ConnectionIntent;
use crate::config::ConfigSnapshot;
use crate::ext::{Authentication, ClassKind, ClientAddr, GovernorRequest, ResolvedHost, SigV2Authentication};
use crate::logging::Refused;
use crate::post_object::PostObjectPrelude;
use crate::render::{S3Error, from_auth, from_handler};

pub(crate) fn applies_to<B>(router: &Router, wire: &WireRequest<B>, target: TargetKind, error: &PreAuthError) -> bool {
    router.selection() == Selection::RustfsLegacy
        && target == TargetKind::Object
        && *wire.method() == Method::POST
        && error.message() == NO_ROUTE_MESSAGE
        && wire.headers().get_str(&CONTENT_TYPE).is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("multipart/form-data"))
        })
}

pub(super) async fn refuse<B>(
    service: &S3Service,
    wire: WireRequest<B>,
    resolved: &ResolvedHost,
    snapshot: &ConfigSnapshot,
    outcome: &mut Outcome<'_>,
    now: RequestNow,
    client_addr: Option<ClientAddr>,
) -> Response<Body>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut body = None;
    let wire = wire.map_body(|pending| body = Some(pending));
    // Metadata is only a governor hint here. A name failure must not become a new refusal ahead
    // of the form's existing metadata/signature order, and no operation is being dispatched.
    let meta = MetaView::addressed_with(&wire, resolved.target, resolved.bucket().cloned(), &service.inner.names).ok();
    let _lease = match service
        .inner
        .governor
        .try_acquire(&GovernorRequest::new(
            "UnroutedPostForm",
            meta.as_ref().and_then(MetaView::bucket),
            wire.framing().declared_length(),
            client_addr,
            ClassKind::CredentialLookup,
        ))
        .await
    {
        Ok(lease) => lease,
        Err(()) => return outcome.refuse_for_load(),
    };
    let content_type = wire.headers().get_str(&CONTENT_TYPE).unwrap_or_default();
    let mut headers = HeaderMap::new();
    if let Some(length) = wire.framing().declared_length() {
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(length));
    }
    let read = service.inner.view_policy.post_forms.read(&headers);
    let prelude = match PostObjectPrelude::read_form(
        body,
        content_type,
        read.limits,
        read.grammar,
        snapshot.request_body_deadlines(),
        form_refusal,
    )
    .await
    {
        Ok(prelude) => prelude,
        Err(error) => return outcome.refuse_at(Refused::Decode, error),
    };
    let policy_limits = prelude.policy_limits();
    let fields = prelude.form_fields();
    let policy = match UnroutedPostPolicy::read(&fields, policy_limits) {
        Ok(policy) => policy,
        Err(error) => return outcome.refuse_at(Refused::Authentication, metadata_refusal(error)),
    };
    let empty_headers = HeaderMap::new();
    let view = WireView::new(&empty_headers, RawQuery::new("")).with_form_fields(&fields);
    if policy.is_none() && view.form_contains("signature") {
        // A SigV2 form. Legacy RustFS verifies its policy signature, then refuses the method
        // (`v2_check_post_signature` before `S3Path::Object`; rustfs/gateway#1184, #1185). Only a
        // scheme the floor admits is verified, and a verified form still reaches no operation.
        let presence = detect_credentials(&view);
        let sealed = match service.inner.floor.admit(view, crate::dto::PostObject::floor(), now) {
            Ok(Admission::SealedSigV2(sealed)) => sealed,
            Err(error) => return outcome.refuse_at(Refused::Authentication, from_auth(error, ResponseKind::Other, true)),
            Ok(_) => return outcome.refuse_handler(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, NO_ROUTE_MESSAGE)),
        };
        // The form's own policy ceilings, as the routed path and the SigV4 branch below pass them.
        let question = SigV2Authentication::new(&sealed, wire.method(), wire.raw_path().as_str(), None)
            .with_post_policy_limits(Some(policy_limits));
        let Ok(authentication) = service.inner.authenticator.authenticate_sigv2(&question).await else {
            return outcome.refuse_handler_at(
                Refused::Authentication,
                HandlerError::internal_error("the form could not be authenticated"),
            );
        };
        let (verdict, _, _) = authentication.into_parts();
        if let Some(error) = SecurityFloor::seal_verdict(verdict, presence).rejection() {
            return outcome.refuse_at(Refused::Authentication, from_auth(error, ResponseKind::Other, true));
        }
        return method_refusal(outcome);
    }
    if let Some(policy) = policy {
        // Legacy-compat (rustfs/backlog#2684): a multipart form ignores header/query signatures,
        // verifies its policy before the method check, and enforces upload conditions only after
        // that check. The refusal has no route to authorization or a file reader.
        let presence = detect_credentials(&view);
        let sealed = match service.inner.floor.admit(view, crate::dto::PostObject::floor(), now) {
            Ok(Admission::Sealed(sealed)) => sealed,
            Err(error) => return outcome.refuse_at(Refused::Authentication, from_auth(error, ResponseKind::Other, true)),
            _ => {
                return outcome.refuse_handler_at(
                    Refused::Authentication,
                    HandlerError::new(ErrorCode::ACCESS_DENIED, "the form was not authenticated"),
                );
            }
        };
        let payload = PayloadMode::Unsigned;
        let question = Authentication::new(
            &sealed,
            wire.method(),
            wire.raw_path().as_str(),
            wire.host().raw_for_signing(),
            &payload,
            wire.framing().declared_length(),
        )
        .with_post_policy_limits(Some(policy_limits))
        .with_unrouted_post_policy(&policy);
        let authentication = service.inner.authenticator.authenticate(&question).await;
        let (_, legacy, _) = question.into_published();
        let authentication = match authentication {
            Ok(authentication) => authentication,
            Err(_) => {
                return outcome.refuse_handler_at(
                    Refused::Authentication,
                    HandlerError::internal_error("the form could not be authenticated"),
                );
            }
        };
        let (verdict, _, _) = authentication.into_parts();
        let verdict = SecurityFloor::seal_verdict(verdict, presence);
        if let Some(error) = verdict.rejection() {
            let refusal = match legacy {
                Some(legacy) => legacy.render(&error, ResponseKind::Other, true),
                None => from_auth(error, ResponseKind::Other, true),
            };
            return outcome.refuse_at(Refused::Authentication, refusal);
        }
    }
    method_refusal(outcome)
}

/// Legacy RustFS's answer to a form it has authenticated, or admitted unsigned, on an object path.
fn method_refusal(outcome: &mut Outcome<'_>) -> Response<Body> {
    let refusal = LegacyRustfsRefusal::new(
        ErrorCode::METHOD_NOT_ALLOWED,
        Some("The specified method is not allowed against this resource.".to_owned()),
        LegacyRustfsFacts::default(),
    );
    match refusal {
        Ok(refusal) => outcome.refuse_at(
            Refused::Wire,
            S3Error::from(resolve(ErrorContext::legacy_rustfs(refusal), ResponseKind::Other)),
        ),
        Err(_) => outcome.refuse_handler(HandlerError::internal_error("the method refusal could not be resolved")),
    }
}

fn form_refusal(error: FormReject) -> S3Error {
    let (code, message) = match error {
        FormReject::MalformedContentType => (ErrorCode::INVALID_REQUEST, "the multipart boundary is invalid"),
        _ => (ErrorCode::MALFORMED_POST_REQUEST, "the POST form was not accepted"),
    };
    from_handler(HandlerError::new(code, message), ResponseKind::Other, ConnectionIntent::MayKeepAlive)
}

fn metadata_refusal(error: UnroutedPostPolicyError) -> S3Error {
    use UnroutedPostPolicyError as Error;
    let (code, message) = match error {
        Error::MissingAlgorithm => (ErrorCode::INVALID_REQUEST, "invalid multipart fields: missing field: x-amz-algorithm"),
        Error::MissingCredential => (ErrorCode::INVALID_REQUEST, "invalid multipart fields: missing field: x-amz-credential"),
        Error::MissingDate => (ErrorCode::INVALID_REQUEST, "invalid multipart fields: missing field: x-amz-date"),
        Error::MissingPolicy => (ErrorCode::INVALID_REQUEST, "invalid multipart fields: missing field: policy"),
        Error::UnsupportedAlgorithm => (
            ErrorCode::NOT_IMPLEMENTED,
            "x-amz-algorithm other than AWS4-HMAC-SHA256 is not implemented",
        ),
        Error::InvalidCredential => (ErrorCode::INVALID_REQUEST, "invalid field: x-amz-credential"),
        Error::InvalidDate => (ErrorCode::INVALID_REQUEST, "invalid field: x-amz-date"),
        Error::InvalidEncoding => (ErrorCode::INVALID_REQUEST, "invalid field: policy"),
        Error::DateNotBound => (ErrorCode::INVALID_POLICY_DOCUMENT, "x-amz-date does not match policy"),
        Error::CredentialNotBound => (ErrorCode::INVALID_POLICY_DOCUMENT, "x-amz-credential does not match policy"),
        Error::AlgorithmNotBound => (ErrorCode::INVALID_POLICY_DOCUMENT, "x-amz-algorithm does not match policy"),
        _ => (ErrorCode::INVALID_POLICY_DOCUMENT, "the POST policy document was not accepted"),
    };
    from_handler(HandlerError::new(code, message), ResponseKind::Other, ConnectionIntent::MayKeepAlive)
}
