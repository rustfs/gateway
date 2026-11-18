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

//! The POST Object bridge's refusals: how a form, a policy or a file the bridge refuses is answered.
//!
//! Responsible for: the code and sentence of each refusal `super` raises, the RustFS profile's
//! included. NOT responsible for: deciding to refuse (`super`, `rustfs-gateway-sig`'s policy
//! reader) or rendering the error document (`crate::render`).
//! Upstream: `super` and its submodules. Downstream: `crate::render::from_handler`.

use rustfs_gateway_http::FormReject;
use rustfs_gateway_sig::PostPolicyError;

use crate::close::ConnectionIntent;
use crate::render::{S3Error, from_handler};
use crate::{ErrorCode, HandlerError, ResponseKind};

/// Legacy RustFS's sentence for an empty form file: the legacy stack's text for
/// `UnexpectedContent`.
const LEGACY_EMPTY_FILE: &str = "This request does not support content.";

/// Legacy RustFS's answer to an empty form file: `400 UnexpectedContent`.
pub(super) fn legacy_empty_file_refusal() -> S3Error {
    from_handler(
        HandlerError::new(ErrorCode::UNEXPECTED_CONTENT, LEGACY_EMPTY_FILE),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

/// AWS's answer to a form its POST policy does not admit, under the RustFS profile: `403
/// AccessDenied` "Invalid according to Policy", for a field failing its condition (a named field
/// the form lacks and a policy for another bucket included) and for a field no condition names.
/// `None` for every other refusal.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS answers a failed condition `400
/// InvalidPolicyDocument`; the decision on rustfs/gateway#1444 follows AWS instead. The messages
/// are fixed and never echo the condition or the value.
pub(super) fn aws_policy_violation(error: PostPolicyError) -> Option<S3Error> {
    let message = match error {
        PostPolicyError::ConditionFailed => "Invalid according to Policy: Policy Condition failed",
        PostPolicyError::FieldNotInPolicy => "Invalid according to Policy: Extra input fields",
        _ => return None,
    };
    Some(from_handler(
        HandlerError::new(ErrorCode::ACCESS_DENIED, message),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    ))
}

/// The RustFS profile's answer to a file its POST policy refuses: a policy violation as AWS answers
/// it (`aws_policy_violation`), the size range's own code, `AccessDenied` otherwise.
pub(super) fn legacy_file_policy_refusal(error: PostPolicyError) -> S3Error {
    if let Some(refusal) = aws_policy_violation(error) {
        return refusal;
    }
    let code = match error {
        PostPolicyError::EntityTooSmall => ErrorCode::ENTITY_TOO_SMALL,
        PostPolicyError::EntityTooLarge => ErrorCode::ENTITY_TOO_LARGE,
        _ => ErrorCode::ACCESS_DENIED,
    };
    from_handler(
        HandlerError::new(code, "the POST file did not satisfy its policy"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

pub(super) fn form_refusal(reject: FormReject) -> S3Error {
    let code = match reject {
        FormReject::FileTooLarge | FormReject::WholeStreamTooLarge => ErrorCode::ENTITY_TOO_LARGE,
        FormReject::IncompleteStream => ErrorCode::INCOMPLETE_BODY,
        _ => ErrorCode::MALFORMED_POST_REQUEST,
    };
    from_handler(
        HandlerError::new(code, "the POST form was not accepted"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

pub(super) fn policy_refusal(reject: PostPolicyError) -> S3Error {
    let code = match reject {
        PostPolicyError::EntityTooLarge => ErrorCode::ENTITY_TOO_LARGE,
        PostPolicyError::EntityTooSmall => ErrorCode::ENTITY_TOO_SMALL,
        PostPolicyError::Malformed => ErrorCode::MALFORMED_POST_REQUEST,
        PostPolicyError::Expired | PostPolicyError::ConditionFailed | PostPolicyError::SignatureMismatch => {
            ErrorCode::ACCESS_DENIED
        }
        _ => ErrorCode::ACCESS_DENIED,
    };
    from_handler(
        HandlerError::new(code, "the POST policy was not accepted"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}
