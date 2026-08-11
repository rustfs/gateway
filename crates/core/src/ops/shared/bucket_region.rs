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

//! Shares: bucket_region
//! Members: CreateBucket, DeleteBucket, HeadBucket
//!
//! Responsible for: the `x-amz-bucket-region` contract of the bucket lifecycle family — where the
//! header must appear ([`RegionHeaderDuty`]), and the two redirect refusals that carry it:
//! [`permanent_redirect`] (the 301 a path-style request for a bucket in another region receives)
//! and [`temporary_redirect`] (the 307 shape AWS answers during a new bucket's DNS propagation
//! window; the trigger is the caller's bucket-placement knowledge, not this module's).
//! NOT responsible for: the header on a *success* response — that is the generated encoder's,
//! driven by `HeadBucketOutput.bucket_region` being a required output field — or for deciding
//! which region a bucket is in, which only a backend knows.
//! Upstream: [`crate::fault`], `rustfs-gateway-types`' error codes. Downstream: the three member
//! operations, and every backend that answers one of them.
//!
//! # Why the 301 is built here and nowhere else
//!
//! The defect this module exists to prevent is a `301 PermanentRedirect` without
//! `x-amz-bucket-region`: SDKs complete the redirect by reading that header, so leaving it off
//! turns "your bucket is over there" into a client that simply fails. Building the refusal in one
//! place makes the header structurally inseparable from the status — a caller cannot spell the 301
//! through this module and forget the region, because the region is the argument.

use rustfs_gateway_types::BucketName;

use crate::error_resolution::HandlerErrorContext;
use crate::fault::{RedirectTarget, RegionLabel};
use crate::handler::HandlerError;

/// The message every permanent redirect this module builds carries. One spelling, wire format.
pub const PERMANENT_REDIRECT_MESSAGE: &str = "The bucket you are attempting to access must be addressed using the specified endpoint. \
     Please send all future requests to this endpoint.";

/// The message of the temporary form, for a bucket whose endpoint is still propagating.
pub const TEMPORARY_REDIRECT_MESSAGE: &str = "Please re-send this request to the specified temporary endpoint. \
     Continue to use the original request endpoint for future requests.";

/// Where `x-amz-bucket-region` must appear for one operation of the family.
///
/// Declared by each member as a `pub static`, so the answer to "does this operation's success
/// carry the header?" is a fact in the operation's own file rather than a branch in a renderer.
/// Every member's redirect carries it regardless — that half is not optional anywhere, which is
/// why it is not a variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionHeaderDuty {
    /// The success response carries the header too. `HeadBucket`, whose output makes the region a
    /// required field so a success without it cannot be constructed.
    SuccessAndRedirect,
    /// Only a redirect carries it. `CreateBucket` and `DeleteBucket`, whose successes say where
    /// the bucket is by other means (the `Location` header) or not at all (a 204).
    RedirectOnly,
}

/// The `301 PermanentRedirect` for a bucket that lives in another region.
///
/// The region argument is the *bucket's* region — the one the client should re-sign and re-send
/// for — and it lands in both places a client might look: the `x-amz-bucket-region` header, which
/// is the only one a `HEAD` response can carry, and the `<Region>` element of the error document.
#[must_use]
pub fn permanent_redirect(region: RegionLabel) -> HandlerError {
    HandlerErrorContext::permanent_redirect(region).into()
}

/// The same refusal, also naming the bucket in the document.
///
/// The bucket name is caller input, but by the time a handler answers it the caller is
/// authenticated and the name has passed the bucket-name validation, so echoing it back is an
/// answer to somebody entitled to it.
#[must_use]
pub fn permanent_redirect_for(bucket: BucketName, region: RegionLabel) -> HandlerError {
    HandlerErrorContext::permanent_redirect_for(bucket, region).into()
}

/// The `307 TemporaryRedirect` shape: a `Location` to retry against, and the region beside it.
///
/// This module fixes the shape only. The trigger — knowing that a just-created bucket's endpoint
/// has not propagated yet — is bucket-placement knowledge this crate does not hold, so nothing
/// here decides *when* to answer this; a backend that knows, can.
#[must_use]
pub fn temporary_redirect(target: RedirectTarget, region: RegionLabel) -> HandlerError {
    HandlerErrorContext::temporary_redirect(region, target).into()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rustfs_gateway_types::ErrorCode;

    use crate::fault::ErrorDetail;

    fn region(name: &str) -> RegionLabel {
        RegionLabel::new(name).expect("a valid region")
    }

    fn bucket(name: &str) -> BucketName {
        BucketName::new(name).expect("a valid bucket")
    }

    /// Positive — the 301 carries the region in its head and in its document, and answers 301.
    /// This is the golden for the redirect shape: header name, header value, element, status.
    #[test]
    fn the_permanent_redirect_carries_the_region_in_head_and_document() {
        let error = permanent_redirect(region("eu-west-1"));
        assert_eq!(*error.code(), ErrorCode::PERMANENT_REDIRECT);
        assert_eq!(error.code().default_status(), http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(error.headers().len(), 1);
        assert_eq!(error.headers()[0].name().as_str(), "x-amz-bucket-region");
        assert_eq!(error.headers()[0].value(), "eu-west-1");
        assert_eq!(error.details().len(), 1);
        assert_eq!(error.details()[0].element(), "Region");
        assert_eq!(error.details()[0].text(), "eu-west-1");
    }

    /// Positive — the bucket-naming form adds `<BucketName>` ahead of `<Region>`, in the declared
    /// element order rather than the call order.
    #[test]
    fn the_named_form_states_the_bucket_before_the_region() {
        let error = permanent_redirect_for(bucket("bucket-one"), region("eu-west-1"));
        let elements: Vec<&str> = error.details().iter().map(ErrorDetail::element).collect();
        assert_eq!(elements, ["BucketName", "Region"]);
    }

    /// Positive — the 307 shape: a `Location`, the region header beside it, status 307. Golden for
    /// the shape this family registers without implementing the trigger.
    #[test]
    fn the_temporary_redirect_carries_a_location_and_the_region() {
        let target = RedirectTarget::new("https://b.s3.eu-west-1.example.com").expect("a valid target");
        let error = temporary_redirect(target, region("eu-west-1"));
        assert_eq!(*error.code(), ErrorCode::TEMPORARY_REDIRECT);
        assert_eq!(error.code().default_status(), http::StatusCode::TEMPORARY_REDIRECT);
        let names: Vec<String> = error
            .headers()
            .iter()
            .map(|header| header.name().as_str().to_owned())
            .collect();
        assert!(names.iter().any(|name| name == "location"), "{names:?}");
        assert!(names.iter().any(|name| name == "x-amz-bucket-region"), "{names:?}");
    }

    /// Negative — a 301 cannot be spelled through this module without a region: the argument is
    /// the region, so "forgot the header" is not a reachable state. What *is* checkable is that
    /// no constructor produces a redirect whose header set lacks the region header.
    #[test]
    fn n_no_redirect_this_module_builds_lacks_the_region_header() {
        let redirects = [
            permanent_redirect(region("us-west-2")),
            permanent_redirect_for(bucket("bucket-one"), region("us-west-2")),
            temporary_redirect(RedirectTarget::new("https://example.com").expect("a valid target"), region("us-west-2")),
        ];
        for error in redirects {
            assert!(
                error
                    .headers()
                    .iter()
                    .any(|header| header.name().as_str() == "x-amz-bucket-region"),
                "{error}"
            );
        }
    }

    /// Negative — a hostile region never reaches a redirect, because the label refuses it at
    /// construction and this module has no constructor taking a raw string.
    #[test]
    fn n_a_hostile_region_cannot_reach_the_header() {
        assert!(RegionLabel::new("evil\r\nx-amz-id-2: forged").is_err());
    }

    /// Negative — each member's declared duty agrees with the shape of its generated output.
    ///
    /// This is what stops [`RegionHeaderDuty`] from being decoration. `HeadBucket` declares that
    /// its *success* carries the header, and the only thing that enforces it is
    /// `output_required = ["BucketRegion"]` in `model/overlays/ops/bucket.toml`, three files away:
    /// drop it and the member becomes an `Option` a handler may leave `None`, producing a `200`
    /// with no region for an SDK that sent the request precisely to learn one.
    ///
    /// The assertion is the struct literal below, and it is a **compile-time** one: `bucket_region`
    /// is given a bare `String`, which stops compiling the moment the member becomes optional. A
    /// run-time check cannot see that difference — `String::default()` is a legitimate wire value,
    /// so `check_required` passes either way, which is exactly the trap this comment exists to
    /// stop the next reader from walking into.
    #[test]
    fn n_the_declared_duty_agrees_with_the_generated_output_shape() {
        use rustfs_gateway_types::dto;

        assert_eq!(crate::ops::head_bucket::REGION_HEADER_DUTY, RegionHeaderDuty::SuccessAndRedirect);
        let success = dto::HeadBucketOutput {
            bucket_region: "eu-west-1".to_owned(),
        };
        assert_eq!(success.bucket_region, "eu-west-1");

        // The other two say the region rides only on a redirect, and their outputs carry no region
        // member at all — the other half of the same agreement, and equally a compile failure if a
        // region member is added to one of them without the duty moving with it.
        assert_eq!(crate::ops::create_bucket::REGION_HEADER_DUTY, RegionHeaderDuty::RedirectOnly);
        let created = dto::CreateBucketOutput {
            location: Some("/b".to_owned()),
        };
        assert_eq!(created.location.as_deref(), Some("/b"));
        assert_eq!(crate::ops::delete_bucket::REGION_HEADER_DUTY, RegionHeaderDuty::RedirectOnly);
        assert!(dto::DeleteBucketOutput::default().check_required().is_ok());
    }
}
