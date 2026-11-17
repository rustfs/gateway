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

//! Key conditions carried with an authenticated browser form.
//!
//! Responsible for: exposing only constraints attached to a matching authenticated form.
//! NOT responsible for: authenticating the form, completing its body, or authorizing a write.
//! Upstream: the gateway's resolved form. Downstream: a trusted host's POST handler.

use std::sync::Arc;

use rustfs_gateway_sig::post_policy::PostKeyConstraints;
use rustfs_gateway_sig::{SigFamily, SigLocation};

use super::RequestContextView;

impl RequestContextView {
    /// Installs the key conditions from the same authenticated and resolved form.
    ///
    /// The facade supplies this only after signature verification. This method
    /// rejects anonymous, non-form and differently addressed contexts; it is
    /// not a substitute for verifying the supplied policy's provenance.
    #[doc(hidden)]
    #[must_use]
    pub fn with_post_object_key_constraints(mut self, constraints: Option<PostKeyConstraints>) -> Self {
        self.post_object_key_constraints = None;
        let signed_form = self.principal().is_some_and(|principal| {
            let scheme = principal.scheme();
            matches!(scheme.family(), SigFamily::V4 | SigFamily::V2) && scheme.location() == SigLocation::FormField
        });
        if self.operation == "PostObject"
            && signed_form
            && let (Some(key), Some(constraints)) = (self.addressed.key.as_ref(), constraints)
            && constraints.permits(key.as_str())
        {
            self.post_object_key_constraints = Some(Arc::new(constraints));
        }
        self
    }

    /// The signed form's parsed key conditions, if the facade attached them.
    ///
    /// This is not a body-completion or write-authorization proof. A host must
    /// validate the complete form and authorize every derived write separately.
    #[must_use]
    pub fn post_object_key_constraints(&self) -> Option<&PostKeyConstraints> {
        self.post_object_key_constraints.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfs_gateway_sig::{Identity, PostPolicyError, PostPolicyLimits, RequestNow, SigService, SigV2PostPolicy};

    fn fixture_constraints() -> Result<PostKeyConstraints, PostPolicyError> {
        let encoded = rustfs_gateway_sig::codec::encode_base64_exact(
            br#"{"expiration":"2030-01-02T12:34:56Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"}]}"#,
        );
        let fields = [
            ("awsaccesskeyid", "fixture"),
            ("signature", "fixture"),
            ("key", "upload"),
            ("bucket", "example-bucket"),
            ("policy", encoded.as_str()),
        ];
        let policy =
            SigV2PostPolicy::parse_as_legacy_rustfs(&fields, "", PostPolicyLimits::default(), RequestNow::from_unix_seconds(0))?;
        Ok(policy.key_constraints().clone())
    }

    #[test]
    fn detached_post_cannot_acquire_signed_key_constraints() -> Result<(), Box<dyn std::error::Error>> {
        let mut context = RequestContextView::detached("PostObject");
        context.addressed.key = Some(rustfs_gateway_types::ObjectKey::new("upload")?);
        let context = context.with_post_object_key_constraints(Some(fixture_constraints()?));
        assert!(context.post_object_key_constraints().is_none());
        Ok(())
    }

    #[test]
    fn unrelated_operation_scheme_or_key_cannot_acquire_form_constraints() -> Result<(), Box<dyn std::error::Error>> {
        for (operation, location, key) in [
            ("PostObject", SigLocation::FormField, "other"),
            ("PutObject", SigLocation::FormField, "upload"),
            ("PostObject", SigLocation::Header, "upload"),
        ] {
            let mut context = RequestContextView::detached(operation);
            context.addressed.key = Some(rustfs_gateway_types::ObjectKey::new(key)?);
            context.principal = Some(super::super::RequestPrincipal {
                identity: Identity::new("fixture")?,
                scheme: super::super::AuthenticatedScheme {
                    family: SigFamily::V2,
                    location,
                    service: SigService::S3,
                    temporary: false,
                },
                scope: None,
                secret: None,
                verified_form_session_token: None,
            });
            let context = context.with_post_object_key_constraints(Some(fixture_constraints()?));
            assert!(
                context.post_object_key_constraints().is_none(),
                "{operation} {location:?} {key} must not receive constraints"
            );
        }
        Ok(())
    }
}
