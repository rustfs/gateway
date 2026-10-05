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

//! POST Object success controls and response serialization.
//!
//! Responsible for: selecting a success action and rendering its storage result in the selected
//! form profile. NOT responsible for: reading file bytes, authentication or authorization.
//! Upstream: the POST prelude and authorized handoff. Downstream: service response assembly.

use http::{HeaderValue, StatusCode, Uri, header};
use rustfs_gateway_core::{EncodedResponse, ResponseBody, TransportSecurity};
use rustfs_gateway_sig::{PostPolicyError, build_success_action_redirect};
use rustfs_gateway_types::{BucketName, ObjectKey};
use rustfs_gateway_xml::{S3_XMLNS, XmlWriter};

use super::{legacy, policy_refusal};
use crate::ext::TargetOrigin;
use crate::render::S3Error;
use crate::{ErrorCode, HandlerError};

#[derive(Clone)]
enum SuccessAction {
    Ok,
    Created,
    NoContent,
    Malformed,
    EmptyRedirect,
    Redirect(String),
}

#[derive(Clone)]
pub(crate) struct PostObjectResponsePlan {
    action: SuccessAction,
    bucket: String,
    key: String,
    legacy: bool,
}

impl PostObjectResponsePlan {
    pub(super) fn parse(fields: &[(&str, &str)], bucket: &BucketName, key: &ObjectKey, legacy: bool) -> Result<Self, S3Error> {
        let status = unique_success_field(fields, "success_action_status")?;
        let normalized = status.filter(|_| legacy).map(legacy::success_status).transpose()?;
        let status = normalized.as_deref().or(status);
        let redirect = unique_success_field(fields, "success_action_redirect")?;
        let action = if legacy {
            let status_action = match status {
                Some("200") => SuccessAction::Ok,
                Some("201") => SuccessAction::Created,
                Some("204") | None => SuccessAction::NoContent,
                Some(_) => SuccessAction::Malformed,
            };
            match (status_action, redirect) {
                (SuccessAction::Malformed, _) => SuccessAction::Malformed,
                (_, Some("")) => SuccessAction::EmptyRedirect,
                (_, Some(raw)) => validated_redirect(raw, bucket.as_str(), key.as_str())
                    .map(SuccessAction::Redirect)
                    .unwrap_or(SuccessAction::Malformed),
                (action, None) => action,
            }
        } else {
            match (status, redirect) {
                (Some(_), Some(_)) => return Err(policy_refusal(PostPolicyError::Malformed)),
                (Some("200"), None) => SuccessAction::Ok,
                (Some("201"), None) => SuccessAction::Created,
                (Some("204"), None) | (None, None) => SuccessAction::NoContent,
                (Some(_), None) => return Err(policy_refusal(PostPolicyError::Malformed)),
                (None, Some(raw)) => SuccessAction::Redirect(validated_redirect(raw, bucket.as_str(), key.as_str())?),
            }
        };
        Ok(Self {
            action,
            bucket: bucket.as_str().to_owned(),
            key: key.as_str().to_owned(),
            legacy,
        })
    }

    pub(super) fn before_storage(&self) -> Result<(), PostPolicyError> {
        if matches!(self.action, SuccessAction::Malformed) {
            return Err(PostPolicyError::Malformed);
        }
        Ok(())
    }

    pub(crate) fn apply(
        self,
        encoded: &mut EncodedResponse,
        security: TransportSecurity,
        host: &str,
        origin: TargetOrigin,
    ) -> Result<(), HandlerError> {
        match self.action {
            SuccessAction::Ok => {
                encoded.status = StatusCode::OK;
                encoded.body = ResponseBody::Empty;
            }
            SuccessAction::Created => {
                let e_tag = encoded_etag(encoded, self.legacy)?;
                let location = if self.legacy {
                    format!("/{}/{}", self.bucket, self.key)
                } else {
                    object_location(security, host, origin, &self.bucket, &self.key)
                };
                let mut writer = XmlWriter::document();
                writer.legacy_layout(self.legacy);
                writer.open("PostResponse", (!self.legacy).then_some(S3_XMLNS));
                writer.element("Location", &location);
                writer.element("Bucket", &self.bucket);
                writer.element("Key", &self.key);
                writer.element("ETag", e_tag);
                encoded.status = StatusCode::CREATED;
                encoded.set_header("content-type", "application/xml");
                encoded.body = ResponseBody::Complete(writer.finish().into_bytes());
            }
            SuccessAction::NoContent => {
                encoded.status = StatusCode::NO_CONTENT;
                encoded.body = ResponseBody::Empty;
            }
            SuccessAction::Malformed => {
                return Err(HandlerError::new(
                    ErrorCode::MALFORMED_POST_REQUEST,
                    "the POST success controls were not accepted",
                ));
            }
            SuccessAction::EmptyRedirect => {
                // Legacy RustFS reports an empty redirect only after a successful storage call.
                return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "Invalid redirect URL"));
            }
            SuccessAction::Redirect(raw) => {
                let e_tag = encoded_etag(encoded, self.legacy)?;
                let location = if self.legacy {
                    legacy_redirect(&raw, &self.bucket, &self.key, e_tag)
                } else {
                    build_success_action_redirect(&raw, &self.bucket, &self.key, e_tag, None)
                        .map_err(|_| HandlerError::internal_error("the accepted POST redirect could not be rendered"))?
                };
                let location = HeaderValue::from_str(&location)
                    .map_err(|_| HandlerError::internal_error("the accepted POST redirect could not become a header"))?;
                encoded.status = StatusCode::SEE_OTHER;
                encoded.headers.insert(header::LOCATION, location);
                encoded.body = ResponseBody::Empty;
            }
        }
        Ok(())
    }
}

// The redirect was validated before storage. Append only the form-encoded parameters; leave the
// original path/query spelling and fragment alone, including an existing trailing ampersand.
fn legacy_redirect(raw: &str, bucket: &str, key: &str, etag: &str) -> String {
    let (base, fragment) = raw
        .split_once('#')
        .map_or((raw, None), |(base, fragment)| (base, Some(fragment)));
    let mut location = base.to_owned();
    let query_start = if let Some(separator) = location.find('?') {
        separator + 1
    } else {
        location.push('?');
        location.len()
    };
    let mut query = form_urlencoded::Serializer::for_suffix(location, query_start);
    query
        .append_pair("bucket", bucket)
        .append_pair("key", key)
        .append_pair("etag", etag);
    let mut location = query.finish();
    if let Some(fragment) = fragment {
        location.push('#');
        location.push_str(fragment);
    }
    location
}

fn unique_success_field<'a>(fields: &'a [(&str, &str)], wanted: &str) -> Result<Option<&'a str>, S3Error> {
    let mut found = None;
    for (name, value) in fields {
        if *name == wanted && found.replace(*value).is_some() {
            return Err(policy_refusal(PostPolicyError::Malformed));
        }
    }
    Ok(found)
}

fn validated_redirect(raw: &str, bucket: &str, key: &str) -> Result<String, S3Error> {
    let rendered = build_success_action_redirect(raw, bucket, key, "", None).map_err(policy_refusal)?;
    let without_fragment = rendered.split_once('#').map_or(rendered.as_str(), |(base, _)| base);
    let uri = without_fragment
        .parse::<Uri>()
        .map_err(|_| policy_refusal(PostPolicyError::Malformed))?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(policy_refusal(PostPolicyError::Malformed));
    }
    HeaderValue::from_str(&rendered).map_err(|_| policy_refusal(PostPolicyError::Malformed))?;
    Ok(raw.to_owned())
}

fn encoded_etag(encoded: &EncodedResponse, legacy: bool) -> Result<&str, HandlerError> {
    let tag = encoded
        .headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HandlerError::internal_error("a POST success response did not contain an entity tag"))?;
    Ok(if legacy {
        tag.strip_prefix('"').and_then(|tag| tag.strip_suffix('"')).unwrap_or(tag)
    } else {
        tag
    })
}

fn object_location(security: TransportSecurity, host: &str, origin: TargetOrigin, bucket: &str, key: &str) -> String {
    let scheme = match security {
        TransportSecurity::Plaintext => "http",
        TransportSecurity::Encrypted => "https",
    };
    let mut location = String::with_capacity(scheme.len() + host.len() + bucket.len() + key.len() + 5);
    location.push_str(scheme);
    location.push_str("://");
    location.push_str(host);
    location.push('/');
    if origin == TargetOrigin::Path {
        location.push_str(bucket);
        location.push('/');
    }
    push_encoded_object_path(&mut location, key.as_bytes());
    location
}

fn push_encoded_object_path(out: &mut String, bytes: &[u8]) {
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(hex_digit(byte >> 4)));
            out.push(char::from(hex_digit(byte & 0x0f)));
        }
    }
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'A' + nibble - 10,
        _ => b'?',
    }
}
