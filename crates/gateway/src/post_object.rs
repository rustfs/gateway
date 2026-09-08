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

//! The narrow production bridge from a POST Object form to the ordinary typed pipeline.
//!
//! Responsible for: reading only bounded text parts before authentication, resolving the already
//! implemented SigV4/SigV2 POST-policy authority, and exposing the file as a policy-bounded live
//! stream after authentication, and applying the form's success action to a successful storage
//! result. NOT responsible for: signature comparison, authorization, or storage. Upstream:
//! `crate::service` after routing and governing. Downstream: the ordinary core decoder/handler
//! dispatch path.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::fmt;

use bytes::{Bytes, BytesMut};
use http::{HeaderValue, StatusCode, Uri, header};
use http_body::{Body, Frame, SizeHint};
use rustfs_gateway_core::{EncodedResponse, ResponseBody, TransportSecurity};
use rustfs_gateway_http::{BodyIntegrity, FileReader, FileStep, FormLimits, FormReader, FormReject, FormStep};
use rustfs_gateway_sig::{
    PostPolicy, PostPolicyError, PostPolicyLimits, RequestNow, SigV2PostPolicy, build_success_action_redirect,
};
use rustfs_gateway_types::dto::PostObjectInput;
use rustfs_gateway_types::{BucketName, NamePolicy, ObjectKey};
use rustfs_gateway_xml::{S3_XMLNS, XmlWriter};

use crate::close::ConnectionIntent;
use crate::ext::TargetOrigin;
use crate::gate::{BodyCeilings, BodyDigestObligation, BodyTimeouts, MetadataAdmission};
use crate::render::{S3Error, from_handler};
use crate::request_body::{BodyMonitor, StreamingRead};
use crate::wire_read::{WireFrames, WireProgress};
use crate::{ErrorCode, HandlerError, RequestBody, ResponseKind};

#[derive(Clone)]
enum SuccessAction {
    Ok,
    Created,
    NoContent,
    Redirect(String),
}

#[derive(Clone)]
pub(crate) struct PostObjectResponsePlan {
    action: SuccessAction,
    bucket: String,
    key: String,
}

impl PostObjectResponsePlan {
    fn parse(fields: &[(&str, &str)], bucket: &BucketName, key: &ObjectKey) -> Result<Self, S3Error> {
        let status = unique_success_field(fields, "success_action_status")?;
        let redirect = unique_success_field(fields, "success_action_redirect")?;
        let action = match (status, redirect) {
            (Some(_), Some(_)) => return Err(policy_refusal(PostPolicyError::Malformed)),
            (Some("200"), None) => SuccessAction::Ok,
            (Some("201"), None) => SuccessAction::Created,
            (Some("204"), None) | (None, None) => SuccessAction::NoContent,
            (Some(_), None) => return Err(policy_refusal(PostPolicyError::Malformed)),
            (None, Some(raw)) => SuccessAction::Redirect(validated_redirect(raw, bucket.as_str(), key.as_str())?),
        };
        Ok(Self {
            action,
            bucket: bucket.as_str().to_owned(),
            key: key.as_str().to_owned(),
        })
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
                let e_tag = encoded_etag(encoded)?;
                let location = object_location(security, host, origin, &self.bucket, &self.key);
                let mut writer = XmlWriter::document();
                writer.open("PostResponse", Some(S3_XMLNS));
                writer.element("Location", &location);
                writer.element("Bucket", &self.bucket);
                writer.element("Key", &self.key);
                writer.element_quoting("ETag", e_tag);
                encoded.status = StatusCode::CREATED;
                encoded.set_header("content-type", "application/xml");
                encoded.body = ResponseBody::Complete(writer.finish().into_bytes());
            }
            SuccessAction::NoContent => {
                encoded.status = StatusCode::NO_CONTENT;
                encoded.body = ResponseBody::Empty;
            }
            SuccessAction::Redirect(raw) => {
                let e_tag = encoded_etag(encoded)?;
                let location = build_success_action_redirect(&raw, &self.bucket, &self.key, e_tag, None)
                    .map_err(|_| HandlerError::internal_error("the accepted POST redirect could not be rendered"))?;
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

fn encoded_etag(encoded: &EncodedResponse) -> Result<&str, HandlerError> {
    encoded
        .headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HandlerError::internal_error("a POST success response did not contain an entity tag"))
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

enum AcceptedPolicy {
    SigV4(PostPolicy),
    SigV2(SigV2PostPolicy),
    Anonymous,
}

impl AcceptedPolicy {
    fn final_key<'a>(&'a self, anonymous_key: &'a str) -> &'a str {
        match self {
            Self::SigV4(policy) => policy.final_key(),
            Self::SigV2(policy) => policy.final_key(),
            Self::Anonymous => anonymous_key,
        }
    }

    fn read_ceiling(&self, limits: FormLimits) -> u64 {
        match self {
            Self::SigV4(policy) => policy.read_ceiling(),
            Self::SigV2(policy) => policy.read_ceiling(),
            Self::Anonymous => limits.max_file_bytes(),
        }
    }

    fn enforce_final(&self, bucket: &str, key: &str, file_bytes: u64) -> Result<(), PostPolicyError> {
        match self {
            Self::SigV4(policy) => policy.enforce_final(bucket, key, file_bytes).map(|_| ()),
            Self::SigV2(policy) => policy.enforce_final(bucket, key, file_bytes).map(|_| ()),
            Self::Anonymous => Ok(()),
        }
    }
}

/// A governed form whose text fields are in hand and whose first file byte remains unread.
pub(crate) struct PostObjectPrelude<B> {
    reader: FormReader,
    frames: WireFrames<B>,
    first_file_bytes: Option<Bytes>,
    limits: FormLimits,
    timeouts: BodyTimeouts,
}

impl<B> PostObjectPrelude<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub(crate) async fn read(
        body: Option<B>,
        content_type: &str,
        limits: FormLimits,
        timeouts: BodyTimeouts,
    ) -> Result<Self, S3Error> {
        let Some(body) = body else {
            return Err(form_refusal(FormReject::MissingFile));
        };
        let progress = WireProgress::for_body(BodyDigestObligation::None, Some(&body));
        let mut frames = WireFrames::new(body, progress, BodyCeilings::streaming(None), timeouts);
        let mut reader = FormReader::new(content_type, limits).map_err(form_refusal)?;
        loop {
            let Some(frame) = core::future::poll_fn(|context| frames.poll_next(context)).await? else {
                return Err(form_refusal(reader.finish()));
            };
            match reader.push(&frame).map_err(form_refusal)? {
                FormStep::NeedMore => {}
                FormStep::FileReached { consumed } => {
                    let first_file_bytes = frame
                        .get(consumed..)
                        .filter(|bytes| !bytes.is_empty())
                        .map(Bytes::copy_from_slice);
                    return Ok(Self {
                        reader,
                        frames,
                        first_file_bytes,
                        limits,
                        timeouts,
                    });
                }
            }
        }
    }

    pub(crate) fn form_fields(&self) -> Vec<(&str, &str)> {
        self.reader
            .fields()
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect()
    }

    pub(crate) fn resolve(
        self,
        bucket: BucketName,
        names: &NamePolicy,
        now: RequestNow,
    ) -> Result<ResolvedPostObject<B>, S3Error> {
        let fields: Vec<(&str, &str)> = self
            .reader
            .fields()
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect();
        let filename = self.reader.filename().unwrap_or_default();
        let has_policy = fields.iter().any(|(name, _)| *name == "policy");
        let policy = if fields.iter().any(|(name, _)| *name == "x-amz-algorithm") {
            AcceptedPolicy::SigV4(PostPolicy::parse(&fields, filename, PostPolicyLimits::default(), now).map_err(policy_refusal)?)
        } else if fields.iter().any(|(name, _)| *name == "awsaccesskeyid") {
            AcceptedPolicy::SigV2(
                SigV2PostPolicy::parse(&fields, filename, PostPolicyLimits::default(), now).map_err(policy_refusal)?,
            )
        } else if has_policy {
            return Err(policy_refusal(PostPolicyError::Malformed));
        } else {
            AcceptedPolicy::Anonymous
        };
        let anonymous_key = fields
            .iter()
            .find_map(|(name, value)| (*name == "key").then_some(*value))
            .ok_or_else(|| policy_refusal(PostPolicyError::Malformed))?;
        let anonymous_key = if matches!(policy, AcceptedPolicy::Anonymous) {
            anonymous_key.replace("${filename}", filename)
        } else {
            anonymous_key.to_owned()
        };
        let key_text = policy.final_key(&anonymous_key);
        let key =
            ObjectKey::materialize_decoded(key_text, names).map_err(|_| policy_refusal(PostPolicyError::ConditionFailed))?;
        let metadata = fields
            .iter()
            .filter_map(|(name, value)| {
                name.strip_prefix("x-amz-meta-")
                    .map(|suffix| (suffix.to_owned(), (*value).to_owned()))
            })
            .collect();
        let response = PostObjectResponsePlan::parse(&fields, &bucket, &key)?;
        let ceiling = policy.read_ceiling(self.limits);
        let file = self.reader.into_file(ceiling).map_err(form_refusal)?;
        Ok(ResolvedPostObject {
            frames: self.frames,
            first_file_bytes: self.first_file_bytes,
            file,
            policy,
            bucket,
            key,
            metadata,
            response,
            timeouts: self.timeouts,
        })
    }
}

/// A resolved POST Object request held between authentication and route authorization.
pub(crate) struct ResolvedPostObject<B> {
    frames: WireFrames<B>,
    first_file_bytes: Option<Bytes>,
    file: FileReader,
    policy: AcceptedPolicy,
    bucket: BucketName,
    key: ObjectKey,
    metadata: Vec<(String, String)>,
    response: PostObjectResponsePlan,
    timeouts: BodyTimeouts,
}

impl<B> ResolvedPostObject<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }

    pub(crate) fn response_plan(&self) -> PostObjectResponsePlan {
        self.response.clone()
    }

    pub(crate) fn handoff(self, _proof: &MetadataAdmission<'_>) -> Result<(RequestBody, Option<BodyMonitor>), S3Error> {
        let body = PostFileBody {
            frames: self.frames,
            first: self.first_file_bytes,
            initial: true,
            file: self.file,
            policy: self.policy,
            bucket: self.bucket.as_str().to_owned(),
            key: self.key.as_str().to_owned(),
            ended: false,
        };
        let opened = StreamingRead::new(
            Some(body),
            None,
            (BodyCeilings::streaming(None), self.timeouts, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )?;
        let (stream, monitor) = opened.into_parts();
        Ok((
            RequestBody::PostObject(Box::new(PostObjectInput {
                bucket: self.bucket,
                key: self.key,
                body: stream,
                content_type: None,
                metadata: self.metadata,
            })),
            Some(monitor),
        ))
    }
}

#[derive(Debug)]
struct PostBodyError(&'static str);

impl fmt::Display for PostBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PostBodyError {}

struct PostFileBody<B> {
    frames: WireFrames<B>,
    first: Option<Bytes>,
    initial: bool,
    file: FileReader,
    policy: AcceptedPolicy,
    bucket: String,
    key: String,
    ended: bool,
}

impl<B> Body for PostFileBody<B>
where
    B: Body,
{
    type Data = Bytes;
    type Error = PostBodyError;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        loop {
            let frame = if self.initial {
                self.initial = false;
                Bytes::new()
            } else {
                match self.first.take() {
                    Some(frame) => frame,
                    None => match self.frames.poll_next(context) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(_)) => return Poll::Ready(Some(Err(PostBodyError("the POST body transport failed")))),
                        Poll::Ready(Ok(None)) => {
                            self.ended = true;
                            return Poll::Ready(Some(Err(PostBodyError("the POST form ended before its closing boundary"))));
                        }
                        Poll::Ready(Ok(Some(frame))) => frame,
                    },
                }
            };
            let mut emitted = BytesMut::new();
            let step = {
                let this = &mut *self;
                let mut sink = |bytes: &[u8]| emitted.extend_from_slice(bytes);
                this.file.push(&frame, &mut sink)
            };
            match step {
                Ok(FileStep::NeedMore) if emitted.is_empty() => {}
                Ok(FileStep::NeedMore) => return Poll::Ready(Some(Ok(Frame::data(emitted.freeze())))),
                Ok(FileStep::Complete { file_bytes }) => {
                    if self.policy.enforce_final(&self.bucket, &self.key, file_bytes).is_err() {
                        self.ended = true;
                        return Poll::Ready(Some(Err(PostBodyError("the POST file did not satisfy its policy"))));
                    }
                    self.ended = true;
                    if emitted.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(emitted.freeze()))));
                }
                Err(FormReject::FileTooLarge) => {
                    self.ended = true;
                    return Poll::Ready(Some(Err(PostBodyError("the POST file exceeded its policy ceiling"))));
                }
                Err(_) => {
                    self.ended = true;
                    return Poll::Ready(Some(Err(PostBodyError("the POST form was malformed"))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn form_refusal(reject: FormReject) -> S3Error {
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

fn policy_refusal(reject: PostPolicyError) -> S3Error {
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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    const BOUNDARY: &str = "----RustFSPostUnit";

    fn form(file: &str) -> Bytes {
        Bytes::from(format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/report.txt\r\n\
             --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\r\n\
             {file}\r\n--{BOUNDARY}--\r\n"
        ))
    }

    fn truncated_form(file: &str) -> Bytes {
        Bytes::from(format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/report.txt\r\n\
             --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\r\n\
             {file}"
        ))
    }

    async fn resolved(body: Bytes, limits: FormLimits) -> Result<ResolvedPostObject<Full<Bytes>>, String> {
        let prelude = PostObjectPrelude::read(
            Some(Full::new(body)),
            &format!("multipart/form-data; boundary={BOUNDARY}"),
            limits,
            BodyTimeouts::S3,
        )
        .await
        .map_err(|_| "fixture form prelude must parse".to_owned())?;
        let bucket = BucketName::new("example-bucket").map_err(|_| "fixture bucket must be valid".to_owned())?;
        prelude
            .resolve(bucket, &NamePolicy::default(), RequestNow::from_unix_seconds(0))
            .map_err(|_| "fixture anonymous form must resolve".to_owned())
    }

    fn file_body(resolved: ResolvedPostObject<Full<Bytes>>) -> PostFileBody<Full<Bytes>> {
        PostFileBody {
            frames: resolved.frames,
            first: resolved.first_file_bytes,
            initial: true,
            file: resolved.file,
            policy: resolved.policy,
            bucket: resolved.bucket.as_str().to_owned(),
            key: resolved.key.as_str().to_owned(),
            ended: false,
        }
    }

    #[tokio::test]
    async fn an_anonymous_file_adapter_reaches_its_closing_boundary() -> Result<(), String> {
        let bytes = file_body(resolved(form("hello"), FormLimits::default()).await?)
            .collect()
            .await
            .map_err(|error| error.to_string())?
            .to_bytes();
        assert_eq!(bytes, Bytes::from_static(b"hello"));
        Ok(())
    }

    #[tokio::test]
    async fn an_anonymous_file_stops_at_the_deployment_ceiling() -> Result<(), String> {
        let result = file_body(resolved(form("hello"), FormLimits::default().with_max_file_bytes(4)).await?)
            .collect()
            .await;
        assert!(result.is_err(), "five bytes exceed the four-byte ceiling");
        let Err(error) = result else {
            return Ok(());
        };
        assert_eq!(error.to_string(), "the POST file exceeded its policy ceiling");
        Ok(())
    }

    #[test]
    fn an_anonymous_form_names_the_deployment_ceiling_before_file_reading() {
        let limits = FormLimits::default().with_max_file_bytes(4);
        assert_eq!(AcceptedPolicy::Anonymous.read_ceiling(limits), 4);
    }

    #[tokio::test]
    async fn a_truncated_file_never_becomes_a_successful_eof() -> Result<(), String> {
        let result = file_body(resolved(truncated_form("hello"), FormLimits::default()).await?)
            .collect()
            .await;
        assert!(result.is_err(), "the closing boundary is required");
        let Err(error) = result else {
            return Ok(());
        };
        assert_eq!(error.to_string(), "the POST form ended before its closing boundary");
        Ok(())
    }
}
